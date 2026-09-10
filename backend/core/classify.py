"""공격 유형 분류(단일 홈).

이 프로젝트에는 분류 정규식이 세 벌로 흩어져 있었다(analyzer.infer_attack_type,
ai_analyzer._infer_category/_norm_category). 서로 조금씩 달라 유지보수가 어렵고,
무엇보다 **요청 헤더를 전혀 보지 않아** SOC 가 패킷을 붙여넣을 때 헤더에 실린 공격
(Log4Shell·Shellshock·헤더 SQLi 등)이 통째로 미분류됐다.

이 모듈이 분류의 단일 소스다:
  - payload·URL·본문뿐 아니라 **요청 헤더까지** 프로브에 포함한다.
  - 단, 헤더는 정상 트래픽에도 흔한 토큰(localhost·//host. 등)이 있어 오탐 위험이 크므로,
    '정상 헤더엔 거의 없는' 안전 마커(scan_headers=True)만 헤더를 훑는다.
  - 여러 유형이 겹칠 수 있어 다중 후보를 돌려준다(주 유형 + 후보 목록).

분류 ≠ 판정. 여기서 '무슨 공격인가'만 넓게 정하고, '실제로 통했는가'는 analyzer 의
증거 기반 탐지기가 좁게 판정한다. 그래서 분류를 넉넉하게 잡아도 오탐(허위 성공)은 늘지 않는다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote, urlsplit

# ── 카테고리와 무관하게 파일 '내용' 탐지를 켜는 힌트(경로 트래버설·민감파일 접근) ──
# 힌트는 '콘텐츠 마커 검사를 켤지'만 정하는 게이트다. 실제 성공 판정은 엄격한 파일 내용
# 시그니처가 하므로, 힌트를 넉넉히 잡아도 오탐이 늘지 않는다(인코딩 변형 포함).
_FILE_READ_HINT = re.compile(
    r"\.\.[\\/]|%2e|%252e|%c0%ae|"                 # 경로 트래버설(평문/단·이중 인코딩)
    r"%2f|%5c|%252f|%255c|"                        # 인코딩된 슬래시/백슬래시
    r"/etc/|etc%2f|/proc/|windows[\\/]|/windows/system32|win\.ini|boot\.ini|"
    r"passwd|shadow|/hosts\b|access\.log|/environ\b|/cmdline\b|"
    r"\.git[/%]|\.svn/|\.hg/|\.bzr/|\.env\b|wp-config\.php|web\.config|"  # VCS·설정·시크릿 파일
    r"\.htaccess|/WEB-INF|id_rsa|\.(?:bak|old|swp|save|orig)\b|\.DS_Store|"
    r"file://|LOAD_FILE|pg_read_file|xp_cmdshell",
    re.I,
)
_SSRF_HINT = re.compile(
    r"169\.254\.169\.254|/latest/meta-data|metadata\.google|metadata\.azure|"
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|file://|gopher://|dict://|"
    r"internal|/computeMetadata", re.I)
_SQLI_HINT = re.compile(
    r"\bUNION\b\s+SELECT|\bSELECT\b.+\bFROM\b|SLEEP\s*\(|pg_sleep|benchmark\s*\(|"
    r"waitfor\s+delay|information_schema|xp_cmdshell|load_file\s*\(|"
    r"'\s*OR\s*'|\"\s*OR\s*\"|\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+|"
    r"'--|\"--|--\s|/\*.*\*/", re.I)
_REDIRECT_HINT = re.compile(
    r"redirect|url=|next=|returnurl|return_to|dest=|goto=|callback=|//[a-z0-9.-]+\.", re.I)
# XSS/오픈리다이렉트로 이어지는 위험 URI 스킴(링크 href·Location 에 들어가면 스크립트 실행)
_DANGEROUS_SCHEME = re.compile(r"(?i)(?:javascript|data|vbscript)\s*:")
# 명령 주입 지표 — 구분자(;|&)만으로는 SQLi(SLEEP·;DROP)·nosql(||)을 오인하므로,
# '구분자 + 실제 셸 명령' 또는 명령치환($()·백틱)·알려진 지표만 인정.
_CMDI_HINT = re.compile(
    r"(?:[;&|]|\|\||&&|%0a|%0d)\s*"
    r"(?:id\b|cat\b|ls\b|dir\b|pwd\b|whoami|uname|sleep\b|ping\b|curl\b|wget\b|nslookup|"
    r"nc\b|netcat|bash\b|/bin/|/etc/|\bsh\b|cmd\b|powershell|echo\b|type\b|net\s|ipconfig|ifconfig)"
    r"|\$\([^)]*\)|`[^`]+`|dest_host|\b(?:exec|system|passthru|popen|shell_exec|proc_open)\s*\(", re.I)
# XSS 강력 지표(스크립트 태그·이벤트 핸들러·위험 스킴).
_XSS_HINT = re.compile(
    r"<script|<img\b|<svg|<iframe|<body|<details|<marquee|"
    r"on(?:error|load|mouseover|focus|click|toggle|animationstart)\s*=|"
    r"alert\s*\(|prompt\s*\(|confirm\s*\(|document\.cookie|javascript:|data:text/html|vbscript:", re.I)

# ── 헤더에 실려 오는 공격 — 정상 트래픽엔 거의 없어 헤더 스캔이 안전한 마커 ──
# SOC 붙여넣기의 핵심 공백: 이들은 User-Agent·Referer·X-Api-Version 등에 들어오는데
# 예전 프로브는 헤더를 안 봤다.
_LOG4SHELL_HINT = re.compile(r"\$\{jndi:(?:ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http)s?:", re.I)
_SHELLSHOCK_HINT = re.compile(r"\(\s*\)\s*\{\s*[:_a-z].*?;\s*\}\s*;", re.I)
_NOSQL_HINT = re.compile(r"\$ne\b|\$gt\b|\$lt\b|\$where\b|\$regex\b|\$or\b|\[\$", re.I)


@dataclass(frozen=True)
class ClassHit:
    """분류 후보 하나 — 유형, 어느 위치에서, 무엇에 매칭됐는지."""
    attack_type: str
    where: str          # "payload/url/body" | "header"
    evidence: str       # 매칭된 스니펫(원문)
    subtype: str = ""   # 세부 이름(예: "log4shell", "shellshock") — 표시용


@dataclass
class AttackClass:
    primary: str = ""               # 주 유형(기존 소비자 호환 어휘)
    candidates: list = field(default_factory=list)  # list[ClassHit] — 우선순위순
    header_borne: bool = False      # 매칭이 헤더에서 나왔는가(SOC 단서)

    @property
    def types(self) -> list:
        seen, out = set(), []
        for c in self.candidates:
            if c.attack_type not in seen:
                seen.add(c.attack_type)
                out.append(c.attack_type)
        return out


# 규칙: (유형, 정규식, 헤더_스캔_허용, 세부이름). 순서 = 우선순위(첫 매칭이 primary).
# 헤더_스캔_허용=False 인 규칙은 payload/url/body 만 본다(정상 헤더 오탐 방지):
#   - SSRF: localhost·internal 이 Host/Referer 에 흔함 → 헤더 제외
#   - REDIRECT: //host. 가 모든 Referer/Origin 에 있음 → 헤더 제외
#   - SSTI: ${ 가 일부 정상 헤더에 있을 수 있음 → 본문/URL 만
# 헤더_스캔_허용=True 는 정상 헤더엔 거의 없는 마커(jndi·shellshock·<script·UNION SELECT 등).
_RULES = [
    ("cmdi", _LOG4SHELL_HINT,  True,  "log4shell"),   # ${jndi:...} — 헤더 최빈
    ("cmdi", _SHELLSHOCK_HINT, True,  "shellshock"),  # () { :;}; — 헤더
    ("lfi",  _FILE_READ_HINT,  True,  ""),
    ("xss",  _XSS_HINT,        True,  ""),
    ("cmdi", _CMDI_HINT,       False, ""),
    ("ssti", None,             False, ""),             # ssti 는 아래 전용 검사(7*7 등)
    ("ssrf", _SSRF_HINT,       False, ""),
    ("sqli", _SQLI_HINT,       True,  ""),
    ("nosql", _NOSQL_HINT,     False, ""),
    ("xmlrpc", None,           False, ""),             # xmlrpc 전용 검사
]
_SSTI_RE = re.compile(r"7\s*\*\s*7|\{\{|\$\{|#\{|<%=")


def _decode(s: str) -> str:
    """URL 이중 디코딩본을 덧붙여 인코딩 변형(%27 등)도 매칭되게 한다."""
    try:
        return s + " " + unquote(unquote(s))
    except Exception:
        return s


def _url_wo_host(url: Optional[str]) -> str:
    """대상 URL 에서 scheme://host 를 뺀 path+query(+fragment). 상대경로/빈 값은 그대로."""
    if not url:
        return ""
    try:
        u = urlsplit(url)
        if u.netloc:            # 절대 URL → host 제외
            rest = u.path or ""
            if u.query:
                rest += "?" + u.query
            if u.fragment:
                rest += "#" + u.fragment
            return rest
    except Exception:
        pass
    return url                 # 상대경로 등은 그대로(host 없음)


def _headers_text(headers: Optional[dict]) -> str:
    """헤더를 'key: value' 한 줄들로. dict(소문자 매칭용)나 HeaderView 모두 허용."""
    if not headers:
        return ""
    items = headers.items()
    return "\n".join(f"{k}: {v}" for k, v in items)


def classify(payload: Optional[str] = None, url: Optional[str] = None,
             req_body: Optional[str] = None, headers: Optional[dict] = None,
             category: Optional[str] = None) -> AttackClass:
    """요청(헤더 포함)을 보고 공격 유형을 분류. 판정이 아니라 '무슨 공격인가'만 정한다."""
    # 대상 URL 의 scheme://host 는 분류에서 제외한다. SSRF·오픈리다이렉트 마커(localhost·
    # 169.254·//host.)가 '공격 대상 주소 자체'에 흔히 들어 있어(특히 SOC 의 내부 IP 대상),
    # 그걸 공격 페이로드로 오인하면 모든 내부 대상이 SSRF 로 오분류된다. 공격은 경로·쿼리·
    # 본문·payload 에 있으므로 host 만 떼고 path+query 를 본다.
    body_probe = _decode(f"{payload or ''} {_url_wo_host(url)} {req_body or ''}")
    hdr_probe = _decode(_headers_text(headers))

    hits: list = []

    def _scan(attack_type, rx, allow_header, subtype):
        m = rx.search(body_probe)
        if m:
            hits.append(ClassHit(attack_type, "payload/url/body", m.group(0)[:80], subtype))
            return
        if allow_header and hdr_probe:
            m = rx.search(hdr_probe)
            if m:
                hits.append(ClassHit(attack_type, "header", m.group(0)[:80], subtype))

    for attack_type, rx, allow_header, subtype in _RULES:
        if rx is not None:
            _scan(attack_type, rx, allow_header, subtype)
        elif attack_type == "ssti":
            m = _SSTI_RE.search(body_probe)
            # ${jndi:...} 는 위에서 이미 log4shell(cmdi)로 잡혔으면 ssti 로 중복 분류하지 않는다
            if m and not any(h.subtype == "log4shell" for h in hits):
                hits.append(ClassHit("ssti", "payload/url/body", m.group(0)[:80], ""))
        elif attack_type == "xmlrpc":
            probe_l = body_probe.lower()
            if "xmlrpc" in probe_l or "<methodcall" in probe_l:
                hits.append(ClassHit("xmlrpc", "payload/url/body", "xmlrpc", ""))

    primary = hits[0].attack_type if hits else (category or "").lower()
    return AttackClass(primary=primary, candidates=hits,
                       header_borne=any(h.where == "header" for h in hits))


# ── 기존 소비자 호환 어댑터 ────────────────────────────────────────────────
# analyzer.infer_attack_type 과 ai_analyzer._infer_category 가 이 한 곳으로 위임한다.

def infer_attack_type(probe: str, category: str = "", headers: Optional[dict] = None) -> str:
    """payload+URL+본문(+헤더)로 주 공격 유형을 추론. 기존 analyzer.infer_attack_type 대체.

    probe 는 이미 합쳐진 문자열(payload/url/body)이라 그대로 payload 자리에 넣는다.
    """
    return classify(payload=probe, headers=headers, category=category).primary or (category or "").lower()
