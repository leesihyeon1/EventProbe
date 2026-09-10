"""
응답 분석 엔진 - WAF/IDS 차단 여부, 취약점 탐지, ZAP 스타일 Alert 생성
"""
import ast
import json
import os
import re
from typing import Optional
from urllib.parse import unquote, urlsplit, parse_qsl

# 공격 유형 분류의 단일 홈 — 힌트 정규식도 여기서 가져온다(예전엔 세 벌로 흩어져 있었다).
from core import classify as _classify
from core.classify import (_FILE_READ_HINT, _SSRF_HINT, _SQLI_HINT, _REDIRECT_HINT,
                           _DANGEROUS_SCHEME, _CMDI_HINT, _XSS_HINT)
from core import detectors as _detectors


def _ver_lt(body: str, pattern: str, target: tuple) -> bool:
    """body 에서 pattern(캡처그룹1=버전)을 찾아 target 미만이면 True (취약 라이브러리 판정용)."""
    m = re.search(pattern, body or "", re.I)
    if not m:
        return False
    try:
        parts = tuple(int(x) for x in re.findall(r"\d+", m.group(1))[:3])
        return parts < target
    except Exception:
        return False


# ── WAF 차단 시그니처 ────────────────────────────────────────────────────────
# 오탐을 줄이기 위해 매칭 대상을 3가지로 분리:
#   header_names : 응답 "헤더 이름"에 부분일치 (전용 헤더)
#   cookies      : Set-Cookie 값에 부분일치 (전용 세션 쿠키)
#   server       : Server / Via / X-Powered-By / X-CDN 값에 부분일치 (제품명)
WAF_SIGNATURES = {
    "Cloudflare":   {"header_names": ["cf-ray", "cf-cache-status"], "cookies": ["__cfduid", "__cf_bm"], "server": ["cloudflare"]},
    "AWS WAF":      {"header_names": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-waf-action"], "cookies": ["awsalb", "awselb"], "server": []},
    "ModSecurity":  {"header_names": [], "cookies": [], "server": ["mod_security", "modsecurity"]},
    "Akamai":       {"header_names": ["x-akamai-transformed", "akamai-grn"], "cookies": ["ak_bmsc"], "server": ["akamaighost"]},
    "Imperva":      {"header_names": ["x-iinfo", "x-cdn"], "cookies": ["visid_incap", "incap_ses", "nlbi_"], "server": ["incapsula"]},
    "F5 BIG-IP":    {"header_names": ["x-waf-status"], "cookies": ["bigipserver", "ts01"], "server": ["big-ip", "bigip"]},
    "Barracuda":    {"header_names": [], "cookies": ["barra_counter_session"], "server": ["barracuda"]},
    "Fortinet":     {"header_names": ["x-waf-event-info"], "cookies": ["fortiwafsid"], "server": ["fortiweb", "fortigate"]},
    "Sucuri":       {"header_names": ["x-sucuri-id", "x-sucuri-cache"], "cookies": [], "server": ["sucuri"]},
    "Wordfence":    {"header_names": [], "cookies": [], "server": ["wordfence"]},
}


class HeaderView(dict):
    """매칭용 소문자 헤더 맵. 원본 값은 raw()/raw_items() 로 꺼낸다.

    값까지 소문자로 만들면 매칭은 편하지만 증거가 원문과 달라진다 — Location URL,
    Set-Cookie, 토큰처럼 대소문자가 의미를 갖는 값은 사용자가 응답에서 그대로
    검색해도 찾지 못한다. 그래서 매칭(dict 접근)은 소문자로, 표시는 원본으로 나눈다.
    dict 그대로이므로 기존 호출부(get/items/keys)는 하나도 바뀌지 않는다.
    """

    def __init__(self, headers: Optional[dict] = None):
        headers = headers or {}
        super().__init__({str(k).lower(): str(v or "").lower() for k, v in headers.items()})
        self._raw = {str(k).lower(): str(v or "") for k, v in headers.items()}

    def raw(self, key: str, default: str = "") -> str:
        return self._raw.get(str(key or "").lower(), default)

    def raw_items(self):
        return self._raw.items()


def _hdr_raw(headers_lower, key: str, default: str = "") -> str:
    """표시용 원본 헤더 값. HeaderView 가 아니면(외부 호출) 소문자 값으로 폴백."""
    getter = getattr(headers_lower, "raw", None)
    if callable(getter):
        return getter(key, default)
    return (headers_lower or {}).get(str(key or "").lower(), default)


def _hdr_raw_items(headers_lower):
    getter = getattr(headers_lower, "raw_items", None)
    return list(getter()) if callable(getter) else list((headers_lower or {}).items())


def detect_waf(headers_lower: dict) -> Optional[str]:
    """응답 헤더에서 WAF 제품을 탐지. 헤더 이름/전용 쿠키/제품명 기준으로만 매칭."""
    header_names = list(headers_lower.keys())
    server_blob = " ".join(
        headers_lower.get(h, "") for h in ("server", "via", "x-powered-by", "x-cdn")
    )
    set_cookie = headers_lower.get("set-cookie", "")
    for waf, sig in WAF_SIGNATURES.items():
        if any(hn in name for hn in sig["header_names"] for name in header_names):
            return waf
        if any(cv in set_cookie for cv in sig["cookies"]):
            return waf
        if any(sv in server_blob for sv in sig["server"]):
            return waf
    return None


# ── 기술 스택/인프라 지문 ─────────────────────────────────────────────────────
# (라벨, 유형, [(헤더명 부분일치, 값 정규식 | None)]). 하나라도 매칭되면 감지.
# 값이 None 이면 '그 이름을 포함하는 헤더가 존재'하는 것만으로 매칭(예: x-envoy-* 계열).
_STACK_SIGNATURES = [
    # 프록시 / 게이트웨이 / 서비스메시
    ("Envoy",          "프록시",       [("server", r"\benvoy\b"), ("x-envoy-", None)]),
    ("Istio",          "서비스 메시",  [("x-istio", None), ("server", r"istio")]),
    ("Kong",           "API 게이트웨이", [("server", r"kong"), ("via", r"kong"), ("x-kong-", None)]),
    ("Traefik",        "프록시",       [("server", r"traefik")]),
    ("HAProxy",        "프록시",       [("server", r"haproxy")]),
    ("Varnish",        "캐시 프록시",  [("via", r"varnish"), ("x-varnish", None)]),
    ("Apache Traffic Server", "캐시 프록시", [("server", r"ats/|trafficserver")]),
    # CDN
    ("Cloudflare",     "CDN",          [("cf-ray", None), ("server", r"cloudflare")]),
    ("Fastly",         "CDN",          [("via", r"fastly"), ("x-served-by", r"cache-"), ("x-fastly", None)]),
    ("Amazon CloudFront", "CDN",       [("via", r"cloudfront"), ("x-amz-cf-id", None)]),
    ("Akamai",         "CDN",          [("server", r"akamai"), ("x-akamai", None)]),
    ("Vercel",         "호스팅/CDN",   [("server", r"vercel"), ("x-vercel-", None)]),
    # 웹서버
    ("nginx",          "웹서버",       [("server", r"nginx|openresty")]),
    ("Apache",         "웹서버",       [("server", r"apache")]),
    ("IIS",            "웹서버",       [("server", r"microsoft-iis|iis/")]),
    ("LiteSpeed",      "웹서버",       [("server", r"litespeed")]),
    # 프레임워크 / 런타임
    ("Next.js",        "프레임워크",   [("x-powered-by", r"next\.?js"), ("x-nextjs-", None)]),
    ("Express",        "프레임워크",   [("x-powered-by", r"express")]),
    ("ASP.NET",        "프레임워크",   [("x-powered-by", r"asp\.net"), ("x-aspnet-version", None), ("x-aspnetmvc-version", None)]),
    ("PHP",            "런타임",       [("x-powered-by", r"php/")]),
    ("Ruby on Rails",  "프레임워크",   [("x-powered-by", r"phusion passenger"), ("x-runtime", None)]),
    ("Django",         "프레임워크",   [("server", r"wsgiserver"), ("x-frame-options", r"__django__never__")]),
    ("Spring",         "프레임워크",   [("x-application-context", None)]),
    ("Laravel",        "프레임워크",   [("set-cookie", r"laravel_session")]),
]


def detect_stack(headers_lower: dict) -> list:
    """응답 헤더에서 프록시·CDN·웹서버·프레임워크 등 기술 스택을 식별.

    반환: [{"name","kind","evidence"}]. Envoy(server 또는 x-envoy-*) 같은 인프라도 인식한다.
    """
    items = list(headers_lower.items())          # 매칭은 소문자로
    out, seen = [], set()
    for label, kind, checks in _STACK_SIGNATURES:
        for name_needle, val_re in checks:
            hit = None
            for hk, hv in items:
                if name_needle in hk and (val_re is None or re.search(val_re, hv, re.I)):
                    hit = (hk, hv)
                    break
            if hit and label not in seen:
                seen.add(label)
                raw_v = _hdr_raw(headers_lower, hit[0], hit[1])   # 증거는 원본 값으로
                ev = f"{hit[0]}: {raw_v[:60]}" if raw_v else hit[0]
                out.append({"name": label, "kind": kind, "evidence": ev})
                break
    return out

# ── 차단 응답 바디 키워드 ────────────────────────────────────────────────────
BLOCK_KEYWORDS = [
    "blocked", "forbidden", "access denied", "not allowed",
    "security violation", "request blocked", "attack detected",
    "illegal request", "rejected", "차단", "금지", "접근 거부",
]
# 차단 상태코드(성공 코드와 구분)
_BLOCK_STATUS = (400, 403, 406, 429, 503)


def _body_signals_block(status_code: int, body: str, body_lower: str) -> bool:
    """바디의 차단 키워드를 '차단'으로 볼지 판단.

    차단 페이지는 대개 짧다. 상태코드가 200 같은 성공인데 응답이 크면(예: 84KB 정상
    페이지에 'forbidden' 단어가 우연히 포함) 차단으로 오판하지 않는다.
    """
    if not any(k in body_lower for k in BLOCK_KEYWORDS):
        return False
    if status_code in _BLOCK_STATUS:
        return True
    # 성공 상태코드에서는 '짧은 차단 페이지'일 때만 인정(대형 정상 페이지 오탐 방지)
    return len(body or "") < 4096

# ── 에러 누출 패턴 ────────────────────────────────────────────────────────────
# DB/앱 에러 시그니처 — 선언형 데이터에서 로드(backend/data/dbms_error_signatures.json).
# 외부 참조: sqlmap data/xml/errors.xml → tools/import_sqlmap_errors.py 로 갱신(그대로 임포트).
# 이 목록은 '모든 응답'에 전역 적용되므로 오탐 낮은 특이 패턴만. 파일 없거나 손상 시 내장 폴백.
_ERROR_PATTERNS_FALLBACK = [
    (r"SQL syntax.*?MySQL", "MySQL 에러 노출"),
    (r"You have an error in your SQL syntax", "MySQL/MariaDB 문법 에러"),
    (r"ORA-\d{5}", "Oracle DB 에러 코드"),
    (r"PostgreSQL.*?ERROR", "PostgreSQL 에러"),
    (r"Microsoft SQL Server", "MSSQL 에러"),
    (r"SQLSTATE\[", "SQL(PDO/SQLSTATE) 에러"),
    (r"Traceback \(most recent", "Python 트레이스백"),
    (r"stack trace", "스택 트레이스 노출"),
]


def _load_error_patterns():
    """(global_list, sqli_list) 반환.
    global = 모든 응답에 적용(오탐 낮은 특이 패턴), sqli = SQLi 문맥에서만 적용(sqlmap 임포트분)."""
    fp = os.path.join(os.path.dirname(__file__), "..", "data", "dbms_error_signatures.json")
    try:
        with open(fp, encoding="utf-8") as f:
            sigs = json.load(f).get("error_signatures", [])
        g, s_only = [], []
        for s in sigs:
            rx, lbl = s.get("regex"), s.get("label", "")
            if not rx:
                continue
            try:
                re.compile(rx)          # 손상된 패턴은 스킵(전체 실패 방지)
            except re.error:
                continue
            (s_only if s.get("scope") == "sqli" else g).append((rx, lbl))
        return (g or list(_ERROR_PATTERNS_FALLBACK)), s_only
    except Exception:
        return list(_ERROR_PATTERNS_FALLBACK), []


# ERROR_LEAK_PATTERNS: 전역(모든 응답). SQLI_ERROR_PATTERNS: SQLi 문맥 전용(전역 + sqli scope).
ERROR_LEAK_PATTERNS, _SQLI_ONLY_ERROR_PATTERNS = _load_error_patterns()
SQLI_ERROR_PATTERNS = ERROR_LEAK_PATTERNS + _SQLI_ONLY_ERROR_PATTERNS

# ── 민감 정보 패턴 ────────────────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    (r"root:[x*]:0:0",                             "passwd 파일 내용"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",    "개인키 노출"),
    (r"password\s*[=:]\s*\S+",                     "패스워드 노출"),
    (r"api[_-]?key\s*[=:]\s*['\"]?\w{10,}",       "API 키 노출"),
    (r"secret[_-]?key\s*[=:]\s*['\"]?\w{10,}",    "Secret 키 노출"),
    (r"access[_-]?token\s*[=:]\s*['\"]?\S{10,}",  "Access Token 노출"),
    # JWT 만 정밀 탐지(eyJ...=base64 '{"'). 과거의 '60자+ base64 전부' 규칙은
    # PNG/폰트/번들/SRI 해시까지 '토큰'으로 오탐해 제거함(구체 토큰은 secret Alert 룰이 커버).
    (r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "JWT 토큰 노출"),
    # ── 정밀 추출형 클라우드/서비스 시크릿(구조가 명확 → 오탐 거의 없음) ──
    (r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b", "AWS Access Key ID 노출"),
    (r"aws_secret_access_key\s*[=:,]\s*['\"]?[A-Za-z0-9/+]{40}", "AWS Secret Access Key 노출"),
    (r"\bAIza[0-9A-Za-z_\-]{35}\b",                 "Google API 키 노출"),
    (r"\bgh[pousr]_[0-9A-Za-z]{36,}\b",             "GitHub 토큰 노출"),
    (r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",           "Slack 토큰 노출"),
    (r"\bsk_live_[0-9A-Za-z]{24,}\b",               "Stripe 라이브 시크릿키 노출"),
    (r"-----BEGIN (?:OPENSSH|DSA|PGP) PRIVATE KEY-----", "개인키 노출"),
    (r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b",
                                                   "내부 IP 주소 노출"),
]


# ════════════════════════════════════════════════════════════════════════════════
# ZAP 스타일 ALERT 룰셋
# ════════════════════════════════════════════════════════════════════════════════
# 각 룰: {
#   id, name, risk (high/medium/low/informational),
#   confidence (certain/firm/tentative),
#   description, solution, reference,
#   check: callable(headers_lower, body, body_lower, status_code) -> bool | str
# }

ALERT_RULES = [

    # ── 보안 헤더 누락 ─────────────────────────────────────────────────────────
    {
        "id": "10016",
        "name": "Content-Security-Policy 헤더 누락",
        "risk": "medium",
        "confidence": "certain",
        "description": "CSP 헤더가 없습니다. XSS 및 데이터 인젝션 공격에 취약할 수 있습니다.",
        "solution": "Content-Security-Policy 헤더를 응답에 추가하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "content-security-policy" not in h and s == 200,
    },
    {
        "id": "10035",
        "name": "Strict-Transport-Security 헤더 누락",
        "risk": "low",
        "confidence": "certain",
        "description": "HSTS 헤더가 없습니다. HTTPS 강제 설정이 되어있지 않아 다운그레이드 공격에 노출될 수 있습니다.",
        "solution": "Strict-Transport-Security: max-age=31536000; includeSubDomains 헤더를 추가하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "strict-transport-security" not in h and s == 200,
    },
    {
        "id": "10021",
        "name": "X-Content-Type-Options 헤더 누락",
        "risk": "low",
        "confidence": "certain",
        "description": "X-Content-Type-Options 헤더가 없어 MIME 스니핑 공격에 취약합니다.",
        "solution": "X-Content-Type-Options: nosniff 헤더를 추가하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "x-content-type-options" not in h and s == 200,
    },
    {
        "id": "10020",
        "name": "X-Frame-Options 헤더 누락",
        "risk": "medium",
        "confidence": "certain",
        "description": "X-Frame-Options 헤더가 없습니다. 클릭재킹(Clickjacking) 공격에 취약합니다.",
        "solution": "X-Frame-Options: DENY 또는 SAMEORIGIN 헤더를 추가하세요.",
        "reference": "https://owasp.org/www-community/attacks/Clickjacking",
        "check": lambda h, b, bl, s: "x-frame-options" not in h
                                      and "frame-ancestors" not in h.get("content-security-policy","")
                                      and s == 200,
    },
    {
        "id": "10038",
        "name": "Content-Security-Policy — unsafe-inline 허용",
        "risk": "medium",
        "confidence": "certain",
        "description": "CSP에 'unsafe-inline'이 허용되어 XSS 방어 효과가 크게 감소합니다.",
        "solution": "unsafe-inline 지시어를 제거하고 nonce 또는 hash 기반 CSP를 사용하세요.",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        "check": lambda h, b, bl, s: "unsafe-inline" in h.get("content-security-policy", ""),
    },
    {
        "id": "10036",
        "name": "Permissions-Policy 헤더 누락",
        "risk": "low",
        "confidence": "tentative",
        "description": "Permissions-Policy(Feature-Policy) 헤더가 없어 불필요한 브라우저 기능이 활성화될 수 있습니다.",
        "solution": "Permissions-Policy 헤더를 추가하여 카메라, 마이크 등의 권한을 제한하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "permissions-policy" not in h
                                      and "feature-policy" not in h
                                      and s == 200,
    },

    # ── 쿠키 보안 ─────────────────────────────────────────────────────────────
    {
        "id": "10010",
        "name": "쿠키 HttpOnly 플래그 누락",
        "risk": "medium",
        "confidence": "firm",
        "description": "Set-Cookie 헤더에 HttpOnly 플래그가 없습니다. JavaScript에서 쿠키 접근이 가능하여 XSS를 통한 세션 탈취가 가능합니다.",
        "solution": "모든 세션 쿠키에 HttpOnly 플래그를 설정하세요.",
        "reference": "https://owasp.org/www-community/HttpOnly",
        "check": lambda h, b, bl, s: "set-cookie" in h
                                      and "httponly" not in h.get("set-cookie", "").lower(),
    },
    {
        "id": "10011",
        "name": "쿠키 Secure 플래그 누락",
        "risk": "medium",
        "confidence": "firm",
        "description": "Set-Cookie 헤더에 Secure 플래그가 없습니다. HTTP로 쿠키가 전송될 수 있습니다.",
        "solution": "세션 쿠키에 Secure 플래그를 설정하세요.",
        "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute",
        "check": lambda h, b, bl, s: "set-cookie" in h
                                      and "secure" not in h.get("set-cookie", "").lower(),
    },
    {
        "id": "10054",
        "name": "쿠키 SameSite 속성 없음",
        "risk": "low",
        "confidence": "firm",
        "description": "Set-Cookie 헤더에 SameSite 속성이 없어 CSRF 공격에 취약할 수 있습니다.",
        "solution": "SameSite=Strict 또는 SameSite=Lax 속성을 쿠키에 추가하세요.",
        "reference": "https://owasp.org/www-community/SameSite",
        "check": lambda h, b, bl, s: "set-cookie" in h
                                      and "samesite" not in h.get("set-cookie", "").lower(),
    },

    # ── 프레임워크/서버 정보 노출 ─────────────────────────────────────────────
    {
        "id": "10036-server",
        "name": "Server 헤더 — 버전 정보 노출",
        "risk": "low",
        "confidence": "certain",
        "description": lambda h, **_: f"Server 헤더에 상세 버전 정보가 노출됩니다: {h.get('server','')}",
        "solution": "Server 헤더에서 버전 정보를 제거하거나 헤더 자체를 숨기세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: bool(re.search(
            r"(apache|nginx|iis|tomcat|jetty|lighttpd|gunicorn|uvicorn)[/\s]\d+",
            h.get("server", ""), re.I)),
    },
    {
        "id": "10037",
        "name": "X-Powered-By 헤더 — 프레임워크 노출",
        "risk": "low",
        "confidence": "certain",
        "description": lambda h, **_: f"X-Powered-By 헤더가 기술 스택을 노출합니다: {h.get('x-powered-by','')}",
        "solution": "X-Powered-By 헤더를 제거하거나 비활성화하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: "x-powered-by" in h,
    },
    {
        "id": "10054-asp",
        "name": "ASP.NET 버전 헤더 노출",
        "risk": "low",
        "confidence": "certain",
        "description": lambda h, **_: f"X-AspNet-Version 헤더가 노출됩니다: {h.get('x-aspnet-version','')}",
        "solution": "httpRuntime enableVersionHeader=\"false\" 설정으로 헤더를 비활성화하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: "x-aspnet-version" in h or "x-aspnetmvc-version" in h,
    },

    # ── 웹 서버 식별 ──────────────────────────────────────────────────────────
    {
        "id": "90001-apache",
        "name": "웹서버 식별 — Apache",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Apache 웹서버가 식별되었습니다: {h.get('server','')}",
        "solution": "Server 헤더에서 버전 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"apache", h.get("server",""), re.I)),
    },
    {
        "id": "90001-nginx",
        "name": "웹서버 식별 — Nginx",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Nginx 웹서버가 식별되었습니다: {h.get('server','')}",
        "solution": "server_tokens off; 설정으로 버전 정보를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"nginx", h.get("server",""), re.I)),
    },
    {
        "id": "90001-iis",
        "name": "웹서버 식별 — Microsoft IIS",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Microsoft IIS가 식별되었습니다: {h.get('server','')}",
        "solution": "IIS Manager에서 HTTP 응답 헤더의 Server 값을 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"iis|microsoft-iis", h.get("server",""), re.I)),
    },
    {
        "id": "90001-tomcat",
        "name": "WAS 식별 — Apache Tomcat",
        "risk": "informational", "confidence": "firm",
        "description": lambda h, **_: f"Apache Tomcat이 식별되었습니다: {h.get('server','')}",
        "solution": "server.xml에서 Server 헤더를 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"tomcat", h.get("server",""), re.I))
                                      or "apache-coyote" in h.get("server","").lower(),
    },
    {
        "id": "90001-jetty",
        "name": "WAS 식별 — Jetty",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Eclipse Jetty가 식별되었습니다: {h.get('server','')}",
        "solution": "Server 헤더 노출을 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"jetty", h.get("server",""), re.I)),
    },
    {
        "id": "90001-weblogic",
        "name": "WAS 식별 — Oracle WebLogic",
        "risk": "low", "confidence": "firm",
        "description": "Oracle WebLogic 서버가 식별되었습니다. 알려진 취약점이 다수 존재합니다.",
        "solution": "Server 헤더를 제거하고 최신 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"weblogic", h.get("server",""), re.I))
                                      or "weblogic" in bl,
    },
    {
        "id": "90001-websphere",
        "name": "WAS 식별 — IBM WebSphere",
        "risk": "low", "confidence": "firm",
        "description": "IBM WebSphere 서버가 식별되었습니다.",
        "solution": "Server 헤더를 제거하고 최신 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"websphere|was/", h.get("server",""), re.I)),
    },
    {
        "id": "90001-jboss",
        "name": "WAS 식별 — JBoss / WildFly",
        "risk": "low", "confidence": "firm",
        "description": "JBoss 또는 WildFly 서버가 식별되었습니다.",
        "solution": "Server 헤더를 제거하고 최신 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"jboss|wildfly", h.get("server",""), re.I))
                                      or "jboss" in bl,
    },
    {
        "id": "90001-gunicorn",
        "name": "웹서버 식별 — Gunicorn (Python)",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Gunicorn WSGI 서버가 식별되었습니다: {h.get('server','')}",
        "solution": "reverse proxy 뒤에 배치하여 Server 헤더를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"gunicorn", h.get("server",""), re.I)),
    },
    {
        "id": "90001-uvicorn",
        "name": "웹서버 식별 — Uvicorn (Python ASGI)",
        "risk": "informational", "confidence": "certain",
        "description": "Uvicorn ASGI 서버가 식별되었습니다.",
        "solution": "reverse proxy 뒤에 배치하여 Server 헤더를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"uvicorn", h.get("server",""), re.I)),
    },
    {
        "id": "90001-lighttpd",
        "name": "웹서버 식별 — lighttpd",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"lighttpd 웹서버가 식별되었습니다: {h.get('server','')}",
        "solution": "server.tag 설정으로 버전 정보를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"lighttpd", h.get("server",""), re.I)),
    },
    {
        "id": "90001-caddy",
        "name": "웹서버 식별 — Caddy",
        "risk": "informational", "confidence": "certain",
        "description": "Caddy 웹서버가 식별되었습니다.",
        "solution": "Server 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"caddy", h.get("server",""), re.I)),
    },

    # ── 언어/런타임 식별 ──────────────────────────────────────────────────────
    {
        "id": "90002-php",
        "name": "언어 식별 — PHP",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"PHP 런타임이 노출됩니다: {h.get('x-powered-by','')}",
        "solution": "expose_php = Off (php.ini) 설정으로 헤더를 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"php", h.get("x-powered-by",""), re.I))
                                      or bool(re.search(r"php/\d", h.get("server",""), re.I)),
    },
    {
        "id": "90002-aspnet",
        "name": "언어 식별 — ASP.NET",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"ASP.NET이 식별되었습니다: {h.get('x-powered-by','')}",
        "solution": "X-Powered-By 헤더를 제거하고 버전 정보를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"asp\.net", h.get("x-powered-by",""), re.I)),
    },
    {
        "id": "90002-python",
        "name": "언어 식별 — Python",
        "risk": "informational", "confidence": "tentative",
        "description": "Python 기반 서버가 식별되었습니다.",
        "solution": "Server 헤더에서 언어 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"python|django|flask|fastapi|tornado|aiohttp",
                                           h.get("server","") + h.get("x-powered-by",""), re.I)),
    },
    {
        "id": "90002-ruby",
        "name": "언어 식별 — Ruby",
        "risk": "informational", "confidence": "firm",
        "description": "Ruby 기반 서버가 식별되었습니다.",
        "solution": "Server 헤더에서 언어 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"ruby|rails|phusion passenger",
                                           h.get("server","") + h.get("x-powered-by",""), re.I)),
    },
    {
        "id": "90002-java",
        "name": "언어 식별 — Java",
        "risk": "informational", "confidence": "tentative",
        "description": "Java 기반 서버가 식별되었습니다.",
        "solution": "Server 헤더에서 언어 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"java|jsessionid",
                                           h.get("server","") + h.get("set-cookie",""), re.I)),
    },
    {
        "id": "90002-nodejs",
        "name": "언어 식별 — Node.js",
        "risk": "informational", "confidence": "firm",
        "description": "Node.js 기반 서버가 식별되었습니다.",
        "solution": "Server 헤더에서 런타임 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"node\.js|nodejs",
                                           h.get("server","") + h.get("x-powered-by",""), re.I)),
    },

    # ── 프레임워크 식별 ────────────────────────────────────────────────────────
    {
        "id": "90005-django",
        "name": "프레임워크 식별 — Django",
        "risk": "informational", "confidence": "firm",
        "description": "Django 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "csrftoken" in h.get("set-cookie","")
                                      or "django" in h.get("x-powered-by","").lower()
                                      or bool(re.search(r"django", bl)),
    },
    {
        "id": "90005-flask",
        "name": "프레임워크 식별 — Flask",
        "risk": "informational", "confidence": "firm",
        "description": "Flask 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "werkzeug" in h.get("server","").lower()
                                      or bool(re.search(r"flask|werkzeug", bl)),
    },
    {
        "id": "90005-fastapi",
        "name": "프레임워크 식별 — FastAPI",
        "risk": "informational", "confidence": "firm",
        "description": "FastAPI 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"fastapi", bl))
                                      or h.get("server","").lower().startswith("uvicorn"),
    },
    {
        "id": "90005-laravel",
        "name": "프레임워크 식별 — Laravel",
        "risk": "informational", "confidence": "firm",
        "description": "Laravel 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "laravel_session" in h.get("set-cookie","")
                                      or "laravel" in h.get("x-powered-by","").lower()
                                      or bool(re.search(r"laravel", bl)),
    },
    {
        "id": "90005-symfony",
        "name": "프레임워크 식별 — Symfony (PHP)",
        "risk": "informational", "confidence": "firm",
        "description": "Symfony 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "symfony" in h.get("x-powered-by","").lower()
                                      or bool(re.search(r"symfony|sfid=", h.get("set-cookie",""), re.I))
                                      or bool(re.search(r"symfony", bl)),
    },
    {
        "id": "90005-spring",
        "name": "프레임워크 식별 — Spring (Java)",
        "risk": "informational", "confidence": "tentative",
        "description": "Spring Framework가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "jsessionid" in h.get("set-cookie","").lower()
                                      or "spring" in h.get("x-application-context","").lower()
                                      or bool(re.search(r"whitelabel error|spring", bl)),
    },
    {
        "id": "90005-express",
        "name": "프레임워크 식별 — Express.js",
        "risk": "informational", "confidence": "certain",
        "description": "Express.js 프레임워크가 식별되었습니다.",
        "solution": "app.disable('x-powered-by')로 헤더를 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "express" in h.get("x-powered-by","").lower(),
    },
    {
        "id": "90005-nestjs",
        "name": "프레임워크 식별 — NestJS",
        "risk": "informational", "confidence": "tentative",
        "description": "NestJS 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"nestjs|nest\.js", bl, re.I)),
    },
    {
        "id": "90005-rails",
        "name": "프레임워크 식별 — Ruby on Rails",
        "risk": "informational", "confidence": "firm",
        "description": "Ruby on Rails 프레임워크가 식별되었습니다.",
        "solution": "config.middleware.delete ActionDispatch::ServerTiming 등으로 정보 노출을 줄이세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"rails|_session_id|_rails",
                                           h.get("set-cookie",""), re.I))
                                      or bool(re.search(r"ruby on rails|rails", bl, re.I)),
    },
    {
        "id": "90005-nextjs",
        "name": "프레임워크 식별 — Next.js",
        "risk": "informational", "confidence": "firm",
        "description": "Next.js 프레임워크가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-nextjs-cache" in h or "x-nextjs-page" in h
                                      or bool(re.search(r"__next|_next/static", bl)),
    },
    {
        "id": "90005-nuxt",
        "name": "프레임워크 식별 — Nuxt.js",
        "risk": "informational", "confidence": "firm",
        "description": "Nuxt.js 프레임워크가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"__nuxt|_nuxt/", bl)),
    },
    {
        "id": "90005-aspnet-core",
        "name": "프레임워크 식별 — ASP.NET Core",
        "risk": "informational", "confidence": "firm",
        "description": "ASP.NET Core 프레임워크가 식별되었습니다.",
        "solution": "헤더 노출 설정을 검토하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"asp\.net core", h.get("x-powered-by",""), re.I))
                                      or "x-aspnetcore-env" in h,
    },
    {
        "id": "90005-struts",
        "name": "프레임워크 식별 — Apache Struts",
        "risk": "low", "confidence": "tentative",
        "description": "Apache Struts 프레임워크가 식별되었습니다. 심각한 취약점(CVE-2017-5638 등) 이력이 있습니다.",
        "solution": "최신 버전으로 패치하고 프레임워크 정보 노출을 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"struts|\.action\b|\.do\b", bl, re.I)),
    },

    # ── CMS / 플랫폼 식별 ─────────────────────────────────────────────────────
    {
        "id": "90006-wp",
        "name": "CMS 식별 — WordPress",
        "risk": "informational", "confidence": "firm",
        "description": "WordPress CMS가 식별되었습니다.",
        "solution": "버전 정보 노출을 제거하고 보안 플러그인을 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "wp-content" in bl or "wp-includes" in bl
                                      or bool(re.search(r"wordpress|wp-json", bl)),
    },
    {
        "id": "90006-drupal",
        "name": "CMS 식별 — Drupal",
        "risk": "informational", "confidence": "firm",
        "description": "Drupal CMS가 식별되었습니다.",
        "solution": "버전 정보를 숨기고 최신 보안 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-generator" in h and "drupal" in h.get("x-generator","").lower()
                                      or bool(re.search(r"drupal|/sites/default/files", bl)),
    },
    {
        "id": "90006-joomla",
        "name": "CMS 식별 — Joomla",
        "risk": "informational", "confidence": "firm",
        "description": "Joomla CMS가 식별되었습니다.",
        "solution": "버전 정보를 숨기고 최신 보안 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"joomla|/components/com_", bl)),
    },
    {
        "id": "90006-magento",
        "name": "E-Commerce 식별 — Magento",
        "risk": "informational", "confidence": "firm",
        "description": "Magento 전자상거래 플랫폼이 식별되었습니다.",
        "solution": "버전 정보를 숨기고 최신 보안 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"magento|mage-|/skin/frontend/", bl)),
    },
    {
        "id": "90006-shopify",
        "name": "E-Commerce 식별 — Shopify",
        "risk": "informational", "confidence": "certain",
        "description": "Shopify 플랫폼이 식별되었습니다.",
        "solution": "SaaS 플랫폼 특성상 추가 보안 설정을 검토하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "shopify" in h.get("server","").lower()
                                      or bool(re.search(r"shopify|cdn\.shopify", bl)),
    },

    # ── CDN / 클라우드 식별 ────────────────────────────────────────────────────
    {
        "id": "90007-cloudflare",
        "name": "CDN 식별 — Cloudflare",
        "risk": "informational", "confidence": "certain",
        "description": "Cloudflare CDN/WAF가 식별되었습니다.",
        "solution": "Cloudflare 설정에서 불필요한 헤더 노출을 검토하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "cloudflare" in h.get("server","").lower()
                                      or "cf-ray" in h or "cf-cache-status" in h,
    },
    {
        "id": "90007-aws-cf",
        "name": "CDN 식별 — AWS CloudFront",
        "risk": "informational", "confidence": "certain",
        "description": "AWS CloudFront CDN이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-amz-cf-id" in h or "x-amz-cf-pop" in h
                                      or "cloudfront" in h.get("server","").lower(),
    },
    {
        "id": "90007-fastly",
        "name": "CDN 식별 — Fastly",
        "risk": "informational", "confidence": "certain",
        "description": "Fastly CDN이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-fastly-request-id" in h or "fastly" in h.get("server","").lower()
                                      or "x-served-by" in h,
    },
    {
        "id": "90007-akamai",
        "name": "CDN 식별 — Akamai",
        "risk": "informational", "confidence": "firm",
        "description": "Akamai CDN이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "akamai" in h.get("server","").lower()
                                      or "x-akamai-transformed" in h or "x-check-cacheable" in h,
    },
    {
        "id": "90007-azure",
        "name": "클라우드 식별 — Microsoft Azure",
        "risk": "informational", "confidence": "firm",
        "description": "Microsoft Azure 인프라가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-ms-request-id" in h or "x-msedge-ref" in h
                                      or "azure" in h.get("server","").lower(),
    },
    {
        "id": "90007-aws-elb",
        "name": "클라우드 식별 — AWS ELB/ALB",
        "risk": "informational", "confidence": "certain",
        "description": "AWS Elastic Load Balancer가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "awselb" in h.get("set-cookie","").lower()
                                      or "x-amzn-requestid" in h or "x-amzn-trace-id" in h,
    },
    {
        "id": "90007-gcp",
        "name": "클라우드 식별 — Google Cloud",
        "risk": "informational", "confidence": "firm",
        "description": "Google Cloud 인프라가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-goog-request-id" in h or "x-google-backends" in h
                                      or "google frontend" in h.get("server","").lower(),
    },
    {
        "id": "90007-vercel",
        "name": "플랫폼 식별 — Vercel",
        "risk": "informational", "confidence": "certain",
        "description": "Vercel 배포 플랫폼이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-vercel-id" in h or "x-vercel-cache" in h
                                      or "vercel" in h.get("server","").lower(),
    },
    {
        "id": "90007-netlify",
        "name": "플랫폼 식별 — Netlify",
        "risk": "informational", "confidence": "certain",
        "description": "Netlify 배포 플랫폼이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-nf-request-id" in h or "netlify" in h.get("server","").lower(),
    },

    # ── 보안 장비 / 프록시 식별 ────────────────────────────────────────────────
    {
        "id": "90008-nginx-proxy",
        "name": "리버스 프록시 식별",
        "risk": "informational", "confidence": "tentative",
        "description": "리버스 프록시 또는 로드밸런서가 식별되었습니다.",
        "solution": "프록시 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "via" in h or "x-forwarded-server" in h
                                      or "x-proxy-id" in h,
    },
    {
        "id": "90008-f5",
        "name": "보안장비 식별 — F5 BIG-IP",
        "risk": "informational", "confidence": "firm",
        "description": "F5 BIG-IP 로드밸런서/WAF가 식별되었습니다.",
        "solution": "BIG-IP 버전 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"\bts\w+=", h.get("set-cookie",""), re.I))
                                      or "bigipserver" in h.get("set-cookie","").lower(),
    },

    # ── 캐시 제어 ─────────────────────────────────────────────────────────────
    {
        "id": "10015",
        "name": "캐시 제어 헤더 미설정",
        "risk": "informational",
        "confidence": "tentative",
        "description": "민감한 데이터가 캐시될 수 있습니다. Cache-Control 또는 Pragma 헤더가 없습니다.",
        "solution": "Cache-Control: no-store, Pragma: no-cache 헤더를 민감한 페이지에 추가하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: "cache-control" not in h and "pragma" not in h and s == 200,
    },

    # ── 정보 노출 (바디 기반) ─────────────────────────────────────────────────
    {
        "id": "10095",
        "name": "Backup 파일 경로 노출",
        "risk": "medium",
        "confidence": "firm",
        "description": "응답에서 백업 파일 경로 또는 임시 파일 경로가 발견되었습니다.",
        "solution": "백업 파일을 웹 루트 외부로 이동하고 디렉터리 리스팅을 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(
            r"\.(bak|backup|old|orig|tmp|swp|sql|dump)\b", bl)),
    },
    {
        "id": "10096",
        "name": "내부 경로 노출",
        "risk": "low",
        "confidence": "firm",
        "description": "응답 바디에 서버 내부 파일 시스템 경로가 노출되었습니다.",
        "solution": "에러 메시지에서 경로 정보를 제거하고 커스텀 에러 페이지를 사용하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: bool(re.search(
            r"[Cc]:\\[\\a-zA-Z]+|/home/\w+/|/var/www/|/usr/local/", b)),
    },
    {
        "id": "10097",
        "name": "이메일 주소 노출",
        "risk": "informational",
        "confidence": "tentative",
        "description": "응답 바디에서 이메일 주소가 발견되었습니다.",
        "solution": "이메일 주소 노출을 최소화하거나 마스킹 처리하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", b)),
    },
    {
        "id": "10098",
        "name": "주석 내 민감 정보",
        "risk": "informational",
        "confidence": "tentative",
        "description": "HTML/JS 주석에 민감한 정보(TODO, 비밀번호 힌트, 내부 경로 등)가 포함되어 있습니다.",
        "solution": "프로덕션 코드에서 민감한 정보가 담긴 주석을 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(
            r"<!--.*?(password|secret|todo|fixme|hack|admin|key)[^>]*-->", bl, re.DOTALL)),
    },

    # ── CORS 설정 오류 ─────────────────────────────────────────────────────────
    {
        "id": "10098-cors",
        "name": "CORS — 와일드카드 허용 (Access-Control-Allow-Origin: *)",
        "risk": "medium",
        "confidence": "certain",
        "description": "모든 도메인에서의 크로스오리진 요청을 허용합니다. 민감한 API에 적용된 경우 심각한 보안 문제가 될 수 있습니다.",
        "solution": "신뢰할 수 있는 특정 도메인만 허용하도록 CORS 정책을 제한하세요.",
        "reference": "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
        "check": lambda h, b, bl, s: h.get("access-control-allow-origin","").strip() == "*",
    },
    {
        "id": "10099-cors-cred",
        "name": "CORS — 자격증명 + 와일드카드 허용",
        "risk": "high",
        "confidence": "certain",
        "description": "Access-Control-Allow-Credentials: true 와 Access-Control-Allow-Origin: * 가 동시에 설정되어 있습니다. 인증 토큰 탈취가 가능합니다.",
        "solution": "자격증명을 허용할 경우 특정 오리진만 명시하세요.",
        "reference": "https://portswigger.net/web-security/cors",
        "check": lambda h, b, bl, s: h.get("access-control-allow-origin","").strip() == "*"
                                      and "true" in h.get("access-control-allow-credentials","").lower(),
    },

    # ── 기타 취약점 힌트 ─────────────────────────────────────────────────────
    {
        "id": "10050",
        "name": "리디렉션 — 열린 리디렉션 가능성",
        "risk": "medium",
        "confidence": "tentative",
        "description": "외부 URL로의 리디렉션이 감지되었습니다. 열린 리디렉션 취약점이 존재할 수 있습니다.",
        "solution": "리디렉션 대상 URL을 화이트리스트로 검증하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: s in [301,302,303,307,308]
                                      and bool(re.search(r"https?://", h.get("location",""))),
    },
    {
        "id": "10055",
        "name": "소스맵 파일 참조 노출",
        "risk": "low",
        "confidence": "tentative",
        "description": "응답에 JavaScript 소스맵 파일 참조가 포함되어 있습니다. 원본 소스코드가 노출될 수 있습니다.",
        "solution": "프로덕션 환경에서 소스맵 파일을 제거하거나 접근을 제한하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "//# sourcemappingurl=" in bl,
    },
    {
        "id": "10056",
        "name": "GraphQL 엔드포인트 노출",
        "risk": "informational",
        "confidence": "firm",
        "description": "GraphQL 엔드포인트가 노출되어 있습니다. 인트로스펙션이 활성화된 경우 스키마 전체가 유출될 수 있습니다.",
        "solution": "프로덕션 환경에서 GraphQL 인트로스펙션을 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r'"__schema"|"__type"|graphql', bl)),
    },

    # ══════════════════════════════════════════════════════════════════
    # 확장 룰 (OWASP Secure Headers / Nuclei / ZAP / gitleaks 기준)
    # ══════════════════════════════════════════════════════════════════

    # ── 추가 보안 헤더 ─────────────────────────────────────────────────
    {
        "id": "10063-referrer", "name": "Referrer-Policy 헤더 누락", "risk": "low", "confidence": "certain",
        "description": "Referrer-Policy 헤더가 없어 외부 사이트로 Referer 를 통한 정보 유출 가능성이 있습니다.",
        "solution": "Referrer-Policy: no-referrer 또는 strict-origin-when-cross-origin 을 설정하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "referrer-policy" not in h and s == 200,
    },
    {
        "id": "90004-coop", "name": "Cross-Origin-Opener-Policy 누락", "risk": "low", "confidence": "firm",
        "description": "COOP 헤더가 없어 교차 오리진 창 간 격리가 되지 않습니다(XS-Leaks/Spectre 노출).",
        "solution": "Cross-Origin-Opener-Policy: same-origin 을 설정하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "cross-origin-opener-policy" not in h and s == 200,
    },
    {
        "id": "90004-corp", "name": "Cross-Origin-Resource-Policy 누락", "risk": "informational", "confidence": "tentative",
        "description": "CORP 헤더가 없어 리소스가 타 오리진에 임베드될 수 있습니다.",
        "solution": "Cross-Origin-Resource-Policy: same-origin 을 검토하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "cross-origin-resource-policy" not in h and s == 200,
    },
    {
        "id": "10063-xpcdp", "name": "X-Permitted-Cross-Domain-Policies 누락", "risk": "informational", "confidence": "tentative",
        "description": "Adobe 크로스도메인 정책 제어 헤더가 없습니다.",
        "solution": "X-Permitted-Cross-Domain-Policies: none 을 설정하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "x-permitted-cross-domain-policies" not in h and s == 200,
    },
    {
        "id": "10098-cors-methods", "name": "CORS — Allow-Methods 와일드카드", "risk": "low", "confidence": "certain",
        "description": "Access-Control-Allow-Methods 가 * 로 모든 메서드를 허용합니다.",
        "solution": "필요한 메서드만 명시하세요.",
        "reference": "https://portswigger.net/web-security/cors",
        "check": lambda h, b, bl, s: h.get("access-control-allow-methods", "").strip() == "*",
    },
    {
        "id": "10098-cors-headers", "name": "CORS — Allow-Headers 와일드카드", "risk": "low", "confidence": "certain",
        "description": "Access-Control-Allow-Headers 가 * 로 모든 헤더를 허용합니다.",
        "solution": "허용 헤더를 제한하세요.",
        "reference": "https://portswigger.net/web-security/cors",
        "check": lambda h, b, bl, s: h.get("access-control-allow-headers", "").strip() == "*",
    },
    {
        "id": "10038-cspro", "name": "CSP 가 Report-Only 로만 설정", "risk": "medium", "confidence": "firm",
        "description": "Content-Security-Policy-Report-Only 만 있고 실제 강제(CSP)가 없어 XSS 를 차단하지 못합니다.",
        "solution": "테스트 후 Content-Security-Policy 로 강제 적용하세요.",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        "check": lambda h, b, bl, s: "content-security-policy-report-only" in h and "content-security-policy" not in h,
    },
    {
        "id": "10054-samesite-none", "name": "쿠키 SameSite=None + Secure 누락", "risk": "medium", "confidence": "firm",
        "description": "SameSite=None 쿠키에 Secure 가 없어 최신 브라우저에서 거부되거나 평문 전송됩니다.",
        "solution": "SameSite=None 쿠키에는 반드시 Secure 를 함께 설정하세요.",
        "reference": "https://owasp.org/www-community/SameSite",
        "check": lambda h, b, bl, s: "samesite=none" in h.get("set-cookie", "").lower()
                                      and "secure" not in h.get("set-cookie", "").lower(),
    },
    {
        "id": "10037-via", "name": "Via 헤더 — 프록시 정보 노출", "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Via 헤더로 프록시/캐시 정보가 노출됩니다: {h.get('via','')}",
        "solution": "Via 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "via" in h,
    },

    # ── 시크릿/토큰 노출 (gitleaks 계열) ───────────────────────────────
    {
        "id": "secret-aws", "name": "AWS Access Key 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 AWS Access Key ID(AKIA…) 로 보이는 문자열이 있습니다.",
        "solution": "키를 즉시 폐기·회전하고 응답에서 제거하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", b or "")),
    },
    {
        "id": "secret-gcp", "name": "Google API Key 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 Google API 키(AIza…) 로 보이는 문자열이 있습니다.",
        "solution": "키를 폐기·제한하고 응답에서 제거하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"\bAIza[0-9A-Za-z_\-]{35}\b", b or "")),
    },
    {
        "id": "secret-github", "name": "GitHub 토큰 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 GitHub 토큰(ghp_/gho_/github_pat_) 이 노출됩니다.",
        "solution": "토큰을 폐기하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|github_pat_[0-9A-Za-z_]{22,}", b or "")),
    },
    {
        "id": "secret-slack", "name": "Slack 토큰/웹훅 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 Slack 토큰(xox…) 또는 웹훅 URL 이 노출됩니다.",
        "solution": "토큰/웹훅을 폐기하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"xox[baprs]-[0-9A-Za-z-]{10,}|hooks\.slack\.com/services/", b or "")),
    },
    {
        "id": "secret-stripe", "name": "Stripe 라이브 키 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 Stripe 라이브 시크릿 키(sk_live_) 가 노출됩니다.",
        "solution": "키를 즉시 폐기하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"\bsk_live_[0-9A-Za-z]{24,}\b|\brk_live_[0-9A-Za-z]{24,}\b", b or "")),
    },
    {
        "id": "secret-jwt", "name": "JWT 토큰 노출", "risk": "medium", "confidence": "firm",
        "description": "응답 본문에 JWT 로 보이는 토큰이 노출됩니다(민감 클레임·세션 가능).",
        "solution": "토큰이 본문에 노출되지 않도록 하세요.",
        "reference": "https://portswigger.net/web-security/jwt",
        "check": lambda h, b, bl, s: bool(re.search(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", b or "")),
    },
    {
        "id": "secret-pw-json", "name": "패스워드 필드 노출(JSON)", "risk": "high", "confidence": "tentative",
        "description": "응답 JSON 에 password/passwd 값이 평문으로 포함되어 있을 수 있습니다.",
        "solution": "비밀번호 등 민감 필드를 응답에서 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r'"(password|passwd|pwd)"\s*:\s*"[^"]{3,}"', b or "", re.I)),
    },

    # ── 프레임워크 디버그/에러 페이지 ──────────────────────────────────
    {
        "id": "debug-django", "name": "Django DEBUG 페이지 노출", "risk": "high", "confidence": "certain",
        "description": "Django 디버그 페이지가 노출되어 소스·설정·환경변수가 유출됩니다.",
        "solution": "프로덕션에서 DEBUG=False 로 설정하세요.",
        "reference": "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
        "check": lambda h, b, bl, s: "you're seeing this error because you have" in bl or "django.core.exceptions" in bl,
    },
    {
        "id": "debug-flask", "name": "Werkzeug/Flask 디버거 노출", "risk": "high", "confidence": "certain",
        "description": "Werkzeug 대화형 디버거가 노출됩니다. PIN 우회 시 원격 코드 실행이 가능합니다.",
        "solution": "프로덕션에서 디버그 모드를 끄세요.",
        "reference": "https://werkzeug.palletsprojects.com/",
        "check": lambda h, b, bl, s: "werkzeug debugger" in bl or "the console has been disabled" in bl,
    },
    {
        "id": "debug-rails", "name": "Rails 예외 페이지 노출", "risk": "high", "confidence": "certain",
        "description": "Rails 상세 예외 페이지가 노출되어 소스/스택이 유출됩니다.",
        "solution": "config.consider_all_requests_local = false 로 설정하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "action controller: exception caught" in bl or "actionview::template::error" in bl,
    },
    {
        "id": "debug-laravel", "name": "Laravel 디버그(Ignition) 노출", "risk": "high", "confidence": "certain",
        "description": "Laravel Whoops/Ignition 디버그 페이지가 노출됩니다(CVE-2021-3129 이력).",
        "solution": "APP_DEBUG=false 로 설정하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: ("whoops" in bl and "laravel" in bl) or "illuminate\\" in bl or "ignition" in bl and "laravel" in bl,
    },
    {
        "id": "debug-spring", "name": "Spring Whitelabel 에러 노출", "risk": "medium", "confidence": "firm",
        "description": "Spring Boot Whitelabel 에러 페이지가 노출됩니다(스택/버전 유출 가능).",
        "solution": "server.error.whitelabel.enabled=false 및 상세 에러 숨김.",
        "reference": "",
        "check": lambda h, b, bl, s: "whitelabel error page" in bl,
    },
    {
        "id": "debug-aspnet", "name": "ASP.NET 상세 오류(YSOD) 노출", "risk": "high", "confidence": "certain",
        "description": "ASP.NET 노란 오류 화면이 노출되어 스택/소스가 유출됩니다.",
        "solution": "customErrors mode=On, <deployment retail=true> 설정.",
        "reference": "",
        "check": lambda h, b, bl, s: "server error in '/' application" in bl and "stack trace" in bl,
    },
    {
        "id": "debug-symfony", "name": "Symfony 프로파일러/예외 노출", "risk": "medium", "confidence": "firm",
        "description": "Symfony 디버그 툴바/예외 페이지가 노출됩니다.",
        "solution": "APP_ENV=prod, APP_DEBUG=0 으로 설정하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "symfony\\component" in bl or "sf-toolbar" in bl or "x-debug-token" in h,
    },
    {
        "id": "debug-php", "name": "PHP 오류/경고 노출", "risk": "medium", "confidence": "firm",
        "description": "PHP Fatal/Warning/Notice 등 오류가 노출되어 경로·코드가 유출됩니다.",
        "solution": "display_errors=Off 로 설정하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"<b>(fatal error|warning|notice|parse error)</b>|on line <b>\d+</b>", bl)),
    },
    {
        "id": "debug-phpinfo", "name": "phpinfo() 노출", "risk": "high", "confidence": "certain",
        "description": "phpinfo() 출력이 노출되어 서버 구성 전체가 유출됩니다.",
        "solution": "phpinfo 페이지를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "phpinfo()" in bl or (">php version<" in bl and "configuration" in bl and "php credits" in bl),
    },

    # ── 노출 파일/디렉토리 ─────────────────────────────────────────────
    {
        "id": "expose-dirlist", "name": "디렉토리 리스팅 노출", "risk": "medium", "confidence": "firm",
        "description": "디렉토리 인덱스가 노출되어 파일 구조가 공개됩니다.",
        "solution": "Options -Indexes 등으로 디렉토리 리스팅을 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: ("<title>index of /" in bl or "directory listing for" in bl) and "parent directory" in bl or "<title>index of /" in bl,
    },
    {
        "id": "expose-git", "name": ".git 저장소 노출", "risk": "high", "confidence": "certain",
        "description": ".git 설정/객체가 노출되어 전체 소스 복원이 가능합니다.",
        "solution": ".git 디렉토리 외부 접근을 차단하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "[core]" in bl and "repositoryformatversion" in bl,
    },
    {
        "id": "expose-env", "name": ".env 환경파일 노출", "risk": "critical", "confidence": "certain",
        "description": ".env 파일이 노출되어 DB/API 키 등 시크릿이 유출됩니다.",
        "solution": ".env 접근을 차단하고 노출된 시크릿을 폐기하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"(app_key|db_password|db_username|aws_secret|secret_key)\s*=", bl)),
    },
    {
        "id": "expose-swagger", "name": "API 문서(Swagger/OpenAPI) 노출", "risk": "informational", "confidence": "firm",
        "description": "Swagger/OpenAPI 문서가 노출되어 전체 API 표면이 공개됩니다.",
        "solution": "프로덕션에서 API 문서 접근을 제한하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r'"swagger"\s*:|"openapi"\s*:|swagger-ui', bl)),
    },
    {
        "id": "expose-actuator", "name": "Spring Actuator 노출", "risk": "high", "confidence": "firm",
        "description": "Spring Boot Actuator 엔드포인트(env/heapdump 등)가 노출됩니다.",
        "solution": "management.endpoints 노출을 제한하고 인증을 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r'"_links"\s*:.*"(env|health|heapdump|beans|mappings)"|activeprofiles', bl)),
    },
    {
        "id": "expose-ds-store", "name": ".DS_Store / 백업 흔적 노출", "risk": "low", "confidence": "tentative",
        "description": "OS/에디터 임시·백업 파일 흔적이 노출됩니다.",
        "solution": "불필요한 파일을 제거하고 접근을 차단하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "bud1" in bl and ".ds_store" in bl,
    },

    # ══════════════════════════════════════════════════════════════════
    # 2차 확장 — 시크릿 패턴 대량 / 기술 지문 / 노출 서비스 / 정보 유출
    # ══════════════════════════════════════════════════════════════════

    # ── 시크릿/토큰 (gitleaks 계열 다수) ───────────────────────────────
    {"id": "sec-openai", "name": "OpenAI API 키 노출", "risk": "high", "confidence": "firm",
     "description": "OpenAI 키(sk-…) 로 보이는 문자열 노출.", "solution": "키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b|\bsk-proj-[A-Za-z0-9_-]{20,}\b", b or ""))},
    {"id": "sec-anthropic", "name": "Anthropic API 키 노출", "risk": "high", "confidence": "firm",
     "description": "Anthropic 키(sk-ant-…) 노출.", "solution": "키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", b or ""))},
    {"id": "sec-gitlab", "name": "GitLab PAT 노출", "risk": "high", "confidence": "firm",
     "description": "GitLab Personal Access Token(glpat-…) 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bglpat-[A-Za-z0-9_-]{20}\b", b or ""))},
    {"id": "sec-twilio", "name": "Twilio 자격증명 노출", "risk": "high", "confidence": "firm",
     "description": "Twilio Account SID/Auth Token 노출.", "solution": "자격증명 회전.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bAC[a-z0-9]{32}\b|\bSK[a-z0-9]{32}\b", b or "", re.I)) and "twilio" in bl},
    {"id": "sec-sendgrid", "name": "SendGrid API 키 노출", "risk": "high", "confidence": "firm",
     "description": "SendGrid 키(SG.…) 노출.", "solution": "키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", b or ""))},
    {"id": "sec-mailgun", "name": "Mailgun API 키 노출", "risk": "high", "confidence": "firm",
     "description": "Mailgun 키(key-…) 노출.", "solution": "키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bkey-[0-9a-f]{32}\b", b or "")) and "mailgun" in bl},
    {"id": "sec-square", "name": "Square 액세스 토큰 노출", "risk": "high", "confidence": "firm",
     "description": "Square 토큰(sq0atp/EAAA…) 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bsq0(atp|csp)-[A-Za-z0-9_-]{22,}\b|\bEAAA[A-Za-z0-9]{60}\b", b or ""))},
    {"id": "sec-paypal", "name": "PayPal Braintree 토큰 노출", "risk": "high", "confidence": "firm",
     "description": "Braintree 액세스 토큰 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", b or ""))},
    {"id": "sec-npm", "name": "npm 토큰 노출", "risk": "high", "confidence": "firm",
     "description": "npm 토큰(npm_…) 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bnpm_[A-Za-z0-9]{36}\b", b or ""))},
    {"id": "sec-heroku", "name": "Heroku API 키 노출", "risk": "high", "confidence": "tentative",
     "description": "Heroku API 키(UUID) 노출 의심.", "solution": "키 회전.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: "heroku" in bl and bool(re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", b or ""))},
    {"id": "sec-cloudflare", "name": "Cloudflare API 토큰 노출", "risk": "high", "confidence": "tentative",
     "description": "Cloudflare API 토큰 노출 의심.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: "cloudflare" in bl and bool(re.search(r"\b[A-Za-z0-9_-]{40}\b", b or "")) and "api_token" in bl},
    {"id": "sec-discord", "name": "Discord 토큰/웹훅 노출", "risk": "medium", "confidence": "firm",
     "description": "Discord 봇 토큰 또는 웹훅 URL 노출.", "solution": "폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"discord(app)?\.com/api/webhooks/\d+/", b or "")) or bool(re.search(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b", b or ""))},
    {"id": "sec-telegram", "name": "Telegram 봇 토큰 노출", "risk": "medium", "confidence": "firm",
     "description": "Telegram 봇 토큰 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", b or ""))},
    {"id": "sec-facebook", "name": "Facebook 액세스 토큰 노출", "risk": "medium", "confidence": "tentative",
     "description": "Facebook 토큰(EAACEdEose…) 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bEAACEdEose0cBA[0-9A-Za-z]+\b", b or ""))},
    {"id": "sec-gcp-sa", "name": "GCP 서비스계정 키(JSON) 노출", "risk": "critical", "confidence": "certain",
     "description": "GCP 서비스계정 키 JSON(private_key 포함) 노출.", "solution": "즉시 키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: '"type": "service_account"' in bl or ('"private_key_id"' in bl and '"client_email"' in bl)},
    {"id": "sec-azure-storage", "name": "Azure Storage 키/연결문자열 노출", "risk": "high", "confidence": "firm",
     "description": "Azure Storage 연결문자열/AccountKey 노출.", "solution": "키 회전.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: "accountkey=" in bl and "core.windows.net" in bl},
    {"id": "sec-s3url", "name": "S3 버킷 URL/리스팅 노출", "risk": "medium", "confidence": "firm",
     "description": "S3 버킷 리스팅(XML) 또는 버킷 URL 노출.", "solution": "버킷 권한을 검토하세요.", "reference": "",
     "check": lambda h, b, bl, s: "<listbucketresult" in bl or bool(re.search(r"[a-z0-9.-]+\.s3\.amazonaws\.com", bl))},
    {"id": "sec-basicurl", "name": "URL 내 자격증명 노출", "risk": "high", "confidence": "firm",
     "description": "응답에 user:pass@host 형태의 자격증명 포함 URL 이 있습니다.", "solution": "자격증명 제거.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"[a-z]+://[^/\s:@]+:[^/\s:@]+@[a-z0-9.-]+", b or "", re.I))},
    {"id": "sec-generic-key", "name": "일반 API/시크릿 키 할당 노출", "risk": "medium", "confidence": "tentative",
     "description": "api_key/secret/token 등에 값이 하드코딩된 형태가 노출됩니다.", "solution": "시크릿을 응답/코드에서 제거.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", b or "", re.I))},
    {"id": "sec-authbearer", "name": "응답 내 Authorization Bearer 노출", "risk": "medium", "confidence": "tentative",
     "description": "응답 본문에 Authorization: Bearer 토큰이 노출됩니다.", "solution": "토큰 노출 제거.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"authorization['\"]?\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._-]{16,}", b or "", re.I))},

    # ── 노출 서비스/패널 ───────────────────────────────────────────────
    {"id": "svc-phpmyadmin", "name": "phpMyAdmin 노출", "risk": "medium", "confidence": "firm",
     "description": "phpMyAdmin 로그인/패널 노출.", "solution": "접근을 제한하세요.", "reference": "",
     "check": lambda h, b, bl, s: "phpmyadmin" in bl and ("pma_username" in bl or "phpmyadmin" in bl and "login" in bl)},
    {"id": "svc-adminer", "name": "Adminer 노출", "risk": "medium", "confidence": "firm",
     "description": "Adminer DB 관리 도구 노출.", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "adminer" in bl and "login" in bl},
    {"id": "svc-jenkins", "name": "Jenkins 노출", "risk": "medium", "confidence": "firm",
     "description": "Jenkins 대시보드 노출.", "solution": "인증/접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "x-jenkins" in h or "jenkins" in bl and "dashboard" in bl},
    {"id": "svc-grafana", "name": "Grafana 노출", "risk": "low", "confidence": "firm",
     "description": "Grafana 인스턴스 노출.", "solution": "인증/접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "grafana" in bl and ("grafanabootdata" in bl or "grafana" in h.get("set-cookie",""))},
    {"id": "svc-kibana", "name": "Kibana/Elasticsearch 노출", "risk": "medium", "confidence": "firm",
     "description": "Kibana 또는 Elasticsearch 정보가 노출됩니다.", "solution": "인증/접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "kbn-name" in h or '"cluster_name"' in bl or "kibana" in bl and "bootstrap" in bl},
    {"id": "svc-prometheus", "name": "Prometheus/메트릭 노출", "risk": "low", "confidence": "firm",
     "description": "Prometheus 메트릭 엔드포인트 노출.", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"# help \w+|# type \w+ (counter|gauge|histogram)", bl))},
    {"id": "svc-apachestatus", "name": "Apache server-status 노출", "risk": "medium", "confidence": "firm",
     "description": "mod_status(server-status) 가 노출되어 요청/워커 정보가 유출됩니다.", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "apache server status" in bl or ("server uptime" in bl and "requests currently being processed" in bl)},
    {"id": "svc-nginxstatus", "name": "Nginx stub_status 노출", "risk": "low", "confidence": "firm",
     "description": "Nginx stub_status 노출.", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "active connections:" in bl and "server accepts handled requests" in bl},
    {"id": "svc-wp-users", "name": "WordPress 사용자 열거(wp-json)", "risk": "medium", "confidence": "firm",
     "description": "wp-json/wp/v2/users 로 사용자 목록이 노출됩니다.", "solution": "REST users 엔드포인트를 제한하세요.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'"slug"\s*:.*"wp:author"|/wp-json/wp/v2/users', bl))},
    {"id": "svc-securitytxt", "name": "security.txt 존재", "risk": "informational", "confidence": "certain",
     "description": "security.txt 가 존재합니다(정보).", "solution": "정상적인 보안 연락처 공개입니다.", "reference": "https://securitytxt.org/",
     "check": lambda h, b, bl, s: "contact:" in bl and ("expires:" in bl or "encryption:" in bl) and len(bl) < 4000},

    # ── 추가 기술 지문 (Wappalyzer 계열) ──────────────────────────────
    {"id": "fp-jquery", "name": "라이브러리 식별 — jQuery", "risk": "informational", "confidence": "firm",
     "description": lambda h, **_: "jQuery 사용 감지.", "solution": "구버전 시 알려진 XSS 취약점 확인.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"jquery[.-]?\d|jquery\.min\.js|jquery\.js", bl))},
    {"id": "fp-react", "name": "프레임워크 식별 — React", "risk": "informational", "confidence": "firm",
     "description": "React 사용 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "data-reactroot" in bl or "react-dom" in bl or "__react" in bl},
    {"id": "fp-vue", "name": "프레임워크 식별 — Vue.js", "risk": "informational", "confidence": "firm",
     "description": "Vue.js 사용 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "data-v-" in bl or "vue.js" in bl or "__vue__" in bl},
    {"id": "fp-angular", "name": "프레임워크 식별 — Angular", "risk": "informational", "confidence": "firm",
     "description": "Angular 사용 감지.", "solution": "AngularJS 구버전은 CSTI 위험.", "reference": "",
     "check": lambda h, b, bl, s: "ng-version" in bl or "ng-app" in bl or "angular.js" in bl},
    {"id": "fp-bootstrap", "name": "라이브러리 식별 — Bootstrap", "risk": "informational", "confidence": "tentative",
     "description": "Bootstrap 사용 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "bootstrap.min.css" in bl or "bootstrap.min.js" in bl},
    {"id": "fp-ga", "name": "분석도구 — Google Analytics/GTM", "risk": "informational", "confidence": "firm",
     "description": "Google Analytics/Tag Manager 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "googletagmanager.com/gtm" in bl or "google-analytics.com/analytics" in bl or "gtag(" in bl},
    {"id": "fp-sentry", "name": "모니터링 — Sentry", "risk": "informational", "confidence": "firm",
     "description": "Sentry DSN/SDK 감지(DSN 노출 시 이벤트 위조 가능).", "solution": "공개 DSN 노출 검토.", "reference": "",
     "check": lambda h, b, bl, s: "sentry-cdn" in bl or "@sentry" in bl or bool(re.search(r"https://[0-9a-f]+@[a-z0-9.]*sentry", bl))},
    {"id": "fp-cloudfront-h", "name": "CDN 식별 — CloudFront(헤더)", "risk": "informational", "confidence": "firm",
     "description": "AWS CloudFront 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "x-amz-cf-id" in h or "cloudfront" in h.get("via","")},
    {"id": "fp-openresty", "name": "서버 식별 — OpenResty", "risk": "informational", "confidence": "certain",
     "description": "OpenResty(Nginx+Lua) 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "openresty" in h.get("server","")},
    {"id": "fp-kestrel", "name": "서버 식별 — Kestrel(.NET)", "risk": "informational", "confidence": "certain",
     "description": "Kestrel(.NET Core) 감지.", "solution": "리버스 프록시 뒤 배치 권장.", "reference": "",
     "check": lambda h, b, bl, s: "kestrel" in h.get("server","")},
    {"id": "fp-ghost", "name": "CMS 식별 — Ghost", "risk": "informational", "confidence": "firm",
     "description": "Ghost CMS 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "ghost" in h.get("x-powered-by","") or "content=\"ghost" in bl},
    {"id": "fp-mediawiki", "name": "플랫폼 식별 — MediaWiki", "risk": "informational", "confidence": "firm",
     "description": "MediaWiki 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "mediawiki" in bl or "x-powered-by" in h and "mediawiki" in h.get("x-powered-by","")},
    {"id": "fp-atlassian", "name": "플랫폼 식별 — Atlassian(Jira/Confluence)", "risk": "informational", "confidence": "firm",
     "description": "Jira/Confluence 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "atl-traceid" in h or "x-confluence-request-time" in h or "jira.webresources" in bl},

    # ── 추가 정보 유출/설정 ────────────────────────────────────────────
    {"id": "info-xruntime", "name": "X-Runtime — 응답시간 노출(Rails)", "risk": "informational", "confidence": "certain",
     "description": "X-Runtime 헤더로 처리시간이 노출됩니다(타이밍 공격 보조).", "solution": "헤더 제거.", "reference": "",
     "check": lambda h, b, bl, s: "x-runtime" in h},
    {"id": "info-xgenerator", "name": "X-Generator/Generator — 제품·버전 노출", "risk": "low", "confidence": "certain",
     "description": lambda h, **_: f"Generator 정보 노출: {h.get('x-generator','')}", "solution": "제거.", "reference": "",
     "check": lambda h, b, bl, s: "x-generator" in h or bool(re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']+', bl))},
    {"id": "info-xdrupal", "name": "Drupal 캐시/동적 헤더 노출", "risk": "informational", "confidence": "firm",
     "description": "X-Drupal-* 헤더 노출.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "x-drupal-cache" in h or "x-drupal-dynamic-cache" in h},
    {"id": "info-xpingback", "name": "WordPress XML-RPC(Pingback) 노출", "risk": "low", "confidence": "certain",
     "description": "X-Pingback 헤더로 xmlrpc.php 노출(무차별/증폭 악용).", "solution": "xmlrpc 비활성화 검토.", "reference": "",
     "check": lambda h, b, bl, s: "x-pingback" in h or "xmlrpc.php" in bl},
    {"id": "info-etag-inode", "name": "ETag inode 노출(Apache)", "risk": "informational", "confidence": "tentative",
     "description": "ETag 에 inode 정보가 포함되어 있을 수 있습니다.", "solution": "FileETag MTime Size 로 변경.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'^"?[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"?$', h.get("etag","")))},
    {"id": "info-xssprotection-off", "name": "X-XSS-Protection 비활성(0)", "risk": "low", "confidence": "firm",
     "description": "X-XSS-Protection: 0 으로 브라우저 XSS 필터를 끕니다(레거시).", "solution": "CSP 로 대체 권장.", "reference": "",
     "check": lambda h, b, bl, s: h.get("x-xss-protection","").strip().startswith("0")},
    {"id": "info-allow-dangerous", "name": "위험 HTTP 메서드 허용(Allow)", "risk": "medium", "confidence": "firm",
     "description": lambda h, **_: f"Allow 헤더에 위험 메서드 노출: {h.get('allow','')}", "solution": "PUT/DELETE/TRACE 등 불필요 메서드 비활성화.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"\b(put|delete|trace|connect|patch)\b", h.get("allow","")))},
    {"id": "info-session-url", "name": "세션 ID URL 노출", "risk": "medium", "confidence": "firm",
     "description": "URL 에 세션 ID(jsessionid/phpsessid 등)가 노출됩니다.", "solution": "세션을 쿠키로만 전달하세요.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"(jsessionid|phpsessid|sid|sessionid)=[A-Za-z0-9]{8,}", bl))},
    {"id": "info-insecure-form", "name": "폼 action 이 평문(http) 전송", "risk": "medium", "confidence": "firm",
     "description": "form action 이 http:// 로 민감정보가 평문 전송될 수 있습니다.", "solution": "https 로 변경하세요.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'<form[^>]+action=["\']http://', bl))},
    {"id": "info-pw-autocomplete", "name": "패스워드 필드 autocomplete 미차단", "risk": "low", "confidence": "tentative",
     "description": "password 입력에 autocomplete=off 가 없어 브라우저 저장 위험.", "solution": "민감 필드에 autocomplete=off.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'<input[^>]+type=["\']?password["\']?(?![^>]*autocomplete)', bl))},
    {"id": "info-private-ip-body", "name": "내부 IP 노출(본문)", "risk": "low", "confidence": "tentative",
     "description": "응답 본문에 사설 IP 대역이 노출됩니다.", "solution": "내부 IP 노출을 제거하세요.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b", b or ""))},

    # ── 추가 DB/스택트레이스 ───────────────────────────────────────────
    {"id": "err-db2", "name": "DB2 에러 노출", "risk": "medium", "confidence": "firm",
     "description": "IBM DB2 오류 메시지 노출.", "solution": "상세 오류 숨김.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"sql\d{4}n|db2 sql error", bl))},
    {"id": "err-sybase", "name": "Sybase/ASE 에러 노출", "risk": "medium", "confidence": "firm",
     "description": "Sybase 오류 메시지 노출.", "solution": "상세 오류 숨김.", "reference": "",
     "check": lambda h, b, bl, s: "sybase message" in bl or "com.sybase.jdbc" in bl},
    {"id": "err-go-panic", "name": "Go 패닉/스택 노출", "risk": "medium", "confidence": "firm",
     "description": "Go 런타임 패닉 스택이 노출됩니다.", "solution": "recover 로 처리하고 상세 노출 제거.", "reference": "",
     "check": lambda h, b, bl, s: "goroutine " in bl and "runtime.gopanic" in bl or "panic: runtime error" in bl},
    {"id": "err-dotnet-stack", "name": ".NET 스택트레이스 노출", "risk": "medium", "confidence": "firm",
     "description": ".NET 예외/스택이 노출됩니다.", "solution": "customErrors 로 상세 숨김.", "reference": "",
     "check": lambda h, b, bl, s: "system.web." in bl and "at system." in bl or "microsoft.aspnetcore" in bl and "stack trace" in bl},

    # ══════════════════════════════════════════════════════════════════
    # 3차 확장 — 취약 라이브러리(Retire.js) / 제품 CVE 지문 / 노출 파일 추가
    # ══════════════════════════════════════════════════════════════════

    # ── 취약/구버전 라이브러리 (Retire.js 계열, tentative) ─────────────
    {"id": "lib-jquery-old", "name": "취약 jQuery(<3.5.0)", "risk": "medium", "confidence": "tentative",
     "description": "jQuery 3.5.0 미만은 XSS(CVE-2020-11022/11023) 취약.", "solution": "jQuery 3.5+ 로 업그레이드.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"jquery[/-]?(\d+\.\d+\.\d+)", (3, 5, 0))},
    {"id": "lib-angularjs", "name": "AngularJS(1.x) — EOL/CSTI 위험", "risk": "medium", "confidence": "tentative",
     "description": "AngularJS 1.x 는 지원 종료·클라이언트 템플릿 인젝션 위험.", "solution": "최신 Angular 로 마이그레이션.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"angular[.-]?(1\.\d+\.\d+)", (2, 0, 0))},
    {"id": "lib-bootstrap-old", "name": "취약 Bootstrap(<3.4/<4.3.1)", "risk": "low", "confidence": "tentative",
     "description": "구버전 Bootstrap XSS(CVE-2019-8331 등).", "solution": "최신 Bootstrap 사용.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"bootstrap[/-]?(\d+\.\d+\.\d+)", (4, 3, 1))},
    {"id": "lib-lodash-old", "name": "취약 Lodash(<4.17.21)", "risk": "medium", "confidence": "tentative",
     "description": "구버전 Lodash 프로토타입 오염(CVE-2020-8203 등).", "solution": "lodash 4.17.21+.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"lodash[/-]?(\d+\.\d+\.\d+)", (4, 17, 21))},
    {"id": "lib-moment-old", "name": "취약 Moment.js(<2.29.4)", "risk": "low", "confidence": "tentative",
     "description": "구버전 moment.js ReDoS/경로 취약.", "solution": "moment 2.29.4+ 또는 대체.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"moment[/-]?(\d+\.\d+\.\d+)", (2, 29, 4))},
    {"id": "lib-vue2-eol", "name": "Vue 2 — EOL", "risk": "low", "confidence": "tentative",
     "description": "Vue 2.x 는 지원 종료.", "solution": "Vue 3 마이그레이션.", "reference": "",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"vue[/-]?(2\.\d+\.\d+)", (3, 0, 0))},

    # ── 제품/CVE 지문 ─────────────────────────────────────────────────
    {"id": "cve-struts", "name": "Apache Struts 흔적", "risk": "medium", "confidence": "tentative",
     "description": "Struts(.action/.do) 흔적 — CVE-2017-5638(RCE) 등 이력.", "solution": "최신 패치 적용.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"\.action(\?|\"|')|struts\.token|org\.apache\.struts", bl))},
    {"id": "cve-weblogic", "name": "Oracle WebLogic 콘솔 노출", "risk": "high", "confidence": "tentative",
     "description": "WebLogic 콘솔/uddiexplorer 노출 — 다수 RCE(CVE-2020-14882 등).", "solution": "콘솔 접근 제한·패치.", "reference": "",
     "check": lambda h, b, bl, s: "weblogic" in bl and ("console" in bl or "uddiexplorer" in bl)},
    {"id": "cve-exchange", "name": "MS Exchange OWA/ECP 노출", "risk": "medium", "confidence": "tentative",
     "description": "Exchange OWA/ECP/Autodiscover 노출 — ProxyLogon 등 이력.", "solution": "패치·접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "x-owa-version" in h or "/owa/auth" in bl or "outlook web app" in bl},
    {"id": "cve-citrix", "name": "Citrix ADC/Gateway 흔적", "risk": "medium", "confidence": "tentative",
     "description": "Citrix Netscaler/Gateway 흔적 — CVE-2019-19781/CVE-2023-4966 이력.", "solution": "패치.", "reference": "",
     "check": lambda h, b, bl, s: "ns_af" in h.get("set-cookie","") or "citrix" in bl and "gateway" in bl or "/vpn/index.html" in bl},
    {"id": "cve-confluence", "name": "Atlassian Confluence 노출", "risk": "medium", "confidence": "tentative",
     "description": "Confluence 노출 — OGNL RCE(CVE-2021-26084/CVE-2022-26134) 이력.", "solution": "패치.", "reference": "",
     "check": lambda h, b, bl, s: "confluence" in bl and ("x-confluence-request-time" in h or "com.atlassian.confluence" in bl)},
    {"id": "cve-gitlab", "name": "GitLab 노출", "risk": "low", "confidence": "tentative",
     "description": "GitLab 노출 — 다수 취약점 이력.", "solution": "최신 버전 유지.", "reference": "",
     "check": lambda h, b, bl, s: "gitlab" in bl and ("gitlab_session" in h.get("set-cookie","") or "gon.gitlab" in bl)},
    {"id": "cve-spring4shell", "name": "Spring 프레임워크(Spring4Shell 표면)", "risk": "low", "confidence": "tentative",
     "description": "Spring MVC/WebFlux 흔적 — CVE-2022-22965(Spring4Shell) 대상 가능.", "solution": "Spring 패치 확인.", "reference": "",
     "check": lambda h, b, bl, s: "org.springframework" in bl and ("bindingresult" in bl or "class.module" in bl)},
    {"id": "cve-log4shell-refl", "name": "Log4Shell 페이로드 반사", "risk": "medium", "confidence": "tentative",
     "description": "응답에 ${jndi:...} 페이로드가 반사됩니다(로그 인젝션 표면).", "solution": "Log4j 패치.", "reference": "",
     "check": lambda h, b, bl, s: "${jndi:" in bl or "jndi:ldap" in bl},
    {"id": "svc-solr", "name": "Apache Solr 노출", "risk": "medium", "confidence": "firm",
     "description": "Solr 관리/쿼리 노출 — RCE 이력.", "solution": "접근 제한·패치.", "reference": "",
     "check": lambda h, b, bl, s: '"responseheader"' in bl and ("solr" in bl or '"qtime"' in bl)},
    {"id": "svc-couchdb", "name": "CouchDB/Redis 등 DB 응답 노출", "risk": "medium", "confidence": "tentative",
     "description": "CouchDB/Redis/Mongo 등의 응답 흔적이 노출됩니다.", "solution": "인증·접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: '"couchdb":"welcome"' in bl or "redis_version:" in bl or '"ismaster"' in bl},

    # ── 노출 파일/설정 추가 ────────────────────────────────────────────
    {"id": "expose-webconfig", "name": "web.config 노출", "risk": "high", "confidence": "firm",
     "description": "IIS web.config 노출 — 연결문자열/설정 유출.", "solution": "접근 차단.", "reference": "",
     "check": lambda h, b, bl, s: "<configuration>" in bl and ("<connectionstrings" in bl or "<system.web" in bl)},
    {"id": "expose-htaccess", "name": ".htaccess/.htpasswd 노출", "risk": "high", "confidence": "firm",
     "description": ".htaccess/.htpasswd 노출.", "solution": "접근 차단.", "reference": "",
     "check": lambda h, b, bl, s: "rewriteengine" in bl or bool(re.search(r"^[a-z0-9_-]+:\$apr1\$", b or "", re.I | re.M))},
    {"id": "expose-composer", "name": "composer.json/lock 노출", "risk": "low", "confidence": "firm",
     "description": "PHP composer 의존성 파일 노출(구성/버전 유출).", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: '"require"' in bl and ("composer" in bl or '"packages"' in bl and '"dist"' in bl)},
    {"id": "expose-packagejson", "name": "package.json 노출", "risk": "low", "confidence": "firm",
     "description": "Node package.json 노출(의존성/스크립트 유출).", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: '"dependencies"' in bl and '"scripts"' in bl and '"name"' in bl},
    {"id": "expose-npmrc", "name": ".npmrc/.pypirc 노출", "risk": "high", "confidence": "firm",
     "description": ".npmrc/.pypirc 노출(레지스트리 토큰 유출 가능).", "solution": "접근 차단·토큰 폐기.", "reference": "",
     "check": lambda h, b, bl, s: "_authtoken" in bl or "//registry.npmjs.org/:_authToken".lower() in bl or "[pypi]" in bl and "password" in bl},
    {"id": "expose-wpconfig", "name": "wp-config 백업 노출", "risk": "critical", "confidence": "firm",
     "description": "wp-config 백업 노출 — DB 자격증명/솔트 유출.", "solution": "즉시 제거·자격증명 변경.", "reference": "",
     "check": lambda h, b, bl, s: "db_password" in bl and "wp_" in bl and "define(" in bl},
    {"id": "expose-sourcemap", "name": "JS 소스맵 파일 노출", "risk": "low", "confidence": "firm",
     "description": ".map 소스맵이 노출되어 원본 소스가 복원될 수 있습니다.", "solution": "프로덕션 소스맵 제거.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'\{"version"\s*:\s*3\s*,\s*"(file|sources|mappings)"', bl)) or "x-sourcemap" in h},
    {"id": "expose-idea", "name": "IDE 설정(.idea/.vscode) 노출", "risk": "low", "confidence": "tentative",
     "description": "IDE 프로젝트 설정 노출.", "solution": "접근 차단.", "reference": "",
     "check": lambda h, b, bl, s: "<project version" in bl and "component name" in bl or "workspace.xml" in bl},
    {"id": "expose-backup-archive", "name": "백업 아카이브 노출(.sql/.zip/.tar.gz)", "risk": "medium", "confidence": "tentative",
     "description": "본문/링크에 백업 아카이브 참조가 있습니다.", "solution": "백업 파일을 웹 루트 밖으로 이동.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'href=["\'][^"\']+\.(sql|zip|tar\.gz|tgz|bak|7z|rar)\b', bl))},
    {"id": "expose-crossdomain", "name": "crossdomain.xml 과대 허용", "risk": "medium", "confidence": "firm",
     "description": "crossdomain.xml 이 * 로 모든 도메인을 허용합니다.", "solution": "허용 도메인을 제한하세요.", "reference": "",
     "check": lambda h, b, bl, s: "cross-domain-policy" in bl and 'domain="*"' in bl},

    # ── 디버그/에러 추가 ───────────────────────────────────────────────
    {"id": "debug-nextjs", "name": "Next.js 에러/디버그 노출", "risk": "low", "confidence": "tentative",
     "description": "Next.js 상세 에러 오버레이/스택 노출.", "solution": "프로덕션 빌드로 배포.", "reference": "",
     "check": lambda h, b, bl, s: "__next_error__" in bl or ("nextjs" in bl and "call stack" in bl)},
    {"id": "debug-nuxt", "name": "Nuxt 에러 노출", "risk": "low", "confidence": "tentative",
     "description": "Nuxt 에러 페이지/스택 노출.", "solution": "프로덕션 설정.", "reference": "",
     "check": lambda h, b, bl, s: "nuxt" in bl and "stack" in bl and "statuscode" in bl},
    {"id": "debug-phoenix", "name": "Elixir/Phoenix 디버그 노출", "risk": "medium", "confidence": "tentative",
     "description": "Phoenix 상세 예외 페이지 노출.", "solution": "prod 설정으로 상세 숨김.", "reference": "",
     "check": lambda h, b, bl, s: "phoenix" in bl and ("plug.conn" in bl or "stacktrace" in bl)},
    {"id": "debug-graphql-verbose", "name": "GraphQL 상세 에러 노출", "risk": "low", "confidence": "tentative",
     "description": "GraphQL 응답에 상세 스택/디버그 에러가 포함됩니다.", "solution": "프로덕션에서 에러 마스킹.", "reference": "",
     "check": lambda h, b, bl, s: '"errors"' in bl and ("stacktrace" in bl or '"exception"' in bl)},
    {"id": "debug-node-stack", "name": "Node.js 스택트레이스 노출", "risk": "medium", "confidence": "firm",
     "description": "Node.js 예외 스택이 노출됩니다.", "solution": "상세 에러를 사용자에게 노출하지 마세요.", "reference": "",
     "check": lambda h, b, bl, s: "at object.<anonymous>" in bl or bool(re.search(r"at [\w.]+ \([^)]+:\d+:\d+\)", bl))},

    # ── 헤더/직렬화 추가 ───────────────────────────────────────────────
    {"id": "hdr-server-timing", "name": "Server-Timing 헤더 노출", "risk": "informational", "confidence": "certain",
     "description": "Server-Timing 으로 내부 처리시간/구성이 노출됩니다.", "solution": "프로덕션에서 상세 제거.", "reference": "",
     "check": lambda h, b, bl, s: "server-timing" in h},
    {"id": "hdr-deprecated-sec", "name": "폐기된 보안 헤더 사용", "risk": "informational", "confidence": "firm",
     "description": "Public-Key-Pins/Expect-CT/Feature-Policy 등 폐기된 헤더 사용.", "solution": "최신 대체 헤더(CSP/Permissions-Policy)로 전환.", "reference": "",
     "check": lambda h, b, bl, s: "public-key-pins" in h or "expect-ct" in h or "feature-policy" in h},
    {"id": "ser-java", "name": "Java 직렬화 객체 노출", "risk": "medium", "confidence": "firm",
     "description": "응답에 Java 직렬화 데이터(rO0AB / aced0005)가 노출됩니다.", "solution": "직렬화 데이터 노출 제거·역직렬화 보안 검토.", "reference": "",
     "check": lambda h, b, bl, s: "ro0ab" in bl or "\xac\xed\x00\x05" in (b or "")},
    {"id": "ser-php", "name": "PHP 직렬화 객체 노출", "risk": "low", "confidence": "tentative",
     "description": "응답에 PHP 직렬화 객체(O:n:) 흔적이 있습니다.", "solution": "역직렬화 입력 검증.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'O:\d+:"[a-z_][\w]*":\d+:\{', b or "", re.I))},
    {"id": "leak-viewstate", "name": "ASP.NET ViewState 노출", "risk": "informational", "confidence": "firm",
     "description": "__VIEWSTATE 가 노출됩니다(MAC 미적용 시 역직렬화 위험).", "solution": "ViewState MAC/암호화 적용.", "reference": "",
     "check": lambda h, b, bl, s: "__viewstate" in bl and "value=" in bl},

    # ── 클라우드 메타데이터 응답(SSRF 성공 흔적) ───────────────────────
    {"id": "cloud-aws-meta", "name": "AWS 메타데이터 응답 노출", "risk": "critical", "confidence": "firm",
     "description": "응답에 AWS 메타데이터/IAM 자격증명 흔적이 있습니다(SSRF 성공 가능).", "solution": "SSRF 차단·IMDSv2 강제.", "reference": "",
     "check": lambda h, b, bl, s: "iam/security-credentials" in bl or "instance-identity" in bl or ('"accesskeyid"' in bl and '"secretaccesskey"' in bl)},
    {"id": "cloud-gcp-meta", "name": "GCP 메타데이터 응답 노출", "risk": "critical", "confidence": "firm",
     "description": "GCP 메타데이터 흔적이 있습니다(SSRF 성공 가능).", "solution": "SSRF 차단.", "reference": "",
     "check": lambda h, b, bl, s: "computemetadata" in bl or "metadata.google.internal" in bl},
]


# ════════════════════════════════════════════════════════════════════════════════
# ALERT 증거 추출 — 각 룰의 check 람다에서 정규식/문자열/헤더 키를 정적 분석으로 뽑아,
# 매칭 시 "응답에서 실제로 탐지된 문자열"을 evidence 로 함께 반환한다(사용자가 검색·검증용).
# 룰 196개를 수정하지 않고, 이 파일 소스를 AST 로 한 번만 파싱해 인덱스를 만든다.
# ════════════════════════════════════════════════════════════════════════════════

def _eval_re_flags(node) -> int:
    try:
        return int(eval(compile(ast.Expression(node), "<flags>", "eval"), {"re": re}))
    except Exception:
        return 0


def _build_evidence_index() -> dict:
    """자기 자신(analyzer.py) 소스를 AST 로 파싱해 rule id → 증거 추출 스펙 맵을 만든다."""
    index = {}
    try:
        with open(__file__, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
    except Exception:
        return index

    # ALERT_RULES 대입문의 값(리스트)만 대상으로 한다
    rules_node = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "ALERT_RULES":
                    rules_node = node.value
    if rules_node is None:
        return index

    def _lit(n):
        return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None

    for elt in getattr(rules_node, "elts", []):
        if not isinstance(elt, ast.Dict):
            continue
        rid = None
        check = None
        for k, v in zip(elt.keys, elt.values):
            key = _lit(k)
            if key == "id":
                rid = _lit(v)
            elif key == "check":
                check = v
        if not rid or not isinstance(check, ast.Lambda):
            continue

        spec = {"regex": [], "lit_b": [], "lit_bl": [], "hdr": []}
        for sub in ast.walk(check):
            # re.search / re.match / re.findall(pattern, target[, flags])
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                    and isinstance(sub.func.value, ast.Name) and sub.func.value.id == "re" \
                    and sub.func.attr in ("search", "match", "findall") and len(sub.args) >= 2:
                pat = _lit(sub.args[0])
                if pat is None:
                    continue
                tgt = sub.args[1]
                tgt_name = None
                if isinstance(tgt, ast.Name):
                    tgt_name = tgt.id
                elif isinstance(tgt, ast.BoolOp) and tgt.values and isinstance(tgt.values[0], ast.Name):
                    tgt_name = tgt.values[0].id  # `b or ""`
                is_bl = tgt_name in ("bl", "body_lower")
                flags = _eval_re_flags(sub.args[2]) if len(sub.args) >= 3 else 0
                spec["regex"].append((pat, flags, is_bl))
            # `"literal" in bl` / `in b` / `in h` / `in h.get("key",...)`
            elif isinstance(sub, ast.Compare) and len(sub.ops) == 1 and isinstance(sub.ops[0], ast.In):
                left = _lit(sub.left)
                right = sub.comparators[0]
                if left is None:
                    continue
                if isinstance(right, ast.Name) and right.id in ("bl", "body_lower"):
                    spec["lit_bl"].append(left)
                elif isinstance(right, ast.Name) and right.id in ("b", "body"):
                    spec["lit_b"].append(left)
                elif isinstance(right, ast.Name) and right.id == "h":
                    spec["hdr"].append(left)  # `"x-powered-by" in h`
                elif isinstance(right, ast.Call) and isinstance(right.func, ast.Attribute) \
                        and right.func.attr == "get" and isinstance(right.func.value, ast.Name) \
                        and right.func.value.id == "h" and right.args:
                    key = _lit(right.args[0])
                    if key:
                        spec["hdr"].append(key)  # `"unsafe-inline" in h.get("csp","")`
            # `h.get("key", ...)` 단독 사용(== "*", startswith 등)
            elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                    and sub.func.attr == "get" and isinstance(sub.func.value, ast.Name) \
                    and sub.func.value.id == "h" and sub.args:
                key = _lit(sub.args[0])
                if key:
                    spec["hdr"].append(key)

        # 중복 제거(순서 유지)
        for kk in ("lit_b", "lit_bl", "hdr"):
            spec[kk] = list(dict.fromkeys(spec[kk]))
        index[rid] = spec
    return index


_EVIDENCE_INDEX = _build_evidence_index()


def _clip_evidence(text: str, limit: int = 180) -> str:
    """증거 스니펫을 검색 가능한 형태로 정리(제어문자 정돈·길이 제한)."""
    if not text:
        return ""
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def _extract_alert_evidence(rule_id: str, headers_lower: dict, body: str, body_lower: str) -> str:
    """매칭된 룰에 대해 응답에서 실제 탐지된 증거 문자열을 뽑는다(없으면 "")."""
    spec = _EVIDENCE_INDEX.get(rule_id)
    if not spec:
        return ""
    body = body or ""
    body_lower = body_lower or ""

    # 1) 정규식 매칭(원본 body 로 실제 대소문자 보존; bl 대상이었으면 대소문자 무시)
    for pat, flags, is_bl in spec["regex"]:
        try:
            m = re.search(pat, body, flags | (re.I if is_bl else 0))
        except Exception:
            m = None
        if m:
            return _clip_evidence(m.group(0))

    # 2) body 리터럴(대소문자 유지 원본 슬라이스)
    for lit in spec["lit_b"]:
        idx = body.find(lit)
        if idx >= 0:
            return _clip_evidence(body[idx:idx + len(lit)])
    for lit in spec["lit_bl"]:
        idx = body_lower.find(lit)
        if idx >= 0:
            return _clip_evidence(body[idx:idx + len(lit)])

    # 3) 헤더 값(존재하는 헤더만; 누락 기반 룰은 여기서 자연히 빈 값)
    #    증거는 원본 대소문자로 — 사용자가 응답에서 그대로 검색할 수 있어야 한다.
    for key in spec["hdr"]:
        if headers_lower.get(key):
            return _clip_evidence(f"{key}: {_hdr_raw(headers_lower, key)}")

    return ""


def run_alert_rules(headers_lower: dict, body: str, body_lower: str, status_code: int) -> list:
    """ALERT 룰셋 전체 실행 후 발견된 Alert 목록 반환"""
    alerts = []
    for rule in ALERT_RULES:
        try:
            matched = rule["check"](headers_lower, body, body_lower, status_code)
            if matched:
                # description이 callable이면 동적 생성
                desc = rule["description"]
                if callable(desc):
                    desc = desc(headers_lower)
                alerts.append({
                    "id":          rule["id"],
                    "name":        rule["name"],
                    "risk":        rule["risk"],
                    "confidence":  rule["confidence"],
                    "description": desc,
                    "solution":    rule["solution"],
                    "reference":   rule["reference"],
                    "evidence":    _extract_alert_evidence(rule["id"], headers_lower, body, body_lower),
                })
        except Exception:
            pass
    # 위험도 순 정렬
    risk_order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    alerts.sort(key=lambda a: risk_order.get(a["risk"], 9))
    return alerts


# ── 사용자 정의 Alert 룰 ────────────────────────────────────────────────────────
# 브라우저 localStorage 에만 있고 JS 로만 실행돼서, 커스텀 룰이 단일 전송 화면에서만
# 동작하고 일괄 테스트·리포트에는 전혀 반영되지 않았다(엔진 이원화). 이제 룰을 요청에
# 실어 보내면 서버가 모든 경로에서 같은 방식으로 평가한다.
#
# 룰 스키마(프론트 모달과 동일):
#   {id, name, risk, confidence, description, solution, enabled,
#    target: header_key|header_value|body|status, method: contains|not_contains|equals|regex,
#    value}
_CUSTOM_RISKS = ("high", "medium", "low", "informational")


def _custom_rule_match(rule: dict, headers_lower: dict, body: str,
                       body_lower: str, status_code: int):
    """룰 1개 평가 → (매칭여부, 증거문자열). 정규식 오류 등은 미매칭으로 처리."""
    target = str(rule.get("target") or "")
    method = str(rule.get("method") or "")
    raw_val = str(rule.get("value") or "")
    val = raw_val.lower()

    def _re(pattern, text, flags=re.I):
        try:
            return re.search(pattern, text, flags)
        except re.error:
            return None

    if target == "header_key":
        keys = list(headers_lower.keys())
        if method == "not_contains":
            return (not any(val in k for k in keys)), ""
        if method == "contains":
            hit = next((k for k in keys if val in k), None)
        elif method == "equals":
            hit = next((k for k in keys if k == val), None)
        elif method == "regex":
            hit = next((k for k in keys if _re(raw_val, k)), None)
        else:
            return False, ""
        return bool(hit), (f"{hit}: {_hdr_raw(headers_lower, hit)}" if hit else "")

    if target == "header_value":
        pairs = _hdr_raw_items(headers_lower)          # 증거는 원본 값으로
        if method == "not_contains":
            return (not any(val in str(v).lower() for _, v in pairs)), ""
        if method == "contains":
            hit = next((kv for kv in pairs if val in str(kv[1]).lower()), None)
        elif method == "equals":
            hit = next((kv for kv in pairs if str(kv[1]).lower() == val), None)
        elif method == "regex":
            hit = next((kv for kv in pairs if _re(raw_val, str(kv[1]))), None)
        else:
            return False, ""
        return bool(hit), (f"{hit[0]}: {hit[1]}" if hit else "")

    if target == "body":
        if method == "not_contains":
            return (val not in body_lower), ""
        if method == "contains":
            idx = body_lower.find(val)
            return idx >= 0, (_clip_evidence(body[idx:idx + len(raw_val)]) if idx >= 0 else "")
        if method == "equals":
            return body == raw_val, (_clip_evidence(body) if body == raw_val else "")
        if method == "regex":
            m = _re(raw_val, body)
            return bool(m), (_clip_evidence(m.group(0)) if m else "")
        return False, ""

    if target == "status":
        sc = str(status_code)
        if method == "equals":
            ok = sc == raw_val
        elif method == "contains":
            ok = raw_val in sc
        elif method == "not_contains":
            return (raw_val not in sc), ""
        elif method == "regex":
            ok = bool(_re(raw_val, sc, 0))
        else:
            return False, ""
        return ok, (f"HTTP {sc}" if ok else "")

    return False, ""


def run_custom_alert_rules(rules: Optional[list], headers_lower: dict, body: str,
                           body_lower: str, status_code: int) -> list:
    """사용자 정의 룰을 평가해 Alert 목록 반환. 잘못된 룰은 조용히 건너뛴다."""
    out = []
    for rule in (rules or []):
        if not isinstance(rule, dict) or rule.get("enabled") is False:
            continue
        try:
            matched, evidence = _custom_rule_match(rule, headers_lower, body,
                                                   body_lower, status_code)
        except Exception:
            continue
        if not matched:
            continue
        risk = str(rule.get("risk") or "informational").lower()
        out.append({
            "id": str(rule.get("id") or "custom"),
            "name": str(rule.get("name") or "사용자 정의 룰"),
            "risk": risk if risk in _CUSTOM_RISKS else "informational",
            "confidence": rule.get("confidence"),
            "description": str(rule.get("description") or ""),
            "solution": str(rule.get("solution") or ""),
            "reference": "",
            "evidence": evidence,
            "_custom": True,
        })
    return out


# ════════════════════════════════════════════════════════════════════════════════
# 공격 결과 분석 — "이 공격이 실제로 통했는가"를 증거 기반으로 판정 (결정적)
# ════════════════════════════════════════════════════════════════════════════════

# 파일 읽기 성공 마커 — 강/약으로 분리한다.
# 강한 마커: 매우 구체적이라 오탐이 거의 없다. 요청 형태와 무관하게 '모든 응답'에서
#   확인한다(어느 엔드포인트든 이 내용이 있으면 실제 파일/소스 유출).
_FILE_READ_MARKERS_STRONG = [
    (r"root:.*?:0:0:",                          "리눅스 /etc/passwd 내용"),
    (r"root:[^:\n]{0,80}:\d{4,5}:\d:\d{4,5}:",  "리눅스 /etc/shadow 내용(해시)"),
    (r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",  "개인키 노출"),
    (r"repositoryformatversion\s*=",            "Git 설정(.git/config) 내용"),
]
# 약한 마커: 정상 문서/코드 예제 페이지에도 나올 수 있어 오탐 위험이 있다. 요청이
#   파일 접근처럼 보일 때만(lfi/xxe 또는 _FILE_READ_HINT) 확인한다.
_FILE_READ_MARKERS_WEAK = [
    (r"\[extensions\]|\[fonts\]|16-bit app support", "Windows win.ini 내용"),
    (r"\[boot loader\]|\[operating systems\]", "Windows boot.ini 내용"),
    (r"(?m)^\s*127\.0\.0\.1\s+localhost",      "hosts 파일 내용"),
    (r"Linux version \d+\.\d+",                 "/proc/version 내용"),
    (r"\d+\.\d+\.\d+\.\d+ - - \[\d{2}/\w{3}/\d{4}", "웹서버 access 로그 내용"),
    (r"<\?php[\s\S]{0,40}",                     "PHP 소스코드 노출"),
    (r"DB_PASSWORD|DB_USERNAME|APP_KEY=",       ".env 설정 노출"),
    # /proc/self/environ — 프로세스 환경변수 덤프(웹 LFI 시 CGI 변수가 특징적으로 노출)
    (r"SCRIPT_FILENAME=|DOCUMENT_ROOT=|GATEWAY_INTERFACE=|SERVER_SOFTWARE=|HTTP_USER_AGENT=",
     "/proc/self/environ (환경변수) 노출"),
    (r"(?s)\bPATH=/[^\x00\n]{0,120}\x00",       "/proc/self/environ (환경변수) 노출"),
    # /proc/net/tcp — 커널 연결 테이블(로컬/원격 주소 hex)
    (r"sl\s+local_address\s+rem_address",       "/proc/net/tcp 내용"),
    # /proc/self/cmdline — 실행 커맨드라인(널 구분)
    (r"(?s)/[a-z]+/[a-z0-9._-]+\x00-{1,2}[a-z]", "/proc/self/cmdline 내용"),
]
# 파일 읽기 시도로 보이는 payload 지표 — 카테고리(lfi/xxe)와 무관하게 파일 내용
# 탐지를 켜기 위한 힌트. 수많은 경로 트래버설 익스플로잇이 'cve'·'sqli' 등으로 들어온다.
# 힌트는 '콘텐츠 마커 검사를 켤지'만 정하는 게이트다. 실제 성공 판정은 엄격한 파일
# '내용' 시그니처가 하므로, 힌트를 넉넉하게 잡아도 오탐이 늘지 않는다(인코딩 변형 포함).
# _FILE_READ_HINT → core.classify(위에서 import).
# 공격 유형 추론 힌트 — 카테고리를 고르지 않은 요청(PoC·붙여넣기 등)에서도 payload·URL·
# 본문을 보고 어떤 공격인지 추정해, 맥락이 필요한 오라클(SSRF·SQLi·리다이렉트)을 켠다.
# (증거가 자명한 오라클—명령 출력·파일 내용—은 힌트 없이 전역으로 동작한다.)
# _SSRF_HINT·_SQLI_HINT·_REDIRECT_HINT·_DANGEROUS_SCHEME → core.classify(위에서 import).

# 명령 실행 출력 마커 (Command Injection)
_CMD_OUTPUT_MARKERS = [
    (r"uid=\d+\([^)]+\)\s+gid=\d+",            "id 출력(uid/gid)"),
    (r"Microsoft Windows \[Version",            "Windows ver 출력"),
    (r"Volume in drive [A-Z] |Directory of ",   "Windows dir 출력"),
]
# 클라우드 메타데이터 마커 (SSRF)
_SSRF_MARKERS = [
    (r"ami-id|instance-id|iam/security-credentials|InstanceProfileArn", "AWS 메타데이터"),
    (r"computeMetadata|metadata\.google\.internal",                     "GCP 메타데이터"),
    (r"\"compute\"\s*:|\"network\"\s*:.*macAddress",                    "Azure 메타데이터"),
]
# UNION/버전 추출 '성공 출력' 마커 — 버전 함수(v$version·@@version 등) 결과가 응답에 나타나면
# SQLi 로 DB 데이터가 추출된 것(에러가 아니라 '추출된 데이터'). SQLi 프로브일 때만 적용.
_DB_VERSION_MARKERS = [
    (r"Oracle Database \d+g|PL/SQL Release \d|NLSRTL Version|TNS for \w",     "Oracle 버전 배너 추출"),
    (r"Microsoft SQL Server\s*\d{4}|Microsoft Corporation.*x\d{2}",           "MSSQL 버전 배너 추출"),
    (r"PostgreSQL \d+\.\d+.*\bon\b",                                          "PostgreSQL 버전 배너 추출"),
    (r"\b\d+\.\d+\.\d+-MariaDB",                                              "MariaDB 버전 배너 추출"),
    (r"\b\d+\.\d+\.\d+-[\w.]*(?:ubuntu|debian|log|community|mariadb|mysql)",   "MySQL 버전 배너 추출"),
    (r"\bSQLite\s+version\s+\d|\bsqlite_version\b",                           "SQLite 버전 배너 추출"),
]

# 민감 파일 탐색 프로브: (요청 payload 의 파일 지표, 노출 확증용 본문 시그니처, 파일 라벨)
# 상태코드가 아니라 '응답 본문에 실제 파일 내용이 있는가'로 노출을 판정하기 위한 표.
# 200 응답이라도 본문이 일반 페이지/오류 페이지/SPA 껍데기면 시그니처가 없어 '미노출'로 판정된다.
# (payload 지표, 노출 확증 정규식, 라벨, 응답에서 검색한 시그니처 설명)
_SENSITIVE_FILE_PROBES = [
    (r"\.git/config",  r"repositoryformatversion|\[remote\s+\"|\[branch\s+\"", "Git 설정(.git/config)", "repositoryformatversion / [remote \"…\"]"),
    (r"\.git/HEAD",    r"^\s*ref:\s*refs/heads/",                              "Git HEAD(.git/HEAD)", "ref: refs/heads/…"),
    (r"\.env(?![a-z])", r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\S",                      "환경파일(.env)", "KEY=값 형태의 환경변수 줄"),
    (r"wp-config\.php", r"DB_PASSWORD|DB_NAME|AUTH_KEY|define\(\s*['\"]DB_",   "WordPress wp-config.php", "DB_PASSWORD / define('DB_…')"),
    (r"web\.config",   r"<configuration[\s>]|<system\.web",                    "IIS web.config", "<configuration> / <system.web>"),
    (r"\.htaccess",    r"RewriteEngine|RewriteRule|AuthType|Require\s",        ".htaccess", "RewriteEngine / AuthType"),
    (r"id_rsa",        r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",             "SSH 개인키(id_rsa)", "BEGIN … PRIVATE KEY"),
    (r"accessKeys?\.csv|credentials\.csv|/\.aws/credentials|aws[_-]?credentials",
     r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|aws_secret_access_key|Access key ID\s*,\s*Secret access key",
     "AWS 자격증명(accessKeys.csv/credentials)",
     "AKIA…/ASIA… · aws_secret_access_key · CSV 헤더(Access key ID,Secret access key)"),
    (r"service[_-]?account\.json|/\.gcp/", r'"type"\s*:\s*"service_account"|"private_key"\s*:\s*"-----BEGIN',
     "GCP 서비스계정 키(service_account.json)", '"type":"service_account" / "private_key"'),
    (r"\.npmrc",       r"_authToken\s*=|//[^/]+/:_authToken",                   "npm 인증토큰(.npmrc)", "_authToken="),
    (r"\.dockercfg|\.docker/config\.json", r'"auths"\s*:|"auth"\s*:\s*"[A-Za-z0-9+/]{16,}', "Docker 레지스트리 인증", '"auths" / "auth":"…"'),
    (r"\.pypirc",      r"\[(?:pypi|distutils)\]|password\s*=",                  "PyPI 자격증명(.pypirc)", "[pypi] password="),
    (r"\.DS_Store",    r"Bud1",                                                ".DS_Store", "Bud1 매직바이트"),
    (r"phpinfo",       r"<title>phpinfo\(\)|>PHP Version\s*<",                 "phpinfo()", "<title>phpinfo() / PHP Version"),
    (r"/actuator/(?:env|configprops|heapdump|gateway)",
     r'"propertySources"|"activeProfiles"|"systemProperties"|"predicate"|"route_id"', "Spring Actuator",
     "\"propertySources\" / \"activeProfiles\""),
]

# CVE 항목에 확증 매처가 없을 때의 정직한 서술(공용 시그니처를 들이대지 않는다).
_CVE_NO_MATCHER = "이 CVE 항목에 확증 매처 없음 — 응답만으로 자동 확증 불가(수동 확인 필요)"

# 카테고리별 '응답에서 검색한 성공 시그니처' 사람용 설명(미확인 증거에 사용).
_CHECKED_DESC = {
    "lfi":  "root:x:0:0(passwd) · shadow 해시 · BEGIN PRIVATE KEY · win.ini · /proc 환경변수",
    "xxe":  "root:x:0:0(passwd) · 파일 내용 · BEGIN PRIVATE KEY",
    "cmdi": "uid=0(root) gid=(id 출력) · Microsoft Windows [Version(cmd 출력)",
    "ssrf": "클라우드 메타데이터(ami-id · iam/security-credentials · computeMetadata)",
    "ssti": "표현식 계산 결과(예: 7*7=49)",
    "sqli": "SQL/DB 에러(문법 오류 · EXTRACTVALUE 마커) · 시간지연 · 참/거짓 차이",
    "xss":  "payload 의 실행 컨텍스트 반사",
    "redirect": "외부 도메인으로의 3xx Location",
    "nosql": "참/거짓 응답 차이 · $where 평가",
    # CVE 는 취약점마다 성공 신호가 전혀 다르다. 공용 파일읽기 시그니처(root:x:0:0 등)로
    # 검증하는 것은 부정직하므로, 해당 CVE 항목이 들고 있는 매처만 근거로 쓴다(_cve_checked_desc).
    # 이 문구는 '그 CVE 에 확증 매처가 아예 없는' 경우의 정직한 서술이다.
    "cve":  _CVE_NO_MATCHER,
    "xmlrpc": "methodResponse · system.multicall · pingback.ping · wp.getUsersBlogs/getUsers · 'Incorrect username or password' · 'accepts POST requests only'",
}
_CHECKED_DEFAULT = "root:x:0:0 · uid=0(root) · 개인키 · 에러/메타데이터 시그니처"


def _checked_desc(category: str) -> str:
    return _CHECKED_DESC.get((category or "").lower(), _CHECKED_DEFAULT)


# _CMDI_HINT·_XSS_HINT → core.classify(위에서 import).


# 공격유형 → '검색한 성공 시그니처' 서술
_SIG_DESC = {
    "cmdi": "명령 실행 출력(uid=0(root) 등)",
    "lfi":  "파일 내용(root:x:0:0 · 환경변수 · 개인키 등)",
    "xxe":  "파일 내용(root:x:0:0 · 개인키 등)",
    "ssti": "템플릿 계산 결과(예: 49)",
    "sqli": "SQL/DB 에러 · 시간지연 · 참/거짓 차이",
    "ssrf": "클라우드 메타데이터",
    "xss":  "payload 의 실행 컨텍스트 반사(<script>/onerror 등)",
}


def infer_attack_type(probe: str, category: str = "", headers: Optional[dict] = None) -> str:
    """payload+URL+본문(+요청 헤더)으로 공격 유형을 추론 — core.classify 에 위임.

    payload 가 특정 유형을 명확히 가리키면 카테고리 라벨보다 그걸 신뢰한다(라벨이 틀리거나
    뭉뚱그려진 cve 인 경우 오분류 방지). headers 를 주면 헤더에 실린 공격(Log4Shell·
    Shellshock 등)도 분류한다 — SOC 패킷 붙여넣기에서 헤더 공격이 미분류되던 문제 해결."""
    return _classify.infer_attack_type(probe or "", category, headers)


def _checked_desc_for(probe: str, category: str) -> str:
    """'응답에서 무엇을 검색했는지' 서술 — payload 가 가리키는 유형을 카테고리보다 우선.

    payload 힌트가 하나라도 있으면 그것만 나열(틀린 카테고리가 SQL 등 무관한 시그니처를
    끼워넣지 않도록). 힌트가 전혀 없을 때만 카테고리 설명으로 폴백.
    """
    probe = probe or ""
    cat = (category or "").lower()
    # XSS 강력 마커가 있으면 XSS 로 확정 서술(payload 의 ';' 가 cmdi 로 오인되지 않도록 최우선)
    if _XSS_HINT.search(probe):
        return _SIG_DESC["xss"]
    parts = []
    # payload 가 직접 가리키는 유형(카테고리 라벨보다 우선)
    if _CMDI_HINT.search(probe):
        parts.append(_SIG_DESC["cmdi"])
    if _FILE_READ_HINT.search(probe):
        parts.append(_SIG_DESC["lfi"])
    if re.search(r"7\s*\*\s*7|\{\{|\$\{|#\{", probe):
        parts.append(_SIG_DESC["ssti"])
    if _SQLI_HINT.search(probe):
        parts.append(_SIG_DESC["sqli"])
    if _SSRF_HINT.search(probe):
        parts.append(_SIG_DESC["ssrf"])
    if parts:
        return " · ".join(parts)
    # CVE 는 공용 시그니처가 없다 — 경로에 맞는 CVE 항목의 '자기 매처'를 우선 서술한다.
    if cat == "cve":
        own = _cve_checked_desc(probe)
        if own:
            return own
    # payload 에 유형 힌트가 전혀 없을 때만 카테고리 기반 설명
    return _SIG_DESC.get(cat, _checked_desc(cat))


# ── L1/L2: 형식 인식 파일 노출 검증 (파일별 시그니처 없이 '형식'으로 확증) ──────────
# L1 = 응답이 HTML(=catch-all/SPA/soft-404)이면 노출 아님. L2 = 확장자에 맞는 형식으로 파싱/매칭.
def _looks_html(body: str, content_type: str) -> bool:
    if "html" in (content_type or "").lower():
        return True
    head = (body or "").lstrip()[:256].lower()
    return (head.startswith("<!doctype html") or head.startswith("<html")
            or "<head" in head or "<body" in head or "<script" in head)


def _fmt_yaml(b: str) -> bool:
    try:
        import yaml  # 있으면 실제 파싱
        d = yaml.safe_load(b)
        return isinstance(d, dict) and len(d) >= 1
    except ImportError:
        # 폴백 휴리스틱: 'key:' 매핑 줄이 2개 이상이고 HTML 태그가 없음
        return len(re.findall(r'(?m)^[A-Za-z0-9_.\-]+\s*:(?:\s|$)', b)) >= 2
    except Exception:
        return False


def _fmt_json(b: str) -> bool:
    try:
        d = json.loads(b)
        return isinstance(d, (dict, list)) and (len(d) >= 1 if hasattr(d, "__len__") else True)
    except Exception:
        return False


def _fmt_env(b: str) -> bool:
    return len(re.findall(r'(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*=', b)) >= 2


def _fmt_ini(b: str) -> bool:
    return bool(re.search(r'(?m)^\s*\[[^\]\n]+\]\s*$', b)) or _fmt_env(b)


def _fmt_xml(b: str) -> bool:
    s = (b or "").lstrip()
    return s.startswith("<?xml") or bool(re.match(r'^<[A-Za-z][\w:.-]*(?:\s|>|/)', s))


def _fmt_pem(b: str) -> bool:
    return "BEGIN" in b and "PRIVATE KEY" in b


def _fmt_sql(b: str) -> bool:
    return bool(re.search(r'\b(CREATE TABLE|INSERT INTO|DROP TABLE|ALTER TABLE|CREATE DATABASE)\b', b, re.I))


# 확장자 → (형식 라벨, 검증 함수)
_FMT_VALIDATORS = {
    "yaml": ("YAML", _fmt_yaml), "yml": ("YAML", _fmt_yaml),
    "json": ("JSON", _fmt_json),
    "env": ("dotenv", _fmt_env), "properties": ("properties", _fmt_env),
    "ini": ("INI", _fmt_ini), "toml": ("TOML", _fmt_ini),
    # .conf/.cfg 는 형식이 제각각(nginx/apache/redis)이라 단일 INI 검증이 오판 → 특정 시그니처(exposure)로 처리
    "xml": ("XML", _fmt_xml), "config": ("XML/config", _fmt_xml),
    "pem": ("PEM", _fmt_pem), "key": ("PEM", _fmt_pem),
    "sql": ("SQL", _fmt_sql),
}

# 민감 파일로 볼 경로: (1) 확장자 자체가 민감(env/pem/sql/bak…) 또는
# (2) 흔한 설정/시크릿 파일명(yaml/json/xml 은 이름이 설정류일 때만 — 일반 API JSON 오탐 방지).
_SENSITIVE_ALWAYS_EXT = re.compile(
    r'\.(env|pem|key|p12|pfx|keystore|sql|bak|old|backup|swp|ini|conf|cfg|properties|'
    r'tfstate|htpasswd|htaccess)(?:$|[?#/\s])', re.I)
_SENSITIVE_NAMED = re.compile(
    r'(?:^|/)(?:serverless|docker-compose|compose|config|configuration|settings|secret|secrets|'
    r'credentials?|appsettings(?:\.\w+)?|application(?:-\w+)?|database|db|firebase|'
    r'\.npmrc|\.dockercfg|\.pypirc|\.netrc|\.aws|\.terraform)'
    r'[\w.-]*\.(ya?ml|json|xml|config|toml|ini|conf|properties)(?:$|[?#/\s])', re.I)


def _sensitive_file_ext(path: str):
    """경로가 '민감 파일'로 보이면 (확장자, 형식라벨, 검증함수) 반환, 아니면 None.
    확장자는 매칭된 민감파일 토큰에서 뽑아 URL 호스트의 .com 등을 오인하지 않는다."""
    m_always = _SENSITIVE_ALWAYS_EXT.search(path)
    m_named = _SENSITIVE_NAMED.search(path)
    if m_always:
        ext = m_always.group(1).lower()
    elif m_named:
        ext = m_named.group(1).lower()
    else:
        return None
    fmt = _FMT_VALIDATORS.get(ext)
    return (ext, fmt[0], fmt[1]) if fmt else None


def file_exposure_looks_real(body: str, headers_lower: Optional[dict],
                             status_code: int, ext: str) -> bool:
    """응답이 '실제 노출된 파일'로 보이는지 — L1(not-HTML) + L2(확장자 형식 검증).
    L3 catch-all 차분 확증(api.py)에서 대상/형제 경로 비교에 재사용하는 공용 판정."""
    if status_code and status_code >= 400:
        return False
    ct = (headers_lower or {}).get("content-type", "")
    if _looks_html(body or "", ct):
        return False
    fmt = _FMT_VALIDATORS.get((ext or "").lower())
    if not fmt:
        return False
    return bool((body or "").strip()) and fmt[1](body or "")


# ── nuclei exposure 매처 임포트 소비 ─────────────────────────────
# data/exposure_signatures.json 의 커뮤니티 시그니처(nuclei http/exposures 매처)를 로드해
# '경로 매칭 + 응답 word/regex/status 매칭'으로 노출을 확증한다. 파일별 정밀 시그니처를
# 손으로 쓰지 않고도 수백 종 노출을 커버(L1/L2 형식검증을 보완).
_EXPOSURE_SIGS = None


def _load_exposure_sigs() -> list:
    global _EXPOSURE_SIGS
    if _EXPOSURE_SIGS is not None:
        return _EXPOSURE_SIGS
    path = os.path.join(os.path.dirname(__file__), "..", "data", "exposure_signatures.json")
    try:
        with open(path, encoding="utf-8") as f:
            _EXPOSURE_SIGS = json.load(f).get("signatures", [])
    except Exception:
        _EXPOSURE_SIGS = []
    return _EXPOSURE_SIGS


def _word_hits(text: str, words: list, cond: str):
    if not words:
        return True, []
    tl = text.lower()
    hits = [w for w in words if str(w).lower() in tl]
    ok = (len(hits) == len(words)) if cond == "and" else bool(hits)
    return ok, hits


def _re_search(pat: str, text: str):
    """임포트된 커뮤니티 정규식은 파이썬에서 컴파일 실패할 수 있으므로 안전하게 감싼다."""
    try:
        return re.search(pat, text, re.I)
    except re.error:
        return None


def _eval_matchers(sig: dict, body: str, hdr_blob: str, status_code: int):
    """시그니처의 매처 집합을 평가 → (matched, evidence_list).

    nuclei 매처 문법(status·word·regex + condition/matchers-condition)을 그대로 해석한다.
    exposure 시그니처와 CVE 항목이 같은 엔진을 쓰도록 분리했다.
    """
    matchers = sig.get("matchers") or []
    if not matchers:
        return False, []
    mcond = str(sig.get("matchers_condition") or "and").lower()
    results, ev, unsupported = [], [], False
    for m in matchers:
        t = (m.get("type") or "").lower()
        if t == "status":
            results.append(status_code in (m.get("status") or []))
        elif t == "word":
            part = body if m.get("part", "body") != "header" else hdr_blob
            ok, hits = _word_hits(part, m.get("words") or [], m.get("condition", "or"))
            results.append(ok)
            if ok:
                ev += hits
        elif t == "regex":
            part = body if m.get("part", "body") != "header" else hdr_blob
            pats = m.get("regex") or []
            found = [mm for mm in (_re_search(pt, part) for pt in pats) if mm]
            ok = (len(found) == len(pats)) if m.get("condition", "or") == "and" else bool(found)
            results.append(ok)
            if ok:
                ev += [_clip_evidence(mm.group(0), 80) for mm in found[:3]]
        else:
            unsupported = True   # dsl 등 미지원 매처
    # 'and' 조건에서 미지원 매처가 있으면 제약을 무시하게 되어 오탐 위험 → 평가 포기
    if unsupported and mcond == "and":
        return False, []
    if not results:
        return False, []
    return (all(results) if mcond == "and" else any(results)), ev


def _matchers_desc(sig: dict) -> str:
    """매처 집합을 사람이 읽는 '무엇을 확인했는가' 서술로 변환."""
    parts = []
    for m in sig.get("matchers") or []:
        t = (m.get("type") or "").lower()
        if t == "word":
            ws = [str(w) for w in (m.get("words") or [])][:4]
            if ws:
                parts.append("본문/헤더 문자열(" + " , ".join(ws) + ")")
        elif t == "regex":
            rs = [str(r) for r in (m.get("regex") or [])][:2]
            if rs:
                parts.append("정규식(" + " , ".join(rs) + ")")
        elif t == "status":
            st = [str(x) for x in (m.get("status") or [])]
            if st:
                parts.append("상태코드(" + "/".join(st) + ")")
    return " · ".join(parts)


def _hdr_blob(headers_lower: Optional[dict]) -> str:
    """매처가 훑을 헤더 텍스트. 값은 원본 — word 매칭은 양쪽 소문자, regex 는 re.I 라
    매칭 결과는 같고, 뽑히는 증거만 원문이 된다."""
    return " ".join(f"{k}: {v}" for k, v in _hdr_raw_items(headers_lower))


def _detect_exposure_sig(probe: str, body: str, headers_lower: Optional[dict], status_code: int) -> list:
    """임포트된 nuclei exposure 매처로 노출 확증. (경로가 시그니처에 맞을 때만 평가)"""
    out, seen = [], set()
    body = body or ""
    hdr_blob = _hdr_blob(headers_lower)
    pl = (probe or "").lower()
    for sig in _load_exposure_sigs():
        pcs = sig.get("path_contains") or []
        if pcs and not any(str(pc).lower() in pl for pc in pcs):
            continue
        matched, ev = _eval_matchers(sig, body, hdr_blob, status_code)
        if not matched:
            continue
        sid = sig.get("id", "")
        if sid in seen:
            continue
        seen.add(sid)
        words_checked = "; ".join(str(w) for m in (sig.get("matchers") or []) if m.get("type") == "word"
                                  for w in (m.get("words") or [])) or "(status/regex)"
        out.append({
            "name": f"노출 확인 — {sig.get('name', sid)}",
            "verdict": "성공", "confidence": 88,
            "why": f"[nuclei:{sid}] exposure 시그니처 매칭 → 실제 노출 확인",
            "checked": words_checked,
            "evidence": (", ".join(ev[:6]) or f"HTTP {status_code}")[:180],
        })
    return out


# ── CVE 항목의 '자기 매처'로 확증 ──────────────────────────────────
# CVE 는 취약점마다 성공 신호가 전혀 달라 공용 시그니처(파일읽기 root:x:0:0 등)로는 검증할 수
# 없다. import_nuclei 가 템플릿의 matcher(status/word/regex)를 CVE 항목에 함께 담으므로,
# 여기서는 '경로 매칭 + 그 CVE 자신의 매처' 로만 확증한다(exposure 와 같은 엔진 재사용).
_CVE_SIGS = None
_PAYLOADS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "payloads.json")


def _cve_entry_to_sig(entry: dict) -> Optional[dict]:
    """payloads.json 의 cve 항목 → 경로+매처 시그니처. 확증 근거가 약하면 None."""
    matchers = entry.get("matchers") or []
    # 상태코드만 있는 매처는 '200 = 성공'이 되어 오탐 → 내용 매처(word/regex)가 있어야 확증에 쓴다.
    if not any((m.get("type") or "").lower() in ("word", "regex") for m in matchers):
        return None
    pv = str(entry.get("payload") or "")
    pcs = []
    if pv.startswith("/"):
        seg = pv.split("?")[0]
        if len(seg) >= 4:
            pcs.append(seg)
    if not pcs:
        pcs = [str(x) for x in ((entry.get("applies_to") or {}).get("path_contains") or [])
               if len(str(x)) >= 4]
    if not pcs:
        return None
    return {
        "id": entry.get("cve") or entry.get("id") or "",
        "name": entry.get("name") or entry.get("cve") or entry.get("id") or "",
        "cve": entry.get("cve") or "",
        "path_contains": sorted(set(pcs))[:4],
        "matchers": matchers,
        "matchers_condition": entry.get("matchers_condition", "and"),
    }


def _load_cve_sigs() -> list:
    global _CVE_SIGS
    if _CVE_SIGS is not None:
        return _CVE_SIGS
    sigs = []
    try:
        with open(_PAYLOADS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        cat = next((c for c in data.get("categories", []) if c.get("id") == "cve"), None)
        for p in (cat or {}).get("payloads", []):
            sig = _cve_entry_to_sig(p)
            if sig:
                sigs.append(sig)
    except Exception:
        sigs = []
    _CVE_SIGS = sigs
    return _CVE_SIGS


def _cve_sigs_for(probe: str) -> list:
    """요청 경로에 해당하는 CVE 시그니처(자기 매처를 가진 것)들."""
    pl = (probe or "").lower()
    return [sig for sig in _load_cve_sigs()
            if any(str(pc).lower() in pl for pc in (sig.get("path_contains") or []))]


def _cve_checked_desc(probe: str) -> str:
    """'이 CVE 프로브에서 무엇을 확인했는가' — 경로에 맞는 CVE 항목의 매처만 서술."""
    descs = []
    for sig in _cve_sigs_for(probe)[:3]:
        d = _matchers_desc(sig)
        if d:
            descs.append(f"{sig.get('id') or sig.get('name')}: {d}")
    return " | ".join(descs)


def _detect_cve_sig(probe: str, body: str, headers_lower: Optional[dict], status_code: int) -> list:
    """CVE 항목의 자기 매처로 익스플로잇 성공을 확증(경로가 맞을 때만 평가)."""
    out, seen = [], set()
    hdr_blob = _hdr_blob(headers_lower)
    for sig in _cve_sigs_for(probe):
        matched, ev = _eval_matchers(sig, body or "", hdr_blob, status_code)
        if not matched:
            continue
        sid = sig.get("id") or sig.get("name")
        if sid in seen:
            continue
        seen.add(sid)
        out.append({
            "name": f"CVE 확증 — {sid}",
            "verdict": "성공", "confidence": 90,
            "why": f"{sig.get('name')} 의 확증 매처가 응답에 일치 → 이 대상에서 해당 CVE 취약점 확인",
            "checked": _matchers_desc(sig),
            "evidence": (", ".join(str(e) for e in ev[:6]) or f"HTTP {status_code}")[:180],
        })
    return out


def _cve_nonapplicable_reason(status_code: int, body: str, headers_lower: Optional[dict]) -> str:
    """CVE 프로브 응답이 '익스플로잇 결과를 담을 수 없는 형태'인지 → 사유 문자열(아니면 '')."""
    if status_code in (301, 302, 303, 307, 308):
        loc = _hdr_raw(headers_lower, "location")
        return (f"HTTP {status_code} 리다이렉트" + (f" → {loc[:80]}" if loc else "")
                + " — 취약 엔드포인트가 응답하지 않고 다른 곳으로 돌림")
    if status_code in (401, 403):
        return f"HTTP {status_code} 인증/접근 거부 — 취약 엔드포인트에 도달하지 못함"
    if status_code in (404, 410):
        return f"HTTP {status_code} — 해당 경로/컴포넌트가 대상에 존재하지 않음"
    # 5xx 는 익스플로잇이 서버를 흔든 신호일 수 있다 → 빈 본문이어도 "미해당"으로 단정하지 않는다.
    if status_code < 500 and not (body or "").strip():
        return f"HTTP {status_code} · 빈 응답 본문 — 익스플로잇 결과가 담길 내용 자체가 없음"
    return ""


def _detect_sensitive_file(payload: Optional[str], body: str,
                           headers_lower: Optional[dict] = None,
                           status_code: int = 200) -> Optional[dict]:
    """민감 파일 탐색 페이로드에 대해 '실제 노출' 여부를 본문 내용으로 판정.

    1) 고가치 파일은 정밀 시그니처(_SENSITIVE_FILE_PROBES)로 확증.
    2) 그 외는 L1(not-HTML) + L2(확장자별 형식 검증)로 파일 종류와 무관하게 확증.

    반환:
      - None                : 민감 파일 탐색 페이로드가 아님(해당 없음)
      - {"exposed": True,  ...}: 요청한 파일의 실제 내용이 응답에 있음 → 노출 확증
      - {"exposed": False, ...}: 파일을 요청했으나 내용이 없음 → 미노출(200이어도 안전)
    """
    p = payload or ""
    # (1) 고가치 파일 — 정밀 내용 시그니처
    for path_re, sig_re, label, checked in _SENSITIVE_FILE_PROBES:
        if re.search(path_re, p, re.I):
            m = re.search(sig_re, body or "", re.I)
            if m:
                return {"targeted": label, "exposed": True, "checked": checked,
                        "evidence": _clip_evidence(m.group(0), 120)}
            return {"targeted": label, "exposed": False, "checked": checked, "evidence": ""}

    # (2) 형식 인식 검증 — 파일별 시그니처가 없어도 확장자 형식으로 노출 확증
    hit = _sensitive_file_ext(p)
    if not hit:
        return None
    ext, fmt_label, validator = hit
    ct = (headers_lower or {}).get("content-type", "")
    label = f"설정/시크릿 파일(.{ext})"
    checked = f"Content-Type≠html · {fmt_label} 형식 파싱 · 실제 파일 내용"
    body = body or ""

    if status_code in (401, 403):
        return {"targeted": label, "exposed": False, "checked": checked,
                "evidence": f"HTTP {status_code} — 접근 제한(보호됨)"}
    # L1: HTML(catch-all/SPA)이면 노출 아님
    if _looks_html(body, ct):
        return {"targeted": label, "exposed": False, "checked": checked,
                "evidence": f"응답이 HTML(catch-all/SPA 추정) — {fmt_label} 파일 아님 "
                            f"(Content-Type: {ct or 'n/a'})"}
    # L2: 확장자 형식으로 파싱/매칭되면 노출 확증
    if body.strip() and validator(body):
        return {"targeted": label, "exposed": True, "checked": checked,
                "evidence": f"{fmt_label} 형식으로 파싱됨 + HTML 아님(Content-Type: {ct or 'n/a'}) "
                            f"→ {ext} 파일 내용 노출: {_clip_evidence(body.strip(), 120)}"}
    return {"targeted": label, "exposed": False, "checked": checked,
            "evidence": f"{fmt_label} 형식으로 파싱되지 않음 → 파일 내용 아님 "
                        f"(HTTP {status_code} · {len(body)}B · Content-Type: {ct or 'n/a'})"}

# ── 클라이언트측(client-side) 취약점 탐지용 ──────────────────────────
# DOM XSS 소스: 공격자가 제어 가능한 클라이언트 입력
# DOM XSS 소스/싱크 — 선언형 데이터(backend/data/dom_xss_signatures.json)에서 로드.
# tools/mine_dom_xss.py 로 RAG 코퍼스에서 후보를 마이닝→검증→추가. 파일 없으면 내장 폴백.
_DOM_SOURCES_FALLBACK = [
    r"location\.hash", r"location\.search", r"location\.href", r"location\.pathname",
    r"document\.URL", r"document\.documentURI", r"document\.referrer",
    r"window\.name", r"URLSearchParams", r"\.searchParams",
    r"postMessage", r"event\.data",
]
_DOM_SINKS_FALLBACK = [
    (r"\.innerHTML\s*=",                 "innerHTML"),
    (r"\.outerHTML\s*=",                 "outerHTML"),
    (r"document\.write(?:ln)?\s*\(",     "document.write"),
    (r"\.insertAdjacentHTML\s*\(",       "insertAdjacentHTML"),
    (r"\beval\s*\(",                     "eval"),
    (r"\bnew\s+Function\s*\(",           "Function()"),
    (r"setTimeout\s*\(\s*[\"'`]",        "setTimeout(문자열)"),
    (r"setInterval\s*\(\s*[\"'`]",       "setInterval(문자열)"),
    (r"\.(?:html|append|prepend|before|after|replaceWith)\s*\(", "jQuery html/append"),
    (r"\$\(\s*(?:location|document\.URL|window\.name)", "jQuery $(source)"),
]


def _load_dom_signatures():
    fp = os.path.join(os.path.dirname(__file__), "..", "data", "dom_xss_signatures.json")
    try:
        with open(fp, encoding="utf-8") as f:
            d = json.load(f)
        srcs, sinks = [], []
        for s in d.get("sources", []):
            rx = s.get("regex")
            if rx:
                try:
                    re.compile(rx); srcs.append(rx)
                except re.error:
                    pass
        for s in d.get("sinks", []):
            rx, lbl = s.get("regex"), s.get("label", "")
            if rx:
                try:
                    re.compile(rx); sinks.append((rx, lbl))
                except re.error:
                    pass
        return (srcs or list(_DOM_SOURCES_FALLBACK)), (sinks or list(_DOM_SINKS_FALLBACK))
    except Exception:
        return list(_DOM_SOURCES_FALLBACK), list(_DOM_SINKS_FALLBACK)


_DOM_SOURCES, _DOM_SINKS = _load_dom_signatures()
# 클라이언트 템플릿 프레임워크 마커 (CSTI 가능성)
_CLIENT_TPL_MARKERS = (
    "ng-app", "ng-version", "ng-controller", "ng-bind", "angular.js", "angular.min.js",
    "v-app", "data-v-", "__vue__", "vue.js", "vue.min.js", "x-data=", "alpinejs",
)


def _detect_dom_xss(body: str):
    """응답 <script> 안에서 클라이언트 입력 소스가 위험 싱크로 흐르는지 정적 탐지(휴리스틱).
    소스·싱크가 동시에 존재할 때만 보고하여 오탐을 줄인다."""
    if not body:
        return None
    scripts = re.findall(r"<script\b[^>]*>([\s\S]*?)</script>", body, re.I)
    js = "\n".join(scripts)
    if not js:
        return None
    src = next((re.search(s, js) for s in _DOM_SOURCES if re.search(s, js)), None)
    if not src:
        return None
    for pat, lbl in _DOM_SINKS:
        m = re.search(pat, js)
        if m:
            s = max(0, m.start() - 30)
            return {"source": src.group(0), "sink": lbl, "evidence": js[s:m.end() + 40]}
    return None


# ── DOM 기반 취약점 싱크 → 보안 Alert ────────────────────────────────────────────
# PortSwigger 분류: 응답 스크립트에 '위험 싱크'가 있고 '오염 가능 소스'가 함께 있으면
# (source→sink 흐름 가능) 해당 DOM 취약점 클래스로 Alert 을 낸다. 정적 휴리스틱이라
# 실제 흐름은 브라우저 확인이 필요함을 명시하고, 소스 부재 시 흔한 싱크(JSON.parse 등)로
# 오탐하지 않도록 '소스 동시 존재'를 게이트로 둔다.
_DOM_ALERT_SOURCES = [
    r"document\.URL\b", r"document\.documentURI", r"document\.URLUnencoded", r"document\.baseURI",
    r"\blocation\b", r"document\.cookie", r"document\.referrer", r"window\.name",
    r"history\.(?:push|replace)State", r"localStorage", r"sessionStorage",
    r"(?:moz|webkit|ms)?IndexedDB", r"URLSearchParams", r"\.searchParams",
    r"event\.data\b", r"postMessage",
]
# (싱크 정규식, 싱크 라벨, 취약점 클래스, 위험도). 정규식은 '구별 가능한(저오탐)' 싱크만 담는다.
# 의도적으로 제외한 고오탐 싱크(정적 정규식으로 정상 코드와 구분 불가 → 알림 폭주):
#   element.value/text/textContent/innerText/outerText/name/type/target/method/search/
#   backgroundImage/cssText/codebase, script.text/textContent/innerText, document.title,
#   XMLHttpRequest.open()/.send(), 맨몸 open() — 모든 페이지에 흔해 source 게이트로도 억제 불가.
_DOM_ALERT_SINKS = [
    (r"document\.write(?:ln)?\s*\(|\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|"
     r"\.srcdoc\s*=|\.execCommand\s*\(|createContextualFragment\s*\(|createHTMLDocument\s*\(",
     "document.write/innerHTML/srcdoc", "DOM XSS", "high"),
    (r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\"'`]|setInterval\s*\(\s*[\"'`]|"
     r"(?:ms)?[sS]etImmediate\s*\(\s*[\"'`]|\bexecScript\s*\(|\bglobalEval\s*\(|"
     r"generateCRMFRequest\s*\(",
     "eval/Function/globalEval", "JavaScript 주입", "high"),
    (r"\blocation\s*(?:\.(?:href|host|hostname|pathname|search|protocol|assign|replace)\s*)?=(?!=)|"
     r"location\.(?:assign|replace)\s*\(|window\.open\s*\(",
     "window.location/open", "오픈 리디렉션", "medium"),
    (r"document\.cookie\s*=(?!=)", "document.cookie", "쿠키 조작", "medium"),
    (r"document\.domain\s*=(?!=)", "document.domain", "문서 도메인 조작", "medium"),
    (r"new\s+WebSocket\s*\(", "WebSocket()", "WebSocket URL 포이즈닝", "medium"),
    (r"\.(?:src|href|action)\s*=(?!=)", "element.src/href/action", "링크 조작", "medium"),
    (r"\.postMessage\s*\(", "postMessage()", "웹 메시지 조작", "medium"),
    (r"\.setRequestHeader\s*\(", "setRequestHeader()", "Ajax 요청 헤더 조작", "low"),
    (r"FileReader|\.readAs(?:Text|DataURL|ArrayBuffer|BinaryString|File)\s*\(|"
     r"\.root\.getFile\s*\(|requestFileSystem\s*\(",
     "FileReader.readAs*()", "로컬 파일 경로 조작", "medium"),
    (r"\.executeSql\s*\(|openDatabase\s*\(", "executeSql()", "클라이언트측 SQL 인젝션", "medium"),
    (r"(?:session|local)Storage\.setItem\s*\(", "sessionStorage.setItem()", "HTML5 저장소 조작", "low"),
    (r"\.evaluate\s*\(", "document.evaluate()", "클라이언트측 XPath 주입", "medium"),
    (r"JSON\.parse\s*\(|\.parseJSON\s*\(", "JSON.parse()", "클라이언트측 JSON 주입", "low"),
    (r"\.setAttribute\s*\(", "element.setAttribute()", "DOM 데이터 조작", "low"),
    (r"new\s+RegExp\s*\(", "RegExp()", "서비스 거부(ReDoS)", "low"),
]
_DOM_SINK_SOLUTION = {
    "DOM XSS": "출력 인코딩·안전한 DOM API(textContent) 사용, innerHTML/document.write 에 신뢰 안 된 입력 금지",
    "JavaScript 주입": "eval·new Function·문자열 setTimeout 제거, 동적 코드 실행 금지",
    "오픈 리디렉션": "location 대입 값 화이트리스트·상대경로만 허용",
    "쿠키 조작": "쿠키 값에 사용자 입력 직접 대입 금지·검증",
    "문서 도메인 조작": "document.domain 설정 제거(레거시), 대체 격리 사용",
    "WebSocket URL 포이즈닝": "WebSocket URL 을 사용자 입력으로 구성 금지·화이트리스트",
    "링크 조작": "src/href 대입 값 스킴·도메인 검증(javascript: 등 차단)",
    "웹 메시지 조작": "postMessage 수신 시 origin 검증·데이터 스키마 검증",
    "Ajax 요청 헤더 조작": "setRequestHeader 값에 사용자 입력 직접 사용 금지",
    "로컬 파일 경로 조작": "FileReader 대상 경로/이름 검증",
    "클라이언트측 SQL 인젝션": "executeSql 파라미터 바인딩 사용",
    "HTML5 저장소 조작": "저장 값 검증·읽을 때 재검증",
    "클라이언트측 XPath 주입": "document.evaluate 식에 사용자 입력 연결 금지·이스케이프",
    "클라이언트측 JSON 주입": "신뢰 안 된 JSON 파싱 결과 검증, 스키마 확인",
    "DOM 데이터 조작": "setAttribute 값/속성명 검증(on*·href·src 주의)",
    "서비스 거부(ReDoS)": "사용자 입력으로 RegExp 생성 금지·복잡도 제한",
}


def run_dom_alerts(body: str) -> list:
    """응답 스크립트의 DOM 위험 싱크를 취약점 클래스별 Alert 으로. 소스가 함께 있을 때만(오탐↓)."""
    if not body:
        return []
    scripts = re.findall(r"<script\b[^>]*>([\s\S]*?)</script>", body, re.I)
    js = "\n".join(scripts)
    if not js:
        return []
    src = next((m.group(0) for pat in _DOM_ALERT_SOURCES for m in [re.search(pat, js)] if m), None)
    if not src:
        return []   # 오염 가능 소스가 없으면 DOM 흐름 취약점으로 보지 않음(오탐 억제)
    out, seen = [], set()
    for pat, sink_lbl, vuln, risk in _DOM_ALERT_SINKS:
        if vuln in seen:
            continue
        m = re.search(pat, js)
        if not m:
            continue
        seen.add(vuln)
        st = max(0, m.start() - 30)
        out.append({
            "id": "dom_sink_" + re.sub(r"\W+", "_", vuln).strip("_").lower(),
            "name": f"DOM 기반 {vuln} 가능 싱크",
            "risk": risk,
            "confidence": "tentative",
            "description": f"응답 스크립트에 위험 싱크({sink_lbl})와 오염 가능 소스({src})가 함께 존재 → "
                           f"source→sink 흐름 시 {vuln} 가능(정적 휴리스틱). 브라우저에서 실제 흐름을 확인하세요.",
            "solution": _DOM_SINK_SOLUTION.get(vuln, "사용자 입력이 이 싱크로 흐르지 않도록 검증·이스케이프"),
            "reference": "https://portswigger.net/web-security/dom-based",
            "evidence": _clip_evidence(js[st:m.end() + 40], 120),
            "_dom": True,
        })
    return out


# ── API 문서/스펙·엔드포인트 식별 노출 → 보안 Alert ──────────────────────────────
# Swagger UI·OpenAPI 스펙·GraphiQL·WSDL 등이 노출되면 전체 API 공격 표면이 열거된다.
# 응답 본문 시그니처(강한 확증) + 알려진 문서 경로(맥락)로 식별한다.
_API_DOC_SIGS = [
    (r"SwaggerUIBundle|swagger-ui-bundle|swagger-ui\.css|id=[\"']swagger-ui[\"']|<title>[^<]*Swagger UI",
     "Swagger UI"),
    (r'"openapi"\s*:\s*"3\.|"swagger"\s*:\s*"2\.', "OpenAPI/Swagger 스펙"),
    (r"\bRedoc\b|redoc\.standalone|<redoc\b", "ReDoc"),
    (r"GraphQL Playground|graphiql", "GraphiQL/Playground"),
    (r"<wsdl:definitions|<definitions[^>]+xmlns[^>]+wsdl", "WSDL(SOAP)"),
    (r"<application[^>]+xmlns[^>]+wadl", "WADL"),
    (r"(?m)^#%RAML\s", "RAML"),
    (r"(?m)^FORMAT:\s*1A\b", "API Blueprint"),
]
# 알려진 API 문서/디스커버리 경로(요청 URL 경로 매칭용). 사용자 요청분 + 흔한 위치.
_API_DOC_PATHS = re.compile(
    r"/(?:swagger(?:-ui)?(?:/index\.html|/v1|\.json)?|api[-/]?docs?|v[23]/api-docs|"
    r"openapi(?:\.json|\.yaml|\.yml)?|api/swagger(?:/v\d+)?|redoc|graphiql|"
    r"swagger/v\d+/swagger\.json|\.well-known/openapi|wsdl|soap)\b", re.I)


def _looks_json(body: str, headers_lower) -> bool:
    ct = (headers_lower or {}).get("content-type", "")
    if "json" in ct:
        return True
    h = (body or "").lstrip()[:1]
    return h in ("{", "[")


def run_api_doc_alerts(url: str, body: str, headers_lower=None, status_code: int = 200) -> list:
    """API 문서/스펙·엔드포인트 식별 노출 Alert. 응답 시그니처 우선, 없으면 알려진 경로+200 으로 보강."""
    body = body or ""
    out = []
    # ① 응답 본문에 API 문서/스펙 시그니처 → 강한 확증
    for pat, kind in _API_DOC_SIGS:
        m = re.search(pat, body, re.I)
        if m:
            out.append({
                "id": "api_doc_" + re.sub(r"\W+", "_", kind).strip("_").lower(),
                "name": f"API 문서/스펙 노출 — {kind}",
                "risk": "medium", "confidence": "firm",
                "description": f"응답에 {kind} 가 노출됨 → 전체 API 엔드포인트·파라미터·스키마가 열거되어 "
                               "공격 표면이 드러납니다(정보 노출). 운영 환경에서는 접근 제한을 권장합니다.",
                "solution": "운영 환경에서 API 문서(Swagger/OpenAPI/GraphiQL 등) 비활성화 또는 인증 뒤로 이동",
                "reference": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                "evidence": _clip_evidence(m.group(0), 100),
                "_apidoc": True,
            })
            break   # 문서 유형 하나면 충분(중복 알림 방지)
    if out:
        return out
    # ② 시그니처는 없지만 요청 경로가 알려진 API 문서/디스커버리 경로 + 2xx JSON/HTML → 엔드포인트 응답
    try:
        from urllib.parse import urlsplit
        path = urlsplit(url or "").path or (url or "")
    except Exception:
        path = url or ""
    # bare /api 는 실제 API 호출과 구분 어려워 오탐 크므로, 디스커버리 인덱스 마커가 있을 때만.
    api_root = re.search(r"/api/?$", path) is not None
    api_index_marker = bool(re.search(r'"_links"|"routes"\s*:|"endpoints"\s*:', body))
    known_doc_path = _API_DOC_PATHS.search(path) is not None
    if status_code in (200, 201) and body.strip() and (known_doc_path or (api_root and api_index_marker)):
        json_hint = _looks_json(body, headers_lower)
        out.append({
            "id": "api_doc_endpoint",
            "name": "API 문서/디스커버리 엔드포인트 응답",
            "risk": "low", "confidence": "tentative",
            "description": f"알려진 API 문서/디스커버리 경로({path[:60]})가 HTTP {status_code} 로 응답 → "
                           "API 엔드포인트 식별에 이용될 수 있습니다. 노출 내용을 확인하세요."
                           + ("(JSON 응답)" if json_hint else ""),
            "solution": "필요 없으면 해당 경로 차단, 문서는 인증 뒤로 이동",
            "reference": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
            "evidence": f"경로 {path[:60]} · HTTP {status_code}",
            "_apidoc": True,
        })
    return out


def _detect_csti(body: str, payload: str):
    """{{7*7}}·${..} 등 템플릿 표현식이 '미평가 원문'으로 반사 + 클라이언트 프레임워크 존재
    → 브라우저 렌더링 시 평가될 수 있음(CSTI). 서버가 평가했다면(49 등) SSTI 로 별도 처리."""
    if not body or not payload:
        return None
    if not any(t in payload for t in ("{{", "${", "#{")):
        return None
    if payload not in body:            # 원문 그대로(미평가) 반사됐는지
        return None
    if not any(m in body.lower() for m in _CLIENT_TPL_MARKERS):
        return None
    idx = body.find(payload)
    s = max(0, idx - 20)
    return {"evidence": body[s: idx + len(payload) + 20]}


def _detect_client_redirect(body: str):
    """서버 3xx 없이 meta refresh / JS location 대입으로 이동하는 클라이언트측 리다이렉트."""
    if not body:
        return None
    m = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', body, re.I)
    if m and re.match(r'(?:https?:)?//|javascript:', m.group(1).strip(), re.I):
        return {"how": "meta refresh", "target": m.group(1)[:100], "evidence": m.group(0)[:160]}
    m = re.search(r'(?:location\.(?:href|replace|assign)\s*=?\s*\(?|window\.location\s*=)\s*["\']((?:https?:)?//[^"\']+)', body, re.I)
    if m:
        return {"how": "JS location", "target": m.group(1)[:100], "evidence": m.group(0)[:160]}
    return None


# ── XML-RPC (주로 WordPress xmlrpc.php) 위험 응답 탐지 ────────────
# methodResponse 응답에서 악용 가능한 신호를 찾는다: 로그인 메서드 활성(brute-force 표면),
# system.multicall(brute-force 증폭), pingback.ping(SSRF/DDoS), 사용자 열거 메서드 등.
# 응답 형태(methodResponse)로 판정하므로 카테고리와 무관하며 오탐이 거의 없다.
_XMLRPC_METHOD_RISKS = [
    ("system.multicall", "system.multicall 노출 — 한 요청에 수백 개 인증 시도를 묶어 보내는 brute-force 증폭 가능", 88),
    ("pingback.ping",    "pingback.ping 노출 — 내부망 SSRF/포트스캔 및 pingback DDoS 벡터", 85),
    ("wp.getUsersBlogs", "wp.getUsersBlogs 노출 — XML-RPC 를 통한 계정 brute-force 가능", 82),
    ("wp.getUsers",      "wp.getUsers 노출 — 사용자 계정 열거 가능", 75),
    ("metaWeblog.getUsersBlogs", "metaWeblog.getUsersBlogs 노출 — 자격증명 검증(brute-force) 표면", 78),
]
# "Incorrect username or password" 및 흔한 로케일 변형
_XMLRPC_AUTH_FAULT_RE = re.compile(
    r"incorrect username or password|잘못된\s*(?:사용자|아이디|비밀번호)|사용자\s*이름 또는 비밀번호", re.I)


def _detect_xmlrpc(body: str):
    """XML-RPC 응답에서 취약/악용 가능 신호를 수집해 finding 리스트로 반환(없으면 [])."""
    if not body:
        return []
    low = body.lower()
    if "<methodresponse" not in low:
        # GET 등으로 XML-RPC 핸들러에 닿았을 때의 전형적 배너 → 엔드포인트 활성(공격 표면).
        # (methodResponse 가 아니면 그 외 응답은 XML-RPC 신호로 보지 않음 → 오탐 방지)
        if "xml-rpc server accepts post requests only" in low:
            return [{"name": "XML-RPC 엔드포인트 활성", "verdict": "미확정", "confidence": 45,
                     "why": "'XML-RPC server accepts POST requests only' 배너 → xmlrpc.php 활성(공격 표면). "
                            "POST 로 system.listMethods 를 보내 노출 메서드(pingback/multicall/인증)를 점검하세요.",
                     "evidence": body.strip()[:160]}]
        return []
    out = []

    # (1) 인증 메서드가 살아있음 — fault(top-level <fault> 또는 multicall 배열 내 faultString) +
    #     "Incorrect username or password". xmlrpc.php 가 로그인 시도를 처리·거부 =
    #     wp.getUsersBlogs 등 인증 메서드 활성(brute-force 표면). multicall 응답이면 증폭까지 확인.
    has_fault = "<fault" in low or "faultstring" in low or "faultcode" in low
    if has_fault and _XMLRPC_AUTH_FAULT_RE.search(body):
        # 배열 안에 fault struct 가 여러 개면 system.multicall 응답 = 증폭 벡터까지 확인됨
        multicall = ("<array" in low) and (low.count("faultstring") + low.count("faultcode")) >= 2
        why = ("xmlrpc.php 가 로그인 시도를 처리하고 'Incorrect username or password' fault 를 반환 "
               "→ 인증 메서드(wp.getUsersBlogs 등)가 활성. 계정 brute-force 표면.")
        if multicall:
            why += " 응답이 multicall 배열 형태 → system.multicall 로 한 요청에 다수 시도를 묶는 증폭도 가능."
        out.append({"name": "XML-RPC 인증 메서드 노출 (brute-force 표면)",
                    "verdict": "성공", "confidence": 88 if multicall else 85,
                    "why": why, "evidence": body.strip()[:200]})

    # (2) system.listMethods 등으로 노출된 위험 메서드 — 메서드명을 '토큰 경계'로 매칭해
    #     wp.getUsers 가 wp.getUsersBlogs 에 부분매칭되어 중복 탐지되던 문제 방지.
    for name, why, conf in _XMLRPC_METHOD_RISKS:
        if re.search(r'(?<![\w.])' + re.escape(name.lower()) + r'(?![\w.])', low):
            out.append({"name": f"XML-RPC 위험 메서드 — {name}", "verdict": "성공", "confidence": conf,
                        "why": why, "evidence": name})

    # (3) 위 신호가 없으면 XML-RPC 활성 자체를 정보성 신호로(공격 표면 존재)
    if not out:
        out.append({"name": "XML-RPC 엔드포인트 활성", "verdict": "미확정", "confidence": 45,
                    "why": "methodResponse 를 반환 → XML-RPC 엔드포인트가 켜져 있음(공격 표면). "
                           "system.listMethods 로 노출 메서드 점검 권장.",
                    "evidence": body.strip()[:200]})
    return out


# ── SPA 셸 감지 ──────────────────────────────────────────────
# 응답이 "빈 JS 마운트 지점 + 번들 스크립트"뿐이면 서버는 껍데기만 주고 본문은 브라우저가
# 렌더한다. 이 경우 파라미터 반사/주입이 서버 응답엔 안 나타나 HTTP 계층 테스트가 무의미하므로
# 실제 API(XHR)를 대상으로 하라고 경고한다.
_SPA_EMPTY_MOUNT_RE = re.compile(
    r'<div[^>]+id=["\'](?:root|app|__next|__nuxt)["\'][^>]*>\s*</div>', re.I)
_SPA_MOUNT_RE  = re.compile(r'id=["\'](?:root|app|__next|__nuxt)["\']', re.I)
_SPA_BUNDLE_RE = re.compile(r'<script[^>]+src=["\'][^"\']*\.js', re.I)
_SPA_TEXT_RE   = re.compile(r'<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>', re.I)


def _detect_spa_shell(body: str, headers_lower: dict) -> Optional[dict]:
    if not body or "html" not in (headers_lower.get("content-type") or ""):
        return None
    has_empty_mount = bool(_SPA_EMPTY_MOUNT_RE.search(body))
    has_mount  = bool(_SPA_MOUNT_RE.search(body))
    has_bundle = bool(_SPA_BUNDLE_RE.search(body))
    # 태그·스크립트 제거 후 가시 텍스트 길이
    visible = re.sub(r"\s+", " ", _SPA_TEXT_RE.sub(" ", body)).strip()
    thin = len(visible) < 200
    if not (has_empty_mount or (has_mount and has_bundle and thin)):
        return None
    b = body.lower()
    if "ng-version" in b:
        fw = "Angular"
    elif "__next" in b or "__next_data__" in b:
        fw = "Next.js"
    elif "__nuxt" in b:
        fw = "Vue/Nuxt"
    elif "reactroot" in b or 'id="root"' in b or "id='root'" in b:
        fw = "React"
    else:
        fw = "SPA"
    return {"framework": fw, "visible_len": len(visible)}


def _detect_reflection(body: str, payload: Optional[str]) -> Optional[dict]:
    """payload가 응답에 반사됐는지 + 미인코딩 여부 + 컨텍스트 추정."""
    if not payload or len(payload) < 3 or payload not in body:
        return None
    idx = body.find(payload)
    seg = body[:idx]
    # 컨텍스트 추정
    open_s = seg.rfind("<script")
    close_s = seg.rfind("</script")
    if open_s > close_s:
        ctx = "JavaScript(script 내부)"
    elif re.search(r'=\s*"[^"]*$', seg) or re.search(r"=\s*'[^']*$", seg):
        ctx = "HTML 속성값"
    else:
        ctx = "HTML 본문"
    # 미인코딩: payload에 특수문자가 있고 원문 그대로 존재하면 미인코딩(실행 위험)
    has_special = any(c in payload for c in "<>\"'")
    start = max(0, idx - 40)
    end = min(len(body), idx + len(payload) + 40)

    # 클라이언트측 XSS 실행 컨텍스트 정밀 판정 (반사 위치·payload 형태 기반)
    exec_ctx = None
    if re.search(r"\bon[a-z]+\s*=\s*[\"']?[^\"'>]*$", seg, re.I):
        exec_ctx = "이벤트 핸들러 속성"                       # ... onerror=" [여기]
    elif re.search(r"(?:href|src|action|formaction)\s*=\s*[\"']?\s*javascript:[^\"'>]*$", seg, re.I) \
            or payload.strip().lower().startswith("javascript:"):
        exec_ctx = "javascript: URI"
    elif ctx.startswith("JavaScript") and any(c in payload for c in "\"'`</"):
        exec_ctx = "script 내부(문자열 이탈)"                  # <script> 내부에서 문자열/블록 이탈 가능
    elif re.search(r"<\s*(?:script|img|svg|iframe|body|details|input|video|audio|object|embed|marquee)\b"
                   r"|on[a-z]+\s*=|javascript:", payload, re.I):
        exec_ctx = "HTML 본문(태그/핸들러 삽입)"               # 실행형 태그가 원문 삽입

    return {
        "reflected": True,
        "unescaped": bool(has_special),   # 특수문자 원문 반사 = 실행 가능성
        "exec_ctx": exec_ctx,             # 실행 가능 컨텍스트(없으면 None) — 클라이언트측 XSS 판정
        "context": ctx,
        "snippet": body[start:end],
        "payload": payload,
    }


def _extract_sleep_seconds(payload: str) -> Optional[int]:
    if not payload:
        return None
    for pat in (r"sleep\(\s*(\d+)", r"pg_sleep\(\s*(\d+)", r"WAITFOR\s+DELAY\s+'0:0:(\d+)",
                r"RECEIVE_MESSAGE\([^,]+,\s*(\d+)", r"\bsleep\s+(\d+)"):
        m = re.search(pat, payload, re.I)
        if m:
            return int(m.group(1))
    return None


# ── HTTP 메소드 기반 오라클(PUT 업로드·DELETE 삭제·WebDAV·TRACE) ────────────────
# 쓰기/삭제 메소드가 2xx 로 응답되면 그 자체가 성공 신호다(임의 파일 쓰기/삭제 = 심각).
_WEBDAV_METHODS = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH"}
# 쓰기 가능한 정적 파일처럼 보이는 경로(REST API의 PUT/DELETE 오탐을 줄이기 위한 확장자)
_STATIC_FILE_EXT = re.compile(
    r"\.(?:txt|html?|shtml|php\d?|phtml|jsp|jspx|asp|aspx|ashx|cer|cfm|pl|cgi|sh|bak|"
    r"config|cfg|ini|xml|svg|gif|jpe?g|png|js|css|jar|war|zip|bin|dat)(?:$|[?#])", re.I)


def _looks_static_file(path: str) -> bool:
    return bool(_STATIC_FILE_EXT.search(path or ""))


def _method_findings(method: str, status_code: int, url: str, body: str) -> list:
    """위험 HTTP 메소드의 응답으로 성공/활성 여부를 판정."""
    m = (method or "").upper().strip()
    if not m or m in ("GET", "POST", "HEAD"):
        return []
    parts = urlsplit(url or "")
    path = parts.path or (url or "")
    ok2xx = status_code in (200, 201, 204)
    denied = status_code in (403, 405, 501)   # 메소드 거부(양호)
    out = []

    if m == "PUT" and ok2xx:
        static = _looks_static_file(path)
        strong = status_code == 201 or static
        out.append({
            "name": "PUT 메소드 파일 업로드 허용", "verdict": "성공" if strong else "미확정",
            "confidence": 90 if status_code == 201 else (85 if static else 70),
            "why": ("PUT 요청이 " + str(status_code) + " 로 수락됨 → 서버에 임의 파일 쓰기가 허용됩니다"
                    "(WebDAV/PUT 활성). 웹셸(.jsp/.php 등) 업로드로 원격 코드 실행까지 이어질 수 있는 심각 취약점."
                    + ("" if strong else " REST API의 정상 PUT일 수 있으니 업로드 경로를 GET 하여 실제 생성 여부 확인 필요.")),
            "evidence": "PUT " + path + " → HTTP " + str(status_code)
                        + (" (201 Created)" if status_code == 201 else "") + "; 업로드 경로 GET 으로 파일 내용 확인 권장",
        })
    elif m == "DELETE" and status_code in (200, 202, 204):
        out.append({
            "name": "DELETE 메소드 리소스 삭제 허용", "verdict": "미확정", "confidence": 72,
            "why": "DELETE 요청이 " + str(status_code) + " 로 수락됨 → 임의 리소스 삭제가 가능할 수 있습니다. "
                   "대상 경로를 GET 하여 실제 삭제(404 전환) 여부를 확인하세요.",
            "evidence": "DELETE " + path + " → HTTP " + str(status_code),
        })
    elif m == "TRACE" and status_code == 200:
        echoed = "trace" in (body or "").lower() or "user-agent" in (body or "").lower()
        out.append({
            "name": "TRACE 메소드 활성(XST 가능)", "verdict": "성공" if echoed else "미확정",
            "confidence": 80 if echoed else 60,
            "why": "TRACE 가 200 으로 응답" + ("되고 요청이 그대로 반향됨 → Cross-Site Tracing 으로 "
                   "HttpOnly 쿠키·인증 헤더 탈취 가능." if echoed else " — TRACE 활성(XST 가능성). 응답 반향 확인 필요."),
            "evidence": "TRACE → HTTP 200" + ("; 응답에 요청 반향 확인" if echoed else ""),
        })
    elif m in _WEBDAV_METHODS and status_code < 400 and status_code not in (301, 302, 304):
        out.append({
            "name": "WebDAV 메소드 활성(" + m + ")", "verdict": "성공", "confidence": 82,
            "why": m + " 메소드가 " + str(status_code) + " 로 응답됨 → WebDAV 가 활성화되어 있습니다. "
                   "디렉터리 열람·파일 쓰기/이동 등 인증 우회 공격 표면이 노출됩니다.",
            "evidence": m + " " + path + " → HTTP " + str(status_code),
        })
    elif m == "CONNECT":
        # CONNECT 는 프록시/터널 수립 메소드. 일반 웹서버로 오면 오픈 프록시·터널 프로브다.
        # 경로/컨텍스트로 Cisco ASA WebVPN(AnyConnect) 터널 스캔을 식별한다:
        #   /cscosslc/tunnel · /+CSCOE+/ · /+CSCOU+/ · /+webvpn+/ · webvpn 쿠키.
        blob = ((url or "") + " " + (body or "")).lower()
        is_cisco = bool(re.search(r"cscosslc|/\+csco[eu]?\+|/\+webvpn\+|webvpn", blob))
        label = "Cisco ASA WebVPN 터널 스캔(CONNECT)" if is_cisco else "CONNECT 메소드(오픈 프록시/터널) 스캔"
        why_cisco = (" 경로/쿠키가 Cisco ASA WebVPN(AnyConnect) 터널 수립 요청과 일치 → "
                     "장비 지문 식별·인증 우회(CVE-2018-0101 계열 등) 표면 점검용 스캔입니다."
                     if is_cisco else "")
        if ok2xx:
            short_body = len((body or "").strip()) < 64
            success = short_body   # 정상 서버는 CONNECT 에 2xx 를 주지 않음. 빈/짧은 본문 2xx = 터널 수립
            out.append({
                "name": label, "verdict": "성공" if success else "미확정",
                "confidence": 85 if success else 60,
                "why": ("CONNECT 요청이 " + str(status_code) + " 로 수락됨 → 프록시/터널이 수립됩니다"
                        "(오픈 프록시 악용·내부망 피벗 가능)." + why_cisco
                        + ("" if success else " 본문이 일반 페이지 형태라 실제 터널 수립 여부는 원시 소켓 응답으로 재확인 필요.")),
                "evidence": "CONNECT " + path + " → HTTP " + str(status_code)
                            + ("; 빈/짧은 본문(터널 수립 정황)" if success else ""),
            })
        elif status_code in (400, 403, 405, 501, 502):
            out.append({
                "name": label + " — 거부됨", "verdict": "안전", "confidence": 72,
                "why": "CONNECT 요청이 " + str(status_code) + " 로 거부됨 → 프록시/터널 메소드가 비활성입니다(양호)."
                       + why_cisco,
                "evidence": "CONNECT " + path + " → HTTP " + str(status_code),
            })
        else:
            out.append({
                "name": label, "verdict": "미확인", "confidence": 45,
                "why": "CONNECT 요청에 HTTP " + str(status_code) + " 응답 → 프록시/터널 수립 여부가 불명확합니다. "
                       "원시 소켓으로 응답 라인을 확인하세요(200 이면 터널 수립)." + why_cisco,
                "evidence": "CONNECT " + path + " → HTTP " + str(status_code),
            })
    elif m in ("PUT", "DELETE") and denied:
        out.append({
            "name": m + " 메소드 거부됨", "verdict": "안전", "confidence": 70,
            "why": m + " 요청이 " + str(status_code) + " 로 거부됨 → 쓰기/삭제 메소드가 제한되어 있습니다(양호).",
            "evidence": m + " " + path + " → HTTP " + str(status_code),
        })

    # 미처리 비표준 메소드(OPTIONS/PATCH/임의 메소드 등)도 '메소드 스캔'으로 최소 인식한다.
    # (아무 finding 도 없으면 스캔 자체가 누락돼 보이는 문제 방지 — 응답으로 3-상태 판정)
    if not out:
        if denied or status_code in (400, 501):
            out.append({
                "name": m + " 메소드 스캔 — 거부됨", "verdict": "안전", "confidence": 65,
                "why": m + " 메소드가 " + str(status_code) + " 로 거부됨 → 비표준/위험 메소드가 제한되어 있습니다(양호).",
                "evidence": m + " " + path + " → HTTP " + str(status_code),
            })
        elif ok2xx:
            out.append({
                "name": m + " 메소드 스캔 — 수락됨", "verdict": "미확정", "confidence": 55,
                "why": m + " 메소드가 " + str(status_code) + " 로 수락됨 → 비표준 메소드가 처리됩니다. "
                       "의도된 동작인지, 위험 동작(쓰기/조회 우회)인지 응답 본문으로 확인하세요.",
                "evidence": m + " " + path + " → HTTP " + str(status_code),
            })
        else:
            out.append({
                "name": m + " 메소드 스캔", "verdict": "미확인", "confidence": 40,
                "why": m + " 메소드에 HTTP " + str(status_code) + " 응답 → 처리 여부가 불명확합니다. 응답을 확인하세요.",
                "evidence": m + " " + path + " → HTTP " + str(status_code),
            })
    return out


# ── 검증 내역(method/where) 부여 ──────────────────────────────────
# finding 이름(부분일치) → (검증 방법, 검증 위치). 각 신호가 "어떤 전략으로 / 어디서"
# 검증됐는지 명시해 분석 패널·리포트에 서술한다. docs/attack-verification.md 의 전략과 대응.
# 향후 룰 추가 시: 이 표에 한 줄 추가하거나, finding 에 method/where 를 직접 넣으면 됨(직접 지정 우선).
_VERIFY_META = [
    ("반사형 XSS",               ("반사+실행 컨텍스트",      "응답 본문의 payload 반사 위치")),
    ("payload 미인코딩 반사",     ("반사+실행 컨텍스트",      "응답 본문의 payload 반사 위치")),
    ("payload 반사",             ("반사 확인",              "응답 본문")),
    ("payload 인코딩 반사",       ("반사 확인(인코딩)",       "응답 본문(HTML 엔티티)")),
    ("DOM 기반 XSS",             ("정적 소스→싱크 분석",     "응답 <script> 내 소스/싱크")),
    ("클라이언트 템플릿 인젝션",    ("반사+프레임워크 확인",     "응답 본문 + 프레임워크 마커")),
    ("파일 읽기 성공",            ("콘텐츠 시그니처",         "응답 본문")),
    ("노출 확인 —",              ("콘텐츠 시그니처(nuclei)",  "응답 본문/헤더")),
    ("robots.txt",              ("콘텐츠 시그니처(recon)",   "응답 본문(Disallow/Allow)")),
    ("민감 파일 노출",            ("콘텐츠 시그니처",         "응답 본문")),
    ("민감 파일 미노출",          ("콘텐츠 시그니처(미검출)",  "응답 본문")),
    ("명령 실행 출력",            ("콘텐츠 시그니처",         "응답 본문")),
    ("내부/메타데이터 응답",       ("콘텐츠 시그니처",         "응답 본문")),
    ("템플릿 평가됨",             ("계산 결과",              "응답 본문(7*7→49)")),
    ("SQL/DB 에러 노출",          ("콘텐츠 시그니처",         "응답 본문(DB 에러)")),
    ("UNION 기반 SQLi",           ("콘텐츠 시그니처",         "응답 본문(추출된 DB 데이터)")),
    ("외부 리다이렉트",           ("상태/헤더 오라클",        "응답 헤더 Location")),
    ("위험 스킴 리다이렉트",       ("상태/헤더 오라클",        "응답 헤더 Location")),
    ("클라이언트측 오픈 리다이렉트", ("콘텐츠 시그니처",        "응답 본문 meta/JS")),
    ("시간 지연 일치",            ("타이밍",                "응답 시간 vs 요청 지연")),
    ("시간 지연 없음",            ("타이밍",                "응답 시간 vs 요청 지연")),
    ("베이스라인 대비 변화",       ("차분(baseline)",        "응답 상태·크기 vs baseline")),
    ("차분 판정(대조군 비교)",     ("차분(대조군)",           "응답 상태·본문 vs 대조군")),
    ("JWT alg=none",             ("토큰 구조 분석(+대조군)",  "요청 JWT 헤더")),
    ("CORS 오설정",              ("응답 헤더 시그니처",       "응답 ACAO/ACAC vs 요청 Origin")),
    ("GraphQL introspection",    ("응답 시그니처",           "응답 본문(스키마)")),
    ("CRLF 헤더 인젝션",         ("주입 헤더 vs 응답 헤더",   "응답 헤더")),
    ("인젝션 에러 노출",         ("응답 에러 시그니처",       "응답 본문(파서 에러)")),
    ("XML-RPC 인증 메서드 노출",   ("콘텐츠 시그니처",         "응답 본문(methodResponse)")),
    ("XML-RPC 위험 메서드",       ("콘텐츠 시그니처",         "응답 본문(methodResponse)")),
    ("XML-RPC 엔드포인트 활성",    ("응답 형태 확인",          "응답 본문(methodResponse)")),
    ("XML-RPC 취약 신호 미검출",   ("콘텐츠 시그니처(미검출)",  "응답 본문")),
    ("오픈 리다이렉트 취약 신호 미검출", ("상태/헤더 오라클(미검출)", "응답 헤더 Location + 본문")),
    ("CVE 확증 —",               ("CVE 매처(nuclei)",       "응답 상태/본문/헤더")),
    ("CVE 프로브 — 취약 징후 없음",  ("CVE 매처(미검출)+응답 형태", "응답 상태/본문")),
    ("취약 신호 미검출",           ("시그니처(미검출)",        "응답")),
    ("PUT 메소드",               ("상태/헤더 오라클",        "응답 상태코드")),
    ("DELETE 메소드",            ("상태/헤더 오라클",        "응답 상태코드")),
    ("TRACE 메소드",             ("상태/헤더 오라클",        "응답 상태코드+본문 에코")),
    ("WebDAV 메소드",            ("상태/헤더 오라클",        "응답 상태코드")),
    ("CONNECT 메소드",           ("상태/헤더 오라클",        "응답 상태코드(+본문 길이)")),
    ("Cisco ASA WebVPN 터널 스캔", ("경로 지문 + 상태 오라클",  "요청 경로/쿠키 + 응답 상태코드")),
    ("메소드 스캔",              ("상태/헤더 오라클",        "응답 상태코드")),
    ("메소드 거부됨",             ("상태/헤더 오라클",        "응답 상태코드")),
    ("차단됨",                   ("상태/헤더 오라클",        "응답 상태코드/차단 문구")),
    ("자동 판정 불가",            ("판정 불가",              "단일 응답(증거 없음)")),
]


def _verify_meta_for(name: str):
    for stem, meta in _VERIFY_META:
        if stem in (name or ""):
            return meta
    return None


def _enrich_verification(findings: list) -> list:
    """모든 finding 에 검증 방법(method)·위치(where)를 부여한다.
    finding 이 이미 값을 지정했으면 유지하고, 표에 없으면 안전한 기본값을 채워
    향후 추가되는 신호도 검증 내역을 항상 갖도록 한다."""
    for f in findings:
        meta = _verify_meta_for(f.get("name", ""))
        if meta:
            f.setdefault("method", meta[0])
            f.setdefault("where", meta[1])
        else:
            f.setdefault("method", "휴리스틱")
            f.setdefault("where", "응답")
    return findings


# robots.txt / 유사 recon 파일 — 숨겨진 경로(관리·백업·API 등) 노출 분석
_ROBOTS_INTERESTING = re.compile(
    r"/(?:admin|administrator|backup|bak|config|conf|api|internal|private|secret|"
    r"test|dev|staging|stage|db|sql|dump|log|logs|panel|manage|console|wp-admin|"
    r"phpmyadmin|\.git|\.env|\.svn|old|tmp|temp|upload|cgi-bin|server-status|"
    r"actuator|swagger|graphql|debug|hidden|flag|key|token|user|account)", re.I)


def _detect_robots(body, status_code, probe):
    """robots.txt 응답을 파싱해 노출된 경로를 분석. probe(요청)에 /robots.txt 가 있을 때만."""
    if "/robots.txt" not in (probe or "").lower():
        return None
    b = body or ""
    if status_code != 200 or not re.search(r"(?im)^\s*(?:user-agent|disallow|allow|sitemap)\s*:", b):
        return None
    paths = [p for p in dict.fromkeys(re.findall(r"(?im)^\s*(?:dis)?allow\s*:\s*(\S+)", b))
             if p not in ("/", "*", "")]
    sitemaps = re.findall(r"(?im)^\s*sitemap\s*:\s*(\S+)", b)
    interesting = [p for p in paths if _ROBOTS_INTERESTING.search(p)]
    return {"paths": paths, "interesting": interesting, "sitemaps": sitemaps}


def _reflection_candidates(payload, url, req_body):
    """반사 검사 대상 값 후보 — payload 뿐 아니라 요청의 실제 값(URL 쿼리·body)도 포함.
    URL 에 payload 를 직접 넣어 req.payload 가 빈 경우에도 반사형 XSS 를 잡기 위함."""
    cands = []
    if payload and payload.strip():
        cands.append(payload)               # 명시적 payload 는 항상 검사
    # URL/body 값은 XSS 특수문자(<>"')를 포함할 때만 후보 — benign 검색어 반사 노이즈 방지
    _susp = lambda v: any(c in v for c in "<>\"'")
    try:
        for _, v in parse_qsl(urlsplit(url or "").query, keep_blank_values=False):
            if v and len(v) >= 3 and _susp(v):
                cands.append(v)
    except Exception:
        pass
    b = (req_body or "").strip()
    if b:
        try:
            obj = json.loads(b)
            if isinstance(obj, dict):
                cands += [str(v) for v in obj.values()
                          if isinstance(v, (str, int, float)) and len(str(v)) >= 3 and _susp(str(v))]
        except Exception:
            for _, v in parse_qsl(b, keep_blank_values=False):   # form-encoded
                if v and len(v) >= 3 and _susp(v):
                    cands.append(v)
    return list(dict.fromkeys(cands))   # 순서 유지 중복 제거


# 후보에서 '실행형 구성요소'(script 태그 / 이벤트핸들러 태그 / javascript: 스킴) 추출.
_XSS_CONSTRUCT_RE = re.compile(
    r'<\s*script\b[^>]*>?'
    r'|<\s*[a-z][a-z0-9]*\b[^>]*?\bon[a-z]+\s*=[^>]*>?'
    r'|javascript:[^\s"\'>]+', re.I)


def _exec_construct_reflected(body, cand):
    """후보의 실행형 구성요소가 응답에 '인코딩 없이' 반사됐는지(대소문자 무시).
    서버가 일부 문자만 인코딩(예: 따옴표)해도 <svg onload=…> 가 원문으로 남으면 실행 가능 →
    전체 payload 리터럴 매칭이 실패해도 이걸로 잡는다. (HTML 전체 인코딩이면 태그가 &lt; 라 미매칭=안전)"""
    m = _XSS_CONSTRUCT_RE.search(cand or "")
    if not m:
        return None
    frag = m.group(0)
    if len(frag) < 6:
        return None
    idx = (body or "").lower().find(frag.lower())
    if idx < 0:
        return None
    return {"reflected": True, "exec_ctx": "HTML 본문(태그/핸들러 삽입)", "unescaped": True,
            "context": "HTML", "snippet": body[max(0, idx - 30): idx + len(frag) + 30], "payload": cand}


def _encoded_reflection(body, payload, url, req_body):
    """payload 가 응답 본문에 'HTML 엔티티로 인코딩'되어 반사됐는지(원문은 없고 인코딩본만).
    이 위치(응답 본문)에선 실행 안 됨(서버 방어) — 단 DOM 싱크가 있으면 클라이언트 실행 가능.
    사용자가 '왜 응답에 &quot;·&lt; 로 나오나' 헷갈리지 않도록 설명 신호로 표기한다."""
    b = body or ""
    for c in _reflection_candidates(payload, url, req_body):
        if not any(ch in c for ch in "<>\"'"):
            continue
        if c in b:                       # 원문이 이미 있으면 인코딩 반사 아님(다른 신호가 처리)
            continue
        base = c.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        for apos in ("&apos;", "&#39;", "&#x27;", "'"):     # 따옴표 인코딩 변형 대응
            enc = base.replace("'", apos)
            idx = b.find(enc)
            if idx >= 0 and len(enc) >= 6:
                return {"snippet": b[max(0, idx - 20): idx + len(enc) + 20], "payload": c}
    return None


def _best_reflection(body, payload, url, req_body):
    """후보 값들 중 '가장 강한' 반사를 선택(실행컨텍스트 > 미인코딩 > 단순반사).
    전체 반사가 안 잡히면 '실행형 구성요소'가 인코딩 없이 반사됐는지로 보강(인코딩 변형 일관성)."""
    rank = lambda r: 3 if r.get("exec_ctx") else (2 if r.get("unescaped") else 1)
    best = None
    for cand in _reflection_candidates(payload, url, req_body):
        r = _detect_reflection(body or "", cand) or _exec_construct_reflected(body or "", cand)
        if r and (best is None or rank(r) > rank(best)):
            best = r
            if rank(best) == 3:
                break
    return best


def _is_external_location(loc: str, url: Optional[str]) -> bool:
    """Location 이 요청 호스트와 다른 곳(=외부)을 가리키는지. 요청 URL 을 모르면 외부로 본다."""
    if not url:
        return True
    try:
        req_host = urlsplit(url).netloc.lower().split("@")[-1]
        loc_host = urlsplit(loc if "//" in loc else "//" + loc).netloc.lower().split("@")[-1]
    except Exception:
        return True
    if not req_host or not loc_host:
        return True
    # 포트 표기 차이(:80/:443)는 같은 호스트로 본다
    strip = lambda h: re.sub(r":(?:80|443)$", "", h)
    return strip(loc_host) != strip(req_host)


def _note_body_truncated(findings: list, shown: int, full: int) -> None:
    """본문이 잘린 상태에서 나온 '미검출' 계열 판정에 그 사실을 붙인다.

    시그니처가 응답에 '없다'는 판정은 응답 전체를 봤을 때만 성립한다. 앞부분만 보고
    내린 '안전/미확인' 을 근거 없이 단정처럼 보여주지 않기 위해 문구로 명시한다.
    """
    if not full or full <= shown:
        return
    note = (f"⚠ 응답 본문이 잘렸습니다 — 전체 {full:,}자 중 앞 {shown:,}자만 검사. "
            f"잘린 뒷부분에 신호가 있을 수 있어 '미검출'을 단정으로 보면 안 됩니다.")
    for f in findings:
        if f.get("verdict") not in ("안전", "미확인"):
            continue
        f["why"] = (f.get("why") or "") + " " + note
        f["evidence"] = (f.get("evidence") or "") + f" · 본문 절단({shown:,}/{full:,}자)"
        f["truncated_scope"] = True


def _first_redirect_hop(status_code, headers_lower, url, redirect_chain):
    """리다이렉트 판정에 쓸 "우리 요청에 대한 첫 3xx 응답" → (status, location, 그 홉의 요청 URL).

    - 리다이렉트를 따라가지 않았으면 현재 응답 자체가 첫 홉이다.
    - 따라갔으면 최종 응답엔 Location 이 없으므로 redirect_chain[0] 을 쓴다.
      2번째 이후 홉은 대상 사이트 내부 사정(사이트→CDN 등)이라 오픈 리다이렉트 근거가 아니다.
    없으면 (0, "", "") 를 돌려 판정을 건너뛴다.
    """
    if redirect_chain:
        hop = redirect_chain[0] or {}
        try:
            st = int(hop.get("status_code") or 0)
        except (TypeError, ValueError):
            st = 0
        return st, str(hop.get("location") or ""), str(hop.get("url") or url or "")
    if status_code in (301, 302, 303, 307, 308):
        # Location 은 원본 대소문자로 — 경로·토큰이 소문자로 뭉개지면 증거가 못 쓰게 된다.
        return status_code, _hdr_raw(headers_lower, "location"), url or ""
    return 0, "", ""


def _redirect_hint_probe(payload, url, req_body) -> str:
    r"""리다이렉트 힌트 판정용 프로브 — 대상 URL 의 scheme://host 는 뺀다.

    _REDIRECT_HINT 의 `//[a-z0-9.-]+\.` 는 주입값의 `//evil.com` 을 잡으려는 것인데,
    프로브에 대상 URL 자체가 섞여 있으면 점 있는 호스트면 무조건 매칭돼 평범한
    사이트→CDN 리다이렉트까지 오픈 리다이렉트로 오탐한다. 경로·쿼리·본문·payload 만 본다.
    """
    try:
        u = urlsplit(url or "")
        url_part = f"{u.path} {u.query}"
    except Exception:
        url_part = str(url or "")
    raw = f"{payload or ''} {url_part} {req_body or ''}"
    try:
        return raw + " " + unquote(unquote(raw))
    except Exception:
        return raw


def attack_findings(status_code, headers_lower, body, response_time, payload, category, baseline,
                    url=None, req_body=None, method=None, redirect_chain=None, req_headers=None):
    """공격별 성공 신호를 증거와 함께 수집. (findings, outcome, confidence) 반환.

    payload/카테고리에만 의존하지 않고, 요청 전체(payload+URL+본문)를 프로브로 삼아
    공격 유형을 추론한다. 그래서 PoC·붙여넣기 요청처럼 카테고리가 없어도 결과를 확인한다.
    """
    findings = []
    body_lower = (body or "").lower()
    # 공격 탐지용 프로브: payload 뿐 아니라 요청 URL(경로+쿼리)·본문까지 합친다.
    # 페이로드 미선택으로 주소/본문에만 공격이 들어간 경우(직접 GET·붙여넣기 POST)도 잡기 위함.
    # URL 인코딩된 요청(%27=', %2f=/ 등)도 매칭되도록 디코딩본을 함께 붙인다.
    _raw_probe = f"{payload or ''} {url or ''} {req_body or ''}"
    try:
        probe = _raw_probe + " " + unquote(unquote(_raw_probe))
    except Exception:
        probe = _raw_probe
    # '요청' 헤더에 실린 공격(Log4Shell·헤더 트래버설 등)도 파일-내용 게이트를 열도록 헤더
    # 텍스트를 덧붙인다. 파일읽기 판정은 엄격한 '응답 내용' 시그니처라 프로브를 넓혀도 허위 성공은 없다.
    _hdr_text = _classify._headers_text(req_headers or {})
    file_probe = probe + (' ' + _hdr_text if _hdr_text else '')
    # 리다이렉트 힌트는 대상 URL 의 호스트를 제외하고 판정(오픈 리다이렉트 오탐 방지)
    _redirect_probe = _redirect_hint_probe(payload, url, req_body)

    # ⓪ HTTP 메소드 오라클 — PUT 업로드·DELETE 삭제·WebDAV·TRACE (2xx 자체가 성공 신호)
    findings.extend(_method_findings(method, status_code, url, body))

    # ① payload 반사 (클라이언트측 XSS 실행 컨텍스트 정밀 판정 포함)
    #    payload 필드뿐 아니라 요청의 실제 값(URL 쿼리·body)도 검사 — URL 직접 입력 대응
    refl = _best_reflection(body or "", payload, url, req_body)
    if refl:
        if refl.get("exec_ctx"):
            findings.append({"name": "반사형 XSS(실행 컨텍스트)", "verdict": "성공", "confidence": 92,
                             "why": f"payload가 {refl['exec_ctx']}에 실행 가능한 형태로 반영됨 → 브라우저에서 스크립트 실행 가능(반사형 XSS)",
                             "evidence": refl["snippet"]})
        elif refl["unescaped"]:
            findings.append({"name": "payload 미인코딩 반사", "verdict": "성공", "confidence": 88,
                             "why": f"payload가 {refl['context']}에 인코딩 없이 반영됨 → XSS 등 실행 가능",
                             "evidence": refl["snippet"]})
        else:
            findings.append({"name": "payload 반사", "verdict": "미확정", "confidence": 40,
                             "why": f"{refl['context']}에 반영되나 특수문자 없음/인코딩 가능",
                             "evidence": refl["snippet"]})
    else:
        # 실행형 반사는 없지만 payload 가 '인코딩되어' 응답에 반사된 경우 → 서버 방어(이 위치는 안전).
        # DOM 싱크가 있으면 클라이언트에서 실행될 수 있음을 함께 안내(사용자 혼동 방지).
        enc = _encoded_reflection(body or "", payload, url, req_body)
        if enc:
            findings.append({"name": "payload 인코딩 반사 (응답 본문 — 여기선 안전)", "verdict": "안전", "confidence": 70,
                             "why": "서버가 payload 를 HTML 엔티티(&quot; &lt; &gt; &apos; 등)로 인코딩해 반사 → "
                                    "응답 본문 이 위치에선 실행되지 않음(서버측 방어). "
                                    "단, 클라이언트 JS(document.write 등 DOM 싱크)가 원본 입력을 다시 쓰면 실행될 수 있으니 "
                                    "DOM 싱크가 함께 탐지되면 브라우저 확증으로 검증하세요.",
                             "checked": "응답 본문의 HTML 엔티티 인코딩 반사",
                             "evidence": enc["snippet"]})

    # ② 카테고리별 성공 신호
    def _hit(markers):
        for pat, label in markers:
            m = re.search(pat, body or "", re.I)
            if m:
                s = max(0, m.start() - 20)
                return label, (body or "")[s:m.end() + 40]
        return None

    # 파일/소스 내용 노출 — 강한 시그니처는 요청 형태와 무관하게 '모든 응답'에서 확인하고,
    # 약한 시그니처는 파일 접근처럼 보일 때만(lfi/xxe 또는 _FILE_READ_HINT) 확인한다.
    h = _hit(_FILE_READ_MARKERS_STRONG)
    if not h and (category in ("lfi", "xxe") or _FILE_READ_HINT.search(file_probe)):
        h = _hit(_FILE_READ_MARKERS_WEAK)
    if h:
        findings.append({"name": "파일 읽기 성공", "verdict": "성공", "confidence": 92,
                         "why": h[0], "evidence": h[1]})
    # 명령 실행 출력 — uid/gid·Windows ver/dir 는 매우 구체적인 출력 시그니처라 요청 형태와
    # 무관하게 확인한다(어느 요청이든 이 출력이 있으면 명령 실행 성공).
    hc = _hit(_CMD_OUTPUT_MARKERS)
    if hc:
        findings.append({"name": "명령 실행 출력", "verdict": "성공", "confidence": 93,
                         "why": hc[0], "evidence": hc[1]})

    # 내부/클라우드 메타데이터 응답(SSRF) — 정상 API/문서에도 나올 수 있어, 요청이
    # SSRF 처럼 보일 때(내부주소·메타데이터 URL 등)만 성공 신호로 본다.
    if category == "ssrf" or _SSRF_HINT.search(probe):
        hs = _hit(_SSRF_MARKERS)
        if hs:
            findings.append({"name": "내부/메타데이터 응답", "verdict": "성공", "confidence": 85,
                             "why": hs[0], "evidence": hs[1]})

    # SSTI/EL/OGNL 표현식 평가는 canary 탐지기(core.detectors.CanaryEvalDetector)가 판정한다.
    #   7*7=49 하드코딩을 일반화 — 임의 피연산자의 '곱'을 확인해 우연 일치(‘49’ 흔함)를 없앴다.
    #   (아래 ④ run_registered 에서 tier-1 로 실행됨)

    # SQL/DB 에러 노출 — SQLi 처럼 보이는 요청일 때 error-based 성공 신호로 본다(카테고리 무관).
    if category == "sqli" or _SQLI_HINT.search(probe):
        for pat, desc in SQLI_ERROR_PATTERNS:   # 전역 + SQLi 문맥 전용(sqlmap 임포트분) 모두 적용
            if re.search(pat, body or "", re.I):
                findings.append({"name": "SQL/DB 에러 노출", "verdict": "성공", "confidence": 85,
                                 "why": f"{desc} — error-based 성공 가능", "evidence": desc})
                break
        # UNION/버전 추출 성공 — 버전 함수 결과(DB 배너)가 응답에 노출되면 데이터 추출 확증.
        #   에러 기반이 아니라 '추출된 데이터'라 error 마커로는 안 잡히던 케이스.
        if re.search(r"union\s+(?:all\s+)?select|v\$version|@@version|\bbanner\b|version\s*\(\)|"
                     r"information_schema|\bfrom\s+dual\b", probe, re.I):
            hv = _hit(_DB_VERSION_MARKERS)
            if hv:
                findings.append({"name": "UNION 기반 SQLi — DB 데이터 추출 성공", "verdict": "성공", "confidence": 92,
                                 "why": f"주입한 UNION/버전 쿼리 결과가 응답에 노출됨({hv[0]}) → DB 데이터 추출 확증",
                                 "evidence": hv[1]})

    # 외부 리다이렉트 — 3xx Location 이 외부로 나가면 오픈 리다이렉트 성공. 리다이렉트처럼
    # 보이는 요청일 때만(정상 SSO 리다이렉트 오탐 억제).
    #
    # 판정 대상은 "우리 요청에 대한 첫 응답"이다. 클라이언트가 리다이렉트를 따라갔으면
    # 최종 응답엔 Location 이 없으므로(그래서 예전엔 오픈 리다이렉트가 영원히 미검출),
    # 호출부가 넘겨준 redirect_chain 의 첫 홉으로 판정한다.
    hop_status, hop_loc, hop_url = _first_redirect_hop(status_code, headers_lower, url, redirect_chain)
    if category == "redirect" or _REDIRECT_HINT.search(_redirect_probe) or _DANGEROUS_SCHEME.search(_redirect_probe):
        _via = "" if not redirect_chain else " (따라간 리다이렉트 체인의 첫 홉)"
        # '외부' 여야 오픈 리다이렉트다. 같은 호스트로의 절대 URL 리다이렉트(로그인 페이지 이동 등)는
        # 성공이 아니므로 Location 호스트와 그 홉의 요청 호스트를 비교한다.
        if (hop_status and re.search(r"^https?://|^//", hop_loc, re.I)
                and _is_external_location(hop_loc, hop_url)):
            findings.append({"name": "외부 리다이렉트", "verdict": "성공", "confidence": 80,
                             "why": f"HTTP {hop_status} Location 헤더가 외부로 이동{_via}: {hop_loc[:80]}",
                             "evidence": f"HTTP {hop_status} Location: {hop_loc[:120]}"})
        # 위험 스킴 리다이렉트 — Location 이 javascript:/data:/vbscript: 로 나가면 XSS 로 이어짐
        elif hop_status and _DANGEROUS_SCHEME.match(hop_loc.strip()):
            findings.append({"name": "위험 스킴 리다이렉트(XSS)", "verdict": "성공", "confidence": 85,
                             "why": f"HTTP {hop_status} Location 헤더가 위험 스킴으로 이동{_via} → 클릭 시 스크립트 실행(XSS): {hop_loc[:80]}",
                             "evidence": f"HTTP {hop_status} Location: {hop_loc[:120]}"})

    # ②-c 민감 파일 노출 — 상태코드가 아니라 '실제 파일 내용'으로 노출/미노출을 판정.
    #     (카테고리 무관: .git/config·.env 등은 cve/path 프로브로 들어온다)
    sf = _detect_sensitive_file(file_probe, body or "", headers_lower, status_code)
    if sf and sf["exposed"]:
        if not h:   # 강한 마커(위)로 이미 노출을 잡았으면 중복 표기하지 않음
            findings.append({"name": f"민감 파일 노출 — {sf['targeted']}", "verdict": "성공", "confidence": 92,
                             "why": f"요청한 {sf['targeted']} 의 실제 내용이 응답에 노출됨 → 소스/시크릿 유출",
                             "checked": sf.get("checked", ""),
                             "evidence": sf["evidence"]})
    elif sf and status_code in (301, 302, 303, 307, 308):
        # 3xx 는 본문에 파일이 없는 게 당연 → '미노출' 이라 단정하지 않는다. Location 을 보는
        # FileScanRedirectDetector(tier-1)가 파일 존재/보호/추적필요를 판정한다(위음성 방지).
        pass
    elif sf:
        findings.append({"name": f"민감 파일 미노출 — {sf['targeted']}", "verdict": "안전", "confidence": 80,
                         "why": f"요청한 {sf['targeted']} 이(가) 응답 본문에 없음 → 파일 미노출"
                                " (200 응답은 일반 페이지·오류 페이지·SPA 껍데기일 수 있음)",
                         "checked": sf.get("checked", ""),
                         "evidence": f"응답에서 {sf['targeted']} 시그니처({sf.get('checked','')})를 "
                                     f"검색 → 없음 (HTTP {status_code} · {len(body or '')}B)"})

    # ②-c2 nuclei exposure 매처 — 임포트된 커뮤니티 시그니처로 노출 확증(경로 매칭 시에만 평가)
    findings.extend(_detect_exposure_sig(file_probe, body or "", headers_lower, status_code))

    # ②-c2b CVE 자기 매처 확증 — CVE 마다 성공 신호가 달라 공용 시그니처로는 검증 불가.
    #       import_nuclei 가 담아둔 그 CVE 자신의 matcher(status/word/regex)로만 확증한다.
    findings.extend(_detect_cve_sig(file_probe, body or "", headers_lower, status_code))

    # ②-c3 robots.txt — 노출된 경로(관리·백업·API 등) 분석. recon 단서.
    rb = _detect_robots(body or "", status_code, file_probe)
    if rb:
        if rb["interesting"]:
            ev = ", ".join(rb["interesting"][:8]) + (f" 외 {len(rb['interesting'])-8}" if len(rb["interesting"]) > 8 else "")
            findings.append({"name": "robots.txt 민감 경로 노출", "verdict": "미확정", "confidence": 55,
                             "why": f"robots.txt 가 흥미로운 경로를 노출: {ev} → 숨겨진 관리/백업/API 영역 recon 단서(직접 접근 점검)",
                             "checked": "robots.txt Disallow/Allow 경로", "evidence": ev})
        elif rb["paths"]:
            ev = ", ".join(rb["paths"][:8]) + (f" 외 {len(rb['paths'])-8}" if len(rb["paths"]) > 8 else "")
            findings.append({"name": "robots.txt 경로 노출", "verdict": "미확정", "confidence": 35,
                             "why": f"robots.txt 에 {len(rb['paths'])}개 경로 명시 → recon 단서(숨김 경로 점검): {ev}",
                             "checked": "robots.txt Disallow/Allow 경로", "evidence": ev})

    # ②-b 클라이언트측(client-side) 취약점 신호
    # DOM 기반 XSS — 응답 스크립트에서 소스→싱크 흐름 (XSS 테스트 시)
    if category == "xss" or refl:
        dom = _detect_dom_xss(body or "")
        if dom:
            findings.append({"name": "DOM 기반 XSS 싱크", "verdict": "미확정", "confidence": 55,
                             "why": f"클라이언트 입력({dom['source']})이 위험 싱크({dom['sink']})로 흐름 → DOM XSS 가능(브라우저 실행 확인 필요)",
                             "evidence": dom["evidence"]})
    # 클라이언트 템플릿 인젝션(CSTI) — 템플릿 표현식 미평가 반사 + 프레임워크 존재
    if category in ("xss", "ssti") or any(t in probe for t in ("{{", "${", "#{")):
        csti = _detect_csti(body or "", payload or "")
        if csti:
            findings.append({"name": "클라이언트 템플릿 인젝션(CSTI) 가능", "verdict": "미확정", "confidence": 60,
                             "why": "템플릿 표현식이 미평가 원문으로 반사 + 클라이언트 프레임워크 존재 → 브라우저 렌더링 시 평가 가능",
                             "evidence": csti["evidence"]})
    # 클라이언트측 오픈 리다이렉트 — meta refresh / JS location (서버 3xx 아님)
    if category == "redirect":
        cr = _detect_client_redirect(body or "")
        if cr:
            findings.append({"name": "클라이언트측 오픈 리다이렉트", "verdict": "성공", "confidence": 78,
                             "why": f"{cr['how']}로 외부 이동: {cr['target']} → 클라이언트에서 리다이렉트 실행",
                             "evidence": cr["evidence"]})

    # ②-d XML-RPC (WordPress xmlrpc.php 등) 위험 응답 — 응답 형태로 판정, 카테고리 무관
    findings.extend(_detect_xmlrpc(body or ""))

    # ②-e 시그니처 기반(비-blind) 검사의 '미검출 = 영향 없음(안전)' 판정.
    #     해당 검사를 겨냥한 요청인데 그 검사의 양성 신호가 하나도 없으면 '영향 없음' 으로 명시한다.
    #     ⚠️ blind/OOB 가능 계열(sqli·cmdi·ssrf·lfi·xxe·ssti·xss)은 제외 — 단일 응답으로
    #        취약 부재를 단정할 수 없어 기존 '자동 판정 불가(미확인)' 로 남긴다.
    #     각 항목: (라벨, probe 판정 함수, 양성 finding 이름 판별). 향후 비-blind 검사는 여기 추가.
    # probe 판정은 '대상 URL' 이 아니라 공격 의도(카테고리/페이로드)에 근거해야 오탐이 없다.
    # (대상 URL 의 https:// 를 리다이렉트/SSRF 힌트로 오인하지 않도록 category 중심으로 좁힘)
    _probed_xmlrpc = ((url and "xmlrpc" in url.lower())
                      or (category or "").lower() == "xmlrpc"
                      or (req_body and "<methodcall" in req_body.lower()))
    _probed_redirect = (category or "").lower() == "redirect"
    _SIG_SAFE_CHECKS = [
        ("XML-RPC",        _probed_xmlrpc,  lambda n: "XML-RPC" in n,
         "methodResponse · system.multicall · pingback.ping · wp.getUsersBlogs/getUsers · "
         "'Incorrect username or password' · 'accepts POST requests only'"),
        ("오픈 리다이렉트",  _probed_redirect, lambda n: "리다이렉트" in n,
         "3xx Location(외부 http(s)://·//) · 위험 스킴(javascript:/data:) · meta refresh · JS location"),
    ]
    for label, probed, is_positive, checked in _SIG_SAFE_CHECKS:
        if probed and not any(is_positive(f.get("name", "")) for f in findings):
            findings.append({
                "name": f"{label} 취약 신호 미검출 — 영향 없음", "verdict": "안전", "confidence": 75,
                "why": f"요청은 {label} 를 겨냥했으나 응답에서 취약 신호를 찾지 못함 → 이 검사 한정 영향 없음. "
                       "(blind/OOB 유형은 단일 응답으로 완전 배제 불가)",
                "checked": checked,
                "evidence": f"확인 시그니처 [{checked}] → 모두 미검출 (HTTP {status_code} · {len(body or '')}B)",
            })

    # ④ 등록된 탐지기(tier-1 시그니처/구조/canary + tier-2 차분) — core.detectors 레지스트리.
    #    파일스캔 3xx·인증우회·불리언·JWT·CORS·역직렬화 등을 판정한다. cve 미해당(②-f)보다 먼저
    #    돌려, 이 탐지기들의 성공/의심 신호가 '미해당(안전)'에 가려지지 않게 한다.
    _dctx = _detectors.DetectionContext(
        status_code=status_code, body=body or "", body_lower=body_lower,
        response_time=response_time, payload=payload, category=category,
        attack_type=infer_attack_type(probe, category), url=url, req_body=req_body,
        method=method, headers_lower=headers_lower, req_headers=req_headers,
        baseline=baseline, probe=probe)
    findings.extend(_detectors.run_registered(_dctx))

    # ②-f CVE 프로브 '미해당' 판정 — CVE 는 자기 매처로만 확증하므로, 매처가 맞지 않았고
    #     응답 자체가 익스플로잇 결과를 담을 수 없는 형태(3xx 리다이렉트·401/403·404·빈 본문)면
    #     '이 대상엔 해당 없음' 으로 정직하게 판정한다. (예전에는 무관한 파일읽기 시그니처로
    #      '미확인 + 무관한 확인 시그니처' 를 붙여 오해를 만들었다.)
    #     payload 가 다른 유형(트래버설 등)을 명확히 가리키면 그 유형 판정을 유지한다.
    cve_non_applicable = False
    if (category or "").lower() == "cve" and _classify.classify(
            payload=payload, url=url, req_body=req_body, category=category).primary == "cve" \
            and not any(f["verdict"] in ("성공", "의심") for f in findings):
        _reason = _cve_nonapplicable_reason(status_code, body, headers_lower)
        if _reason:
            _cchecked = _cve_checked_desc(file_probe) or _CVE_NO_MATCHER
            findings.append({
                "name": "CVE 프로브 — 취약 징후 없음(미해당)", "verdict": "안전", "confidence": 75,
                "why": f"{_reason}. 해당 CVE 의 확증 매처가 매칭되지 않았고 응답도 익스플로잇 결과를 "
                       "담을 수 없는 형태 → 이 대상에는 해당 없음(미해당). "
                       "(컴포넌트/버전이 다르거나 취약 경로가 없는 경우입니다)",
                "checked": _cchecked,
                "evidence": f"{_reason} (HTTP {status_code} · {len(body or '')}B)",
            })
            cve_non_applicable = True

    # ③ 타이밍 (time-based)
    n = _extract_sleep_seconds(payload)
    if n:
        if response_time >= n * 1000 * 0.8:
            findings.append({"name": "시간 지연 일치", "verdict": "성공", "confidence": 90,
                             "why": f"지연 {n}s 요청 → 실제 {response_time/1000:.1f}s 지연 (Blind time-based)",
                             "evidence": f"{response_time:.0f}ms ≈ {n}s"})
        else:
            findings.append({"name": "시간 지연 없음", "verdict": "미확정", "confidence": 30,
                             "why": f"{n}s 지연 payload지만 응답 {response_time:.0f}ms — 미영향/필터",
                             "evidence": f"{response_time:.0f}ms"})


    # ⑤ 차단 신호
    blocked = status_code in (403, 406, 429, 503) or _body_signals_block(status_code, body, body_lower)

    # 종합 판정
    success = [f for f in findings if f["verdict"] == "성공"]
    if success:
        outcome = "success"
        conf = max(f["confidence"] for f in success)
    elif cve_non_applicable:
        # 401/403 도 '차단' 이 아니라 'CVE 미해당' 이 더 정확한 서술이라 차단보다 우선한다.
        outcome = "safe"
        conf = max((f["confidence"] for f in findings if f["verdict"] == "안전"), default=75)
    elif blocked:
        outcome = "blocked"
        conf = 70
        # 403 등은 WAF가 payload 를 막은 것일 수도, 경로 자체가 원래 거부되는 것일 수도 있다.
        # baseline(정상 값) 이 없으면 'payload 특정 차단'인지 단정할 수 없으므로 그렇게 서술.
        why = f"상태 {status_code} 또는 차단 응답 — WAF/필터 또는 경로 자체 접근제한으로 거부됨"
        if not baseline:
            why += " (정상 파라미터로 baseline 비교 시 payload 특정 차단인지 구분 가능)"
        findings.append({"name": "차단됨", "verdict": "차단", "confidence": 70,
                         "why": why, "evidence": f"HTTP {status_code}"})
    elif any(f["verdict"] == "의심" for f in findings):
        # tier-2 차분/이상 신호 — 단일 응답 시그니처론 못 봤지만 대조군 대비 유의미한 차이가
        # 있음. '성공(확증)'도 '판정 불가(inconclusive)'도 아닌 중간 등급 — 추가 확인 대상.
        outcome = "suspicious"
        conf = max((f["confidence"] for f in findings if f["verdict"] == "의심"), default=60)
    elif any(f["verdict"] == "안전" for f in findings) and \
            not any(f["verdict"] in ("미확정", "미확인") for f in findings):
        # 시그니처 기반 검사가 '미노출/영향 없음'을 정의적으로 확인(예: 404 파일 미노출) →
        # '미확정' 이 아니라 'safe' 로 명확히 한다(AI 종합판정이 outcome 을 강제 반영).
        outcome = "safe"
        conf = max((f["confidence"] for f in findings if f["verdict"] == "안전"), default=70)
    else:
        outcome = "inconclusive"
        conf = 30
    return findings, outcome, conf


# ── 결정적 서술(AI 없이도 판정 요약·우선확인·조치를 생성) ──────────────────────
# AI 종합판정이 없거나(키 미설정) 실패해도 사용자에게 '무엇이/왜/어떻게'를 제공한다.
_DET_REMEDIATION = {
    "xss":      "출력 인코딩(문맥별)·CSP 적용, 사용자 입력을 HTML/JS 컨텍스트에 직접 삽입 금지",
    "sqli":     "파라미터라이즈드 쿼리/ORM 바인딩 사용, 입력 검증, DB 계정 최소권한",
    "cmdi":     "셸 호출 제거·인자 배열 실행, 입력 화이트리스트, 시스템 호출 최소화",
    "lfi":      "경로 정규화·화이트리스트, 사용자 입력으로 파일 경로 구성 금지",
    "xxe":      "XML 파서에서 외부 엔티티/DTD 처리 비활성화",
    "ssrf":     "아웃바운드 목적지 화이트리스트, 내부/메타데이터 대역 차단, 리다이렉트 검증",
    "ssti":     "사용자 입력을 템플릿 소스로 사용 금지, 로직리스/샌드박스 템플릿 사용",
    "redirect": "리다이렉트 대상 화이트리스트·상대경로만 허용",
    "xmlrpc":   "불필요하면 xmlrpc.php 비활성화, pingback/multicall 차단, 인증 rate limit",
    "nosql":    "쿼리 연산자 주입 방지(입력 타입 강제)·파라미터 바인딩",
    "idor":     "객체 접근마다 서버측 소유권/권한 검사",
    "cve":      "해당 컴포넌트를 패치된 버전으로 업데이트",
    "file":     "웹 루트에서 설정/시크릿 파일 제거·접근 차단, 배포 산출물에서 제외",
}
_DET_PRIORITY = {
    "success":      "공격 성공 신호 확인 — 취약점을 재현·검증하고 패치를 우선 적용",
    "safe":         "이 검사 한정 영향 없음 — 다른 파라미터/벡터로 범위를 넓혀 점검",
    "blocked":      "차단 확인 — 정상 파라미터로 baseline 비교해 '경로 자체 거부'인지 'payload 차단'인지 구분",
    "suspicious":   "의심 신호(대조군 대비 차이) — 확증 스캔으로 재현하거나 대조군을 넓혀 확인",
    "inconclusive": "단일 응답으로 판정 불가 — 확증 스캔(대조군 비교)·baseline·수동 확인 수행",
}


# ── 판정 불가·의심 이벤트의 '다음 단계' 안내(행동 가능하게) ─────────────────────
# inconclusive/suspicious 는 "판정 못 했다"로 끝내지 않고, 유형별로 '무엇을 하면 확증되는지'를
# 정확히 제시한다. confirm(확증 스캔)으로 되는 것 / OOB 콜백이 필요한 것 / 브라우저 확증이
# 필요한 것을 구분해 분석가가 바로 다음 행동을 고르게 한다.
_CONFIRM_SCAN = {"sqli", "ssti", "xss", "lfi", "cmdi", "redirect", "nosql", "idor",
                 "business", "ldap", "auth", "xpath"}       # 확증 스캔(대조군 프로브) 가능
_OOB_FAMILIES = {"cmdi", "ssrf", "xxe", "log4shell", "email", "deserial"}  # 블라인드/OOB 콜백 필요
_BROWSER_FAMILIES = {"xss", "prototype", "domclob", "cssinj", "csti"}      # 브라우저 DOM 확증

_UNDETERMINED_NEXT = {
    "sqli": "확증 스캔 실행(time-based SLEEP·error-based EXTRACTVALUE) 또는 정상값으로 baseline 저장 후 "
            "재요청해 불리언(참/거짓) 차이를 비교하세요.",
    "xss":  "payload 가 인코딩돼 반사됐는지(서버 방어) 확인하고, DOM 싱크가 있으면 브라우저로 실행을 확증하세요.",
    "lfi":  "다른 대상 파일(/etc/hosts·win.ini·/proc/self/environ)과 인코딩 변형(%2e··..%2f·이중인코딩)으로 재시도하세요.",
    "xxe":  "OOB DTD(외부 엔티티 콜백)나 error-based 파일읽기로 확증하세요 — 단일 응답으론 블라인드일 수 있습니다.",
    "ssti": "다른 템플릿 엔진 구문으로 재시도하세요({{7*7}}·${7*7}·#{7*7}·<%= 7*7 %>·%{7*7}).",
    "cmdi": "블라인드 계열 — time-based(;sleep 5) 또는 OOB 콜백(nslookup <마커>.oob)으로 확증하세요.",
    "ssrf": "OOB 콜백 URL(interactsh 류)로 아웃바운드 요청을 확인하세요 — 응답에 마커가 없으면 블라인드입니다.",
    "redirect": r"다양한 우회 표기로 재시도하세요(//evil·/\evil·https:evil·whitelisted.com@evil·인코딩).",
    "nosql": "$where 에 time-based(sleep) 주입 또는 정상 대비 참/거짓 응답 차이를 비교하세요.",
    "jwt":  "토큰 변형으로 재시도하세요(alg=none·약한 서명·kid 주입) — 서버 수용 여부는 대조군 상태전이로 확증됩니다.",
    "ldap": "error-based(파서 에러 유발) 또는 참/거짓 필터 차이로 확증하세요.",
    "xpath": "error-based(XPath 파서 에러) 또는 참/거짓 표현식 차이로 확증하세요.",
}


def _undetermined_next(attack_type: str) -> dict:
    """판정 불가/의심 이벤트의 다음 단계 안내 — 문구 + 확증 경로 플래그."""
    at = (attack_type or "").lower()
    text = _UNDETERMINED_NEXT.get(at)
    if not text:
        text = ("확증 스캔(대조군 비교)을 실행하거나, 정상 파라미터로 baseline 을 저장한 뒤 재요청해 "
                "차이를 비교하세요. 블라인드/OOB 계열이면 콜백 기반 확증이 필요합니다.")
    return {
        "text": text,
        "confirm_scan": at in _CONFIRM_SCAN,     # '확증 스캔' 버튼으로 자동 확증 가능
        "oob": at in _OOB_FAMILIES,              # OOB 콜백 필요(단일 응답 불가)
        "browser": at in _BROWSER_FAMILIES,      # 브라우저 DOM 확증 필요
    }


def _deterministic_narrative(result: dict) -> dict:
    """outcome·findings·attack_type·alerts 로 판정 요약/우선확인/조치를 결정적으로 생성."""
    outcome = result.get("attack_outcome") or "inconclusive"
    findings = result.get("findings") or []
    at = (result.get("attack_type") or "").lower()

    # 요약
    if result.get("sensitive_data"):
        summary = "민감 정보가 응답에 노출됨 — 즉시 조치 필요"
    elif result.get("error_leaks"):
        summary = "에러/DB 정보가 응답에 노출됨 — 정보 누출"
    else:
        succ = [f for f in findings if f.get("verdict") == "성공"]
        safe = [f for f in findings if f.get("verdict") == "안전"]
        if outcome == "success" and succ:
            summary = f"공격 성공 신호 확인 — {succ[0].get('name', '')}"
        elif outcome == "safe":
            summary = (safe[0].get("name") if safe else "취약 신호 미검출 — 영향 없음(이 검사 한정)")
        elif outcome == "blocked":
            summary = "요청이 차단됨 — WAF/필터 또는 경로 접근제한"
        elif outcome == "suspicious":
            _sus = [f for f in findings if f.get("verdict") == "의심"]
            summary = ("의심 신호 — " + (_sus[0].get("name", "") if _sus else "대조군 대비 차이") +
                       " (확증 필요)")
        else:
            summary = "자동 판정 불가 — 수동 확인 필요(단일 응답 증거 없음)"

    priority = _DET_PRIORITY.get(outcome, _DET_PRIORITY["inconclusive"])

    # 조치: 공격 성공/민감노출이면 유형별 조치, 그 외엔 응답 위생(alert) 조치
    rem_parts = []
    if outcome == "success" or result.get("sensitive_data") or result.get("error_leaks"):
        rem = _DET_REMEDIATION.get(at)
        if not rem and any("파일" in f.get("name", "") or "노출" in f.get("name", "") for f in findings):
            rem = _DET_REMEDIATION["file"]
        if rem:
            rem_parts.append(rem)
    hi_alerts = [a for a in (result.get("alerts") or []) if a.get("risk") in ("high", "medium")]
    if hi_alerts:
        rem_parts.append("응답 위생 점검: " + ", ".join(a.get("name", "") for a in hi_alerts[:3]))
    if rem_parts:
        remediation = " · ".join(rem_parts)
    elif outcome in ("safe", "blocked"):
        remediation = "추가 조치 불필요(현재 신호 기준)"      # 영향 없음/차단 → 유형별 조치 불필요
    else:
        remediation = "수동 확인 후 필요 시 대상 컴포넌트·입력 처리 점검"

    return {"summary": summary, "priority": priority, "remediation": remediation}


# ════════════════════════════════════════════════════════════════════════════════
# 메인 분석 함수
# ════════════════════════════════════════════════════════════════════════════════

def analyze_response(
    status_code: int,
    headers: dict,
    body: str,
    response_time: float,
    payload: Optional[str] = None,
    category: Optional[str] = None,
    baseline: Optional[dict] = None,
    url: Optional[str] = None,
    req_body: Optional[str] = None,
    method: Optional[str] = None,
    redirect_chain: Optional[list] = None,
    body_truncated: bool = False,
    full_body_len: Optional[int] = None,
    custom_alert_rules: Optional[list] = None,
    req_headers: Optional[dict] = None,   # 요청 헤더 — 헤더에 실린 공격(Log4Shell 등) 분류용
) -> dict:
    """HTTP 응답을 분석하여 보안 판정 결과 반환.

    url: 요청 URL(경로+쿼리). payload 를 고르지 않고 주소만으로 민감 파일을
         직접 GET 한 경우(예: /public/.git/config)도 탐지하기 위해 함께 검사한다.
    redirect_chain: 클라이언트가 따라간 리다이렉트 홉 목록
         [{status_code, location, url}, …] (따라가지 않았으면 None/[]).
         따라간 경우 최종 응답엔 Location 이 없어 오픈 리다이렉트를 판정할 수 없으므로,
         첫 홉을 여기로 넘겨야 한다.
    body_truncated / full_body_len: body 가 상한으로 잘렸는지와 원본 길이.
         잘린 채로 낸 '미검출(안전/미확인)' 판정에 그 사실을 명시하기 위함
         — 앞부분만 보고 '없다'고 단정하면 위음성을 안전으로 보고하게 된다.
    custom_alert_rules: 사용자 정의 Alert 룰. 예전엔 브라우저에서만 돌아 단일 전송
         화면에만 반영됐다 — 여기서 평가해 일괄 테스트·리포트에도 똑같이 적용한다.
    """

    result = {
        "verdict": "unknown",
        "confidence": 0,
        "waf_detected": None,
        "tech_stack": [],       # 프록시/CDN/웹서버/프레임워크 지문(Envoy, Next.js 등)
        "block_reason": [],
        "error_leaks": [],
        "sensitive_data": [],
        "response_anomalies": [],
        "risk_level": "info",
        "details": [],
        "score": 0,
        "alerts": [],          # ZAP 스타일 Alert 목록
        "findings": [],        # 공격 결과 신호(증거 기반)
        "attack_outcome": None,  # success | blocked | inconclusive
        "reflection": None,
        "spa_shell": None,     # SPA 껍데기면 {framework, visible_len}
        "body_truncated": False,   # 상한으로 본문이 잘렸는지(‘미검출’ 판정의 신뢰 범위)
        "body_len_seen": 0,        # 실제로 검사한 길이
        "body_len_full": 0,        # 원본 길이
    }

    body = body or ""
    body_lower = body.lower()
    # 매칭은 소문자, 증거 표시는 원본 — HeaderView 가 둘 다 들고 있다.
    headers_lower = HeaderView(headers)

    # 1. 상태코드 분석
    if status_code in [403, 406, 429, 503]:
        result["verdict"] = "blocked"
        result["confidence"] = 75
        result["details"].append(f"HTTP {status_code} — 차단 응답")
        result["block_reason"].append(f"상태코드 {status_code}")
    elif status_code == 400:
        result["verdict"] = "blocked"
        result["confidence"] = 60
        result["details"].append("HTTP 400 — 잘못된 요청 (WAF 필터링 가능성)")
        result["block_reason"].append("상태코드 400")
    elif status_code == 200:
        result["verdict"] = "passed"
        result["confidence"] = 50
        result["details"].append("HTTP 200 — 요청 통과")
    elif status_code >= 500:
        result["verdict"] = "error"
        result["confidence"] = 40
        result["details"].append(f"HTTP {status_code} — 서버 에러")

    # 2. WAF 헤더 탐지
    result["tech_stack"] = detect_stack(headers_lower)
    waf_name = detect_waf(headers_lower)
    if waf_name:
        result["waf_detected"] = waf_name
        result["details"].append(f"WAF 탐지: {waf_name}")
        result["confidence"] = min(result["confidence"] + 20, 95)

    # 3. 응답 바디 차단 키워드 — 단, 대형 성공 응답의 우연한 매칭은 차단으로 보지 않는다
    if _body_signals_block(status_code, body, body_lower):
        for kw in BLOCK_KEYWORDS:
            if kw in body_lower:
                result["block_reason"].append(f"바디 키워드: '{kw}'")
                result["verdict"] = "blocked"
                result["confidence"] = min(result["confidence"] + 15, 95)

    # 4. 에러 누출 탐지 (실제 탐지된 증거 문자열을 함께 표기 → 응답에서 검색·검증 가능)
    for pattern, desc in ERROR_LEAK_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            ev = _clip_evidence(m.group(0), 120)
            result["error_leaks"].append(f"{desc}: {ev}" if ev else desc)
            result["details"].append(f"⚠️ 에러 정보 누출: {desc}" + (f" — {ev}" if ev else ""))
            if result["verdict"] == "passed":
                result["verdict"] = "bypass"
            result["risk_level"] = "high"

    # 5. 민감 정보 탐지 (실제 탐지된 증거 문자열을 함께 표기)
    for pattern, desc in SENSITIVE_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            ev = _clip_evidence(m.group(0), 120)
            result["sensitive_data"].append(f"{desc}: {ev}" if ev else desc)
            result["details"].append(f"🔴 민감 정보 노출: {desc}" + (f" — {ev}" if ev else ""))
            result["verdict"] = "bypass"
            result["risk_level"] = "critical"

    # 6. 응답 시간 이상
    if response_time > 5000:
        result["response_anomalies"].append(f"응답 지연 {response_time:.0f}ms (Time-based 공격 가능성)")
        result["details"].append(f"⏱️ 응답 지연 탐지: {response_time:.0f}ms")

    # 7. 응답 크기 이상
    if len(body) < 50 and status_code == 200:
        result["response_anomalies"].append("비정상적으로 짧은 200 응답")

    # 8. ZAP 스타일 Alert 실행 (+ 사용자 정의 룰 — 모든 경로에서 같은 엔진으로)
    result["alerts"] = run_alert_rules(headers_lower, body, body_lower, status_code)
    result["alerts"] += run_custom_alert_rules(custom_alert_rules, headers_lower, body,
                                               body_lower, status_code)
    result["alerts"] += run_dom_alerts(body)   # DOM 기반 취약점 싱크(소스 동시 존재 시)
    result["alerts"] += run_api_doc_alerts(url, body, headers_lower, status_code)  # API 문서/엔드포인트 노출
    _risk_order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    result["alerts"].sort(key=lambda a: _risk_order.get(a.get("risk"), 9))

    # 9. Alert 위험도를 종합 risk_level에 반영
    alert_risks = [a["risk"] for a in result["alerts"]]
    if "high" in alert_risks and result["risk_level"] not in ("critical",):
        result["risk_level"] = "high"
    elif "medium" in alert_risks and result["risk_level"] in ("info", "low"):
        result["risk_level"] = "medium"

    # 11. 공격 결과 분석(반사/카테고리 성공신호/타이밍/베이스라인) — 증거 기반.
    #     위험도 산정(10)보다 먼저 실행해, '차단 안 됨'이 아니라 '실제 증거'로 판정한다.
    findings, outcome, aconf = attack_findings(
        status_code, headers_lower, body, response_time, payload, category, baseline, url, req_body, method,
        redirect_chain, req_headers,
    )
    result["reflection"] = _detect_reflection(body, payload)
    result["spa_shell"] = _detect_spa_shell(body, headers_lower)

    # 3-상태 명확화: 성공/안전(차단)이 아니고 아무 신호도 없는 '공격 시도'는 '안전'이 아니라
    # '자동 판정 불가(수동 검토 필요)'로 명시한다. (블라인드/OOB/로직/시그니처 없는 파일 등
    # 단일 응답으로 판정 못 하는 유형이 거짓 안심을 주지 않도록.)
    # payload/URL 로 실제 공격 유형을 추론(카테고리 라벨이 틀릴 수 있음) — 서술·AI 판정에 사용
    _probe_all = f"{payload or ''} {url or ''} {req_body or ''}"
    # 요청 헤더까지 넘겨 헤더에 실린 공격(Log4Shell·Shellshock 등)도 분류한다.
    # 헤더 공격은 "요청" 헤더에 있다(응답 헤더가 아니라). SOC 붙여넣기의 Log4Shell·Shellshock 대응.
    # url·body·headers 를 구조화해 넘겨야 classify 가 대상 host 를 분류에서 제외한다
    # (내부 IP 대상이 SSRF 로 오분류되는 것 방지).
    _req_hv = HeaderView(req_headers or {})
    result["attack_type"] = _classify.classify(
        payload=payload, url=url, req_body=req_body, headers=_req_hv, category=category
    ).primary or (category or "").lower()

    is_attack_attempt = bool((payload and payload.strip()) or category)
    has_signal = any(f.get("verdict") in ("성공", "안전", "미확정", "의심") for f in findings)
    if (is_attack_attempt and outcome == "inconclusive" and not has_signal
            and not result["sensitive_data"] and not result["error_leaks"]):
        _mprobe = _probe_all
        _sigs = _checked_desc_for(_mprobe, category)
        _bn = "" if baseline else " · baseline 없음"
        _nx = _undetermined_next(result["attack_type"])
        findings.append({
            "name": "자동 판정 불가 — 다음 단계로 확증 필요", "verdict": "미확인", "confidence": 30,
            "why": "성공/실패를 단일 응답으로 판정할 근거(반사·에러·마커·시간차·베이스라인 변화)를 찾지 "
                   "못했습니다. 블라인드/OOB/로직 계열이거나 이 대상에 취약하지 않을 수 있습니다. → "
                   + _nx["text"],
            "checked": _sigs,
            "next_action": _nx["text"],
            "confirm_scan": _nx["confirm_scan"], "oob": _nx["oob"], "browser": _nx["browser"],
            "evidence": f"응답에서 성공 시그니처 [{_sigs}]를 검색 → 미검출; 반사·시간지연·baseline 변화도 없음 "
                        f"(HTTP {status_code} · {len(body)}B · {response_time:.0f}ms{_bn})",
        })

    # 본문이 잘렸으면 '미검출' 계열 판정에 검사 범위를 명시(위음성을 안전으로 보고하지 않도록)
    _seen = len(body)
    _full = int(full_body_len) if full_body_len else _seen
    result["body_truncated"] = bool(body_truncated and _full > _seen)
    result["body_len_seen"], result["body_len_full"] = _seen, _full
    if result["body_truncated"]:
        _note_body_truncated(findings, _seen, _full)
        result["response_anomalies"].append(
            f"응답 본문 절단 — 전체 {_full:,}자 중 앞 {_seen:,}자만 분석(뒷부분 미검사)")

    result["findings"] = _enrich_verification(findings)   # 전 finding에 검증 내역(method/where) 부여
    result["attack_outcome"] = outcome
    result["attack_confidence"] = aconf

    # 10. 최종 위험도 산정 — '차단되지 않음'이 아니라 '취약 증거'를 기준으로 한다.
    if result["verdict"] == "bypass" or result["sensitive_data"]:
        result["risk_level"] = "critical"
        result["score"] = 90
    elif result["error_leaks"]:
        result["risk_level"] = "high"
        result["score"] = 70
    elif result["verdict"] == "passed":
        # (구) '차단 안 됨 + sqli/cmdi/ssrf → high/65' 휴리스틱 제거: 차단되지 않았다고
        #  취약한 것은 아니다(방어장비 미탐 ≠ 대상 취약). 실제 성공은 아래 성공 격상에서
        #  처리하고, 증거가 없으면 미확정 신호 유무로만 위험도를 나눠 오탐을 막는다.
        if outcome == "success":
            pass   # 성공 격상 블록에서 risk/score 확정
        elif any(f.get("verdict") in ("성공", "미확정", "의심") for f in findings):
            result["risk_level"] = "medium"   # 반사·베이스라인 변화 등 추가 확인 필요 신호
            result["score"] = 40
        else:
            # 차단도 안 됐고 우려 신호도 없음(‘안전/미노출’ 신호만 있거나 무신호) → 낮음
            result["risk_level"] = "low"
            result["score"] = 25
    elif result["verdict"] == "blocked":
        result["risk_level"] = "info"
        result["score"] = 10
    else:
        # 상태코드로 판정 불가(404/405/410 등) — '차단 안 됨'이 아니라 '증거 신호'로 위험도 결정.
        # 404 처럼 대상이 없거나 '안전(미노출)' 신호만 있으면 medium 이 아니라 낮게 잡아 오탐 방지.
        if any(f.get("verdict") in ("성공", "미확정", "의심") for f in findings):
            result["risk_level"] = "medium"
            result["score"] = 40
        else:
            result["risk_level"] = "low"
            result["score"] = 20

    # 공격 성공이 증거로 확인되면 종합 판정/위험도 격상(상태코드 relabel보다 신뢰도 높음)
    if outcome == "success":
        result["verdict"] = "bypass"
        if result["risk_level"] not in ("critical",):
            result["risk_level"] = "high"
        result["score"] = max(result["score"], aconf)

    # 결정적 서술(AI 미설정/실패 시 폴백, AI 있어도 누락 항목 보강용) — 항상 생성
    # 판정 불가·의심 이벤트의 '다음 행동' — UI 가 확증 스캔/OOB/브라우저 CTA 를 안내하도록 최상위 노출.
    if outcome in ("inconclusive", "suspicious"):
        _nxa = _undetermined_next(result["attack_type"])
        if outcome == "suspicious":
            _sus = [f for f in result["findings"] if f.get("verdict") == "의심"]
            _lead = (_sus[0].get("why", "") if _sus else "대조군 대비 차이가 관측됨")
            _nxa = dict(_nxa, text=f"의심 신호를 확증하세요 — {_nxa['text']}")
            result["next_action"] = {"outcome": "suspicious", "lead": _lead[:160], **_nxa}
        else:
            result["next_action"] = {"outcome": "inconclusive", "lead":
                "단일 응답으론 판정 근거가 없습니다", **_nxa}
    else:
        result["next_action"] = None

    result["det_verdict"] = _deterministic_narrative(result)

    return result


def generate_summary(results: list) -> dict:
    total = len(results)
    if total == 0:
        return {}

    blocked = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "blocked")
    passed  = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "passed")
    bypass  = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "bypass")
    error   = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "error")

    detection_rate = (blocked / total * 100) if total > 0 else 0

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        lvl = r.get("analysis", {}).get("risk_level", "info")
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    return {
        "total": total,
        "blocked": blocked,
        "passed": passed,
        "bypass": bypass,
        "error": error,
        "detection_rate": round(detection_rate, 1),
        "risk_counts": risk_counts,
        "waf_detected": list({
            r.get("analysis", {}).get("waf_detected")
            for r in results
            if r.get("analysis", {}).get("waf_detected")
        }),
    }
