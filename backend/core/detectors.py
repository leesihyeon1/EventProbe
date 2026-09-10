"""탐지기 추상화 — 판정을 '무슨 공격인가(분류)'가 아니라 '통했는가(판정)'로 좁게 확증한다.

배경(왜 이 구조가 필요한가):
    기존 판정은 analyzer.attack_findings 안 ~21개 인라인 if-블록이 전부다. 각 블록이
    고정 시그니처(root:x:0:0·uid=0 등 ~409개)로만 성공을 판정한다. 그래서:
      - 시그니처가 없는 알려진 공격(등록 카테고리 30종 중 ~20종)은 판정 불가
      - 차분(정상 vs 공격 응답)으로만 드러나는 공격(블라인드 SQLi·인증우회·IDOR·불리언)은
        '베이스라인 대비 변화(미확정)'에 묻혀 성공으로 격상되지 않음

이 모듈은 탐지기를 (id, tier, applies, detect) 계약으로 추상화한다:
      tier 1 = 시그니처(기존 인라인 블록이 이 계층) — 강한 직접 증거
      tier 2 = 차분/이상 — 대조군(baseline) 비교로 확증
      tier 3 = AI(추후) — 위 둘이 놓친 것을 '의심'까지만 격상(판정은 못 뒤집음)

분류(core.classify)는 '무슨 공격인가'를 넓게 정하고, 이 탐지기들은 '통했는가'를 좁게 판정한다.
그래서 분류를 관대하게 잡아도 허위 성공(오탐)은 늘지 않는다 — 판정은 증거·차분으로만.

새 탐지기를 붙이려면 Detector 를 구현해 REGISTRY 에 등록하면 된다(인라인 21블록을 안 건드림).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class DetectionContext:
    """탐지기 전원이 공유하는 읽기 전용 입력. analyzer 가 조립해 넘긴다."""
    status_code: int
    body: str
    body_lower: str
    response_time: float
    payload: Optional[str] = None
    category: Optional[str] = None
    attack_type: str = ""             # core.classify 결과(무슨 공격인가)
    url: Optional[str] = None
    req_body: Optional[str] = None
    method: Optional[str] = None
    headers_lower: Optional[dict] = None    # 응답 헤더(소문자)
    req_headers: Optional[dict] = None      # 요청 헤더
    baseline: Optional[dict] = None         # 대조군(정상) 응답 {status_code, body, ...}
    probe: str = ""                    # payload+url+body(+디코딩) — 게이트 판정용

    # 편의: 대조군이 실제로 비교 가능한 형태인지
    def has_control(self) -> bool:
        return bool(self.baseline) and self.baseline.get("status_code") is not None


# ── 인증 실패/차단 문구(차분에서 '실패 문구 소멸' 판정용) ──────────────────────
_AUTH_FAIL_RE = re.compile(
    r"(?:invalid|incorrect|wrong|failed|denied|unauthorized|forbidden|not\s+allowed|"
    r"로그인\s*실패|인증\s*실패|권한\s*없|아이디\s*(?:또는|/)?\s*비밀번호|"
    r"틀렸|잘못된\s*(?:자격|비밀번호|아이디))", re.I)
_ERROR_5XX = re.compile(r"\b(?:exception|stack\s*trace|traceback|fatal error|syntax error|"
                        r"sql\b.*error|odbc|jdbc)\b", re.I)


# 인증 실패 시 되돌리는 리다이렉트 타깃(로그인/에러 페이지). 401/403 → 이런 곳으로의 3xx 는
# '우회'가 아니라 '거부를 리다이렉트로 표현'한 것 → 인증우회로 오판하면 안 된다.
_LOGIN_REDIRECT_RE = re.compile(
    r"/(?:login|log-in|signin|sign-in|sso|auth(?:enticate|orize)?|account/login|session/new|"
    r"error|denied|unauthor(?:ized|ised)|forbidden|403|401|access-?denied)", re.I)


def _redirect_is_auth_reject(location):
    """3xx Location 이 로그인/인증/에러 페이지를 가리키면 True(=거부지 우회가 아님)."""
    return bool(location) and bool(_LOGIN_REDIRECT_RE.search(location))


class Detector:
    """탐지기 계약. applies() 로 이 요청에 돌릴지 정하고 detect() 로 finding(dict) 목록을 낸다."""
    id: str = ""
    tier: int = 2
    attack_types: frozenset = frozenset()

    def applies(self, ctx: DetectionContext) -> bool:
        return True

    def detect(self, ctx: DetectionContext) -> list:
        return []


def _hdr(headers, name: str) -> str:
    """헤더 값을 대소문자 무관하게 읽는다. dict/HeaderView(소문자키) 모두 허용. 없으면 ''."""
    if not headers:
        return ""
    name = name.lower()
    for k, v in headers.items():
        if str(k).lower() == name:
            return str(v or "")
    return ""


REGISTRY: list = []


def register(det: Detector) -> Detector:
    REGISTRY.append(det)
    return det


def run_registered(ctx: DetectionContext, max_tier: int = 2) -> list:
    """등록된 탐지기(tier ≤ max_tier)를 돌려 finding 목록을 모은다. 하나가 죽어도 나머지 진행."""
    out = []
    for det in REGISTRY:
        if det.tier > max_tier:
            continue
        try:
            if det.applies(ctx):
                out.extend(det.detect(ctx) or [])
        except Exception:
            continue
    return out


# ══════════════════════════════════════════════════════════════════════════════
# tier-2 차분 탐지기 — 대조군(baseline) 비교로 '통했는가'를 확증
# ══════════════════════════════════════════════════════════════════════════════
# 블라인드 SQLi·인증우회·IDOR·불리언 등 '단일 응답으론 못 보고 정상 대비 차이로만 드러나는'
# 공격을 판정한다. 예전엔 이 신호가 전부 '베이스라인 대비 변화(미확정)' 하나로 뭉개졌다.
#
# 강도 등급:
#   성공(강): 인증 상태 전이(401/403 → 200/3xx) · 실패문구 소멸 + 200  → 인증우회 확증
#   의심(중): 본문 크기 유의미 변화 · 상태 변화(비인증) · 5xx 에러 유발  → 추가 확인 필요
#   무시(약): 사소한 차이(< 임계)
_BODY_DELTA_STRONG = 512      # 이 이상 본문 크기 차이 = 불리언 참/거짓 페이지 구분 가능성 높음
_BODY_DELTA_WEAK = 64


class DifferentialDetector(Detector):
    id = "differential"
    tier = 2
    attack_types = frozenset()     # 카테고리 무관 — 대조군만 있으면 어떤 공격이든 적용

    def applies(self, ctx: DetectionContext) -> bool:
        # 공격 시도(payload/category/공격분류 중 하나)가 있고 대조군이 있을 때만
        is_attack = bool((ctx.payload and ctx.payload.strip()) or ctx.category or ctx.attack_type)
        return is_attack and ctx.has_control()

    def detect(self, ctx: DetectionContext) -> list:
        b = ctx.baseline or {}
        b_status = b.get("status_code")
        b_body = b.get("body") or ""
        c_status = ctx.status_code
        c_body = ctx.body or ""
        dl = len(c_body) - len(b_body)

        b_fail = bool(_AUTH_FAIL_RE.search(b_body))
        c_fail = bool(_AUTH_FAIL_RE.search(c_body))

        # ── 강: 인증 상태 전이 = 인증우회 확증 ──
        # 대조(정상 파라미터)는 거부(401/403)인데 공격은 통과 → 우회. 단, 3xx 는 Location 을 봐야
        # 한다: 로그인/에러 페이지로의 리다이렉트는 '거부를 리다이렉트로 표현'한 것이지 우회가 아니다.
        # 307/308 은 메소드·본문을 보존하므로(RFC 7538) 증거에 그 사실을 함께 남긴다.
        if b_status in (401, 403):
            loc = _hdr(ctx.headers_lower, 'location')
            if c_status in (200, 201):
                return [self._f("성공", 84,
                                f"인증 우회 — 정상 파라미터는 HTTP {b_status}(거부)인데 공격은 "
                                f"HTTP {c_status}(직접 통과) → 접근제어 우회 확증",
                                f"상태 {b_status}→{c_status}")]
            if c_status in (301, 302, 303, 307, 308):
                if _redirect_is_auth_reject(loc):
                    # 로그인/에러 페이지로 되돌림 = 거부→거부. 우회도 아니고 유의미한 변화도
                    # 아니므로 신호를 내지 않는다(401 인라인 거부와 302 리다이렉트 거부는 같은 '거부').
                    return []
                else:
                    _mp = " (307/308: 메소드·본문 보존)" if c_status in (307, 308) else ""
                    _to = f" → {loc[:60]}" if loc else ""
                    return [self._f("성공", 78,
                                    f"인증 우회 가능 — 정상은 HTTP {b_status}(거부)인데 공격은 "
                                    f"HTTP {c_status} 리다이렉트{_to}{_mp}(로그인/에러 페이지 아님) → "
                                    "로그인 성공 리다이렉트일 가능성. 따라가 본문을 확인해 확증하세요",
                                    f"상태 {b_status}→{c_status}{_to}")]
        # 실패 문구가 대조엔 있고 공격엔 없으며 200 → 로그인/인증 우회
        if b_fail and not c_fail and c_status == 200:
            return [self._f("성공", 80,
                            "인증 우회 — 정상 요청엔 있던 인증 실패 문구가 공격 응답에선 사라지고 200 → "
                            "우회로 인증을 통과했을 가능성이 높음(확증)",
                            "인증 실패 문구 소멸 + HTTP 200")]

        signals = []
        # ── 중: 5xx 에러 유발(대조는 정상) = 주입이 처리 로직을 깨뜨림 ──
        if c_status >= 500 and (b_status is None or b_status < 500):
            signals.append((f"공격 페이로드로 서버 오류 유발(HTTP {b_status}→{c_status}) — 주입이 "
                            "처리 로직을 깨뜨렸을 수 있음",
                            f"상태 {b_status}→{c_status}"))
        # ── 중: 비인증 상태 변화 ──
        elif b_status is not None and b_status != c_status:
            signals.append((f"정상 대비 상태코드 변화(HTTP {b_status}→{c_status}) — 입력이 응답 분기에 "
                            "영향(불리언/인증 로직 점검 필요)",
                            f"상태 {b_status}→{c_status}"))
        # ── 중: 본문 크기 유의미 변화(불리언 참/거짓) ──
        if abs(dl) >= _BODY_DELTA_STRONG:
            signals.append((f"정상 대비 본문 크기 {'+' if dl > 0 else ''}{dl}B 변화 — 참/거짓 페이지가 "
                            "구분됨(블라인드 SQLi·불리언 우회 가능성)",
                            f"본문 {'+' if dl > 0 else ''}{dl}B"))
        # 에러 마커가 공격에서만 새로 등장
        if _ERROR_5XX.search(c_body) and not _ERROR_5XX.search(b_body):
            signals.append(("정상엔 없던 에러/스택트레이스가 공격 응답에 등장 — 주입이 예외를 유발",
                            "에러/스택트레이스 신규 등장"))

        if signals:
            why = "정상(대조군) 대비 차이 확인 — " + " · ".join(s[0] for s in signals)
            ev = ", ".join(s[1] for s in signals)
            return [self._f("의심", 60, why, ev)]

        # 사소한 차이만 → 대조군 비교 결과 '유의미한 차이 없음'(안전에 가까운 신호)
        if abs(dl) < _BODY_DELTA_WEAK and (b_status == c_status):
            return [self._f("안전", 65,
                            "정상(대조군)과 응답이 거의 동일 — 이 벡터로는 관측되는 영향 없음",
                            f"상태 동일({c_status}) · 본문 Δ{dl}B")]
        return []

    def _f(self, verdict, conf, why, ev):
        return {"name": "차분 판정(대조군 비교)", "verdict": verdict, "confidence": conf,
                "why": why, "evidence": ev,
                "method": "차분(baseline 대조)", "where": "응답 상태·본문 vs 대조군",
                "detector_id": self.id, "tier": self.tier}


register(DifferentialDetector())


# ══════════════════════════════════════════════════════════════════════════════
# tier-1 JWT 탐지기 — 요청의 토큰을 '구조'로 판정(응답 불필요)
# ══════════════════════════════════════════════════════════════════════════════
# jwt 는 등록 카테고리인데 판정 로직이 없던 '고아' 중 하나. alg:none·서명 없음은 요청만으로
# 확인되는 구체 취약 신호다(서버가 받아주면 인증우회). 대조군이 있으면 수용 여부까지 확증.
import base64
import json as _json

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")


def _b64url(seg: str) -> Optional[dict]:
    try:
        pad = seg + "=" * (-len(seg) % 4)
        return _json.loads(base64.urlsafe_b64decode(pad.encode()).decode("utf-8", "ignore"))
    except Exception:
        return None


class JwtNoneAlgDetector(Detector):
    id = "jwt_none_alg"
    tier = 1
    attack_types = frozenset({"jwt"})

    def _tokens(self, ctx: DetectionContext):
        blob = " ".join(str(x) for x in [
            ctx.payload or "", ctx.req_body or "", ctx.url or "",
            " ".join(f"{k}: {v}" for k, v in (ctx.req_headers or {}).items()),
        ])
        return _JWT_RE.findall(blob)

    def applies(self, ctx: DetectionContext) -> bool:
        return bool(self._tokens(ctx))

    def detect(self, ctx: DetectionContext) -> list:
        out = []
        for tok in self._tokens(ctx)[:3]:
            head = _b64url(tok.split(".")[0])
            if not head:
                continue
            alg = str(head.get("alg", "")).lower()
            sig = tok.split(".")[2] if tok.count(".") >= 2 else ""
            if alg == "none" or (alg in ("none", "") and not sig):
                # 서버 수용 여부까지 보려면 대조군 필요 — 있으면 상태 전이로 확증
                verdict, conf, why = "의심", 62, (
                    "요청 JWT 의 alg=none(서명 없음) — 서버가 이를 받아주면 서명 검증 우회로 "
                    "임의 클레임 위조가 가능(인증우회). 서버 수용 여부를 확인하세요")
                if ctx.has_control():
                    b_status = (ctx.baseline or {}).get("status_code")
                    _loc = _hdr(ctx.headers_lower, 'location')
                    # 직접 통과(200/201)면 확증. 3xx 는 로그인/에러 리다이렉트가 아닐 때만(차분과 동일 기준).
                    _passed = (ctx.status_code in (200, 201)) or (
                        ctx.status_code in (301, 302, 303, 307, 308) and not _redirect_is_auth_reject(_loc))
                    if b_status in (401, 403) and _passed:
                        verdict, conf, why = "성공", 85, (
                            "JWT alg=none 위조 토큰이 통과 — 정상은 거부(HTTP %s)인데 위조는 "
                            "HTTP %s → 서명 검증 우회 확증" % (b_status, ctx.status_code))
                out.append({"name": "JWT alg=none 서명 우회", "verdict": verdict, "confidence": conf,
                            "why": why, "evidence": f"header.alg={head.get('alg')} · sig={'없음' if not sig else '있음'}",
                            "method": "요청 토큰 구조 분석(+대조군)", "where": "요청 JWT 헤더",
                            "detector_id": self.id, "tier": self.tier})
        return out


register(JwtNoneAlgDetector())


# ══════════════════════════════════════════════════════════════════════════════
# tier-1 Canary(자가 마커) 탐지기 — 대조군 없이 '단일 응답'으로 실행을 확증
# ══════════════════════════════════════════════════════════════════════════════
# 원리(SSTI 7*7=49 의 일반화): payload 가 '자기 성공 표식을 품은' 표현식이면, 그 표식의
# 계산된(=평가된) 결과가 응답에 나오고 원문 표현식은 안 나올 때 서버가 평가한 것 → 성공.
# 마커(계산 결과)가 곧 대조군이라 별도 정상 요청이 필요 없다.
#
# 예전엔 7*7=49 만 하드코딩이라 (1) '49' 가 페이지에 우연히 흔해 오탐, (2) 다른 피연산자·엔진
# 미지원. 이제 payload 의 '실제 피연산자'로 곱을 계산해 확인하므로 우연 일치가 거의 없고
# ({{99999*99999}} → 9999800001) Jinja2/Twig/Freemarker/JSP-EL/OGNL/ERB 등 여러 구문을 커버.
#
# 곱(*)만 인정한다: 덧셈·작은 수는 페이지에 흔해 오탐이 크지만, 두 수의 곱은 자릿수가 커
# 우연 매칭이 사실상 없다.
_CANARY_EXPR_RE = re.compile(
    r"(?:\{\{|\$\{|#\{|%\{|<%=|\*\{)\s*"      # 여는 구분자: {{ ${ #{ %{ <%= *{(OGNL)
    r"['\"]?(\d{1,7})['\"]?\s*\*\s*['\"]?(\d{1,7})['\"]?"  # 정수 * 정수 (따옴표 변형 허용)
    r"\s*(?:\}\}|\}|%>)",                     # 닫는 구분자: }} } %>
    re.I)


class CanaryEvalDetector(Detector):
    id = "canary_eval"
    tier = 1
    attack_types = frozenset({"ssti"})

    def _exprs(self, ctx: DetectionContext):
        return _CANARY_EXPR_RE.findall(ctx.probe or "")

    def applies(self, ctx: DetectionContext) -> bool:
        return bool(self._exprs(ctx))

    def detect(self, ctx: DetectionContext) -> list:
        body = ctx.body or ""
        out, seen = [], set()
        for a_s, b_s in self._exprs(ctx):
            try:
                a, b = int(a_s), int(b_s)
            except ValueError:
                continue
            result = a * b
            key = (a, b)
            if key in seen:
                continue
            seen.add(key)
            literal = f"{a}*{b}"          # 원문 표현식(공백 없는 정규형)
            # 결과가 응답에 있고, 원문 표현식은 없어야(반사가 아니라 '평가') 성공
            if str(result) in body and literal not in body.replace(" ", ""):
                out.append({
                    "name": f"템플릿 표현식 평가됨({a}*{b}={result})", "verdict": "성공", "confidence": 90,
                    "why": f"주입한 표현식 {a}*{b} 가 서버에서 계산돼 결과 {result} 로 응답에 나타남 "
                           "(원문 표현식은 미반사) → 서버측 템플릿/표현식 주입(SSTI/EL) 실행 확증",
                    "evidence": f"{a}*{b} → 응답에 '{result}' (canary)",
                    "method": "canary(계산 결과 확인)", "where": "응답 본문(표현식 평가 결과)",
                    "detector_id": self.id, "tier": self.tier})
        return out


register(CanaryEvalDetector())


# ══════════════════════════════════════════════════════════════════════════════
# tier-1 응답 시그니처 탐지기 — 대조군 없이 '단일 응답의 확정 표식'으로 판정
# ══════════════════════════════════════════════════════════════════════════════
# SQL 에러·파일 내용 시그니처와 같은 원리로, 응답 하나에 '성공을 증명하는 표식'이 있으면
# 대조군이 필요 없다. 판정 로직이 없던 고아 카테고리(cors·graphql·crlf·ldap·xpath)를 닫는다.

def _origin_host(v: str) -> str:
    from urllib.parse import urlsplit
    try:
        return urlsplit(v if "//" in v else "//" + v).netloc.lower()
    except Exception:
        return ""


class CorsDetector(Detector):
    """CORS 오설정 — 응답 헤더로 확증. Origin 반사 + credentials 허용이면 자격증명 탈취 가능."""
    id = "cors_misconfig"
    tier = 1
    attack_types = frozenset({"cors"})

    def _acao(self, ctx):
        return _hdr(ctx.headers_lower, "access-control-allow-origin")

    def applies(self, ctx):
        # 응답에 ACAO 가 있고, 요청이 Origin 을 보냈을 때만(정상 동일출처 요청은 판정 안 함)
        return bool(self._acao(ctx)) and bool(_hdr(ctx.req_headers, "origin"))

    def detect(self, ctx):
        acao = self._acao(ctx)
        acac = _hdr(ctx.headers_lower, "access-control-allow-credentials").lower() == "true"
        origin = _hdr(ctx.req_headers, "origin")
        reflected = acao and origin and acao.strip().lower() == origin.strip().lower()

        if reflected and acac:
            return [self._f("성공", 85,
                            f"CORS 오설정 — 응답이 요청 Origin({origin})을 그대로 반사하고 "
                            "Allow-Credentials:true → 공격자 사이트가 피해자 자격증명으로 응답을 읽을 수 있음",
                            f"ACAO: {acao} · ACAC: true")]
        if reflected:
            return [self._f("의심", 62,
                            f"CORS 관대 — 임의 Origin({origin})을 반사(자격증명은 미허용). 민감 데이터가 "
                            "쿠키 없이도 노출되면 문제. 자격증명 포함 요청으로 재확인 권장",
                            f"ACAO: {acao}")]
        if acao.strip() == "*" and acac:
            return [self._f("의심", 55,
                            "CORS — Allow-Origin:* 와 Credentials:true 조합(브라우저는 보통 거부하나 오설정 신호)",
                            "ACAO: * · ACAC: true")]
        return []

    def _f(self, verdict, conf, why, ev):
        return {"name": "CORS 오설정", "verdict": verdict, "confidence": conf, "why": why,
                "evidence": ev, "method": "응답 헤더 시그니처", "where": "응답 헤더(ACAO/ACAC) vs 요청 Origin",
                "detector_id": self.id, "tier": self.tier}


register(CorsDetector())


_GRAPHQL_INTROSPECT = re.compile(
    r'"__schema"\s*:\s*\{|"queryType"\s*:\s*\{|"__type"\s*:\s*\{|"types"\s*:\s*\[\s*\{', re.I)
# introspection 이 명시적으로 차단됐음을 알리는 오류 문구(→ 확정적 '영향 없음')
_GRAPHQL_INTROSPECT_OFF = re.compile(
    r"introspection\s+(?:is\s+)?(?:not\s+allowed|disabled|forbidden)|"
    r"GraphQL introspection is not allowed|"
    r'(?:Cannot|Field)\s+["\']?__schema["\']?', re.I)


def _graphql_returned_data(body: str):
    """GraphQL 응답이 '실제 데이터를 담은 data 봉투'면 "dict"/"list" 반환, 아니면 "".

    {"data":{...실제 값...}} 또는 {"data":[...]} 를 인식한다. data 가 null·{}·[]·전부 null 이면
    데이터 반환이 아니다(introspection off·빈 결과와 구분). 잘린 JSON 은 정규식으로 보수적 판정.
    """
    b = (body or "").strip()
    if '"data"' not in b:
        return ""
    try:
        d = _json.loads(b)
        data = d.get("data") if isinstance(d, dict) else None
    except Exception:
        # 파싱 실패(잘림 등) → 보수적 정규식: "data":{ 또는 [ 뒤에 필드가 있고 null 아님
        if re.search(r'"data"\s*:\s*null', b):
            return ""
        m = re.search(r'"data"\s*:\s*(\{|\[)', b)
        if not m:
            return ""
        seg = b[m.start():m.start()+600]
        if not re.search(r'"[A-Za-z_][A-Za-z0-9_]*"\s*:', seg):
            return ""
        # data 값이 배열이거나, 내부에 객체 배열( [ { )이 있으면 다건 나열
        return "list" if (m.group(1) == "[" or re.search(r':\s*\[\s*\{', seg)) else "dict"
    if data is None:
        return ""
    if isinstance(data, list):
        return "list" if any(_has_value(x) for x in data) else ""
    if isinstance(data, dict):
        # __schema:null 만 있는 경우 등은 데이터 반환이 아니다
        real = {k: v for k, v in data.items() if k not in ("__schema", "__type")}
        if not _has_value(real):
            return ""
        return "list" if _has_enumeration(real) else "dict"   # 중첩 배열이면 다건 나열
    return ""


def _has_enumeration(x) -> bool:
    """중첩 어디에든 실제 값이 든 배열(레코드 나열)이 있으면 True."""
    if isinstance(x, list):
        return any(_has_value(v) for v in x)
    if isinstance(x, dict):
        return any(_has_enumeration(v) for v in x.values())
    return False


def _has_value(x) -> bool:
    """null/빈 컨테이너가 아닌 '실제 값'이 하나라도 있으면 True."""
    if x is None:
        return False
    if isinstance(x, dict):
        return any(_has_value(v) for v in x.values())
    if isinstance(x, list):
        return any(_has_value(v) for v in x)
    if isinstance(x, str):
        return x.strip() != ""
    return True   # 숫자·bool 등


class GraphqlDetector(Detector):
    """GraphQL introspection — 응답에 스키마가 실리면 노출(성공), introspection 프로브인데
    스키마가 안 오면(404·차단·미노출) 이 검사 한정 '영향 없음(안전)'으로 확정한다."""
    id = "graphql_introspection"
    tier = 1
    attack_types = frozenset({"graphql"})

    def _is_introspection_probe(self, ctx):
        blob = f"{ctx.probe or ''} {ctx.req_body or ''}".lower()
        return "__schema" in blob or "introspectionquery" in blob

    def applies(self, ctx):
        pl = (ctx.probe or "").lower()
        u = (ctx.url or "").lower()
        return ("graphql" in u or "graphql" in pl or "__schema" in pl
                or "introspectionquery" in pl or (ctx.category or "").lower() == "graphql")

    def detect(self, ctx):
        body = ctx.body or ""
        # ① 스키마 노출 = introspection 활성(성공)
        if _GRAPHQL_INTROSPECT.search(body):
            return [{"name": "GraphQL introspection 노출", "verdict": "성공", "confidence": 80,
                     "why": "introspection 질의에 스키마(__schema/queryType/types)가 응답에 노출됨 → "
                            "전체 API 구조 열람 가능(공격 표면 정보 노출)",
                     "evidence": "응답에 __schema/queryType/types",
                     "method": "응답 시그니처", "where": "응답 본문(GraphQL 스키마)",
                     "detector_id": self.id, "tier": self.tier}]
        # ② GraphQL 쿼리가 데이터를 반환({"data":{...}}) → 엔드포인트 활성·쿼리 가능(공격 표면 확인).
        #    __schema 노출은 아니지만, 예시처럼 실제 레코드가 돌아오면 introspection 없이도 API 가
        #    살아있고 데이터를 내준다는 확정 신호(배열이면 다건 나열 = 열람 범위 점검 대상).
        gd = _graphql_returned_data(body)
        if gd:
            enum = " · 배열(다건 레코드 나열)" if gd == "list" else ""
            return [{"name": "GraphQL 엔드포인트 활성 — 쿼리 데이터 반환", "verdict": "미확정",
                     "confidence": 45,
                     "why": "GraphQL 질의에 데이터가 반환됨(\"data\":{...}) → 엔드포인트가 활성이고 쿼리에 "
                            "응답함(공격 표면 확인)" + enum + ". 반환 필드에 민감정보·과다노출·IDOR 여부와 "
                            "필드 단위 인가를 점검하세요. (introspection 스키마는 미노출)",
                     "checked": "응답의 GraphQL 데이터 봉투(\"data\":{…})",
                     "evidence": f"data 봉투 반환({gd}) (HTTP {ctx.status_code} · {len(body)}B)",
                     "method": "응답 시그니처(GraphQL data)", "where": "응답 본문(GraphQL data 봉투)",
                     "detector_id": self.id, "tier": self.tier}]
        # ③ introspection '스캔 프로브'였는데 스키마도 데이터도 안 옴 → 이 검사 한정 영향 없음(안전).
        #    (introspection 프로브가 아니면 판정하지 않음 — 무관한 요청을 안전이라 하지 않도록)
        if not self._is_introspection_probe(ctx):
            return []
        if ctx.status_code in (404, 400, 405, 501):
            reason = f"HTTP {ctx.status_code} — GraphQL 엔드포인트가 없거나 introspection 질의를 거부"
        elif _GRAPHQL_INTROSPECT_OFF.search(body):
            reason = "introspection 비활성화(오류로 명시적 차단)"
        elif '"errors"' in body or '"error"' in body:
            reason = "introspection 질의가 오류로 거부됨(스키마 미노출)"
        elif body.strip():
            reason = "응답에 스키마(__schema)가 없음 → introspection 비활성/제한"
        else:
            return []   # 빈 응답 등 불명확 → 판정 보류(inconclusive)
        return [{"name": "GraphQL introspection 비활성 — 영향 없음", "verdict": "안전", "confidence": 78,
                 "why": f"introspection 질의를 보냈으나 응답에 스키마가 없음({reason}) → introspection 이 "
                        "노출되지 않음(이 검사 한정 영향 없음).",
                 "checked": "응답의 __schema/queryType/types 및 introspection 차단 오류",
                 "evidence": f"{reason} (HTTP {ctx.status_code} · {len(body)}B)",
                 "method": "응답 시그니처(미검출)", "where": "응답 본문(GraphQL 스키마 부재)",
                 "detector_id": self.id, "tier": self.tier}]


register(GraphqlDetector())


# 요청에 주입한 CRLF 뒤 헤더가 응답 헤더에 나타나면 헤더 인젝션 성공
_CRLF_INJECT = re.compile(r"(?:%0d%0a|%0a|\r\n|\r\n)\s*([A-Za-z][A-Za-z0-9\-]{1,40})\s*:\s*([^\r\n]{1,60})", re.I)


class CrlfDetector(Detector):
    """CRLF 헤더 인젝션 — 주입한 헤더가 응답 헤더에 반영되면 확증(단일 응답)."""
    id = "crlf_injection"
    tier = 1
    attack_types = frozenset({"crlf"})

    def _injected(self, ctx):
        from urllib.parse import unquote
        raw = f"{ctx.payload or ''} {ctx.url or ''} {ctx.req_body or ''}"
        for probe in (raw, unquote(raw), unquote(unquote(raw))):
            m = _CRLF_INJECT.search(probe)
            if m:
                return m.group(1).strip(), m.group(2).strip()
        return None

    def applies(self, ctx):
        return self._injected(ctx) is not None

    def detect(self, ctx):
        inj = self._injected(ctx)
        if not inj:
            return []
        name, val = inj
        # 응답 헤더에 주입한 이름:값이 실제로 나타나는가
        resp_val = _hdr(ctx.headers_lower, name.lower())
        if resp_val and (val.lower() in resp_val.lower() or not val):
            return [{"name": "CRLF 헤더 인젝션", "verdict": "성공", "confidence": 84,
                     "why": f"요청에 주입한 헤더 '{name}: {val}' 가 응답 헤더에 반영됨 → 응답 분할/헤더 "
                            "인젝션 성공(세션 고정·캐시 오염·XSS 로 이어질 수 있음)",
                     "evidence": f"응답 헤더 {name}: {resp_val[:60]}",
                     "method": "요청 주입 헤더 vs 응답 헤더", "where": "응답 헤더",
                     "detector_id": self.id, "tier": self.tier}]
        return []


register(CrlfDetector())


# LDAP/XPath 파서 에러 — SQL 에러처럼 응답에 노출되면 인젝션 가능 신호
_LDAP_ERR = re.compile(
    r"javax\.naming\.|LDAPException|com\.sun\.jndi|Invalid DN syntax|ldap_search|"
    r"LDAP:\s*error|InvalidSearchFilter|ldap_bind|Bad search filter", re.I)
_XPATH_ERR = re.compile(
    r"XPathException|org\.jaxen|MS\.Internal\.Xml|System\.Xml\.XPath|xmlXPathEval|"
    r"Expression must evaluate to a node-set|SimpleXMLElement::xpath|"
    r"Warning:\s*xpath|XPath\s*error|unclosed token", re.I)


class LdapXpathErrorDetector(Detector):
    """LDAP/XPath 인젝션 — 파서 에러 문구가 응답에 노출되면 error-based 확증."""
    id = "ldap_xpath_error"
    tier = 1
    attack_types = frozenset({"ldap", "xpath"})

    def applies(self, ctx):
        cat = (ctx.category or "").lower()
        pl = (ctx.probe or "")
        # 카테고리가 ldap/xpath 이거나, 인젝션다운 특수문자 조합이 있을 때만(오탐 억제)
        looks_inject = bool(re.search(r"\)\(|\*\)|\)\(&|\)\(\||count\(|\bor\b\s*['\"]?\d|node\(\)", pl, re.I))
        return cat in ("ldap", "xpath") or looks_inject

    def detect(self, ctx):
        body = ctx.body or ""
        out = []
        m = _LDAP_ERR.search(body)
        if m:
            out.append(self._f("ldap", "LDAP", m.group(0)))
        m = _XPATH_ERR.search(body)
        if m:
            out.append(self._f("xpath", "XPath", m.group(0)))
        return out

    def _f(self, kind, label, ev):
        return {"name": f"{label} 인젝션 에러 노출", "verdict": "성공", "confidence": 82,
                "why": f"{label} 파서 에러가 응답에 노출됨 → 주입한 입력이 {label} 질의로 해석됨"
                       f"(error-based 인젝션 확증)",
                "evidence": ev[:120],
                "method": "응답 에러 시그니처", "where": f"응답 본문({label} 파서 에러)",
                "detector_id": self.id, "tier": self.tier}


register(LdapXpathErrorDetector())


# ══════════════════════════════════════════════════════════════════════════════
# tier-1 요청 구조 탐지기 — 요청만으로 취약 '시도'를 판정(JWT 와 같은 계열)
# ══════════════════════════════════════════════════════════════════════════════
# 역직렬화·파일업로드는 요청 구조(가젯 매직바이트·위험 확장자)로 '시도'가 확인된다. 성공(RCE)은
# 보통 블라인드/OOB 라 단일 응답 확증이 어려우므로 '의심'으로 두고, 대조군 신호(5xx·상태전이)나
# 수용 응답(2xx)으로 등급을 조정한다. JWT 탐지기와 동일한 요청-구조 판정 패턴.

_DESERIAL_SIGS = [
    (re.compile(r"rO0AB|\xac\xed\x00\x05"), "Java", "Java 직렬화 객체(aced0005/rO0AB)"),
    (re.compile(r"O:\d+:\"|a:\d+:\{"), "PHP", "PHP 직렬화 객체(O:/a:)"),
    (re.compile(r"AAEAAAD/////"), ".NET", ".NET BinaryFormatter 스트림"),
    (re.compile(r"!ruby/object:|--- !ruby|\x04\x08"), "Ruby", "Ruby Marshal/YAML 객체"),
    (re.compile(r"!!python/object|!!python/"), "Python-YAML", "Python YAML 객체 태그"),
    (re.compile(r"\x80\x04|\x80\x05|gASV|gAJ9|gAN9"), "Python-pickle", "Python pickle 스트림"),
]


class DeserializationDetector(Detector):
    id = "deserialization"
    tier = 1
    attack_types = frozenset({"deserial"})

    def _hit(self, ctx):
        blob = f"{ctx.payload or ''} {ctx.req_body or ''} {ctx.url or ''}"
        for rx, lang, desc in _DESERIAL_SIGS:
            if rx.search(blob):
                return lang, desc
        return None

    def applies(self, ctx):
        return self._hit(ctx) is not None

    def detect(self, ctx):
        hit = self._hit(ctx)
        if not hit:
            return []
        lang, desc = hit
        # 기본: '시도 확인'(의심). 대조군이 5xx 로 변하거나 서버 오류면 처리됨 신호로 강화.
        verdict, conf, extra = "의심", 60, ""
        if ctx.status_code >= 500:
            conf, extra = 70, " · 응답 5xx(역직렬화가 예외를 유발했을 수 있음)"
        elif ctx.has_control():
            b = (ctx.baseline or {}).get("status_code")
            if b is not None and b < 500 and ctx.status_code >= 500:
                conf, extra = 72, " · 대조군 대비 서버 오류 유발"
        return [{"name": f"{lang} 역직렬화 시도", "verdict": verdict, "confidence": conf,
                 "why": f"요청에 {desc}가 실림 → 서버가 신뢰 없이 역직렬화하면 원격코드실행(RCE) 위험. "
                        "성공(RCE)은 보통 블라인드/OOB 라 OOB 콜백·확증 스캔으로 검증 필요" + extra,
                 "evidence": desc,
                 "method": "요청 구조(직렬화 매직바이트)", "where": "요청 본문/파라미터",
                 "detector_id": self.id, "tier": self.tier}]


register(DeserializationDetector())


# 위험 실행 확장자(웹셸) + 이미지 위장 XSS 확장자
_DANGER_EXT = (r"ph(?:p[3-7]?|tml|t|ar)|jspx?|jsw|jsv|asp(?:x)?|ashx|asmx|cer|cfml?|"
               r"pl|cgi|sh|bash|py|rb|htaccess|htpasswd")
_UPLOAD_FILENAME = re.compile(r'filename\s*=\s*"?([^";\r\n]+)', re.I)
_DBL_EXT = re.compile(r"\.(?:" + _DANGER_EXT + r")\.(?:jpe?g|png|gif|bmp|txt|pdf)$", re.I)
_DANGER_END = re.compile(r"\.(?:" + _DANGER_EXT + r")$", re.I)
_NULLBYTE = re.compile(r"\.(?:" + _DANGER_EXT + r")(?:%00|\x00|;)", re.I)


class FileUploadDetector(Detector):
    id = "file_upload"
    tier = 1
    attack_types = frozenset({"upload"})

    def _filename(self, ctx):
        ct = _hdr(ctx.req_headers, "content-type").lower()
        blob = ctx.req_body or ""
        if "multipart/form-data" not in ct and "filename" not in blob.lower():
            return None
        m = _UPLOAD_FILENAME.search(blob)
        return m.group(1).strip() if m else None

    def applies(self, ctx):
        return self._filename(ctx) is not None

    def detect(self, ctx):
        fn = self._filename(ctx)
        if not fn:
            return []
        reason = None
        if _NULLBYTE.search(fn):
            reason = "널바이트로 확장자 우회"
        elif _DBL_EXT.search(fn):
            reason = "이중 확장자(위험.이미지)"
        elif _DANGER_END.search(fn):
            reason = "위험 실행 확장자"
        elif re.search(r"\.sv<|\.svg$|\.html?$", fn, re.I):
            reason = "SVG/HTML 업로드(저장형 XSS)"
        if not reason:
            return []
        # 서버가 수용(2xx)했으면 강화 — 실제 실행은 업로드된 URL 재요청으로 확증 필요
        accepted = ctx.status_code in (200, 201)
        verdict = "의심"
        conf = 66 if accepted else 55
        acc = " · 서버가 2xx 로 수용" if accepted else ""
        return [{"name": "위험 파일 업로드 시도", "verdict": verdict, "confidence": conf,
                 "why": f"업로드 파일명 '{fn[:50]}' — {reason}. 서버가 저장·실행하면 웹셸/저장형 XSS. "
                        "업로드된 경로를 재요청(GET)해 실제 실행 여부를 확증하세요" + acc,
                 "evidence": f"filename={fn[:60]} ({reason})",
                 "method": "요청 구조(업로드 파일명/확장자)", "where": "요청 본문(multipart)",
                 "detector_id": self.id, "tier": self.tier}]


register(FileUploadDetector())


# ══════════════════════════════════════════════════════════════════════════════
# tier-1 검증 경로 안내 — OOB/클라이언트 계열은 '단일 응답 판정 불가'를 정직하게 라벨
# ══════════════════════════════════════════════════════════════════════════════
# email/cache/csv/prototype/domclob/cssinj 은 원리상 단일 응답으로 확증할 수 없다(OOB·저장·
# 2차요청·브라우저 DOM 필요). 억지 판정은 오탐이므로, '시도는 인식하되 판정 불가 + 정확한 검증
# 경로'를 명시한다. 예전엔 아무 안내 없이 inconclusive 였다 → 분석가가 다음 행동을 알 수 있게.
_VERIFY_ROUTE = {
    "email":     ("OOB(메일 발송) 확인", "주입한 헤더(BCC/CC/Subject)가 실제 발송 메일에 반영되는지 "
                  "수신함/메일서버 로그로 확인 — 응답만으론 판정 불가"),
    "cache":     ("2차 요청(캐시 반영) 확인", "오염 요청 후 캐시된 변형이 다른 사용자 응답에 나오는지 "
                  "재요청으로 확인 — 단일 응답으론 판정 불가"),
    "csv":       ("내보내기(export) 후 확인", "주입한 수식(=cmd|'/…)이 CSV/XLSX 로 내보내질 때 "
                  "스프레드시트에서 실행되는지 확인 — 응답 본문으론 판정 불가"),
    "prototype": ("브라우저 DOM 확인", "__proto__ 오염이 클라이언트 렌더링/가젯에 영향을 주는지 "
                  "브라우저 콘솔로 확인 — 서버 응답으론 판정 불가"),
    "domclob":   ("브라우저 DOM 확인", "주입한 id/name 이 DOM 을 덮어써 스크립트 흐름을 바꾸는지 "
                  "브라우저에서 확인 — 서버 응답으론 판정 불가"),
    "cssinj":    ("브라우저 렌더 확인", "주입한 CSS 가 데이터 유출(속성 선택자·background url)로 "
                  "이어지는지 브라우저에서 확인 — 서버 응답으론 판정 불가"),
}


class VerificationRouteDetector(Detector):
    """OOB/클라이언트 계열 — 판정 불가를 정직하게 라벨하고 검증 경로를 제시(허위 성공 금지)."""
    id = "verification_route"
    tier = 1

    def _cat(self, ctx):
        for c in (ctx.attack_type, ctx.category):
            if (c or "").lower() in _VERIFY_ROUTE:
                return (c or "").lower()
        return None

    def applies(self, ctx):
        return self._cat(ctx) is not None

    def detect(self, ctx):
        cat = self._cat(ctx)
        route, guide = _VERIFY_ROUTE[cat]
        return [{"name": f"{cat.upper()} — 단일 응답 판정 불가(검증 경로 안내)", "verdict": "미확정",
                 "confidence": 30,
                 "why": f"이 계열은 응답 하나로 성공을 확증할 수 없습니다({route}). {guide}",
                 "evidence": f"검증 경로: {route}",
                 "method": route, "where": "OOB/클라이언트(응답 밖)",
                 "detector_id": self.id, "tier": self.tier}]


register(VerificationRouteDetector())


# ══════════════════════════════════════════════════════════════════════════════
# tier-1 파일 스캔 3xx 응답 처리 — 리다이렉트 Location 으로 '파일 존재/제공'을 판정
# ══════════════════════════════════════════════════════════════════════════════
# 민감파일 스캔(.git/config·.env·backup.zip 등)에 3xx 가 오면 본문엔 파일 내용이 없어
# 기존 판정은 무조건 '미노출(안전)' 이었다. 그러나 Location 을 보면:
#   - Location 이 '요청한 그 파일'을 가리키면(예: /.env → https://cdn/.env) → 파일 존재·제공 중
#     (추적하면 노출). '미노출' 이라 안심시키는 건 위음성 → '의심' 으로 격상.
#   - Location 이 로그인/에러/홈이면 → 보호·부재(안전).
#   - 그 외 → 리다이렉트 추적 필요(미확정).
from core.classify import _FILE_READ_HINT as _FILE_HINT

_FILE_EXT_RE = re.compile(r"/[^/?#]+\.[a-z0-9]{1,8}(?:[?#]|$)", re.I)
_SENSITIVE_BASENAME = re.compile(
    r"\.(?:git|svn|hg|env|bak|old|swp|save|orig|sql|zip|tar|gz|rar|7z|log|ini|conf|config|"
    r"pem|key|p12|pfx|htpasswd|htaccess)\b|/wp-config|web\.config|/\.aws|/\.ssh|id_rsa", re.I)
_GENERIC_REDIR = re.compile(r"^/?(?:$|index\.\w+|home\b|default\b|404|error)", re.I)


def _path_of(u):
    from urllib.parse import urlsplit
    try:
        s = urlsplit(u or "")
        return (s.path or ""), s.netloc.lower()
    except Exception:
        return (u or ""), ""


def _basename(path):
    return (path or "").rstrip("/").rsplit("/", 1)[-1].lower()


class FileScanRedirectDetector(Detector):
    id = "filescan_redirect"
    tier = 1

    def _requested(self, ctx):
        """스캔 대상 경로 — url 경로 우선, 없으면 payload(경로형)."""
        rp, _ = _path_of(ctx.url)
        if not rp or rp == "/":
            pl = (ctx.payload or "").strip()
            if pl.startswith("/") or _SENSITIVE_BASENAME.search(pl):
                rp = pl
        return rp

    def applies(self, ctx):
        if ctx.status_code not in (301, 302, 303, 307, 308):
            return False
        rp = self._requested(ctx)
        blob = f"{rp} {ctx.payload or ''}"
        # 파일 스캔처럼 보일 때만(민감 파일명·확장자·트래버설/파일 힌트)
        return bool(_SENSITIVE_BASENAME.search(blob) or _FILE_EXT_RE.search(rp)
                    or _FILE_HINT.search(blob))

    def detect(self, ctx):
        loc = _hdr(ctx.headers_lower, "location")
        if not loc:
            return []
        rp = self._requested(ctx)
        req_base = _basename(rp)
        loc_path, loc_host = _path_of(loc if "//" in loc else "//x" + loc if loc.startswith("/") else loc)
        loc_base = _basename(loc_path)

        # ① Location 이 '요청한 그 파일'을 가리킴 → 파일 존재·리다이렉트로 제공
        same_file = req_base and len(req_base) >= 3 and (
            req_base == loc_base or (rp and rp.rstrip("/") and rp.rstrip("/") in loc)
            or (req_base in loc.lower() and _SENSITIVE_BASENAME.search(req_base)))
        if same_file:
            return [self._f("의심", 66,
                            f"파일 스캔에 3xx — Location 이 요청 파일({req_base})을 가리킴 → 파일이 존재하며 "
                            f"리다이렉트로 제공되는 중일 수 있음(예: CDN/스토리지). 리다이렉트를 추적해 "
                            "본문 노출을 확증하세요",
                            f"HTTP {ctx.status_code} → {loc[:80]}")]

        # ② 트레일링 슬래시 정규화(/.git → /.git/) = 경로(디렉터리) 존재 recon
        if rp and loc_path.rstrip("/") == rp.rstrip("/") and loc_path != rp:
            return [self._f("의심", 58,
                            f"경로 존재 신호 — 요청 {rp} 가 {loc_path}(디렉터리)로 정규화 리다이렉트 → "
                            "해당 경로가 존재. 하위 파일(.git/config 등) 직접 접근을 점검하세요",
                            f"HTTP {ctx.status_code} → {loc_path}")]

        # ③ 로그인/에러/홈으로 되돌림 = 보호·부재(안전)
        if _redirect_is_auth_reject(loc) or _GENERIC_REDIR.search(loc_path) or loc_path in ("", "/"):
            return [self._f("안전", 70,
                            f"파일 스캔에 3xx — Location 이 로그인/에러/홈({loc_path or loc[:40]})으로 되돌림 → "
                            "요청 파일은 보호되거나 존재하지 않음(직접 노출 아님)",
                            f"HTTP {ctx.status_code} → {loc[:80]}")]

        # ④ 그 외 — 판정하려면 추적 필요
        return [self._f("미확정", 35,
                        f"파일 스캔에 3xx — Location({loc[:60]})이 요청 파일과 다름. 파일 노출 여부는 "
                        "리다이렉트를 추적해 최종 응답 본문으로 판정해야 함",
                        f"HTTP {ctx.status_code} → {loc[:80]}")]

    def _f(self, verdict, conf, why, ev):
        return {"name": "파일 스캔 리다이렉트(3xx)", "verdict": verdict, "confidence": conf,
                "why": why, "evidence": ev,
                "method": "리다이렉트 Location 분석", "where": "응답 헤더 Location vs 요청 파일",
                "detector_id": self.id, "tier": self.tier}


register(FileScanRedirectDetector())
