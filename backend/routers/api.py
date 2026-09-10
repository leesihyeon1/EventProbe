import time
import json
import asyncio
import socket
import re
import httpx
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from typing import Optional
import sys, os, secrets
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.analyzer import analyze_response, generate_summary, file_exposure_looks_real, _sensitive_file_ext
from urllib.parse import urlsplit, quote

# 쿼리에서 RFC3986 상 합법이며 보안 페이로드에 흔히 쓰이는 문자는 보존하고
# (@ / : ; + , = ! $ ( ) * 등), 구조를 깨는 문자(공백·&·#·%)만 인코딩한다.
# httpx 의 params= 는 @·/ 까지 전부 인코딩해 ProxyLogon 등 페이로드를 깨뜨리므로,
# 파라미터를 URL 쿼리에 직접 병합해서 원문을 최대한 보존한다.
_QUERY_SAFE = "@:/;+,=!$()*~-._'"

def _url_with_params(url: str, params: dict) -> str:
    # '#' 은 프래그먼트라 서버로 전송되지 않고, 공백은 URL 을 깨뜨린다. payload(OGNL/Struts
    # 의 #, SQLi 의 공백 등)로 들어온 리터럴을 인코딩해 그대로 전송되게 한다(보안 테스트에선
    # 실제 프래그먼트가 불필요). %23 은 '#' 를 포함하지 않으므로 이중 인코딩되지 않는다.
    url = (url or "").replace("#", "%23").replace(" ", "%20")
    if not params:
        return url
    q = "&".join(
        f"{quote(str(k), safe=_QUERY_SAFE)}={quote(str(v), safe=_QUERY_SAFE)}"
        for k, v in params.items()
    )
    return url + ("&" if "?" in url else "?") + q
from core.ai_analyzer import ai_analyze, ai_generate_variants, ai_suggest_payloads, ai_verdict, ai_classify_attack, is_enabled as ai_enabled, response_analysis_enabled, ai_verdict_enabled
from core.raw_http import raw_send
from core.cve_matcher import match_cve_payloads
from core.followup import hot_families, escalation_candidates
from core import confirm as confirm_scan
from core import discover as api_discover
from core import capture as api_capture
from core import xss_confirm
from core.tlsscan import tls_scan
from core import rag

router = APIRouter(prefix="/api")

# ── 기본 헤더 프로파일 ──────────────────────────────────────
# 헤더 미입력 시 python-httpx UA로 나가 WAF/서버가 다르게 반응하는 문제 보완.
# fill-missing-only: 사용자가 지정한 헤더는 절대 덮지 않고, 빠진 것만 보충.
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1",
    "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

# httpx가 body/전송 계층 기준으로 직접 계산·관리하는 헤더.
# 캡처/붙여넣기한 raw 패킷에 그대로 들어있으면 실제 body 길이와 충돌해
# "Too little data for declared Content-Length" 같은 오류로 전송이 실패한다.
# (Host 는 Host 헤더 인젝션 테스트를 위해 일부러 남겨둔다)
# 캡처/붙여넣기 패킷의 Accept-Encoding(br/zstd 포함)은 그대로 보내되,
# 응답 디코딩은 requirements 의 brotli/zstandard 로 httpx 가 처리한다.
# (디코더가 없으면 br/zstd 응답이 깨진 바이트로 들어오므로 두 패키지는 필수 의존성)
_AUTO_MANAGED_HEADERS = {"content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection"}


def _strip_auto_managed(headers: dict) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in _AUTO_MANAGED_HEADERS}


def merge_headers(user_headers: dict, profile: dict = None, use_defaults: bool = True) -> dict:
    """기본 헤더 위에 사용자 헤더를 얹음(사용자 값 우선, 대소문자 무시). use_defaults=False면 사용자 헤더만.
    전송 계층이 직접 관리하는 헤더(Content-Length 등)는 제거해 body 길이 충돌을 방지한다."""
    user_headers = user_headers or {}
    if not use_defaults:
        return _strip_auto_managed(dict(user_headers))
    base = dict(profile) if profile else dict(DEFAULT_HEADERS)
    lower_map = {k.lower(): k for k in base}
    for k, v in user_headers.items():
        base[lower_map.get(k.lower(), k)] = v
    return _strip_auto_managed(base)

# ── 요청 모델 ──────────────────────────────────────────────
class SingleRequest(BaseModel):
    method: str
    url: str
    headers: dict = {}
    body: Optional[str] = None
    params: dict = {}
    payload: Optional[str] = None
    payload_id: Optional[str] = None
    category: Optional[str] = None
    timeout: int = 10
    default_headers: dict = {}
    use_defaults: bool = True
    http_version: Optional[str] = None   # 지정 시(비 HTTP/1.1) raw 소켓으로 요청라인 버전 그대로 전송
    baseline: Optional[dict] = None      # {status_code, body} — 공격 결과 Diff 판정용(정상 응답)
    # 리다이렉트 추적은 기본 OFF — 보안 도구는 '서버가 실제로 준 응답'을 봐야 한다.
    # 따라가면 3xx/Location 이 최종 응답으로 덮여 오픈 리다이렉트를 영영 탐지할 수 없고,
    # 로그인 페이지 200 을 '정상 통과'로 오인하게 된다.
    follow_redirects: bool = False
    # AI 상세분석·RAG·AI 종합판정을 이 응답 안에서 처리할지. 기본 OFF —
    # UI 는 규칙 기반 결과를 먼저 그리고 /api/analyze/enrich 로 나중에 채운다.
    inline_ai: bool = False
    # 사용자 정의 Alert 룰(브라우저 localStorage 보관분). 서버가 평가해야
    # 단일 전송·일괄 테스트·리포트가 같은 룰셋을 쓴다.
    custom_alert_rules: list = []

class BulkRequest(BaseModel):
    custom_alert_rules: list = []   # 사용자 정의 Alert 룰(단일 전송과 같은 룰셋 적용)
    method: str
    url: str
    target_param: str
    inject_in: str = "params"
    headers: dict = {}
    body: Optional[str] = None
    params: dict = {}
    payload_ids: list[str]
    category: str
    timeout: int = 10
    default_headers: dict = {}
    use_defaults: bool = True

# 다중 타겟 일괄 테스트
class MultiTargetRequest(BaseModel):
    custom_alert_rules: list = []   # 사용자 정의 Alert 룰(단일 전송과 같은 룰셋 적용)
    method: str
    urls: list[str]
    target_param: str
    inject_in: str = "params"
    headers: dict = {}
    body: Optional[str] = None
    params: dict = {}
    payload_ids: list[str] = []
    category: str = ""
    custom_payloads: list[dict] = []   # 직접 입력 페이로드
    timeout: int = 10
    default_headers: dict = {}
    use_defaults: bool = True
    concurrency: int = 12              # 동시 요청 수(속도) — 대상 부하/차단 방지 상한 적용

# 확증 스캔 — 파라미터 1개에 오라클 프로브 세트를 보내 확증
class ConfirmTarget(BaseModel):
    location: str = "param"       # param | body | path | header
    param: str = ""               # 대상 파라미터명 (path 는 무시)
    base_value: str = ""          # 유효한 기존 값(sqli/cmdi 브레이크 접두). 없으면 빈 문자열

class ConfirmRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: Optional[str] = None
    params: dict = {}
    default_headers: dict = {}
    use_defaults: bool = True
    target: ConfirmTarget
    category: str                 # 확증할 카테고리(로드된 페이로드 기준)
    timeout: int = 10

# 포트 스캔
class PortScanRequest(BaseModel):
    hosts: list[str]           # 단일/다중 호스트 모두 지원
    ports: list[int] = []      # 빈 경우 기본 포트 목록 사용
    timeout: float = 2.0

# ── 페이로드 DB 로드 ────────────────────────────────────────
DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "payloads.json")

_PAYLOAD_CACHE = None
_PAYLOAD_MTIME = None

def load_payloads():
    # 파일 수정 시각(mtime)이 바뀌면 다시 읽어 반영(서버 재시작 없이 payloads.json 편집 가능)
    global _PAYLOAD_CACHE, _PAYLOAD_MTIME
    try:
        mtime = os.path.getmtime(DATA_FILE)
    except OSError:
        mtime = None
    if _PAYLOAD_CACHE is None or mtime != _PAYLOAD_MTIME:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            _PAYLOAD_CACHE = json.load(f)
        _PAYLOAD_MTIME = mtime
    return _PAYLOAD_CACHE

def find_payload_by_id(payload_id: str):
    data = load_payloads()
    for cat in data["categories"]:
        for p in cat["payloads"]:
            if p["id"] == payload_id:
                return p, cat
    return None, None


_SENSITIVE_HDRS = ("host", "authorization", "cookie", "proxy-authorization")


def _blurred_request(req) -> dict:
    """AI 분석/판정에 넘길 '호스트 제외' 요청 패킷(응답 본문 아님, ai-suggest 와 동일 정책)."""
    parts = urlsplit(req.url or "")
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    # SingleRequest 는 header 이름 목록이 아니라 headers dict 를 가진다 — 키에서 뽑아 민감 헤더 제외
    hdr_names = [h for h in (getattr(req, "headers", None) or {}).keys()
                 if str(h).lower() not in _SENSITIVE_HDRS]
    return {
        "method": (req.method or "GET").upper(),
        "path": path,
        "payload": req.payload or "",
        "params": req.params or {},
        "body": (req.body or "")[:800],
        "header_names": hdr_names,
    }


# 분석에 쓰는 응답 본문 상한(문자). 경로마다 5KB/10KB/50KB 로 제각각이라
# 같은 페이로드가 단일 전송과 일괄 테스트에서 다른 판정을 내던 문제가 있었다 → 하나로 통일.
# 동시 실행 상한이 30 이라 피크 메모리는 문제되지 않는다.
BODY_LIMIT = 50000


def _read_body(response) -> tuple:
    """응답 본문을 상한까지 읽고 (본문, 잘렸는지, 원본 길이) 반환.

    잘린 사실을 analyzer 로 넘겨야 '시그니처 미검출 = 안전' 을 앞부분 한정으로 서술할 수 있다.
    """
    try:
        full = response.text
    except Exception:
        return "", False, 0
    return full[:BODY_LIMIT], len(full) > BODY_LIMIT, len(full)


def _redirect_chain(response) -> list:
    """httpx 가 따라간 리다이렉트 홉 목록 → [{status_code, location, url}, …].

    따라가지 않았으면 빈 리스트. analyzer 는 첫 홉으로 오픈 리다이렉트를 판정하고,
    UI 는 사용자에게 '무엇을 거쳐 최종 응답에 도달했는지' 보여준다.
    """
    return [{"status_code": h.status_code,
             "location": str(h.headers.get("location", "")),
             "url": str(h.url)}
            for h in getattr(response, "history", []) or []]


# 공격유형 → 코퍼스(산문)와 의미가 잘 맞는 앵커 문구. 원시 경로/페이로드만으로는
# 임베딩 유사도가 낮아 관련 문서를 놓치므로, 이 서술 용어로 질의를 앵커링한다.
_CATEGORY_DESC = {
    "sqli": "SQL injection database query error-based union blind order by",
    "xss": "cross-site scripting XSS javascript injection reflected DOM",
    "ssrf": "server-side request forgery internal metadata endpoint",
    "lfi": "local file inclusion path traversal directory traversal file read",
    "xxe": "XML external entity injection",
    "cmdi": "OS command injection remote code execution shell",
    "ssti": "server-side template injection expression evaluation",
    "redirect": "open redirect location header",
    "jwt": "JSON web token JWT algorithm confusion signature",
    "idor": "access control IDOR authorization insecure direct object reference",
    "nosql": "NoSQL injection MongoDB operator",
    "xmlrpc": "XML-RPC pingback multicall wordpress",
    "csrf": "cross-site request forgery CSRF token",
}


async def _retrieve_related(category: str, outcome: str, findings: list, probe: str = "") -> list:
    """RAG 검색 — 공격유형 의미 앵커 + 신호 이름(+요청 보조)으로 조회. AI 유무와 무관하게
    동작(관련 문서 표시 + AI 판정 근거 공용). 공개 문서라 유출 위험 없음."""
    if not rag.has_sources():
        return []
    # '미확인' finding 의 why 는 일반 boilerplate 라 질의를 희석 → 실제 신호(성공/미확정/안전)만 사용.
    specific = [f for f in (findings or []) if f.get("verdict") != "미확인"]
    names = " ".join(f.get("name", "") for f in specific)
    whys = " ".join(str(f.get("why", "")) for f in specific)[:300]
    # 카테고리 서술 용어를 앞에 두어 의미 앵커로 삼고, 원시 probe 는 보조로만(노이즈 최소화).
    desc = _CATEGORY_DESC.get((category or "").lower(), category or "")
    rag_q = " ".join(filter(None, [desc, names, whys, str(probe or "")[:120]])).strip()
    if not rag_q:
        return []
    try:
        hits = await asyncio.to_thread(rag.search, rag_q, 4, category)
        if hits:
            # 참고용(판정 불변)이므로 하한을 0.42 로. 약하거나 엉뚱한 스니펫은 여전히 버린다.
            top = hits[0]["score"]
            hits = [h for h in hits if h["score"] >= max(0.42, top * 0.6)][:3]
        return hits
    except Exception:
        return []


async def _rag_lookup(query: str, k: int, category: str = "", floor: float = 0.35) -> list:
    """RAG 검색 + 관련도 게이팅(공용). RAG 소스 없거나 빈 질의면 []."""
    if not (rag.has_sources() and (query or "").strip()):
        return []
    try:
        hits = await asyncio.to_thread(rag.search, query, k, category)
    except Exception:
        return []
    if hits:
        top = hits[0]["score"]
        hits = [h for h in hits if h["score"] >= max(floor, top * 0.5)]
    return hits[:k]


def _rag_ctx_fields(retrieved: list) -> dict:
    """응답에 실을 RAG 표시 필드(rag_used/rag_sources/rag_context) 생성(공용)."""
    retrieved = retrieved or []
    return {
        "rag_used": len(retrieved),
        "rag_sources": sorted({r.get("title", "") for r in retrieved}),
        "rag_context": [{"title": r.get("title", ""), "loc": r.get("loc", ""), "score": r.get("score"),
                         "excerpt": re.sub(r"\s+", " ", str(r.get("text", ""))).strip()[:240]}
                        for r in retrieved[:6]],
    }


async def _attach_rag_and_verdict(analysis: dict, req, status_code, resp_time):
    """RAG 관련 문서를 (AI 유무와 무관하게) analysis['related_docs'] 에 붙이고,
    AI 판정이 켜져 있으면 '같은 검색 결과'로 판정을 생성한다(검색 1회로 공유)."""
    _fnd = [{"name": f["name"], "verdict": f.get("verdict"), "why": f.get("why"), "evidence": f.get("evidence")}
            for f in analysis.get("findings", [])]
    _atype = analysis.get("attack_type") or req.category
    _blur = _blurred_request(req)
    _probe = f"{_blur['path']} {_blur['payload']}"
    hits = await _retrieve_related(_atype, analysis.get("attack_outcome"), _fnd, _probe)
    if hits:
        analysis["related_docs"] = [{"title": h.get("title", ""), "loc": h.get("loc", ""),
                                     "score": h.get("score"), "excerpt": (h.get("text", "") or "")[:220]}
                                    for h in hits]
    if ai_verdict_enabled():
        analysis["ai_verdict"] = await ai_verdict({
            "category": _atype, "status": status_code, "time": resp_time,
            "outcome": analysis.get("attack_outcome"),
            "findings": _fnd, "request": _blur,
            "alerts": [{"name": a["name"], "risk": a["risk"]} for a in analysis.get("alerts", [])],
            "retrieved": hits,
        })


class EnrichRequest(BaseModel):
    """이미 규칙 기반 판정이 끝난 요청/응답에 AI·RAG 만 덧붙이기 위한 입력.

    판정을 다시 계산하지 않는다 — 서버 규칙이 이미 확정한 findings 를 그대로 근거로 쓴다.
    필드 이름은 SingleRequest 와 맞춰 _blurred_request() 를 그대로 재사용한다.
    """
    method: str = "GET"
    url: str = ""
    headers: dict = {}
    params: dict = {}
    body: Optional[str] = None
    payload: Optional[str] = None
    category: Optional[str] = None
    status_code: int = 0
    response_time: float = 0
    resp_headers: dict = {}
    resp_body: str = ""
    analysis: dict = {}          # 규칙 기반 분석(findings/alerts/attack_* 등)


@router.post("/analyze/enrich")
async def analyze_enrich(req: EnrichRequest):
    """규칙 기반 판정에 AI 상세분석·RAG 관련문서·AI 종합판정을 덧붙인다.

    /api/request 에서 분리한 이유: 임베딩·LLM 왕복이 붙으면 이미 받아 놓은 응답조차
    수 초간 화면에 못 띄운다. UI 는 즉시 렌더한 뒤 이 호출로 채운다.
    AI 상세분석과 RAG→종합판정은 서로 의존하지 않으므로 동시에 돌린다.
    """
    analysis = dict(req.analysis or {})
    out: dict = {}

    async def _detail():
        if not response_analysis_enabled():
            return None
        return await ai_analyze({
            "method": (req.method or "GET").upper(), "url": req.url, "payload": req.payload,
            "category": req.category, "req_body": req.body,
            "status_code": req.status_code, "response_time": req.response_time,
            "resp_headers": req.resp_headers, "resp_body": (req.resp_body or "")[:BODY_LIMIT],
            "base_verdict": analysis.get("verdict"),
            "base_alerts": [a.get("name") for a in analysis.get("alerts", [])],
        })

    async def _verdict():
        await _attach_rag_and_verdict(analysis, req, req.status_code, req.response_time)

    async def _classify():
        # 규칙 기반 분류가 이미 유형을 정했으면 AI 를 부르지 않는다(하이브리드: miss 일 때만).
        # attack_type 이 비어 있을 때만 = 정규식 힌트가 아무것도 못 맞춘 SOC 붙여넣기 케이스.
        if (analysis.get("attack_type") or "").strip():
            return None
        if not ai_enabled():
            return None
        # 호스트 제거한 경로만 — 요청 본문/헤더값은 분석가 자신의 공격이라 저유출.
        try:
            path = urlsplit(req.url).path or "/"
        except Exception:
            path = req.url or "/"
        return await ai_classify_attack({
            "method": req.method, "path": path, "params": req.params,
            "body": req.body, "headers": req.headers,
        })

    try:
        detail, _, klass = await asyncio.gather(_detail(), _verdict(), _classify())
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    if detail is not None:
        out["ai"] = detail
    if analysis.get("related_docs") is not None:
        out["related_docs"] = analysis["related_docs"]
    if analysis.get("ai_verdict") is not None:
        out["ai_verdict"] = analysis["ai_verdict"]
    if klass and not klass.get("error") and (klass.get("primary") or klass.get("types")):
        out["attack_class"] = klass          # {primary, types, confidence, header_borne, reason, source:"ai"}
    return out


# ── 단일 요청 전송 ──────────────────────────────────────────
@router.post("/request")
async def send_request(req: SingleRequest):
    try:
        sent_headers = merge_headers(req.headers, req.default_headers, req.use_defaults)

        # HTTP 버전 지정(비 HTTP/1.1) → raw 소켓 모드로 요청라인 버전 그대로 전송
        ver = (req.http_version or "").strip()
        if ver and ver.upper() != "HTTP/1.1":
            r = await asyncio.to_thread(
                raw_send, req.method, _url_with_params(req.url, req.params),
                sent_headers, req.body or "", ver, float(req.timeout),
            )
            analysis = analyze_response(
                status_code=r["status_code"], headers=r["headers"], body=r["body"],
                response_time=r["response_time"], payload=req.payload, category=req.category,
                baseline=req.baseline, url=_url_with_params(req.url, req.params), req_body=req.body,
                method=req.method, req_headers=sent_headers,
            )
            if response_analysis_enabled():
                analysis["ai"] = await ai_analyze({
                    "method": req.method.upper(), "url": req.url, "payload": req.payload,
                    "category": req.category, "req_body": req.body,
                    "status_code": r["status_code"], "response_time": r["response_time"],
                    "resp_headers": r["headers"], "resp_body": r["body"],
                    "base_verdict": analysis.get("verdict"),
                    "base_alerts": [a.get("name") for a in analysis.get("alerts", [])],
                })
            await _attach_rag_and_verdict(analysis, req, r["status_code"], r["response_time"])
            return {
                "status_code": r["status_code"], "headers": r["headers"], "body": r["body"],
                "response_time": r["response_time"], "body_size": r["body_size"],
                "sent_headers": sent_headers, "raw_mode": True,
                "request_line": r["request_line"], "analysis": analysis,
                "redirect_chain": [],          # raw 소켓은 리다이렉트를 따라가지 않음
                "followed_redirects": False,
            }

        async with httpx.AsyncClient(verify=False, follow_redirects=req.follow_redirects) as client:
            start = time.time()
            response = await client.request(
                method=req.method.upper(),
                url=_url_with_params(req.url, req.params),
                headers=sent_headers,
                content=req.body.encode() if req.body else None,
                timeout=req.timeout,
            )
            elapsed = (time.time() - start) * 1000

        body_text, body_cut, body_full = _read_body(response)
        chain = _redirect_chain(response)
        analysis = analyze_response(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body_text,
            response_time=elapsed,
            payload=req.payload,
            category=req.category,
            baseline=req.baseline,
            url=_url_with_params(req.url, req.params),
            req_body=req.body,
            method=req.method,
            redirect_chain=chain,
            body_truncated=body_cut,
            full_body_len=body_full,
            custom_alert_rules=req.custom_alert_rules,
            req_headers=sent_headers,
        )

        # AI 상세 분석 + RAG/AI 종합판정은 기본적으로 여기서 하지 않는다.
        # 임베딩·LLM 호출이 최대 3회 붙어 '이미 도착한 응답'조차 수 초간 못 보게 만들기 때문.
        # UI 는 규칙 기반 결과를 즉시 렌더한 뒤 POST /api/analyze/enrich 로 보강한다.
        # (스크립트 등에서 한 번에 받고 싶으면 inline_ai=true 로 예전 동작을 쓴다.)
        if req.inline_ai and response_analysis_enabled():
            analysis["ai"] = await ai_analyze({
                "method": req.method.upper(),
                "url": req.url,
                "payload": req.payload,
                "category": req.category,
                "req_body": req.body,
                "status_code": response.status_code,
                "response_time": round(elapsed, 2),
                "resp_headers": dict(response.headers),
                "resp_body": body_text,
                "base_verdict": analysis.get("verdict"),
                "base_alerts": [a.get("name") for a in analysis.get("alerts", [])],
            })

        # RAG 관련 문서(AI 무관) + AI 종합 판정(켜져 있으면) — 검색 1회로 공유
        if req.inline_ai:
            await _attach_rag_and_verdict(analysis, req, response.status_code, round(elapsed, 2))

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body_text,
            "response_time": round(elapsed, 2),
            "body_size": len(response.content),
            "sent_headers": sent_headers,
            "analysis": analysis,
            "redirect_chain": chain,
            "followed_redirects": bool(req.follow_redirects),
            "final_url": str(response.url),
        }
    except httpx.TimeoutException:
        return {
            "status_code": 0,
            "headers": {},
            "body": "",
            "response_time": req.timeout * 1000,
            "body_size": 0,
            "analysis": {
                "verdict": "timeout",
                "confidence": 30,
                "waf_detected": None,
                "block_reason": ["요청 타임아웃"],
                "error_leaks": [],
                "sensitive_data": [],
                "response_anomalies": ["응답 시간 초과 — Time-based 공격 가능성"],
                "risk_level": "medium",
                "details": ["요청 타임아웃 발생"],
                "score": 35,
            },
        }
    except Exception as e:
        # 연결 실패/DNS/헤더 거부 등 — 500 대신 구조화된 에러로 반환해
        # 단일 전송·GO TEST UI 가 "HTTP undefined" 대신 명확히 표시하도록 함.
        # httpx 일부 예외는 str(e) 가 비어 있으므로 하위 원인(__cause__)까지 뽑아낸다.
        detail = str(e).strip()
        cause = e.__cause__ or e.__context__
        if cause and str(cause).strip():
            detail = (detail + f" ({type(cause).__name__}: {cause})").strip() if detail else f"{type(cause).__name__}: {cause}"
        if not detail:
            detail = "연결 실패 (대상 도달 불가 — DNS/방화벽/포트 확인)"
        msg = f"{type(e).__name__}: {detail}"
        return {
            "status_code": 0,
            "headers": {},
            "body": "",
            "response_time": 0,
            "body_size": 0,
            "error": msg,
            "analysis": {
                "verdict": "error",
                "confidence": 0,
                "waf_detected": None,
                "block_reason": [],
                "error_leaks": [],
                "sensitive_data": [],
                "response_anomalies": [],
                "risk_level": "info",
                "details": [f"요청 실패: {msg}"],
                "score": 0,
            },
        }


# ── AI 상태 / 페이로드 변형 ─────────────────────────────────
class AiVariantRequest(BaseModel):
    base_payload: str
    category: str = ""
    waf: str = ""
    count: int = 8

@router.get("/ai-status")
def ai_status():
    return {"enabled": ai_enabled()}

@router.post("/ai-payloads")
async def ai_payloads(req: AiVariantRequest):
    if not ai_enabled():
        raise HTTPException(status_code=400, detail="AI 미설정 (.env 의 NVIDIA_API_KEY 없음)")
    count = max(1, min(req.count, 20))
    # RAG: WAF/필터 우회 기법을 코퍼스에서 검색해 변형 생성 근거로 주입
    retrieved = await _rag_lookup(
        " ".join(filter(None, [req.base_payload, req.category, req.waf,
                               "WAF 필터 우회 인코딩 bypass filter evasion encoding"])),
        5, req.category, floor=0.3)
    res = await ai_generate_variants(req.base_payload, req.category, req.waf, count, retrieved=retrieved)
    if isinstance(res, dict):
        res.update(_rag_ctx_fields(retrieved))
    return res


class AiSuggestRequest(BaseModel):
    method: str = "GET"
    url: str = ""
    params: dict = {}
    body: Optional[str] = None
    header_names: list[str] = []
    count: int = 8
    fingerprint: dict = {}   # {server, powered_by, body} — 직전 응답 지문(선택, 로컬 CVE 매칭용)

@router.post("/ai-suggest")
async def ai_suggest(req: AiSuggestRequest):
    # 유출 방지: URL 에서 host 제거하고 path(+query) 만 사용
    parts = urlsplit(req.url or "")
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    count = max(1, min(req.count, 15))

    # 1) 로컬 CVE/알려진취약점 매칭 (무유출) — 저장소에서 지문에 맞는 알려진 익스플로잇
    cve_cands = match_cve_payloads(load_payloads(), path, req.params, req.body or "",
                                   req.fingerprint or {}, limit=8)

    # 1-b) RAG 검색 — 인제스트한 공개 문서에서 이 요청에 맞는 실제 페이로드/기법을 top-k 검색.
    #      (검색 결과는 LLM 생성에만 주입되므로 AI 활성일 때만 조회)
    retrieved = []
    if ai_enabled() and rag.has_sources():
        fp = req.fingerprint or {}
        rag_q = " ".join(filter(None, [
            re.sub(r"[/?&=]", " ", path),
            " ".join((req.params or {}).keys()),
            str(fp.get("server", "")), str(fp.get("powered_by", "")),
        ]))
        try:
            retrieved = await asyncio.to_thread(rag.search, rag_q, 6)
            # 관련도 낮은 스니펫은 버려 무관한 요청에 문서가 끼어드는 것을 막는다(상위 대비 40%↑)
            if retrieved:
                top = retrieved[0]["score"]
                retrieved = [r for r in retrieved if r["score"] >= max(0.3, top * 0.4)]
        except Exception:
            retrieved = []

    # 2) AI 후보 (키 있을 때만). path/param/body/헤더 '이름' + RAG 검색 스니펫 전송(host·인증 제외)
    ai_res = None
    if ai_enabled():
        safe_header_names = [h for h in (req.header_names or [])
                             if h.lower() not in ("host", "authorization", "cookie", "proxy-authorization")]
        ai_res = await ai_suggest_payloads(req.method, path, req.params, req.body or "", safe_header_names, count,
                                           retrieved=retrieved)
    ai_res = ai_res if isinstance(ai_res, dict) else {}
    ai_cands = ai_res.get("candidates") or []
    ai_err = ai_res.get("error")

    # 3) 병합 — CVE(알려진취약점) 먼저, 그다음 AI. (location, param, payload) 기준 중복 제거
    seen, merged = set(), []
    for c in cve_cands + ai_cands:
        key = (c.get("location"), (c.get("param") or "").lower(), c.get("payload"))
        if not c.get("payload") or key in seen:
            continue
        seen.add(key)
        merged.append(c)

    if not merged:
        if not ai_enabled():
            return {"error": "AI 미설정이고 매칭된 CVE도 없음 (.env 의 NVIDIA_API_KEY 설정 또는 경로/지문 확인)"}
        return ai_res or {"error": "후보 없음"}

    summary = ai_res.get("summary") or ""
    if cve_cands:
        summary = (f"로컬 CVE/알려진취약점 {len(cve_cands)}건" + (" · " + summary if summary else "")).strip()
    if retrieved:
        titles = ", ".join(sorted({r.get("title", "") for r in retrieved})[:3])
        summary = (f"참고 문서 {len(retrieved)}개 스니펫 반영({titles})" + (" · " + summary if summary else "")).strip()
    if ai_err and cve_cands:
        summary += f" (AI 보강 실패: {ai_err})"
    test_type = ai_res.get("test_type") or (f"CVE 매칭 {len(cve_cands)}건" if cve_cands else "분석")

    return {
        "test_type": test_type,
        "summary": summary,
        "candidates": merged[: len(cve_cands) + count],
        "model": ai_res.get("model", ""),
        "cve_count": len(cve_cands),
        "rag_used": len(retrieved),
        "rag_sources": sorted({r.get("title", "") for r in retrieved}) if retrieved else [],
        # 실제 검색·주입된 스니펫(맥락) — 사용자가 매칭이 타당한지 눈으로 확인
        "rag_context": [
            {"title": r.get("title", ""), "loc": r.get("loc", ""),
             "score": r.get("score"),
             "excerpt": re.sub(r"\s+", " ", str(r.get("text", ""))).strip()[:240]}
            for r in retrieved[:6]
        ],
    }


# ── 결과 기반 후속(승격) 페이로드 (기능2) ──────────────────────
class FollowupRequest(BaseModel):
    method: str = "GET"
    url: str = ""
    params: dict = {}
    body: Optional[str] = None
    header_names: list[str] = []
    location: str = "param"        # 취약이 확인된 위치(param/body/path/header)
    param: str = ""                # 취약 파라미터 이름
    fingerprint: dict = {}         # {server, powered_by} — 직전 응답 지문(로컬 매칭용)
    category: str = ""             # 시도한 공격 카테고리
    attack_outcome: str = ""       # success|blocked|inconclusive
    finding_names: list[str] = []  # 보안분석 신호 이름(라벨만)
    alert_names: list[str] = []    # ALERT 이름(라벨만)
    tried_payload: str = ""        # 이미 시도한 payload(중복 제외)
    count: int = 8
    use_ai: bool = True

@router.post("/followup-suggest")
async def followup_suggest(req: FollowupRequest):
    """검증 결과(보안분석 신호 라벨)를 근거로 승격/우회 페이로드를 제안. 무유출(라벨만 사용)."""
    parts = urlsplit(req.url or "")
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    data = load_payloads()

    families = hot_families({
        "category": req.category,
        "finding_names": req.finding_names,
        "alert_names": req.alert_names,
        "attack_outcome": req.attack_outcome,
    })

    # 1) 로컬 승격 페이로드 (신호 → 카테고리, 고급 변형 우선)
    esc = escalation_candidates(data, families, req.location, req.param,
                                per_family=3, exclude_payload=(req.tried_payload or None))
    # 2) 기술스택 지문 기반 CVE 매칭 (기능1 재사용)
    cve = match_cve_payloads(data, path, req.params, req.body or "", req.fingerprint or {}, limit=6)

    # 3) AI 라벨-only 보강 (선택) — 계열/판정/탐지기술 이름만 전송(응답 데이터 미전송).
    #    근거(승격 계열) 또는 성공 판정이 있을 때만 — 근거 없이 일반 후보를 쏟아내지 않는다.
    ai_res = {}
    has_evidence = bool(families) or (req.attack_outcome or "").strip().lower() == "success"
    # RAG: 확증·승격 방법을 코퍼스에서 검색(AI 유무와 무관하게 근거로 표시). 근거 있을 때만.
    retrieved = []
    if has_evidence:
        retrieved = await _rag_lookup(
            " ".join(filter(None, [path, " ".join(families), " ".join(req.finding_names or []),
                                   req.category, "확증 승격 우회 exploit escalate confirm bypass"])),
            5, (families[0] if families else req.category), floor=0.35)
    if req.use_ai and ai_enabled() and has_evidence:
        fp = req.fingerprint or {}
        tech = ", ".join(x for x in [fp.get("server"), fp.get("powered_by")] if x)
        hint = "; ".join(filter(None, [
            ("계열=" + "/".join(families)) if families else "",
            ("판정=" + req.attack_outcome) if req.attack_outcome else "",
            ("기술=" + tech) if tech else "",
        ]))
        safe_headers = [h for h in (req.header_names or [])
                        if h.lower() not in ("host", "authorization", "cookie", "proxy-authorization")]
        r = await ai_suggest_payloads(req.method, path, req.params, req.body or "",
                                      safe_headers, req.count, hint=hint, retrieved=retrieved)
        ai_res = r if isinstance(r, dict) else {}
    ai_cands = ai_res.get("candidates") or []

    # 병합: 승격(신호기반) → CVE → AI, 중복 제거
    seen, merged = set(), []
    for c in esc + cve + ai_cands:
        key = (c.get("location"), (c.get("param") or "").lower(), c.get("payload"))
        if not c.get("payload") or key in seen:
            continue
        seen.add(key)
        merged.append(c)

    if not merged:
        if not has_evidence:
            return {"error": "직접적인 취약 신호가 없어 승격 후보를 만들지 않았습니다 — "
                             "먼저 '확증 스캔'으로 취약 여부를 확정한 뒤 다시 시도하세요."}
        return {"error": "후속 후보를 만들지 못했습니다 — 저장소에 매칭되는 승격 페이로드가 없습니다."}

    seg = []
    if families:
        seg.append("계열 " + "/".join(families))
    if esc:
        seg.append(f"승격 {len(esc)}")
    if cve:
        seg.append(f"CVE {len(cve)}")
    summary = " · ".join(seg)
    if ai_res.get("error"):
        summary += " (AI 보강 실패)"

    return {
        "test_type": "결과 기반 후속 — " + (", ".join(families) if families else "일반"),
        "summary": summary,
        "candidates": merged[: max(req.count, len(esc) + len(cve))],
        "model": ai_res.get("model", ""),
        "families": families,
        **_rag_ctx_fields(retrieved),
    }


# ── 다중 페이로드 일괄 테스트 ───────────────────────────────
def _strip_query_param(url: str, key: str) -> str:
    """URL 쿼리에서 key= 항목을 제거(확증 프로브가 같은 파라미터를 params 로 다시 넣을 때 중복 방지)."""
    qi = url.find("?")
    if qi < 0 or not key:
        return url
    base, q = url[:qi], url[qi + 1:]
    kept = [seg for seg in q.split("&") if seg and seg.split("=", 1)[0] != key]
    return base + ("?" + "&".join(kept) if kept else "")


def _inject_probe(base_url: str, params: dict, body: Optional[str],
                  headers: dict, location: str, param: str, value: str):
    """프로브 value 를 지정 위치에 주입한 (final_url, body) 반환. params/headers 는 사본을 수정."""
    loc = (location or "param").lower()
    if loc == "header":
        headers[param or "X-Test-Payload"] = value
        return _url_with_params(base_url, params), body
    if loc == "body":
        if body and body.strip():
            try:
                bd = json.loads(body)
                if isinstance(bd, dict):
                    bd[param or "q"] = value
                    return _url_with_params(base_url, params), json.dumps(bd)
            except (ValueError, TypeError):
                pass
        return _url_with_params(base_url, params), value
    if loc == "path":
        qi = base_url.find("?")
        stem, q = (base_url[:qi], base_url[qi:]) if qi >= 0 else (base_url, "")
        sep = "" if stem.endswith("/") else "/"
        return stem + sep + value.lstrip("/") + q, body
    # param (default): URL 쿼리에서 같은 키 제거 후 params 로 주입
    url2 = _strip_query_param(base_url, param or "q")
    params[param or "q"] = value
    return _url_with_params(url2, params), body


_LOGIN_RE = re.compile(r"login|sign[\-_ ]?in|signin|logon|/auth|/session|/account|/admin|oauth", re.I)
_PW_RE = re.compile(r"pass(word|wd)?|\bpwd\b|\bpw\b|credential|secret", re.I)
_CRED_PARAMS = {"user", "username", "email", "login", "userid", "uid", "account", "id"}


def _looks_login(req: "ConfirmRequest") -> bool:
    """요청이 로그인/인증 흐름처럼 보이면 True (인증 우회 오라클 자동 병행 판단)."""
    blob = f"{req.url or ''} {req.body or ''} {' '.join((req.params or {}).keys())}"
    if _LOGIN_RE.search(blob):
        return True
    if (req.target.param or "").lower() in _CRED_PARAMS and _PW_RE.search(blob):
        return True
    return False


async def _run_confirm_probes(req: "ConfirmRequest", headers_base: dict, plan: list, follow: bool):
    """프로브 세트를 순차 전송(타이밍 정확도) 후 (results, probes_out) 반환."""
    results, probes_out = [], []
    async with httpx.AsyncClient(verify=False, follow_redirects=follow) as client:
        for p in plan:
            params = dict(req.params)
            headers = dict(headers_base)
            final_url, body = _inject_probe(
                req.url, params, req.body, headers,
                req.target.location, req.target.param, p["value"],
            )
            try:
                start = time.time()
                resp = await client.request(
                    method=req.method.upper(), url=final_url, headers=headers,
                    content=body.encode() if body else None, timeout=req.timeout,
                )
                elapsed = (time.time() - start) * 1000
                results.append({
                    "role": p["role"], "status": resp.status_code, "time_ms": elapsed,
                    "body": resp.text[:50000], "headers": dict(resp.headers), "value": p["value"],
                })
                probes_out.append({
                    "role": p["role"], "label": p["label"], "value": p["value"],
                    "status": resp.status_code, "time_ms": round(elapsed),
                    "len": len(resp.text),   # 응답 크기 — 불린 기반 길이차를 표에서 눈으로 비교
                })
            except httpx.TimeoutException:
                results.append({"role": p["role"], "status": 0, "time_ms": float(req.timeout) * 1000,
                                "body": "", "headers": {}, "value": p["value"]})
                probes_out.append({"role": p["role"], "label": p["label"], "value": p["value"],
                                   "status": 0, "time_ms": round(float(req.timeout) * 1000), "timeout": True})
            except Exception as e:
                results.append({"role": p["role"], "status": 0, "time_ms": 0.0,
                                "body": "", "headers": {}, "value": p["value"]})
                probes_out.append({"role": p["role"], "label": p["label"], "value": p["value"],
                                   "status": 0, "time_ms": 0, "error": str(e)[:120]})
    return results, probes_out


_METHOD_PROBE_TRIGGERS = {"PUT", "DELETE", "PATCH", "PROPFIND", "PROPPATCH",
                          "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "TRACE"}


async def _run_method_probes(req: "ConfirmRequest", headers_base: dict):
    """메소드 확증: OPTIONS 로 허용 메소드 열거 + 고유 마커 파일을 PUT→GET 되읽기로
    임의 파일 쓰기를 확증한다. 업로드한 테스트 파일은 마지막에 DELETE 로 정리한다.
    (대상은 요청 경로와 같은 디렉터리의 새 고유 파일명 — 기존 파일을 덮어쓰지 않음.)"""
    parts = urlsplit(req.url)
    base = f"{parts.scheme}://{parts.netloc}"
    dirpath = parts.path.rsplit("/", 1)[0] if "/" in (parts.path or "") else ""
    put_path = f"{dirpath}/evtprobe_{secrets.token_hex(4)}.txt"
    put_url = base + put_path
    marker = "EVPROBE-" + secrets.token_hex(6)
    opt_url = _url_with_params(req.url, req.params)

    res, probes = {}, []

    async def _send(client, method, url, **kw):
        try:
            start = time.time()
            r = await client.request(method, url, timeout=req.timeout, **kw)
            return r, (time.time() - start) * 1000
        except Exception as e:
            return e, 0.0

    async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
        # 1) OPTIONS — 허용 메소드 열거(비침습)
        r, ms = await _send(client, "OPTIONS", opt_url, headers=dict(headers_base))
        if isinstance(r, httpx.Response):
            res["options_headers"] = dict(r.headers); allow = r.headers.get("allow", "") or r.headers.get("public", "")
            probes.append({"role": "method:OPTIONS", "label": f"OPTIONS 허용 메소드{(' — Allow: ' + allow) if allow else ''}",
                           "value": parts.path or "/", "status": r.status_code, "time_ms": round(ms), "len": len(r.text)})
        else:
            probes.append({"role": "method:OPTIONS", "label": "OPTIONS", "value": parts.path or "/",
                           "status": 0, "time_ms": 0, "error": str(r)[:120]})

        # 2) PUT 고유 마커 파일 업로드
        r, ms = await _send(client, "PUT", put_url, headers={**headers_base, "Content-Type": "text/plain"},
                            content=(marker + "\n").encode())
        if isinstance(r, httpx.Response):
            res["put_status"] = r.status_code
            probes.append({"role": "method:PUT", "label": f"PUT 마커 파일 업로드 ({put_path})",
                           "value": marker, "status": r.status_code, "time_ms": round(ms), "len": len(r.text)})
        else:
            probes.append({"role": "method:PUT", "label": "PUT 업로드", "value": marker,
                           "status": 0, "time_ms": 0, "error": str(r)[:120]})

        # 3) GET 되읽기 — 마커가 그대로 오면 실제 파일 쓰기 확증
        if res.get("put_status") in (200, 201, 204):
            r, ms = await _send(client, "GET", put_url, headers=dict(headers_base))
            if isinstance(r, httpx.Response):
                res["get_status"] = r.status_code; res["get_body"] = r.text[:20000]
                hit = marker in res["get_body"]
                probes.append({"role": "method:GET", "label": "업로드 파일 되읽기" + (" — 마커 확인" if hit else " — 마커 없음"),
                               "value": put_path, "status": r.status_code, "time_ms": round(ms), "len": len(r.text)})
            # 4) 정리 — 업로드한 테스트 파일 DELETE(best-effort)
            r, ms = await _send(client, "DELETE", put_url, headers=dict(headers_base))
            if isinstance(r, httpx.Response):
                res["del_status"] = r.status_code
                probes.append({"role": "method:DELETE", "label": "테스트 파일 정리(DELETE)",
                               "value": put_path, "status": r.status_code, "time_ms": round(ms), "len": len(r.text)})

    techniques = confirm_scan.decide_method(
        res.get("options_headers"), res.get("put_status"), res.get("get_status"),
        res.get("get_body", ""), marker, res.get("del_status"))
    return techniques, probes


# L3 catch-all 차분 확증 캐시 — (host, ext) → {"real": bool, "status": int}.
# 형제 경로(존재하지 않는 파일) 응답은 호스트·확장자의 성질이라 한 번만 조회해 재사용한다.
_CATCHALL_CACHE: dict = {}


async def _run_file_exposure_confirm(req: "ConfirmRequest", headers_base: dict):
    """파일 노출 catch-all 차분 확증(L3, traffic-safe).

    - 대상 경로가 '민감/설정 파일'일 때만 동작(그 외엔 None → 요청 미발생).
    - 대상 1회 + 존재하지 않는 형제 경로 1회. 형제 결과는 (host,ext)로 캐시해 재사용.
    """
    tgt_url = _url_with_params(req.url, req.params)
    parts = urlsplit(tgt_url)
    path = parts.path or "/"
    hit = _sensitive_file_ext(path)
    if not hit:
        return None                      # 민감 파일 아님 → 추가 요청 없음
    ext, fmt_label, _ = hit
    host = parts.netloc
    dirpath = path.rsplit("/", 1)[0] if "/" in path else ""
    sib_path = f"{dirpath}/__evtprobe_{secrets.token_hex(4)}.{ext}"
    sib_url = f"{parts.scheme}://{host}{sib_path}"
    probes = []

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        # 대상 파일 1회 조회 → 유효 파일형 여부(L1+L2)
        target_real, tstatus = False, 0
        try:
            tr = await client.get(tgt_url, headers=dict(headers_base), timeout=req.timeout)
            tstatus = tr.status_code
            target_real = file_exposure_looks_real(tr.text, dict(tr.headers), tstatus, ext)
        except Exception as e:
            probes.append({"role": "fileexp:target", "label": f"대상 조회 실패 ({path})",
                           "value": path, "status": 0, "error": str(e)[:120]})
        else:
            probes.append({"role": "fileexp:target",
                           "label": f"대상 파일 조회 — {fmt_label} 형식 {'O' if target_real else 'X'}",
                           "value": path, "status": tstatus, "len": len(tr.text)})

        # 형제(존재하지 않는) 경로 — (host,ext) 캐시로 1회만
        key = (host, ext)
        cached = _CATCHALL_CACHE.get(key)
        if cached is None:
            try:
                sr = await client.get(sib_url, headers=dict(headers_base), timeout=req.timeout)
                cached = {"real": file_exposure_looks_real(sr.text, dict(sr.headers), sr.status_code, ext),
                          "status": sr.status_code}
            except Exception as e:
                cached = {"real": False, "status": 0, "error": str(e)[:120]}
            _CATCHALL_CACHE[key] = cached
            probes.append({"role": "fileexp:sibling",
                           "label": f"존재하지 않는 형제 경로 확인 ({sib_path}) — 파일형 "
                                    f"{'O(catch-all 의심)' if cached['real'] else 'X'}",
                           "value": sib_path, "status": cached.get("status", 0)})
        else:
            probes.append({"role": "fileexp:sibling(cache)",
                           "label": f".{ext} catch-all 판정 캐시 재사용 — 파일형 "
                                    f"{'O' if cached['real'] else 'X'}",
                           "value": f"({host}, .{ext})", "status": cached.get("status", 0)})

    tech = confirm_scan.decide_file_exposure(ext, target_real, cached["real"])
    return tech, probes


@router.post("/confirm-scan")
async def confirm_scan_endpoint(req: ConfirmRequest):
    """대상 파라미터에 오라클 프로브 세트를 순차 전송해 취약 여부를 확증한다.

    선택 페이로드의 카테고리 오라클을 돌리고, 요청이 로그인/인증 흐름처럼 보이면
    '인증 우회' 오라클도 자동으로 함께 돌려 결과를 합친다(별도 버튼 불필요).
    타이밍 오라클 정확도를 위해 프로브는 순차 전송한다.
    """
    cat = (req.category or "").lower()
    sent_headers_base = merge_headers(req.headers, req.default_headers, req.use_defaults)
    techniques, all_probes, ran = [], [], []

    # 1) 카테고리 오라클 (선택 페이로드 계열)
    if cat and cat != "auth" and confirm_scan.is_supported(cat):
        plan = confirm_scan.probe_plan(cat, req.target.base_value)
        if plan:
            results, probes = await _run_confirm_probes(
                req, sent_headers_base, plan, follow=(cat != "redirect"))
            techniques += confirm_scan.decide(cat, results)["techniques"]
            all_probes += probes
            ran.append(cat)

    # 2) 인증 우회 오라클 — 로그인처럼 보이면(또는 명시적으로 auth) 자동 병행.
    #    로그인 성공 리다이렉트(302)를 포착해야 하므로 리다이렉트는 따라가지 않는다.
    if cat == "auth" or _looks_login(req):
        aplan = confirm_scan.probe_plan("auth", req.target.base_value)
        results, probes = await _run_confirm_probes(req, sent_headers_base, aplan, follow=False)
        techniques += confirm_scan.decide("auth", results)["techniques"]
        all_probes += [{**pp, "role": "auth:" + pp["role"]} for pp in probes]
        ran.append("인증우회")

    # 3) 메소드 확증 — 쓰기/위험 메소드 요청이면 OPTIONS 열거 + PUT→GET 되읽기로 확증.
    if (req.method or "").upper() in _METHOD_PROBE_TRIGGERS:
        mtech, mprobes = await _run_method_probes(req, sent_headers_base)
        techniques += mtech
        all_probes += mprobes
        ran.append("메소드")

    # 4) 파일 노출 catch-all 차분 확증 — 대상 경로가 민감/설정 파일일 때만(그 외 추가 요청 없음)
    fx = await _run_file_exposure_confirm(req, sent_headers_base)
    if fx is not None:
        techniques += fx[0]
        all_probes += fx[1]
        ran.append("파일노출")

    # 5) 브라우저 기반 XSS 확증 — 반사형/DOM XSS 는 실제 실행이 브라우저에서만 관측됨
    #    (서버 응답엔 인코딩돼 보여도, 클라이언트 JS(document.write 등)에서 실행될 수 있음)
    _xss_blob = f"{req.url} {req.body or ''} " + " ".join(str(v) for v in (req.params or {}).values())
    if cat == "xss" or re.search(r"<script|<svg|<img|on(?:error|load|toggle)\s*=|javascript:|alert\(|prompt\(", _xss_blob, re.I):
        # 브라우저 확증엔 '원시 URL' 사용 — _url_with_params 의 공백→%20 인코딩이
        # <svg%20onload=...> 처럼 DOM 파싱을 깨뜨려 실행을 막기 때문(실제 브라우저 동작과 불일치).
        target_url = req.url
        if req.params:
            from urllib.parse import urlencode
            target_url += ("&" if "?" in target_url else "?") + urlencode(req.params)
        xr = await xss_confirm.confirm_xss(target_url, timeout=min(req.timeout, 20))
        if xr.get("executed"):
            sig = ", ".join(f"{s[0]}({s[1]})" if isinstance(s, list) and len(s) > 1 else str(s)
                            for s in xr.get("signals", [])) or f"주입 실행형 요소 {xr.get('injected_elements', 0)}개"
            techniques.append({"name": "XSS 실행 확증 (헤드리스 브라우저)",
                               "evidence": f"대상 페이지를 실제 로드해 스크립트 실행 관측: {sig}"})
            all_probes.append({"role": "xss:browser", "label": "브라우저 XSS 확증 — 실행됨",
                               "value": target_url[:90], "status": 200})
            ran.append("XSS확증")
        elif xr.get("supported") and not xr.get("error"):
            all_probes.append({"role": "xss:browser", "label": "브라우저 XSS 확증 — 실행 신호 없음(인코딩/필터 추정)",
                               "value": target_url[:90], "status": 0})
            ran.append("XSS확증")
        # playwright 미설치/오류면 조용히 스킵(다른 확증엔 영향 없음)

    if not ran:
        return {
            "supported": False, "category": cat,
            "message": f"'{cat}' 은(는) 확증 프로브 미지원 — 단발 전송으로 확인하세요.",
        }

    return {
        "supported": True,
        "category": "+".join(ran),
        "target": {"location": req.target.location, "param": req.target.param},
        "probes_sent": len(all_probes),
        "confirmed": bool(techniques),
        "techniques": techniques,
        "probes": all_probes,
    }


class DiscoverRequest(BaseModel):
    url: str
    timeout: int = 15


@router.post("/discover-apis")
async def discover_apis(req: DiscoverRequest):
    """SPA가 호출하는 실제 API를 발견.

    1차: 헤드리스 브라우저로 페이지를 실제 실행해 XHR/fetch 를 파라미터까지 캡처(정확).
    2차(폴백): 캡처 실패 시 JS 번들 정적 분석으로 백엔드·엔드포인트 추정.
    """
    live = await api_capture.capture_apis(req.url, req.timeout)
    if live.get("entries"):
        return {"mode": "live", "entries": live["entries"], "captured": live.get("captured", 0)}

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        static = await api_discover.discover(client, req.url, req.timeout)
    static["mode"] = "static"
    static["live_error"] = live.get("error")
    return static


@router.post("/bulk-test")
async def bulk_test(req: BulkRequest):
    data = load_payloads()
    # 카테고리에서 선택된 페이로드 추출
    payloads_to_test = []
    for cat in data["categories"]:
        if cat["id"] == req.category:
            if req.payload_ids:
                payloads_to_test = [p for p in cat["payloads"] if p["id"] in req.payload_ids]
            else:
                payloads_to_test = cat["payloads"]
            break

    if not payloads_to_test:
        raise HTTPException(status_code=404, detail="페이로드를 찾을 수 없습니다")

    results = []
    _base_headers = merge_headers(req.headers, req.default_headers, req.use_defaults)
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for p in payloads_to_test:
            # 파라미터 조립
            params = dict(req.params)
            headers = dict(_base_headers)
            body = req.body

            if req.inject_in == "params":
                params[req.target_param] = p["payload"]
            elif req.inject_in == "body":
                try:
                    body_dict = json.loads(body) if body else {}
                    body_dict[req.target_param] = p["payload"]
                    body = json.dumps(body_dict)
                    headers.setdefault("Content-Type", "application/json")
                except Exception:
                    body = p["payload"]
            elif req.inject_in == "headers":
                headers[req.target_param] = p["payload"]

            try:
                start = time.time()
                response = await client.request(
                    method=req.method.upper(),
                    url=_url_with_params(req.url, params),
                    headers=headers,
                    content=body.encode() if body else None,
                    timeout=req.timeout,
                )
                elapsed = (time.time() - start) * 1000
                body_text, body_cut, body_full = _read_body(response)
                analysis = analyze_response(
                    response.status_code, dict(response.headers),
                    body_text, elapsed, p["payload"], req.category,
                    url=_url_with_params(req.url, params), req_body=body, method=req.method,
                    redirect_chain=_redirect_chain(response),
                    body_truncated=body_cut, full_body_len=body_full,
                    custom_alert_rules=getattr(req, "custom_alert_rules", None),
                    req_headers=headers,
                )
                results.append({
                    "payload_id": p["id"],
                    "payload_name": p["name"],
                    "payload": p["payload"],
                    "description": p["description"],
                    "risk": p["risk"],
                    "status_code": response.status_code,
                    "response_time": round(elapsed, 2),
                    "analysis": analysis,
                })
            except httpx.TimeoutException:
                results.append({
                    "payload_id": p["id"],
                    "payload_name": p["name"],
                    "payload": p["payload"],
                    "description": p["description"],
                    "risk": p["risk"],
                    "status_code": 0,
                    "response_time": req.timeout * 1000,
                    "analysis": {
                        "verdict": "timeout", "confidence": 30,
                        "waf_detected": None, "block_reason": ["타임아웃"],
                        "error_leaks": [], "sensitive_data": [],
                        "response_anomalies": ["응답 시간 초과"],
                        "risk_level": "medium", "details": ["타임아웃"], "score": 35,
                    },
                })
            except Exception as e:
                results.append({
                    "payload_id": p["id"],
                    "payload_name": p["name"],
                    "payload": p["payload"],
                    "description": p["description"],
                    "risk": p["risk"],
                    "status_code": 0,
                    "response_time": 0,
                    "analysis": {
                        "verdict": "error", "confidence": 0,
                        "waf_detected": None, "block_reason": [str(e)],
                        "error_leaks": [], "sensitive_data": [],
                        "response_anomalies": [],
                        "risk_level": "info", "details": [f"에러: {e}"], "score": 0,
                    },
                })

    summary = generate_summary(results)
    return {"results": results, "summary": summary}


# ── 다중 타겟 일괄 테스트 ───────────────────────────────────
@router.post("/multi-target-test")
async def multi_target_test(req: MultiTargetRequest):
    if not req.urls:
        raise HTTPException(status_code=400, detail="대상 URL이 없습니다")

    # 직접 입력 페이로드 우선, 없으면 체크리스트에서 로드
    if req.custom_payloads:
        payloads_to_test = req.custom_payloads
    else:
        data = load_payloads()
        payloads_to_test = []
        for cat in data["categories"]:
            if cat["id"] == req.category:
                payloads_to_test = [p for p in cat["payloads"] if p["id"] in req.payload_ids] if req.payload_ids else cat["payloads"]
                break
        if not payloads_to_test:
            raise HTTPException(status_code=404, detail="페이로드를 찾을 수 없습니다")

    _base_headers = merge_headers(req.headers, req.default_headers, req.use_defaults)
    urls = [u.strip() for u in req.urls if u and u.strip()]

    # 동시 실행 수 — 속도↑. 대상 서버 부하/차단 방지를 위해 상한(30)을 둔다.
    concurrency = max(1, min(req.concurrency or 12, 30))
    sem = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency + 10, max_keepalive_connections=concurrency)

    def _fail_result(p, verdict, block, risk, detail, score, rtime):
        return {
            "payload_id": p["id"], "payload_name": p["name"],
            "payload": p["payload"], "description": p["description"],
            "risk": p["risk"], "status_code": 0, "response_time": rtime,
            "analysis": {"verdict": verdict, "confidence": 30 if verdict == "timeout" else 0,
                "waf_detected": None, "block_reason": block,
                "error_leaks": [], "sensitive_data": [], "response_anomalies": [],
                "risk_level": risk, "details": detail, "score": score, "alerts": []},
        }

    async with httpx.AsyncClient(verify=False, follow_redirects=True, limits=limits) as client:
        async def run_one(url, p):
            params  = dict(req.params)
            headers = dict(_base_headers)
            body    = req.body

            # 빈 페이로드면 삽입 없이 그대로 요청
            if p.get("payload", ""):
                if req.inject_in == "params":
                    params[req.target_param] = p["payload"]
                elif req.inject_in == "body":
                    try:
                        bd = json.loads(body) if body else {}
                        bd[req.target_param] = p["payload"]
                        body = json.dumps(bd)
                        headers.setdefault("Content-Type", "application/json")
                    except Exception:
                        body = p["payload"]
                elif req.inject_in == "headers":
                    headers[req.target_param] = p["payload"]

            async with sem:
                try:
                    start = time.time()
                    resp  = await client.request(
                        method=req.method.upper(), url=_url_with_params(url, params),
                        headers=headers,
                        content=body.encode() if body else None,
                        timeout=req.timeout,
                    )
                    elapsed = (time.time() - start) * 1000
                    bt, bt_cut, bt_full = _read_body(resp)
                    # 여기선 리다이렉트를 따라가므로(대상 앱 흐름 유지) 최종 응답엔 Location 이
                    # 없다 → 첫 홉을 넘겨야 오픈 리다이렉트가 탐지된다.
                    analysis = analyze_response(resp.status_code, dict(resp.headers), bt, elapsed, p["payload"], req.category, url=_url_with_params(url, params), req_body=body, method=req.method, redirect_chain=_redirect_chain(resp), body_truncated=bt_cut, full_body_len=bt_full, custom_alert_rules=getattr(req, "custom_alert_rules", None), req_headers=headers)
                    return {
                        "payload_id": p["id"], "payload_name": p["name"],
                        "payload": p["payload"], "description": p["description"],
                        "risk": p["risk"], "status_code": resp.status_code,
                        "response_time": round(elapsed, 2), "analysis": analysis,
                    }
                except httpx.TimeoutException:
                    return _fail_result(p, "timeout", ["타임아웃"], "medium", ["타임아웃"], 35, req.timeout * 1000)
                except Exception as e:
                    return _fail_result(p, "error", [str(e)], "info", [f"에러: {e}"], 0, 0)

        # 모든 (url × payload) 조합을 동시에 실행(세마포어로 상한) 후 URL별로 재그룹화
        tasks = [(url, asyncio.create_task(run_one(url, p)))
                 for url in urls for p in payloads_to_test]
        gathered = await asyncio.gather(*[t for _, t in tasks])

    # 결과를 URL 순서·페이로드 순서 그대로 재구성(gather 는 태스크 생성 순서를 보존)
    by_url = {url: [] for url in urls}
    for (url, _), res in zip(tasks, gathered):
        by_url[url].append(res)

    target_results = [{
        "url": url,
        "results": by_url[url],
        "summary": generate_summary(by_url[url]),
    } for url in urls]

    return {"targets": target_results, "target_count": len(target_results)}


# ── 포트 스캔 ────────────────────────────────────────────────
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
    9200, 27017, 1433, 1521, 2375, 2376, 4444, 4848,
    7001, 8161, 9090, 9300, 11211, 50070,
]

WELL_KNOWN = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB", 1433: "MSSQL", 1521: "Oracle",
    2375: "Docker(비보안)", 2376: "Docker(TLS)", 4444: "Metasploit",
    4848: "GlassFish", 7001: "WebLogic", 8161: "ActiveMQ",
    9090: "Prometheus/Openshift", 9300: "Elasticsearch(클러스터)",
    11211: "Memcached", 50070: "Hadoop NameNode",
}

RISK_PORTS = {21, 23, 445, 3389, 6379, 2375, 4444, 27017, 11211, 50070}

async def _check_port(host: str, port: int, timeout: float) -> dict:
    try:
        start = time.time()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        elapsed = (time.time() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {
            "port": port,
            "state": "open",
            "service": WELL_KNOWN.get(port, "Unknown"),
            "response_time": round(elapsed, 2),
            "risk": "high" if port in RISK_PORTS else "low",
            "note": _port_note(port),
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "state": "closed", "service": WELL_KNOWN.get(port, ""), "response_time": None, "risk": "info", "note": ""}

def _port_note(port: int) -> str:
    notes = {
        6379: "⚠️ Redis 인증 없이 노출 여부 확인 필요",
        27017: "⚠️ MongoDB 인증 없이 노출 여부 확인 필요",
        2375: "🔴 Docker 데몬 비보안 노출 — RCE 가능",
        3389: "⚠️ RDP 노출 — 무차별 대입 위험",
        23: "🔴 Telnet 평문 통신 — 사용 지양",
        11211: "⚠️ Memcached 노출 — DDoS 증폭 위험",
        4444: "🔴 Metasploit 기본 포트 — 백도어 의심",
        50070: "⚠️ Hadoop NameNode 관리 인터페이스 노출",
        9200: "⚠️ Elasticsearch 무인증 노출 여부 확인",
        5900: "⚠️ VNC 원격 접속 노출",
    }
    return notes.get(port, "")

@router.post("/port-scan")
async def port_scan(req: PortScanRequest):
    if not req.hosts:
        raise HTTPException(status_code=400, detail="호스트를 입력하세요")

    ports = req.ports if req.ports else DEFAULT_PORTS

    async def scan_one(raw_host: str) -> dict:
        host = raw_host.strip()
        for scheme in ("http://", "https://", "ftp://"):
            if host.startswith(scheme):
                host = host[len(scheme):]
        host = host.split("/")[0].split(":")[0]
        if not host:
            return {"host": raw_host, "error": "유효하지 않은 호스트"}
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {"host": host, "ip": None, "error": f"DNS 해석 실패: {host}",
                    "total_scanned": 0, "open_count": 0, "risky_count": 0,
                    "results": [], "open_ports": []}
        tasks   = [_check_port(ip, p, req.timeout) for p in ports]
        raw     = await asyncio.gather(*tasks)
        results = sorted(raw, key=lambda x: x["port"])
        open_ports  = [r for r in results if r["state"] == "open"]
        risky_ports = [r for r in open_ports if r["risk"] == "high"]
        return {
            "host": host, "ip": ip, "error": None,
            "total_scanned": len(ports),
            "open_count": len(open_ports),
            "risky_count": len(risky_ports),
            "results": results,
            "open_ports": open_ports,
        }

    host_results = []
    for h in req.hosts:
        if h.strip():
            host_results.append(await scan_one(h))

    total_open  = sum(r.get("open_count", 0)  for r in host_results)
    total_risky = sum(r.get("risky_count", 0) for r in host_results)

    return {
        "host_count": len(host_results),
        "total_open": total_open,
        "total_risky": total_risky,
        "hosts": host_results,
    }


class TlsScanRequest(BaseModel):
    host: str = ""
    port: int = 443
    timeout: float = 8.0
    heartbleed: bool = True


@router.post("/tls-scan")
async def tls_scan_endpoint(req: TlsScanRequest):
    """대상의 TLS 전송계층 점검(버전·cipher·인증서·Heartbleed). 외부 바이너리 미사용.

    전송계층 스캔은 HTTP 요청보다 침습적 → 인가된 대상에만 사용.
    URL 을 넣어도 host 로 정규화한다.
    """
    raw = (req.host or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="host 가 필요합니다")
    # URL 이 들어오면 host[:port] 만 추출
    parsed = urlsplit(raw if "://" in raw else "//" + raw, scheme="https")
    host = parsed.hostname or raw
    port = parsed.port or req.port or 443
    return await tls_scan(host, port, float(req.timeout or 8.0), bool(req.heartbleed))


# ── RAG 문서 인제스트/검색(공개 테스트 문서용) ────────────────
@router.post("/rag/ingest")
async def rag_ingest(url: str = Form(""), file: UploadFile = File(None)):
    """공개 테스트 문서(PDF/URL/텍스트)를 로컬 RAG 코퍼스에 색인. 검색·저장은 로컬."""
    try:
        if file is not None:
            data = await file.read()
            fn = file.filename or "upload"
            if fn.lower().endswith(".pdf") or (data[:5] == b"%PDF-"):
                src = await asyncio.to_thread(rag.ingest_pdf, fn, data)
            else:
                src = await asyncio.to_thread(rag.ingest_text, fn, data.decode("utf-8", "ignore"), "text", fn)
        elif url.strip():
            src = await asyncio.to_thread(rag.ingest_url, url.strip())
        else:
            raise HTTPException(status_code=400, detail="url 또는 file 이 필요합니다")
        return {"ok": True, "source": src}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"인제스트 실패: {type(e).__name__} {e}")


@router.get("/rag/sources")
def rag_sources():
    return {"sources": rag.list_sources(), "embeddings": rag.embeddings_enabled()}


@router.post("/rag/reindex")
async def rag_reindex():
    """벡터가 없는 기존 문서를 임베딩해 백필(의미 검색 활성화)."""
    return await asyncio.to_thread(rag.reindex_embeddings)


@router.delete("/rag/sources/{source_id}")
def rag_delete(source_id: str):
    return {"ok": rag.delete_source(source_id)}


class ReportRefsRequest(BaseModel):
    categories: list[str] = []      # 리포트에 등장한 공격 유형/카테고리 목록


@router.post("/rag/report-refs")
async def rag_report_refs(req: ReportRefsRequest):
    """리포트용 — 공격 유형별로 코퍼스에서 조치·참고 자료를 검색(유형당 1회, 트래픽 절약)."""
    if not rag.has_sources():
        return {"refs": []}
    out = []
    for cat in list(dict.fromkeys([c for c in req.categories if c]))[:12]:   # 순서 유지 dedup, 상한
        hits = await _rag_lookup(f"{cat} 취약점 조치 대응 remediation prevention {cat}", 3, cat, floor=0.35)
        if hits:
            out.append({"category": cat, "docs": _rag_ctx_fields(hits)["rag_context"]})
    return {"refs": out}


# ── 페이로드 목록 조회 ──────────────────────────────────────
@router.get("/payloads")
def get_payloads():
    return load_payloads()

@router.get("/payloads/{category_id}")
def get_category_payloads(category_id: str):
    data = load_payloads()
    for cat in data["categories"]:
        if cat["id"] == category_id:
            return cat
    raise HTTPException(status_code=404, detail="카테고리를 찾을 수 없습니다")
