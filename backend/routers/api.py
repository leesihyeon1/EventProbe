import time
import json
import asyncio
import socket
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.analyzer import analyze_response, generate_summary
from urllib.parse import urlsplit, quote

# 쿼리에서 RFC3986 상 합법이며 보안 페이로드에 흔히 쓰이는 문자는 보존하고
# (@ / : ; + , = ! $ ( ) * 등), 구조를 깨는 문자(공백·&·#·%)만 인코딩한다.
# httpx 의 params= 는 @·/ 까지 전부 인코딩해 ProxyLogon 등 페이로드를 깨뜨리므로,
# 파라미터를 URL 쿼리에 직접 병합해서 원문을 최대한 보존한다.
_QUERY_SAFE = "@:/;+,=!$()*~-._'"

def _url_with_params(url: str, params: dict) -> str:
    if not params:
        return url
    q = "&".join(
        f"{quote(str(k), safe=_QUERY_SAFE)}={quote(str(v), safe=_QUERY_SAFE)}"
        for k, v in params.items()
    )
    return url + ("&" if "?" in url else "?") + q
from core.ai_analyzer import ai_analyze, ai_generate_variants, ai_suggest_payloads, ai_verdict, is_enabled as ai_enabled, response_analysis_enabled, ai_verdict_enabled
from core.raw_http import raw_send
from core.cve_matcher import match_cve_payloads
from core.followup import hot_families, escalation_candidates
from core import confirm as confirm_scan
from core import discover as api_discover
from core import capture as api_capture

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

class BulkRequest(BaseModel):
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
            if ai_verdict_enabled():
                analysis["ai_verdict"] = await ai_verdict({
                    "category": req.category, "status": r["status_code"], "time": r["response_time"],
                    "outcome": analysis.get("attack_outcome"),
                    "findings": [{"name": f["name"], "verdict": f.get("verdict"), "why": f.get("why")}
                                 for f in analysis.get("findings", [])],
                    "alerts": [{"name": a["name"], "risk": a["risk"]} for a in analysis.get("alerts", [])],
                })
            return {
                "status_code": r["status_code"], "headers": r["headers"], "body": r["body"],
                "response_time": r["response_time"], "body_size": r["body_size"],
                "sent_headers": sent_headers, "raw_mode": True,
                "request_line": r["request_line"], "analysis": analysis,
            }

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            start = time.time()
            response = await client.request(
                method=req.method.upper(),
                url=_url_with_params(req.url, req.params),
                headers=sent_headers,
                content=req.body.encode() if req.body else None,
                timeout=req.timeout,
            )
            elapsed = (time.time() - start) * 1000

        body_text = response.text[:50000]  # 최대 50KB
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
        )

        # AI 상세 분석 — 응답 body 를 외부로 보내므로 기본 비활성(AI_RESPONSE_ANALYSIS=true 일 때만).
        if response_analysis_enabled():
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

        # AI 종합 판정 — 라벨(판정/신호 이름·상태·시간)만 전송, 대상 응답 데이터 미전송(유출 없음)
        if ai_verdict_enabled():
            analysis["ai_verdict"] = await ai_verdict({
                "category": req.category, "status": response.status_code, "time": round(elapsed, 2),
                "outcome": analysis.get("attack_outcome"),
                "findings": [{"name": f["name"], "verdict": f.get("verdict"), "why": f.get("why")}
                             for f in analysis.get("findings", [])],
                "alerts": [{"name": a["name"], "risk": a["risk"]} for a in analysis.get("alerts", [])],
            })

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body_text,
            "response_time": round(elapsed, 2),
            "body_size": len(response.content),
            "sent_headers": sent_headers,
            "analysis": analysis,
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
    return await ai_generate_variants(req.base_payload, req.category, req.waf, count)


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

    # 2) AI 후보 (키 있을 때만). path/param/body/헤더 '이름'만 전송(host·인증 제외)
    ai_res = None
    if ai_enabled():
        safe_header_names = [h for h in (req.header_names or [])
                             if h.lower() not in ("host", "authorization", "cookie", "proxy-authorization")]
        ai_res = await ai_suggest_payloads(req.method, path, req.params, req.body or "", safe_header_names, count)
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
    if ai_err and cve_cands:
        summary += f" (AI 보강 실패: {ai_err})"
    test_type = ai_res.get("test_type") or (f"CVE 매칭 {len(cve_cands)}건" if cve_cands else "분석")

    return {
        "test_type": test_type,
        "summary": summary,
        "candidates": merged[: len(cve_cands) + count],
        "model": ai_res.get("model", ""),
        "cve_count": len(cve_cands),
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
    })

    # 1) 로컬 승격 페이로드 (신호 → 카테고리, 고급 변형 우선)
    esc = escalation_candidates(data, families, req.location, req.param,
                                per_family=5, exclude_payload=(req.tried_payload or None))
    # 2) 기술스택 지문 기반 CVE 매칭 (기능1 재사용)
    cve = match_cve_payloads(data, path, req.params, req.body or "", req.fingerprint or {}, limit=6)

    # 3) AI 라벨-only 보강 (선택) — 계열/판정/탐지기술 이름만 전송(응답 데이터 미전송)
    ai_res = {}
    if req.use_ai and ai_enabled():
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
                                      safe_headers, req.count, hint=hint)
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
        return {"error": "후속 후보를 만들지 못했습니다 — 취약 신호가 약하거나 저장소에 매칭이 없습니다."}

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


@router.post("/confirm-scan")
async def confirm_scan_endpoint(req: ConfirmRequest):
    """파라미터 1개에 오라클 프로브 세트를 순차 전송하고 응답 차이로 취약 여부를 확증한다.

    타이밍 오라클(시간 기반)의 정확도를 위해 프로브는 병렬이 아니라 순차 전송한다.
    """
    cat = (req.category or "").lower()
    if not confirm_scan.is_supported(cat):
        return {
            "supported": False,
            "category": cat,
            "message": f"'{cat}' 은(는) 확증 프로브 미지원 — 단발 전송으로 확인하세요.",
        }

    plan = confirm_scan.probe_plan(cat, req.target.base_value)
    if not plan:
        return {"supported": False, "category": cat, "message": "프로브가 없습니다."}

    sent_headers_base = merge_headers(req.headers, req.default_headers, req.use_defaults)
    # 오픈 리다이렉트는 3xx Location 을 봐야 하므로 리다이렉트를 따라가지 않는다.
    follow = cat != "redirect"

    results = []
    probes_out = []
    async with httpx.AsyncClient(verify=False, follow_redirects=follow) as client:
        for p in plan:
            params = dict(req.params)
            headers = dict(sent_headers_base)
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
                body_text = resp.text[:50000]
                results.append({
                    "role": p["role"], "status": resp.status_code, "time_ms": elapsed,
                    "body": body_text, "headers": dict(resp.headers), "value": p["value"],
                })
                probes_out.append({
                    "role": p["role"], "label": p["label"], "value": p["value"],
                    "status": resp.status_code, "time_ms": round(elapsed),
                })
            except httpx.TimeoutException:
                # 타임아웃도 신호가 될 수 있으나(예: SLEEP), 시간 측정이 불가하므로 실패로 기록
                results.append({"role": p["role"], "status": 0, "time_ms": float(req.timeout) * 1000,
                                "body": "", "headers": {}, "value": p["value"]})
                probes_out.append({"role": p["role"], "label": p["label"], "value": p["value"],
                                   "status": 0, "time_ms": round(float(req.timeout) * 1000), "timeout": True})
            except Exception as e:
                results.append({"role": p["role"], "status": 0, "time_ms": 0.0,
                                "body": "", "headers": {}, "value": p["value"]})
                probes_out.append({"role": p["role"], "label": p["label"], "value": p["value"],
                                   "status": 0, "time_ms": 0, "error": str(e)[:120]})

    decision = confirm_scan.decide(cat, results)
    return {
        "supported": True,
        "category": cat,
        "target": {"location": req.target.location, "param": req.target.param},
        "probes_sent": len(plan),
        "confirmed": decision["confirmed"],
        "techniques": decision["techniques"],
        "probes": probes_out,
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
                body_text = response.text[:10000]
                analysis = analyze_response(
                    response.status_code, dict(response.headers),
                    body_text, elapsed, p["payload"], req.category,
                    url=_url_with_params(req.url, params), req_body=body,
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
                    bt = resp.text[:5000]
                    analysis = analyze_response(resp.status_code, dict(resp.headers), bt, elapsed, p["payload"], req.category, url=_url_with_params(url, params), req_body=body)
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
