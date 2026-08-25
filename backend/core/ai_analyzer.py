"""
AI 상세 분석 - NVIDIA NIM (OpenAI 호환 API)로 요청/응답을 LLM 분석.

정규식 기반 analyzer 의 얕은 details 를 보강한다:
요청+응답+기존 판정을 함께 넘겨 "공격이 실제로 통했는지"를 추론하게 한다.

설정(환경변수):
  NVIDIA_API_KEY   필수. 없으면 기능 자동 비활성(도구는 그대로 동작).
  NVIDIA_MODEL     선택. 기본 meta/llama-3.1-70b-instruct
  NVIDIA_BASE_URL  선택. 기본 https://integrate.api.nvidia.com/v1

⚠️ 클라우드 API 사용 시 분석 대상 응답이 NVIDIA로 전송된다.
   내부/민감 대상은 로컬 NIM(NVIDIA_BASE_URL 변경)으로 돌리는 것을 권장.
"""
import os
import json
import re
import httpx

# 설정은 호출 시점에 읽는다(lazy) — .env 가 import 순서와 무관하게 반영되도록.
def _api_key():  return os.getenv("NVIDIA_API_KEY", "").strip()
def _model():    return os.getenv("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct").strip()
def _base_url(): return os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").strip().rstrip("/")
def _timeout():
    try: return max(10.0, float(os.getenv("AI_TIMEOUT", "120")))
    except ValueError: return 120.0

_BODY_LIMIT = 4000   # LLM 에 보낼 응답 본문 최대 길이(토큰/비용 관리)

_SYSTEM_PROMPT = (
    "You are a senior web application penetration tester. "
    "Given an HTTP request (possibly carrying an attack payload) and the server's response, "
    "decide whether the attack actually SUCCEEDED — not merely whether it was blocked. "
    "A 200 status alone does NOT mean success; look for payload reflection, SQL/error output, "
    "data leakage, timing, or behavioral changes. Be skeptical and flag false positives. "
    "Respond ONLY with a single JSON object, no prose, using exactly these keys: "
    '{"attack_success":"yes|no|inconclusive","vulnerability":"short name or null",'
    '"severity":"critical|high|medium|low|info","confidence":0-100,'
    '"reasoning":"1-3 sentences","evidence":["concrete observations from the response"],'
    '"reproduction":"how to reproduce, or null","remediation":"short fix","false_positive_risk":"low|medium|high"}. '
    "Write reasoning/remediation in Korean."
)


def is_enabled() -> bool:
    """AI 기능 전반(페이로드 생성 등, 저유출) 사용 가능 여부 — 키만 있으면 True."""
    return bool(_api_key())


def response_analysis_enabled() -> bool:
    """AI '응답 분석' 사용 여부 — 응답 body 를 외부로 보내 유출 위험이 있으므로 기본 OFF.
    켜려면 .env 에 AI_RESPONSE_ANALYSIS=true 를 명시해야 한다(키만으론 켜지지 않음)."""
    if not _api_key():
        return False
    return os.getenv("AI_RESPONSE_ANALYSIS", "false").strip().lower() in ("1", "true", "yes", "on")


def _build_user_prompt(ctx: dict) -> str:
    body = (ctx.get("resp_body") or "")[:_BODY_LIMIT]
    return (
        f"[REQUEST]\n"
        f"method: {ctx.get('method')}\n"
        f"url: {ctx.get('url')}\n"
        f"payload: {ctx.get('payload') or '(none)'}\n"
        f"category: {ctx.get('category') or '(none)'}\n"
        f"request_body: {(ctx.get('req_body') or '(none)')[:1000]}\n\n"
        f"[RESPONSE]\n"
        f"status: {ctx.get('status_code')}\n"
        f"response_time_ms: {ctx.get('response_time')}\n"
        f"headers: {json.dumps(ctx.get('resp_headers') or {}, ensure_ascii=False)[:1500]}\n"
        f"body (truncated to {_BODY_LIMIT} chars):\n{body}\n\n"
        f"[REGEX_ENGINE_VERDICT]\n"
        f"verdict: {ctx.get('base_verdict')}\n"
        f"alerts: {json.dumps(ctx.get('base_alerts') or [], ensure_ascii=False)[:1000]}\n"
    )


def _extract_json(text: str) -> dict:
    """모델 응답에서 JSON 객체를 최대한 안전하게 추출."""
    text = text.strip()
    # ```json ... ``` 코드펜스 제거
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    else:
        brace = re.search(r"\{.*\}", text, re.DOTALL)
        if brace:
            text = brace.group(0)
    return json.loads(text)


async def ai_analyze(ctx: dict) -> dict | None:
    """LLM 상세 분석 실행. 비활성/실패 시 None 또는 {'error':...} 반환(메인 분석은 영향 없음)."""
    key = _api_key()
    if not key:
        return None
    model, base_url = _model(), _base_url()
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(ctx)},
        ],
        "temperature": 0.2,
        "max_tokens": 800,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=_timeout()) as client:
            r = await client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
        if r.status_code != 200:
            return {"error": f"NVIDIA API {r.status_code}: {r.text[:200]}", "model": model}
        content = r.json()["choices"][0]["message"]["content"]
        parsed = _extract_json(content)
        parsed["model"] = model
        return parsed
    except json.JSONDecodeError:
        return {"error": "AI 응답 JSON 파싱 실패", "model": model}
    except Exception as e:
        return {"error": f"AI 분석 오류: {e}", "model": model}


_VARIANT_SYSTEM = (
    "You are a WAF-evasion payload generator for AUTHORIZED security testing. "
    "Given a base attack payload that was blocked, produce evasion variants that keep the "
    "same attack semantics but may bypass signature/pattern filters — using techniques like "
    "case toggling, inline comments, encoding (URL/double-URL/unicode/hex), whitespace tricks, "
    "keyword splitting, and equivalent syntax. "
    "Respond ONLY with a JSON array of strings (the payloads), no prose, no numbering."
)


async def ai_generate_variants(base_payload: str, category: str = "", waf: str = "", count: int = 8) -> dict:
    """차단된 payload의 WAF 우회 변형을 생성. 응답 민감정보를 보내지 않음(payload+WAF명만)."""
    key = _api_key()
    if not key:
        return {"error": "AI 미설정 (.env 의 NVIDIA_API_KEY 없음)"}
    model, base_url = _model(), _base_url()
    user = (
        f"Base payload: {base_payload}\n"
        f"Attack category: {category or '(unspecified)'}\n"
        f"Target WAF: {waf or '(unknown)'}\n"
        f"Generate {count} distinct evasion variants as a JSON array of strings."
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _VARIANT_SYSTEM},
            {"role": "user", "content": user},
        ],
        "temperature": 0.7,
        "max_tokens": 1000,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=_timeout()) as client:
            r = await client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
        if r.status_code != 200:
            return {"error": f"NVIDIA API {r.status_code}: {r.text[:200]}"}
        content = r.json()["choices"][0]["message"]["content"].strip()
        # JSON 배열 추출
        fence = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", content, re.DOTALL)
        arr_text = fence.group(1) if fence else (re.search(r"\[.*\]", content, re.DOTALL) or [None])[0]
        variants = json.loads(arr_text) if arr_text else []
        variants = [str(v) for v in variants if str(v).strip()]
        return {"variants": variants, "model": model}
    except json.JSONDecodeError:
        return {"error": "AI 변형 응답 파싱 실패"}
    except Exception as e:
        return {"error": f"AI 변형 오류: {e}"}


_SUGGEST_SYSTEM = (
    "You are a web app pentest planner (authorized testing). Given one HTTP request (Host removed), "
    "propose payload candidates as JSON. HARD RULES:\n"
    "- location MUST be 'param' (existing query param), 'path' (append to URL path), or 'body'. "
    "Use 'header' ONLY for Host / X-Forwarded-For / X-Forwarded-Host / X-Original-URL / Referer.\n"
    "- NEVER use User-Agent, Content-Type, Accept, or Accept-* as an injection target. Do not put "
    "payloads in them. If you have no query param, use 'path'.\n"
    "- Identify the app from the path and pick fitting tests. Examples: "
    "/manager* = Tomcat Manager -> path auth-bypass '/manager/html/..;/', read '/..;/WEB-INF/web.xml'. "
    "/autodiscover* = MS Exchange -> path traversal, SSRF via path, CVE-2021-26855(ProxyLogon)-style path. "
    "/.env /.git = secret file read. /actuator* = Spring Boot (/actuator/env, /actuator/heapdump). "
    "/wp-* = WordPress. If a query param exists, test it for sqli/xss/lfi/etc.\n"
    "- 6-8 DISTINCT candidates, no duplicates.\n"
    "Output ONLY this JSON (no prose):\n"
    '{"test_type":"app/endpoint","summary":"Korean 1 sentence",'
    '"candidates":[{"category":"sqli|xss|lfi|ssrf|cmdi|ssti|redirect|idor|nosql|authbypass|other",'
    '"location":"param|path|body|header","param":"name or empty for path",'
    '"payload":"string","why":"Korean short"}]}\n'
    "EXAMPLE for GET /autodiscover/autodiscover.json (no params):\n"
    '{"test_type":"MS Exchange Autodiscover","summary":"Exchange Autodiscover 엔드포인트 - 경로 기반 취약점 점검",'
    '"candidates":[{"category":"authbypass","location":"path","param":"","payload":"/autodiscover/..;/ecp/",'
    '"why":"경로 세그먼트 우회로 ECP 접근 시도"},{"category":"lfi","location":"path","param":"",'
    '"payload":"/autodiscover/../../../../etc/passwd","why":"경로 traversal 파일 읽기"}]}'
)


def _salvage_candidates(text: str) -> list:
    """잘리거나 깨진 JSON 에서 완성된 후보 객체만 건져낸다.
    문자열/이스케이프/중괄호 깊이를 추적하므로 payload 안의 {{7*7}}/${..} 같은
    중괄호나 응답 truncation 에도 안전하다."""
    start_at = text.find('"candidates"')
    if start_at == -1:
        start_at = 0
    out = []
    depth = 0
    obj_start = None
    in_str = False
    esc = False
    for j in range(start_at, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == '{':
            if depth == 0:
                obj_start = j
            depth += 1
        elif ch == '}':
            if depth > 0:
                depth -= 1
                if depth == 0 and obj_start is not None:
                    seg = text[obj_start:j + 1]
                    if '"payload"' in seg:
                        try:
                            out.append(json.loads(seg))
                        except json.JSONDecodeError:
                            pass
                    obj_start = None
    return out


async def ai_suggest_payloads(method: str, path: str, params: dict,
                              body: str = "", header_names=None, count: int = 8) -> dict:
    """요청(호스트 제외)을 보고 테스트 종류 인식 + 후보 payload 생성. 응답 데이터는 보내지 않음."""
    key = _api_key()
    if not key:
        return {"error": "AI 미설정 (.env 의 NVIDIA_API_KEY 없음)"}
    model, base_url = _model(), _base_url()
    user = (
        f"method: {method}\n"
        f"path (host removed): {path}\n"
        f"query params: {json.dumps(params or {}, ensure_ascii=False)[:800]}\n"
        f"body: {(body or '(none)')[:800]}\n"
        f"header names: {json.dumps(header_names or [], ensure_ascii=False)[:400]}\n"
        f"Propose up to {count} payload candidates."
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SUGGEST_SYSTEM},
            {"role": "user", "content": user},
        ],
        "temperature": 0.4,
        "max_tokens": 1100,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=_timeout()) as client:
            r = await client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
        if r.status_code != 200:
            return {"error": f"NVIDIA API {r.status_code}: {r.text[:200]}"}
        content = r.json()["choices"][0]["message"]["content"]
        try:
            parsed = _extract_json(content)
            cands = parsed.get("candidates") or []
            test_type = str(parsed.get("test_type", ""))
            summary = str(parsed.get("summary", ""))
        except json.JSONDecodeError:
            # 응답이 max_tokens 등으로 잘렸을 때: 완성된 후보 객체만 살려낸다
            cands = _salvage_candidates(content)
            if not cands:
                return {"error": "AI 후보 응답 파싱 실패"}
            mt = re.search(r'"test_type"\s*:\s*"([^"]*)"', content)
            ms = re.search(r'"summary"\s*:\s*"([^"]*)"', content)
            test_type = (mt.group(1) if mt else "(부분 파싱)")
            summary = (ms.group(1) if ms else "") + " ⚠️ 응답이 잘려 일부 후보만 표시"
        # 헤더 주입이 의미 있는 헤더만 허용 (일반 헤더 남용 방지)
        INJECTABLE_HEADERS = {
            "host", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
            "x-original-url", "x-rewrite-url", "referer", "true-client-ip",
            "x-real-ip", "forwarded", "cf-connecting-ip", "x-host", "x-custom-ip-authorization",
        }
        # 방어적 정규화 + 품질 필터
        norm, seen = [], set()
        for c in cands:
            if not isinstance(c, dict) or not c.get("payload"):
                continue
            loc = str(c.get("location", "param")).lower()
            if loc not in ("param", "path", "body", "header"):
                loc = "param"
            param = str(c.get("param", ""))
            # 일반 헤더(User-Agent/Content-Type 등)에 주입류를 꽂은 후보는 버림
            if loc == "header" and param.lower() not in INJECTABLE_HEADERS:
                continue
            payload = str(c.get("payload"))
            key = (loc, param.lower(), payload)
            if key in seen:      # 중복 제거
                continue
            seen.add(key)
            norm.append({
                "category": str(c.get("category", "other")),
                "param": param,
                "location": loc,
                "payload": payload,
                "why": str(c.get("why", "")),
            })
        return {
            "test_type": test_type,
            "summary": summary,
            "candidates": norm[:count],
            "model": model,
        }
    except httpx.TimeoutException:
        return {"error": "AI 응답 시간 초과 — 모델이 느리거나 요청이 큽니다. 더 빠른 모델(NVIDIA_MODEL) 사용 권장"}
    except json.JSONDecodeError:
        return {"error": "AI 후보 응답 파싱 실패"}
    except Exception as e:
        return {"error": f"AI 후보 오류: {type(e).__name__} {e}"}
