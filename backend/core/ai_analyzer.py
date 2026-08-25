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
        async with httpx.AsyncClient(timeout=30) as client:
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
        "max_tokens": 700,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
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
