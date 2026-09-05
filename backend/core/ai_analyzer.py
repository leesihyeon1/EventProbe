"""
AI 상세 분석 - NVIDIA NIM (OpenAI 호환 API)로 요청/응답을 LLM 분석.

정규식 기반 analyzer 의 얕은 details 를 보강한다:
요청+응답+기존 판정을 함께 넘겨 "공격이 실제로 통했는지"를 추론하게 한다.

설정(환경변수):
  NVIDIA_API_KEY   필수. 없으면 기능 자동 비활성(도구는 그대로 동작).
  NVIDIA_MODEL     선택. 기본 meta/llama-3.2-11b-vision-instruct
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
def _model():    return os.getenv("NVIDIA_MODEL", "meta/llama-3.2-11b-vision-instruct").strip()
def _base_url(): return os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").strip().rstrip("/")
def _timeout():
    try: return max(10.0, float(os.getenv("AI_TIMEOUT", "120")))
    except ValueError: return 120.0

def _apply_model_opts(payload: dict) -> dict:
    """모델별 요청 옵션 보정. nemotron 등 추론형은 chain-of-thought 가 content 대신
    reasoning_content 로 나오면서 max_tokens 를 잡아먹어 JSON 이 잘린다. 구조화 JSON
    출력 태스크에서는 사고과정이 불필요하므로 thinking 을 끈다(응답 짧고 안정적).
    끄고 싶지 않으면 .env 에 AI_THINKING=on."""
    model = payload.get("model", "")
    thinking_on = os.getenv("AI_THINKING", "off").strip().lower() in ("1", "true", "yes", "on")
    if ("nemotron" in model.lower() or "reason" in model.lower()) and not thinking_on:
        payload["chat_template_kwargs"] = {"thinking": False}
    return payload

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


def ai_verdict_enabled() -> bool:
    """AI 종합 판정 — 대상 응답 데이터를 보내지 않고 라벨(판정/신호 이름·상태·시간)만 전송하므로
    유출 위험이 없어 키만 있으면 기본 ON. 끄려면 .env 에 AI_VERDICT=false."""
    if not _api_key():
        return False
    return os.getenv("AI_VERDICT", "true").strip().lower() in ("1", "true", "yes", "on")


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
    text = (text or "").strip()
    # 추론형 모델(nemotron 등)의 <think>…</think> 프리앰블 제거(내부 중괄호 오탐 방지)
    text = re.sub(r"(?is)<think>.*?</think>", "", text).strip()
    text = re.sub(r"(?is)^<think>.*", "", text).strip()   # 닫히지 않은 경우
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
            r = await client.post(f"{base_url}/chat/completions", headers=headers, json=_apply_model_opts(payload))
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
            r = await client.post(f"{base_url}/chat/completions", headers=headers, json=_apply_model_opts(payload))
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


_SUGGEST_SYSTEM = '''You are a web app pentest planner (authorized testing). Given one HTTP request (Host removed), propose payload candidates as JSON. HARD RULES:
- Each "payload" MUST be a CONCRETE, literal, ready-to-send string that actually triggers the test. NEVER a description or placeholder. FORBIDDEN examples: "shell command", "{{shell command}}", "PAYLOAD", "your payload", "<command>", "[payload]". Use REAL values from the PAYLOAD BANK below.
- location MUST be "param" (existing query/body param), "path" (append to URL path), or "body". Use "header" ONLY for Host / X-Forwarded-For / X-Forwarded-Host / X-Original-URL / Referer.
- NEVER use User-Agent, Content-Type, Accept, or Accept-* as an injection target.
- Identify the app from the path and pick fitting tests: /manager* = Tomcat Manager; /autodiscover* = MS Exchange (ProxyLogon path); /.env /.git = secret file read; /actuator* = Spring Boot; /wp-* = WordPress; /GponForm/diag_Form = GPON router RCE (inject cmdi into body param dest_host, e.g. dest_host=;id;); /cgi-bin/* = CGI/Shellshock; /boaform/* /goform/* = router admin. If a query/body param exists, inject the payload INTO that param.
- CRITICAL — do NOT invent parameter names. Use param ONLY if it appears in "query params" or "body". If there is NO usable param, set location="path" (param="") or location="body" and target the app's REAL known field (e.g. dest_host for GPON). Never emit a made-up param like "images/", "input", "data".
- PRIORITIZE by param name / endpoint and put the BEST-FIT category FIRST. Map:
    numeric value OR name in {id,uid,pid,user,userid,order,orderid,account,no,seq} -> sqli (first) + idor;
    login/signin/auth/session/token endpoints -> sqli AND nosql AUTH-BYPASS on the credential fields (' OR '1'='1 , {"$ne":""});
    name in {url,uri,next,return,returnurl,redirect,callback,dest,continue,link,site} -> ssrf + redirect;
    name in {file,path,page,doc,document,template,include,view,lang,dir} -> lfi + ssti;
    name in {cmd,command,exec,run,ping,host,domain,ip,addr} -> cmdi;
    free-text search/comment/message/q/query/name -> xss + sqli.
  ALWAYS include the obvious high-signal category for the endpoint — NEVER omit sqli on an id/login, ssrf on a url param, or lfi on a file param.
- 6-8 DISTINCT candidates. Ensure CATEGORY DIVERSITY: at most 2 per category (more only if the endpoint strongly implies one, e.g. a login page), and never repeat near-identical payloads.

PAYLOAD BANK (use these exact styles; pick real values, never placeholders):
  sqli: ' OR '1'='1     1' ORDER BY 5-- -     ' UNION SELECT NULL,NULL-- -     1 AND SLEEP(5)-- -
  xss:  <script>alert(1)</script>     "><img src=x onerror=alert(1)>     '-alert(1)-'
  cmdi: ;id     | id     $(id)     `id`     ;cat /etc/passwd     & whoami
  ssti: {{7*7}}     ${7*7}     #{7*7}     <%= 7*7 %>     {{7*'7'}}
  lfi:  ../../../../etc/passwd     ....//....//etc/passwd     /etc/passwd%00
  ssrf: http://127.0.0.1:80/     http://169.254.169.254/latest/meta-data/     file:///etc/passwd
  redirect: //evil.example.com     https://evil.example.com     @evil.example.com
  nosql: ' || '1'=='1     [$ne]=     {"$gt":""}
  path/authbypass: /..;/     ..%2f..%2f     /%2e%2e/     /manager/html/..;/

Output ONLY this JSON (no prose):
{"test_type":"app/endpoint","summary":"Korean 1 sentence","candidates":[{"category":"sqli|xss|lfi|ssrf|cmdi|ssti|redirect|idor|nosql|authbypass|other","location":"param|path|body|header","param":"name or empty for path","payload":"string","why":"Korean short"}]}

EXAMPLE for POST with body {"q":"test"} (param q exists):
{"test_type":"검색 파라미터 q","summary":"검색 파라미터 q에 대한 인젝션 점검","candidates":[{"category":"sqli","location":"body","param":"q","payload":"' OR '1'='1","why":"불린 기반 SQL 인젝션"},{"category":"xss","location":"body","param":"q","payload":"<script>alert(1)</script>","why":"반사형 XSS"},{"category":"cmdi","location":"body","param":"q","payload":";id","why":"OS 명령 주입"},{"category":"ssti","location":"body","param":"q","payload":"{{7*7}}","why":"템플릿 평가 결과 49 확인"}]}'''


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


# 실제 페이로드가 아니라 설명/자리표시자를 뱉은 후보를 걸러낸다(소형 모델 품질 방어)
_PLACEHOLDER_MARKERS = (
    "shell command", "your payload", "your command", "arbitrary command",
    "some command", "command here", "placeholder", "insert payload",
    "put your", "<command>", "<payload>", "[command]", "[payload]",
    "example payload", "payload here", "malicious command",
)


def _is_placeholder_payload(payload: str) -> bool:
    p = (payload or "").strip().lower()
    if not p:
        return True
    if any(m in p for m in _PLACEHOLDER_MARKERS):
        return True
    # 영어 단어만으로 이뤄져 인젝션 문자가 전혀 없는 설명형 문자열(예: "shell command")
    if re.fullmatch(r"[a-z][a-z ]{2,}", p) and not re.search(r"[<>{}$;|&'\"=/()\\.]", payload):
        return True
    return False


_KNOWN_CATS = {"sqli", "xss", "lfi", "ssrf", "cmdi", "ssti",
               "redirect", "idor", "nosql", "authbypass", "other"}


def _infer_category(payload: str) -> str:
    """모델이 category 를 스키마 문자열('sqli|xss|...')로 뱉거나 빠뜨린 경우 payload 로 추론."""
    p = (payload or "").lower()
    if any(t in payload for t in ("{{", "${", "#{", "<%=")):
        return "ssti"
    if "<script" in p or "onerror=" in p or "alert(" in p or "<img" in p:
        return "xss"
    if any(t in p for t in ("$ne", "$gt", "$where", "[$")):
        return "nosql"
    if any(t in p for t in ("union select", "or '1'='1", " or 1=1", "order by", "sleep(", "-- -", "waitfor delay")):
        return "sqli"
    if any(t in p for t in ("169.254.169.254", "file://", "http://127.", "http://localhost", "gopher://", "dict://")):
        return "ssrf"
    if "..;/" in p or "%2e%2e" in p or "..%2f" in p:
        return "authbypass"
    if any(t in p for t in ("../", "..\\", "/etc/passwd", "%00", "..//")):
        return "lfi"
    if p.startswith(("//", "@", "http://evil", "https://evil")) or "\\evil" in p:
        return "redirect"
    if any(payload.strip().startswith(t) for t in (";", "|", "&", "$(", "`")) or "whoami" in p or ";id" in p:
        return "cmdi"
    return "other"


def _norm_category(cat: str, payload: str) -> str:
    c = (cat or "").strip().lower()
    return c if c in _KNOWN_CATS else _infer_category(payload)


async def ai_suggest_payloads(method: str, path: str, params: dict,
                              body: str = "", header_names=None, count: int = 8,
                              hint: str = "", retrieved=None) -> dict:
    """요청(호스트 제외)을 보고 테스트 종류 인식 + 후보 payload 생성. 응답 데이터는 보내지 않음.
    hint: 결과 기반 후속 생성용 라벨-only 힌트(취약 계열·판정·탐지 기술 이름만).
    retrieved: RAG 로 검색한 문서 스니펫 [{title, text, loc}] — 프롬프트에 근거로 주입."""
    key = _api_key()
    if not key:
        return {"error": "AI 미설정 (.env 의 NVIDIA_API_KEY 없음)"}
    model, base_url = _model(), _base_url()
    hint_line = (f"이전 검증에서 확인된 신호(라벨): {hint}. 이 계열을 승격/우회하는 페이로드 위주로.\n"
                 if hint else "")
    # RAG 검색 결과를 '이 대상에 적합한 실제 근거'로 주입(있으면 최우선 적용/변형)
    rag_block = ""
    if retrieved:
        lines = []
        for i, r in enumerate(retrieved[:6], 1):
            snip = re.sub(r"\s+", " ", str(r.get("text", "")))[:400]
            lines.append(f"{i}) [{r.get('title', '')}{(' ' + r.get('loc', '')) if r.get('loc') else ''}] {snip}")
        rag_block = ("RETRIEVED (인제스트한 참고문서에서 이 요청에 적합. 여기 나온 실제 페이로드/파라미터/"
                     "기법을 최우선으로 이 요청에 맞게 구체화하라. 문서에 없는 파라미터는 지어내지 말 것):\n"
                     + "\n".join(lines) + "\n\n")
    user = (
        f"method: {method}\n"
        f"path (host removed): {path}\n"
        f"query params: {json.dumps(params or {}, ensure_ascii=False)[:800]}\n"
        f"body: {(body or '(none)')[:800]}\n"
        f"header names: {json.dumps(header_names or [], ensure_ascii=False)[:400]}\n"
        f"{hint_line}"
        f"{rag_block}"
        f"Propose up to {count} payload candidates."
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SUGGEST_SYSTEM},
            {"role": "user", "content": user},
        ],
        "temperature": 0.3,
        "max_tokens": 1500,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    # 헤더 주입이 의미 있는 헤더만 허용 (일반 헤더 남용 방지)
    INJECTABLE_HEADERS = {
        "host", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
        "x-original-url", "x-rewrite-url", "referer", "true-client-ip",
        "x-real-ip", "forwarded", "cf-connecting-ip", "x-host", "x-custom-ip-authorization",
    }
    try:
        last_err = "AI 후보 응답 파싱 실패"
        # 소형 모델은 간헐적으로 파싱 불가/빈 응답을 냄 → 최대 2회 시도
        for attempt in range(2):
            async with httpx.AsyncClient(timeout=_timeout()) as client:
                r = await client.post(f"{base_url}/chat/completions", headers=headers, json=_apply_model_opts(payload))
            if r.status_code != 200:
                return {"error": f"NVIDIA API {r.status_code}: {r.text[:200]}"}
            content = r.json()["choices"][0]["message"]["content"]
            summary_suffix = ""
            try:
                parsed = _extract_json(content)
                cands = parsed.get("candidates") or []
                test_type = str(parsed.get("test_type", ""))
                summary = str(parsed.get("summary", ""))
            except json.JSONDecodeError:
                # 응답이 max_tokens 등으로 잘렸을 때: 완성된 후보 객체만 살려낸다
                cands = _salvage_candidates(content)
                if not cands:
                    last_err = "AI 후보 응답 파싱 실패"
                    continue   # 재시도
                mt = re.search(r'"test_type"\s*:\s*"([^"]*)"', content)
                ms = re.search(r'"summary"\s*:\s*"([^"]*)"', content)
                test_type = (mt.group(1) if mt else "(부분 파싱)")
                summary = (ms.group(1) if ms else "")
                summary_suffix = " ⚠️ 응답이 잘려 일부 후보만 표시"

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
                payload_str = str(c.get("payload"))
                if _is_placeholder_payload(payload_str):   # 'shell command' 같은 설명/자리표시자 제거
                    continue
                key = (loc, param.lower(), payload_str)
                if key in seen:      # 중복 제거
                    continue
                seen.add(key)
                norm.append({
                    "category": _norm_category(c.get("category", ""), payload_str),
                    "param": param,
                    "location": loc,
                    "payload": payload_str,
                    "why": str(c.get("why", "")),
                })

            # 카테고리 편중 방지 — 한 카테고리가 목록을 도배하지 않도록 카테고리당 최대 3개.
            capped, per_cat = [], {}
            for c in norm:
                cat = c.get("category") or "other"
                if per_cat.get(cat, 0) >= 3:
                    continue
                per_cat[cat] = per_cat.get(cat, 0) + 1
                capped.append(c)
            norm = capped

            if norm:
                return {
                    "test_type": test_type,
                    "summary": summary + summary_suffix,
                    "candidates": norm[:count],
                    "model": model,
                }
            last_err = "AI 후보 없음 — 다시 시도해 주세요"   # 전부 필터링됨 → 재시도

        return {"error": last_err, "model": model}
    except httpx.TimeoutException:
        return {"error": "AI 응답 시간 초과 — 모델이 느리거나 요청이 큽니다. 더 빠른 모델(NVIDIA_MODEL) 사용 권장"}
    except json.JSONDecodeError:
        return {"error": "AI 후보 응답 파싱 실패"}
    except Exception as e:
        return {"error": f"AI 후보 오류: {type(e).__name__} {e}"}


_VERDICT_SYSTEM = (
    "당신은 웹 보안 분석가입니다. 결정적 스캐너가 뽑은 라벨/결과(공격 성공 신호, 알림 이름·위험도, "
    "상태코드, 응답시간)만 받습니다 — 원본 응답 데이터는 없습니다. 당신의 일은 재판정이 아니라, 이 신호들을 "
    "사람이 읽기 좋은 자연스러운 한국어로 요약·우선순위화·조치 제안하는 것입니다.\n"
    "규칙:\n"
    "1) outcome 은 주어진 '확정_판정'을 그대로 따른다(뒤집지 말 것). 공격 성공 신호가 있으면 success, "
    "없으면 inconclusive. 보안 헤더/쿠키 같은 '응답 위생' 문제는 별개이며 '공격이 차단됐다'는 뜻이 아니다.\n"
    "1-b) 이번 공격의 결과가 판정의 중심이다. '응답 위생'은 이번 공격 결과가 아니므로 주된 발견처럼 "
    "앞세우지 말 것 — 공격 결과를 먼저 서술하고, 위생 문제는 있으면 뒤에 한 문장으로만 덧붙인다.\n"
    "1-b-2) outcome 이 blocked 여도 WAF 지문이나 baseline 근거 없이 '공격이 성공적으로 차단/방어됐다'고 "
    "단정하지 말 것. 차단 상태코드(403 등)는 payload 를 막은 것일 수도, 경로 자체가 원래 거부되는 것일 "
    "수도 있다. 반드시 '주어진 상태코드' 를 그대로 언급하고(임의로 403 이라 쓰지 말 것), '요청이 <상태코드>"
    "로 거부됨(WAF 필터인지 경로 자체 제한인지 미확인)' 수준으로 서술하고, priority 에 '정상 파라미터로 "
    "baseline 비교'를 제안한다. 이때 confidence 는 80 을 넘기지 말 것.\n"
    "1-c) 각 공격_신호에는 verdict 가 붙어 있다(성공/안전/미확정). 반드시 그 verdict 대로 서술한다: "
    "'성공'=실제로 뚫림, '안전'=그 항목은 안전함(예: 요청한 파일이 응답에 노출되지 않음), '미확정'=추가 확인 필요. "
    "verdict 가 '안전'인 항목을 '노출됨/성공'처럼 쓰지 말 것. 신호 이름의 글자(예: '미노출'에 든 '노출')만 보고 "
    "반대로 해석하지 말고, 반드시 verdict 와 why 를 근거로 삼는다. '노출됐지만 성공 아님' 같은 모순 문장 금지.\n"
    "1-d) 세 상태를 분명히 구분한다: (성공)취약 확인 / (안전·차단)안전 확인 / (미확인)자동 판정 불가. "
    "verdict 가 '미확인'이거나 신호가 전혀 없는 inconclusive 는 '안전/취약하지 않음/노출되지 않음'이라고 단정하지 "
    "말 것 — 이는 '판정 불가'이지 '안전'이 아니다. 이 경우 '자동 판정 불가 — 응답을 직접 확인하거나 확증 스캔/"
    "baseline 비교 필요'로 서술하고 priority 에 그 확인 방법을 넣는다. '안전/미노출' 이라는 표현은 verdict 가 "
    "실제로 '안전'(또는 outcome=blocked)인 신호가 있을 때만 쓴다.\n"
    "2) severity 는 공격 결과와 알림 위험도 중 가장 높은 값.\n"
    "3) 문장은 자연스러운 한국어로 쓰고, 내부 필드명·변수명(attack_signals, security_alerts, outcome 등)을 "
    "그대로 노출하지 말 것. 무엇을 확인해서 무엇을 확인한다는 식의 동어반복·순환 문장 금지. 신호가 실제로 "
    "의미하는 바를 구체적으로 서술한다.\n"
    "4) confidence(0-100)는 이 판정을 얼마나 확신하는지. 반사·파일읽기·명령출력·시간지연 일치 등 직접 증거가 "
    "있으면 85-100, 성공 신호가 전혀 없어 미확인이면 50-70. 미확인(inconclusive)에 100 을 주지 말 것.\n"
    "5) reasoning 은 무엇이 관찰됐고 그래서 어떤 상태인지 1-2문장. 각 신호에는 evidence(관찰된 근거: "
    "상태코드·응답크기·검출/미검출한 시그니처·시간차 등)가 붙어 있으니, 결론만 말하지 말고 그 evidence 를 "
    "구체적으로 인용해 근거를 밝힌다(예: 'HTTP 200·84KB 응답에 .env 시그니처가 없어 미노출'). priority 는 다음에 "
    "실제로 확인/수행할 구체적 행동(없으면 빈 문자열). remediation 은 구체적 수정(없으면 빈 문자열). 지어내지 말 것.\n"
    "6) remediation 에서 누락된 보안 헤더/쿠키 플래그를 하나하나 나열하지 말 것. 여러 개면 "
    "'여러 보안 헤더 누락(CSP·HSTS 등) 및 쿠키 플래그 미설정 보완' 처럼 한 구절로 요약한다. 공격이 실제로 "
    "성공(verdict 성공/outcome success)했다면 remediation 은 그 취약점 수정에 집중하고 위생은 덧붙이지 않는다.\n"
    "오직 JSON 객체 하나만 출력(그 외 설명 금지): "
    '{"outcome":"success|blocked|inconclusive","severity":"critical|high|medium|low|info",'
    '"confidence":0-100,"reasoning":"한국어 1-2문장","priority":"한국어 짧게 또는 빈 문자열",'
    '"remediation":"한국어 짧게 또는 빈 문자열"}\n'
    "7) reasoning 은 반드시 '공격_신호'의 evidence/verdict 에 근거해 그 공격 유형에 맞게 쓴다. 파일/노출 "
    "공격이 아니면(예: 명령 주입·SQLi·SSTI) '파일이 노출되지 않았다'고 쓰지 말 것 — evidence 가 '명령 실행 "
    "출력 검색 → 미검출'이면 '명령 실행 흔적이 확인되지 않음'처럼 그 내용을 그대로 반영한다.\n"
    "좋은 예(명령 주입이 미확인으로 끝난 경우 — 공격 유형에 맞춰, 위생은 뒤에 한 문장): "
    '{"outcome":"inconclusive","severity":"low","confidence":75,'
    '"reasoning":"주입한 명령의 실행 출력(uid= 등)이 응답에서 확인되지 않아 명령 주입 성공은 미확인입니다(200 일반 페이지). 블라인드일 수 있으니 확증 스캔/OOB 로 재확인하세요. 별개로 CSP 등 보안 헤더 누락이 있습니다.",'
    '"priority":"확증 스캔 또는 OOB(콜백)로 blind 실행 여부 재확인",'
    '"remediation":"응답 위생 개선이 필요하면 여러 보안 헤더 누락(CSP·HSTS 등) 보완"}\n'
    "8) RETRIEVED(참고문서) 블록이 있으면 이 공격 유형에 대한 검증된 지식이다. priority(다음 확인 방법)와 "
    "remediation(수정 방안)을 그 문서 내용에 근거해 더 구체적으로 쓴다(예: SSRF 성공 → URL 파서 불일치 확인 "
    "기법을 priority 에 반영). 단, 판정(outcome/verdict)을 뒤집는 근거로는 쓰지 말 것 — 판정은 실제 신호로만 "
    "결정한다. 문서에 없는 내용을 지어내거나 문서 제목/페이지를 그대로 인용하지 말고, 내용을 녹여 서술한다."
)


async def ai_verdict(ctx: dict) -> dict | None:
    """라벨-only AI 종합 판정. 대상 응답 데이터를 보내지 않음(유출 없음)."""
    key = _api_key()
    if not key:
        return None
    model, base_url = _model(), _base_url()
    findings = ctx.get("findings") or []
    alerts = ctx.get("alerts") or []
    # RAG 검색 스니펫(있으면) — priority/remediation 을 문서 지식에 근거해 구체화(판정은 안 바꿈)
    rag_block = ""
    retrieved = ctx.get("retrieved") or []
    if retrieved:
        lines = []
        for i, r in enumerate(retrieved[:4], 1):
            snip = re.sub(r"\s+", " ", str(r.get("text", "")))[:400]
            lines.append(f"{i}) {snip}")
        rag_block = ("RETRIEVED (이 공격 유형 관련 참고문서 발췌 — priority·remediation 근거로만 활용, "
                     "판정은 바꾸지 말 것):\n" + "\n".join(lines) + "\n")
    user = (
        f"공격_유형: {ctx.get('category') or '(없음)'}\n"
        f"상태코드: {ctx.get('status')}\n"
        f"응답시간_ms: {ctx.get('time')}\n"
        f"확정_판정: {ctx.get('outcome')}\n"
        f"공격_신호(각 항목 verdict=성공/안전/미확정, why=근거): {json.dumps(findings, ensure_ascii=False)}\n"
        f"응답_보안_점검: {json.dumps(alerts, ensure_ascii=False)}\n"
        f"{rag_block}"
        f"위 신호만 근거로 종합 판정을 JSON 으로 주세요."
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _VERDICT_SYSTEM},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
        "max_tokens": 800,   # 추론형 모델(nemotron)은 서술이 길어 400 이면 JSON 이 잘림
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=_timeout()) as client:
            r = await client.post(f"{base_url}/chat/completions", headers=headers, json=_apply_model_opts(payload))
        if r.status_code != 200:
            return {"error": f"NVIDIA API {r.status_code}", "model": model}
        content = r.json()["choices"][0]["message"]["content"]
        parsed = _extract_json(content)
        # outcome 은 결정적 엔진 값으로 강제(모델이 뒤집지 못하게). AI 는 서술만 담당.
        if ctx.get("outcome"):
            parsed["outcome"] = ctx["outcome"]
        parsed["model"] = model
        parsed["rag_used"] = len(retrieved)   # 참고문서 반영 개수(UI 표시용)
        return parsed
    except httpx.TimeoutException:
        return {"error": "AI 판정 시간 초과", "model": model}
    except json.JSONDecodeError:
        return {"error": "AI 판정 파싱 실패", "model": model}
    except Exception as e:
        return {"error": f"AI 판정 오류: {type(e).__name__}", "model": model}
