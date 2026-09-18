"""FortiSOAR → 검증도구 연동 (2단계) : raw 패킷을 검증도구로 보내 판정 결과 수신.

FortiSOAR '버튼②(검증)' 플레이북의 Execute Python Block 에 이 파일 내용을 붙여넣고,
스텝 마지막에서 main(params) 를 호출한다. 분석가가 수정한 raw_request 필드를 그대로
검증도구의 POST /api/request/raw 로 보내 실제 전송·판정한 결과를 돌려받는다.

입력(params):
    raw_request : 검증할 raw HTTP 패킷 문자열            (필수)
    tester_url  : 검증도구 베이스 URL (예 http://10.0.0.5:8000)  (필수)
    scheme      : 패킷 URI 가 상대경로일 때 대상 스킴      (기본 https)
    host        : 대상 Host override                       (선택)
    category    : 페이로드 카테고리 힌트(예 cve)            (선택)
    baseline    : {"status_code":302,"location":"/login"}   정상(우회 안 한) 응답 — 우회 확증용(선택)
    timeout     : 대상 요청 타임아웃 초                     (기본 10)
    verify_tls  : 검증도구 호출 시 TLS 검증 여부            (기본 False)
    http_timeout: 검증도구 호출 자체의 타임아웃 초          (기본 30)

반환: {
    "ok": bool, "error": str|None,
    "outcome": "success|suspicious|safe|blocked|inconclusive",
    "risk_level": str, "verdict": str,
    "summary": "분석가용 한 줄 요약",
    "findings": [{"name","verdict","confidence","why"} ...],   # 성공/의심만
    "next_action": "다음 단계 안내",
    "target_status": int, "sent": {"method","url","http_version"},
    "raw_response": {...}   # 도구 원본 응답(감사/디버그용)
}

로컬 테스트:
    python verify_packet.py '{"tester_url":"http://127.0.0.1:8000","raw_request":"GET /admin HTTP/1.1\\r\\nHost: t\\r\\n\\r\\n"}'
"""
import json

try:
    import requests   # FortiSOAR 실행 환경 기본 포함
    _HAVE_REQUESTS = True
except Exception:      # 폴백: 표준 라이브러리
    import urllib.request
    import ssl
    _HAVE_REQUESTS = False


_POSITIVE = ("성공", "의심")   # 분석가가 먼저 볼 finding verdict


def _post(url, payload, verify_tls, timeout):
    """검증도구로 JSON POST. (status_code, json_dict) 반환."""
    data = json.dumps(payload).encode("utf-8")
    if _HAVE_REQUESTS:
        r = requests.post(url, data=data, headers={"Content-Type": "application/json"},
                          verify=verify_tls, timeout=timeout)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"error": f"비-JSON 응답: {r.text[:300]}"}
    # urllib 폴백
    ctx = None
    if url.lower().startswith("https") and not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read().decode("utf-8", "ignore")
        try:
            return resp.status, json.loads(raw)
        except Exception:
            return resp.status, {"error": f"비-JSON 응답: {raw[:300]}"}


def summarize(result):
    """검증도구 원본 응답 → 분석가용 축약 요약."""
    if not isinstance(result, dict):
        return {"ok": False, "error": "예상치 못한 응답 형식", "raw_response": result}
    if result.get("error"):
        return {"ok": False, "error": str(result["error"]), "raw_response": result}

    analysis = result.get("analysis") or {}
    outcome = analysis.get("attack_outcome") or "inconclusive"
    findings = [
        {"name": f.get("name"), "verdict": f.get("verdict"),
         "confidence": f.get("confidence"), "why": f.get("why")}
        for f in (analysis.get("findings") or [])
        if f.get("verdict") in _POSITIVE
    ]
    # 확증(성공)을 의심보다, 같은 등급이면 confidence 높은 순으로 — 분석가가 먼저 볼 순서.
    findings.sort(key=lambda f: (f["verdict"] != "성공", -(f.get("confidence") or 0)))
    parsed = result.get("parsed_request") or {}
    na = analysis.get("next_action") or {}

    top = findings[0]["name"] if findings else None
    summary = f"[{outcome}] " + (top or analysis.get("verdict") or "판정 신호 없음")
    if analysis.get("risk_level"):
        summary += f" · 위험도 {analysis['risk_level']}"

    return {
        "ok": True, "error": None,
        "outcome": outcome,
        "risk_level": analysis.get("risk_level", ""),
        "verdict": analysis.get("verdict", ""),
        "summary": summary,
        "findings": findings,
        "next_action": (na.get("text") if isinstance(na, dict) else na) or "",
        "target_status": result.get("status_code"),
        "sent": {"method": parsed.get("method"), "url": parsed.get("url"),
                 "http_version": parsed.get("http_version")},
        "raw_response": result,
    }


def main(params):
    """FortiSOAR Execute Python Block 진입점. params = 스텝 arguments(dict)."""
    params = params or {}
    raw_request = params.get("raw_request") or ""
    tester = (params.get("tester_url") or "").rstrip("/")
    if not raw_request.strip():
        return {"ok": False, "error": "raw_request 가 비어 있습니다."}
    if not tester:
        return {"ok": False, "error": "tester_url(검증도구 주소)이 필요합니다."}

    payload = {
        "raw": raw_request,
        "scheme": params.get("scheme", "https"),
        "category": params.get("category"),
        "timeout": params.get("timeout", 10),
    }
    if params.get("host"):
        payload["host"] = params["host"]
    if params.get("baseline"):
        payload["baseline"] = params["baseline"]

    endpoint = tester + "/api/request/raw"
    try:
        status, body = _post(endpoint, payload,
                             verify_tls=bool(params.get("verify_tls", False)),
                             timeout=float(params.get("http_timeout", 30)))
    except Exception as e:
        return {"ok": False, "error": f"검증도구 호출 실패: {type(e).__name__}: {e}",
                "endpoint": endpoint}
    if status != 200:
        return {"ok": False, "error": f"검증도구 HTTP {status}", "raw_response": body}
    return summarize(body)


if __name__ == "__main__":   # 로컬 테스트용
    import sys
    p = json.loads(sys.argv[1]) if len(sys.argv) > 1 else json.loads(sys.stdin.read() or "{}")
    print(json.dumps(main(p), ensure_ascii=False, indent=2))
