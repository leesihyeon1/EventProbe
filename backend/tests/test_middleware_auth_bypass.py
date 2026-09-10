"""미들웨어/게이트웨이 인가 우회 인식·판정 — CVE-2025-29927(Next.js) 등.

배경: X-Middleware-Subrequest 같은 '헤더로 인가 단계를 건너뛰는' 공격은 응답 문자열
시그니처가 없어 예전 판정엔 통째로 안 잡혔다(분류·판정 모두 미인식). 이 헤더는 정상
트래픽엔 없는 마커라 분류는 넉넉히 잡고, '통했는가'는 대조군 상태전이로 확증한다.
"""
from core.classify import classify
from core.analyzer import analyze_response

_MW = "middleware:middleware:middleware:middleware:middleware"
_HDRS = {"x-middleware-subrequest": _MW, "host": "test.com"}
_URL = "http://test.com/123/v1/js/common/vendor.js"


def _find(r, kw="CVE-2025-29927"):
    return [f for f in r["findings"] if kw in f["name"] or "우회" in f["name"]]


# ── 분류: 헤더에 실린 우회를 인식 ──────────────────────────────────────────────
def test_classify_recognizes_middleware_bypass_header():
    c = classify(payload="", url=_URL, headers=_HDRS, category="")
    assert c.primary == "authbypass"
    assert c.header_borne is True
    assert any(h.subtype == "middleware" for h in c.candidates)


def test_original_url_header_judged_by_detector():
    # X-Original-Url 은 분류(classify)에선 authbypass 로 잡지 않는다(값에 트래버설이 실리면 lfi 가
    # 더 구체적). 대신 detectors 가 헤더 존재로 '접근제어 우회'를 직접 판정한다.
    r = analyze_response(200, {}, "admin panel" * 10, 40, payload="", category="",
                         url="http://test.com/admin", req_headers={"x-original-url": "/admin"},
                         baseline={"status_code": 403, "body": "Forbidden"})
    fs = [f for f in r["findings"] if "우회" in f["name"]]
    assert fs and fs[0]["verdict"] == "성공"
    assert "x-original-url" in fs[0]["evidence"].lower()


def test_classify_no_bypass_header_is_not_authbypass():
    c = classify(payload="", url=_URL, headers={"host": "test.com", "accept": "*/*"}, category="")
    assert c.primary != "authbypass"


# ── 판정: 대조군 없음(단일 응답) → 의심 + 다음 단계 ────────────────────────────
def test_single_request_is_suspicious_with_next_action():
    r = analyze_response(200, {"content-type": "application/javascript"}, "x" * 300, 40,
                         payload="", category="", url="http://test.com/admin", req_headers=_HDRS)
    assert r["attack_outcome"] == "suspicious"
    assert r["attack_type"] == "authbypass"
    fs = _find(r)
    assert fs and fs[0]["verdict"] == "의심"
    assert "CVE-2025-29927" in fs[0]["name"]
    na = r.get("next_action") or {}
    assert na.get("confirm_scan") is True
    assert "정상 요청" in na.get("text", "")


# ── 판정: 대조군 차분(정상 거부 → 우회 제공) → 성공 확증 ───────────────────────
def test_baseline_redirect_login_attack_200_is_success():
    r = analyze_response(200, {}, "secret dashboard" * 20, 40,
                         payload="", category="", url="http://test.com/admin", req_headers=_HDRS,
                         baseline={"status_code": 302, "location": "/login", "body": ""})
    assert r["attack_outcome"] == "success"
    fs = _find(r)
    assert fs and fs[0]["verdict"] == "성공"
    assert fs[0]["confidence"] >= 80


def test_baseline_401_attack_200_is_success():
    r = analyze_response(200, {}, "admin panel" * 10, 40,
                         payload="", category="", url="http://test.com/admin", req_headers=_HDRS,
                         baseline={"status_code": 401, "body": "Unauthorized"})
    assert r["attack_outcome"] == "success"
    assert _find(r)[0]["verdict"] == "성공"


# ── 판정: 우회 요청도 거부 → 미우회(안전), 허위 의심 없음 ──────────────────────
def test_attack_still_403_is_safe_not_success():
    r = analyze_response(403, {}, "Forbidden", 40,
                         payload="", category="", url="http://test.com/admin", req_headers=_HDRS)
    fs = _find(r)
    assert fs and fs[0]["verdict"] == "안전"
    assert r["attack_outcome"] != "success"


def test_attack_redirects_to_login_is_safe():
    r = analyze_response(302, {"location": "/login"}, "", 40,
                         payload="", category="", url="http://test.com/admin", req_headers=_HDRS)
    fs = _find(r)
    assert fs and fs[0]["verdict"] == "안전"


# ── 대조군도 통과(정상도 200) → 우회 아님(보호 자체가 없음) → 성공 아님 ─────────
def test_baseline_also_200_is_not_success():
    r = analyze_response(200, {}, "public file" * 10, 40,
                         payload="", category="", url="http://test.com/public.js", req_headers=_HDRS,
                         baseline={"status_code": 200, "body": "public file"})
    fs = _find(r)
    # 정상도 200 이면 우회로 볼 수 없다 — 성공 격상 금지(의심까지만).
    assert not any(f["verdict"] == "성공" for f in fs)


# ── 우회 헤더가 없으면 이 탐지기는 전혀 발동하지 않음(오탐 방지) ───────────────
def test_no_finding_without_bypass_header():
    r = analyze_response(200, {}, "x" * 100, 40, payload="", category="",
                         url="http://test.com/admin", req_headers={"host": "test.com"})
    assert not _find(r)
