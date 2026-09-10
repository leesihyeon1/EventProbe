"""#5 헤더 증거 원문 보존 / #6 커스텀 Alert 룰 서버 평가.

#5 회귀 방지:
    analyze_response 가 헤더 '값'까지 소문자로 만들어 두고 그걸 그대로 증거로 썼다.
    Location URL·토큰·Set-Cookie 처럼 대소문자가 의미를 갖는 값은 화면에 소문자로 찍혀,
    사용자가 응답에서 그대로 검색해도 찾지 못했다. 매칭은 소문자, 표시는 원문으로 분리.

#6 회귀 방지:
    커스텀 룰이 브라우저 localStorage 에만 있고 JS 로만 실행돼, 단일 전송 화면에서만
    동작하고 일괄 테스트·리포트에는 전혀 반영되지 않았다. 이제 서버가 평가한다.
"""
import pytest

from core.analyzer import (HeaderView, analyze_response, detect_stack,
                           run_custom_alert_rules)

_MIXED_LOC = "https://Target.Example.com/Auth/CallBack?State=AbC123XyZ&Token=Zm9vQmFy"


# ─────────────────────────────────────────────────────────────────────────────
# #5 HeaderView — 매칭은 소문자, 표시는 원본
# ─────────────────────────────────────────────────────────────────────────────
def test_headerview_matches_lowercase_but_keeps_raw():
    h = HeaderView({"Location": _MIXED_LOC, "Server": "Apache/2.4"})
    assert h["location"] == _MIXED_LOC.lower()      # 기존 매칭 동작 그대로
    assert h.get("server") == "apache/2.4"
    assert h.raw("Location") == _MIXED_LOC          # 표시용은 원문
    assert h.raw("LOCATION") == _MIXED_LOC          # 키는 대소문자 무관
    assert dict(h.raw_items())["server"] == "Apache/2.4"
    assert h.raw("missing", "-") == "-"


def test_headerview_is_a_plain_dict_for_existing_callers():
    h = HeaderView({"Content-Type": "TEXT/HTML"})
    assert isinstance(h, dict)
    assert list(h.keys()) == ["content-type"]
    assert "html" in h.get("content-type", "")


def test_redirect_evidence_preserves_original_case():
    """핵심 회귀: Location 증거가 원문 그대로여야 응답에서 검색이 된다."""
    r = analyze_response(302, {"Location": _MIXED_LOC}, "", 50,
                         payload="//target.example.com", category="redirect",
                         url="https://other.example.net/go?next=//target.example.com")
    hit = [f for f in r["findings"] if "외부 리다이렉트" in f["name"]]
    assert hit
    assert _MIXED_LOC in hit[0]["evidence"]
    assert "abc123xyz" not in hit[0]["evidence"]     # 소문자로 뭉개지지 않았다


def test_uppercase_scheme_location_still_detected():
    """원문을 쓰면 'HTTPS://' 같은 표기도 들어온다 — 스킴 판정은 대소문자 무시."""
    r = analyze_response(302, {"Location": "HTTPS://Evil.Example.COM/x"}, "", 50,
                         payload="//evil.example.com", category="redirect",
                         url="https://t.example.com/go?next=//evil.example.com")
    assert any("외부 리다이렉트" in f["name"] for f in r["findings"])


def test_tech_stack_evidence_preserves_original_case():
    r = analyze_response(200, {"Server": "Apache/2.4.41 (Ubuntu)"}, "<html>x</html>", 50)
    ev = " ".join(t["evidence"] for t in r["tech_stack"])
    assert "Apache/2.4.41 (Ubuntu)" in ev


def test_detect_stack_accepts_plain_dict_still():
    """외부에서 평범한 dict 로 불러도 죽지 않는다(폴백 경로)."""
    out = detect_stack({"server": "nginx/1.18.0"})
    assert out and "nginx" in out[0]["evidence"]


def test_alert_evidence_header_value_is_original():
    r = analyze_response(200, {"Server": "Apache/2.4.41 (Ubuntu)",
                               "X-Powered-By": "PHP/8.1.2-MyBuild"},
                         "<html>x</html>", 50)
    ev = " ".join(a.get("evidence") or "" for a in r["alerts"])
    assert "PHP/8.1.2-MyBuild" in ev or "Apache/2.4.41 (Ubuntu)" in ev


# ─────────────────────────────────────────────────────────────────────────────
# #6 커스텀 Alert 룰 — 서버 평가
# ─────────────────────────────────────────────────────────────────────────────
def _rule(**kw):
    base = {"id": "r1", "name": "내 룰", "risk": "high", "confidence": 80,
            "description": "설명", "solution": "조치", "enabled": True}
    base.update(kw)
    return base


_H = HeaderView({"Server": "MyApp/1.0", "X-Debug-Token": "AbC123"})


def _run(rules, body="hello WORLD body", status=200):
    return run_custom_alert_rules(rules, _H, body, body.lower(), status)


@pytest.mark.parametrize("target,method,value,expect", [
    ("header_key", "contains", "debug", True),
    ("header_key", "contains", "nope", False),
    ("header_key", "equals", "server", True),
    ("header_key", "equals", "serv", False),
    ("header_key", "regex", "^x-.*token$", True),
    ("header_key", "not_contains", "debug", False),
    ("header_key", "not_contains", "absent", True),
    ("header_value", "contains", "myapp", True),
    ("header_value", "equals", "myapp/1.0", True),
    ("header_value", "regex", r"abc\d+", True),
    ("header_value", "not_contains", "myapp", False),
    ("body", "contains", "world", True),
    ("body", "contains", "absent", False),
    ("body", "regex", r"hello\s+WORLD", True),
    ("body", "not_contains", "absent", True),
    ("status", "equals", "200", True),
    ("status", "equals", "404", False),
    ("status", "contains", "20", True),
    ("status", "regex", r"^2\d\d$", True),
    ("status", "not_contains", "40", True),
])
def test_custom_rule_matching(target, method, value, expect):
    out = _run([_rule(target=target, method=method, value=value)])
    assert bool(out) is expect


def test_custom_rule_body_equals_is_case_sensitive():
    """프론트 엔진과 동일하게 body equals 는 원문 비교."""
    assert _run([_rule(target="body", method="equals", value="hello WORLD body")])
    assert not _run([_rule(target="body", method="equals", value="hello world body")])


def test_custom_rule_evidence_is_original_case():
    out = _run([_rule(target="body", method="contains", value="world")])
    assert out[0]["evidence"] == "WORLD"           # 원문 슬라이스
    out = _run([_rule(target="header_value", method="contains", value="abc123")])
    assert "AbC123" in out[0]["evidence"]


def test_custom_rule_disabled_is_skipped():
    assert _run([_rule(target="status", method="equals", value="200", enabled=False)]) == []


def test_custom_rule_broken_regex_is_skipped_not_raised():
    assert _run([_rule(target="body", method="regex", value="(?<bad")]) == []


def test_custom_rule_garbage_input_is_ignored():
    assert run_custom_alert_rules([None, "str", 42, {}], _H, "b", "b", 200) == []
    assert run_custom_alert_rules(None, _H, "b", "b", 200) == []


def test_custom_rule_unknown_risk_falls_back():
    out = _run([_rule(target="status", method="equals", value="200", risk="URGENT")])
    assert out[0]["risk"] == "informational"


def test_custom_rule_marked_custom():
    out = _run([_rule(target="status", method="equals", value="200")])
    assert out[0]["_custom"] is True and out[0]["name"] == "내 룰"


# ── analyze_response 통합 — 내장 룰과 함께 위험도순으로 병합 ──────────────────
def test_custom_rules_merge_into_alerts_sorted():
    rules = [_rule(id="c-hi", name="치명", risk="high", target="body",
                   method="contains", value="secret"),
             _rule(id="c-lo", name="참고", risk="informational", target="status",
                   method="equals", value="200")]
    r = analyze_response(200, {"Content-Type": "text/html"}, "top secret here", 50,
                         custom_alert_rules=rules)
    names = [a["name"] for a in r["alerts"]]
    assert "치명" in names and "참고" in names
    risks = [a["risk"] for a in r["alerts"]]
    order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    assert risks == sorted(risks, key=lambda x: order.get(x, 9))
    assert names.index("치명") < names.index("참고")


def test_no_custom_rules_leaves_builtin_alerts_untouched():
    a = analyze_response(200, {"Content-Type": "text/html"}, "<html>x</html>", 50)
    b = analyze_response(200, {"Content-Type": "text/html"}, "<html>x</html>", 50,
                         custom_alert_rules=[])
    assert [x["id"] for x in a["alerts"]] == [x["id"] for x in b["alerts"]]
    assert not any(x.get("_custom") for x in b["alerts"])


def test_all_request_models_accept_custom_rules():
    """단일·일괄·멀티타깃이 같은 룰셋을 받을 수 있어야 한다(#6 의 핵심)."""
    from routers.api import BulkRequest, MultiTargetRequest, SingleRequest
    assert SingleRequest(method="GET", url="u").custom_alert_rules == []
    assert BulkRequest(method="GET", url="u", target_param="q",
                       payload_ids=[], category="sqli").custom_alert_rules == []
    assert MultiTargetRequest(method="GET", urls=["u"], target_param="q").custom_alert_rules == []
