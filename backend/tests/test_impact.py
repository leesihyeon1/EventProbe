from copy import deepcopy

import pytest

from core.analyzer import analyze_response
from core.impact import describe_impact


@pytest.mark.parametrize("outcome", ["success", "safe", "blocked", "suspicious", "inconclusive"])
def test_impact_never_mutates_verdict(outcome):
    analysis = {"attack_outcome": outcome, "risk_level": "high", "score": 85,
                "confidence": 70, "attack_type": "cmdi", "findings": []}
    before = deepcopy(analysis)
    impact = describe_impact(analysis)
    assert analysis == before
    assert "파일 접근" not in impact["confirmed"]


def test_error_leak_does_not_claim_database_access():
    impact = describe_impact({"attack_outcome": "success", "attack_type": "sqli",
                              "error_leaks": ["SQL syntax error"]})
    assert impact["confirmed"] == "오류 정보가 응답에 노출됨"
    assert "확증" in impact["potential"]


def test_incomplete_inspection_reports_limits():
    impact = describe_impact({"attack_outcome": "safe", "body_truncated": True,
                              "validity": {"warnings": [{"code": "test"}]}})
    assert "미검출" in impact["confirmed"]
    assert "일부만" in impact["limitations"]
    assert "유효성" in impact["limitations"]


def test_analysis_adds_impact_without_changing_existing_result(monkeypatch):
    import core.impact as module
    args = (200, {"content-type": "text/html"}, "ordinary response", 100)
    actual = analyze_response(*args, payload="1 OR 1=1", category="sqli")
    monkeypatch.setattr(module, "describe_impact", lambda _: {})
    reference = analyze_response(*args, payload="1 OR 1=1", category="sqli")
    assert actual.pop("impact")["confirmed"]
    reference.pop("impact")
    assert actual == reference
