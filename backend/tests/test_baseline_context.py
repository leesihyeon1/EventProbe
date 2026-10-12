from core.baseline_context import validate
from core.analyzer import analyze_response


def _base(url="https://test.invalid/private?id=1", headers=None, body=""):
    return {"status_code": 403, "body": "Denied", "protected_marker": "private-record-72391",
            "request": {"method": "GET", "url": url, "headers": headers or {}, "body": body}}


def test_one_changed_parameter_is_comparable():
    check = validate(_base(), method="GET", url="https://test.invalid/private?id=2")
    assert check["valid"] and check["changes"] == ["query:id"]


def test_changed_target_session_or_multiple_variables_is_invalid():
    assert validate(_base(), method="GET", url="https://other.invalid/private?id=2")["code"] == "target_changed"
    assert validate(_base(headers={"Cookie": "sid=a"}), method="GET",
                    url="https://test.invalid/private?id=2", headers={"Cookie": "sid=b"})["code"] == "auth_changed"
    assert validate(_base(), method="GET", url="https://test.invalid/private?id=2&mode=debug")["code"] == "multiple_changes"


def test_attack_payload_cannot_be_its_own_control():
    baseline = _base()
    baseline["request"]["payload"] = "attack"
    assert validate(baseline, method="GET", url="https://test.invalid/private?id=2")["code"] == "tainted_control"


def test_unverified_or_mismatched_baseline_cannot_confirm_bypass():
    for baseline in (_base(url="https://other.invalid/private?id=1"),
                     {"status_code": 403, "body": "Denied", "protected_marker": "private-record-72391"}):
        result = analyze_response(200, {}, "private-record-72391", 50,
                                  category="authbypass", method="GET",
                                  url="https://test.invalid/private?id=2", baseline=baseline)
        assert result["attack_outcome"] != "success"
        assert result["baseline_check"]["valid"] is False
        assert any(w["code"] == "baseline_invalid" for w in result["validity"]["warnings"])
