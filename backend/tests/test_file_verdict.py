import pytest

from core.analyzer import analyze_response


@pytest.mark.parametrize("status", [200, 403, 503])
def test_single_slow_response_never_confirms_injection(status):
    result = analyze_response(status, {}, "Service unavailable", 5000,
                              payload="SLEEP(5)", category="sqli",
                              url="https://example.test/?q=SLEEP(5)")
    assert result["attack_outcome"] != "success"
    assert not any(f["verdict"] == "성공" for f in result["findings"])


@pytest.mark.parametrize("status", [200, 403, 404])
def test_direct_git_missing_is_scoped_to_response(status):
    result = analyze_response(status, {}, "Not Found", 100,
                              url="https://example.test/.git/config", method="GET")
    assert result["attack_type"] == "file"
    finding = next(f for f in result["findings"] if "민감 파일 미노출" in f["name"])
    assert f"HTTP {status}" in finding["why"]
    assert "200 응답은" not in finding["why"]
    assert "파일 존재 여부" in finding["why"]
    assert "서비스 계정" not in result["impact"]["potential"]


@pytest.mark.parametrize("url", [
    "https://example.test/read?file=../../.git/config",
    "https://example.test/../../.git/config",
    "https://example.test/%2e%2e/.git/config",
])
def test_traversal_keeps_lfi_classification(url):
    result = analyze_response(404, {}, "Not Found", 100, url=url)
    assert result["attack_type"] == "lfi"


def test_actual_git_content_still_detected():
    result = analyze_response(200, {}, '[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = example',
                              100, url="https://example.test/.git/config")
    assert result["attack_type"] == "file"
    assert result["attack_outcome"] == "success"


def test_header_attack_not_hidden_by_git_path():
    result = analyze_response(404, {}, "Not Found", 100,
                              url="https://example.test/.git/config",
                              req_headers={"User-Agent": "${jndi:ldap://example.test/a}"})
    assert result["attack_type"] == "cmdi"
