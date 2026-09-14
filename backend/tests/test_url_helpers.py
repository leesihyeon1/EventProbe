"""_url_with_params 인코딩 단위 테스트 — # (프래그먼트)·공백이 서버로 그대로 전송되도록."""
from routers.api import _url_with_params

_OGNL = "/${(#a=@java.lang.Runtime@getRuntime().exec('id'))}"


def test_fragment_hash_encoded_in_path():
    """OGNL/Struts payload 의 '#' 가 프래그먼트로 잘리지 않도록 %23 으로 인코딩."""
    u = _url_with_params("https://h" + _OGNL, {})
    assert "#" not in u          # bare '#' 없음(잘림 방지)
    assert "%23" in u


def test_space_encoded_in_url():
    u = _url_with_params("https://h/a b c", {})
    assert " " not in u
    assert "%20" in u


def test_hash_in_param_value_encoded():
    u = _url_with_params("https://h/x", {"q": _OGNL})
    assert "#" not in u
    assert "%23" in u


def test_no_double_encoding():
    """이미 %23 인 것은 다시 인코딩하지 않는다(%2523 방지)."""
    u = _url_with_params("https://h/x%23y", {})
    assert "%2523" not in u
    assert "%23" in u


def test_erb_ssti_percent_encoded_valid():
    """ERB SSTI(<%= %>)의 리터럴 '%' 가 잘못된 퍼센트 인코딩으로 나가 서버 500 을 유발하던
    문제 — %=, %> 를 %25 로 교정하고 <>\" 를 인코딩해 유효한 URI 로 전송한다."""
    import re
    u = _url_with_params('https://h/?message=<%= system("id") %>', {})
    # 잘못된 퍼센트 시퀀스(%가 %XX 아님)가 남아있지 않아야 함
    assert not re.search(r"%(?![0-9A-Fa-f]{2})", u)
    assert "<" not in u and ">" not in u and '"' not in u
    assert "%3C%25" in u          # <%  → %3C%25


def test_already_encoded_not_double_encoded():
    """이미 %XX 로 인코딩된 payload 는 이중 인코딩하지 않는다."""
    u = _url_with_params("https://h/?p=%2e%2e%2f%2e%2e%2f", {})
    assert "%252e" not in u        # %2e 가 %252e 로 이중인코딩되면 안 됨
    assert "%2e%2e%2f" in u


def test_ssti_braces_encoded():
    """SSTI {{7*7}} 의 { } 는 URI 불법문자라 인코딩(서버가 디코드해 원문 수신)."""
    u = _url_with_params("https://h/?q={{7*7}}", {})
    assert "{" not in u and "}" not in u
    assert "%7B%7B" in u
