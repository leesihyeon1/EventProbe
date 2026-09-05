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
