"""요청 자동 보정(ASP.NET VIEWSTATE 갱신 · Content-Type 추론) 헬퍼 단위 테스트 —
네트워크 없이 순수 함수만 검증."""
from routers.api import (_extract_hidden, _is_aspnet_form, _merge_tokens,
                         _infer_content_type, _ensure_content_type)


def test_infer_content_type():
    assert _infer_content_type("tbUsername=admin'--&tbPassword=") == "application/x-www-form-urlencoded"
    assert _infer_content_type('{"user":"admin"}') == "application/json"
    assert _infer_content_type('[1,2,3]') == "application/json"
    assert _infer_content_type('<xml/>') == "application/xml"
    assert _infer_content_type("") == ""
    assert _infer_content_type("   ") == ""


def test_ensure_content_type_adds_when_missing():
    """Content-Type 없는 POST 폼 body → 추론값 주입."""
    h = {"User-Agent": "x"}
    added = _ensure_content_type(h, "tbUsername=admin'--&tbPassword=", "POST")
    assert added == "application/x-www-form-urlencoded"
    assert h["Content-Type"] == "application/x-www-form-urlencoded"


def test_ensure_content_type_respects_existing():
    """이미 Content-Type 이 있으면(대소문자 무관) 건드리지 않는다."""
    h = {"content-type": "text/plain"}
    added = _ensure_content_type(h, "a=b", "POST")
    assert added == ""
    assert h["content-type"] == "text/plain"


def test_ensure_content_type_skips_get_and_empty_body():
    assert _ensure_content_type({}, "a=b", "GET") == ""
    assert _ensure_content_type({}, "", "POST") == ""


def test_extract_hidden_both_attr_orders():
    """name→value, value→name 두 속성 순서 모두에서 값 추출."""
    h1 = '<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="ABC123" />'
    h2 = '<input type="hidden" value="XYZ789" name="__EVENTVALIDATION" />'
    assert _extract_hidden(h1, "__VIEWSTATE") == "ABC123"
    assert _extract_hidden(h2, "__EVENTVALIDATION") == "XYZ789"
    assert _extract_hidden("<html>no tokens</html>", "__VIEWSTATE") is None


def test_is_aspnet_form_triggers():
    """.aspx POST(body 有) 또는 body 에 __VIEWSTATE 가 있으면 대상."""
    assert _is_aspnet_form("http://h/login.aspx", "tbUsername=a&tbPassword=b", "POST")
    assert _is_aspnet_form("http://h/x", "__VIEWSTATE=abc&u=1", "POST")       # 확장자 무관, 토큰 존재
    assert not _is_aspnet_form("http://h/login.aspx", "u=a", "GET")           # GET 은 제외
    assert not _is_aspnet_form("http://h/login.aspx", "", "POST")            # body 없음
    assert not _is_aspnet_form("http://h/api/login", "u=a&p=b", "POST")       # aspx 도 토큰도 아님


def test_merge_tokens_replaces_and_preserves():
    """기존 토큰은 최신값으로 치환, 없으면 추가, 나머지 필드는 보존."""
    body = "__VIEWSTATE=OLD&tbUsername=admin'--&tbPassword=&btnLogin=Login"
    out = _merge_tokens(body, {"__VIEWSTATE": "NEW/v+1", "__EVENTVALIDATION": "EV=2"})
    # 기존 __VIEWSTATE 치환(URL 인코딩)
    assert "__VIEWSTATE=NEW%2Fv%2B1" in out
    assert "__VIEWSTATE=OLD" not in out
    # 없던 __EVENTVALIDATION 추가
    assert "__EVENTVALIDATION=EV%3D2" in out
    # 사용자 필드 보존
    assert "tbUsername=admin'--" in out
    assert "btnLogin=Login" in out


def test_merge_tokens_skips_none():
    body = "u=1"
    out = _merge_tokens(body, {"__VIEWSTATE": None})
    assert out == "u=1"
