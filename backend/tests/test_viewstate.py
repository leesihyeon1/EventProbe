"""요청 자동 보정(ASP.NET VIEWSTATE 갱신 · Content-Type 추론) 헬퍼 단위 테스트 —
네트워크 없이 순수 함수만 검증."""
import asyncio

from routers.api import (_extract_hidden, _extract_meta, _is_aspnet_form, _is_stateful_form,
                         _merge_tokens, _infer_content_type, _ensure_content_type,
                         _has_csrf_header, _find_page_csrf_token, _refresh_form_tokens)


class _FakeCookies:
    def __init__(self, d): self._d = d
    def get(self, k): return self._d.get(k)


class _FakeClient:
    """네트워크 없는 httpx 대역 — 고정 HTML/쿠키를 반환."""
    def __init__(self, html, cookies=None):
        self.html = html
        self.cookies = _FakeCookies(cookies or {})

    async def get(self, url, headers=None, timeout=None):
        class R:  # noqa
            pass
        r = R(); r.text = self.html
        return r


def _run(coro):
    return asyncio.run(coro)


def test_extract_meta_csrf_token():
    """SPA/Rails 의 <meta name=csrf-token content=..> 추출(속성 순서·따옴표 무관)."""
    assert _extract_meta('<meta name="csrf-token" content="abc==">', "csrf-token") == "abc=="
    assert _extract_meta("<meta content='tok' name='xsrf-token'>", "xsrf-token") == "tok"
    assert _extract_meta("<div>none</div>", "csrf-token") is None


def test_has_csrf_header_detection():
    assert _has_csrf_header({"X-CSRF-Token": "x", "Content-Type": "json"})
    assert _has_csrf_header({"x-xsrf-token": "x"})
    assert not _has_csrf_header({"Authorization": "Bearer x"})


def test_find_page_csrf_token_prefers_meta():
    assert _find_page_csrf_token('<meta name="csrf-token" content="M">'
                                 '<input name="csrf_token" value="H">') == "M"
    assert _find_page_csrf_token('<input name="csrf_token" value="H">') == "H"


def test_refresh_header_csrf_from_meta():
    """SPA: 요청의 X-CSRF-Token 헤더가 폼 페이지 meta 토큰으로 갱신된다."""
    c = _FakeClient('<meta name="csrf-token" content="FRESH">')
    body, headers, note = _run(_refresh_form_tokens(
        c, "http://t/api", {"X-CSRF-Token": "OLD", "Content-Type": "application/json"}, ""))
    assert headers["X-CSRF-Token"] == "FRESH"
    assert "헤더 CSRF 토큰" in note


def test_refresh_header_csrf_from_double_submit_cookie():
    """meta 없으면 더블-서브밋 쿠키(XSRF-TOKEN)값을 X-XSRF-TOKEN 헤더로 되돌려보낸다."""
    c = _FakeClient("<html>no meta</html>", cookies={"XSRF-TOKEN": "CVAL"})
    _, headers, note = _run(_refresh_form_tokens(
        c, "http://t/api", {"X-XSRF-TOKEN": "OLD"}, ""))
    assert headers["X-XSRF-TOKEN"] == "CVAL"
    assert "헤더 CSRF 토큰" in note


def test_refresh_body_form_csrf_still_works():
    """기존 body 폼 CSRF 갱신 회귀 — 헤더 확장이 body 경로를 깨지 않는다."""
    c = _FakeClient('<input name="csrfmiddlewaretoken" value="NEW">')
    body, headers, note = _run(_refresh_form_tokens(
        c, "http://t/login", {}, "user=a&csrfmiddlewaretoken=OLD&pw=b"))
    assert "csrfmiddlewaretoken=NEW" in body
    assert "폼 CSRF 토큰" in note


def test_is_stateful_form_covers_csrf_tokens():
    """VIEWSTATE(.aspx) 외에 Rails/Django/일반 CSRF 토큰 폼도 갱신 대상."""
    assert _is_stateful_form("http://h/login.aspx", "u=a&p=b", "POST")          # aspnet
    assert _is_stateful_form("http://h/users", "authenticity_token=x&u=a", "POST")   # Rails
    assert _is_stateful_form("http://h/accounts/login/", "csrfmiddlewaretoken=x&u=a", "POST")  # Django
    assert _is_stateful_form("http://h/x", "_csrf=x&a=1", "POST")               # 일반
    assert not _is_stateful_form("http://h/api", '{"u":"a"}', "POST")           # 토큰 없음
    assert not _is_stateful_form("http://h/x", "authenticity_token=x", "GET")   # GET 제외


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
