"""_blurred_request 회귀 — SingleRequest 는 header_names 가 아니라 headers dict 를 가진다."""
from routers.api import _blurred_request, SingleRequest


def test_blurred_request_from_headers_dict():
    req = SingleRequest(method="get", url="http://h/board?id=1", params={"id": "1"},
                        payload="1' OR 1=1", category="sqli",
                        headers={"User-Agent": "x", "Cookie": "secret", "Host": "h"})
    b = _blurred_request(req)                 # AttributeError 나면 실패
    assert b["method"] == "GET"
    assert b["path"] == "/board?id=1"
    assert b["payload"] == "1' OR 1=1"
    assert b["header_names"] == ["User-Agent"]   # host/cookie 제외
