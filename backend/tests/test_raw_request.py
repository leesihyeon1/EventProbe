"""raw HTTP 패킷 전송 엔드포인트 — SOAR incident 연동(버튼→raw 출력→수정→검증).

SOAR 는 raw 패킷 문자열만 POST /api/request/raw 로 보내면, 서버가 파싱해 기존 전송·판정
흐름(SingleRequest)을 그대로 재사용한다. 네트워크 전송(send_request)은 monkeypatch 로 대체 —
외부로 나가는 요청 없이 '파싱→SingleRequest 변환→디스패치'만 검증한다.
"""
import pytest
from fastapi.testclient import TestClient

from main import app
from routers import api as api_mod
from core.raw_http import parse_raw_request

client = TestClient(app)

_RAW = (
    "GET /123/v1/js/common/vendor.js HTTP/1.1\r\n"
    "Host: TEST.COM\r\n"
    "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware\r\n"
    "Accept: */*\r\n"
    "\r\n"
)


# ── 파서 단위 테스트 ──────────────────────────────────────────────────────────
def test_parse_basic_get():
    p = parse_raw_request(_RAW)
    assert p["method"] == "GET"
    assert p["url"] == "https://TEST.COM/123/v1/js/common/vendor.js"
    assert p["http_version"] == "HTTP/1.1"
    assert p["headers"]["X-Middleware-Subrequest"].startswith("middleware:middleware")
    assert p["body"] == ""


def test_parse_scheme_override():
    p = parse_raw_request("GET /x HTTP/1.1\r\nHost: h\r\n\r\n", scheme="http")
    assert p["url"] == "http://h/x"


def test_parse_absolute_url_in_request_line():
    p = parse_raw_request("GET https://a.com/p?q=1 HTTP/1.1\r\nHost: ignored\r\n\r\n")
    assert p["url"] == "https://a.com/p?q=1"


def test_parse_host_override():
    p = parse_raw_request("GET /p HTTP/1.1\r\n\r\n", host_override="target.local")
    assert p["url"] == "https://target.local/p"


def test_parse_post_with_json_body_not_parsed_as_headers():
    raw = ('POST /api/login HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n'
           '{"user":"a","pw":"b"}')
    p = parse_raw_request(raw)
    assert p["method"] == "POST"
    assert p["body"] == '{"user":"a","pw":"b"}'
    assert "user" not in p["headers"]           # 본문이 헤더로 잘못 파싱되지 않음
    assert p["headers"]["Content-Type"] == "application/json"


def test_parse_uri_with_unencoded_spaces():
    # SQLi 페이로드처럼 URI 에 공백이 있어도 메서드/버전만 떼고 나머지 전체가 URI.
    p = parse_raw_request("GET /s?q=1 OR 1=1 -- - HTTP/1.1\r\nHost: h\r\n\r\n")
    assert p["method"] == "GET"
    assert p["url"] == "https://h/s?q=1 OR 1=1 -- -"


def test_parse_no_http_version():
    p = parse_raw_request("GET /p\r\nHost: h\r\n\r\n")
    assert p["http_version"] == ""
    assert p["url"] == "https://h/p"


def test_parse_single_line_flattened_packet_reflow():
    # SOAR/티켓이 줄바꿈을 다 지워 한 줄로 온 패킷도 헤더 경계로 복원해 파싱.
    oneline = ("GET /static/x.svg Accept-Language: en-US,en;q=0.5 Host: m.ncsoft.com "
               "Referer: https://google.com User-Agent: Mozilla/5.0 (X11; Linux) Chrome/77.0 "
               "X-Forwarded-For: 1.2.3.4 Cache-Control: max-age=0")
    p = parse_raw_request(oneline, scheme="https")
    assert p["method"] == "GET"
    assert p["url"] == "https://m.ncsoft.com/static/x.svg"
    assert p["host"] == "m.ncsoft.com"
    assert p["headers"]["User-Agent"] == "Mozilla/5.0 (X11; Linux) Chrome/77.0"   # 값 내 공백 보존
    assert p["headers"]["Referer"] == "https://google.com"                        # URL 스킴 콜론 미분할
    assert len(p["headers"]) == 6


def test_multiline_packet_not_reflowed():
    # 정상 멀티라인은 reflow 미적용 — 헤더 값 안의 'Word: ' 가 잘못 분할되지 않아야.
    raw = "GET /p HTTP/1.1\r\nHost: h\r\nX-Note: see also: nothing\r\n\r\n"
    p = parse_raw_request(raw)
    assert p["headers"]["X-Note"] == "see also: nothing"


def test_parse_collapsed_blank_line_body():
    # 붙여넣기에서 헤더/본문 사이 빈 줄이 사라져도 '헤더 형식 아닌 첫 줄'에서 본문 시작.
    raw = "POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\nhello world body"
    p = parse_raw_request(raw)
    assert p["body"] == "hello world body"


# ── 엔드포인트 테스트(전송은 monkeypatch) ────────────────────────────────────
@pytest.fixture
def capture_send(monkeypatch):
    """send_request 를 가짜로 대체해 넘어온 SingleRequest 를 포착(네트워크 없음)."""
    seen = {}

    async def _fake(single):
        seen["req"] = single
        return {"status_code": 200, "analysis": {"attack_outcome": "suspicious"}}

    monkeypatch.setattr(api_mod, "send_request", _fake)
    return seen


def test_endpoint_parses_and_dispatches(capture_send):
    r = client.post("/api/request/raw", json={"raw": _RAW, "category": "cve"})
    assert r.status_code == 200
    data = r.json()
    assert data["parsed_request"]["url"] == "https://TEST.COM/123/v1/js/common/vendor.js"
    assert data["parsed_request"]["method"] == "GET"
    single = capture_send["req"]
    assert single.url == "https://TEST.COM/123/v1/js/common/vendor.js"
    assert single.category == "cve"
    assert single.use_defaults is False        # raw 충실도: 기본 헤더 미주입
    # 파싱된 요청 헤더가 그대로 실려 미들웨어 우회 헤더가 판정으로 전달됨
    assert any(k.lower() == "x-middleware-subrequest" for k in single.headers)


def test_endpoint_empty_raw_is_error(capture_send):
    r = client.post("/api/request/raw", json={"raw": "   "})
    assert r.status_code == 200
    assert "비어" in r.json().get("error", "")
    assert "req" not in capture_send            # 전송까지 가지 않음


def test_endpoint_no_host_no_absolute_url_is_error(capture_send):
    r = client.post("/api/request/raw", json={"raw": "GET /p HTTP/1.1\r\nAccept: */*\r\n\r\n"})
    assert r.status_code == 200
    assert "URL" in r.json().get("error", "")
    assert "req" not in capture_send


def test_endpoint_host_field_override(capture_send):
    r = client.post("/api/request/raw",
                    json={"raw": "GET /p HTTP/1.1\r\nAccept: */*\r\n\r\n", "host": "t.local"})
    assert r.status_code == 200
    assert capture_send["req"].url == "https://t.local/p"
