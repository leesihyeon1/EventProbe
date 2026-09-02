"""확증 스캔 엔드포인트의 로그인 감지(_looks_login) 단위 테스트 — 네트워크 없음.

확증 스캔은 로그인/인증 흐름처럼 보이는 요청이면 '인증 우회' 오라클을 자동 병행한다.
그 판단 로직만 검증한다(실제 프로브 전송은 인가된 대상에서 엔드포인트로).
"""
from types import SimpleNamespace as NS

from routers.api import _looks_login


def _req(url="", body="", params=None, param=""):
    return NS(url=url, body=body, params=params or {}, target=NS(param=param))


def test_login_paths_trigger():
    assert _looks_login(_req(url="https://x/login"))
    assert _looks_login(_req(url="https://x/api/signin"))
    assert _looks_login(_req(url="https://x/admin/"))
    assert _looks_login(_req(url="https://x/oauth/token"))


def test_credential_param_with_password_triggers():
    assert _looks_login(_req(url="https://x/do", body="username=a&password=b", param="username"))
    assert _looks_login(_req(url="https://x/do", body="pwd=x", param="user"))


def test_generic_requests_do_not_trigger():
    assert not _looks_login(_req(url="https://x/search?q=1", params={"q": "1"}, param="q"))
    # id 파라미터라도 비밀번호 맥락이 없으면 로그인으로 보지 않는다(오탐 방지)
    assert not _looks_login(_req(url="https://x/item?id=5", params={"id": "5"}, param="id"))
