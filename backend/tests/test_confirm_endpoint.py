"""확증 스캔 엔드포인트의 로그인 감지(_looks_login) 단위 테스트 — 네트워크 없음.

확증 스캔은 로그인/인증 흐름처럼 보이는 요청이면 '인증 우회' 오라클을 자동 병행한다.
그 판단 로직만 검증한다(실제 프로브 전송은 인가된 대상에서 엔드포인트로).
"""
import asyncio
from types import SimpleNamespace as NS

from routers import api
from routers.api import _looks_login, ConfirmRequest, ConfirmTarget


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


def test_confirm_endpoint_exposes_idor_observation_without_claiming_success(monkeypatch):
    async def fake_probes(req, headers, plan, follow):
        rows = [
            {"role": "baseline", "status": 200, "body": "public item A" * 20},
            {"role": "id_up", "status": 200, "body": "public item B" * 20},
            {"role": "nonexistent", "status": 404, "body": "not found"},
        ]
        return rows, [{"role": row["role"], "status": row["status"],
                       "label": row["role"], "value": "1"} for row in rows]

    async def no_file_probe(req, headers):
        return None

    monkeypatch.setattr(api, "_run_confirm_probes", fake_probes)
    monkeypatch.setattr(api, "_run_file_exposure_confirm", no_file_probe)
    req = ConfirmRequest(url="https://review.invalid/api/items?id=1", category="idor",
                         target=ConfirmTarget(location="param", param="id", base_value="1"))
    result = asyncio.run(api.confirm_scan_endpoint(req))
    assert result["supported"] is True
    assert result["confirmed"] is False
    assert result["techniques"] == []
    assert result["observations"][0]["level"] == "suspicious"


def test_confirm_endpoint_exposes_header_bypass_observation(monkeypatch):
    async def fake_header_probe(req, headers):
        return [], [{"role": "authbypass:normal", "status": 403,
                     "label": "헤더 제거", "value": req.url}], [
            {"name": "인가 우회 의심", "level": "suspicious",
             "evidence": "403→200; 보호 콘텐츠 미확인", "next_action": "보호 콘텐츠 확인"}]

    monkeypatch.setattr(api, "_run_authbypass_probe", fake_header_probe)
    req = ConfirmRequest(url="https://review.invalid/public.js", category="authbypass",
                         headers={"X-Middleware-Subrequest": "middleware"},
                         target=ConfirmTarget(location="header", param="X-Middleware-Subrequest"))
    result = asyncio.run(api.confirm_scan_endpoint(req))
    assert result["confirmed"] is False
    assert result["observations"][0]["name"] == "인가 우회 의심"


def test_confirm_endpoint_probe_timeout_is_not_clean_result(monkeypatch):
    async def fake_probes(req, headers, plan, follow):
        return [], [{"role": "baseline", "status": 0, "timeout": True,
                     "label": "대조군", "value": "1"}]

    monkeypatch.setattr(api, "_run_confirm_probes", fake_probes)
    req = ConfirmRequest(url="https://review.invalid/api/items?id=1", category="idor",
                         target=ConfirmTarget(location="param", param="id", base_value="1"))
    result = asyncio.run(api.confirm_scan_endpoint(req))
    assert result["confirmed"] is False
    assert any(o["level"] == "invalid" for o in result["observations"])
