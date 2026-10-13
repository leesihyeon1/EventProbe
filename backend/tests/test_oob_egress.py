"""strict 반출 모드에서 OOB(콜백) 경계 — 공개 수집기로의 발급 차단 (리뷰 F5).

AI 외 네트워크 반출 경로도 strict 에서 통제한다. 공개(제3자) interactsh(oast.fun 등)로는
콜백을 발급하지 않고 해당 블라인드 검사를 미검증 처리한다. 사내 self-host 는 허용한다.
네트워크 호출은 하지 않는다 — mint 는 발급 이전 단계에서 None 을 반환한다.
"""
import asyncio

import pytest

from core import oob


def _public(mp):
    mp.setenv("OOB_ENABLED", "true")
    mp.setenv("OOB_SERVER", "https://oast.fun")


def _selfhost(mp):
    mp.setenv("OOB_ENABLED", "true")
    mp.setenv("OOB_SERVER", "https://oob.mycorp.example")


def test_permissive_public_allows(monkeypatch):
    _public(monkeypatch)
    monkeypatch.setenv("AI_EXPORT_MODE", "permissive")
    assert oob.minting_allowed() is True
    assert oob.minting_block_reason() == ""


def test_strict_public_blocks(monkeypatch):
    _public(monkeypatch)
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    assert oob.is_public_server() is True
    assert oob.minting_allowed() is False
    assert "엄격" in oob.minting_block_reason()


def test_strict_selfhost_allows(monkeypatch):
    _selfhost(monkeypatch)
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    assert oob.is_public_server() is False
    assert oob.minting_allowed() is True


def test_mint_returns_none_in_strict_public_without_network(monkeypatch):
    _public(monkeypatch)
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    # minting_allowed False → 등록/네트워크 이전에 None 반환
    assert asyncio.run(oob.mint({"url": "http://corp-internal.lan/x"})) is None


def test_policy_endpoint_reports_oob(monkeypatch):
    from fastapi.testclient import TestClient
    from main import app
    _public(monkeypatch)
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    body = TestClient(app).get("/api/egress/policy").json()
    assert body["oob"]["enabled"] is True
    assert body["oob"]["public_server"] is True
    assert body["oob"]["minting_allowed"] is False
