"""#4 AI·RAG 를 응답 경로에서 분리 — /api/analyze/enrich.

회귀 방지:
    /api/request 가 대상 응답을 받은 뒤 ai_analyze → RAG 임베딩 검색 → ai_verdict 를
    **직렬로** 호출했다. NVIDIA API 왕복이 최대 3번 붙어, 이미 손에 들어온 응답 본문조차
    수 초 동안 화면에 못 띄웠다. 이제 /api/request 는 규칙 기반 판정만 즉시 돌려주고,
    보강은 이 엔드포인트가 (상세분석 ∥ RAG→종합판정) 병렬로 처리한다.

네트워크 호출은 전부 monkeypatch 로 대체 — 외부로 나가는 요청 없음.
"""
import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from main import app
from routers import api as api_mod

client = TestClient(app)


@pytest.fixture
def fake_ai(monkeypatch):
    """ai_analyze / RAG / ai_verdict 를 '느린 가짜'로 대체하고 호출을 기록."""
    calls = {"analyze": 0, "verdict": 0, "rag": 0}

    async def _analyze(payload):
        calls["analyze"] += 1
        await asyncio.sleep(0.30)
        return {"summary": "ai detail", "echo_status": payload.get("status_code")}

    async def _verdict(payload):
        calls["verdict"] += 1
        await asyncio.sleep(0.30)
        return {"outcome": payload.get("outcome"), "severity": "high",
                "confidence": 77, "model": "fake", "rag_used": len(payload.get("retrieved") or [])}

    def _search(q, k=4, category=""):
        calls["rag"] += 1
        time.sleep(0.30)                       # 임베딩 API 왕복 흉내(스레드로 실행됨)
        return [{"title": "OWASP", "loc": "p1", "score": 0.9, "text": "open redirect guidance"}]

    monkeypatch.setattr(api_mod, "ai_analyze", _analyze)
    monkeypatch.setattr(api_mod, "ai_verdict", _verdict)
    monkeypatch.setattr(api_mod, "response_analysis_enabled", lambda: True)
    monkeypatch.setattr(api_mod, "ai_verdict_enabled", lambda: True)
    monkeypatch.setattr(api_mod.rag, "has_sources", lambda: True)
    monkeypatch.setattr(api_mod.rag, "search", _search)
    return calls


_BODY = {
    "method": "GET", "url": "https://t.example.com/go?next=//evil.example.com",
    "headers": {}, "params": {}, "body": None,
    "payload": "//evil.example.com", "category": "redirect",
    "status_code": 302, "response_time": 12.0,
    "resp_headers": {"location": "https://evil.example.com"}, "resp_body": "",
    "analysis": {
        "verdict": "bypass", "attack_type": "redirect", "attack_outcome": "success",
        "findings": [{"name": "외부 리다이렉트", "verdict": "성공", "why": "외부로 이동", "evidence": "…"}],
        "alerts": [],
    },
}


def test_enrich_returns_ai_and_rag(fake_ai):
    r = client.post("/api/analyze/enrich", json=_BODY)
    assert r.status_code == 200
    d = r.json()
    assert d["ai"]["summary"] == "ai detail"
    assert d["ai_verdict"]["outcome"] == "success"
    assert d["ai_verdict"]["rag_used"] == 1
    assert d["related_docs"][0]["title"] == "OWASP"
    assert fake_ai == {"analyze": 1, "verdict": 1, "rag": 1}


def test_enrich_runs_detail_and_verdict_concurrently(fake_ai):
    """상세분석(0.3s)과 RAG→종합판정(0.6s)이 겹쳐 돌아야 한다 — 직렬이면 0.9s."""
    t0 = time.time()
    assert client.post("/api/analyze/enrich", json=_BODY).status_code == 200
    assert time.time() - t0 < 0.85


def test_enrich_passes_findings_through_without_recomputing(fake_ai, monkeypatch):
    """판정을 다시 계산하지 않는다 — 서버 규칙이 확정한 findings 를 그대로 근거로 쓴다."""
    seen = {}

    async def _verdict(payload):
        seen.update(payload)
        return {"outcome": payload.get("outcome")}

    monkeypatch.setattr(api_mod, "ai_verdict", _verdict)
    client.post("/api/analyze/enrich", json=_BODY)
    assert [f["name"] for f in seen["findings"]] == ["외부 리다이렉트"]
    assert seen["outcome"] == "success"


def test_enrich_blurs_request_before_sending_to_ai(fake_ai, monkeypatch):
    """외부로 나가는 질의엔 원 호스트가 아니라 블러 처리된 요청만 실린다."""
    seen = {}

    async def _verdict(payload):
        seen.update(payload)
        return {}

    monkeypatch.setattr(api_mod, "ai_verdict", _verdict)
    client.post("/api/analyze/enrich", json=_BODY)
    assert "t.example.com" not in str(seen["request"])


def test_enrich_without_ai_still_returns_rag(monkeypatch):
    monkeypatch.setattr(api_mod, "response_analysis_enabled", lambda: False)
    monkeypatch.setattr(api_mod, "ai_verdict_enabled", lambda: False)
    monkeypatch.setattr(api_mod.rag, "has_sources", lambda: True)
    monkeypatch.setattr(api_mod.rag, "search", lambda q, k=4, category="": [
        {"title": "NIST", "loc": "3.2", "score": 0.8, "text": "guidance"}])
    d = client.post("/api/analyze/enrich", json=_BODY).json()
    assert "ai" not in d and "ai_verdict" not in d
    assert d["related_docs"][0]["title"] == "NIST"


def test_enrich_with_nothing_enabled_is_empty(monkeypatch):
    monkeypatch.setattr(api_mod, "response_analysis_enabled", lambda: False)
    monkeypatch.setattr(api_mod, "ai_verdict_enabled", lambda: False)
    monkeypatch.setattr(api_mod.rag, "has_sources", lambda: False)
    assert client.post("/api/analyze/enrich", json=_BODY).json() == {}


def test_enrich_failure_is_reported_not_raised(monkeypatch):
    async def _boom(_):
        raise RuntimeError("nim down")

    monkeypatch.setattr(api_mod, "response_analysis_enabled", lambda: True)
    monkeypatch.setattr(api_mod, "ai_analyze", _boom)
    monkeypatch.setattr(api_mod, "ai_verdict_enabled", lambda: False)
    monkeypatch.setattr(api_mod.rag, "has_sources", lambda: False)
    r = client.post("/api/analyze/enrich", json=_BODY)
    assert r.status_code == 200
    assert "nim down" in r.json()["error"]


def test_enrich_accepts_minimal_payload():
    """UI 외 호출자를 위해 전 필드가 선택적이어야 한다."""
    assert client.post("/api/analyze/enrich", json={}).status_code == 200


def test_single_request_defaults_to_no_inline_ai():
    """/api/request 는 기본적으로 AI/RAG 를 기다리지 않는다."""
    from routers.api import SingleRequest
    assert SingleRequest(method="GET", url="https://t/").inline_ai is False
