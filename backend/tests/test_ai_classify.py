"""#1 AI 공격 분류(정규식 miss 보강) — core.ai_analyzer.ai_classify_attack + /api/analyze/enrich 편입.

설계:
    정규식(core.classify)이 유형을 못 정한 요청(attack_type 빈 값)일 때만 LLM 에 요청(호스트 제외)을
    보내 분류한다. 분류만 담당 — 판정(통했는가)은 여전히 증거 기반. AI 는 판정을 못 바꾼다.

모든 LLM 호출은 monkeypatch 로 대체 — 외부 네트워크 없음.
"""
import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from main import app
from routers import api as api_mod
from core import ai_analyzer

client = TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# ai_classify_attack — 어휘 정규화·안전 처리
# ─────────────────────────────────────────────────────────────────────────────
def _fake_llm(monkeypatch, content):
    class _Resp:
        status_code = 200
        def json(self):
            return {"choices": [{"message": {"content": content}}]}

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, *a, **k): return _Resp()

    monkeypatch.setattr(ai_analyzer.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(ai_analyzer, "_api_key", lambda: "test-key")


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_classify_returns_normalized(monkeypatch):
    _fake_llm(monkeypatch, '{"types":["log4shell","cmdi"],"primary":"log4shell",'
                           '"confidence":88,"header_borne":true,"reason":"UA에 jndi"}')
    r = _run(ai_analyzer.ai_classify_attack({"method": "GET", "path": "/x",
             "headers": {"user-agent": "${jndi:ldap://a}"}}))
    assert r["primary"] == "log4shell"
    assert r["types"] == ["log4shell", "cmdi"]
    assert r["header_borne"] is True
    assert r["source"] == "ai"


def test_classify_drops_unknown_labels(monkeypatch):
    _fake_llm(monkeypatch, '{"types":["sqli","totally-made-up","xss"],"primary":"made-up"}')
    r = _run(ai_analyzer.ai_classify_attack({"method": "GET", "path": "/x"}))
    assert r["types"] == ["sqli", "xss"]           # 어휘 밖 제거
    assert r["primary"] == "sqli"                  # 잘못된 primary → 첫 유효 유형


def test_classify_no_attack_is_empty(monkeypatch):
    _fake_llm(monkeypatch, '{"types":[],"primary":"","confidence":10,"header_borne":false}')
    r = _run(ai_analyzer.ai_classify_attack({"method": "GET", "path": "/normal"}))
    assert r["primary"] == "" and r["types"] == []


def test_classify_without_key_errors(monkeypatch):
    monkeypatch.setattr(ai_analyzer, "_api_key", lambda: "")
    r = _run(ai_analyzer.ai_classify_attack({"method": "GET", "path": "/x"}))
    assert "error" in r


def test_classify_bad_json_is_handled(monkeypatch):
    _fake_llm(monkeypatch, "이건 JSON 이 아님")
    r = _run(ai_analyzer.ai_classify_attack({"method": "GET", "path": "/x"}))
    # _extract_json 이 빈 dict → 정규화 결과 primary 빈 값(예외로 죽지 않음)
    assert r.get("error") or r.get("primary") == ""


# ─────────────────────────────────────────────────────────────────────────────
# /api/analyze/enrich 편입 — 하이브리드(정규식 miss 일 때만 AI 호출)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def stub_enrich(monkeypatch):
    """RAG·verdict·detail 은 무력화하고 분류 호출만 관찰."""
    calls = {"classify": 0}

    async def _classify(ctx):
        calls["classify"] += 1
        return {"primary": "nosql", "types": ["nosql"], "confidence": 80,
                "header_borne": False, "reason": "$ne 연산자", "model": "fake", "source": "ai"}

    monkeypatch.setattr(api_mod, "ai_classify_attack", _classify)
    monkeypatch.setattr(api_mod, "ai_enabled", lambda: True)
    monkeypatch.setattr(api_mod, "response_analysis_enabled", lambda: False)
    monkeypatch.setattr(api_mod, "ai_verdict_enabled", lambda: False)
    monkeypatch.setattr(api_mod.rag, "has_sources", lambda: False)
    return calls


def _body(attack_type):
    return {"method": "POST", "url": "https://t.example.com/api/login",
            "headers": {}, "params": {}, "body": '{"user":{"$ne":null}}',
            "payload": None, "category": None,
            "status_code": 200, "response_time": 10, "resp_headers": {}, "resp_body": "{}",
            "analysis": {"verdict": "passed", "attack_type": attack_type,
                         "attack_outcome": "inconclusive", "findings": [], "alerts": []}}


def test_enrich_calls_ai_when_type_missing(stub_enrich):
    r = client.post("/api/analyze/enrich", json=_body(""))       # 정규식 miss
    assert r.status_code == 200
    d = r.json()
    assert d["attack_class"]["primary"] == "nosql"
    assert d["attack_class"]["source"] == "ai"
    assert stub_enrich["classify"] == 1


def test_enrich_skips_ai_when_type_present(stub_enrich):
    r = client.post("/api/analyze/enrich", json=_body("sqli"))   # 이미 분류됨
    assert r.status_code == 200
    assert "attack_class" not in r.json()
    assert stub_enrich["classify"] == 0                          # AI 안 부름(하이브리드)


def test_enrich_skips_ai_when_disabled(monkeypatch):
    called = {"n": 0}
    async def _c(ctx):
        called["n"] += 1; return {"primary": "x"}
    monkeypatch.setattr(api_mod, "ai_classify_attack", _c)
    monkeypatch.setattr(api_mod, "ai_enabled", lambda: False)    # 키 없음
    monkeypatch.setattr(api_mod, "response_analysis_enabled", lambda: False)
    monkeypatch.setattr(api_mod, "ai_verdict_enabled", lambda: False)
    monkeypatch.setattr(api_mod.rag, "has_sources", lambda: False)
    r = client.post("/api/analyze/enrich", json=_body(""))
    assert "attack_class" not in r.json()
    assert called["n"] == 0


def test_enrich_ai_classify_does_not_change_verdict(stub_enrich):
    """AI 분류는 라벨만 — outcome/verdict 를 뒤집지 않는다(오탐 억제 원칙)."""
    d = client.post("/api/analyze/enrich", json=_body("")).json()
    # enrich 응답엔 attack_class 만 추가되고 판정 필드는 없음
    assert "attack_outcome" not in d and "verdict" not in d
    assert d["attack_class"]["primary"] == "nosql"


def test_enrich_ai_classify_empty_result_not_attached(monkeypatch):
    """AI 도 공격을 못 찾으면(빈 분류) attack_class 를 붙이지 않는다."""
    async def _c(ctx):
        return {"primary": "", "types": [], "source": "ai"}
    monkeypatch.setattr(api_mod, "ai_classify_attack", _c)
    monkeypatch.setattr(api_mod, "ai_enabled", lambda: True)
    monkeypatch.setattr(api_mod, "response_analysis_enabled", lambda: False)
    monkeypatch.setattr(api_mod, "ai_verdict_enabled", lambda: False)
    monkeypatch.setattr(api_mod.rag, "has_sources", lambda: False)
    d = client.post("/api/analyze/enrich", json=_body("")).json()
    assert "attack_class" not in d
