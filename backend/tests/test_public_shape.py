"""비식별 요청 구조(PublicRequestShape) + strict 모드 적용 검증 (리뷰 F2).

핵심: 외부 AI 로 나가는 분류/후보 생성 프롬프트에 실제 값(도메인·업무 값·헤더 값)이
포함되지 않고, 구조(필드 이름+타입)와 공격 신호 토큰만 담기는지 확인한다.
알 수 없는 형식은 전송을 거부한다.
"""
import asyncio
import json

import pytest

from core import public_shape as ps
from core import ai_analyzer as ai


# ── 구조 변환 단위 ──────────────────────────────────────────────────────────────
def test_path_template_replaces_dynamic_segments():
    assert ps.build(url="/api/orders/12345").path_template == "/api/orders/{id}"
    assert ps.build(url="/users/550e8400-e29b-41d4-a716-446655440000/edit").path_template == "/users/{id}/edit"
    assert ps.build(url="/v2/items/abcdef0123456789").path_template == "/v2/items/{id}"
    # 정적 경로/파일명/버전은 유지
    assert ps.build(url="/v2/static/app.js").path_template == "/v2/static/app.js"


def test_query_keeps_names_and_types_not_values():
    shape = ps.build(url="/s", params={"id": "42", "redirect": "https://victim.corp/x", "q": "hello"})
    types = shape.query_types()
    assert types == {"id": "int", "redirect": "url", "q": "string"}
    dumped = json.dumps(shape.to_dict(), ensure_ascii=False)
    assert "victim.corp" not in dumped and "hello" not in dumped   # 값 미포함


def test_body_json_structure_only():
    shape = ps.build(method="POST", url="/o", body=json.dumps({"amount": 100, "note": "secret-memo"}))
    assert shape.body_kind == "json"
    assert {f.name: f.type for f in shape.body_fields} == {"amount": "int", "note": "string"}
    assert "secret-memo" not in json.dumps(shape.to_dict(), ensure_ascii=False)


def test_body_form_and_xml():
    assert ps.build(body="a=1&b=x").body_kind == "form"
    assert ps.build(body="<root><item>v</item></root>").body_kind == "xml"


def test_unknown_body_not_shapeable():
    shape = ps.build(body="this is just free prose with no structure")
    assert shape.body_kind == "unknown" and shape.shapeable is False


def test_empty_body_shapeable():
    shape = ps.build(url="/x")
    assert shape.body_kind == "none" and shape.shapeable is True


def test_attack_tokens_extracted_but_business_values_not():
    shape = ps.build(url="/s", params={"q": "' UNION SELECT 1,2--", "name": "Alice Kim"})
    assert any("UNION SELECT" in t for t in shape.attack_tokens)   # 공격 신호는 유지
    assert all("Alice Kim" not in t for t in shape.attack_tokens)  # 업무 값은 토큰 아님


def test_header_allowlist_and_content_type_normalization():
    shape = ps.build(headers={"Cookie": "sess=x", "Authorization": "Bearer y",
                              "Accept": "*/*", "X-Internal-Secret": "z",
                              "Content-Type": "application/json; charset=utf-8"})
    assert "accept" in shape.header_names
    assert "cookie" not in shape.header_names and "authorization" not in shape.header_names
    assert "x-internal-secret" not in shape.header_names
    assert shape.content_type == "application/json"


# ── strict 적용: suggest / classify 프롬프트에 값이 새지 않는다 ──────────────────
def _fake_post(captured, content):
    async def fake(base, headers, payload, tries=3):
        captured["payload"] = payload
        captured["base"] = base

        class R:
            status_code = 200

            def json(self):
                return {"choices": [{"message": {"content": content}}]}
        return R()
    return fake


def test_suggest_strict_sends_structure_not_values(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    monkeypatch.setenv("NVIDIA_API_KEY", "fake")
    captured = {}
    content = json.dumps({"test_type": "sqli", "summary": "s",
                          "candidates": [{"payload": "' OR 1=1", "category": "sqli",
                                          "param": "q", "location": "param"}]})
    monkeypatch.setattr(ai, "_post_chat", _fake_post(captured, content))

    res = asyncio.run(ai.ai_suggest_payloads(
        "GET", "/api/orders/98765",
        {"redirect": "https://victim.corp/home", "q": "normalvalue"},
        body="", header_names=["Cookie", "Accept", "X-Internal-Token"]))
    assert "error" not in res
    sent = json.dumps(captured["payload"], ensure_ascii=False)
    assert "victim.corp" not in sent and "normalvalue" not in sent   # 값 미반출
    assert "/api/orders/{id}" in sent                                # 경로 템플릿
    assert "98765" not in sent                                       # 동적 ID 제거
    assert "x-internal-token" not in sent.lower()                    # 비허용 헤더 제외


def test_suggest_strict_refuses_unshapeable_body(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    monkeypatch.setenv("NVIDIA_API_KEY", "fake")
    called = {"n": 0}

    async def fake(*a, **k):
        called["n"] += 1
    monkeypatch.setattr(ai, "_post_chat", fake)

    res = asyncio.run(ai.ai_suggest_payloads("POST", "/x", {}, body="free prose no structure", header_names=[]))
    assert "엄격 반출 모드" in res["error"]
    assert called["n"] == 0            # 전송 자체를 하지 않음


def test_classify_strict_keeps_attack_signal_drops_secrets(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    monkeypatch.setenv("NVIDIA_API_KEY", "fake")
    captured = {}
    content = json.dumps({"primary": "sqli", "types": ["sqli"], "confidence": 0.9})
    monkeypatch.setattr(ai, "_post_chat", _fake_post(captured, content))

    res = asyncio.run(ai.ai_classify_attack({
        "method": "GET", "path": "/search",
        "params": {"q": "' UNION SELECT 1,2--"},
        "body": "", "headers": {"Cookie": "sess=TOPSECRET123", "User-Agent": "UA"}}))
    assert res.get("primary") == "sqli"
    sent = json.dumps(captured["payload"], ensure_ascii=False)
    assert "UNION SELECT" in sent              # 공격 신호는 분류를 위해 유지
    assert "TOPSECRET123" not in sent          # 쿠키 값은 반출되지 않음


def test_permissive_suggest_unchanged(monkeypatch):
    """permissive(기본)에서는 기존대로 값이 그대로 전달된다(비파괴적)."""
    monkeypatch.setenv("AI_EXPORT_MODE", "permissive")
    monkeypatch.setenv("NVIDIA_API_KEY", "fake")
    captured = {}
    content = json.dumps({"test_type": "t", "summary": "s", "candidates": []})
    monkeypatch.setattr(ai, "_post_chat", _fake_post(captured, content))

    asyncio.run(ai.ai_suggest_payloads("GET", "/api/orders/98765",
                                       {"q": "normalvalue"}, body="", header_names=["Accept"]))
    sent = json.dumps(captured["payload"], ensure_ascii=False)
    assert "normalvalue" in sent and "98765" in sent    # 기존 동작 유지
