"""세션 요약의 범위와 AI 판정 경계를 검증한다."""

import asyncio

from core import ai_analyzer
from core.verification_context import compact
from routers import api


def _event(url="https://target.invalid/private?id=1", session="session-a", **extra):
    return {"session_id": session, "kind": "request", "method": "GET", "url": url,
            "status": 403, "outcome": "blocked", "category": "authbypass",
            "body": "SECRET-BODY", "headers": {"Authorization": "secret-token"}, **extra}


def test_only_same_session_origin_and_summary_fields_survive():
    rows = compact([_event(), _event(session="other"),
                    _event(url="https://other.invalid/private")],
                   session_id="session-a", current_url="https://target.invalid/private?id=2")
    assert len(rows) == 1
    assert rows[0]["path"] == "/private"
    assert "SECRET-BODY" not in str(rows) and "secret-token" not in str(rows)
    assert "id=1" not in str(rows)


def test_context_is_bounded_and_path_tokens_are_redacted():
    rows = compact([_event(url="https://target.invalid/users/12345678901234567890?token=hidden")
                    for _ in range(12)], session_id="session-a",
                   current_url="https://target.invalid/users/other")
    assert len(rows) == 5
    assert rows[0]["path"] == "/users/{id}"
    assert "hidden" not in str(rows)


def test_untrusted_history_is_prompt_context_not_outcome(monkeypatch):
    seen = {}

    async def fake_verdict(ctx):
        seen.update(ctx)
        return {"outcome": ctx["outcome"]}

    monkeypatch.setattr(api, "ai_verdict_enabled", lambda: True)
    monkeypatch.setattr(api, "ai_verdict", fake_verdict)
    monkeypatch.setattr(api, "_retrieve_related", _empty_retrieval)
    req = api.EnrichRequest(method="GET", url="https://target.invalid/private?id=2",
                            status_code=200, session_id="session-a", context_events=[_event()],
                            analysis={"attack_type": "authbypass", "attack_outcome": "inconclusive",
                                      "baseline_check": {"valid": False, "code": "auth_changed",
                                                         "reason": "인증 조건 불일치"},
                                      "findings": [], "alerts": []})
    result = asyncio.run(api.analyze_enrich(req))
    assert result["context_used"] == 1
    assert seen["context_events"][0]["outcome"] == "blocked"
    assert seen["outcome"] == "inconclusive"
    assert seen["baseline_check"]["code"] == "auth_changed"
    assert result["ai_verdict"]["outcome"] == "inconclusive"
    assert "SECRET-BODY" not in str(seen)


async def _empty_retrieval(*args):
    return []


def test_ai_detail_prompt_labels_history_as_untrusted():
    text = ai_analyzer._build_user_prompt({"context_events": [{"outcome": "blocked"}]})
    assert "untrusted, not proof" in text
    assert "blocked" in text
