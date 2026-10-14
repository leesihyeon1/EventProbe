"""반출(egress) 공통 정책 — 외부 전송 직전 금지 데이터 차단 검증.

리뷰(docs/artex-integration-review.md)의 필수 검증 기준을 코드로 고정한다:
합성 도메인·IP·이메일·쿠키·JWT·body 비밀값·응답 마커를 여러 필드에 넣고,
strict 모드에서 '실제 외부 전송 직전' 두 chokepoint(chat·embeddings)가 전송을 막는지 본다.
네트워크 호출은 전혀 하지 않는다 — guard 는 전송 이전 단계에서 예외를 올린다.
"""
import asyncio

import pytest

from core import ai_egress
from core import ai_analyzer as ai
from core import rag


@pytest.fixture(autouse=True)
def _isolate():
    ai_egress.clear_canaries()
    ai_egress.clear_audit()
    yield
    ai_egress.clear_canaries()
    ai_egress.clear_audit()


def _strict(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")


EXT = "https://integrate.api.nvidia.com/v1"
INT = "http://localhost:11434/v1"


# ── 모드 ──────────────────────────────────────────────────────────────────────
def test_default_mode_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv("AI_EXPORT_MODE", raising=False)
    assert ai_egress.export_mode() == "strict"      # 미설정 → fail-closed(리뷰 F3)
    assert ai_egress.is_strict()


def test_explicit_permissive(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "permissive")
    assert ai_egress.export_mode() == "permissive"
    assert not ai_egress.is_strict()


def test_unknown_value_fails_closed_and_reports(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "stricct")   # 오타
    assert ai_egress.is_strict()                      # fail-closed
    assert "알 수 없는 값" in ai_egress.config_error()


@pytest.mark.parametrize("val", ["strict", "1", "true", "on", "YES"])
def test_strict_values(monkeypatch, val):
    monkeypatch.setenv("AI_EXPORT_MODE", val)
    assert ai_egress.is_strict()


# ── 스캐너 등급 ────────────────────────────────────────────────────────────────
def test_scan_block_categories():
    kinds = lambda t: {v.kind: v.severity for v in ai_egress.scan(t)}
    assert kinds("tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123_sig")["jwt"] == "block"
    assert kinds("key AKIAIOSFODNN7EXAMPLE here")["aws_key"] == "block"
    assert kinds("Cookie: sessionid=abc123deadbeef")["cookie"] == "block"
    assert kinds("Authorization: Bearer sometoken")["authorization"] == "block"
    assert kinds("mail admin@corp-internal.co.kr now")["email"] == "block"


def test_scan_warn_categories():
    kinds = lambda t: {v.kind: v.severity for v in ai_egress.scan(t)}
    assert kinds("see https://victim-corp.co.kr/app")["url"] == "warn"
    assert kinds("host 10.20.30.40 responded")["ipv4"] == "warn"


def test_example_domains_not_flagged():
    assert ai_egress.scan("contact user@example.com") == []
    assert ai_egress.scan("visit https://example.com/path") == []


def test_canary_blocks():
    ai_egress.register_canary("acme-prod.internal.corp")
    v = ai_egress.scan("the target was acme-prod.internal.corp today")
    assert any(x.kind == "canary" and x.severity == "block" for x in v)


def test_short_canary_ignored():
    ai_egress.register_canary("ab")          # 4자 미만은 무시(대량 오탐 방지)
    assert ai_egress.scan("ab ab ab") == []


# ── guard: strict 차단 / permissive 허용 / 내부 목적지 예외 ──────────────────────
def _chat(*contents):
    return {"model": "m", "messages": [{"role": "user", "content": c} for c in contents]}


def test_guard_strict_blocks_external(monkeypatch):
    _strict(monkeypatch)
    payload = _chat("Authorization: Bearer leaked-token")
    with pytest.raises(ai_egress.EgressBlocked):
        ai_egress.guard(payload, channel="chat", destination_url=EXT)


def test_guard_permissive_allows_but_audits(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "permissive")
    payload = _chat("Authorization: Bearer leaked-token")
    assert ai_egress.guard(payload, channel="chat", destination_url=EXT) is payload
    log = ai_egress.audit_log()
    assert log and log[-1]["blocked"] is False
    assert any(f["kind"] == "authorization" for f in log[-1]["findings"])


def test_guard_internal_destination_not_blocked_even_strict(monkeypatch):
    _strict(monkeypatch)
    payload = _chat("Authorization: Bearer leaked-token")   # 로컬 모델行 = 반출 아님
    assert ai_egress.guard(payload, channel="chat", destination_url=INT) is payload


def test_guard_warn_only_not_blocked_in_strict(monkeypatch):
    _strict(monkeypatch)
    payload = _chat("try SSRF to http://169.254.169.254/latest/meta-data/")  # warn 등급만
    assert ai_egress.guard(payload, channel="chat", destination_url=EXT) is payload


def test_embeddings_channel_scanned(monkeypatch):
    _strict(monkeypatch)
    payload = {"model": "e", "input": ["normal text", "mail admin@corp-internal.co.kr"]}
    with pytest.raises(ai_egress.EgressBlocked):
        ai_egress.guard(payload, channel="embeddings", destination_url=EXT)


def test_multi_field_canary_blocked_in_strict(monkeypatch):
    """리뷰 검증 기준: 합성 식별자를 여러 필드에 흩뿌려도 전송 직전 차단된다."""
    _strict(monkeypatch)
    ai_egress.register_canary("tgt-host.victim.lan", "S3cr3t-Body-Value")
    payload = {"model": "m", "messages": [
        {"role": "system", "content": "plan a test"},
        {"role": "user", "content": "path=/api on tgt-host.victim.lan"},
        {"role": "user", "content": "body carried S3cr3t-Body-Value and eyJhbGciOi.JIUzI1.sig_abc12345"},
    ]}
    with pytest.raises(ai_egress.EgressBlocked) as ei:
        ai_egress.guard(payload, channel="chat", destination_url=EXT)
    assert ei.value.channel == "chat"


# ── 감사: 원문 민감값을 기록하지 않음 ──────────────────────────────────────────
def test_audit_redacts_secret(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "permissive")
    secret = "admin@corp-internal.co.kr"
    ai_egress.guard(_chat(f"mail {secret}"), channel="chat", destination_url=EXT)
    serialized = str(ai_egress.audit_log())
    assert secret not in serialized          # 원문은 감사 기록에 남지 않는다
    assert "email" in serialized             # 종류는 남는다


# ── 감사 요약: 운영 집계(P4) ──────────────────────────────────────────────────
def test_audit_summary_aggregates_without_raw_values(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "permissive")
    ai_egress.guard({"model": "m1", "messages": [{"role": "user", "content": "hi"}]}, channel="chat", destination_url=EXT)
    ai_egress.guard({"model": "m1", "input": ["x"]}, channel="embeddings", destination_url=INT)
    ai_egress.guard(_chat("mail admin@corp-internal.co.kr"), channel="chat", destination_url=EXT)
    s = ai_egress.audit_summary()
    assert s["count"] == 3
    assert s["channels"] == {"chat": 2, "embeddings": 1}
    assert s["models"]["m1"] == 2             # 세 번째 호출은 모델 'm'
    assert s["external"] == 2                 # INT 목적지는 외부 아님
    assert s["findings"].get("email") == 1
    assert "admin@corp-internal.co.kr" not in str(s)   # 요약에도 원문 없음


def test_audit_summary_empty_is_safe():
    ai_egress.clear_audit()
    s = ai_egress.audit_summary()
    assert s["count"] == 0 and s["channels"] == {} and s["first_ts"] == ""


# ── 임베딩 허용 매트릭스(F3) ──────────────────────────────────────────────────
def test_embeddings_allowed_matrix(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "permissive")
    assert ai_egress.embeddings_allowed(EXT) is True
    _strict(monkeypatch)
    assert ai_egress.embeddings_allowed(EXT) is False     # 외부 → 차단
    assert ai_egress.embeddings_allowed(INT) is True      # 사내/로컬 → 허용


# ── chokepoint 배선: 전송 이전에 막힌다(네트워크 없음) ────────────────────────
def test_post_chat_blocks_before_network_in_strict(monkeypatch):
    _strict(monkeypatch)
    payload = {"model": "m", "messages": [
        {"role": "user", "content": "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_abcdefgh"}]}
    with pytest.raises(ai_egress.EgressBlocked):
        asyncio.run(ai._post_chat(EXT, {"Authorization": "Bearer k"}, payload, tries=1))


def test_rag_embed_returns_none_in_strict_external(monkeypatch):
    monkeypatch.setenv("EMBEDDING_API_KEY", "fake-key")
    monkeypatch.setenv("EMBEDDING_BASE_URL", EXT)
    _strict(monkeypatch)
    assert rag._embed(["hello world"], "query") is None   # 외부 임베딩 전송 안 함 → BM25 폴백


# ── strict 판정: 외부 호출 없이 로컬 템플릿 + 응답 근거 미반출(F1) ─────────────
def test_strict_verdict_uses_local_template_not_external(monkeypatch):
    from routers import api as api_mod
    _strict(monkeypatch)

    async def _no_rag(*a, **k):
        return []
    monkeypatch.setattr(api_mod, "_retrieve_related", _no_rag)

    async def _boom(*a, **k):
        raise AssertionError("strict 모드에서 외부 ai_verdict 를 호출하면 안 된다")
    monkeypatch.setattr(api_mod, "ai_verdict", _boom)
    monkeypatch.setattr(api_mod, "ai_enabled", lambda: False)   # _classify 건너뜀

    req = api_mod.EnrichRequest(
        method="GET", url="https://corp-target.lan/app?q=1",
        analysis={"attack_type": "sqli", "attack_outcome": "suspicious",
                  "findings": [{"name": "err", "verdict": "미확정",
                                "why": "DB error leaked internal path",
                                "evidence": "SQL syntax near 'secret_users'"}],
                  "det_verdict": {"summary": "로컬 요약", "priority": "high",
                                  "remediation": "파라미터 바인딩"}})
    out = asyncio.run(api_mod.analyze_enrich(req))
    v = out["ai_verdict"]
    assert v["model"] == "local-template(strict-egress)"
    assert v["priority"] == "high" and v["outcome"] == "suspicious"
    # 응답 유래 근거(why/evidence)가 판정 객체로 새어 나가지 않는다
    assert "DB error leaked" not in str(v) and "secret_users" not in str(v)


# ── /api/egress/policy 엔드포인트(UI 반출 정책 표시용) ──────────────────────────
def test_egress_policy_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)

    monkeypatch.setenv("AI_EXPORT_MODE", "permissive")
    body = client.get("/api/egress/policy").json()
    assert body["mode"] == "permissive" and body["strict"] is False
    assert isinstance(body["audit"], list) and body["policy_version"]

    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    body = client.get("/api/egress/policy").json()
    assert body["mode"] == "strict" and body["strict"] is True
