"""Inspect AI HTTP payloads without contacting any external service."""
import asyncio
import copy
import json

import httpx
import pytest

from core import ai_analyzer
from core.ai_privacy import SENSITIVE_HEADERS, sanitize_headers
from routers.api import SingleRequest, _blurred_request


@pytest.mark.parametrize("name", sorted(SENSITIVE_HEADERS))
def test_sensitive_headers_are_removed_case_insensitively(name):
    headers = {f" {name.upper()} ": "secret", "User-Agent": "probe"}
    original = dict(headers)
    assert sanitize_headers(headers) == {"User-Agent": "probe"}
    assert headers == original


def test_empty_headers():
    assert sanitize_headers(None) == {}


@pytest.mark.parametrize("mode", ["classify", "analyze", "verdict"])
def test_ai_transport_excludes_target_credentials(monkeypatch, mode):
    secrets = {name.swapcase(): f"private-value-{i}" for i, name in enumerate(sorted(SENSITIVE_HEADERS))}
    target_headers = {**secrets, "User-Agent": "probe-agent", "X-Test-Probe": "probe-marker"}
    original = copy.deepcopy(target_headers)
    sent = []

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, *, headers, json):
            sent.append((headers, json))
            return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    monkeypatch.setattr(ai_analyzer.httpx, "AsyncClient", Client)
    monkeypatch.setattr(ai_analyzer, "_api_key", lambda: "provider-test-key")
    if mode == "classify":
        result = asyncio.run(ai_analyzer.ai_classify_attack({"headers": target_headers}))
    elif mode == "analyze":
        result = asyncio.run(ai_analyzer.ai_analyze({"resp_headers": target_headers}))
    else:
        req = SingleRequest(method="GET", url="https://target.invalid/", headers=target_headers)
        result = asyncio.run(ai_analyzer.ai_verdict({"request": _blurred_request(req)}))

    assert "error" not in result
    assert len(sent) == 1
    transport_headers, payload = sent[0]
    prompt = json.dumps(payload["messages"])
    for secret in secrets.values():
        assert secret not in prompt
    assert "X-Test-Probe" in prompt
    if mode != "verdict":
        assert "probe-marker" in prompt
    assert transport_headers["Authorization"] == "Bearer provider-test-key"
    assert target_headers == original
