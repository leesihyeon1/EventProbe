"""Offline review regressions. Expected to fail on e92c6b6, not product tests.

All values are synthetic. No live service, model, or saved run is used.
Run explicitly: python -m pytest docs/reviews/2026-10-13/review_contract_checks.py -q
"""
import asyncio
import json
import socket
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "backend"))

from core import agent, ai_egress, confirm
from core.agent_models import Action, RunSpec
from core.agent_store import Store
from core.plan import Plan, PlanStep


@pytest.fixture(autouse=True)
def offline_strict(monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    original_connect = socket.socket.connect

    def no_network(sock, address):
        # Windows asyncio creates a loopback socketpair for its event loop.
        if isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1"):
            return original_connect(sock, address)
        raise AssertionError("Review must not use live network")

    monkeypatch.setattr(socket.socket, "connect", no_network)


def checked_text(context):
    payload = {"messages": [{"role": "user", "content": json.dumps(context)}]}
    try:
        ai_egress.guard(payload, channel="chat",
                        destination_url="https://integrate.api.nvidia.com/v1")
    except ai_egress.EgressBlocked:
        return ""
    return payload["messages"][0]["content"]


def test_missing_egress_setting_must_fail_closed(monkeypatch):
    monkeypatch.delenv("AI_EXPORT_MODE", raising=False)
    assert ai_egress.is_strict(), "Missing setting currently permits external data export"


@pytest.mark.parametrize("body", [
    {"profile": {"password": "REVIEW_PRIVATE_VALUE", "host": "payroll.corp.test"}},
    [{"password": "REVIEW_PRIVATE_VALUE", "host": "payroll.corp.test"}],
])
def test_plan_shape_must_not_export_nested_values(body):
    spec = RunSpec(goal="review", request={
        "url": "https://app.test/api/profile", "body": json.dumps(body),
    })
    outbound = checked_text(agent._plan_context(spec))
    assert "REVIEW_PRIVATE_VALUE" not in outbound and "payroll.corp.test" not in outbound


def test_strict_context_must_remove_response_derived_evidence():
    response_text = "uid=1001(review_private_account)"
    decision = confirm.decide("cmdi", [
        {"role": "baseline", "status": 200, "body": "ok"},
        {"role": "idcmd", "status": 200, "body": response_text},
    ])
    assert decision["techniques"], "Fixture must generate actual local evidence"
    context = agent._strict_context({"goal": "review", "verified_results": [
        {"status": "confirmed", "rounds": [decision, decision]},
    ]})
    assert response_text not in checked_text(context)


def execute_single(tmp_path, kind):
    calls = []
    spec = RunSpec(goal="review", request={"url": "https://app.test/?id=1"},
                   actors=[{"id": "owner"}, {"id": "reader"}], objects=[{
                       "id": "object1", "url": "https://app.test/objects/1",
                       "owner_actor": "owner", "identity_pointer": "/id",
                       "identity_value": "1", "description": "Synthetic ownership",
                   }], mode="plan")
    manager = agent.AgentManager(Store(tmp_path / "review.db"))
    data = {"endpoints": {"seed": spec.request.model_dump()}}

    async def fetch(req, actor, *args):
        calls.append((req["url"], actor))
        return {"id": str(len(calls)), "response": {
            "status": 200, "headers": {"content-type": "application/json"},
            "body": '{"id":1}', "truncated": False,
        }, "analysis": {"findings": []}}

    action = Action(kind=kind, hypothesis="review", actor_id="reader",
                    category="sqli" if kind == "confirm" else "",
                    param="id", object_id="object1" if kind == "access" else "")
    result = asyncio.run(manager._exec_plan_step("unused", spec, data, fetch, action, "step"))
    return calls, result


def test_plan_confirm_must_run_differential_probes(tmp_path):
    calls, result = execute_single(tmp_path, "confirm")
    assert len(calls) > 1, f"confirm only performed a baseline read; verdict={result.verdict}"


def test_plan_access_must_check_owner_and_unauthorized_actor(tmp_path):
    calls, _ = execute_single(tmp_path, "access")
    assert calls == [("https://app.test/objects/1", actor)
                     for actor in ("owner", "reader", "reader")]


def execute_plan(tmp_path, monkeypatch, max_ai_calls):
    generated = []

    async def generate(spec):
        generated.append(True)
        return Plan(entry="observe", steps=[PlanStep(action_id="observe", action=Action(
            kind="observe", hypothesis="review"))])

    monkeypatch.setattr(agent, "generate_plan", generate)

    async def run():
        manager = agent.AgentManager(Store(tmp_path / "run.db"), transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text="ok")))
        spec = RunSpec(goal="review", request={"url": "https://app.test/"},
                       mode="plan", max_ai_calls=max_ai_calls)
        rid = manager.create(spec)
        await manager.tasks[rid]
        return manager.snapshot(rid)

    return asyncio.run(run()), generated


def test_plan_must_respect_zero_ai_budget(tmp_path, monkeypatch):
    run, generated = execute_plan(tmp_path, monkeypatch, 0)
    assert not generated, f"Plan generated despite zero budget; recorded calls={run['data']['ai_calls']}"


def test_plan_observations_must_link_to_action(tmp_path, monkeypatch):
    run, _ = execute_plan(tmp_path, monkeypatch, 1)
    actions = {e["step_id"] for e in run["events"] if e["kind"] == "action"}
    observations = [e for e in run["events"] if e["kind"] == "observation"]
    assert observations, "Fixture must produce an observation"
    assert all(e["step_id"] in actions for e in observations)
