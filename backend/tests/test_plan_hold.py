"""A human hold cancels an active plan without replaying an uncertain step."""
import asyncio

import httpx
import pytest

import core.agent as agent_mod
from core.agent import AgentManager
from core.agent_models import RunSpec
from core.agent_store import Store


PLAN = {'entry': 'observe', 'steps': [
    {'action_id': 'observe', 'action': {'kind': 'observe', 'hypothesis': 'synthetic'}}]}


def test_hold_records_reason_and_does_not_replay_inflight_request(tmp_path):
    async def run():
        started = asyncio.Event()
        sent = []

        async def reply(request):
            sent.append(request)
            started.set()
            await asyncio.Event().wait()

        store = Store(tmp_path / 'hold.db')
        manager = AgentManager(store, transport=httpx.MockTransport(reply))
        spec = RunSpec.model_validate({'goal': 'synthetic hold',
                                       'request': {'url': 'https://app.test/'},
                                       'approved_plan': PLAN})
        rid = manager.create(spec)
        await asyncio.wait_for(started.wait(), 5)
        paused = await manager.hold_plan(rid, '범위 확인 필요')
        assert paused['state'] == 'paused'
        assert paused['data']['stop_code'] == 'plan_hold'
        assert paused['data']['reason'] == '계획 보류: 범위 확인 필요'
        holds = [event for event in paused['events'] if event['kind'] == 'plan_hold']
        assert len(holds) == 1
        assert holds[0]['data']['reason'] == '범위 확인 필요'
        assert holds[0]['data']['fingerprint'] == paused['data']['plan_fingerprint']
        latest = [event for event in paused['events'] if event['kind'] == 'conclusion'][-1]
        assert latest['data']['stop_code'] == 'plan_hold'
        assert latest['data']['stop_reason'] == paused['conclusion']['stop_reason']
        assert len(sent) == 1
        resumed = AgentManager(Store(tmp_path / 'hold.db'), transport=httpx.MockTransport(reply))
        resumed.start(rid)
        await resumed.tasks[rid]
        return resumed.snapshot(rid), sent

    snapshot, sent = asyncio.run(run())
    assert len(sent) == 1
    assert snapshot['data']['stop_code'] == 'plan_step_uncertain'
    assert sum(event['kind'] == 'plan_hold' for event in snapshot['events']) == 1


def test_hold_endpoint_checks_owner_before_state(tmp_path, monkeypatch):
    manager = AgentManager(Store(tmp_path / 'owner.db'))
    spec = RunSpec.model_validate({'goal': 'synthetic hold',
                                   'request': {'url': 'https://app.test/'},
                                   'approved_plan': PLAN})
    rid = manager.store.create({'spec': spec.model_dump(), 'owner': 'alice',
                                'needs_credentials': False})
    monkeypatch.setattr(agent_mod, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    route = f'/api/agent/runs/{rid}/plan/hold'
    assert client.post(route, headers={'x-eventprobe-user': 'bob'},
                       json={'reason': 'not yours'}).status_code == 403
    assert client.post(route, headers={'x-eventprobe-user': 'alice'},
                       json={'reason': 'not running'}).status_code == 409
