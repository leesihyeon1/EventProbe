"""Pinned approvals expire locally before a target request is sent."""
import asyncio
import time

import httpx
import pytest

import core.agent as agent_mod
from core.agent import AgentManager
from core.agent_models import RunSpec
from core.agent_store import Store


PLAN = {'entry': 'observe', 'steps': [
    {'action_id': 'observe', 'action': {'kind': 'observe', 'hypothesis': 'synthetic'}}]}


def test_pinned_plan_has_bounded_default_lifetime():
    now = time.time()
    spec = RunSpec.model_validate({'goal': 'synthetic', 'request': {'url': 'https://app.test/'},
                                   'approved_plan': PLAN})
    assert now < spec.approved_plan_expires_at <= now + 3601
    with pytest.raises(ValueError, match='최대 1시간'):
        RunSpec.model_validate({'goal': 'synthetic', 'request': {'url': 'https://app.test/'},
                                'approved_plan': PLAN, 'approved_plan_expires_at': now + 7200})


def test_expired_approval_sends_no_request(tmp_path):
    async def run():
        sent = []
        def reply(request):
            sent.append(request)
            return httpx.Response(200, text='synthetic')
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        spec = RunSpec.model_validate({'goal': 'synthetic', 'request': {'url': 'https://app.test/'},
                                       'approved_plan': PLAN,
                                       'approved_plan_expires_at': time.time() - 1})
        rid = manager.create(spec)
        await manager.tasks[rid]
        return manager.snapshot(rid), sent

    snapshot, sent = asyncio.run(run())
    assert snapshot['state'] == 'paused'
    assert '만료' in snapshot['data']['reason']
    assert sent == []
    assert not any(e['kind'] == 'plan_approval' for e in snapshot['events'])


def test_accepted_plan_approval_records_fingerprint_and_policy_once(tmp_path):
    async def run():
        manager = AgentManager(Store(tmp_path / 'approved.db'),
                               transport=httpx.MockTransport(lambda request: httpx.Response(200)))
        spec = RunSpec.model_validate({'goal': 'synthetic', 'request': {'url': 'https://app.test/'},
                                       'approved_plan': PLAN})
        rid = manager.create(spec)
        await manager.tasks[rid]
        return manager.snapshot(rid)

    snapshot = asyncio.run(run())
    approved = [e for e in snapshot['events'] if e['kind'] == 'plan_approval']
    plans = [e for e in snapshot['events'] if e['kind'] == 'plan']
    assert len(approved) == len(plans) == 1
    assert approved[0]['data']['fingerprint'] == plans[0]['data']['fingerprint']
    assert approved[0]['data']['policy_version'] == snapshot['data']['spec']['policy_version']
    assert approved[0]['data']['expires_at'] == snapshot['data']['spec']['approved_plan_expires_at']


def test_revoked_approval_is_audited_and_cannot_resume_after_restart(tmp_path):
    async def run():
        sent = []
        manager = AgentManager(Store(tmp_path / 'runs.db'),
                               transport=httpx.MockTransport(lambda request: sent.append(request) or httpx.Response(200)))
        spec = RunSpec.model_validate({'goal': 'synthetic', 'request': {'url': 'https://app.test/'},
                                       'approved_plan': PLAN, 'approved_plan_expires_at': time.time() - 1})
        rid = manager.create(spec)
        await manager.tasks[rid]
        revoked = await manager.revoke_plan(rid, '범위 승인 철회')
        again = AgentManager(Store(tmp_path / 'runs.db'), transport=manager.transport)
        with pytest.raises(ValueError, match='철회'):
            again.start(rid)
        return revoked, sent

    snapshot, sent = asyncio.run(run())
    assert sent == []
    assert snapshot['data']['spec']['approved_plan_revoked_at']
    assert snapshot['data']['stop_code'] == 'plan_revoked'
    events = [e for e in snapshot['events'] if e['kind'] == 'plan_revoke']
    assert len(events) == 1 and events[0]['data']['reason'] == '범위 승인 철회'
    latest = [e for e in snapshot['events'] if e['kind'] == 'conclusion'][-1]
    assert latest['data']['stop_code'] == 'plan_revoked'
    assert latest['data']['stop_reason'] == snapshot['conclusion']['stop_reason']


def test_revoke_cancels_inflight_request_without_retry(tmp_path):
    async def run():
        started = asyncio.Event()
        sent = []
        async def reply(request):
            sent.append(request)
            started.set()
            await asyncio.Event().wait()
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        spec = RunSpec.model_validate({'goal': 'synthetic', 'request': {'url': 'https://app.test/'},
                                       'approved_plan': PLAN})
        rid = manager.create(spec)
        await asyncio.wait_for(started.wait(), 5)
        snapshot = await manager.revoke_plan(rid, '대상 요청 중지')
        return snapshot, sent

    snapshot, sent = asyncio.run(run())
    assert len(sent) == 1
    assert snapshot['state'] == 'paused'
    assert snapshot['data']['stop_code'] == 'plan_revoked'
    assert any(e['kind'] == 'request_error' for e in snapshot['events'])


def test_revoke_api_enforces_owner_and_blocks_resume(tmp_path, monkeypatch):
    async def setup():
        manager = AgentManager(Store(tmp_path / 'runs.db'),
                               transport=httpx.MockTransport(lambda request: httpx.Response(200)))
        spec = RunSpec.model_validate({'goal': 'synthetic', 'request': {'url': 'https://app.test/'},
                                       'approved_plan': PLAN, 'approved_plan_expires_at': time.time() - 1})
        rid = manager.create(spec, owner='alice')
        await manager.tasks[rid]
        return manager, rid

    manager, rid = asyncio.run(setup())
    monkeypatch.setattr(agent_mod, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    route = f'/api/agent/runs/{rid}/plan/revoke'
    assert client.post(route, headers={'x-eventprobe-user': 'bob'}, json={'reason': 'no'}).status_code == 403
    revoked = client.post(route, headers={'x-eventprobe-user': 'alice'},
                          json={'reason': '정책 변경'})
    assert revoked.status_code == 200
    assert revoked.json()['data']['stop_code'] == 'plan_revoked'
    assert client.post(f'/api/agent/runs/{rid}/resume', headers={'x-eventprobe-user': 'alice'},
                       json={}).status_code == 409
