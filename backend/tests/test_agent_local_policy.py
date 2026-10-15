"""Durable path, method and category restrictions are enforced locally."""
import asyncio
import time

import httpx
import pytest

from core.agent import AgentManager, _enforce_request_policy, _validate_plan_scope
from core.agent_models import RunSpec
from core.agent_store import Store
from core.plan import Plan


def _spec(**changes):
    return RunSpec.model_validate({'goal': 'synthetic',
                                   'request': {'url': 'https://app.test/api/items'},
                                   **changes})


def test_path_segment_and_method_limits():
    spec = _spec(policy_version=3, allowed_path_prefixes=['/api'],
                 denied_path_prefixes=['/api/admin'], allowed_methods=['GET'])
    _enforce_request_policy(spec, {'url': 'https://app.test/api/items', 'method': 'GET'})
    _enforce_request_policy(spec, {'url': 'https://app.test/api/administrator', 'method': 'GET'})
    with pytest.raises(ValueError, match='금지 경로'):
        _enforce_request_policy(spec, {'url': 'https://app.test/api/admin/users', 'method': 'GET'})
    with pytest.raises(ValueError, match='허용 경로'):
        _enforce_request_policy(spec, {'url': 'https://app.test/other', 'method': 'GET'})
    with pytest.raises(ValueError, match='메서드'):
        _enforce_request_policy(spec, {'url': 'https://app.test/api/items', 'method': 'POST'})
    with pytest.raises(ValueError, match='모호한'):
        _enforce_request_policy(spec, {'url': 'https://app.test/api/%61dmin', 'method': 'GET'})
    with pytest.raises(ValueError, match='모호한'):
        _enforce_request_policy(spec, {'url': 'https://app.test/api/../admin', 'method': 'GET'})
    with pytest.raises(ValueError, match='모호한'):
        _enforce_request_policy(spec, {'url': 'https://app.test/api/admin;mode=1', 'method': 'GET'})


def test_category_rejected_before_plan_execution():
    spec = _spec(allowed_categories=['xss'])
    plan = Plan.model_validate({'entry': 'one', 'steps': [
        {'action_id': 'one', 'action': {'kind': 'probe', 'hypothesis': 'synthetic',
                                     'category': 'sqli', 'payload': "'"}}]})
    with pytest.raises(ValueError, match='허용되지 않은 계획'):
        _validate_plan_scope(spec, plan)


def test_disallowed_seed_path_sends_no_request(tmp_path):
    async def run():
        seen = []
        def reply(request):
            seen.append(request)
            return httpx.Response(200, text='ok')
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        plan = {'entry': 'observe', 'steps': [
            {'action_id': 'observe', 'action': {'kind': 'observe', 'hypothesis': 'synthetic'}}]}
        spec = _spec(allowed_path_prefixes=['/safe'], approved_plan=plan)
        rid = manager.create(spec)
        await manager.tasks[rid]
        return manager.snapshot(rid), seen

    result, seen = asyncio.run(run())
    assert result['state'] == 'paused'
    assert '허용 경로' in result['data']['reason']
    assert seen == []


def test_new_pinned_plan_rejects_stale_policy_before_storage(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENT_POLICY_VERSION', '2')
    manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    plan = {'entry': 'observe', 'steps': [
        {'action_id': 'observe', 'action': {'kind': 'observe', 'hypothesis': 'synthetic'}}]}
    spec = _spec(policy_version=1, approved_plan=plan)
    with pytest.raises(ValueError, match='정책 버전'):
        manager.create(spec)
    with manager.store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0


def test_policy_change_between_plan_steps_sends_no_next_request(tmp_path, monkeypatch):
    async def run():
        seen = []
        def reply(request):
            seen.append(request)
            monkeypatch.setenv('AGENT_POLICY_VERSION', '2')
            return httpx.Response(200, text='synthetic')
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        plan = {'entry': 'one', 'steps': [
            {'action_id': 'one', 'action': {'kind': 'observe', 'hypothesis': 'first'}, 'default_next': 'two'},
            {'action_id': 'two', 'action': {'kind': 'observe', 'hypothesis': 'second'}}]}
        spec = _spec(policy_version=1, approved_plan=plan,
                     approved_plan_expires_at=time.time() + 300)
        rid = manager.create(spec)
        await manager.tasks[rid]
        return manager.snapshot(rid), seen

    result, seen = asyncio.run(run())
    assert len(seen) == 1
    assert result['state'] == 'paused'
    assert '정책' in result['data']['reason']


def test_policy_change_blocks_resume_after_restart(tmp_path, monkeypatch):
    async def run():
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        plan = {'entry': 'observe', 'steps': [
            {'action_id': 'observe', 'action': {'kind': 'observe', 'hypothesis': 'synthetic'}}]}
        spec = _spec(policy_version=1, approved_plan=plan, approved_plan_expires_at=time.time() - 1)
        rid = manager.create(spec)
        await manager.tasks[rid]
        return rid

    rid = asyncio.run(run())
    monkeypatch.setenv('AGENT_POLICY_VERSION', '2')
    restarted = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(ValueError, match='정책 버전'):
        restarted.start(rid)
    assert restarted.store.get(rid)['state'] == 'paused'
