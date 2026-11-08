"""Synthetic provider routing: no live target, external model or real credential."""
import asyncio
import json

import httpx
import pytest
from pydantic import ValidationError

from core import ai_analyzer as ai, ai_egress
from core.agent import AgentManager
from core.agent_models import RunSpec
from core.agent_runtime_store import RunConflict
from core.agent_store import Store
from core.model_profiles import ModelProfile
from core.model_routing import ACTIVE_MODEL, ModelRouter, ModelUnavailable, validate_chain
from core.model_store import ModelCallBudgetExceeded


def profile(store, monkeypatch, name='primary', **changes):
    key_env = 'EVENTPROBE_MODEL_' + name.upper()
    monkeypatch.setenv(key_env, 'synthetic-key-never-persist')
    return store.save_model_profile({'name': name, 'model': name,
        'base_url': f'https://{name}.example.invalid/v1', 'key_env': key_env,
        'failure_threshold': 1, **changes})


def run(store, ids, budget=4):
    spec = RunSpec(goal='synthetic', request={'url': 'https://example.test/'},
                   max_ai_calls=budget, model_profile_ids=ids)
    rid = store.create({'spec': spec.model_dump(), 'requests': 0, 'ai_calls': 0})
    store.set_run_model_chain(rid, ids, expected_revision=0)
    assert store.claim(rid)
    return rid


@pytest.mark.parametrize('change', [
    {'base_url': 'https://user:pass@example.test/v1'},
    {'base_url': 'https://example.test/v1?key=bad'},
    {'base_url': 'file:///tmp/provider'}, {'base_url': 'https://example.test:99999'},
    {'base_url': 'https://example.test/chat/completions'}, {'model': '\nunsafe'},
    {'name': '  '}, {'key_env': 'AWS_SECRET_ACCESS_KEY'}, {'api_key': 'never-store'},
    {'format': 'unsupported'}, {'max_concurrent_calls': 0},
])
def test_profile_rejects_unsafe_or_unsupported_configuration(change):
    with pytest.raises(ValidationError):
        ModelProfile.model_validate({'name': 'n', 'model': 'm',
            'base_url': 'https://model.example.invalid/v1', **change})


def test_profile_revision_and_health_survive_reopen_without_keys(tmp_path, monkeypatch):
    store = Store(tmp_path / 'profiles.db')
    p = profile(store, monkeypatch)
    store.record_model_health(p, 'quota')
    edited = store.save_model_profile({k: v for k, v in p.items() if k not in ('id', 'revision')},
                                      p['id'], expected_revision=1)
    assert edited['revision'] == 2
    with pytest.raises(RunConflict):
        store.save_model_profile({k: v for k, v in p.items() if k not in ('id', 'revision')},
                                 p['id'], expected_revision=1)
    reopened = Store(store.path)
    assert reopened.model_health(p['id'])['error_code'] == 'quota'
    with store.connect() as db:
        assert 'synthetic-key-never-persist' not in str([dict(x) for x in db.execute('SELECT * FROM model_profiles')])


def test_internal_external_chain_and_duplicate_profile_are_rejected(tmp_path, monkeypatch):
    store = Store(tmp_path / 'zones.db')
    external = profile(store, monkeypatch)
    internal = profile(store, monkeypatch, 'inside', base_url='http://127.0.0.1:9999/v1')
    with pytest.raises(ValueError, match='혼합'):
        validate_chain(store, [internal['id'], external['id']])
    with pytest.raises(ValueError, match='중복'):
        validate_chain(store, [external['id'], external['id']])


def test_failover_accounts_each_attempt_and_preserves_real_usage(tmp_path, monkeypatch):
    store = Store(tmp_path / 'failover.db')
    a, b = profile(store, monkeypatch), profile(store, monkeypatch, 'backup')
    rid = run(store, [a['id'], b['id']])
    requests = []
    async def post(url, headers, payload, **kwargs):
        requests.append((url, payload['model'], kwargs['tries']))
        return httpx.Response(503 if payload['model'] == 'primary' else 200,
                              json={'usage': {'total_tokens': 7}})
    monkeypatch.setattr(ai, '_post_chat_direct', post)
    async def scenario():
        with ModelRouter(store).bind(rid):
            response = await ai._post_chat('ignored', {}, {'model': 'ignored', 'messages': []})
        assert response.status_code == 200
        assert ACTIVE_MODEL.get() is None
    asyncio.run(scenario())
    assert len(requests) == 2 and all(x[2] == 1 for x in requests)
    assert store.get(rid)['data']['ai_calls'] == 2
    assert store.run_model_chain(rid)['active_position'] == 1
    assert store.model_health(a['id'])['cooldown_until'] > 0
    calls = store.model_call_page(rid)['items']
    assert {x['model'] for x in calls} == {'primary', 'backup'}
    assert calls[0]['actual_tokens'] == 7
    assert 'synthetic-key-never-persist' not in json.dumps(calls)


def test_failover_cannot_exceed_task_ai_budget(tmp_path, monkeypatch):
    store = Store(tmp_path / 'budget.db')
    a, b = profile(store, monkeypatch), profile(store, monkeypatch, 'backup')
    rid = run(store, [a['id'], b['id']], budget=1)
    sent = []
    async def post(*args, **kwargs):
        sent.append(1)
        return httpx.Response(503)
    monkeypatch.setattr(ai, '_post_chat_direct', post)
    async def scenario():
        with ModelRouter(store).bind(rid), pytest.raises(ModelCallBudgetExceeded):
            await ai._post_chat('', {}, {'messages': []})
    asyncio.run(scenario())
    assert len(sent) == store.get(rid)['data']['ai_calls'] == 1


@pytest.mark.parametrize('status', [200, 400, 403, 302])
def test_success_invalid_request_and_redirect_are_never_replayed(tmp_path, monkeypatch, status):
    store = Store(tmp_path / 'no-replay.db')
    a, b = profile(store, monkeypatch), profile(store, monkeypatch, 'backup')
    rid = run(store, [a['id'], b['id']])
    sent = []
    async def post(*args, **kwargs):
        sent.append(1)
        return httpx.Response(status, text='synthetic')
    monkeypatch.setattr(ai, '_post_chat_direct', post)
    async def scenario():
        with ModelRouter(store).bind(rid):
            assert (await ai._post_chat('', {}, {})).status_code == status
    asyncio.run(scenario())
    assert sent == [1]
    assert store.model_call_page(rid)['items'][0]['actual_tokens'] is None


def test_policy_block_never_fails_over_or_sends_transport(tmp_path, monkeypatch):
    store = Store(tmp_path / 'egress.db')
    a, b = profile(store, monkeypatch), profile(store, monkeypatch, 'backup')
    rid = run(store, [a['id'], b['id']])
    monkeypatch.setenv('AI_EXPORT_MODE', 'strict')
    monkeypatch.setattr(ai.httpx, 'AsyncClient', lambda **k: pytest.fail('Transport must remain unopened'))
    async def scenario():
        with ModelRouter(store).bind(rid), pytest.raises(ai_egress.EgressBlocked):
            await ai._post_chat('', {}, {'messages': [{'role': 'user', 'content': 'Authorization: Bearer synthetic-target-credential'}]})
    asyncio.run(scenario())
    calls = store.model_call_page(rid)['items']
    assert len(calls) == 1 and calls[0]['status'] == 'blocked'
    assert store.model_health(a['id'])['failures'] == 0


def test_cancellation_does_not_switch_models_or_leak_context(tmp_path, monkeypatch):
    store = Store(tmp_path / 'cancel.db')
    a, b = profile(store, monkeypatch), profile(store, monkeypatch, 'backup')
    rid = run(store, [a['id'], b['id']])
    async def scenario():
        entered = asyncio.Event()
        async def post(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(ai, '_post_chat_direct', post)
        async def call():
            with ModelRouter(store).bind(rid):
                await ai._post_chat('', {}, {})
        task = asyncio.create_task(call())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert ACTIVE_MODEL.get() is None
    asyncio.run(scenario())
    calls = store.model_call_page(rid)['items']
    assert len(calls) == 1 and calls[0]['status'] == 'cancelled'
    assert store.model_health(a['id'])['failures'] == 0


def test_profile_limiter_is_shared_across_tasks_and_chain_edits_are_revisioned(tmp_path, monkeypatch):
    store = Store(tmp_path / 'shared.db')
    p = profile(store, monkeypatch)
    ids = [run(store, [p['id']]) for _ in range(3)]
    router = ModelRouter(store)
    active, peak = 0, 0
    async def post(*args, **kwargs):
        nonlocal active, peak
        active += 1
        peak = max(active, peak)
        await asyncio.sleep(.01)
        active -= 1
        return httpx.Response(200, json={})
    monkeypatch.setattr(ai, '_post_chat_direct', post)
    async def one(rid):
        with router.bind(rid):
            await ai._post_chat('', {}, {})
    async def scenario():
        await asyncio.gather(*(one(rid) for rid in ids))
    asyncio.run(scenario())
    assert peak == 1
    state = store.set_run_model_chain(ids[0], [], expected_revision=1)
    assert state['revision'] == 2
    assert not store.advance_model_cursor(ids[0], 1, 1)
    assert store.run_model_chain(ids[0])['active_position'] == 0


def test_model_calls_counters_and_chain_survive_stale_run_saves(tmp_path, monkeypatch):
    store = Store(tmp_path / 'stale.db')
    p = profile(store, monkeypatch)
    rid = run(store, [p['id']])
    stale = store.get(rid)['data']
    store.begin_model_call(rid, p)
    store.set_run_model_chain(rid, [], expected_revision=1)
    store.update(rid, stale)
    saved = store.get(rid)['data']
    assert saved['ai_calls'] == stale['ai_calls'] == 1
    assert saved['spec']['model_profile_ids'] == []
    with pytest.raises(RunConflict):
        store.set_run_model_chain(rid, [p['id']], expected_revision=1)


def test_planner_failover_does_not_replay_target_http(tmp_path, monkeypatch):
    store = Store(tmp_path / 'agent.db')
    a, b = profile(store, monkeypatch), profile(store, monkeypatch, 'backup')
    target_requests, provider_calls = [], []
    async def post(url, headers, payload, **kwargs):
        provider_calls.append(payload['model'])
        if payload['model'] == 'primary':
            return httpx.Response(503)
        return httpx.Response(200, json={'choices': [{'message': {'content': json.dumps({
            'kind': 'finish', 'hypothesis': 'synthetic complete', 'basis': ['obs_1']})}}]})
    monkeypatch.setattr(ai, '_post_chat_direct', post)
    async def scenario():
        manager = AgentManager(store, transport=httpx.MockTransport(
            lambda r: (target_requests.append(str(r.url)) or httpx.Response(200, text='synthetic'))))
        spec = RunSpec(goal='synthetic', request={'url': 'https://example.test/'},
                       max_ai_calls=2, model_profile_ids=[a['id'], b['id']])
        rid = manager.create(spec)
        await manager.tasks[rid]
        result = manager.snapshot(rid)
        assert result['state'] == 'completed'
        assert result['data']['ai_calls'] == 2
        assert result['latest_model_call']['model'] == 'backup'
        await manager.shutdown()
    asyncio.run(scenario())
    assert target_requests == ['https://example.test/']
    assert provider_calls == ['primary', 'backup']


def test_preview_has_a_separate_bounded_budget(tmp_path, monkeypatch):
    store = Store(tmp_path / 'preview.db')
    p = profile(store, monkeypatch)
    async def post(*args, **kwargs):
        return httpx.Response(200, json={})
    monkeypatch.setattr(ai, '_post_chat_direct', post)
    async def scenario():
        with ModelRouter(store).bind(profile_ids=[p['id']], preview_budget=1):
            await ai._post_chat('', {}, {})
            with pytest.raises(ModelCallBudgetExceeded):
                await ai._post_chat('', {}, {})
    asyncio.run(scenario())


def test_referenced_profiles_cannot_be_deleted_and_run_deletion_cleans_ledger(tmp_path, monkeypatch):
    store = Store(tmp_path / 'delete.db')
    p = profile(store, monkeypatch)
    rid = run(store, [p['id']])
    store.begin_model_call(rid, p)
    with pytest.raises(RunConflict):
        store.delete_model_profile(p['id'], 1)
    store.delete(rid)
    assert store.model_call_page(rid)['total'] == 0
    store.delete_model_profile(p['id'], 1)
    with pytest.raises(KeyError):
        store.model_profile(p['id'])


def test_restart_marks_inflight_usage_unknown_without_replaying_or_resetting_health(tmp_path, monkeypatch):
    store = Store(tmp_path / 'restart.db')
    p = profile(store, monkeypatch)
    rid = run(store, [p['id']])
    store.begin_model_call(rid, p)
    store.record_model_health(p, 'quota')
    reopened = Store(store.path)
    reopened.recover()
    call = reopened.model_call_page(rid)['items'][0]
    assert call['status'] == 'interrupted'
    assert call['actual_tokens'] is None
    assert reopened.get(rid)['state'] == 'interrupted'
    assert reopened.model_health(p['id'])['error_code'] == 'quota'


def test_multiple_planner_rounds_keep_fallback_budget_in_local_state(tmp_path, monkeypatch):
    store = Store(tmp_path / 'rounds.db')
    a, b = profile(store, monkeypatch), profile(store, monkeypatch, 'backup')
    target_requests, provider_calls = [], []
    async def post(url, headers, payload, **kwargs):
        provider_calls.append(payload['model'])
        if payload['model'] == 'primary':
            return httpx.Response(503)
        action = ({'kind': 'probe', 'category': 'sqli', 'param': 'id', 'payload': "'"}
                  if provider_calls.count('backup') == 1 else {'kind': 'finish'})
        return httpx.Response(200, json={'choices': [{'message': {'content': json.dumps({
            **action, 'hypothesis': 'synthetic', 'basis': ['obs_1']})}}]})
    monkeypatch.setattr(ai, '_post_chat_direct', post)
    async def scenario():
        manager = AgentManager(store, transport=httpx.MockTransport(
            lambda r: (target_requests.append(str(r.url)) or httpx.Response(200, text='synthetic'))))
        rid = manager.create(RunSpec(goal='synthetic', request={'url': 'https://example.test/?id=1'},
            max_ai_calls=3, model_profile_ids=[a['id'], b['id']]))
        await manager.tasks[rid]
        assert manager.snapshot(rid)['data']['ai_calls'] == 3
        assert store.model_call_page(rid)['total'] == 3
        await manager.shutdown()
    asyncio.run(scenario())
    assert provider_calls == ['primary', 'backup', 'backup']
    # Existing probe contract: initial observation plus baseline and two probes.
    assert len(target_requests) == 4
