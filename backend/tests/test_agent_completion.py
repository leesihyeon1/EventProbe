"""Bounded recovery and local conclusions, with no real target/provider calls."""
import asyncio
import json

import httpx
import pytest

from core.agent import AgentManager, PlannerServiceError, PlannerOutputError
from core.agent_models import RunSpec
from core.agent_outcome import build_conclusion
from core.agent_store import Store


def execute(tmp_path, choose, **limits):
    async def scenario():
        manager = AgentManager(Store(tmp_path / 'runs.db'), choose,
                               httpx.MockTransport(lambda r: httpx.Response(200, text='INTERNAL_BODY_SECRET')))
        run_id = manager.create(RunSpec(goal='synthetic', request={'url': 'https://app.test/?id=1'}, **limits))
        await manager.tasks[run_id]
        return manager.snapshot(run_id)
    return asyncio.run(scenario())


def action(ctx, kind='finish', **fields):
    return {'kind': kind, 'hypothesis': 'synthetic', 'basis': [ctx['observations'][-1]['id']], **fields}


def test_duplicate_gets_feedback_then_progresses_without_duplicate_http(tmp_path):
    contexts = []
    async def choose(ctx):
        contexts.append(ctx)
        if len(contexts) == 1:
            return action(ctx, 'observe')
        if len(contexts) == 2:
            return action(ctx, 'probe', category='sqli', param='id', payload="'")
        return action(ctx)
    run = execute(tmp_path, choose)
    assert run['state'] == 'completed'
    assert run['data']['requests'] == 4
    assert contexts[1]['planner_feedback']['code'] == 'duplicate_action'
    assert sum(e['kind'] == 'planner_retry' for e in run['events']) == 1
    assert run['events'][-1]['kind'] == 'conclusion'
    assert run['conclusion']['verdict'] == 'inconclusive'
    assert 'INTERNAL_BODY_SECRET' not in json.dumps(run['conclusion'])


def test_permanent_repetition_is_partial_not_completed(tmp_path):
    async def choose(ctx):
        return action(ctx, 'observe')
    run = execute(tmp_path, choose)
    assert run['state'] == 'paused'
    assert run['data']['ai_calls'] == 3
    assert run['data']['requests'] == 1
    assert run['conclusion']['completion'] == 'partial'
    assert run['conclusion']['stop_code'] == 'planner_stalled'


def test_recovery_never_exceeds_ai_budget(tmp_path):
    async def choose(ctx):
        return action(ctx, 'observe')
    run = execute(tmp_path, choose, max_ai_calls=1)
    assert run['state'] == 'limited'
    assert run['data']['ai_calls'] == 1
    assert run['conclusion']['completion'] == 'partial'


@pytest.mark.parametrize('error', [PlannerServiceError(503), PlannerOutputError('bad format'),
                                 httpx.ConnectError('provider connection')])
def test_retryable_provider_failure_recovers_without_replaying_http(tmp_path, error):
    calls = []
    async def choose(ctx):
        calls.append(ctx)
        if len(calls) == 1:
            raise error
        return action(ctx)
    run = execute(tmp_path, choose)
    assert run['state'] == 'completed'
    assert len(calls) == 2 and run['data']['requests'] == 1


def test_provider_auth_failure_does_not_retry(tmp_path):
    async def choose(ctx):
        raise PlannerServiceError(401)
    run = execute(tmp_path, choose)
    assert run['state'] == 'paused' and run['data']['ai_calls'] == 1
    assert run['conclusion']['completion'] == 'partial'


def test_missing_basis_can_be_repaired(tmp_path):
    calls = []
    async def choose(ctx):
        calls.append(ctx)
        return {'kind': 'finish', 'hypothesis': 'end'} if len(calls) == 1 else action(ctx)
    run = execute(tmp_path, choose)
    assert run['state'] == 'completed' and len(calls) == 2
    assert calls[1]['planner_feedback']['code'] == 'missing_evidence_basis'


def test_unaffordable_action_is_replanned_before_any_partial_probe(tmp_path):
    calls = []
    async def choose(ctx):
        calls.append(ctx)
        if len(calls) == 1:
            return action(ctx, 'confirm', category='sqli', param='id')
        return action(ctx, 'probe', category='sqli', param='id', payload="'") if len(calls) == 2 else action(ctx)
    run = execute(tmp_path, choose, max_requests=5)
    assert run['state'] == 'completed'
    assert run['data']['requests'] == 4
    assert calls[1]['planner_feedback']['code'] == 'insufficient_request_budget'
    assert not any(e['kind'] == 'action' and e['data']['kind'] == 'confirm' for e in run['events'])


def test_budget_exhaustion_still_has_local_conclusion(tmp_path):
    async def choose(ctx):
        raise AssertionError('No AI calls after request budget is exhausted')
    run = execute(tmp_path, choose, max_requests=1)
    assert run['state'] == 'limited'
    assert run['conclusion']['verdict'] == 'inconclusive'
    assert run['conclusion']['observation_count'] == 1
    assert run['events'][-1]['kind'] == 'conclusion'


def test_conclusion_keeps_established_evidence_when_execution_is_limited():
    events = [{'id': 'obs', 'kind': 'observation', 'step_id': 's', 'data': {'body': 'SECRET'}},
              {'id': 'v', 'kind': 'verification', 'step_id': 's',
               'data': {'status': 'confirmed', 'evidence_ids': ['obs']}},
              {'id': 'a2', 'kind': 'action', 'step_id': 's2', 'data': {'kind': 'probe'}}]
    result = build_conclusion({'reason': 'limit'}, events, 'limited')
    assert result['verdict'] == 'confirmed' and result['completion'] == 'partial'
    assert result['evidence_ids'] == ['obs'] and result['unfinished_steps'] == ['s2']
    assert 'SECRET' not in json.dumps(result)


def test_legacy_repeat_and_unlinked_verdict_are_not_success():
    events = [{'id': 'v', 'kind': 'verification', 'step_id': 's',
               'data': {'status': 'confirmed', 'evidence_ids': ['missing']}}]
    result = build_conclusion({'reason': '동일 행동 반복을 감지해 종료했습니다.'}, events, 'completed')
    assert result['completion'] == 'partial'
    assert result['verdict'] == 'inconclusive'


def test_http_error_is_not_replayed_and_has_conclusion(tmp_path):
    async def scenario():
        calls = []
        def handler(req):
            calls.append(req)
            raise httpx.ReadTimeout('synthetic')
        manager = AgentManager(Store(tmp_path / 'timeout.db'),
                               transport=httpx.MockTransport(handler))
        rid = manager.create(RunSpec(goal='t', request={'url': 'https://app.test/'}))
        await manager.tasks[rid]
        run = manager.snapshot(rid)
        assert len(calls) == 1 and run['state'] == 'paused'
        assert run['conclusion']['completion'] == 'partial'
        assert run['events'][-1]['kind'] == 'conclusion'
    asyncio.run(scenario())


def test_existing_run_api_exposes_local_conclusion_without_new_execution(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routers import agent as routes

    async def unused(ctx):
        raise AssertionError('Reading a conclusion must never invoke a model')
    manager = AgentManager(Store(tmp_path / 'api.db'), unused)
    rid = manager.store.create({'spec': {'goal': 'synthetic'}, 'needs_credentials': False,
                                'reason': '동일 행동 반복을 감지해 종료했습니다.'})
    data = manager.store.get(rid)['data']
    manager.store.update(rid, data, 'completed')
    monkeypatch.setattr(routes, 'get_manager', lambda: manager)
    app = FastAPI()
    app.include_router(routes.router)
    with TestClient(app) as client:
        response = client.get('/api/agent/runs/' + rid)
    assert response.status_code == 200
    assert response.json()['conclusion']['completion'] == 'partial'
    assert response.json()['conclusion']['verdict'] == 'inconclusive'
    assert not manager.tasks
