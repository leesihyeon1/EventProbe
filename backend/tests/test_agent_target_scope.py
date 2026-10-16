"""Request-only scope and same-origin discovery use synthetic HTTP only."""
import asyncio

import httpx
import pytest

from core.agent import AgentManager, _enforce_request_policy
from core.agent_models import RunSpec
from core.agent_store import Store


@pytest.mark.parametrize('scope,expected_count', [('request_only', 1), ('same_origin', 2)])
def test_discovery_scope_is_enforced_before_http(tmp_path, scope, expected_count):
    requests, contexts = [], []

    def response(request):
        requests.append(request)
        return httpx.Response(200, headers={'content-type': 'text/html'},
                              text='<a href="/next?q=1">next</a><a href="https://other.test/">offsite</a>')

    async def planner(ctx):
        contexts.append(ctx)
        discovered = [e for e in ctx['endpoints'] if e['id'] != 'seed']
        base = {'hypothesis': 'synthetic', 'basis': [ctx['observations'][-1]['id']]}
        if discovered and len(contexts) == 1:
            return dict(base, kind='observe', endpoint_id=discovered[0]['id'])
        return dict(base, kind='finish')

    async def scenario():
        manager = AgentManager(Store(tmp_path / 'runs.db'), planner, httpx.MockTransport(response))
        rid = manager.create(RunSpec(goal='synthetic', target_scope=scope, request={'url': 'https://app.test/'}))
        await manager.tasks[rid]
        return manager.snapshot(rid)

    run = asyncio.run(scenario())
    assert run['state'] == 'completed'
    assert len(requests) == expected_count
    assert len(contexts[0]['endpoints']) == expected_count
    assert contexts[0]['target_scope'] == scope
    assert all(r.url.host == 'app.test' for r in requests)


@pytest.mark.parametrize('change', [{'url': 'https://app.test/other'}, {'method': 'POST'}])
def test_request_only_rejects_path_or_method_change(change):
    spec = RunSpec(goal='synthetic', target_scope='request_only', request={'url': 'https://app.test/path?q=1'})
    with pytest.raises(ValueError, match='원본 요청 한정'):
        _enforce_request_policy(spec, {**spec.request.model_dump(), **change})


def test_request_only_allows_query_value_mutation():
    spec = RunSpec(goal='synthetic', target_scope='request_only', request={'url': 'https://app.test/path?q=1'})
    _enforce_request_policy(spec, {**spec.request.model_dump(), 'url': 'https://app.test/path?q=synthetic'})


def test_scope_contract_rejects_unknown_mode():
    with pytest.raises(ValueError):
        RunSpec(goal='synthetic', target_scope='all_domains', request={'url': 'https://app.test/'})
