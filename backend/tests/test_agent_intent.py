"""Task/category regressions using synthetic targets and no external services."""
import asyncio
import sqlite3

import httpx
import pytest

from core.agent import AgentManager, injection_base_value
from core.agent_models import Action, RunSpec
from core.agent_outcome import build_conclusion
from core.agent_store import Store
from core import agent as agent_module
from core.plan import Plan


def run_task(tmp_path, planner, body='synthetic'):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, text=body)

    async def scenario():
        manager = AgentManager(Store(tmp_path / 'runs.db'), planner, httpx.MockTransport(respond))
        rid = manager.create(RunSpec(goal='SQL 인젝션 검사', request={'url': 'https://app.test/?id=1'}))
        await manager.tasks[rid]
        return manager.snapshot(rid)

    return asyncio.run(scenario()), requests


def test_sql_rejects_xss_then_repairs_before_http(tmp_path):
    contexts = []

    async def planner(ctx):
        contexts.append(ctx)
        base = {'hypothesis': 'synthetic', 'basis': [ctx['observations'][-1]['id']]}
        if len(contexts) <= 2:
            return dict(base, kind='probe', category='xss' if len(contexts) == 1 else 'sqli',
                        param='id', payload='<script>bad</script>' if len(contexts) == 1 else "'")
        return dict(base, kind='finish')

    run, requests = run_task(tmp_path, planner)
    assert contexts[0]['allowed_categories'] == ['sqli']
    assert contexts[1]['planner_feedback']['code'] == 'category_out_of_scope'
    assert len(requests) == 4
    assert all('script' not in str(r.url) for r in requests)
    assert run['conclusion']['requested_checks'] == [{'category': 'sqli', 'status': 'tested'}]


def test_login_page_does_not_substitute_query_test_for_post_form(tmp_path):
    async def planner(ctx):
        pytest.fail('Missing login input must be detected before planning')

    run, requests = run_task(tmp_path, planner,
                            '<form method="post"><input name="user"><input type="password" name="password"></form>')
    assert len(requests) == 1 and requests[0].method == 'GET'
    assert run['state'] == 'paused'
    assert run['conclusion']['stop_code'] == 'input_required'
    assert run['conclusion']['completion'] == 'partial'
    assert run['conclusion']['requested_checks'] == [{'category': 'sqli', 'status': 'not_tested'}]


def test_legacy_wrong_category_cannot_complete_sql_goal():
    events = [{'id': 'o', 'kind': 'observation', 'step_id': 's', 'data': {}},
              {'id': 'a', 'kind': 'action', 'step_id': 's', 'data': {'kind': 'probe', 'category': 'xss'}},
              {'id': 'v', 'kind': 'verification', 'step_id': 's',
               'data': {'status': 'inconclusive', 'evidence_ids': ['o']}}]
    result = build_conclusion({'spec': {'goal': 'SQL injection'}}, events, 'completed')
    assert result['completion'] == 'partial'
    assert 'sqli' in result['text'] and '미실행' in result['text']


def test_plan_scope_rejects_xss_for_sql_task():
    spec = RunSpec(goal='SQL injection', request={'url': 'https://app.test/?id=1'})
    plan = Plan.model_validate({'entry': 'p', 'steps': [{'action_id': 'p', 'action': {
        'kind': 'probe', 'hypothesis': 'synthetic', 'category': 'xss', 'param': 'id', 'payload': 'x'}}]})
    with pytest.raises(ValueError, match='허용되지 않은 계획'):
        agent_module._validate_plan_scope(spec, plan)


def test_repeated_wrong_category_stops_without_attack_requests(tmp_path):
    async def planner(ctx):
        return {'kind': 'probe', 'hypothesis': 'synthetic', 'category': 'xss', 'param': 'id',
                'payload': 'x', 'basis': [ctx['observations'][-1]['id']]}
    run, requests = run_task(tmp_path, planner)
    assert len(requests) == 1
    assert run['data']['ai_calls'] == 3
    assert run['conclusion']['completion'] == 'partial'


def test_suspicious_confirmation_is_not_discarded(tmp_path, monkeypatch):
    analyze = agent_module.analyze_response
    def valid_analysis(*args, **kwargs):
        result = analyze(*args, **kwargs)
        result['validity'] = {'warnings': []}
        return result
    monkeypatch.setattr(agent_module, 'analyze_response', valid_analysis)
    monkeypatch.setattr(agent_module.confirm, 'decide', lambda *args: {
        'techniques': [], 'observations': [{'level': 'suspicious', 'name': 'synthetic differential'}]})
    calls = []
    async def planner(ctx):
        calls.append(ctx)
        return {'kind': 'confirm' if len(calls) == 1 else 'finish', 'hypothesis': 'synthetic',
                'category': 'sqli', 'param': 'id', 'basis': [ctx['observations'][-1]['id']]}
    run, requests = run_task(tmp_path, planner)
    assert len(requests) > 4
    assert run['conclusion']['verdict'] == 'suspicious'
    assert run['conclusion']['counts']['confirmed'] == 0


@pytest.mark.parametrize('seed,location', [
    ({'url': 'https://app.test/?user=admin'}, 'param'),
    ({'url': 'https://app.test/', 'body': 'user=admin&password=test'}, 'body'),
    ({'url': 'https://app.test/', 'body': '{"user":"admin","password":"test"}'}, 'body'),
])
def test_confirmation_preserves_original_input(seed, location):
    action = Action(kind='confirm', hypothesis='synthetic', category='sqli', location=location, param='user')
    assert injection_base_value(seed, action) == 'admin'


@pytest.mark.parametrize('parameterized', [False, True])
def test_repeated_sql_probe_recovers_with_local_differential_fixture(tmp_path, parameterized):
    database = sqlite3.connect(':memory:')
    database.execute('CREATE TABLE users (name TEXT, details TEXT)')
    database.execute('INSERT INTO users VALUES (?, ?)', ('alpha', 'A' * 120))
    requests = []

    def respond(request):
        requests.append(request)
        value = request.url.params.get('user', '')
        try:
            if parameterized:
                rows = database.execute('SELECT details FROM users WHERE name=?', (value,)).fetchall()
            else:
                rows = database.execute(f"SELECT details FROM users WHERE name='{value}'").fetchall()
        except sqlite3.Error:
            return httpx.Response(500, text='query failed')
        return httpx.Response(200, text='\n'.join(row[0] for row in rows))

    async def planner(ctx):
        return {'kind': 'probe', 'hypothesis': 'synthetic', 'category': 'sqli',
                'param': 'user', 'payload': "'", 'basis': [ctx['observations'][-1]['id']]}

    async def scenario():
        manager = AgentManager(Store(tmp_path / 'runs.db'), planner, httpx.MockTransport(respond))
        rid = manager.create(RunSpec(goal='SQL injection', request={'url': 'https://app.test/?user=alpha'}))
        await manager.tasks[rid]
        return manager.snapshot(rid)

    try:
        run = asyncio.run(scenario())
    finally:
        database.close()
    assert run['data']['requests'] <= 24
    assert len(requests) == run['data']['requests']
    assert any(e['kind'] == 'planner_recovery' for e in run['events'])
    assert any(e['kind'] == 'action' and e['data']['kind'] == 'confirm' for e in run['events'])
    assert run['conclusion']['verdict'] == ('inconclusive' if parameterized else 'suspicious')
    assert run['conclusion']['counts']['confirmed'] == 0
