"""The adaptive workflow uses local evidence and a structured model view."""
import asyncio
import json

import httpx

from core import agent as module
from core.agent import AgentManager
from core.agent_models import RunSpec
from core.agent_recon import planner_view
from core.agent_store import Store


def test_public_planner_view_drops_response_and_server_values():
    context = {'goal_purpose': 'injection', 'goal': 'SECRET_GOAL',
               'endpoints': [{'id': 'seed', 'path': '/accounts/123', 'method': 'GET',
                              'query_fields': ['q'], 'body_fields': []}],
               'observations': [{'id': 'o', 'path': '/accounts/123', 'status': 200,
                                 'signals': [{'name': 'SECRET_RESPONSE'}],
                                 'untrusted_response_excerpt': 'SECRET_RESPONSE'}],
               'previous_actions': [{'kind': 'probe', 'category': 'xss', 'payload': 'SECRET_PAYLOAD',
                                     'hypothesis': 'SECRET_HYPOTHESIS'}],
               'verification_summary': [{'status': 'suspicious', 'category': 'xss', 'endpoint_id': 'seed'}],
               'recon': {'phase': 'testing', 'endpoint_count': 1, 'technologies': ['nginx',
                          'SECRET_TECH'], 'server_headers': ['SECRET_SERVER']}}
    view = planner_view(context)
    rendered = json.dumps(view)
    assert all(secret not in rendered for secret in ('SECRET_GOAL', 'SECRET_RESPONSE',
                                                      'SECRET_PAYLOAD', 'SECRET_HYPOTHESIS',
                                                      'SECRET_SERVER', 'SECRET_TECH'))
    assert view['endpoints'][0]['path'] == '/accounts/{id}'
    assert view['recon']['technologies'] == ['nginx']
    assert view['verified_results'][0]['status'] == 'suspicious'


def test_external_planner_serialization_uses_allowlisted_view(monkeypatch):
    outbound = []

    async def post_chat(url, headers, payload, tries=1):
        outbound.append(payload)
        return httpx.Response(200, json={'choices': [{'message': {'content': json.dumps({
            'kind': 'finish', 'hypothesis': 'done', 'basis': ['obs_1']})}}]})

    monkeypatch.setattr(module.ai, 'is_enabled', lambda: True)
    monkeypatch.setattr(module.ai, '_model', lambda: 'fixture-model')
    monkeypatch.setattr(module.ai, '_base_url', lambda: 'https://model.fixture')
    monkeypatch.setattr(module.ai, '_api_key', lambda: 'fixture-key')
    monkeypatch.setattr(module.ai, '_post_chat', post_chat)
    action = asyncio.run(module.choose_action({
        'goal': 'SECRET_GOAL', 'goal_purpose': 'injection', 'export_mode': 'structured',
        'observations': [{'id': 'o', 'path': '/private/123', 'status': 200,
                          'untrusted_response_excerpt': 'SECRET_RESPONSE'}],
        'previous_actions': [{'payload': 'SECRET_PAYLOAD'}],
        'recon': {'technologies': ['nginx'], 'server_headers': ['SECRET_SERVER']}}))
    serialized = json.dumps(outbound[0])
    assert action.basis == ['o']
    assert 'obs_1' in serialized
    assert '"id": "o"' not in serialized
    assert all(secret not in serialized for secret in
               ('SECRET_GOAL', 'SECRET_RESPONSE', 'SECRET_PAYLOAD', 'SECRET_SERVER'))
    assert 'nginx' in serialized


def test_recon_plan_probe_retest_and_replan(tmp_path, monkeypatch):
    requests, contexts = [], []

    def reply(request):
        requests.append(request)
        if request.url.path == '/':
            return httpx.Response(200, headers={'content-type': 'text/html',
                                                  'server': 'nginx PRIVATE_SERVER'},
                                  text='<a href="/search?q=alpha">Search</a> PRIVATE_RESPONSE')
        return httpx.Response(200, text='PRIVATE_RESPONSE')

    async def planner(context):
        contexts.append(context)
        wire = json.dumps(context)
        assert 'fixture.test' not in wire and 'PRIVATE_' not in wire
        assert context['export_mode'] == 'structured'
        assert context['recon']['technologies'] == ['nginx']
        assert len(context['endpoints']) == 2
        basis = [context['observations'][-1]['id']]
        if len(contexts) == 1:
            return {'kind': 'probe', 'hypothesis': 'test', 'category': 'xss',
                    'endpoint_id': next(e['id'] for e in context['endpoints'] if e['id'] != 'seed'),
                    'param': 'q', 'payload': '<svg/onload=alert(1)>', 'basis': basis}
        return {'kind': 'finish', 'hypothesis': 'bounded checks complete', 'basis': basis}

    monkeypatch.setattr(module, 'choose_action', planner)
    monkeypatch.setattr(module, 'probe_verdict', lambda category, obs: {
        'status': 'suspicious', 'confirmed': [], 'evidence_ids': [o['id'] for o in obs]})

    async def scenario():
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        rid = manager.create(RunSpec(goal='XSS 검사', request={'url': 'https://fixture.test/'},
                                     max_ai_calls=2, max_requests=20))
        await manager.tasks[rid]
        return manager.snapshot(rid), manager.map_view(rid)

    run, site_map = asyncio.run(scenario())
    actions = [event['data'] for event in run['events'] if event['kind'] == 'action']
    assert [a['kind'] for a in actions] == ['observe', 'observe', 'probe', 'confirm', 'finish']
    assert run['data']['ai_calls'] == 2
    assert run['state'] == 'completed'
    assert run['recon']['technologies'] == ['nginx']
    assert run['recon']['server_headers'] == ['nginx PRIVATE_SERVER']
    assert site_map['recon']['technologies'] == ['nginx']
    assert 'PRIVATE_RESPONSE' not in json.dumps(site_map)
    assert contexts[1]['verified_results'][0]['status'] == 'suspicious'
    assert any(e['kind'] == 'planner_recovery' and e['data']['code'] == 'suspicious_probe'
               for e in run['events'])
    assert all(request.url.host == 'fixture.test' for request in requests)


def test_recon_reads_are_bounded_before_ai_planning(tmp_path, monkeypatch):
    visited, contexts = [], []

    def reply(request):
        visited.append(request.url.path)
        if request.url.path == '/':
            return httpx.Response(200, headers={'content-type': 'text/html'}, text=''.join(
                f'<a href="/page/{i}">Page</a>' for i in range(7)))
        return httpx.Response(200, text='page')

    async def planner(context):
        contexts.append(context)
        return {'kind': 'finish', 'hypothesis': 'bounded recon',
                'basis': [context['observations'][-1]['id']]}

    monkeypatch.setattr(module, 'choose_action', planner)

    async def scenario():
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        rid = manager.create(RunSpec(goal='XSS 검사', request={'url': 'https://fixture.test/'},
                                     max_requests=24, max_steps=8, max_ai_calls=1))
        await manager.tasks[rid]
        return manager.snapshot(rid)

    run = asyncio.run(scenario())
    assert len(visited) == 4  # Seed plus three bounded read-only pages.
    assert contexts[0]['recon']['endpoint_count'] == 8
    assert contexts[0]['recon']['unobserved_get_count'] == 4
    assert run['recon']['observed_endpoint_count'] == 4
