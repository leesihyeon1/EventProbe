"""Browser discoveries remain scoped, budgeted and local."""
import asyncio
import json
from urllib.parse import urlsplit

from core import agent_browser_recon
from core.agent import AgentManager, _tool_summary, discover
from core.agent_models import RunSpec
from core.agent_recon import planner_view, snapshot
from core.agent_store import Store
from core.agent_view import map_event


def test_browser_launch_falls_back_to_installed_channel(tmp_path, monkeypatch):
    class BrowserType:
        executable_path = str(tmp_path / 'missing')

        def launch(self, **options):
            if options.get('channel') == 'msedge':
                return 'edge-browser'
            raise RuntimeError('unavailable')

    class Playwright:
        chromium = BrowserType()

    browser, engine = agent_browser_recon._launch(Playwright())
    assert (browser, engine) == ('edge-browser', 'edge')


def test_browser_discovery_is_scoped_and_redacted(tmp_path, monkeypatch):
    seen = {}

    async def capture(url, pages, limit, timeout, permit, reserve):
        seen.update(url=url, pages=pages, limit=limit,
                    permits=[permit('GET', 'https://fixture.test/api/search')])
        return {'requests': [
            {'method': 'GET', 'url': 'https://fixture.test/api/search?token=PRIVATE_VALUE',
             'resource_type': 'fetch', 'status': 200, 'technologies': ['nginx'], 'server': 'nginx'},
            {'method': 'POST', 'url': 'https://fixture.test/api/delete', 'resource_type': 'fetch'},
            {'method': 'GET', 'url': 'https://outside.test/leak', 'resource_type': 'fetch'},
        ]}

    monkeypatch.setattr(agent_browser_recon, 'capture', capture)
    manager = AgentManager(Store(tmp_path / 'runs.db'))
    spec = RunSpec(goal='API 탐색', request={'url': 'https://fixture.test/'}, max_requests=24)
    seed = spec.request.model_dump()
    data = {'spec': spec.model_dump(), 'requests': 1, 'steps': 1,
            'endpoints': {'seed': seed}, 'elapsed': 0}
    run_id = manager.store.create(data)

    def save():
        manager.store.update(run_id, data, 'running')

    observation = {'response': {'headers': {'content-type': 'text/html'}}}
    asyncio.run(manager._browser_recon(run_id, spec, data, observation, save, float('inf')))
    events = manager.store.events(run_id)
    discovered = [e for e in events if e['kind'] == 'browser_discovery']
    assert len(discovered) == 1
    assert seen['limit'] == 8 and seen['permits'] == [True]
    assert data['requests'] == 2
    assert len(data['endpoints']) == 2
    assert snapshot(data, events)['browser_endpoint_count'] == 1
    assert _tool_summary(events, data['requests'])['http_unresolved'] == 1  # Seed reserved separately.
    public = json.dumps([map_event(e) for e in events])
    assert 'PRIVATE_VALUE' not in public and 'outside.test' not in public
    context = planner_view({'endpoints': [{'id': eid, 'method': req['method'],
                                         'path': urlsplit(req['url']).path} for eid, req in data['endpoints'].items()]})
    assert 'fixture.test' not in json.dumps(context)
    assert 'PRIVATE_VALUE' not in json.dumps(context)


def test_browser_recon_skips_request_only_and_mock_transport(tmp_path, monkeypatch):
    calls = []

    async def capture(*args):
        calls.append(args)
        return {'requests': []}

    monkeypatch.setattr(agent_browser_recon, 'capture', capture)
    manager = AgentManager(Store(tmp_path / 'runs.db'), transport=object())
    spec = RunSpec(goal='요청 검사', request={'url': 'https://fixture.test/'}, target_scope='request_only')
    data = {'requests': 1, 'steps': 1, 'endpoints': {'seed': spec.request.model_dump()}}
    run_id = manager.store.create(data)
    asyncio.run(manager._browser_recon(run_id, spec, data,
                {'response': {'headers': {'content-type': 'text/html'}}}, lambda: None, float('inf')))
    assert not calls
    assert 'browser_recon_attempted' not in data


def test_rendered_dom_login_form_is_registered_without_submitting(tmp_path, monkeypatch):
    async def capture(url, pages, limit, timeout, permit, reserve):
        assert permit('POST', 'https://fixture.test/Login.asp')
        return {'requests': [], 'forms': [{
            'method': 'POST', 'url': 'https://fixture.test/Login.asp',
            'source_url': 'https://fixture.test/', 'params': {},
            'headers': {'content-type': 'application/x-www-form-urlencoded'},
            'body': 'tfUName=&tfUPass=&csrf=LOCAL_ONLY_TOKEN',
            'field_schema': [{'name': 'tfUName', 'type': 'text', 'required': True},
                             {'name': 'tfUPass', 'type': 'password', 'required': True},
                             {'name': 'csrf', 'type': 'hidden', 'required': False}]}]}

    monkeypatch.setattr(agent_browser_recon, 'capture', capture)
    manager = AgentManager(Store(tmp_path / 'runs.db'))
    spec = RunSpec(goal='로그인 SQL 검증', request={'url': 'https://fixture.test/'},
                   target_scope='same_origin', allow_write_methods=True, max_requests=24)
    data = {'spec': spec.model_dump(), 'requests': 1, 'steps': 1,
            'endpoints': {'seed': spec.request.model_dump()}, 'elapsed': 0}
    run_id = manager.store.create(data)
    asyncio.run(manager._browser_recon(run_id, spec, data,
                {'response': {'headers': {'content-type': 'text/html'}}},
                lambda: manager.store.update(run_id, data, 'running'), float('inf')))
    forms = [(eid, request) for eid, request in data['endpoints'].items() if request['method'] == 'POST']
    assert len(forms) == 1
    assert 'tfUName=' in forms[0][1]['body']
    assert forms[0][0] in data['form_sources']
    assert data['form_schema'][forms[0][0]]['fields'][1]['type'] == 'password'
    assert 'LOCAL_ONLY_TOKEN' not in str(data['form_schema'])
    assert data['requests'] == 1
    assert any(e['kind'] == 'browser_discovery' and e['data']['resource_type'] == 'form'
               for e in manager.store.events(run_id))


def test_browser_request_is_durable_before_capture_returns(tmp_path, monkeypatch):
    manager = AgentManager(Store(tmp_path / 'runs.db'))
    spec = RunSpec(goal='탐색', request={'url': 'https://fixture.test/'},
                   target_scope='same_origin', max_requests=24)
    data = {'spec': spec.model_dump(), 'requests': 1, 'steps': 1,
            'endpoints': {'seed': spec.request.model_dump()}, 'elapsed': 0}
    run_id = manager.store.create(data)

    async def capture(url, pages, limit, timeout, permit, reserve):
        rid = reserve('GET', 'https://fixture.test/api', 'fetch')
        assert rid
        assert manager.store.get(run_id)['data']['requests'] == 2
        assert manager.store.events(run_id)[-1]['id'] == rid
        assert reserve('POST', 'https://fixture.test/delete', 'fetch') is None
        return {'requests': [{'method': 'GET', 'url': 'https://fixture.test/api',
                              'resource_type': 'fetch', 'status': 200, 'request_id': rid}]}

    monkeypatch.setattr(agent_browser_recon, 'capture', capture)
    asyncio.run(manager._browser_recon(run_id, spec, data,
                {'response': {'headers': {'content-type': 'text/html'}}},
                lambda: manager.store.update(run_id, data, 'running'), float('inf')))
    assert data['requests'] == 2
    assert sum(e['kind'] == 'browser_request' for e in manager.store.events(run_id)) == 1


def test_login_form_candidate_status_tracks_evidence_not_http_status():
    from core.agent_recon import snapshot

    request = {'method': 'POST', 'url': 'https://fixture.test/Login.asp',
               'headers': {'content-type': 'application/x-www-form-urlencoded'},
               'body': 'tfUName=&tfUPass='}
    data = {'endpoints': {'login': request}, 'requests': 0, 'steps': 0}
    form = snapshot(data, [], 'paused')['form_candidates'][0]
    assert form['login'] is True and form['status'] == 'untested'
    actions = [{'kind': 'action', 'step_id': 's1', 'data': {'kind': 'confirm',
                'endpoint_id': 'login', 'confirmation_profile': 'sql_login'}}]
    assert snapshot(data, actions, 'paused')['form_candidates'][0]['status'] == 'interrupted'
    verified = actions + [{'kind': 'verification', 'step_id': 's1',
                           'data': {'status': 'confirmed', 'evidence_ids': ['missing']}}]
    assert snapshot(data, verified, 'paused')['form_candidates'][0]['status'] == 'inconclusive'


def test_html_discovery_keeps_field_types_without_schema_values():
    request = {'method': 'GET', 'url': 'https://fixture.test/', 'params': {},
               'headers': {}, 'body': ''}
    response = {'headers': {'content-type': 'text/html'},
                'body': '<form method="post" action="/Login.asp">'
                        '<input name="user" required><input name="pass" type="password" '
                        'value="SECRET_PASSWORD"><input name="csrf" type="hidden" '
                        'value="SECRET_TOKEN"></form>'}
    form = discover(request, response, include_post=True)[0]
    assert form['field_schema'] == [
        {'name': 'user', 'type': 'text', 'required': True},
        {'name': 'pass', 'type': 'password', 'required': False},
        {'name': 'csrf', 'type': 'hidden', 'required': False}]
    assert 'SECRET_PASSWORD' not in str(form['field_schema'])
    assert 'SECRET_TOKEN' not in str(form['field_schema'])
