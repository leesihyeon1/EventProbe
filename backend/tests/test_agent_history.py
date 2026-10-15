"""Cursor history is read-only and never calls a target or model."""

import json

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agent_store import Store
from core.agent import AgentManager
from routers import agent_history


def test_event_cursor_and_lazy_body_are_scoped(tmp_path, monkeypatch):
    store = Store(tmp_path / 'events.sqlite3')
    own = store.create({'spec': {'goal': 'synthetic'}})
    other = store.create({'spec': {'goal': 'other'}})
    ids = [store.event(own, 'observation', {'body': f'SECRET_{index}'}) for index in range(4)]
    store.event(other, 'observation', {'body': 'OTHER_SECRET'})

    class Manager:
        def __init__(self):
            self.store = store

        def check_access(self, run_id, principal):
            if principal != 'owner':
                raise PermissionError('denied')

    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    headers = {'x-eventprobe-user': 'owner'}
    base = f'/api/agent/history/runs/{own}/events'

    first = client.get(base, params={'limit': 2}, headers=headers)
    assert first.status_code == 200
    page = first.json()
    assert [event['id'] for event in page['events']] == ids[:2]
    assert page['has_more'] is True
    assert 'SECRET_' not in first.text and 'data' not in page['events'][0]

    second = client.get(base, params={'after': page['cursor'], 'limit': 2}, headers=headers).json()
    assert [event['id'] for event in second['events']] == ids[2:]
    assert second['has_more'] is False
    assert second['cursor'] > page['cursor']

    store.event(own, 'verification', {'status': 'confirmed'})
    appended = client.get(base, params={'after': second['cursor']}, headers=headers).json()
    assert len(appended['events']) == 1
    assert appended['events'][0]['kind'] == 'verification'
    assert client.get(f'{base}/{ids[0]}', headers=headers).json()['data']['body'] == 'SECRET_0'
    assert client.get(f'/api/agent/history/runs/{other}/events/{ids[0]}', headers=headers).status_code == 404
    assert client.get(base, headers={'x-eventprobe-user': 'blocked'}).status_code == 403
    status = client.get(f'/api/agent/history/runs/{own}/status', headers=headers)
    assert status.status_code == 200
    assert status.json()['event_count'] == 5
    assert status.json()['has_plan_event'] is False
    assert status.json()['data']['has_approved_plan'] is False
    assert 'SECRET_' not in status.text
    assert client.get(f'/api/agent/history/runs/{own}/status',
                      headers={'x-eventprobe-user': 'blocked'}).status_code == 403


def test_findings_view_omits_raw_events_and_scopes_owner(tmp_path, monkeypatch):
    store = Store(tmp_path / 'findings.sqlite3')
    rid = store.create({'spec': {'goal': 'synthetic', 'mode': 'normal'}, 'owner': 'owner'})
    store.event(rid, 'observation', {'body': 'PRIVATE_BODY_' + 'x' * 100000})

    class Manager:
        def __init__(self):
            self.store = store

        def check_access(self, run_id, principal):
            if principal != 'owner':
                raise PermissionError('denied')

        def finding_view(self, run_id):
            assert store.get(run_id)
            assert store.finding_events(run_id)
            return {'findings': [{'id': 'finding-1', 'status': 'open'}],
                    'conclusion': {'verdict': 'inconclusive'}}

    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    url = f'/api/agent/history/runs/{rid}/findings'
    response = client.get(url, headers={'x-eventprobe-user': 'owner'})
    assert response.status_code == 200
    body = response.json()
    assert body['findings'][0]['id'] == 'finding-1'
    assert body['event_count'] == 1
    assert body['compact'] is True
    assert 'events' not in body and 'PRIVATE_BODY_' not in response.text
    assert client.get(url, headers={'x-eventprobe-user': 'blocked'}).status_code == 403


def test_map_view_preserves_links_without_raw_values(tmp_path, monkeypatch):
    manager = AgentManager(Store(tmp_path / 'map.sqlite3'))
    request = {'method': 'GET', 'url': 'https://example.test/items?token=PRIVATE_QUERY',
               'params': {'page': 'PRIVATE_PARAM'}, 'headers': {'Authorization': 'PRIVATE_HEADER'},
               'body': 'PRIVATE_REQUEST'}
    rid = manager.store.create({'spec': {'goal': 'synthetic', 'mode': 'normal',
                                         'request': request},
                                'endpoints': {'seed': request}, 'needs_credentials': False})
    manager.store.event(rid, 'action', {'kind': 'probe', 'category': 'xss',
                                        'endpoint_id': 'seed', 'payload': 'PRIVATE_PAYLOAD'}, 's1')
    req_id = manager.store.event(rid, 'request_started', {'request': request}, 's1')
    obs_id = manager.store.event(rid, 'observation', {'request': request, 'request_id': req_id,
                                                      'response': {'status': 200,
                                                                   'body': 'PRIVATE_RESPONSE'}}, 's1')
    manager.store.event(rid, 'verification', {'status': 'confirmed',
                                              'evidence_ids': [obs_id]}, 's1')
    assert 'PRIVATE_RESPONSE' not in str(manager.store.map_events(rid))
    monkeypatch.setattr(manager.store, 'events', lambda _: pytest.fail(
        'map view must not load full observation bodies'))
    monkeypatch.setattr(agent_history, 'get_manager', lambda: manager)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    response = client.get(f'/api/agent/history/runs/{rid}/map')
    assert response.status_code == 200
    body = response.json()
    assert body['compact'] is True and body['view'] == 'map'
    assert body['event_count'] == len(body['events']) == 4
    assert body['events'][2]['data']['request_id'] == req_id
    assert body['events'][3]['data']['evidence_ids'] == [obs_id]
    assert body['data']['endpoints']['seed']['url'] == 'https://example.test/items?token='
    assert body['conclusion']['verdict'] == 'confirmed'
    conclusion = client.get(f'/api/agent/history/runs/{rid}/conclusion')
    assert conclusion.status_code == 200
    assert conclusion.json()['conclusion'] == body['conclusion']
    assert conclusion.json()['view'] == 'timeline'
    for secret in ('PRIVATE_QUERY', 'PRIVATE_PARAM', 'PRIVATE_HEADER',
                   'PRIVATE_REQUEST', 'PRIVATE_PAYLOAD', 'PRIVATE_RESPONSE'):
        assert secret not in response.text
        assert secret not in conclusion.text


def test_cursor_validation_and_missing_run(tmp_path, monkeypatch):
    store = Store(tmp_path / 'events.sqlite3')

    class Manager:
        def __init__(self):
            self.store = store

        def check_access(self, run_id, principal):
            return None

    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    base = '/api/agent/history/runs/missing/events'
    assert client.get(base).status_code == 404
    assert client.get(base, params={'after': -1}).status_code == 422
    assert client.get(base, params={'limit': 101}).status_code == 422


def test_large_history_cursor_has_no_gaps_or_eager_bodies(tmp_path, monkeypatch):
    store = Store(tmp_path / 'large.sqlite3')
    rid = store.create({'spec': {'goal': 'large synthetic'}})
    with store.connect() as db:
        db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?)',
                       [(f'event-{i:04d}', rid, float(i), 'observation', '',
                         json.dumps({'body': 'SYNTHETIC_BODY_' + str(i)})) for i in range(2000)])

    class Manager:
        def __init__(self):
            self.store = store

        def check_access(self, run_id, principal):
            return None

    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    url = f'/api/agent/history/runs/{rid}/events'
    original_get = store.get
    monkeypatch.setattr(store, 'get', lambda _: pytest.fail('status should use a projection'))
    status = client.get(f'/api/agent/history/runs/{rid}/status')
    monkeypatch.setattr(store, 'get', original_get)
    assert status.json()['event_count'] == 2000
    assert len(status.content) < 2048
    ids, cursor = [], 0
    while True:
        page = client.get(url, params={'after': cursor, 'limit': 100}).json()
        ids.extend(item['id'] for item in page['events'])
        assert 'SYNTHETIC_BODY_' not in json.dumps(page)
        cursor = page['cursor']
        if not page['has_more']:
            break
    assert ids == [f'event-{i:04d}' for i in range(2000)]
    assert client.get(f'{url}/event-1999').json()['data']['body'] == 'SYNTHETIC_BODY_1999'


def test_search_pages_all_runs_and_respects_archive_and_owner(tmp_path, monkeypatch):
    store = Store(tmp_path / 'runs.sqlite3')
    large = store.create({'spec': {'goal': 'large private evidence'}, 'owner': 'owner',
                          'synthetic_body': 'SYNTHETIC_PRIVATE_' + 'x' * 1_000_000})
    for index in range(65):
        rid = store.create({'spec': {'goal': f'case {index:02d}'}, 'owner': 'owner',
                            'archived': index == 0})
        if index == 0:
            store.set_run_metadata(rid, '검토 대상', 'access')
    store.create({'spec': {'goal': 'private target'}, 'owner': 'other'})

    class Manager:
        def __init__(self):
            self.store = store

    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    monkeypatch.setattr(agent_history, 'owner_scope_enabled', lambda: True)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    base = '/api/agent/history/runs'
    headers = {'x-eventprobe-user': 'owner'}
    first = client.get(base, params={'limit': 40}, headers=headers).json()
    second = client.get(base, params={'limit': 40, 'offset': 40}, headers=headers).json()
    assert first['total'] == 65 and first['has_more'] is True
    assert len(second['runs']) == 25 and second['has_more'] is False
    ids = [run['id'] for run in first['runs'] + second['runs']]
    assert len(ids) == len(set(ids)) == 65 and large in ids
    assert 'SYNTHETIC_PRIVATE_' not in json.dumps(first)
    assert len(json.dumps(first)) < 20_000
    assert all(run['owner'] == 'owner' for run in first['runs'] + second['runs'])
    archived = client.get(base, params={'archived': 'true'}, headers=headers).json()
    assert archived['total'] == 1 and archived['runs'][0]['goal'] == 'case 00'
    assert archived['runs'][0]['name'] == '검토 대상'
    assert client.get(base, params={'archived': 'true', 'search': '검토 대상',
                                    'category': 'access'}, headers=headers).json()['total'] == 1
    matched = client.get(base, params={'search': 'case 63'}, headers=headers).json()
    assert matched['total'] == 1 and matched['runs'][0]['goal'] == 'case 63'
    assert client.get(base, params={'offset': -1}, headers=headers).status_code == 422
