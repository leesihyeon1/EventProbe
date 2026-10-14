"""Cursor history is read-only and never calls a target or model."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agent_store import Store
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
    assert 'SECRET_' not in status.text
    assert client.get(f'/api/agent/history/runs/{own}/status',
                      headers={'x-eventprobe-user': 'blocked'}).status_code == 403


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


def test_search_pages_all_runs_and_respects_archive_and_owner(tmp_path, monkeypatch):
    store = Store(tmp_path / 'runs.sqlite3')
    for index in range(65):
        store.create({'spec': {'goal': f'case {index:02d}'}, 'owner': 'owner',
                      'archived': index == 0})
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
    assert first['total'] == 64 and first['has_more'] is True
    assert len(second['runs']) == 24 and second['has_more'] is False
    ids = [run['id'] for run in first['runs'] + second['runs']]
    assert len(ids) == len(set(ids)) == 64
    assert all(run['owner'] == 'owner' for run in first['runs'] + second['runs'])
    archived = client.get(base, params={'archived': 'true'}, headers=headers).json()
    assert archived['total'] == 1 and archived['runs'][0]['goal'] == 'case 00'
    matched = client.get(base, params={'search': 'case 63'}, headers=headers).json()
    assert matched['total'] == 1 and matched['runs'][0]['goal'] == 'case 63'
    assert client.get(base, params={'offset': -1}, headers=headers).status_code == 422
