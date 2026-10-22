"""Global asset index must preserve provenance without storing request values."""

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agent_store import Store
from core.agent_view import map_request
from routers import agent_history


def _request(url):
    return {'method': 'POST', 'url': url,
            'headers': {'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': 'PRIVATE_HEADER'},
            'body': 'tfUName=PRIVATE_USER&tfUPass=PRIVATE_PASSWORD'}


def test_global_assets_group_runs_scope_and_redact(tmp_path, monkeypatch):
    path = tmp_path / 'assets.sqlite3'
    store = Store(path)
    shared = _request('https://example.test/Login.asp?RetURL=PRIVATE_ONE')
    one = store.create({'spec': {'goal': 'first'}, 'owner': 'alice',
                        'endpoints': {'seed': shared}})
    two = store.create({'spec': {'goal': 'second'}, 'owner': 'alice',
                        'endpoints': {'login': _request('https://example.test/Login.asp?RetURL=PRIVATE_TWO')}})
    other = store.create({'spec': {'goal': 'other'}, 'owner': 'bob',
                          'endpoints': {'seed': shared}})
    assert len(store.asset_page(owner='alice')['assets']) == 1
    assert store.asset_page(owner='alice')['assets'][0]['run_count'] == 2
    assert store.asset_page(owner='bob')['assets'][0]['run_count'] == 1

    class Manager:
        def __init__(self):
            self.store = store

    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    monkeypatch.setattr(agent_history, 'owner_scope_enabled', lambda: True)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    url = '/api/agent/history/assets'
    response = client.get(url, headers={'x-eventprobe-user': 'alice'})
    assert response.status_code == 200
    asset = response.json()['assets'][0]
    assert asset['run_count'] == 2
    assert {r['id'] for r in asset['runs']} == {one, two}
    assert asset['query'] == ['RetURL']
    assert asset['fields'] == ['tfUName', 'tfUPass']
    for private in ('PRIVATE_ONE', 'PRIVATE_TWO', 'PRIVATE_HEADER',
                    'PRIVATE_USER', 'PRIVATE_PASSWORD', other):
        assert private not in response.text
    assert client.get(url, params={'search': 'Login.asp'},
                      headers={'x-eventprobe-user': 'alice'}).json()['total'] == 1
    assert client.get(url, params={'search': 'missing'},
                      headers={'x-eventprobe-user': 'alice'}).json()['total'] == 0
    focused = client.get(url, params={'asset_id': asset['id']},
                         headers={'x-eventprobe-user': 'alice'}).json()
    assert focused['total'] == 1 and focused['assets'][0]['id'] == asset['id']
    assert client.get(url, params={'asset_id': '0' * 64},
                      headers={'x-eventprobe-user': 'alice'}).json()['total'] == 0
    assert client.get(url, params={'limit': 101}).status_code == 422

    store.set_archived(one, True)
    assert store.asset_page(owner='alice')['assets'][0]['run_count'] == 1
    assert store.asset_page(owner='alice', archived=True)['assets'][0]['runs'][0]['id'] == one
    assert Store(path).asset_page(owner='alice')['assets'][0]['run_count'] == 1
    store.delete(two)
    assert store.asset_page(owner='alice')['total'] == 0
    store.delete(one)
    assert store.asset_page()['total'] == 1
    store.delete(other)
    assert store.asset_page()['total'] == 0


def test_legacy_assets_backfilled_and_updates_replace_refs(tmp_path):
    path = tmp_path / 'legacy.sqlite3'
    store = Store(path)
    with store.connect() as db:
        db.execute("DELETE FROM store_migrations WHERE name='asset_index_v1'")
        db.execute('DELETE FROM asset_refs')
        db.execute('DELETE FROM assets')
        db.execute('INSERT INTO runs VALUES (?,?,?,?,?)',
                   ('legacy', 1, 1, 'paused', json.dumps({'owner': 'alice',
                    'endpoints': {'seed': _request('https://example.test/old?token=PRIVATE')}})))
    store = Store(path)
    assert store.asset_page(owner='alice')['assets'][0]['path'] == '/old'
    data = store.get('legacy')['data']
    data['endpoints'] = {'seed': _request('https://example.test/new?token=PRIVATE')}
    store.update('legacy', data)
    assert [asset['path'] for asset in store.asset_page(owner='alice')['assets']] == ['/new']


def test_map_request_exposes_only_form_field_names():
    projected = map_request(_request('https://example.test/Login.asp?RetURL=PRIVATE_QUERY'))
    assert projected['body_fields'] == ['tfUName', 'tfUPass']
    for value in ('PRIVATE_QUERY', 'PRIVATE_USER', 'PRIVATE_PASSWORD', 'PRIVATE_HEADER'):
        assert value not in json.dumps(projected)


def test_asset_period_uses_scoped_traffic_timestamps(tmp_path, monkeypatch):
    store = Store(tmp_path / 'asset-period.sqlite3')
    request = {'method': 'GET', 'url': 'https://example.test/agent'}
    run_id = store.create({'owner': 'alice', 'spec': {'goal': 'period'},
                           'endpoints': {'seed': request}})
    store.event(run_id, 'observation', {'request': request, 'response': {'status': 200}}, 's1')
    store.record_manual_traffic({'method': 'GET', 'url': 'https://example.test/manual'},
                                200, owner='alice')
    store.record_manual_traffic({'method': 'GET', 'url': 'https://example.test/bob'},
                                200, owner='bob')
    with store.connect() as db:
        db.execute('UPDATE traffic_index SET created=100 WHERE run_id=?', (run_id,))
        db.execute("UPDATE manual_traffic SET created=200 WHERE owner='alice'")
        db.execute("UPDATE manual_traffic SET created=300 WHERE owner='bob'")

    class Manager:
        def __init__(self):
            self.store = store

    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    monkeypatch.setattr(agent_history, 'owner_scope_enabled', lambda: True)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    url = '/api/agent/history/assets'
    headers = {'x-eventprobe-user': 'alice'}
    response = client.get(url, params={'since': 100, 'before': 200}, headers=headers)
    assert response.status_code == 200
    assert [asset['path'] for asset in response.json()['assets']] == ['/agent']
    response = client.get(url, params={'since': 200, 'before': 301}, headers=headers)
    assert [asset['path'] for asset in response.json()['assets']] == ['/manual']
    assert client.get(url, params={'since': 300, 'before': 301},
                      headers=headers).json()['total'] == 0
    store.set_archived(run_id, True)
    assert client.get(url, params={'since': 100, 'before': 200, 'archived': True},
                      headers=headers).json()['total'] == 1
    assert client.get(url, params={'since': 200, 'before': 301, 'archived': True},
                      headers=headers).json()['total'] == 0
    assert client.get(url, params={'since': 200, 'before': 200},
                      headers=headers).status_code == 422
