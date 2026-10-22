"""Global lookup indexes retain provenance and never return HTTP values."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agent_store import Store
from routers import agent_history


def test_global_traffic_and_findings_scope_reindex_and_delete(tmp_path, monkeypatch):
    path = tmp_path / 'lookup.sqlite3'
    store = Store(path)
    request = {'method': 'POST', 'url': 'https://example.test/Login.asp?next=SECRET_URL',
               'headers': {'Content-Type': 'application/x-www-form-urlencoded',
                           'Authorization': 'SECRET_HEADER'},
               'body': 'user=SECRET_USER&pass=SECRET_PASSWORD'}
    ids = []
    for owner in ('alice', 'alice', 'bob'):
        run_id = store.create({'owner': owner, 'spec': {'goal': 'login'},
                               'endpoints': {'seed': request}})
        store.event(run_id, 'action', {'kind': 'probe', 'category': 'sqli',
                                       'endpoint_id': 'seed', 'actor_id': 'current'}, 's1')
        observation = store.event(run_id, 'observation',
                                  {'request': request, 'response': {'status': 302,
                                   'body': 'SECRET_RESPONSE'}, 'request_id': 'req1'}, 's1')
        store.event(run_id, 'verification',
                    {'status': 'suspicious', 'evidence_ids': [observation]}, 's1')
        ids.append(run_id)

    class Manager:
        def __init__(self):
            self.store = store

    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    monkeypatch.setattr(agent_history, 'owner_scope_enabled', lambda: True)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    headers = {'x-eventprobe-user': 'alice'}
    traffic = client.get('/api/agent/history/traffic', headers=headers).json()
    findings = client.get('/api/agent/history/findings', headers=headers).json()
    assert traffic['total'] == findings['total'] == 2
    assert {item['run_id'] for item in traffic['items']} == set(ids[:2])
    assert {item['verdict'] for item in findings['items']} == {'suspicious'}
    assert traffic['items'][0]['path'] == '/Login.asp'
    assert client.get('/api/agent/history/traffic', params={'limit': 1},
                      headers=headers).json()['has_more']
    assert client.get('/api/agent/history/findings', params={'search': 'missing'},
                      headers=headers).json()['total'] == 0
    asset_id = traffic['items'][0]['asset_id']
    assert client.get('/api/agent/history/findings', params={'asset_id': asset_id},
                      headers=headers).json()['total'] == 2
    diagnostics = client.get('/api/agent/history/diagnostics', headers=headers).json()
    assert diagnostics['total'] == 2
    assert {item['id'] for item in diagnostics['items']} == set(ids[:2])
    assert all(item['token_count'] is None for item in diagnostics['items'])
    for secret in ('SECRET_URL', 'SECRET_HEADER', 'SECRET_USER', 'SECRET_PASSWORD',
                   'SECRET_RESPONSE', ids[2]):
        assert secret not in str(traffic) + str(findings)

    store = Store(path)
    assert store.lookup_page('traffic', owner='alice')['total'] == 2
    store.set_archived(ids[0], True)
    assert store.lookup_page('finding', owner='alice')['total'] == 1
    assert store.lookup_page('finding', owner='alice', archived=True)['total'] == 1
    store.delete(ids[1])
    assert store.lookup_page('traffic', owner='alice')['total'] == 0


def test_legacy_events_are_backfilled(tmp_path):
    path = tmp_path / 'legacy.sqlite3'
    store = Store(path)
    run_id = store.create({'owner': 'alice', 'spec': {'goal': 'legacy'}, 'endpoints': {}})
    with store.connect() as db:
        db.execute("DELETE FROM store_migrations WHERE name='lookup_index_v1'")
        db.execute('DELETE FROM traffic_index')
        db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',
                   ('legacy-event', run_id, 1, 'observation', '',
                    '{"request":{"method":"GET","url":"https://example.test/old"},'
                    '"response":{"status":200}}'))
    reopened = Store(path)
    assert reopened.lookup_page('traffic')['items'][0]['id'] == 'legacy-event'


def test_browser_response_updates_the_reserved_request(tmp_path):
    store = Store(tmp_path / 'browser.sqlite3')
    run_id = store.create({'spec': {'goal': 'browser'}, 'endpoints': {}})
    request_id = store.event(run_id, 'browser_request', {
        'request': {'method': 'GET',
        'url': 'https://example.test/app'}, 'resource_type': 'document'})
    store.event(run_id, 'browser_response', {'request_id': request_id, 'status': 200})
    row = store.lookup_page('traffic')['items'][0]
    assert row['id'] == request_id and row['status'] == 200 and row['source'] == 'browser'


def test_traffic_status_and_time_filters_cover_agent_and_manual_rows(tmp_path, monkeypatch):
    store = Store(tmp_path / 'filters.sqlite3')
    run_id = store.create({'owner': 'alice', 'spec': {}, 'endpoints': {}})
    store.event(run_id, 'observation', {
        'request': {'method': 'POST', 'url': 'https://example.test/agent'},
        'response': {'status': 302}}, 'step')
    store.record_manual_traffic({'method': 'POST', 'url': 'https://example.test/manual'},
                                302, owner='alice')
    store.record_manual_traffic({'method': 'GET', 'url': 'https://example.test/other'},
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
    headers = {'x-eventprobe-user': 'alice'}
    endpoint = '/api/agent/history/traffic'
    response = client.get(endpoint, params={'method': 'POST', 'status_code': 302,
                                            'since': 100, 'before': 200}, headers=headers)
    assert response.status_code == 200
    assert [row['source'] for row in response.json()['items']] == ['agent']
    response = client.get(endpoint, params={'status_code': 302, 'since': 200,
                                            'before': 301}, headers=headers)
    assert [row['source'] for row in response.json()['items']] == ['manual']
    assert client.get(endpoint, params={'since': 0, 'before': 301},
                      headers=headers).json()['total'] == 2
    for params in ({'status_code': 600}, {'since': 200, 'before': 200}):
        assert client.get(endpoint, params=params, headers=headers).status_code == 422
