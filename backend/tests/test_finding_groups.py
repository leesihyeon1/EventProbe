"""Related findings group by request shape, category, and actor without merging verdicts."""

import json
import sqlite3

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agent_store import Store
from routers import agent_history


def _finding(store, owner, actor, verdict, request=None):
    request = request or {'method': 'GET', 'url': 'https://example.test/item?id=SECRET',
                          'body': 'SECRET_BODY'}
    run_id = store.create({'owner': owner, 'spec': {'goal': 'test'},
                           'endpoints': {'seed': request}})
    store.event(run_id, 'action', {'kind': 'probe', 'category': 'sqli',
                                   'endpoint_id': 'seed', 'actor_id': actor}, 's1')
    observation = store.event(run_id, 'observation',
                              {'request': request, 'response': {'status': 200}}, 's1')
    store.event(run_id, 'verification',
                {'status': verdict, 'evidence_ids': [observation]}, 's1')
    return run_id


def test_group_api_preserves_member_verdict_and_owner(tmp_path, monkeypatch):
    store = Store(tmp_path / 'groups.sqlite3')
    first = _finding(store, 'alice', 'current', 'confirmed')
    second = _finding(store, 'alice', 'current', 'suspicious')
    _finding(store, 'alice', 'other', 'inconclusive')
    hidden = _finding(store, 'bob', 'current', 'confirmed')

    class Manager:
        def __init__(self):
            self.store = store

    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    monkeypatch.setattr(agent_history, 'owner_scope_enabled', lambda: True)
    app = FastAPI()
    app.include_router(agent_history.router)
    client = TestClient(app)
    headers = {'x-eventprobe-user': 'alice'}
    result = client.get('/api/agent/history/findings/groups', headers=headers).json()
    assert result['total'] == 2
    group = next(row for row in result['items'] if row['actor_id'] == 'current')
    assert group['run_count'] == group['finding_count'] == 2
    assert (group['confirmed_count'], group['suspicious_count'], group['inconclusive_count']) == (1, 1, 0)
    members = client.get('/api/agent/history/findings/groups/members', headers=headers,
                         params={'asset_id': group['asset_id'], 'category': 'sqli',
                                 'actor_id': 'current', 'input_shape_id': group['input_shape_id'],
                                 'limit': 1}).json()
    assert members['total'] == 2 and members['has_more']
    all_members = store.finding_group_members(group['asset_id'], 'sqli', 'current',
                                              group['input_shape_id'], owner='alice')
    assert {item['run_id'] for item in all_members['items']} == {first, second}
    assert {item['verdict'] for item in all_members['items']} == {'confirmed', 'suspicious'}
    assert hidden not in str(result) + str(members) + str(all_members)
    assert 'SECRET' not in str(result) + str(members) + str(all_members)
    filtered = client.get('/api/agent/history/findings/groups', headers=headers,
                          params={'verdict': 'confirmed'}).json()
    assert filtered['total'] == 1 and filtered['items'][0]['finding_count'] == 1
    asset_filtered = client.get('/api/agent/history/findings/groups', headers=headers,
                                params={'asset_id': group['asset_id']}).json()
    assert asset_filtered['total'] == 2
    assert all(item['asset_id'] == group['asset_id'] for item in asset_filtered['items'])
    assert client.get('/api/agent/history/findings/groups', headers=headers,
                      params={'asset_id': '0' * 64}).json()['total'] == 0
    store.set_archived(first, True)
    assert store.finding_group_members(group['asset_id'], 'sqli', 'current',
                                       group['input_shape_id'], owner='alice')['total'] == 1


def test_post_body_field_shape_separates_groups(tmp_path):
    store = Store(tmp_path / 'fields.sqlite3')
    base = {'method': 'POST', 'url': 'https://example.test/login',
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'}}
    _finding(store, 'alice', 'current', 'confirmed', {**base, 'body': 'user=SECRET'})
    _finding(store, 'alice', 'current', 'suspicious', {**base, 'body': 'email=SECRET'})
    groups = store.finding_group_page(owner='alice')
    assert groups['total'] == 2
    assert len({item['input_shape_id'] for item in groups['items']}) == 2
    assert all(item['run_count'] == 1 for item in groups['items'])
    assert 'SECRET' not in str(groups)


def test_old_finding_index_adds_actor_column(tmp_path):
    path = tmp_path / 'old.sqlite3'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE finding_index (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, '
                   'created REAL NOT NULL, updated REAL NOT NULL, category TEXT NOT NULL, '
                   'verdict TEXT NOT NULL, status TEXT NOT NULL, severity TEXT NOT NULL, '
                   'method TEXT NOT NULL, origin TEXT NOT NULL, path TEXT NOT NULL, '
                   'asset_id TEXT NOT NULL, evidence_count INTEGER NOT NULL, '
                   'incomplete_evidence INTEGER NOT NULL)')
        db.execute('CREATE TABLE runs (id TEXT PRIMARY KEY, created REAL NOT NULL, '
                   'updated REAL NOT NULL, state TEXT NOT NULL, data TEXT NOT NULL)')
        db.execute('CREATE TABLE events (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, '
                   'created REAL NOT NULL, kind TEXT NOT NULL, step_id TEXT NOT NULL, data TEXT NOT NULL)')
        request = {'method': 'GET', 'url': 'https://example.test/old'}
        data = {'owner': 'alice', 'spec': {'goal': 'old'}, 'endpoints': {'seed': request}}
        db.execute('INSERT INTO runs VALUES (?,?,?,?,?)', ('old-run', 1, 1, 'paused', json.dumps(data)))
        for event_id, created, kind, payload in (
            ('a', 1, 'action', {'kind': 'probe', 'category': 'sqli',
                                'endpoint_id': 'seed', 'actor_id': 'current'}),
            ('o', 2, 'observation', {'request': request, 'response': {'status': 200}}),
            ('v', 3, 'verification', {'status': 'confirmed', 'evidence_ids': ['o']}),
        ):
            db.execute('INSERT INTO events VALUES (?,?,?,?,?,?)',
                       (event_id, 'old-run', created, kind, 's1', json.dumps(payload)))
    store = Store(path)
    with store.connect() as db:
        assert {'actor_id', 'input_shape_id'} <= {
            row['name'] for row in db.execute('PRAGMA table_info(finding_index)')}
    groups = store.finding_group_page(owner='alice')
    assert groups['total'] == 1 and groups['items'][0]['actor_id'] == 'current'
