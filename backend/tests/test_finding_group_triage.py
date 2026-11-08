"""Group-level canonical triage: one disposition across all runs of a structural group,
layered on top without merging or mutating per-run verdicts/evidence. No live target or LLM.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agent_runtime_store import RunConflict
from core.agent_store import Store
from routers import agent_history


def _finding(store, owner, actor, verdict, category='sqli', request=None):
    request = request or {'method': 'GET', 'url': 'https://example.test/item?id=SECRET',
                          'body': 'SECRET_BODY'}
    run_id = store.create({'owner': owner, 'spec': {'goal': 'test'},
                           'endpoints': {'seed': request}})
    store.event(run_id, 'action', {'kind': 'probe', 'category': category,
                                   'endpoint_id': 'seed', 'actor_id': actor}, 's1')
    obs = store.event(run_id, 'observation', {'request': request, 'response': {'status': 200}}, 's1')
    store.event(run_id, 'verification', {'status': verdict, 'evidence_ids': [obs]}, 's1')
    return run_id


def _key(store, owner):
    item = store.finding_group_page(owner=owner)['items'][0]
    return item['asset_id'], item['category'], item['actor_id'], item['input_shape_id']


def test_set_and_read_group_triage_and_surface_in_page(tmp_path):
    store = Store(tmp_path / 't.sqlite3')
    _finding(store, 'alice', 'current', 'confirmed')   # sqli confirmed -> member severity critical
    key = _key(store, 'alice')
    created = store.set_finding_group_triage(*key, {'status': 'triaged', 'note': '패치 예정'}, 0,
                                             actor='alice', owner='alice')
    assert created['exists'] and created['status'] == 'triaged' and created['revision'] == 1
    assert created['severity'] == 'critical'           # seeded from worst member severity
    assert created['note'] == '패치 예정'
    read = store.finding_group_triage(*key, owner='alice')
    assert read['status'] == 'triaged' and read['revision'] == 1 and len(read['history']) == 1
    page = store.finding_group_page(owner='alice')['items'][0]
    assert page['canonical_status'] == 'triaged' and page['canonical_severity'] == 'critical'
    assert page['canonical_revision'] == 1


def test_untriaged_group_has_null_canonical_fields(tmp_path):
    store = Store(tmp_path / 't.sqlite3')
    _finding(store, 'alice', 'current', 'confirmed')
    page = store.finding_group_page(owner='alice')['items'][0]
    assert page['canonical_status'] is None and page['canonical_revision'] is None
    read = store.finding_group_triage(*_key(store, 'alice'), owner='alice')
    assert read['exists'] is False and read['status'] is None and read['history'] == []


def test_revision_is_compare_and_swap(tmp_path):
    store = Store(tmp_path / 't.sqlite3')
    _finding(store, 'alice', 'current', 'confirmed')
    key = _key(store, 'alice')
    store.set_finding_group_triage(*key, {'status': 'triaged'}, 0, owner='alice')
    store.set_finding_group_triage(*key, {'status': 'resolved'}, 1, owner='alice')   # rev -> 2
    with pytest.raises(RunConflict):
        store.set_finding_group_triage(*key, {'status': 'open'}, 1, owner='alice')    # stale revision
    with pytest.raises(RunConflict):
        store.set_finding_group_triage(*key, {'status': 'open'}, 0, owner='alice')    # exists but expected create
    assert store.finding_group_triage(*key, owner='alice')['revision'] == 2
    assert len(store.finding_group_triage(*key, owner='alice')['history']) == 2


def test_empty_or_invalid_patch_rejected(tmp_path):
    store = Store(tmp_path / 't.sqlite3')
    _finding(store, 'alice', 'current', 'confirmed')
    key = _key(store, 'alice')
    with pytest.raises(ValueError):
        store.set_finding_group_triage(*key, {'status': 'bogus'}, 0, owner='alice')   # dropped -> nothing to change
    assert store.finding_group_triage(*key, owner='alice')['exists'] is False         # no row created


def test_owner_scope_isolates_and_guards_visibility(tmp_path):
    store = Store(tmp_path / 't.sqlite3')
    _finding(store, 'alice', 'current', 'confirmed')
    key = _key(store, 'alice')
    with pytest.raises(KeyError):                                                     # bob cannot see the group
        store.set_finding_group_triage(*key, {'status': 'triaged'}, 0, owner='bob')
    store.set_finding_group_triage(*key, {'status': 'resolved'}, 0, owner='alice')
    assert store.finding_group_page(owner='bob')['total'] == 0
    assert store.finding_group_page(owner='alice')['items'][0]['canonical_status'] == 'resolved'
    assert store.finding_group_triage(*key, owner='bob')['exists'] is False           # per-workspace rows


def test_group_triage_does_not_mutate_member_findings(tmp_path):
    store = Store(tmp_path / 't.sqlite3')
    run_id = _finding(store, 'alice', 'current', 'confirmed')
    key = _key(store, 'alice')
    store.set_finding_group_triage(*key, {'status': 'false_positive', 'severity': 'low'}, 0, owner='alice')
    with store.connect() as db:
        row = db.execute('SELECT status,severity,verdict FROM finding_index WHERE run_id=?',
                         (run_id,)).fetchone()
    # The per-run derived finding is untouched: verdict stays confirmed, severity stays critical.
    assert row['verdict'] == 'confirmed' and row['severity'] == 'critical' and row['status'] == 'open'


def _client(store, monkeypatch):
    class Manager:
        def __init__(self):
            self.store = store
    monkeypatch.setattr(agent_history, 'get_manager', Manager)
    monkeypatch.setattr(agent_history, 'owner_scope_enabled', lambda: True)
    app = FastAPI()
    app.include_router(agent_history.router)
    return TestClient(app)


def test_router_put_get_conflict_404_422(tmp_path, monkeypatch):
    store = Store(tmp_path / 't.sqlite3')
    _finding(store, 'alice', 'current', 'confirmed')
    key = _key(store, 'alice')
    client = _client(store, monkeypatch)
    alice = {'x-eventprobe-user': 'alice'}
    body = {'asset_id': key[0], 'category': key[1], 'actor_id': key[2], 'input_shape_id': key[3]}
    url = '/api/agent/history/findings/groups/triage'

    created = client.put(url, json={**body, 'expected_revision': 0, 'status': 'triaged'}, headers=alice)
    assert created.status_code == 200 and created.json()['revision'] == 1
    assert created.json()['status'] == 'triaged' and created.json()['severity'] == 'critical'

    got = client.get(url, params=body, headers=alice).json()
    assert got['exists'] and got['revision'] == 1 and len(got['history']) == 1

    conflict = client.put(url, json={**body, 'expected_revision': 0, 'status': 'resolved'}, headers=alice)
    assert conflict.status_code == 409

    bad = client.put(url, json={**body, 'expected_revision': 1, 'status': 'nope'}, headers=alice)
    assert bad.status_code == 422

    not_found = client.put(url, json={**body, 'expected_revision': 0, 'status': 'triaged'},
                           headers={'x-eventprobe-user': 'bob'})
    assert not_found.status_code == 404

    assert 'SECRET' not in created.text + client.get(url, params=body, headers=alice).text
