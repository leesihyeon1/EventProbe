"""Portable archives preserve evidence IDs, reject corruption, and never auto-run."""
import io
import json
import zipfile

import httpx
import pytest

import core.agent as agent_mod
from core.agent import AgentManager
from core.agent_archive import read_archive
from core.agent_models import RunSpec
from core.agent_store import Store


def _source(tmp_path):
    store = Store(tmp_path / 'source.db')
    spec = RunSpec.model_validate({'goal': 'synthetic archive',
                                   'request': {'url': 'https://app.test/items'}})
    rid = store.create({'spec': spec.model_dump(), 'owner': 'alice', 'needs_credentials': False,
                        'requests': 1, 'ai_calls': 0, 'steps': 1, 'elapsed': 1,
                        'endpoints': {'seed': {'method': 'GET', 'url': 'https://app.test/items'}}})
    action = store.event(rid, 'action', {'kind': 'observe', 'endpoint_id': 'seed'}, 'step-1')
    observation = store.event(rid, 'observation', {'id': 'obs-1', 'request_id': 'req-1',
        'response': {'status': 200, 'body': 'synthetic'}}, 'step-1')
    store.event(rid, 'verification', {'status': 'inconclusive',
                                     'evidence_ids': [observation]}, 'step-1')
    store.update(rid, store.get(rid)['data'], 'completed')
    return store, rid, action, observation


def _rewrite(blob, name, transform):
    with zipfile.ZipFile(io.BytesIO(blob)) as source:
        files = {item.filename: source.read(item.filename) for item in source.infolist()}
    files[name] = transform(files[name])
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as target:
        for filename, value in files.items():
            target.writestr(filename, value)
    return output.getvalue()


def test_archive_roundtrip_preserves_ids_and_does_not_start(tmp_path):
    source, rid, action, observation = _source(tmp_path)
    blob = source.export_run_archive(rid)
    restored_store = Store(tmp_path / 'restore.db')
    result = restored_store.import_run_archive(blob, owner='bob')
    manager = AgentManager(restored_store, transport=httpx.MockTransport(lambda r: pytest.fail('target request')))
    assert manager.tasks == {}
    assert result == {'id': rid, 'state': 'completed', 'archived': True, 'event_count': 3}
    restored = restored_store.get(rid)
    assert restored['data']['owner'] == 'bob'
    assert restored['data']['archived'] is True
    events = restored_store.events(rid)
    assert [event['id'] for event in events][:2] == [action, observation]
    assert events[2]['data']['evidence_ids'] == [observation]
    with pytest.raises(ValueError, match='동일한 작업 ID'):
        restored_store.import_run_archive(blob, owner='bob')
    assert len(restored_store.events(rid)) == 3


def test_restored_paused_run_is_evidence_only_after_unarchive(tmp_path):
    source, rid, _, _ = _source(tmp_path)
    source.update(rid, source.get(rid)['data'], 'paused')
    destination = Store(tmp_path / 'paused-restore.db')
    destination.import_run_archive(source.export_run_archive(rid))
    data = destination.get(rid)['data']
    data['archived'] = False
    destination.update(rid, data)
    manager = AgentManager(destination, transport=httpx.MockTransport(lambda r: pytest.fail('target request')))
    with pytest.raises(ValueError, match='증거 조회 전용'):
        manager.start(rid)
    assert destination.get(rid)['state'] == 'paused'


def test_archive_and_resume_claim_cannot_cross(tmp_path, monkeypatch):
    store = Store(tmp_path / 'archive-race.db')
    spec = RunSpec.model_validate({'goal': 'synthetic race',
                                   'request': {'url': 'https://app.test/'}})
    rid = store.create({'spec': spec.model_dump(), 'owner': 'alice',
                        'needs_credentials': False, 'requests': 0, 'ai_calls': 0,
                        'steps': 0, 'elapsed': 0, 'endpoints': {}})
    manager = AgentManager(store, transport=httpx.MockTransport(lambda r: pytest.fail('target request')))
    claim = store.claim

    def archive_before_claim(run_id):
        manager.set_archived(run_id, True)
        return claim(run_id)

    monkeypatch.setattr(store, 'claim', archive_before_claim)
    with pytest.raises(ValueError, match='재개'):
        manager.start(rid)
    assert store.get(rid)['data']['archived'] is True
    assert store.get(rid)['state'] == 'paused'
    assert manager.tasks == {}
    assert rid not in manager.specs
    assert store.events(rid) == []

    monkeypatch.setattr(store, 'claim', claim)
    manager.set_archived(rid, False)
    assert store.claim(rid)
    with pytest.raises(ValueError, match='실행 중인 작업'):
        manager.set_archived(rid, True)
    assert store.get(rid)['data']['archived'] is False


def test_archive_rejects_tamper_version_and_extra_path(tmp_path):
    source, rid, _, _ = _source(tmp_path)
    blob = source.export_run_archive(rid)
    bad_hash = _rewrite(blob, 'run.json', lambda raw: raw.replace(b'synthetic archive', b'changed archive'))
    with pytest.raises(ValueError, match='무결성'):
        read_archive(bad_hash)
    bad_version = _rewrite(blob, 'manifest.json', lambda raw: raw.replace(b'"version":1', b'"version":2'))
    with pytest.raises(ValueError, match='버전'):
        read_archive(bad_version)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('../run.json', b'{}')
    with pytest.raises(ValueError, match='파일 구성'):
        read_archive(output.getvalue())
    assert source.get(rid)['state'] == 'completed'


def test_import_rejects_event_id_conflict_transactionally(tmp_path):
    source, rid, _, observation = _source(tmp_path)
    destination = Store(tmp_path / 'destination.db')
    other = destination.create({'spec': {'goal': 'other'}})
    destination.event(other, 'observation', {'id': observation}, event_id=observation)
    with pytest.raises(ValueError, match='이벤트 ID'):
        destination.import_run_archive(source.export_run_archive(rid))
    with pytest.raises(KeyError):
        destination.get(rid)


def test_archive_api_owner_scope_and_import(tmp_path, monkeypatch):
    source, rid, _, _ = _source(tmp_path)
    manager = AgentManager(source, transport=httpx.MockTransport(lambda r: pytest.fail('target request')))
    monkeypatch.setattr(agent_mod, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    url = f'/api/agent/runs/{rid}/archive.zip'
    assert client.get(url, headers={'x-eventprobe-user': 'bob'}).status_code == 403
    exported = client.get(url, headers={'x-eventprobe-user': 'alice'})
    assert exported.status_code == 200
    assert exported.headers['cache-control'] == 'no-store'
    destination = AgentManager(Store(tmp_path / 'api-restore.db'), transport=manager.transport)
    monkeypatch.setattr(agent_mod, '_manager', destination)
    imported = client.post('/api/agent/archives/import', content=exported.content,
                           headers={'x-eventprobe-user': 'bob', 'content-type': 'application/zip'})
    assert imported.status_code == 201
    assert destination.tasks == {}
    assert destination.store.get(rid)['data']['owner'] == 'bob'
    assert client.post('/api/agent/archives/import', content=exported.content,
                       headers={'x-eventprobe-user': 'bob'}).status_code == 409


def test_archive_list_reaches_runs_older_than_200_recent_unarchived(tmp_path):
    store = Store(tmp_path / 'many.db')
    archived = store.create({'spec': {'goal': 'old archive'}, 'archived': True})
    for index in range(205):
        store.create({'spec': {'goal': f'new run {index}'}})
    assert [run['id'] for run in store.list(include_archived=True)] == [archived]
    assert len(store.list()) == 50
