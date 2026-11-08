"""Independent retained evidence uses only synthetic, local data."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import io
import json
import zipfile

import pytest

from core.agent_store import Store
from core.agent_findings import build_findings
from core.agent_evidence_export import build_finding_evidence_zip
from core.agent_runtime_store import RunConflict
from core.saved_evidence import EvidenceCorrupt, encoded, digest
from core.saved_evidence_archive import export_saved_archive, import_saved_archive


def source(store, owner='alice', category='sqli', method='GET', body=''):
    request = {'method': method, 'url': 'https://example.test/check?id=private-query-value',
               'params': {}, 'headers': {}, 'body': body}
    rid = store.create({'owner': owner, 'spec': {'goal': 'synthetic'}, 'endpoints': {'seed': request},
                        'requests': 1, 'ai_calls': 0, 'steps': 1, 'elapsed': 1})
    store.event(rid, 'action', {'kind': 'probe', 'category': category, 'endpoint_id': 'seed',
        'actor_id': 'current', 'location': 'param', 'param': 'id'}, 'step1')
    oid = store.event(rid, 'observation', {'request': {**request,
        'headers': {'Authorization': 'Bearer synthetic-secret', 'Accept': 'text/plain'}},
        'response': {'status': 200, 'headers': {'Set-Cookie': 'synthetic-cookie', 'Content-Type': 'text/plain'},
                     'body': 'PRIVATE_EVIDENCE_BODY', 'truncated': False}}, 'step1')
    store.event(rid, 'verification', {'status': 'confirmed', 'evidence_ids': [oid]}, 'step1')
    store.update(rid, store.get(rid)['data'], 'completed')
    fid = build_findings(rid, store.get(rid)['data'], store.events(rid))[0]['id']
    return rid, fid, oid


def saved_source(tmp_path):
    store = Store(tmp_path / 'source.db')
    rid, fid, oid = source(store)
    saved = store.preserve_finding(rid, fid, 'alice', source_owner_filter='alice')
    return store, rid, fid, oid, saved


def test_preservation_is_explicit_idempotent_and_survives_source_delete(tmp_path):
    store = Store(tmp_path / 'retained.db')
    rid, fid, oid = source(store)
    assert store.saved_finding_page()['total'] == 0
    saved = store.preserve_finding(rid, fid, 'alice')
    assert len(saved['id']) == 32 and saved['id'] != fid
    assert store.preserve_finding(rid, fid, 'alice')['unchanged']
    assert store.saved_finding(saved['id'])['source_finding_id'] == fid
    store.delete(rid)
    view = store.saved_execution_view(saved['id'], owner_filter='alice')
    assert view['findings'][0]['verdict'] == 'confirmed'
    event = next(e for e in view['events'] if e['id'] == oid)
    assert event['data']['response']['body'] == 'PRIVATE_EVIDENCE_BODY'
    assert event['data']['request']['headers'] == {'Accept': 'text/plain'}
    assert 'Set-Cookie' not in event['data']['response']['headers']
    with pytest.raises(KeyError):
        store.get(rid)


def test_versions_are_immutable_and_saved_triage_is_independent(tmp_path):
    store, rid, fid, oid, saved = saved_source(tmp_path)
    own = store.patch_saved_finding(saved['id'], {'note': 'saved note', 'status': 'triaged'}, 1, 'alice')
    store.event(rid, 'finding_update', {'finding_id': fid, 'note': 'source note'})
    with pytest.raises(RunConflict):
        store.preserve_finding(rid, fid, 'alice')
    updated = store.preserve_finding(rid, fid, 'alice', expected_revision=own['revision'])
    assert updated['version'] == 2
    original = store.saved_finding(saved['id'], 1)
    current = store.saved_finding(saved['id'])
    assert original['version'] == 1
    assert current['finding']['note'] == 'saved note'
    assert len(current['changes']) == 1
    with store.connect() as db:
        notes = [json.loads(r['finding_json'])['note'] for r in db.execute(
            'SELECT finding_json FROM saved_finding_versions ORDER BY version')]
        assert notes == ['', 'source note']
        assert db.execute('SELECT COUNT(*) FROM saved_evidence_blobs').fetchone()[0] == 3


def test_concurrent_preserve_has_one_identity_and_one_version(tmp_path):
    store = Store(tmp_path / 'race.db')
    rid, fid, _ = source(store)
    with ThreadPoolExecutor(3) as pool:
        results = list(pool.map(lambda _: store.preserve_finding(rid, fid, 'alice'), range(3)))
    assert len({r['id'] for r in results}) == 1
    assert sum(not r['unchanged'] for r in results) == 1
    assert store.saved_finding_page()['total'] == 1


def test_shared_blobs_are_collected_only_after_last_saved_reference(tmp_path):
    store, rid, fid, _, first = saved_source(tmp_path)
    second = store.preserve_finding(rid, fid, 'bob')
    store.delete_saved_finding(first['id'], 1, 'alice', 'alice')
    assert store.saved_execution_view(second['id'], owner_filter='bob')['events']
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM saved_evidence_blobs').fetchone()[0] == 3
    store.delete_saved_finding(second['id'], 1, 'bob', 'bob')
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM saved_evidence_blobs').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM saved_finding_deletions').fetchone()[0] == 2
    assert store.get(rid)


def test_owner_filters_apply_to_metadata_body_patch_delete_and_source_capture(tmp_path):
    store, rid, fid, _, saved = saved_source(tmp_path)
    record = store.saved_finding(saved['id'])
    sid = record['evidence'][0]['id']
    calls = [lambda: store.saved_finding(saved['id'], owner_filter='bob'),
             lambda: store.saved_event(saved['id'], sid, owner_filter='bob'),
             lambda: store.saved_execution_view(saved['id'], owner_filter='bob'),
             lambda: store.patch_saved_finding(saved['id'], {'note': 'bad'}, 1, 'bob', 'bob'),
             lambda: store.delete_saved_finding(saved['id'], 1, 'bob', 'bob'),
             lambda: store.preserve_finding(rid, fid, 'bob', source_owner_filter='bob')]
    for call in calls:
        with pytest.raises(PermissionError):
            call()
    assert store.saved_finding_page(owner='bob')['total'] == 0


def test_foreign_snapshot_cannot_be_opened_through_an_owned_finding(tmp_path):
    store, _, _, _, first = saved_source(tmp_path)
    second_run, second_fid, _ = source(store, owner='bob')
    second = store.preserve_finding(second_run, second_fid, 'bob')
    foreign = store.saved_finding(second['id'])['evidence'][0]['id']
    with pytest.raises(KeyError):
        store.saved_event(first['id'], foreign, owner_filter='alice')


def test_retention_removes_run_but_not_explicitly_saved_evidence(tmp_path):
    store, rid, _, _, saved = saved_source(tmp_path)
    with store.connect() as db:
        db.execute('UPDATE runs SET updated=1 WHERE id=?', (rid,))
    assert store.prune(1) == 1
    assert store.saved_execution_view(saved['id'])['events']


def test_corrupt_blob_is_reported_and_never_silently_repaired(tmp_path):
    store, rid, fid, _, saved = saved_source(tmp_path)
    record = store.saved_finding(saved['id'])
    with store.connect() as db:
        db.execute("UPDATE saved_evidence_blobs SET payload=X'00'")
    with pytest.raises(EvidenceCorrupt):
        store.saved_execution_view(saved['id'])
    with pytest.raises(EvidenceCorrupt):
        store.preserve_finding(rid, fid, 'alice')
    assert store.saved_finding(saved['id'])['revision'] == record['revision']


def test_missing_blob_is_corruption_and_not_a_valid_empty_body(tmp_path):
    store, rid, fid, _, saved = saved_source(tmp_path)
    with store.connect() as db:
        db.execute('DELETE FROM saved_evidence_blobs')
    with pytest.raises(EvidenceCorrupt):
        store.saved_execution_view(saved['id'])
    with pytest.raises(EvidenceCorrupt):
        store.preserve_finding(rid, fid, 'alice')


def test_metadata_corruption_cannot_change_report_or_retest_target(tmp_path):
    store, _, _, _, saved = saved_source(tmp_path)
    with store.connect() as db:
        row = db.execute('SELECT source_json FROM saved_finding_versions').fetchone()
        data = json.loads(row['source_json'])
        data['request']['url'] = 'https://other.example.test/'
        db.execute('UPDATE saved_finding_versions SET source_json=?', (json.dumps(data),))
    with pytest.raises(EvidenceCorrupt):
        store.saved_finding(saved['id'])
    with pytest.raises(EvidenceCorrupt):
        export_saved_archive(store, saved['id'])


def test_default_evidence_zip_is_redacted_and_raw_requires_explicit_selection(tmp_path):
    store, rid, _, _, saved = saved_source(tmp_path)
    store.delete(rid)
    view = store.saved_execution_view(saved['id'])
    for raw in (False, True):
        payload = build_finding_evidence_zip(view, saved['id'], include_raw=raw)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            contents = b''.join(archive.read(n) for n in archive.namelist())
        assert (b'PRIVATE_EVIDENCE_BODY' in contents) == raw
        assert b'synthetic-secret' not in contents


def test_archive_restores_versions_and_owner_but_starts_no_execution(tmp_path):
    store, rid, fid, _, saved = saved_source(tmp_path)
    store.patch_saved_finding(saved['id'], {'note': 'saved note'}, 1, 'alice')
    store.event(rid, 'finding_update', {'finding_id': fid, 'note': 'source changed'})
    store.preserve_finding(rid, fid, 'alice', expected_revision=2)
    payload = export_saved_archive(store, saved['id'], 'alice')
    target = Store(tmp_path / 'restored.db')
    result = import_saved_archive(target, payload, owner='bob')
    assert not result['execution_started']
    restored = target.saved_finding(saved['id'], owner_filter='bob')
    assert restored['owner'] == 'bob'
    assert restored['current_version'] == 2
    assert restored['finding']['note'] == 'saved note'
    assert target.saved_execution_view(saved['id'], 1)['events']
    with target.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
    with pytest.raises(RunConflict):
        import_saved_archive(target, payload, owner='bob')


def rewrite_package(payload, change):
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        files = {name: archive.read(name) for name in archive.namelist() if name != 'manifest.json'}
    change(files)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json', encoded({'format': 'eventprobe-saved-finding', 'version': 1,
            'sha256': {name: digest(body) for name, body in files.items()}}))
        for name, body in files.items():
            archive.writestr(name, body)
    return output.getvalue()


@pytest.mark.parametrize('mode', ['blob', 'missing', 'path', 'proof', 'link'])
def test_bad_package_is_rejected_atomically(tmp_path, mode):
    store, _, _, _, saved = saved_source(tmp_path)
    package = export_saved_archive(store, saved['id'])
    def mutate(files):
        body = json.loads(files['record.json'])
        if mode == 'blob':
            key = next(k for k in files if k.startswith('blobs/'))
            files[key] = b'{}'
        elif mode == 'missing':
            del files[next(k for k in files if k.startswith('blobs/'))]
        elif mode == 'path':
            files['../outside.json'] = b'{}'
        elif mode == 'proof':
            f = json.loads(body['versions'][0]['finding_json'])
            f['verdict'] = 'inconclusive'
            body['versions'][0]['finding_json'] = json.dumps(f)
        elif mode == 'link':
            body['links'][0]['snapshot_id'] = 'unknown'
        files['record.json'] = encoded(body)
    target = Store(tmp_path / 'target.db')
    with pytest.raises(ValueError):
        import_saved_archive(target, rewrite_package(package, mutate), owner='bob')
    with target.connect() as db:
        for table in ('saved_findings', 'saved_finding_versions', 'saved_evidence_blobs', 'saved_evidence_snapshots'):
            assert db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] == 0


def test_invalid_reference_and_stale_revision_do_not_write_partial_state(tmp_path):
    store, rid, fid, oid, saved = saved_source(tmp_path)
    with pytest.raises(RunConflict):
        store.patch_saved_finding(saved['id'], {'note': 'stale'}, 99)
    with store.connect() as db:
        db.execute('DELETE FROM events WHERE id=?', (oid,))
    with pytest.raises(ValueError):
        store.preserve_finding(rid, fid, 'bob')
    assert store.saved_finding_page()['total'] == 1


def test_gc_and_other_owner_preservation_are_serialized(tmp_path):
    store, rid, fid, _, first = saved_source(tmp_path)
    with ThreadPoolExecutor(2) as pool:
        deletion = pool.submit(store.delete_saved_finding, first['id'], 1, 'alice', 'alice')
        preservation = pool.submit(store.preserve_finding, rid, fid, 'bob')
        deletion.result()
        second = preservation.result()
    assert store.saved_execution_view(second['id'], owner_filter='bob')['events']


def test_archive_size_is_checked_before_loading_all_bodies(tmp_path, monkeypatch):
    from core import saved_evidence_archive as archive
    store, _, _, _, saved = saved_source(tmp_path)
    monkeypatch.setattr(archive, 'MAX_CONTENT_BYTES', 10)
    monkeypatch.setattr(store, '_saved_event_tx', lambda *a, **k: pytest.fail('Body should not be loaded'))
    with pytest.raises(ValueError, match='한도'):
        export_saved_archive(store, saved['id'])
