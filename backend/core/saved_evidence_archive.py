"""Portable retained-evidence backup. Checksums detect corruption, not forgery."""
import io
import json
import math
import re
import time
import zipfile
import zlib

from core.agent_runtime_store import RunConflict
from core.saved_evidence import (MAX_VERSIONS, MAX_EVENTS, MAX_CAPTURE_BYTES, encoded, digest,
                                 normalize_event, snapshot, validate_proof, EvidenceCorrupt)
from core.saved_evidence_contracts import FindingSnapshot, SourceSnapshot
from core.agent_findings import STATUSES, SEVERITIES, valid_patch

MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_CONTENT_BYTES = 50 * 1024 * 1024
MAX_FILES = 1024


def export_saved_archive(store, saved_id, owner_filter=None):
    with store.connect() as db:
        db.execute('BEGIN')
        store._saved_finding_tx(db, saved_id, owner_filter=owner_filter)
        metadata_bytes = db.execute('SELECT COALESCE(SUM(length(CAST(finding_json AS BLOB))+'
                                    'length(CAST(source_json AS BLOB))),0) FROM saved_finding_versions '
                                    'WHERE finding_id=?', (saved_id,)).fetchone()[0]
        change_bytes = db.execute('SELECT COALESCE(SUM(length(CAST(patch AS BLOB))),0) '
                                  'FROM saved_finding_changes WHERE finding_id=?', (saved_id,)).fetchone()[0]
        body_bytes = db.execute('SELECT COALESCE(SUM(length),0) FROM saved_evidence_blobs WHERE hash IN '
                                '(SELECT s.blob_hash FROM saved_finding_evidence e '
                                'JOIN saved_evidence_snapshots s ON s.id=e.snapshot_id WHERE e.finding_id=?)',
                                (saved_id,)).fetchone()[0]
        if metadata_bytes + change_bytes + body_bytes > MAX_CONTENT_BYTES:
            raise ValueError('보존 패키지가 50 MiB 원본 한도를 초과했습니다.')
        record = dict(db.execute('SELECT * FROM saved_findings WHERE id=?', (saved_id,)).fetchone())
        versions = [dict(row) for row in db.execute('SELECT * FROM saved_finding_versions WHERE finding_id=? ORDER BY version', (saved_id,))]
        for version in versions:
            store._saved_finding_tx(db, saved_id, version['version'], owner_filter)
        links = [dict(row) for row in db.execute('SELECT * FROM saved_finding_evidence WHERE finding_id=? ORDER BY version,position', (saved_id,))]
        changes = [dict(row) for row in db.execute('SELECT * FROM saved_finding_changes WHERE finding_id=? ORDER BY revision', (saved_id,))]
        records, blobs = {}, {}
        for link in links:
            event = store._saved_event_tx(db, saved_id, link['snapshot_id'], link['version'])
            info, payload = snapshot(event)
            if info['id'] != link['snapshot_id']:
                raise EvidenceCorrupt('증거 스냅샷 식별자가 손상됐습니다.')
            records[info['id']] = info
            blobs['blobs/' + info['blob_hash']] = payload
        bundle = {'record': record, 'versions': versions, 'links': links,
                  'changes': changes, 'snapshots': list(records.values())}
        payloads = {'record.json': encoded(bundle), **blobs}
    if len(payloads) + 1 > MAX_FILES or sum(map(len, payloads.values())) > MAX_CONTENT_BYTES:
        raise ValueError('보존 패키지가 파일 수 또는 50 MiB 원본 한도를 초과했습니다.')
    manifest = {'format': 'eventprobe-saved-finding', 'version': 1,
                'sha256': {name: digest(body) for name, body in payloads.items()}}
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json', encoded(manifest))
        for name, body in payloads.items():
            archive.writestr(name, body)
    if output.tell() > MAX_ARCHIVE_BYTES:
        raise ValueError('보존 패키지가 25 MiB 한도를 초과했습니다.')
    return output.getvalue()


def read_saved_archive(blob):
    if not isinstance(blob, bytes) or not blob or len(blob) > MAX_ARCHIVE_BYTES:
        raise ValueError('보존 패키지는 25 MiB 이하 ZIP이어야 합니다.')
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if (len(names) != len(set(names)) or not 2 <= len(names) <= MAX_FILES or
                    'manifest.json' not in names or 'record.json' not in names or
                    any(name not in ('manifest.json', 'record.json') and
                        not re.fullmatch(r'blobs/[a-f0-9]{64}', name) for name in names) or
                    any(info.is_dir() or info.flag_bits & 1 for info in infos) or
                    sum(info.file_size for info in infos) > MAX_CONTENT_BYTES):
                raise ValueError('보존 패키지의 파일 구성 또는 크기가 올바르지 않습니다.')
            raw = {}
            total = 0
            for info in infos:
                with archive.open(info) as stream:
                    data = stream.read(MAX_CONTENT_BYTES - total + 1)
                total += len(data)
                if total > MAX_CONTENT_BYTES or len(data) != info.file_size:
                    raise ValueError('보존 패키지의 실제 크기가 한도를 초과했습니다.')
                raw[info.filename] = data
        manifest = json.loads(raw.pop('manifest.json'))
        if (manifest.get('format') != 'eventprobe-saved-finding' or manifest.get('version') != 1 or
                not isinstance(manifest.get('sha256'), dict) or set(manifest['sha256']) != set(raw) or
                any(manifest['sha256'][name] != digest(body) for name, body in raw.items())):
            raise ValueError('보존 패키지의 버전 또는 해시가 올바르지 않습니다.')
        bundle = json.loads(raw['record.json'])
    except (zipfile.BadZipFile, RuntimeError, OSError, zlib.error, UnicodeDecodeError,
            KeyError, TypeError, AttributeError) as exc:
        raise ValueError('보존 패키지를 읽을 수 없습니다.') from exc
    return bundle, raw


def import_saved_archive(store, blob, owner=''):
    try:
        return _import_saved_archive(store, blob, owner)
    except (KeyError, TypeError, AttributeError, OverflowError, IndexError) as exc:
        raise ValueError('보존 패키지의 값 형식이 올바르지 않습니다.') from exc


def _import_saved_archive(store, blob, owner):
    bundle, raw = read_saved_archive(blob)
    if not isinstance(bundle, dict) or set(bundle) != {'record', 'versions', 'links', 'changes', 'snapshots'}:
        raise ValueError('보존 패키지 데이터 구성이 올바르지 않습니다.')
    record, versions, links, changes, snapshots = (bundle[key] for key in ('record', 'versions', 'links', 'changes', 'snapshots'))
    if (not isinstance(record, dict) or not isinstance(record.get('id'), str) or not re.fullmatch(r'[a-f0-9]{32}', str(record.get('id', ''))) or
            not isinstance(record.get('source_run_id'), str) or not 1 <= len(record['source_run_id']) <= 100 or
            not re.fullmatch(r'[a-f0-9]{16}', str(record.get('source_finding_id', ''))) or
            record.get('status') not in STATUSES or record.get('severity') not in SEVERITIES or
            not isinstance(record.get('note'), str) or len(record['note']) > 2000 or
            type(record.get('revision')) is not int or record['revision'] < 1 or
            type(record.get('current_version')) is not int or
            not isinstance(versions, list) or not 1 <= len(versions) <= MAX_VERSIONS or
            record['current_version'] != len(versions) or not isinstance(links, list) or
            not isinstance(changes, list) or len(changes) > 10000 or
            not isinstance(snapshots, list) or len(snapshots) > MAX_EVENTS * MAX_VERSIONS):
        raise ValueError('보존 발견 메타데이터가 올바르지 않습니다.')
    saved_id, source_run = record['id'], record['source_run_id']
    for key in ('created', 'updated'):
        if type(record.get(key)) not in (float, int) or not math.isfinite(record[key]):
            raise ValueError('보존 발견 시각이 올바르지 않습니다.')
    normalized, events_by_id, used_blobs = {}, {}, set()
    for info in snapshots:
        if not isinstance(info, dict) or set(info) != {'id', 'run_id', 'event_id', 'kind', 'step_id', 'created', 'blob_hash', 'length'}:
            raise ValueError('증거 스냅샷 구성이 올바르지 않습니다.')
        name = 'blobs/' + str(info['blob_hash'])
        body = raw.get(name)
        if not re.fullmatch(r'blobs/[a-f0-9]{64}', name) or body is None or len(body) > MAX_CAPTURE_BYTES:
            raise ValueError('증거 본문이 없거나 크기 한도를 초과했습니다.')
        event = normalize_event({'id': info['event_id'], 'run_id': info['run_id'], 'kind': info['kind'],
                                 'step_id': info['step_id'], 'created': info['created'], 'data': json.loads(body)},
                                source_run, importing=True)
        expected, canonical = snapshot(event)
        if expected != info or canonical != body or info['id'] in normalized:
            raise EvidenceCorrupt('증거 본문 또는 스냅샷 해시가 일치하지 않습니다.')
        normalized[info['id']] = (info, body)
        events_by_id[info['id']] = event
        used_blobs.add(name)
    if set(raw) != {'record.json', *used_blobs}:
        raise ValueError('참조되지 않은 파일이 패키지에 있습니다.')
    by_version = {}
    for link in links:
        if (not isinstance(link, dict) or set(link) != {'finding_id', 'version', 'snapshot_id', 'position'} or
                link['finding_id'] != saved_id or type(link['version']) is not int or
                not 1 <= link['version'] <= len(versions) or type(link['position']) is not int or
                link['snapshot_id'] not in normalized):
            raise ValueError('발견과 증거의 연결이 올바르지 않습니다.')
        by_version.setdefault(link['version'], []).append(link)
    normalized_versions = []
    for index, version in enumerate(versions, 1):
        if (not isinstance(version, dict) or set(version) != {'finding_id', 'version', 'created', 'source_digest', 'finding_json', 'source_json'} or
                version['finding_id'] != saved_id or type(version['version']) is not int or version['version'] != index or
                type(version['created']) not in (int, float) or not math.isfinite(version['created'])):
            raise ValueError('발견 버전이 올바르지 않습니다.')
        finding = FindingSnapshot.model_validate(json.loads(version['finding_json'])).model_dump()
        source = SourceSnapshot.model_validate(json.loads(version['source_json'])).model_dump()
        members = sorted(by_version.get(index, []), key=lambda row: row['position'])
        if (not 1 <= len(members) <= MAX_EVENTS or [m['position'] for m in members] != list(range(len(members))) or
                len({m['snapshot_id'] for m in members}) != len(members)):
            raise ValueError('증거 순서 또는 참조가 올바르지 않습니다.')
        events = [events_by_id[m['snapshot_id']] for m in members]
        validate_proof(finding, source, events, source_run, record['source_finding_id'])
        if sum(normalized[m['snapshot_id']][0]['length'] for m in members) + len(encoded(finding)) + len(encoded(source)) > MAX_CAPTURE_BYTES:
            raise ValueError('발견 버전의 증거 크기 한도를 초과했습니다.')
        checksum = digest(encoded({'finding': finding, 'source': source, 'snapshots': [m['snapshot_id'] for m in members]}))
        if checksum != version['source_digest']:
            raise EvidenceCorrupt('발견 버전의 해시가 일치하지 않습니다.')
        normalized_versions.append((saved_id, index, version['created'], checksum, encoded(finding).decode(), encoded(source).decode()))
    if {m['snapshot_id'] for m in links} != set(normalized):
        raise ValueError('어느 버전에서도 참조하지 않는 증거가 있습니다.')
    normalized_changes, seen_revisions, seen_ids = [], set(), set()
    for change in changes:
        if (not isinstance(change, dict) or set(change) != {'id', 'finding_id', 'created', 'actor', 'revision', 'patch'} or
                change['finding_id'] != saved_id or not re.fullmatch(r'[a-f0-9]{32}', str(change['id'])) or
                not isinstance(change['actor'], str) or len(change['actor']) > 64 or
                type(change['revision']) is not int or not 1 < change['revision'] <= record['revision'] or
                change['revision'] in seen_revisions or change['id'] in seen_ids or
                type(change['created']) not in (int, float) or not math.isfinite(change['created'])):
            raise ValueError('발견 변경 이력이 올바르지 않습니다.')
        patch = json.loads(change['patch'])
        if valid_patch(patch) != patch:
            raise ValueError('발견 변경 내용이 올바르지 않습니다.')
        normalized_changes.append((change['id'], saved_id, change['created'], change['actor'], change['revision'], encoded(patch).decode()))
        seen_revisions.add(change['revision'])
        seen_ids.add(change['id'])
    # All parsing, bounds and integrity checks complete before the write transaction.
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT 1 FROM saved_findings WHERE id=? OR (owner=? AND source_run_id=? AND source_finding_id=?)',
                      (saved_id, owner, source_run, record['source_finding_id'])).fetchone():
            raise RunConflict('같은 보존 발견 또는 원본 연결이 이미 존재합니다.')
        db.execute('INSERT INTO saved_findings VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                   (saved_id, owner, source_run, record['source_finding_id'], record['created'], time.time(),
                    record['revision'], record['current_version'], record['status'], record['severity'], record['note']))
        db.executemany('INSERT INTO saved_finding_versions VALUES (?,?,?,?,?,?)', normalized_versions)
        for info, body in normalized.values():
            store._insert_saved_snapshot(db, info, body)
        for link in links:
            db.execute('INSERT INTO saved_finding_evidence VALUES (?,?,?,?)',
                       (saved_id, link['version'], link['snapshot_id'], link['position']))
        if any(db.execute('SELECT 1 FROM saved_finding_changes WHERE id=?', (c[0],)).fetchone() for c in normalized_changes):
            raise RunConflict('변경 이력 식별자가 기존 기록과 충돌합니다.')
        db.executemany('INSERT INTO saved_finding_changes VALUES (?,?,?,?,?,?)', normalized_changes)
    return {'id': saved_id, 'version': record['current_version'], 'restored': True, 'execution_started': False}
