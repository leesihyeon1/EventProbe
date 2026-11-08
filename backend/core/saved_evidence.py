"""Explicitly retained findings with immutable, transactionally stored evidence.

SQLite BLOBs keep snapshot creation/deletion/GC in one transaction. This does not
turn sanitized or truncated observations into complete wire captures.
"""
import copy
import hashlib
import json
import math
import time
import uuid

from core.agent_findings import build_findings, valid_patch
from core.agent_models import AgentRequest
from core.agent_runtime_store import RunConflict
from core.ai_privacy import sanitize_headers
from core.saved_evidence_contracts import FindingSnapshot, SourceSnapshot

MAX_CAPTURE_BYTES = 10 * 1024 * 1024
MAX_VERSIONS = 100
MAX_EVENTS = 250
SNAPSHOT_KINDS = {'action', 'observation', 'verification'}


class EvidenceCorrupt(ValueError):
    pass


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def normalize_event(event, run_id, *, importing=False):
    if (not isinstance(event, dict) or event.get('run_id') != run_id or
            event.get('kind') not in SNAPSHOT_KINDS or not isinstance(event.get('data'), dict) or
            not isinstance(event.get('id'), str) or not 1 <= len(event['id']) <= 100 or
            not isinstance(event.get('step_id'), str) or len(event['step_id']) > 100 or
            type(event.get('created')) not in (int, float) or not math.isfinite(event['created'])):
        raise ValueError('증거 이벤트의 종류·식별자·시간이 올바르지 않습니다.')
    result = {key: copy.deepcopy(event[key]) for key in ('id', 'run_id', 'kind', 'step_id', 'created', 'data')}
    result['created'] = float(result['created'])
    if result['kind'] == 'observation':
        for key in ('request', 'response'):
            part = result['data'].get(key)
            if not isinstance(part, dict):
                raise ValueError('요청·응답이 없는 관측은 보존할 수 없습니다.')
            original = part.get('headers') or {}
            if not isinstance(original, dict):
                raise ValueError('관측 헤더의 형식이 올바르지 않습니다.')
            safe = sanitize_headers(original)
            if importing and original != safe:
                raise ValueError('패키지 증거에 보존할 수 없는 인증 헤더가 있습니다.')
            part['headers'] = safe
    return result


def snapshot(event):
    payload = encoded(event['data'])
    metadata = {key: event[key] for key in ('run_id', 'kind', 'step_id', 'created')}
    metadata.update(event_id=event['id'], blob_hash=digest(payload), length=len(payload))
    return {'id': digest(encoded(metadata)), **metadata}, payload


def validate_proof(finding, source, events, run_id, legacy_id):
    """Structural consistency only; archive hashes are not proof of authenticity."""
    if not isinstance(finding, dict) or finding.get('id') != legacy_id:
        raise ValueError('원본 발견 식별자가 일치하지 않습니다.')
    if finding.get('incomplete_evidence') or not finding.get('evidence_ids'):
        raise ValueError('관측 증거가 없거나 일부가 누락된 발견은 별도 보존할 수 없습니다.')
    refs = finding.get('evidence_ids', [])
    verifications = finding.get('verification_ids', [])
    if (not isinstance(refs, list) or not isinstance(verifications, list) or
            any(not isinstance(x, str) for x in refs + verifications)):
        raise ValueError('발견의 증거 참조가 올바르지 않습니다.')
    observations = {e['id'] for e in events if e['kind'] == 'observation'}
    verified = {e['id'] for e in events if e['kind'] == 'verification'}
    if set(refs) != observations or set(verifications) != verified:
        raise ValueError('발견과 관측·검증 참조가 일치하지 않습니다.')
    for event in events:
        if event['kind'] == 'verification':
            linked = event['data'].get('evidence_ids') or []
            if not isinstance(linked, list) or any(not isinstance(x, str) or x not in observations for x in linked):
                raise ValueError('검증이 존재하지 않는 관측을 참조합니다.')
    request = AgentRequest.model_validate(source['request']).model_dump()
    if request['headers']:
        raise ValueError('원본 실행 명세의 인증 헤더는 보존하지 않습니다.')
    rebuilt = build_findings(run_id, {'endpoints': {finding.get('endpoint_id', ''): request}}, events)
    proof = next((item for item in rebuilt if item['id'] == legacy_id), None)
    if proof is None or any(proof.get(key) != finding.get(key) for key in
                             ('category', 'endpoint_id', 'actor_id', 'verdict', 'method', 'origin', 'path', 'query_keys')):
        raise ValueError('검증 이벤트와 발견 판정이 일치하지 않습니다.')


class SavedEvidenceStore:
    def init_saved_evidence_schema(self):
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS saved_findings (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, source_run_id TEXT NOT NULL,
                    source_finding_id TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
                    revision INTEGER NOT NULL, current_version INTEGER NOT NULL,
                    status TEXT NOT NULL, severity TEXT NOT NULL, note TEXT NOT NULL,
                    UNIQUE(owner,source_run_id,source_finding_id));
                CREATE INDEX IF NOT EXISTS saved_findings_owner ON saved_findings(owner,updated DESC,id);
                CREATE TABLE IF NOT EXISTS saved_finding_versions (
                    finding_id TEXT NOT NULL, version INTEGER NOT NULL, created REAL NOT NULL,
                    source_digest TEXT NOT NULL, finding_json TEXT NOT NULL, source_json TEXT NOT NULL,
                    PRIMARY KEY(finding_id,version));
                CREATE TABLE IF NOT EXISTS saved_evidence_blobs (
                    hash TEXT PRIMARY KEY, length INTEGER NOT NULL, payload BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS saved_evidence_snapshots (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, event_id TEXT NOT NULL,
                    kind TEXT NOT NULL, step_id TEXT NOT NULL, created REAL NOT NULL,
                    blob_hash TEXT NOT NULL, length INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS saved_finding_evidence (
                    finding_id TEXT NOT NULL, version INTEGER NOT NULL, snapshot_id TEXT NOT NULL,
                    position INTEGER NOT NULL, PRIMARY KEY(finding_id,version,snapshot_id));
                CREATE TABLE IF NOT EXISTS saved_finding_changes (
                    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, created REAL NOT NULL,
                    actor TEXT NOT NULL, revision INTEGER NOT NULL, patch TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS saved_finding_deletions (
                    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, deleted REAL NOT NULL,
                    actor TEXT NOT NULL, versions INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS saved_finding_retests (
                    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, version INTEGER NOT NULL,
                    run_id TEXT NOT NULL, owner TEXT NOT NULL, created REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS saved_changes_finding ON saved_finding_changes(finding_id,revision);
                CREATE INDEX IF NOT EXISTS saved_binding_snapshot ON saved_finding_evidence(snapshot_id);
                CREATE INDEX IF NOT EXISTS saved_snapshot_blob ON saved_evidence_snapshots(blob_hash);
                CREATE INDEX IF NOT EXISTS saved_retests_finding ON saved_finding_retests(finding_id,created);
                INSERT OR IGNORE INTO store_migrations VALUES ('saved_evidence_v1');
            ''')

    def preserve_finding(self, run_id, finding_id, owner='', expected_revision=None, source_owner_filter=None):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            run = db.execute('SELECT state,data FROM runs WHERE id=?', (run_id,)).fetchone()
            if run is None:
                raise KeyError(run_id)
            data = json.loads(run['data'])
            if source_owner_filter is not None and data.get('owner', '') not in ('', source_owner_filter):
                raise PermissionError('다른 작업공간의 실행입니다.')
            owner = owner or data.get('owner', '')
            rows = db.execute('SELECT * FROM events WHERE run_id=? ORDER BY created,rowid', (run_id,)).fetchall()
            events = [{**dict(e), 'data': json.loads(e['data'])} for e in rows]
            try:
                finding = next((f for f in build_findings(run_id, data, events) if f['id'] == finding_id), None)
            except (TypeError, AttributeError) as exc:
                raise ValueError('원본 발견 데이터의 형식이 올바르지 않습니다.') from exc
            if finding is None:
                raise KeyError(finding_id)
            endpoint = (data.get('endpoints') or {}).get(finding['endpoint_id']) or (data.get('endpoints') or {}).get('seed')
            if not endpoint:
                raise ValueError('발견의 원본 요청을 찾을 수 없습니다.')
            request = AgentRequest.model_validate({**endpoint, 'headers': {}}).model_dump()
            source = {'goal': str((data.get('spec') or {}).get('goal', ''))[:2000],
                      'source_state': run['state'], 'request': request}
            finding = FindingSnapshot.model_validate(finding).model_dump()
            source = SourceSnapshot.model_validate(source).model_dump()
            needed = set(finding['evidence_ids'] + finding['verification_ids'])
            selected = [normalize_event(e, run_id) for e in events if e['id'] in needed or
                        (e['kind'] == 'action' and e['step_id'] in finding['step_ids'])]
            if len(selected) > MAX_EVENTS:
                raise ValueError('한 발견의 보존 이벤트 수 한도를 초과했습니다.')
            validate_proof(finding, source, selected, run_id, finding_id)
            snapshots = [snapshot(e) for e in selected]
            if len(encoded(finding)) + len(encoded(source)) + sum(len(b) for _, b in snapshots) > MAX_CAPTURE_BYTES:
                raise ValueError('선택한 발견의 증거가 10 MiB 한도를 초과했습니다.')
            fingerprint = digest(encoded({'finding': finding, 'source': source,
                                         'snapshots': [s['id'] for s, _ in snapshots]}))
            existing = db.execute('SELECT * FROM saved_findings WHERE owner=? AND source_run_id=? '
                                  'AND source_finding_id=?', (owner, run_id, finding_id)).fetchone()
            now = time.time()
            if existing:
                current = db.execute('SELECT source_digest FROM saved_finding_versions WHERE finding_id=? AND version=?',
                                     (existing['id'], existing['current_version'])).fetchone()
                if current['source_digest'] == fingerprint:
                    retained = self._saved_finding_tx(db, existing['id'], existing['current_version'])
                    for ref in retained['evidence']:
                        self._saved_event_tx(db, existing['id'], ref['id'], existing['current_version'])
                    return {'id': existing['id'], 'revision': existing['revision'],
                            'version': existing['current_version'], 'unchanged': True}
                if expected_revision != existing['revision']:
                    raise RunConflict('이미 보존한 발견이 있습니다. 최신 보존 버전을 확인한 뒤 갱신하세요.')
                if existing['current_version'] >= MAX_VERSIONS:
                    raise ValueError('발견 버전 수 한도를 초과했습니다.')
                saved_id, version = existing['id'], existing['current_version'] + 1
                revision = existing['revision'] + 1
                db.execute('UPDATE saved_findings SET updated=?,revision=?,current_version=? WHERE id=?',
                           (now, revision, version, saved_id))
            else:
                if expected_revision is not None:
                    raise RunConflict('갱신할 보존 발견이 없습니다.')
                saved_id, version, revision = uuid.uuid4().hex, 1, 1
                db.execute('INSERT INTO saved_findings VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                           (saved_id, owner, run_id, finding_id, now, now, revision, version,
                            finding['status'], finding['severity'], finding.get('note', '')))
            db.execute('INSERT INTO saved_finding_versions VALUES (?,?,?,?,?,?)',
                       (saved_id, version, now, fingerprint, encoded(finding).decode(), encoded(source).decode()))
            for position, (info, payload) in enumerate(snapshots):
                self._insert_saved_snapshot(db, info, payload)
                db.execute('INSERT INTO saved_finding_evidence VALUES (?,?,?,?)',
                           (saved_id, version, info['id'], position))
            return {'id': saved_id, 'revision': revision, 'version': version, 'unchanged': False}

    @staticmethod
    def _insert_saved_snapshot(db, info, payload):
        if len(payload) != info['length'] or digest(payload) != info['blob_hash']:
            raise EvidenceCorrupt('증거 본문 길이 또는 해시가 일치하지 않습니다.')
        metadata = {k: info[k] for k in ('run_id', 'event_id', 'kind', 'step_id', 'created', 'blob_hash', 'length')}
        if digest(encoded(metadata)) != info['id']:
            raise EvidenceCorrupt('증거 스냅샷 메타데이터가 일치하지 않습니다.')
        old = db.execute('SELECT * FROM saved_evidence_blobs WHERE hash=?', (info['blob_hash'],)).fetchone()
        if old is not None and (old['length'] != len(payload) or bytes(old['payload']) != payload):
            raise EvidenceCorrupt('기존 증거 본문이 손상됐습니다.')
        if old is None and db.execute('SELECT 1 FROM saved_evidence_snapshots WHERE blob_hash=? LIMIT 1',
                                      (info['blob_hash'],)).fetchone():
            raise EvidenceCorrupt('기존 증거 본문이 누락됐습니다. 자동으로 덮어쓰지 않습니다.')
        db.execute('INSERT OR IGNORE INTO saved_evidence_blobs VALUES (?,?,?)',
                   (info['blob_hash'], len(payload), payload))
        prior = db.execute('SELECT * FROM saved_evidence_snapshots WHERE id=?', (info['id'],)).fetchone()
        if prior is not None and dict(prior) != info:
            raise EvidenceCorrupt('기존 증거 스냅샷과 충돌합니다.')
        db.execute('INSERT OR IGNORE INTO saved_evidence_snapshots VALUES (?,?,?,?,?,?,?,?)',
                   tuple(info[k] for k in ('id', 'run_id', 'event_id', 'kind', 'step_id', 'created', 'blob_hash', 'length')))

    def saved_finding(self, saved_id, version=None, owner_filter=None):
        with self.connect() as db:
            db.execute('BEGIN')
            return self._saved_finding_tx(db, saved_id, version, owner_filter)

    @staticmethod
    def _saved_finding_tx(db, saved_id, version=None, owner_filter=None):
        row = db.execute('SELECT * FROM saved_findings WHERE id=?', (saved_id,)).fetchone()
        if row is None:
            raise KeyError(saved_id)
        if owner_filter is not None and row['owner'] not in ('', owner_filter):
            raise PermissionError('다른 작업공간의 보존 발견입니다.')
        item = dict(row)
        version = item['current_version'] if version is None else version
        snapshot_row = db.execute('SELECT * FROM saved_finding_versions WHERE finding_id=? AND version=?',
                                  (saved_id, version)).fetchone()
        if snapshot_row is None:
            raise KeyError(version)
        evidence = db.execute('SELECT s.* '
                              'FROM saved_finding_evidence b LEFT JOIN saved_evidence_snapshots s ON s.id=b.snapshot_id '
                              'WHERE b.finding_id=? AND b.version=? ORDER BY b.position', (saved_id, version)).fetchall()
        versions = [dict(r) for r in db.execute('SELECT version,created FROM saved_finding_versions '
                                                'WHERE finding_id=? ORDER BY version DESC', (saved_id,))]
        changes = [dict(r) for r in db.execute('SELECT created,actor,revision,patch FROM saved_finding_changes '
                                              'WHERE finding_id=? ORDER BY revision', (saved_id,))]
        if any(e['id'] is None for e in evidence):
            raise EvidenceCorrupt('보존 증거 스냅샷이 누락됐습니다.')
        finding = json.loads(snapshot_row['finding_json'])
        source = json.loads(snapshot_row['source_json'])
        checksum = digest(encoded({'finding': finding, 'source': source, 'snapshots': [e['id'] for e in evidence]}))
        if checksum != snapshot_row['source_digest']:
            raise EvidenceCorrupt('보존 발견의 메타데이터 해시가 손상됐습니다.')
        for e in evidence:
            metadata = {k: e[k] for k in ('run_id', 'event_id', 'kind', 'step_id', 'created', 'blob_hash', 'length')}
            if digest(encoded(metadata)) != e['id']:
                raise EvidenceCorrupt('보존 스냅샷의 메타데이터 해시가 손상됐습니다.')
        finding.update(id=saved_id, status=item['status'], severity=item['severity'], note=item['note'])
        return {**item, 'version': version, 'finding': finding, 'source': source,
                'evidence': [{k: e[k] for k in ('id', 'event_id', 'kind', 'step_id', 'created', 'length')} for e in evidence], 'versions': versions,
                'changes': [{**c, 'patch': json.loads(c['patch'])} for c in changes]}

    def saved_finding_page(self, owner=None, search='', offset=0, limit=25):
        clauses, params = [], []
        if owner is not None:
            clauses.append("f.owner IN ('',?)")
            params.append(owner)
        if search:
            clauses.append("(instr(lower(v.finding_json),lower(?))>0 OR instr(lower(f.note),lower(?))>0)")
            params.extend([search, search])
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        join = ' FROM saved_findings f JOIN saved_finding_versions v ON v.finding_id=f.id AND v.version=f.current_version'
        with self.connect() as db:
            total = db.execute('SELECT COUNT(*)'+join+where, params).fetchone()[0]
            rows = db.execute('SELECT f.*,v.finding_json'+join+where+' ORDER BY f.updated DESC,f.id DESC LIMIT ? OFFSET ?',
                              [*params, limit, offset]).fetchall()
        items = []
        for r in rows:
            f = json.loads(r['finding_json'])
            items.append({key: r[key] for key in ('id', 'source_run_id', 'source_finding_id', 'updated',
                                                    'revision', 'current_version', 'status', 'severity')} |
                         {key: f.get(key) for key in ('category', 'method', 'origin', 'path', 'verdict')})
        return {'items': items, 'total': total, 'offset': offset, 'limit': limit,
                'has_more': offset + len(items) < total}

    def saved_event(self, saved_id, snapshot_id, version=None, owner_filter=None):
        with self.connect() as db:
            db.execute('BEGIN')
            self._saved_finding_tx(db, saved_id, version, owner_filter)
            return self._saved_event_tx(db, saved_id, snapshot_id, version)

    @staticmethod
    def _saved_event_tx(db, saved_id, snapshot_id, version=None):
        if version is None:
            row = db.execute('SELECT current_version FROM saved_findings WHERE id=?', (saved_id,)).fetchone()
            if row is None:
                raise KeyError(saved_id)
            version = row['current_version']
        row = db.execute('SELECT s.*,b.payload,b.length AS actual_length FROM saved_finding_evidence e '
                         'LEFT JOIN saved_evidence_snapshots s ON s.id=e.snapshot_id '
                         'LEFT JOIN saved_evidence_blobs b ON b.hash=s.blob_hash '
                         'WHERE e.finding_id=? AND e.version=? AND e.snapshot_id=?',
                         (saved_id, version, snapshot_id)).fetchone()
        if row is None:
            raise KeyError(snapshot_id)
        if row['id'] is None or row['payload'] is None:
            raise EvidenceCorrupt('보존 증거 본문 또는 스냅샷이 누락됐습니다.')
        payload = bytes(row['payload'])
        metadata = {key: row[key] for key in ('run_id', 'event_id', 'kind', 'step_id', 'created', 'blob_hash', 'length')}
        if (len(payload) != row['length'] or row['actual_length'] != row['length'] or
                digest(payload) != row['blob_hash'] or digest(encoded(metadata)) != row['id']):
            raise EvidenceCorrupt('보존한 증거의 길이 또는 해시가 손상됐습니다.')
        try:
            data = json.loads(payload)
        except (ValueError, UnicodeDecodeError) as exc:
            raise EvidenceCorrupt('보존한 증거를 읽을 수 없습니다.') from exc
        return {'id': row['event_id'], 'run_id': row['run_id'], 'kind': row['kind'],
                'step_id': row['step_id'], 'created': row['created'], 'data': data}

    def saved_execution_view(self, saved_id, version=None, owner_filter=None):
        # Read the metadata and bodies from one consistent SQLite snapshot.
        with self.connect() as db:
            db.execute('BEGIN')
            record = self._saved_finding_tx(db, saved_id, version, owner_filter)
            events = [self._saved_event_tx(db, saved_id, e['id'], record['version']) for e in record['evidence']]
        f = record['finding']
        counts = {key: int(f['verdict'] == key) for key in ('confirmed', 'suspicious', 'inconclusive')}
        return {'id': record['source_run_id'], 'state': 'saved_snapshot', 'findings': [f], 'events': events,
                'data': {'spec': {'goal': record['source']['goal']},
                         'endpoints': {f['endpoint_id']: record['source']['request']}},
                'conclusion': {'verdict': f['verdict'], 'completion': 'snapshot', 'counts': counts,
                               'observation_count': sum(e['kind'] == 'observation' for e in events),
                               'text': '보존한 시점의 발견과 증거입니다. 현재 대상의 상태를 새로 확인한 결과가 아닙니다.',
                               'scope_note': '원본 실행 삭제와 별개로 사용자가 선택하여 보존한 증거입니다.'}}

    def patch_saved_finding(self, saved_id, patch, expected_revision, actor='', owner_filter=None):
        cleaned = valid_patch(patch)
        if not cleaned:
            raise ValueError('변경할 상태·심각도·메모가 없습니다.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM saved_findings WHERE id=?', (saved_id,)).fetchone()
            if row is None:
                raise KeyError(saved_id)
            if owner_filter is not None and row['owner'] not in ('', owner_filter):
                raise PermissionError('다른 작업공간의 보존 발견입니다.')
            if expected_revision != row['revision']:
                raise RunConflict('보존 발견이 변경됐습니다. 다시 조회하세요.')
            if db.execute('SELECT COUNT(*) FROM saved_finding_changes WHERE finding_id=?', (saved_id,)).fetchone()[0] >= 10000:
                raise ValueError('보존 발견의 변경 이력 한도를 초과했습니다.')
            revision = row['revision'] + 1
            db.execute('UPDATE saved_findings SET status=?,severity=?,note=?,revision=?,updated=? WHERE id=?',
                       (cleaned.get('status', row['status']), cleaned.get('severity', row['severity']),
                        cleaned.get('note', row['note']), revision, time.time(), saved_id))
            db.execute('INSERT INTO saved_finding_changes VALUES (?,?,?,?,?,?)',
                       (uuid.uuid4().hex, saved_id, time.time(), actor, revision, encoded(cleaned).decode()))
        return self.saved_finding(saved_id, owner_filter=owner_filter)

    def delete_saved_finding(self, saved_id, expected_revision, actor='', owner_filter=None):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT owner,revision,current_version FROM saved_findings WHERE id=?', (saved_id,)).fetchone()
            if row is None:
                raise KeyError(saved_id)
            if owner_filter is not None and row['owner'] not in ('', owner_filter):
                raise PermissionError('다른 작업공간의 보존 발견입니다.')
            if expected_revision != row['revision']:
                raise RunConflict('보존 발견이 변경됐습니다. 다시 조회하세요.')
            db.execute('INSERT INTO saved_finding_deletions VALUES (?,?,?,?,?)',
                       (uuid.uuid4().hex, saved_id, time.time(), actor, row['current_version']))
            for table in ('saved_finding_evidence', 'saved_finding_versions', 'saved_finding_changes', 'saved_finding_retests'):
                db.execute(f'DELETE FROM {table} WHERE finding_id=?', (saved_id,))
            db.execute('DELETE FROM saved_findings WHERE id=?', (saved_id,))
            db.execute('DELETE FROM saved_evidence_snapshots WHERE NOT EXISTS '
                       '(SELECT 1 FROM saved_finding_evidence e WHERE e.snapshot_id=saved_evidence_snapshots.id)')
            db.execute('DELETE FROM saved_evidence_blobs WHERE NOT EXISTS '
                       '(SELECT 1 FROM saved_evidence_snapshots s WHERE s.blob_hash=saved_evidence_blobs.hash)')


    def create_saved_retest(self, data, saved_id, version, owner_filter=None):
        from core.agent_assets import reindex_run
        run_id = uuid.uuid4().hex
        now = time.time()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            self._saved_finding_tx(db, saved_id, version, owner_filter)
            db.execute('INSERT INTO runs VALUES (?,?,?,?,?)',
                       (run_id, now, now, 'paused', json.dumps(data, ensure_ascii=False)))
            reindex_run(db, run_id, data)
            db.execute('INSERT INTO saved_finding_retests VALUES (?,?,?,?,?,?)',
                       (uuid.uuid4().hex, saved_id, version, run_id, data.get('owner', ''), now))
        return run_id

    def saved_retest_page(self, saved_id, owner_filter=None, offset=0, limit=25):
        with self.connect() as db:
            db.execute('BEGIN')
            self._saved_finding_tx(db, saved_id, owner_filter=owner_filter)
            condition = 't.finding_id=?'
            params = [saved_id]
            if owner_filter is not None:
                condition += " AND t.owner IN ('',?)"
                params.append(owner_filter)
            total = db.execute('SELECT COUNT(*) FROM saved_finding_retests t WHERE '+condition, params).fetchone()[0]
            rows = db.execute('SELECT t.run_id,t.created,t.version,t.owner,r.state,r.data '
                              'FROM saved_finding_retests t LEFT JOIN runs r ON r.id=t.run_id '
                              'WHERE '+condition+' ORDER BY t.created DESC,t.id DESC LIMIT ? OFFSET ?',
                              [*params, limit, offset]).fetchall()
            items = []
            for row in rows:
                available = row['state'] is not None
                if available and owner_filter is not None:
                    available = json.loads(row['data']).get('owner', '') in ('', owner_filter)
                result = db.execute('SELECT verdict,incomplete_evidence FROM finding_index WHERE run_id=? '
                                    "ORDER BY CASE verdict WHEN 'confirmed' THEN 2 WHEN 'suspicious' THEN 1 ELSE 0 END DESC LIMIT 1",
                                    (row['run_id'],)).fetchone() if available else None
                items.append({'run_id': row['run_id'], 'created': row['created'], 'version': row['version'],
                              'state': row['state'] if available else None, 'evidence_available': available,
                              'verdict': result['verdict'] if result else None,
                              'incomplete_evidence': bool(result['incomplete_evidence']) if result else None})
        return {'items': items, 'total': total, 'offset': offset, 'limit': limit,
                'has_more': offset + len(items) < total}
