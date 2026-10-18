"""Local durable run/evidence log. Credentials remain in the runtime session."""
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from core.agent_archive import build_archive, read_archive
from core.agent_assets import reindex_run
from core.agent_indexes import (FINDING_KINDS, TRAFFIC_KINDS, index_traffic_event,
                                reindex_findings, reindex_run as reindex_lookup_run)


def uid():
    return uuid.uuid4().hex


def _credential_free_template_spec(spec):
    """Enforce the credential boundary even for direct store calls and old rows."""
    data = json.loads(json.dumps(spec, ensure_ascii=False))
    request = data.get('request')
    if isinstance(request, dict) and 'headers' in request:
        request['headers'] = {}
    for actor in data.get('actors') or []:
        if isinstance(actor, dict) and 'headers' in actor:
            actor['headers'] = {}
    return data


class Store:
    def __init__(self, path=None):
        self.path = Path(path or os.getenv('AGENT_DB_PATH') or
                         Path(__file__).resolve().parents[1] / 'data' / 'agent' / 'runs.sqlite3')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, created REAL NOT NULL, updated REAL NOT NULL,
                    state TEXT NOT NULL, data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS runs_incident ON runs(json_extract(data, '$.incident.incident_id'));
                CREATE INDEX IF NOT EXISTS runs_history_archive ON runs(
                    COALESCE(json_extract(data, '$.archived'), 0), created DESC, id DESC);
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, created REAL NOT NULL,
                    kind TEXT NOT NULL, step_id TEXT NOT NULL, data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_run ON events(run_id, created);
                CREATE TABLE IF NOT EXISTS deletions (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, deleted REAL NOT NULL,
                    reason TEXT NOT NULL, state TEXT NOT NULL, events INTEGER NOT NULL,
                    goal TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS templates (
                    id TEXT PRIMARY KEY, created REAL NOT NULL, name TEXT NOT NULL,
                    category TEXT NOT NULL, spec TEXT NOT NULL,
                    owner TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS template_revisions (
                    template_id TEXT NOT NULL, version INTEGER NOT NULL, created REAL NOT NULL,
                    name TEXT NOT NULL, category TEXT NOT NULL, spec TEXT NOT NULL,
                    owner TEXT NOT NULL, PRIMARY KEY(template_id,version));
                CREATE TABLE IF NOT EXISTS store_migrations (name TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY, origin TEXT NOT NULL, method TEXT NOT NULL,
                    path TEXT NOT NULL, query_keys TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS asset_refs (
                    run_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, asset_id TEXT NOT NULL,
                    field_keys TEXT NOT NULL, PRIMARY KEY(run_id,endpoint_id));
                CREATE INDEX IF NOT EXISTS asset_refs_asset ON asset_refs(asset_id,run_id);
                CREATE TABLE IF NOT EXISTS traffic_index (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, created REAL NOT NULL,
                    source TEXT NOT NULL, method TEXT NOT NULL, origin TEXT NOT NULL,
                    path TEXT NOT NULL, status INTEGER, asset_id TEXT NOT NULL,
                    request_id TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS traffic_index_run ON traffic_index(run_id,created DESC,id DESC);
                CREATE INDEX IF NOT EXISTS traffic_index_asset ON traffic_index(asset_id,created DESC,id DESC);
                CREATE TABLE IF NOT EXISTS finding_index (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, created REAL NOT NULL,
                    updated REAL NOT NULL, category TEXT NOT NULL, verdict TEXT NOT NULL,
                    status TEXT NOT NULL, severity TEXT NOT NULL, method TEXT NOT NULL,
                    origin TEXT NOT NULL, path TEXT NOT NULL, asset_id TEXT NOT NULL,
                    evidence_count INTEGER NOT NULL, incomplete_evidence INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS finding_index_run ON finding_index(run_id,updated DESC,id DESC);
                CREATE INDEX IF NOT EXISTS finding_index_asset ON finding_index(asset_id,updated DESC,id DESC);
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY, created REAL NOT NULL, source TEXT NOT NULL,
                    asset_id TEXT NOT NULL, traffic_id TEXT NOT NULL, category TEXT NOT NULL,
                    owner TEXT NOT NULL, data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS incidents_asset ON incidents(asset_id, created);
                CREATE INDEX IF NOT EXISTS incidents_recent ON incidents(created DESC,id DESC);
                CREATE INDEX IF NOT EXISTS incidents_owner_recent ON incidents(owner,created DESC,id DESC);
                CREATE TABLE IF NOT EXISTS incident_deletions (
                    id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, deleted REAL NOT NULL,
                    created REAL NOT NULL, source TEXT NOT NULL, category TEXT NOT NULL,
                    owner TEXT NOT NULL);
            ''')
            if 'owner' not in {row['name'] for row in db.execute('PRAGMA table_info(templates)')}:
                db.execute("ALTER TABLE templates ADD COLUMN owner TEXT NOT NULL DEFAULT ''")
            db.execute('INSERT OR IGNORE INTO template_revisions '
                       '(template_id,version,created,name,category,spec,owner) '
                       'SELECT id,1,created,name,category,spec,owner FROM templates')
            if db.execute("SELECT 1 FROM store_migrations WHERE name='asset_index_v1'").fetchone() is None:
                for row in db.execute('SELECT id,data FROM runs').fetchall():
                    try:
                        reindex_run(db, row['id'], json.loads(row['data']))
                    except (ValueError, TypeError, AttributeError):
                        continue
                db.execute("INSERT OR IGNORE INTO store_migrations VALUES ('asset_index_v1')")
            if db.execute("SELECT 1 FROM store_migrations WHERE name='lookup_index_v1'").fetchone() is None:
                for row in db.execute('SELECT id FROM runs').fetchall():
                    reindex_lookup_run(db, row['id'])
                db.execute("INSERT OR IGNORE INTO store_migrations VALUES ('lookup_index_v1')")
            if db.execute("SELECT 1 FROM store_migrations WHERE name='template_headers_v1'").fetchone() is None:
                for table in ('templates', 'template_revisions'):
                    for row in db.execute(f'SELECT rowid,spec FROM {table}').fetchall():
                        try:
                            original = json.loads(row['spec'])
                            clean = _credential_free_template_spec(original)
                        except (ValueError, TypeError, AttributeError):
                            continue  # Leave malformed legacy rows untouched for explicit repair.
                        if clean != original:
                            db.execute(f'UPDATE {table} SET spec=? WHERE rowid=?',
                                       (json.dumps(clean, ensure_ascii=False), row['rowid']))
                db.execute("INSERT OR IGNORE INTO store_migrations VALUES ('template_headers_v1')")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, data):
        run_id = uid()
        with self.connect() as db:
            db.execute('INSERT INTO runs VALUES (?,?,?,?,?)',
                       (run_id, time.time(), time.time(), 'paused', json.dumps(data, ensure_ascii=False)))
            reindex_run(db, run_id, data)
        return run_id

    def get(self, run_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
        if row is None:
            raise KeyError(run_id)
        return {**dict(row), 'data': json.loads(row['data'])}

    def run_owner(self, run_id):
        with self.connect() as db:
            row = db.execute("SELECT COALESCE(json_extract(data,'$.owner'),'') AS owner "
                             'FROM runs WHERE id=?', (run_id,)).fetchone()
        if row is None:
            raise KeyError(run_id)
        return row['owner']

    def run_status_fields(self, run_id):
        """Projection for frequent history polls; never materialize stored evidence fields."""
        with self.connect() as db:
            row = db.execute(
                'SELECT state,updated,'
                "COALESCE(json_extract(data,'$.spec.goal'),'') AS goal,"
                "COALESCE(json_extract(data,'$.spec.mode'),'') AS mode,"
                "COALESCE(json_extract(data,'$.spec.max_steps'),0) AS max_steps,"
                "COALESCE(json_extract(data,'$.spec.max_requests'),0) AS max_requests,"
                "COALESCE(json_extract(data,'$.spec.max_ai_calls'),0) AS max_ai_calls,"
                "json_extract(data,'$.spec.approved_plan_revoked_at') AS approved_plan_revoked_at,"
                "CASE WHEN json_type(data,'$.spec.approved_plan') IN ('object','array') "
                'THEN 1 ELSE 0 END AS has_approved_plan,'
                "json_extract(data,'$.plan_checkpoint') AS plan_checkpoint,"
                "COALESCE(json_extract(data,'$.name'),'') AS name,"
                "COALESCE(json_extract(data,'$.category'),'') AS category,"
                "COALESCE(json_extract(data,'$.archived'),0) AS archived,"
                "COALESCE(json_extract(data,'$.steps'),0) AS steps,"
                "COALESCE(json_extract(data,'$.requests'),0) AS requests,"
                "COALESCE(json_extract(data,'$.ai_calls'),0) AS ai_calls,"
                "COALESCE(json_extract(data,'$.elapsed'),0) AS elapsed,"
                "COALESCE(json_extract(data,'$.reason'),'') AS reason,"
                "json_extract(data,'$.retest_of') AS retest_of "
                'FROM runs WHERE id=?', (run_id,),
            ).fetchone()
            if row is None:
                raise KeyError(run_id)
            endpoints_count = db.execute(
                "SELECT COUNT(*) FROM runs,json_each(runs.data,'$.endpoints') WHERE runs.id=?",
                (run_id,),
            ).fetchone()[0]
        result = dict(row)
        result['plan_checkpoint'] = json.loads(result['plan_checkpoint']) if result['plan_checkpoint'] else None
        result['has_approved_plan'] = bool(result['has_approved_plan'])
        result['archived'] = bool(result['archived'])
        result['endpoints_count'] = endpoints_count
        return result

    def export_run_archive(self, run_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            events = db.execute('SELECT * FROM events WHERE run_id=? ORDER BY created,rowid',
                                (run_id,)).fetchall()
        run = {**dict(row), 'data': json.loads(row['data'])}
        records = [{**dict(event), 'data': json.loads(event['data'])} for event in events]
        return build_archive(run, records)

    def import_run_archive(self, blob, owner=''):
        """Restore IDs and relations transactionally; keep the run archived, never start it."""
        run, events = read_archive(blob)
        data = run['data']
        data['owner'] = owner or ''
        data['archived'] = True
        data['restored_at'] = time.time()
        with self.connect() as db:
            if db.execute('SELECT 1 FROM runs WHERE id=?', (run['id'],)).fetchone():
                raise ValueError('동일한 작업 ID가 이미 존재합니다.')
            for event in events:
                if db.execute('SELECT 1 FROM events WHERE id=?', (event['id'],)).fetchone():
                    raise ValueError('동일한 증거/이벤트 ID가 이미 존재합니다.')
            db.execute('INSERT INTO runs VALUES (?,?,?,?,?)',
                       (run['id'], run['created'], time.time(), run['state'],
                        json.dumps(data, ensure_ascii=False)))
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?)',
                           [(event['id'], run['id'], event['created'], event['kind'], event['step_id'],
                             json.dumps(event['data'], ensure_ascii=False)) for event in events])
            reindex_run(db, run['id'], data)
            reindex_lookup_run(db, run['id'])
        return {'id': run['id'], 'state': run['state'], 'archived': True,
                'event_count': len(events)}

    def update(self, run_id, data, state=None):
        state = state or self.get(run_id)['state']
        with self.connect() as db:
            db.execute('UPDATE runs SET updated=?,state=?,data=? WHERE id=?',
                       (time.time(), state, json.dumps(data, ensure_ascii=False), run_id))
            reindex_run(db, run_id, data)

    def set_run_metadata(self, run_id, name, category):
        """Edit display fields atomically without overwriting evidence or an active run."""
        with self.connect() as db:
            changed = db.execute(
                "UPDATE runs SET updated=?,data=json_set(data,'$.name',?,'$.category',?) "
                "WHERE id=? AND state!='running'",
                (time.time(), name, category, run_id),
            ).rowcount
            if not changed:
                if db.execute('SELECT 1 FROM runs WHERE id=?', (run_id,)).fetchone() is None:
                    raise KeyError(run_id)
                raise ValueError('실행 중인 작업의 이름과 분류는 수정할 수 없습니다.')
        return {'id': run_id, 'name': name, 'category': category}

    def claim(self, run_id):
        with self.connect() as db:
            return db.execute("UPDATE runs SET state='running',updated=? WHERE id=? "
                              "AND state IN ('paused','interrupted') "
                              "AND COALESCE(json_extract(data, '$.archived'), 0) = 0 "
                              "AND json_extract(data, '$.restored_at') IS NULL "
                              "AND json_extract(data, '$.spec.approved_plan_revoked_at') IS NULL",
                              (time.time(), run_id)).rowcount == 1

    def set_archived(self, run_id, archived):
        """Change only the archive flag, conditional on state in the same transaction."""
        with self.connect() as db:
            changed = db.execute(
                "UPDATE runs SET updated=?,data=json_set(data,'$.archived',json(?)) "
                "WHERE id=? AND (?=0 OR state!='running')",
                (time.time(), 'true' if archived else 'false', run_id, int(bool(archived))),
            ).rowcount
            if not changed:
                if db.execute('SELECT 1 FROM runs WHERE id=?', (run_id,)).fetchone() is None:
                    raise KeyError(run_id)
                raise ValueError('실행 중인 작업은 보관할 수 없습니다. 먼저 중단하세요.')

    def recover(self):
        with self.connect() as db:
            db.execute("UPDATE runs SET state='interrupted' WHERE state='running'")

    def list(self, include_archived=False, owner=None):
        """최근 run 목록(최대 50). 범위가 켜졌으면 소유자 필터를 먼저 적용한다."""
        where = "WHERE COALESCE(json_extract(data, '$.archived'), 0) = ? "
        params = [int(bool(include_archived))]
        if owner is not None:
            where += "AND COALESCE(json_extract(data, '$.owner'), '') IN ('', ?) "
            params.append(owner)
        with self.connect() as db:
            rows = db.execute(
                "SELECT id,created,updated,state,data FROM runs "
                + where + 'ORDER BY created DESC,id DESC LIMIT 50', params
            ).fetchall()
        out = []
        for r in rows:
            data = json.loads(r['data'])
            out.append({'id': r['id'], 'state': r['state'], 'created': r['created'],
                        'goal': data['spec']['goal'], 'owner': data.get('owner', ''),
                        'archived': bool(data.get('archived'))})
        return out

    def asset_page(self, search='', archived=False, owner=None, limit=50, offset=0):
        """Page distinct assets, then fetch only matching run provenance."""
        scope = "COALESCE(json_extract(r.data,'$.archived'),0)=?"
        scope_params = [int(bool(archived))]
        if owner is not None:
            scope += " AND COALESCE(json_extract(r.data,'$.owner'),'') IN ('',?)"
            scope_params.append(owner)
        where = ('EXISTS (SELECT 1 FROM asset_refs ar JOIN runs r ON r.id=ar.run_id '
                 f'WHERE ar.asset_id=a.id AND {scope})')
        params = list(scope_params)
        if search:
            where += (' AND (instr(lower(a.origin),lower(?))>0 OR '
                      'instr(lower(a.path),lower(?))>0 OR '
                      'instr(lower(a.method),lower(?))>0 OR '
                      'instr(lower(a.query_keys),lower(?))>0)')
            params.extend([search] * 4)
        with self.connect() as db:
            total = db.execute(f'SELECT COUNT(*) FROM assets a WHERE {where}', params).fetchone()[0]
            page = db.execute('SELECT a.* FROM assets a WHERE ' + where +
                              ' ORDER BY a.origin,a.path,a.method,a.id LIMIT ? OFFSET ?',
                              (*params, limit, offset)).fetchall()
            result = []
            for asset in page:
                refs = db.execute(
                    'SELECT ar.endpoint_id,ar.field_keys,r.id AS run_id,r.created,r.updated,r.state,'
                    "COALESCE(json_extract(r.data,'$.name'),'') AS name "
                    'FROM asset_refs ar JOIN runs r ON r.id=ar.run_id '
                    f'WHERE ar.asset_id=? AND {scope} ORDER BY r.created DESC,r.id DESC',
                    (asset['id'], *scope_params),
                ).fetchall()
                runs = {}
                fields = set()
                for ref in refs:
                    fields.update(json.loads(ref['field_keys']))
                    runs.setdefault(ref['run_id'], {'id': ref['run_id'], 'name': ref['name'],
                                                    'state': ref['state'], 'created': ref['created']})
                result.append({'id': asset['id'], 'origin': asset['origin'],
                               'method': asset['method'], 'path': asset['path'],
                               'query': json.loads(asset['query_keys']), 'fields': sorted(fields),
                               'run_count': len(runs), 'runs': list(runs.values())[:20],
                               'first_seen': min(ref['created'] for ref in refs),
                               'last_seen': max(ref['updated'] for ref in refs)})
        return {'assets': result, 'total': total, 'offset': offset, 'limit': limit,
                'has_more': offset + len(result) < total}

    def lookup_page(self, kind, *, search='', run_id='', asset_id='', archived=False,
                    owner=None, method='', source='', verdict='', status='',
                    limit=50, offset=0):
        """Server-side search over value-free traffic/finding projections."""
        if kind not in ('traffic', 'finding'):
            raise ValueError('Unknown lookup kind')
        table = 'traffic_index' if kind == 'traffic' else 'finding_index'
        alias = 'x'
        clauses = ["COALESCE(json_extract(r.data,'$.archived'),0)=?"]
        params = [int(bool(archived))]
        if owner is not None:
            clauses.append("COALESCE(json_extract(r.data,'$.owner'),'') IN ('',?)")
            params.append(owner)
        if run_id:
            clauses.append('x.run_id=?')
            params.append(run_id)
        if asset_id:
            clauses.append('x.asset_id=?')
            params.append(asset_id)
        if method:
            clauses.append('x.method=?')
            params.append(method.upper())
        if kind == 'traffic' and source:
            clauses.append('x.source=?')
            params.append(source)
        if kind == 'finding' and verdict:
            clauses.append('x.verdict=?')
            params.append(verdict)
        if kind == 'finding' and status:
            clauses.append('x.status=?')
            params.append(status)
        if search:
            columns = ['x.origin', 'x.path', 'x.method']
            if kind == 'finding':
                columns.append('x.category')
            clauses.append('(' + ' OR '.join(f'instr(lower({col}),lower(?))>0'
                                              for col in columns) + ')')
            params.extend([search] * len(columns))
        where = ' AND '.join(clauses)
        order = 'x.created' if kind == 'traffic' else 'x.updated'
        with self.connect() as db:
            total = db.execute(f'SELECT COUNT(*) FROM {table} x JOIN runs r ON r.id=x.run_id '
                               f'WHERE {where}', params).fetchone()[0]
            rows = db.execute(f'SELECT x.* FROM {table} x JOIN runs r ON r.id=x.run_id '
                              f'WHERE {where} ORDER BY {order} DESC,x.id DESC LIMIT ? OFFSET ?',
                              (*params, limit, offset)).fetchall()
        items = [dict(row) for row in rows]
        if kind == 'finding':
            for item in items:
                item['incomplete_evidence'] = bool(item['incomplete_evidence'])
        return {'items': items, 'total': total, 'offset': offset, 'limit': limit,
                'has_more': offset + len(items) < total}

    def diagnostic_page(self, *, owner=None, limit=20, offset=0):
        """Durable per-run stop and tool metadata; no requests or evidence bodies."""
        where = "COALESCE(json_extract(data,'$.archived'),0)=0"
        params = []
        if owner is not None:
            where += " AND COALESCE(json_extract(data,'$.owner'),'') IN ('',?)"
            params.append(owner)
        with self.connect() as db:
            total = db.execute(f'SELECT COUNT(*) FROM runs WHERE {where}', params).fetchone()[0]
            rows = db.execute(
                'SELECT id,created,updated,state,'
                "COALESCE(json_extract(data,'$.name'),'') AS name,"
                "COALESCE(json_extract(data,'$.reason'),'') AS reason,"
                "COALESCE(json_extract(data,'$.spec.policy_version'),1) AS policy_version,"
                "COALESCE(json_extract(data,'$.ai_calls'),0) AS ai_calls,"
                "json_extract(data,'$.planner_attempts') AS planner_attempts,"
                "json_extract(data,'$.procedure_sha256.agent') AS procedure_sha256 "
                f'FROM runs WHERE {where} ORDER BY updated DESC,id DESC LIMIT ? OFFSET ?',
                (*params, limit, offset),
            ).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                attempts = json.loads(item.pop('planner_attempts') or '[]')
                item['model'] = next((str(a.get('model')) for a in reversed(attempts)
                                      if a.get('model')), '')
                item['planner_failures'] = sum(a.get('status') == 'rejected' for a in attempts)
                item['planner_elapsed_ms'] = sum(a.get('elapsed_ms') or 0 for a in attempts)
                item['token_count'] = None  # Provider usage was not captured for this run.
                browser = db.execute(
                    "SELECT json_extract(data,'$.code') AS code,"
                    "json_extract(data,'$.status') AS status FROM events "
                    "WHERE run_id=? AND kind='browser_recon' ORDER BY created DESC,rowid DESC LIMIT 1",
                    (item['id'],),
                ).fetchone()
                item['browser_status'] = (browser['code'] or browser['status']) if browser else None
                items.append(item)
        return {'items': items, 'total': total, 'offset': offset, 'limit': limit,
                'has_more': offset + len(items) < total}

    def _audit_deletion(self, db, run_id, row, events, reason):
        """삭제 감사 레코드를 남긴다(리뷰 P4: 증거 삭제/감사). deletions 테이블은 삭제·보존 정리의
        대상이 아니므로 run/증거가 사라져도 '무엇을·언제·왜 지웠는지'는 남는다. 응답 원문·URL 은
        저장하지 않고 목표 문구(사용자 입력)·상태·개수만 남긴다."""
        try:
            goal = (json.loads(row['data'])['spec'].get('goal') or '')[:500]
        except (ValueError, KeyError, TypeError):
            goal = ''
        db.execute('INSERT INTO deletions VALUES (?,?,?,?,?,?,?,?)',
                   (uid(), run_id, time.time(), reason, row['state'], events, goal, row['created']))

    def delete(self, run_id, reason='manual'):
        """run 과 그 증거(events)를 영구 삭제하고 삭제 감사를 남긴다. 삭제됐으면 True(없으면 False)."""
        with self.connect() as db:
            row = db.execute('SELECT created,state,data FROM runs WHERE id=?', (run_id,)).fetchone()
            if row is not None:
                n = db.execute('SELECT COUNT(*) AS c FROM events WHERE run_id=?', (run_id,)).fetchone()['c']
                self._audit_deletion(db, run_id, row, n, reason)
            db.execute('DELETE FROM events WHERE run_id=?', (run_id,))
            db.execute('DELETE FROM traffic_index WHERE run_id=?', (run_id,))
            db.execute('DELETE FROM finding_index WHERE run_id=?', (run_id,))
            db.execute('DELETE FROM asset_refs WHERE run_id=?', (run_id,))
            cur = db.execute('DELETE FROM runs WHERE id=?', (run_id,))
            db.execute('DELETE FROM assets WHERE NOT EXISTS '
                       '(SELECT 1 FROM asset_refs WHERE asset_refs.asset_id=assets.id)')
        return cur.rowcount > 0

    def deletions(self, limit=100):
        """최근 삭제 감사(최신순). 읽기 전용 운영 조회."""
        with self.connect() as db:
            rows = db.execute('SELECT * FROM deletions ORDER BY deleted DESC LIMIT ?', (limit,)).fetchall()
        return [dict(r) for r in rows]

    def save_template(self, name, category, spec, owner=''):
        """재사용 검증 템플릿 저장(리뷰 N1). spec 에는 자격증명을 담지 않는다(호출부에서 제거)."""
        tid = uid()
        created = time.time()
        encoded = json.dumps(_credential_free_template_spec(spec), ensure_ascii=False)
        with self.connect() as db:
            db.execute('INSERT INTO templates(id,created,name,category,spec,owner) VALUES (?,?,?,?,?,?)',
                       (tid, created, name, category, encoded, owner or ''))
            db.execute('INSERT INTO template_revisions VALUES (?,?,?,?,?,?,?)',
                       (tid, 1, created, name, category, encoded, owner or ''))
        return tid

    def _template_filter(self, search='', category='', owner=None):
        clauses = []
        params = []
        if owner is not None:
            clauses.append('owner = ?')
            params.append(owner)
        if search:
            clauses.append("(instr(lower(name), lower(?)) > 0 OR "
                           "instr(lower(COALESCE(json_extract(spec, '$.goal'), '')), lower(?)) > 0)")
            params.extend((search, search))
        if category:
            clauses.append('category = ?')
            params.append(category)
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        return where, params

    def templates(self, search='', category='', owner=None, limit=100, offset=0):
        where, params = self._template_filter(search, category, owner)
        with self.connect() as db:
            rows = db.execute('SELECT id,created,name,category,'
                              "COALESCE(json_extract(spec,'$.goal'),'') AS goal,"
                              "COALESCE(json_extract(spec,'$.policy_version'),1) AS policy_version,"
                              "json_type(spec,'$.approved_plan') AS plan_type,"
                              '(SELECT MAX(version) FROM template_revisions WHERE template_id=templates.id) AS version '
                              'FROM templates' + where +
                              ' ORDER BY created DESC,id DESC LIMIT ? OFFSET ?',
                              (*params, limit, offset)).fetchall()
        return [{'id': row['id'], 'created': row['created'], 'name': row['name'],
                 'category': row['category'], 'goal': row['goal'],
                 'version': row['version'] or 1, 'policy_version': row['policy_version'],
                 'pinned_plan': row['plan_type'] in ('object', 'array')}
                for row in rows]

    def templates_count(self, search='', category='', owner=None):
        where, params = self._template_filter(search, category, owner)
        with self.connect() as db:
            return db.execute('SELECT COUNT(*) FROM templates' + where, params).fetchone()[0]

    def template(self, tid, owner=None):
        with self.connect() as db:
            row = db.execute('SELECT * FROM templates WHERE id=?', (tid,)).fetchone()
        if row is None:
            raise KeyError(tid)
        if owner is not None and (not owner or row['owner'] != owner):
            raise PermissionError('다른 작업공간의 템플릿입니다.')
        return {'id': row['id'], 'name': row['name'], 'category': row['category'],
                'spec': json.loads(row['spec'])}

    def update_template(self, tid, name, category, spec, owner=None):
        encoded = json.dumps(_credential_free_template_spec(spec), ensure_ascii=False)
        with self.connect() as db:
            row = db.execute('SELECT owner FROM templates WHERE id=?', (tid,)).fetchone()
            if row is None:
                raise KeyError(tid)
            if owner is not None and (not owner or row['owner'] != owner):
                raise PermissionError('다른 작업공간의 템플릿입니다.')
            version = db.execute('SELECT COALESCE(MAX(version),0)+1 FROM template_revisions '
                                 'WHERE template_id=?', (tid,)).fetchone()[0]
            created = time.time()
            db.execute('UPDATE templates SET name=?,category=?,spec=? WHERE id=?',
                       (name, category, encoded, tid))
            db.execute('INSERT INTO template_revisions VALUES (?,?,?,?,?,?,?)',
                       (tid, version, created, name, category, encoded, row['owner']))
        return {'id': tid, 'version': version}

    def template_revisions(self, tid, owner=None):
        self.template(tid, owner=owner)
        with self.connect() as db:
            rows = db.execute('SELECT version,created,name,category FROM template_revisions '
                              'WHERE template_id=? ORDER BY version DESC', (tid,)).fetchall()
        return [dict(row) for row in rows]

    def restore_template_revision(self, tid, version, owner=None):
        self.template(tid, owner=owner)
        with self.connect() as db:
            row = db.execute('SELECT name,category,spec FROM template_revisions '
                             'WHERE template_id=? AND version=?', (tid, version)).fetchone()
        if row is None:
            raise KeyError((tid, version))
        return self.update_template(tid, row['name'], row['category'], json.loads(row['spec']), owner=owner)

    def delete_template(self, tid, owner=None):
        with self.connect() as db:
            row = db.execute('SELECT owner FROM templates WHERE id=?', (tid,)).fetchone()
            if row is None:
                return False
            if owner is not None and row['owner'] != owner:
                raise PermissionError('다른 작업공간의 템플릿입니다.')
            db.execute('DELETE FROM template_revisions WHERE template_id=?', (tid,))
            cur = db.execute('DELETE FROM templates WHERE id=?', (tid,))
        return cur.rowcount > 0

    def prune(self, max_age_days):
        """보존 기간(일) 초과 run(+증거) 정리. max_age_days<=0 이면 아무것도 안 함. 삭제 수 반환.
        로컬에 증거를 무한 보관하지 않게 하는 보존 정책(리뷰 F6)."""
        try:
            days = float(max_age_days or 0)
        except (TypeError, ValueError):
            return 0
        if days <= 0:
            return 0
        cutoff = time.time() - days * 86400
        with self.connect() as db:
            rows = db.execute('SELECT id,created,state,data FROM runs WHERE updated < ?', (cutoff,)).fetchall()
            for r in rows:
                n = db.execute('SELECT COUNT(*) AS c FROM events WHERE run_id=?', (r['id'],)).fetchone()['c']
                self._audit_deletion(db, r['id'], r, n, 'retention')
            ids = [r['id'] for r in rows]
            if ids:
                marks = ','.join('?' * len(ids))
                db.execute(f'DELETE FROM events WHERE run_id IN ({marks})', ids)
                db.execute(f'DELETE FROM traffic_index WHERE run_id IN ({marks})', ids)
                db.execute(f'DELETE FROM finding_index WHERE run_id IN ({marks})', ids)
                db.execute(f'DELETE FROM asset_refs WHERE run_id IN ({marks})', ids)
                db.execute(f'DELETE FROM runs WHERE id IN ({marks})', ids)
                db.execute('DELETE FROM assets WHERE NOT EXISTS '
                           '(SELECT 1 FROM asset_refs WHERE asset_refs.asset_id=assets.id)')
        return len(ids)

    def create_incident(self, incident, owner=''):
        """사내 이벤트(SIEM/SOAR) 수동 수집(리뷰 P2/N4). 본문(title/summary)은 로컬에만 보관한다."""
        iid = uid()
        with self.connect() as db:
            db.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?)',
                       (iid, time.time(), incident['source'], incident.get('asset_id', ''),
                        incident.get('traffic_id', ''), incident['category'], owner or '',
                        json.dumps(incident, ensure_ascii=False)))
        return iid

    def incident(self, iid):
        with self.connect() as db:
            row = db.execute('SELECT * FROM incidents WHERE id=?', (iid,)).fetchone()
        if row is None:
            raise KeyError(iid)
        return {'id': row['id'], 'created': row['created'], 'owner': row['owner'],
                **json.loads(row['data'])}

    def incidents(self, limit=100, offset=0, owner=None, before_created=None, before_id=None):
        """수집된 사건 목록(최신순). 원문 JSON 대신 목록 필드만 조회한다."""
        clauses, params = [], []
        if owner is not None:
            clauses.append("owner IN ('', ?)")
            params.append(owner)
        if before_created is not None and before_id is not None:
            clauses.append('(created<? OR (created=? AND id<?))')
            params.extend((before_created, before_created, before_id))
        where = 'WHERE ' + ' AND '.join(clauses) if clauses else ''
        params.extend((limit, offset))
        with self.connect() as db:
            rows = db.execute(
                'SELECT id,created,source,asset_id,traffic_id,category,owner,'
                "COALESCE(json_extract(data,'$.title'),'') AS title,"
                "COALESCE(json_extract(data,'$.external_id'),'') AS external_id,"
                "json_extract(data,'$.observed_at') AS observed_at "
                f'FROM incidents {where} ORDER BY created DESC,id DESC LIMIT ? OFFSET ?', params,
            ).fetchall()
        return [dict(row) for row in rows]

    def incidents_count(self, owner=None):
        with self.connect() as db:
            if owner is None:
                return db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
            return db.execute("SELECT COUNT(*) FROM incidents WHERE owner IN ('', ?)",
                              (owner,)).fetchone()[0]

    def incidents_for_asset(self, asset_id, owner=None):
        """All incidents with an explicitly supplied asset ID, scoped before retrieval."""
        if not asset_id:
            return []
        with self.connect() as db:
            if owner is None:
                rows = db.execute('SELECT id FROM incidents WHERE asset_id=? ORDER BY created DESC',
                                  (asset_id,)).fetchall()
            else:
                rows = db.execute("SELECT id FROM incidents WHERE asset_id=? AND owner IN ('', ?) "
                                  'ORDER BY created DESC', (asset_id, owner)).fetchall()
        return [row['id'] for row in rows]

    def delete_incident(self, iid):
        with self.connect() as db:
            row = db.execute('SELECT id,created,source,category,owner FROM incidents WHERE id=?',
                             (iid,)).fetchone()
            if row is None:
                return False
            db.execute('INSERT INTO incident_deletions VALUES (?,?,?,?,?,?,?)',
                       (uid(), iid, time.time(), row['created'], row['source'],
                        row['category'], row['owner']))
            cur = db.execute('DELETE FROM incidents WHERE id=?', (iid,))
        return cur.rowcount > 0

    def incident_deletions(self, limit=100, owner=None):
        """Deletion audit without incident title, request, response, or summary."""
        with self.connect() as db:
            if owner is None:
                rows = db.execute('SELECT * FROM incident_deletions ORDER BY deleted DESC LIMIT ?',
                                  (limit,)).fetchall()
            else:
                rows = db.execute("SELECT * FROM incident_deletions WHERE owner IN ('', ?) "
                                  'ORDER BY deleted DESC LIMIT ?', (owner, limit)).fetchall()
        return [dict(row) for row in rows]

    def runs_for_incident(self, iid):
        """이 사건을 재검증하려고 만든 run 들(읽기 전용 연결). 대상/AI 호출 없음."""
        with self.connect() as db:
            rows = db.execute("SELECT id,created,state,data FROM runs "
                              "WHERE json_extract(data, '$.incident.incident_id')=? "
                              'ORDER BY created DESC', (iid,)).fetchall()
        return [{'id': row['id'], 'created': row['created'], 'state': row['state'],
                 'data': json.loads(row['data'])} for row in rows]

    def event(self, run_id, kind, data, step_id='', event_id=None):
        event_id = event_id or uid()
        created = time.time()
        with self.connect() as db:
            inserted = db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',
                                  (event_id, run_id, created, kind, step_id,
                                   json.dumps(data, ensure_ascii=False))).rowcount
            if inserted and kind in TRAFFIC_KINDS:
                index_traffic_event(db, event_id, run_id, created, kind, data)
            if inserted and kind in FINDING_KINDS:
                reindex_findings(db, run_id)
        return event_id

    def events(self, run_id):
        with self.connect() as db:
            rows = db.execute('SELECT * FROM events WHERE run_id=? ORDER BY created,rowid', (run_id,)).fetchall()
        return [{**dict(r), 'data': json.loads(r['data'])} for r in rows]

    def finding_events(self, run_id):
        """Fields consumed by findings and conclusion; omit observation bodies."""
        with self.connect() as db:
            rows = db.execute(
                'SELECT id,kind,step_id,created,'
                "json_extract(data,'$.kind') AS action_kind,"
                "json_extract(data,'$.category') AS category,"
                "json_extract(data,'$.endpoint_id') AS endpoint_id,"
                "json_extract(data,'$.actor_id') AS actor_id,"
                "json_extract(data,'$.status') AS status,"
                "json_extract(data,'$.evidence_ids') AS evidence_ids,"
                "json_extract(data,'$.finding_id') AS finding_id,"
                "json_extract(data,'$.severity') AS severity,"
                "json_extract(data,'$.note') AS note "
                "FROM events WHERE run_id=? AND kind IN "
                "('action','observation','verification','finding_update') "
                'ORDER BY created,rowid', (run_id,),
            ).fetchall()
        events = []
        for row in rows:
            kind = row['kind']
            if kind == 'action':
                data = {'kind': row['action_kind'], 'category': row['category'],
                        'endpoint_id': row['endpoint_id'], 'actor_id': row['actor_id']}
            elif kind == 'verification':
                data = {'status': row['status'],
                        'evidence_ids': json.loads(row['evidence_ids']) if row['evidence_ids'] else []}
            elif kind == 'finding_update':
                data = {'finding_id': row['finding_id'], 'status': row['status'],
                        'severity': row['severity']}
                if row['note'] is not None:
                    data['note'] = row['note']
            else:
                data = {}
            events.append({'id': row['id'], 'kind': kind, 'step_id': row['step_id'],
                           'created': row['created'], 'data': data})
        return events

    def map_events(self, run_id):
        """Exclude large request/response evidence before Python JSON decoding."""
        with self.connect() as db:
            rows = db.execute(
                'SELECT id,created,kind,step_id,'
                "CASE WHEN kind IN ('observation','request_started') THEN "
                "json_remove(data,'$.request.headers','$.request.body',"
                "'$.response.body','$.response.headers','$.analysis.findings',"
                "'$.analysis.signals') ELSE data END AS data "
                'FROM events WHERE run_id=? ORDER BY created,rowid', (run_id,),
            ).fetchall()
        return [{**dict(row), 'data': json.loads(row['data'])} for row in rows]


_store = None


def get_store():
    global _store
    if _store is None:
        _store = Store()
    return _store


def record_oob(events):
    """Also called when the existing dashboard is the consumer of /oob/poll."""
    import hashlib
    for event in events:
        ctx = event.get('context') or {}
        if not ctx.get('run_id') or ctx.get('direct_domain'):
            continue
        try:
            store = get_store()
            store.get(ctx['run_id'])
            key = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
            store.event(ctx['run_id'], 'oob', event, ctx.get('step_id', ''), key)
        except KeyError:
            continue
