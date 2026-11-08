"""Durable profile revisions, task routing cursor, health and payload-free usage ledger."""
import json
import time
import uuid

from core.agent_runtime_store import RunConflict
from core.model_profiles import ModelProfile, legacy_profile


class ModelCallBudgetExceeded(ValueError):
    pass


class ModelStore:
    def init_model_schema(self):
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS model_profiles (
                    id TEXT PRIMARY KEY, revision INTEGER NOT NULL,
                    data TEXT NOT NULL, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS run_model_chains (
                    run_id TEXT PRIMARY KEY, revision INTEGER NOT NULL,
                    profile_ids TEXT NOT NULL, active_position INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS model_profile_health (
                    profile_id TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
                    cooldown_until REAL NOT NULL DEFAULT 0, error_code TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS model_calls (
                    id TEXT PRIMARY KEY, run_id TEXT, profile_id TEXT NOT NULL,
                    profile_revision INTEGER NOT NULL, model TEXT NOT NULL,
                    started REAL NOT NULL, finished REAL, status TEXT NOT NULL,
                    http_status INTEGER, error_code TEXT NOT NULL DEFAULT '',
                    latency_ms REAL, actual_tokens INTEGER);
                CREATE INDEX IF NOT EXISTS model_calls_run ON model_calls(run_id,started,id);
                CREATE TRIGGER IF NOT EXISTS model_run_delete AFTER DELETE ON runs
                    BEGIN
                        DELETE FROM run_model_chains WHERE run_id=OLD.id;
                        DELETE FROM model_calls WHERE run_id=OLD.id;
                    END;
                INSERT OR IGNORE INTO store_migrations VALUES ('model_routing_v1');
            ''')

    def model_profile(self, profile_id):
        if profile_id == 'default':
            return legacy_profile()
        with self.connect() as db:
            row = db.execute('SELECT * FROM model_profiles WHERE id=?', (profile_id,)).fetchone()
        if row is None:
            raise KeyError(profile_id)
        return {'id': row['id'], 'revision': row['revision'], **json.loads(row['data'])}

    def model_profile_list(self):
        with self.connect() as db:
            ids = [r['id'] for r in db.execute('SELECT id FROM model_profiles ORDER BY updated,id')]
        return [self.model_profile(k) for k in ['default', *ids]]

    def save_model_profile(self, metadata, profile_id=None, expected_revision=None):
        clean = ModelProfile.model_validate(metadata).model_dump()
        if profile_id == 'default':
            raise ValueError('기존 환경 설정은 환경변수로 관리합니다.')
        profile_id = profile_id or uuid.uuid4().hex
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT revision FROM model_profiles WHERE id=?', (profile_id,)).fetchone()
            if row is None:
                if expected_revision is not None:
                    raise KeyError(profile_id)
                revision = 1
            else:
                if expected_revision != row['revision']:
                    raise RunConflict('모델 프로파일이 변경됐습니다. 다시 조회하세요.')
                revision = row['revision'] + 1
            db.execute('INSERT INTO model_profiles VALUES (?,?,?,?) '
                       'ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,'
                       'data=excluded.data,updated=excluded.updated',
                       (profile_id, revision, json.dumps(clean, ensure_ascii=False), time.time()))
        return self.model_profile(profile_id)

    def delete_model_profile(self, profile_id, expected_revision):
        if profile_id == 'default':
            raise ValueError('기존 환경 설정은 삭제할 수 없습니다.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT revision FROM model_profiles WHERE id=?', (profile_id,)).fetchone()
            if row is None:
                raise KeyError(profile_id)
            if row['revision'] != expected_revision:
                raise RunConflict('프로파일 버전이 변경됐습니다.')
            if db.execute('SELECT 1 FROM run_model_chains,json_each(profile_ids) '
                          'WHERE json_each.value=? LIMIT 1', (profile_id,)).fetchone():
                raise RunConflict('작업에서 참조하는 프로파일은 삭제할 수 없습니다. 비활성화하세요.')
            if db.execute("SELECT 1 FROM model_calls WHERE profile_id=? AND status='started' LIMIT 1",
                          (profile_id,)).fetchone():
                raise RunConflict('모델 호출이 진행 중입니다. 완료 후 삭제하세요.')
            db.execute('DELETE FROM model_profiles WHERE id=?', (profile_id,))
            db.execute('DELETE FROM model_profile_health WHERE profile_id=?', (profile_id,))

    def run_model_chain(self, run_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM run_model_chains WHERE run_id=?', (run_id,)).fetchone()
        if row is None:
            with self.connect() as db:
                legacy = db.execute("SELECT json_extract(data,'$.spec.model_profile_ids') AS ids FROM runs WHERE id=?",
                                    (run_id,)).fetchone()
            if legacy is None:
                raise KeyError(run_id)
            return {'revision': 0, 'profile_ids': json.loads(legacy['ids'] or '[]'),
                    'active_position': 0}
        return {'revision': row['revision'], 'profile_ids': json.loads(row['profile_ids']),
                'active_position': row['active_position']}

    def set_run_model_chain(self, run_id, profile_ids, expected_revision):
        # The router revalidates profiles and egress zones at every logical call.
        from core.model_routing import validate_chain
        validate_chain(self, profile_ids)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            run = db.execute('SELECT data FROM runs WHERE id=?', (run_id,)).fetchone()
            if run is None:
                raise KeyError(run_id)
            # Serialize profile deletion against attaching a new chain.
            from core import ai_egress
            zones = set()
            for profile_id in profile_ids or ['default']:
                if profile_id == 'default':
                    metadata = legacy_profile()
                else:
                    record = db.execute('SELECT data FROM model_profiles WHERE id=?', (profile_id,)).fetchone()
                    if record is None:
                        raise KeyError(profile_id)
                    metadata = json.loads(record['data'])
                if not metadata['enabled']:
                    raise ValueError('비활성 모델 프로파일은 실행 순서에 넣을 수 없습니다.')
                zones.add(ai_egress.is_internal_destination(metadata['base_url']))
            if len(zones) > 1:
                raise ValueError('내부 모델과 외부 모델을 같은 장애 전환 순서에 혼합할 수 없습니다.')
            row = db.execute('SELECT revision FROM run_model_chains WHERE run_id=?', (run_id,)).fetchone()
            revision = row['revision'] if row else 0
            if expected_revision != revision:
                raise RunConflict('작업의 모델 순서가 변경됐습니다. 다시 조회하세요.')
            db.execute('INSERT INTO run_model_chains VALUES (?,?,?,0) '
                       'ON CONFLICT(run_id) DO UPDATE SET revision=excluded.revision,'
                       'profile_ids=excluded.profile_ids,active_position=0',
                       (run_id, revision + 1, json.dumps(profile_ids)))
            db.execute("UPDATE runs SET data=json_set(data,'$.spec.model_profile_ids',json(?)),updated=? WHERE id=?",
                       (json.dumps(profile_ids), time.time(), run_id))
        return self.run_model_chain(run_id)

    def advance_model_cursor(self, run_id, chain_revision, position):
        with self.connect() as db:
            return bool(db.execute('UPDATE run_model_chains SET active_position=? '
                                   'WHERE run_id=? AND revision=?',
                                   (position, run_id, chain_revision)).rowcount)

    def model_health(self, profile_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM model_profile_health WHERE profile_id=?', (profile_id,)).fetchone()
        return dict(row) if row else {'profile_id': profile_id, 'failures': 0,
                                      'cooldown_until': 0, 'error_code': ''}

    def record_model_health(self, profile, error_code):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT failures FROM model_profile_health WHERE profile_id=?',
                             (profile['id'],)).fetchone()
            failures = ((row['failures'] if row else 0) + 1) if error_code else 0
            cooldown = (time.time() + profile['cooldown_seconds'] if error_code and
                        (error_code in ('quota', 'auth') or failures >= profile['failure_threshold']) else 0)
            db.execute('INSERT INTO model_profile_health VALUES (?,?,?,?) '
                       'ON CONFLICT(profile_id) DO UPDATE SET failures=excluded.failures,'
                       'cooldown_until=excluded.cooldown_until,error_code=excluded.error_code',
                       (profile['id'], failures, cooldown, error_code))

    def begin_model_call(self, run_id, profile, prepaid=False):
        call_id = uuid.uuid4().hex
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if run_id is not None:
                run = db.execute('SELECT state,data FROM runs WHERE id=?', (run_id,)).fetchone()
                if run is None:
                    raise KeyError(run_id)
                if run['state'] != 'running':
                    raise RunConflict('실행 중인 작업에서만 모델을 호출할 수 있습니다.')
                data = json.loads(run['data'])
                used = int(data.get('ai_calls') or 0)
                maximum = int((data.get('spec') or {}).get('max_ai_calls') or 0)
                if (prepaid and (used < 1 or used > maximum)) or (not prepaid and used >= maximum):
                    raise ModelCallBudgetExceeded('AI 호출 한도에 도달했습니다.')
                if not prepaid:
                    db.execute("UPDATE runs SET data=json_set(data,'$.ai_calls',?),updated=? WHERE id=?",
                               (used + 1, time.time(), run_id))
            db.execute('INSERT INTO model_calls(id,run_id,profile_id,profile_revision,model,started,status) '
                       "VALUES (?,?,?,?,?,?,'started')", (call_id, run_id, profile['id'],
                       profile['revision'], profile['model'], time.time()))
        return call_id

    def finish_model_call(self, call_id, status, http_status, error_code, latency_ms, tokens):
        with self.connect() as db:
            db.execute('UPDATE model_calls SET finished=?,status=?,http_status=?,error_code=?,'
                       'latency_ms=?,actual_tokens=? WHERE id=?',
                       (time.time(), status, http_status, error_code, latency_ms, tokens, call_id))

    def model_call_page(self, run_id, offset=0, limit=50):
        with self.connect() as db:
            total = db.execute('SELECT COUNT(*) FROM model_calls WHERE run_id=?', (run_id,)).fetchone()[0]
            rows = db.execute('SELECT * FROM model_calls WHERE run_id=? '
                              'ORDER BY started DESC,id DESC LIMIT ? OFFSET ?', (run_id, limit, offset)).fetchall()
        return {'items': [dict(x) for x in rows], 'total': total, 'offset': offset,
                'limit': limit, 'has_more': offset + len(rows) < total}
