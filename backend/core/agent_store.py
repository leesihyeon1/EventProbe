"""Local durable run/evidence log. Credentials remain in the runtime session."""
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


def uid():
    return uuid.uuid4().hex


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
                    category TEXT NOT NULL, spec TEXT NOT NULL);
            ''')

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
        return run_id

    def get(self, run_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
        if row is None:
            raise KeyError(run_id)
        return {**dict(row), 'data': json.loads(row['data'])}

    def update(self, run_id, data, state=None):
        state = state or self.get(run_id)['state']
        with self.connect() as db:
            db.execute('UPDATE runs SET updated=?,state=?,data=? WHERE id=?',
                       (time.time(), state, json.dumps(data, ensure_ascii=False), run_id))

    def claim(self, run_id):
        with self.connect() as db:
            return db.execute("UPDATE runs SET state='running',updated=? WHERE id=? AND state IN ('paused','interrupted')",
                              (time.time(), run_id)).rowcount == 1

    def recover(self):
        with self.connect() as db:
            db.execute("UPDATE runs SET state='interrupted' WHERE state='running'")

    def list(self, include_archived=False):
        """최근 run 목록(최대 50). 기본은 보관되지 않은 것만, include_archived 면 보관된 것만(리뷰 N5)."""
        with self.connect() as db:
            rows = db.execute('SELECT id,created,updated,state,data FROM runs ORDER BY created DESC LIMIT 200').fetchall()
        out = []
        for r in rows:
            data = json.loads(r['data'])
            if bool(data.get('archived')) != bool(include_archived):
                continue
            out.append({'id': r['id'], 'state': r['state'], 'created': r['created'],
                        'goal': data['spec']['goal'], 'owner': data.get('owner', ''),
                        'archived': bool(data.get('archived'))})
            if len(out) >= 50:
                break
        return out

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
            cur = db.execute('DELETE FROM runs WHERE id=?', (run_id,))
        return cur.rowcount > 0

    def deletions(self, limit=100):
        """최근 삭제 감사(최신순). 읽기 전용 운영 조회."""
        with self.connect() as db:
            rows = db.execute('SELECT * FROM deletions ORDER BY deleted DESC LIMIT ?', (limit,)).fetchall()
        return [dict(r) for r in rows]

    def save_template(self, name, category, spec):
        """재사용 검증 템플릿 저장(리뷰 N1). spec 에는 자격증명을 담지 않는다(호출부에서 제거)."""
        tid = uid()
        with self.connect() as db:
            db.execute('INSERT INTO templates VALUES (?,?,?,?,?)',
                       (tid, time.time(), name, category, json.dumps(spec, ensure_ascii=False)))
        return tid

    def templates(self):
        with self.connect() as db:
            rows = db.execute('SELECT id,created,name,category,spec FROM templates ORDER BY created DESC LIMIT 100').fetchall()
        return [{'id': r['id'], 'created': r['created'], 'name': r['name'], 'category': r['category'],
                 'goal': json.loads(r['spec']).get('goal', '')} for r in rows]

    def template(self, tid):
        with self.connect() as db:
            row = db.execute('SELECT * FROM templates WHERE id=?', (tid,)).fetchone()
        if row is None:
            raise KeyError(tid)
        return {'id': row['id'], 'name': row['name'], 'category': row['category'], 'spec': json.loads(row['spec'])}

    def delete_template(self, tid):
        with self.connect() as db:
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
                db.execute(f'DELETE FROM runs WHERE id IN ({marks})', ids)
        return len(ids)

    def event(self, run_id, kind, data, step_id='', event_id=None):
        event_id = event_id or uid()
        with self.connect() as db:
            db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',
                       (event_id, run_id, time.time(), kind, step_id, json.dumps(data, ensure_ascii=False)))
        return event_id

    def events(self, run_id):
        with self.connect() as db:
            rows = db.execute('SELECT * FROM events WHERE run_id=? ORDER BY created,rowid', (run_id,)).fetchall()
        return [{**dict(r), 'data': json.loads(r['data'])} for r in rows]


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
