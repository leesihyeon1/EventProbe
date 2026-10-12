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

    def list(self):
        with self.connect() as db:
            rows = db.execute('SELECT id,created,updated,state,data FROM runs ORDER BY created DESC LIMIT 50').fetchall()
        return [{'id': r['id'], 'state': r['state'], 'created': r['created'],
                 'goal': json.loads(r['data'])['spec']['goal']} for r in rows]

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
