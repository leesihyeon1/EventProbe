"""Transactional admission and request reservations for the local agent runtime.

The execution engine remains single-process. SQLite owns the FIFO and counters;
credentials and actor sessions never enter these tables.
"""
import json
import time


class RunConflict(ValueError):
    pass


class RequestBudgetExceeded(ValueError):
    pass


class RuntimeStore:
    def init_runtime_schema(self):
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS runtime_queue (
                    position INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL UNIQUE,
                    enqueued REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS request_reservations (
                    run_id TEXT NOT NULL, reservation_key TEXT NOT NULL,
                    cost INTEGER NOT NULL CHECK(cost > 0), created REAL NOT NULL,
                    PRIMARY KEY(run_id,reservation_key));
                CREATE TABLE IF NOT EXISTS run_revisions (
                    run_id TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 0);
                INSERT OR IGNORE INTO run_revisions SELECT id,0 FROM runs;
                CREATE TRIGGER IF NOT EXISTS runtime_run_insert AFTER INSERT ON runs
                    BEGIN INSERT INTO run_revisions VALUES (NEW.id,0); END;
                CREATE TRIGGER IF NOT EXISTS runtime_run_update AFTER UPDATE ON runs
                    BEGIN UPDATE run_revisions SET revision=revision+1 WHERE run_id=NEW.id; END;
                CREATE TRIGGER IF NOT EXISTS runtime_run_delete AFTER DELETE ON runs
                    BEGIN
                        DELETE FROM run_revisions WHERE run_id=OLD.id;
                        DELETE FROM runtime_queue WHERE run_id=OLD.id;
                        DELETE FROM request_reservations WHERE run_id=OLD.id;
                    END;
                INSERT OR IGNORE INTO store_migrations VALUES ('runtime_admission_v1');
            ''')

    def enqueue(self, run_id):
        """Enqueue once, atomically with the run state. FIFO survives restart."""
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            changed = db.execute(
                "UPDATE runs SET state='queued',updated=? WHERE id=? "
                "AND state IN ('paused','interrupted') "
                "AND COALESCE(json_extract(data,'$.archived'),0)=0 "
                "AND json_extract(data,'$.restored_at') IS NULL "
                "AND json_extract(data,'$.spec.approved_plan_revoked_at') IS NULL",
                (time.time(), run_id),
            ).rowcount
            if not changed:
                if db.execute('SELECT 1 FROM runs WHERE id=?', (run_id,)).fetchone() is None:
                    raise KeyError(run_id)
                raise RunConflict('일시정지/중단된 작업만 실행 대기열에 넣을 수 있습니다.')
            db.execute('INSERT INTO runtime_queue(run_id,enqueued) VALUES (?,?)',
                       (run_id, time.time()))

    def admit_next(self, limit, ready_ids):
        """Claim only the FIFO head and only when this runtime has its session."""
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError('실행 정원은 1 이상의 정수여야 합니다.')
        ready = set(ready_ids)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            # Repair rows removed or paused by a previous interrupted operation.
            db.execute("DELETE FROM runtime_queue WHERE NOT EXISTS "
                       "(SELECT 1 FROM runs WHERE runs.id=runtime_queue.run_id AND state='queued')")
            if db.execute("SELECT COUNT(*) FROM runs WHERE state='running'").fetchone()[0] >= limit:
                return None
            head = db.execute('SELECT run_id FROM runtime_queue ORDER BY position LIMIT 1').fetchone()
            if head is None or head['run_id'] not in ready:
                return None
            run_id = head['run_id']
            db.execute("UPDATE runs SET state='running',updated=? WHERE id=? AND state='queued'",
                       (time.time(), run_id))
            db.execute('DELETE FROM runtime_queue WHERE run_id=?', (run_id,))
            return run_id

    def queued_runs(self):
        with self.connect() as db:
            return [row['run_id'] for row in db.execute(
                "SELECT q.run_id FROM runtime_queue q JOIN runs r ON r.id=q.run_id "
                "WHERE r.state='queued' ORDER BY q.position")]

    def cancel_queued(self, run_id):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            changed = db.execute("UPDATE runs SET state='paused',updated=? "
                                 "WHERE id=? AND state='queued'", (time.time(), run_id)).rowcount
            if changed:
                db.execute('DELETE FROM runtime_queue WHERE run_id=?', (run_id,))
            return bool(changed)

    def queue_position(self, run_id):
        with self.connect() as db:
            row = db.execute('SELECT position FROM runtime_queue WHERE run_id=?', (run_id,)).fetchone()
            if row is None:
                return None
            return db.execute('SELECT COUNT(*) FROM runtime_queue WHERE position<=?',
                              (row['position'],)).fetchone()[0]

    def reserve_requests(self, run_id, reservation_key, cost=1):
        """Count before transport; failures/unknown outcomes do not refund budget.

        Repeating a reservation key never increments twice. A changed cost with
        the same key is an error, not an implicit extra reservation.
        """
        if (isinstance(cost, bool) or not isinstance(cost, int) or cost < 1 or
                not isinstance(reservation_key, str) or not 1 <= len(reservation_key) <= 100):
            raise ValueError('유효한 요청 예약 키와 양의 정수 비용이 필요합니다.')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT state,data FROM runs WHERE id=?', (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            data = json.loads(row['data'])
            used = int(data.get('requests') or 0)
            existing = db.execute('SELECT cost FROM request_reservations '
                                  'WHERE run_id=? AND reservation_key=?',
                                  (run_id, reservation_key)).fetchone()
            if existing:
                if existing['cost'] != cost:
                    raise RunConflict('기존 요청 예약과 비용이 다릅니다.')
                return used
            if row['state'] != 'running':
                raise RunConflict('실행 중인 작업에서만 요청 예산을 예약할 수 있습니다.')
            maximum = int((data.get('spec') or {}).get('max_requests') or 0)
            if used + cost > maximum:
                raise RequestBudgetExceeded('HTTP 요청 한도에 도달했습니다.')
            db.execute('INSERT INTO request_reservations VALUES (?,?,?,?)',
                       (run_id, reservation_key, cost, time.time()))
            db.execute("UPDATE runs SET updated=?,data=json_set(data,'$.requests',?) WHERE id=?",
                       (time.time(), used + cost, run_id))
            return used + cost
