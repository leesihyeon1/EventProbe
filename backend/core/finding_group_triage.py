"""Canonical triage for a structural finding group, applied across every run.

A finding group is the cross-run aggregate keyed by (asset_id, category, actor_id,
input_shape_id) that `finding_group_page` already surfaces without merging per-run
verdicts. This module lets a user triage that whole group once — status, severity,
note — layered on top as a separate, workspace-scoped record. It never writes
`finding_update` events, never touches `finding_index` or `reindex_findings`, and
never rewrites a member finding, so per-run verdicts and the confirmed/suspicious/
inconclusive distribution stay immutable. The canonical status/severity is the human
disposition of the group; it does not collapse the three-state evidence verdicts.

Storage mirrors saved_evidence: a head row holds the current status/severity/note
with an integer revision (optimistic concurrency), and an append-only changes table
keeps the full audit history, both written in one BEGIN IMMEDIATE transaction.
"""
import hashlib
import json
import time
import uuid

from core.agent_findings import SEVERITIES, STATUSES, _SEVERITY_RANK, valid_patch
from core.agent_runtime_store import RunConflict

MAX_TRIAGE_CHANGES = 10000


def group_triage_id(owner, asset_id, category, actor_id, input_shape_id):
    """Stable per-workspace id for one structural group. Owner is part of the key so
    two workspaces triage the same group independently and never read each other's."""
    raw = '\x00'.join([owner or '', asset_id or '', category or '',
                       actor_id or '', input_shape_id or ''])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _compact(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False)


class FindingGroupTriageStore:
    """Mixin on Store: schema + read/write for group-level canonical triage."""

    def init_finding_group_schema(self):
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS finding_group_triage (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL,
                    asset_id TEXT NOT NULL, category TEXT NOT NULL,
                    actor_id TEXT NOT NULL, input_shape_id TEXT NOT NULL,
                    created REAL NOT NULL, updated REAL NOT NULL, revision INTEGER NOT NULL,
                    status TEXT NOT NULL, severity TEXT NOT NULL, note TEXT NOT NULL,
                    UNIQUE(owner, asset_id, category, actor_id, input_shape_id));
                CREATE INDEX IF NOT EXISTS finding_group_triage_key
                    ON finding_group_triage(asset_id, category, actor_id, input_shape_id, owner);
                CREATE TABLE IF NOT EXISTS finding_group_triage_changes (
                    id TEXT PRIMARY KEY, triage_id TEXT NOT NULL, created REAL NOT NULL,
                    actor TEXT NOT NULL, revision INTEGER NOT NULL, patch TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS finding_group_triage_changes_tid
                    ON finding_group_triage_changes(triage_id, revision);
            ''')

    @staticmethod
    def _group_visible(db, asset_id, category, actor_id, input_shape_id, owner):
        """True when the caller can see at least one member finding of this group.
        Owner '' (shared/legacy) rows stay visible; owner=None skips scoping."""
        if owner is None:
            return db.execute(
                'SELECT 1 FROM finding_index WHERE asset_id=? AND category=? AND actor_id=? '
                'AND input_shape_id=? LIMIT 1',
                (asset_id, category, actor_id, input_shape_id)).fetchone() is not None
        return db.execute(
            'SELECT 1 FROM finding_index x JOIN runs r ON r.id=x.run_id '
            'WHERE x.asset_id=? AND x.category=? AND x.actor_id=? AND x.input_shape_id=? '
            "AND COALESCE(json_extract(r.data,'$.owner'),'') IN ('',?) LIMIT 1",
            (asset_id, category, actor_id, input_shape_id, owner)).fetchone() is not None

    def _seed_severity(self, db, asset_id, category, actor_id, input_shape_id, owner):
        """Start a new group's canonical severity at its worst member severity, so the
        first disposition is not silently 'info' on a critical group. User can override."""
        if owner is None:
            rows = db.execute(
                'SELECT DISTINCT severity FROM finding_index WHERE asset_id=? AND category=? '
                'AND actor_id=? AND input_shape_id=?',
                (asset_id, category, actor_id, input_shape_id)).fetchall()
        else:
            rows = db.execute(
                'SELECT DISTINCT x.severity FROM finding_index x JOIN runs r ON r.id=x.run_id '
                'WHERE x.asset_id=? AND x.category=? AND x.actor_id=? AND x.input_shape_id=? '
                "AND COALESCE(json_extract(r.data,'$.owner'),'') IN ('',?)",
                (asset_id, category, actor_id, input_shape_id, owner)).fetchall()
        severities = [row[0] for row in rows if row[0] in SEVERITIES]
        return max(severities, key=lambda s: _SEVERITY_RANK[s]) if severities else 'info'

    def finding_group_triage(self, asset_id, category, actor_id, input_shape_id, *, owner=None):
        """Read one group's canonical triage and its full change history. Returns a
        value-free record; `exists` is False when the group was never triaged."""
        owner_val = '' if owner is None else owner
        triage_id = group_triage_id(owner_val, asset_id, category, actor_id, input_shape_id)
        with self.connect() as db:
            row = db.execute('SELECT * FROM finding_group_triage WHERE id=?', (triage_id,)).fetchone()
            if row is None:
                return {'exists': False, 'asset_id': asset_id, 'category': category,
                        'actor_id': actor_id, 'input_shape_id': input_shape_id,
                        'status': None, 'severity': None, 'note': '',
                        'revision': 0, 'created': None, 'updated': None, 'history': []}
            changes = db.execute(
                'SELECT created,actor,revision,patch FROM finding_group_triage_changes '
                'WHERE triage_id=? ORDER BY revision', (triage_id,)).fetchall()
        history = [{'created': c['created'], 'actor': c['actor'], 'revision': c['revision'],
                    'patch': json.loads(c['patch'])} for c in changes]
        return {'exists': True, 'asset_id': row['asset_id'], 'category': row['category'],
                'actor_id': row['actor_id'], 'input_shape_id': row['input_shape_id'],
                'status': row['status'], 'severity': row['severity'], 'note': row['note'],
                'revision': row['revision'], 'created': row['created'], 'updated': row['updated'],
                'history': history}

    def set_finding_group_triage(self, asset_id, category, actor_id, input_shape_id,
                                 patch, expected_revision, *, actor='', owner=None):
        """Create or update a group's canonical triage under optimistic concurrency.

        expected_revision must be 0 to create and match the current revision to update.
        Raises KeyError if the group is not visible to the caller, RunConflict on a
        revision mismatch, ValueError when the patch changes nothing or history is full.
        """
        cleaned = valid_patch(patch)
        if not cleaned:
            raise ValueError('변경할 상태·심각도·메모가 없습니다.')
        owner_val = '' if owner is None else owner
        triage_id = group_triage_id(owner_val, asset_id, category, actor_id, input_shape_id)
        now = time.time()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if not self._group_visible(db, asset_id, category, actor_id, input_shape_id, owner):
                raise KeyError('발견 그룹을 찾을 수 없습니다.')
            row = db.execute('SELECT * FROM finding_group_triage WHERE id=?', (triage_id,)).fetchone()
            if row is None:
                if expected_revision != 0:
                    raise RunConflict('발견 그룹 분류가 변경됐습니다. 다시 조회하세요.')
                base = {'status': 'open', 'note': '',
                        'severity': self._seed_severity(db, asset_id, category, actor_id,
                                                        input_shape_id, owner)}
                base.update(cleaned)
                db.execute('INSERT INTO finding_group_triage VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                           (triage_id, owner_val, asset_id, category, actor_id, input_shape_id,
                            now, now, 1, base['status'], base['severity'], base['note']))
                revision = 1
            else:
                if expected_revision != row['revision']:
                    raise RunConflict('발견 그룹 분류가 변경됐습니다. 다시 조회하세요.')
                if db.execute('SELECT COUNT(*) FROM finding_group_triage_changes WHERE triage_id=?',
                              (triage_id,)).fetchone()[0] >= MAX_TRIAGE_CHANGES:
                    raise ValueError('발견 그룹 분류의 변경 이력 한도를 초과했습니다.')
                revision = row['revision'] + 1
                db.execute('UPDATE finding_group_triage SET status=?,severity=?,note=?,revision=?,'
                           'updated=? WHERE id=?',
                           (cleaned.get('status', row['status']), cleaned.get('severity', row['severity']),
                            cleaned.get('note', row['note']), revision, now, triage_id))
            db.execute('INSERT INTO finding_group_triage_changes VALUES (?,?,?,?,?,?)',
                       (uuid.uuid4().hex, triage_id, now, actor, revision, _compact(cleaned)))
        return self.finding_group_triage(asset_id, category, actor_id, input_shape_id, owner=owner)
