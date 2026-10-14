"""Read-only, cursor-based access to locally stored agent events."""

import json

from fastapi import APIRouter, HTTPException, Query, Request

from core.agent import get_manager, owner_scope_enabled
from routers.agent import _guard, _principal


router = APIRouter(prefix='/api/agent/history', tags=['agent-history'])


@router.get('/runs')
def search_runs(request: Request, search: str = Query('', max_length=200),
                state: str = Query('', max_length=32), archived: bool = False,
                offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
    """Search every stored run, including records older than the legacy 50-run list."""
    manager = get_manager()
    clauses = ["COALESCE(json_extract(data, '$.archived'), 0) = ?"]
    params = [int(archived)]
    if owner_scope_enabled():
        clauses.append("COALESCE(json_extract(data, '$.owner'), '') IN ('', ?)")
        params.append(_principal(request))
    if search:
        clauses.append("(instr(lower(id), lower(?)) > 0 OR "
                       "instr(lower(COALESCE(json_extract(data, '$.spec.goal'), '')), lower(?)) > 0)")
        params.extend((search, search))
    if state:
        clauses.append('state = ?')
        params.append(state)
    where = ' AND '.join(clauses)
    with manager.store.connect() as db:
        total = db.execute(f'SELECT COUNT(*) FROM runs WHERE {where}', params).fetchone()[0]
        rows = db.execute(
            f'SELECT id,created,updated,state,data FROM runs WHERE {where} '
            'ORDER BY created DESC,id DESC LIMIT ? OFFSET ?', (*params, limit, offset),
        ).fetchall()
    runs = []
    for row in rows:
        data = json.loads(row['data'])
        runs.append({'id': row['id'], 'created': row['created'], 'updated': row['updated'],
                     'state': row['state'], 'goal': (data.get('spec') or {}).get('goal', ''),
                     'owner': data.get('owner', ''), 'archived': bool(data.get('archived'))})
    return {'runs': runs, 'total': total, 'offset': offset, 'limit': limit,
            'has_more': offset + len(runs) < total}


@router.get('/runs/{run_id}/events')
def list_events(run_id: str, request: Request, after: int = Query(0, ge=0),
                limit: int = Query(50, ge=1, le=100)):
    """Return event metadata in insertion order; after is the last seen rowid."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        manager.store.get(run_id)
    except KeyError:
        raise HTTPException(404, '작업을 찾을 수 없습니다.')
    with manager.store.connect() as db:
        rows = db.execute(
            'SELECT rowid AS cursor,id,created,kind,step_id FROM events '
            'WHERE run_id=? AND rowid>? ORDER BY rowid LIMIT ?',
            (run_id, after, limit + 1),
        ).fetchall()
    has_more = len(rows) > limit
    page = rows[:limit]
    events = [dict(row) for row in page]
    return {'events': events, 'cursor': events[-1]['cursor'] if events else after,
            'has_more': has_more}


@router.get('/runs/{run_id}/events/{event_id}')
def get_event(run_id: str, event_id: str, request: Request):
    """Fetch one stored body only when the user opens it."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        manager.store.get(run_id)
    except KeyError:
        raise HTTPException(404, '작업을 찾을 수 없습니다.')
    with manager.store.connect() as db:
        row = db.execute('SELECT id,created,kind,step_id,data FROM events '
                         'WHERE run_id=? AND id=?', (run_id, event_id)).fetchone()
    if row is None:
        raise HTTPException(404, '이벤트를 찾을 수 없습니다.')
    return {**dict(row), 'data': json.loads(row['data'])}
