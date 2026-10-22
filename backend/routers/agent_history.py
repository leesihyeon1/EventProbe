"""Read-only, cursor-based access to locally stored agent events."""

import json

from fastapi import APIRouter, HTTPException, Query, Request

from core.agent import get_manager, owner_scope_enabled
from routers.agent import _guard, _principal


router = APIRouter(prefix='/api/agent/history', tags=['agent-history'])


@router.get('/assets')
def global_assets(request: Request, search: str = Query('', max_length=200),
                  asset_id: str = Query('', max_length=64),
                  since: float | None = Query(None, ge=0),
                  before: float | None = Query(None, ge=0),
                  archived: bool = False, offset: int = Query(0, ge=0),
                  limit: int = Query(50, ge=1, le=100)):
    """Read-only, owner-scoped asset index; response and query values never leave storage."""
    if since is not None and before is not None and before <= since:
        raise HTTPException(422, '종료 시각은 시작 시각보다 늦어야 합니다.')
    owner = _principal(request) if owner_scope_enabled() else None
    return get_manager().store.asset_page(search=search, asset_id=asset_id, archived=archived,
                                          since=since, before=before, owner=owner,
                                          offset=offset, limit=limit)


@router.get('/traffic')
def global_traffic(request: Request, search: str = Query('', max_length=200),
                   run_id: str = Query('', max_length=64), asset_id: str = Query('', max_length=64),
                   method: str = Query('', max_length=16), source: str = Query('', max_length=16),
                   status_code: int | None = Query(None, ge=100, le=599),
                   since: float | None = Query(None, ge=0),
                   before: float | None = Query(None, ge=0),
                   archived: bool = False, offset: int = Query(0, ge=0),
                   limit: int = Query(50, ge=1, le=100)):
    if source and source not in ('agent', 'browser', 'manual', 'bulk', 'raw', 'multi'):
        raise HTTPException(422, '지원하지 않는 출처입니다.')
    if since is not None and before is not None and before <= since:
        raise HTTPException(422, '종료 시각은 시작 시각보다 늦어야 합니다.')
    owner = _principal(request) if owner_scope_enabled() else None
    return get_manager().store.lookup_page(
        'traffic', search=search, run_id=run_id, asset_id=asset_id, method=method,
        source=source, status_code=status_code, since=since, before=before,
        archived=archived, owner=owner, offset=offset, limit=limit)


@router.get('/findings')
def global_findings(request: Request, search: str = Query('', max_length=200),
                    run_id: str = Query('', max_length=64), asset_id: str = Query('', max_length=64),
                    verdict: str = Query('', max_length=20), status: str = Query('', max_length=20),
                    archived: bool = False, offset: int = Query(0, ge=0),
                    limit: int = Query(50, ge=1, le=100)):
    if verdict and verdict not in ('confirmed', 'suspicious', 'inconclusive'):
        raise HTTPException(422, '지원하지 않는 판정입니다.')
    if status and status not in ('open', 'triaged', 'resolved', 'false_positive', 'ignored'):
        raise HTTPException(422, '지원하지 않는 상태입니다.')
    owner = _principal(request) if owner_scope_enabled() else None
    return get_manager().store.lookup_page(
        'finding', search=search, run_id=run_id, asset_id=asset_id,
        verdict=verdict, status=status, archived=archived, owner=owner,
        offset=offset, limit=limit)


@router.get('/findings/groups')
def finding_groups(request: Request, search: str = Query('', max_length=200),
                   asset_id: str = Query('', max_length=64),
                   verdict: str = Query('', max_length=20), status: str = Query('', max_length=20),
                   archived: bool = False, offset: int = Query(0, ge=0),
                   limit: int = Query(50, ge=1, le=100)):
    if verdict and verdict not in ('confirmed', 'suspicious', 'inconclusive'):
        raise HTTPException(422, '지원하지 않는 판정입니다.')
    if status and status not in ('open', 'triaged', 'resolved', 'false_positive', 'ignored'):
        raise HTTPException(422, '지원하지 않는 상태입니다.')
    owner = _principal(request) if owner_scope_enabled() else None
    return get_manager().store.finding_group_page(
        search=search, asset_id=asset_id, verdict=verdict, status=status, archived=archived,
        owner=owner, offset=offset, limit=limit)


@router.get('/findings/groups/members')
def finding_group_members(request: Request, asset_id: str = Query(..., min_length=64, max_length=64),
                          category: str = Query(..., max_length=100),
                          actor_id: str = Query('', max_length=100),
                          input_shape_id: str = Query(..., min_length=64, max_length=64),
                          verdict: str = Query('', max_length=20),
                          status: str = Query('', max_length=20), archived: bool = False,
                          offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100)):
    if verdict and verdict not in ('confirmed', 'suspicious', 'inconclusive'):
        raise HTTPException(422, '지원하지 않는 판정입니다.')
    if status and status not in ('open', 'triaged', 'resolved', 'false_positive', 'ignored'):
        raise HTTPException(422, '지원하지 않는 상태입니다.')
    owner = _principal(request) if owner_scope_enabled() else None
    return get_manager().store.finding_group_members(
        asset_id, category, actor_id, input_shape_id, verdict=verdict, status=status,
        archived=archived, owner=owner, offset=offset, limit=limit)


@router.get('/diagnostics')
def run_diagnostics(request: Request, offset: int = Query(0, ge=0),
                    limit: int = Query(20, ge=1, le=100)):
    owner = _principal(request) if owner_scope_enabled() else None
    return get_manager().store.diagnostic_page(owner=owner, offset=offset, limit=limit)


@router.get('/runs/{run_id}/status')
def run_status(run_id: str, request: Request):
    """A small poll payload; no event bodies, target URLs, or credentials."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        status = manager.store.run_status_fields(run_id)
    except KeyError:
        raise HTTPException(404, '작업을 찾을 수 없습니다.')
    with manager.store.connect() as db:
        counts = db.execute('SELECT COUNT(*) AS n, '
                            "MAX(CASE WHEN kind='oob_pending' THEN 1 ELSE 0 END) AS pending, "
                            "MAX(CASE WHEN kind='plan' THEN 1 ELSE 0 END) AS has_plan "
                            'FROM events WHERE run_id=?', (run_id,)).fetchone()
    return {'id': run_id, 'state': status['state'], 'updated': status['updated'],
            'event_count': counts['n'], 'has_pending_oob': bool(counts['pending']),
            'has_plan_event': bool(counts['has_plan']),
            'data': {'spec': {key: status[key] for key in
                              ('goal', 'mode', 'max_steps', 'max_requests', 'max_ai_calls',
                               'approved_plan_revoked_at')},
                     **{key: status[key] for key in
                        ('has_approved_plan', 'plan_checkpoint', 'name', 'category',
                         'steps', 'requests', 'ai_calls', 'elapsed', 'endpoints_count',
                         'reason', 'retest_of', 'archived')}}}


@router.get('/runs/{run_id}/findings')
def run_findings(run_id: str, request: Request):
    """Return the finding view without transferring raw event bodies to the client."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        view = manager.finding_view(run_id)
    except KeyError:
        raise HTTPException(404, '작업을 찾을 수 없습니다.')
    status = run_status(run_id, request)
    return {**status, **view, 'compact': True}


@router.get('/runs/{run_id}/findings/{finding_id}/retests')
def finding_retests(run_id: str, finding_id: str, request: Request):
    manager = get_manager()
    _guard(manager, run_id, request)
    owner = _principal(request) if owner_scope_enabled() else None
    try:
        return manager.store.retest_comparisons(run_id, finding_id, owner=owner)
    except KeyError:
        raise HTTPException(404, '발견을 찾을 수 없습니다.')


@router.get('/runs/{run_id}/map')
def run_map(run_id: str, request: Request):
    """Passive graph, sitemap, and coverage data without raw evidence bodies."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        view = manager.map_view(run_id)
    except KeyError:
        raise HTTPException(404, '작업을 찾을 수 없습니다.')
    status = run_status(run_id, request)
    status['data']['endpoints'] = view['data']['endpoints']
    status['data']['spec']['request'] = view['data']['spec_request']
    return {**status, 'events': view['events'], 'conclusion': view['conclusion'], 'recon': view['recon'],
            'compact': True, 'view': 'map'}


@router.get('/runs/{run_id}/conclusion')
def run_conclusion(run_id: str, request: Request):
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        conclusion = manager.conclusion_view(run_id)
    except KeyError:
        raise HTTPException(404, '작업을 찾을 수 없습니다.')
    return {**run_status(run_id, request), 'conclusion': conclusion,
            'compact': True, 'view': 'timeline'}


@router.get('/runs')
def search_runs(request: Request, search: str = Query('', max_length=200),
                state: str = Query('', max_length=32), category: str = Query('', max_length=40),
                archived: bool = False,
                offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
    """Search every stored run, including records older than the legacy 50-run list."""
    manager = get_manager()
    clauses = ["COALESCE(json_extract(data, '$.archived'), 0) = ?"]
    params = [int(archived)]
    if owner_scope_enabled():
        clauses.append("COALESCE(json_extract(data, '$.owner'), '') IN ('', ?)")
        params.append(_principal(request))
    scope_where = ' AND '.join(clauses)
    scope_params = list(params)
    if search:
        clauses.append("(instr(lower(id), lower(?)) > 0 OR "
                       "instr(lower(COALESCE(json_extract(data, '$.name'), '')), lower(?)) > 0 OR "
                       "instr(lower(COALESCE(json_extract(data, '$.spec.goal'), '')), lower(?)) > 0)")
        params.extend((search, search, search))
    if state:
        clauses.append('state = ?')
        params.append(state)
    if category:
        clauses.append("COALESCE(json_extract(data, '$.category'), '') = ?")
        params.append(category)
    where = ' AND '.join(clauses)
    with manager.store.connect() as db:
        counts = db.execute(f'SELECT state,COUNT(*) AS n FROM runs WHERE {scope_where} '
                            'GROUP BY state', scope_params).fetchall()
        total = db.execute(f'SELECT COUNT(*) FROM runs WHERE {where}', params).fetchone()[0]
        rows = db.execute(
            'SELECT id,created,updated,state,'
            "COALESCE(json_extract(data, '$.spec.goal'), '') AS goal,"
            "COALESCE(json_extract(data, '$.name'), '') AS name,"
            "COALESCE(json_extract(data, '$.category'), '') AS category,"
            "COALESCE(json_extract(data, '$.owner'), '') AS owner,"
            "COALESCE(json_extract(data, '$.archived'), 0) AS archived "
            f'FROM runs WHERE {where} '
            'ORDER BY created DESC,id DESC LIMIT ? OFFSET ?', (*params, limit, offset),
        ).fetchall()
    runs = [{**dict(row), 'archived': bool(row['archived'])} for row in rows]
    state_counts = {row['state']: row['n'] for row in counts}
    return {'runs': runs, 'total': total, 'scope_total': sum(state_counts.values()),
            'state_counts': state_counts, 'offset': offset, 'limit': limit,
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
