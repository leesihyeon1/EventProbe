"""Explicit preservation, independent evidence reads and bounded local restore."""
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from core.agent import get_manager, owner_scope_enabled, active_policy_version
from core.agent_findings import build_report_html
from core.agent_evidence_export import build_finding_evidence_zip
from core.agent_models import RunSpec
from core.agent_view import map_request
from core import confirm
from core.saved_evidence_archive import export_saved_archive, import_saved_archive, MAX_ARCHIVE_BYTES
from core.saved_evidence_contracts import Severity, Status

router = APIRouter()


class PreserveRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int | None = Field(default=None, ge=1)


class SavedPatch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int = Field(ge=1)
    status: Status | None = None
    severity: Severity | None = None
    note: str | None = Field(default=None, max_length=2000)


class SavedRetest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    version: int | None = Field(default=None, ge=1, le=100)
    request_headers: dict[str, str] = Field(default_factory=dict)
    actor_headers: dict[str, dict[str, str]] = Field(default_factory=dict)
    request_body: str | None = Field(default=None, max_length=100000)
    allow_write_methods: bool = False


def principal(request):
    from routers.agent import _principal
    return _principal(request)


def owner_filter(request):
    return principal(request) if owner_scope_enabled() else None


def creator(request):
    actor = principal(request)
    if owner_scope_enabled() and not actor:
        raise HTTPException(403, '별도 보존과 가져오기를 사용하려면 작업공간 이름이 필요합니다.')
    return actor


def checked(call):
    try:
        return call()
    except PermissionError:
        raise HTTPException(403, '다른 작업공간의 보존 기록입니다.')
    except KeyError:
        raise HTTPException(404, '발견·실행 또는 요청한 증거 버전을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


def public_record(record):
    # Request/body values are opened via an evidence disclosure or explicit raw export.
    request = record['source']['request']
    return {**record, 'source': {**record['source'], 'request': map_request(request),
                                'body_reentry_required': bool(request.get('body'))}}


@router.post('/runs/{run_id}/findings/{finding_id}/preserve')
def preserve(run_id: str, finding_id: str, body: PreserveRequest, request: Request):
    from routers.agent import _guard
    manager = get_manager()
    _guard(manager, run_id, request)
    actor = creator(request)
    return checked(lambda: manager.store.preserve_finding(run_id, finding_id, actor,
                    body.expected_revision, source_owner_filter=owner_filter(request)))


@router.get('/runs/{run_id}/findings/{finding_id}/preserved')
def preserved_link(run_id: str, finding_id: str, request: Request):
    from routers.agent import _guard
    manager = get_manager()
    _guard(manager, run_id, request)
    actor = principal(request) or checked(lambda: manager.store.run_owner(run_id))
    with manager.store.connect() as db:
        row = db.execute('SELECT id,revision,current_version FROM saved_findings '
                         'WHERE owner=? AND source_run_id=? AND source_finding_id=?',
                         (actor, run_id, finding_id)).fetchone()
    return {'saved': dict(row) if row else None}


@router.get('/saved-findings')
def list_saved(request: Request, search: str = Query('', max_length=200),
               offset: int = Query(0, ge=0), limit: int = Query(25, ge=1, le=100)):
    return get_manager().store.saved_finding_page(owner_filter(request), search, offset, limit)


@router.get('/saved-findings/{saved_id}')
def get_saved(saved_id: str, request: Request, version: int | None = Query(None, ge=1, le=100)):
    return public_record(checked(lambda: get_manager().store.saved_finding(saved_id, version, owner_filter(request))))


@router.get('/saved-findings/{saved_id}/evidence/{snapshot_id}')
def get_saved_evidence(saved_id: str, snapshot_id: str, request: Request,
                       version: int | None = Query(None, ge=1, le=100)):
    return checked(lambda: get_manager().store.saved_event(saved_id, snapshot_id, version, owner_filter(request)))


@router.patch('/saved-findings/{saved_id}')
def patch_saved(saved_id: str, body: SavedPatch, request: Request):
    patch = body.model_dump(exclude={'expected_revision'}, exclude_none=True)
    return public_record(checked(lambda: get_manager().store.patch_saved_finding(
        saved_id, patch, body.expected_revision, principal(request), owner_filter(request))))


@router.delete('/saved-findings/{saved_id}')
def delete_saved(saved_id: str, request: Request, expected_revision: int = Query(ge=1)):
    checked(lambda: get_manager().store.delete_saved_finding(
        saved_id, expected_revision, principal(request), owner_filter(request)))
    return {'deleted': True, 'source_run_deleted': False}


@router.get('/saved-findings/{saved_id}/report', response_class=HTMLResponse)
def saved_report(saved_id: str, request: Request, version: int | None = Query(None, ge=1, le=100)):
    view = checked(lambda: get_manager().store.saved_execution_view(saved_id, version, owner_filter(request)))
    return HTMLResponse(build_report_html(view), headers={'Cache-Control': 'no-store'})


@router.get('/saved-findings/{saved_id}/evidence.zip')
def saved_evidence_zip(saved_id: str, request: Request, raw: bool = False,
                       version: int | None = Query(None, ge=1, le=100)):
    def build():
        view = get_manager().store.saved_execution_view(saved_id, version, owner_filter(request))
        return build_finding_evidence_zip(view, saved_id, include_raw=raw)
    return Response(checked(build), media_type='application/zip', headers={
        'Content-Disposition': 'attachment; filename="saved-finding-evidence.zip"',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@router.get('/saved-findings/{saved_id}/archive.zip')
def saved_archive(saved_id: str, request: Request):
    payload = checked(lambda: export_saved_archive(get_manager().store, saved_id, owner_filter(request)))
    return Response(payload, media_type='application/zip', headers={
        'Content-Disposition': 'attachment; filename="saved-finding-archive.zip"',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@router.post('/saved-findings/import')
async def saved_import(request: Request):
    actor = creator(request)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_ARCHIVE_BYTES:
            raise HTTPException(413, '보존 패키지는 25 MiB 이하여야 합니다.')
        chunks.append(chunk)
    return checked(lambda: import_saved_archive(get_manager().store, b''.join(chunks), actor))


@router.post('/saved-findings/{saved_id}/retest')
async def retest_saved(saved_id: str, body: SavedRetest, request: Request):
    manager = get_manager()
    scope = owner_filter(request)
    record = checked(lambda: manager.store.saved_finding(saved_id, body.version, scope))
    view = checked(lambda: manager.store.saved_execution_view(saved_id, record['version'], scope))
    finding, endpoint = view['findings'][0], record['source']['request']
    action = next((e['data'] for e in view['events'] if e['kind'] == 'action'), {})
    category = finding['category']
    if category not in ('sqli', 'auth', 'xss', 'ssti', 'lfi', 'ssrf', 'cmdi', 'redirect', 'nosql') or not confirm.probe_plan(category, ''):
        raise HTTPException(409, '이 발견 유형의 독립 재검증은 아직 지원하지 않습니다.')
    method = endpoint['method']
    if method not in ('GET', 'HEAD') and not body.allow_write_methods:
        raise HTTPException(409, '쓰기 메서드 재검증은 명시적인 허용이 필요합니다.')
    if endpoint.get('body') and body.request_body is None:
        raise HTTPException(409, '원본 요청 본문을 자동 재사용하지 않습니다. 재검증 본문을 다시 입력하세요.')
    actor_id = finding.get('actor_id') or 'current'
    plan = {'entry': 'retest', 'steps': [{'action_id': 'retest', 'action': {
        'kind': 'confirm', 'hypothesis': '별도 보존 발견 재검증', 'category': category,
        'location': action.get('location', 'param'), 'param': action.get('param', ''),
        'actor_id': actor_id, 'endpoint_id': 'seed'}, 'branches': [], 'default_next': ''}]}
    def start():
        spec = RunSpec.model_validate({'goal': f'발견 재검증: {category}',
            'request': {**endpoint, 'headers': body.request_headers, 'body': body.request_body or ''},
            'actors': [{'id': actor_id, 'headers': body.actor_headers.get(actor_id, {})}],
            'target_scope': 'request_only', 'max_steps': 2,
            'max_requests': min(150, 3 + 2 * len(confirm.probe_plan(category, ''))),
            'max_ai_calls': 0, 'max_seconds': 120, 'allow_write_methods': body.allow_write_methods,
            'approved_plan': plan, 'policy_version': active_policy_version()})
        rid = manager.create(spec, owner=principal(request), retest_of={
            'run_id': record['source_run_id'], 'finding_id': record['source_finding_id'],
            'category': category, 'saved_finding_id': saved_id, 'saved_version': record['version']},
            saved_retest={'id': saved_id, 'version': record['version'], 'owner_filter': scope})
        return manager.snapshot(rid)
    return checked(start)


@router.get('/saved-findings/{saved_id}/retests')
def saved_retests(saved_id: str, request: Request, offset: int = Query(0, ge=0),
                   limit: int = Query(25, ge=1, le=100)):
    return checked(lambda: get_manager().store.saved_retest_page(saved_id, owner_filter(request), offset, limit))
