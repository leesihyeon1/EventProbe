import os
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from core.agent import active_policy_version, get_manager, generate_plan, owner_scope_enabled, owns, template_spec, pinned_plan
from core.agent_findings import build_report_html
from core.agent_evidence_export import build_finding_evidence_zip
from core.agent_archive import MAX_ARCHIVE_BYTES
from core.agent_models import RunSpec, IncidentEvent
from core.plan import plan_fingerprint

router = APIRouter(prefix='/api/agent', tags=['context-agent'])


class ResumeRequest(BaseModel):
    request_headers: dict[str, str] | None = None
    actor_headers: dict[str, dict[str, str]] | None = None
    acknowledge_writes: bool = False     # 처리 여부 불명확한 쓰기 재전송 위험 확인(리뷰 P3)


class PlanSkipRequest(BaseModel):
    reason: str


class PlanReviewInput(BaseModel):
    spec: RunSpec
    plan: dict


class FindingPatch(BaseModel):
    status: str | None = None
    severity: str | None = None
    note: str | None = None


class TemplateSave(BaseModel):
    name: str
    category: str = ''
    spec: RunSpec


class TemplateBatchCategory(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=50)
    category: str = Field(max_length=40)


class BatchRuns(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=50)
    action: Literal['archive', 'unarchive', 'stop']


class RunMetadata(BaseModel):
    name: str = Field(default='', max_length=100)
    category: str = Field(default='', max_length=40)


class IncidentAccess(BaseModel):
    owner_actor: str = 'owner'
    intruder_actor: str = 'intruder'
    identity_pointer: str = ''
    identity_value: str = ''
    description: str = ''


class IncidentVerify(BaseModel):
    request_headers: dict[str, str] | None = None
    actor_headers: dict[str, dict[str, str]] | None = None
    access: IncidentAccess | None = None     # 접근제어(access) 사건의 소유자/비소유자 재검증 입력


def _principal(request: Request) -> str:
    """작업 소유권 principal(리뷰 P4). 접근 토큰(EVENTPROBE_TOKEN)이 보안 경계이고, 이 값은
    토큰을 공유하는 사용자들 사이의 작업공간 구분용 자가 선언 식별자다(인증 경계 아님)."""
    return (request.headers.get('x-eventprobe-user') or request.cookies.get('ep_user') or '').strip()[:64]


def _template_owner(request: Request):
    if not owner_scope_enabled():
        return None
    principal = _principal(request)
    if not principal:
        raise HTTPException(403, '템플릿을 사용하려면 작업공간 이름이 필요합니다.')
    return principal


def _guard(manager, run_id, request):
    """소유권 범위가 켜졌을 때 접근 권한을 확인한다. KeyError→404, PermissionError→403."""
    try:
        manager.check_access(run_id, _principal(request))
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except PermissionError as exc:
        raise HTTPException(403, str(exc))


@router.on_event('startup')
async def recover_runs():
    store = get_manager().store
    store.recover()
    # 보존 정책(리뷰 F6): AGENT_RETENTION_DAYS 가 설정돼 있으면 기간 초과 run/증거를 정리.
    # 기본 0(무제한 보관) — 기존 동작 유지. 자동 삭제는 명시적으로 켠다.
    store.prune(os.getenv('AGENT_RETENTION_DAYS', '0'))


@router.on_event('shutdown')
async def stop_runs():
    await get_manager().shutdown()


@router.get('/runs')
def list_runs(request: Request, archived: int = 0):
    owner = _principal(request) if owner_scope_enabled() else None
    runs = get_manager().store.list(include_archived=bool(archived), owner=owner)
    return {'runs': runs}


@router.post('/runs/batch')
async def batch_runs(body: BatchRuns, request: Request):
    """Apply one non-executing command per run and report every individual result."""
    manager = get_manager()
    results = []
    for run_id in dict.fromkeys(body.ids):
        try:
            _guard(manager, run_id, request)
            if body.action == 'stop':
                task = manager.tasks.get(run_id)
                if manager.store.get(run_id)['state'] != 'running' or task is None or task.done():
                    raise ValueError('실행 중인 작업에서만 중단할 수 있습니다.')
                await manager.stop(run_id)
            else:
                manager.set_archived(run_id, body.action == 'archive')
            results.append({'id': run_id, 'ok': True})
        except HTTPException as exc:
            results.append({'id': run_id, 'ok': False, 'status': exc.status_code,
                            'error': str(exc.detail)})
        except KeyError:
            results.append({'id': run_id, 'ok': False, 'status': 404,
                            'error': '실행 기록을 찾을 수 없습니다.'})
        except ValueError as exc:
            results.append({'id': run_id, 'ok': False, 'status': 409, 'error': str(exc)})
    return {'results': results, 'succeeded': sum(item['ok'] for item in results),
            'failed': sum(not item['ok'] for item in results)}


@router.get('/deletions')
def list_deletions(limit: int = 100):
    """증거 삭제 감사(수동/보존). 삭제된 run 자체는 사라져도 기록은 남는다(리뷰 P4)."""
    return {'deletions': get_manager().store.deletions(limit)}


@router.get('/templates')
def list_templates(request: Request, search: str = Query('', max_length=200),
                   category: str = Query('', max_length=40),
                   offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=100)):
    """재사용 검증 템플릿 목록(리뷰 N1). 자격증명은 저장하지 않는다."""
    owner = _template_owner(request)
    store = get_manager().store
    filters = {'search': search.strip(), 'category': category.strip(), 'owner': owner}
    templates = store.templates(**filters, offset=offset, limit=limit)
    total = store.templates_count(**filters)
    return {'templates': templates, 'policy_version': active_policy_version(),
            'total': total, 'offset': offset, 'limit': limit,
            'has_more': offset + len(templates) < total}


@router.post('/templates', status_code=201)
def save_template(body: TemplateSave, request: Request):
    """현재 검증 설정을 템플릿으로 저장한다. 비밀값(헤더)은 제거해 저장한다(리뷰 N1)."""
    tid = get_manager().store.save_template(
        (body.name or '').strip()[:100] or '무제 템플릿', (body.category or '').strip()[:40],
        template_spec(body.spec), owner=_template_owner(request) or '')
    return {'id': tid}


@router.post('/templates/batch/category')
def batch_template_category(body: TemplateBatchCategory, request: Request):
    """Revise selected templates without starting work; report each authorization result."""
    owner = _template_owner(request)
    store = get_manager().store
    category = body.category.strip()
    results = []
    for tid in dict.fromkeys(body.ids):
        try:
            template = store.template(tid, owner=owner)
            revision = store.update_template(tid, template['name'], category,
                                             template['spec'], owner=owner)
            results.append({'id': tid, 'ok': True, 'version': revision['version']})
        except KeyError:
            results.append({'id': tid, 'ok': False, 'status': 404,
                            'error': '템플릿을 찾을 수 없습니다.'})
        except PermissionError as exc:
            results.append({'id': tid, 'ok': False, 'status': 403, 'error': str(exc)})
        except ValueError:
            results.append({'id': tid, 'ok': False, 'status': 409,
                            'error': '템플릿 명세를 읽거나 개정할 수 없습니다.'})
    return {'results': results, 'succeeded': sum(item['ok'] for item in results),
            'failed': sum(not item['ok'] for item in results)}


@router.delete('/templates/{template_id}')
def delete_template(template_id: str, request: Request):
    try:
        if not get_manager().store.delete_template(template_id,
                owner=_template_owner(request)):
            raise HTTPException(404, '템플릿을 찾을 수 없습니다.')
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    return {'deleted': True, 'id': template_id}


@router.patch('/templates/{template_id}')
def revise_template(template_id: str, body: TemplateSave, request: Request):
    try:
        return get_manager().store.update_template(
            template_id, (body.name or '').strip()[:100] or '무제 템플릿',
            (body.category or '').strip()[:40], template_spec(body.spec),
            owner=_template_owner(request))
    except KeyError:
        raise HTTPException(404, '템플릿을 찾을 수 없습니다.')
    except PermissionError as exc:
        raise HTTPException(403, str(exc))


@router.get('/templates/{template_id}/revisions')
def list_template_revisions(template_id: str, request: Request):
    try:
        return {'revisions': get_manager().store.template_revisions(
            template_id, owner=_template_owner(request))}
    except KeyError:
        raise HTTPException(404, '템플릿을 찾을 수 없습니다.')
    except PermissionError as exc:
        raise HTTPException(403, str(exc))


@router.post('/templates/{template_id}/revisions/{version}/restore')
def restore_template_revision(template_id: str, version: int, request: Request):
    try:
        return get_manager().store.restore_template_revision(
            template_id, version, owner=_template_owner(request))
    except KeyError:
        raise HTTPException(404, '템플릿 버전을 찾을 수 없습니다.')
    except PermissionError as exc:
        raise HTTPException(403, str(exc))


@router.post('/templates/{template_id}/run', status_code=201)
async def run_template(template_id: str, req: ResumeRequest, request: Request):
    """템플릿을 새 실행으로 복제한다(리뷰 N1). 자격증명은 실행 시 재주입한다."""
    manager = get_manager()
    owner = _template_owner(request)
    if sum(not task.done() for task in manager.tasks.values()) >= 2:
        raise HTTPException(409, '동시에 최대 두 개 실행할 수 있습니다.')
    try:
        return manager.run_template(template_id, req.request_headers, req.actor_headers, owner=owner or _principal(request))
    except KeyError:
        raise HTTPException(404, '템플릿을 찾을 수 없습니다.')
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


def _incident_guard(manager, incident_id, request):
    """사건 소유권 확인(리뷰 P4). KeyError→404, 비소유자→403. 사건 레코드를 돌려준다."""
    try:
        inc = manager.store.incident(incident_id)
    except KeyError:
        raise HTTPException(404, '사건을 찾을 수 없습니다.')
    if owner_scope_enabled() and not owns({'owner': inc.get('owner', '')}, _principal(request)):
        raise HTTPException(403, '다른 사용자가 소유한 사건입니다.')
    return inc


@router.get('/incidents')
def list_incidents(request: Request, offset: int = Query(0, ge=0),
                   limit: int = Query(100, ge=1, le=100),
                   before_created: float | None = Query(None, ge=0),
                   before_id: str | None = Query(None, min_length=1, max_length=100)):
    """수집된 사내 이벤트 목록(리뷰 P2/N4). 요약 본문은 싣지 않는다."""
    owner = _principal(request) if owner_scope_enabled() else None
    store = get_manager().store
    if (before_created is None) != (before_id is None) or (before_id is not None and offset):
        raise HTTPException(422, '커서 시각과 ID를 함께 보내고 offset은 0으로 두세요.')
    rows = store.incidents(limit=limit + 1, offset=offset, owner=owner,
                           before_created=before_created, before_id=before_id)
    incidents = rows[:limit]
    total = store.incidents_count(owner=owner)
    return {'incidents': incidents, 'total': total, 'offset': offset, 'limit': limit,
            'has_more': len(rows) > limit,
            'next_cursor': {'created': incidents[-1]['created'], 'id': incidents[-1]['id']}
                           if incidents else None}


@router.post('/incidents', status_code=201)
def create_incident(body: IncidentEvent, request: Request):
    """사내 이벤트를 수동 JSON 계약으로 수집한다(리뷰 P2/N4). 본문은 로컬에만 저장한다."""
    try:
        return get_manager().create_incident(body.model_dump(), owner=_principal(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get('/incidents/deletions')
def list_incident_deletions(request: Request):
    owner = _principal(request) if owner_scope_enabled() else None
    records = get_manager().store.incident_deletions(owner=owner)
    return {'deletions': records}


@router.get('/incidents/asset-trace')
def asset_incident_trace(asset_id: str, request: Request):
    """One explicit asset's visible incidents and evidence-linked findings; local read only."""
    if not asset_id or len(asset_id) > 120:
        raise HTTPException(400, '자산 ID는 1~120자여야 합니다.')
    owner = _principal(request) if owner_scope_enabled() else None
    return get_manager().asset_trace(asset_id, owner=owner)


@router.get('/incidents/{incident_id}')
def incident_trace(incident_id: str, request: Request):
    """사건↔연결 실행의 읽기 전용 상관·상태(리뷰 P2/N4). 대상/모델 호출 없음."""
    manager = get_manager()
    _incident_guard(manager, incident_id, request)
    return manager.incident_trace(incident_id)


@router.post('/incidents/{incident_id}/verify', status_code=201)
async def verify_incident(incident_id: str, req: IncidentVerify, request: Request):
    """사건을 새 실행으로 재검증하고 읽기 전용으로 연결한다(리뷰 P2/N4). AI 호출 없이 고정 실행."""
    manager = get_manager()
    _incident_guard(manager, incident_id, request)
    if sum(not task.done() for task in manager.tasks.values()) >= 2:
        raise HTTPException(409, '동시에 최대 두 개 실행할 수 있습니다.')
    try:
        return manager.verify_incident(incident_id, req.request_headers, req.actor_headers,
                                       access=req.access.model_dump() if req.access else None,
                                       owner=_principal(request))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.delete('/incidents/{incident_id}')
def delete_incident(incident_id: str, request: Request):
    manager = get_manager()
    _incident_guard(manager, incident_id, request)
    manager.store.delete_incident(incident_id)
    return {'deleted': True, 'id': incident_id}


@router.post('/plan')
async def preview_plan(spec: RunSpec):
    """비식별 입력으로 조건부 검증 계획을 1회 생성·검증해 돌려준다(실행하지 않음, 리뷰 Stage 3).
    실행 중 분기는 로컬에서 처리되며 응답은 외부로 나가지 않는다."""
    try:
        plan = await generate_plan(spec)
        # fingerprint 로 승인본을 실행에 고정할 수 있다(리뷰 P3). 같은 계획을 approved_plan 으로
        # 보내 run 을 만들면 재생성 없이 그대로 실행되고, plan 이벤트의 fingerprint 로 대조한다.
        return {'plan': plan.model_dump(), 'fingerprint': plan_fingerprint(plan),
                'policy_version': active_policy_version()}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post('/plan/review')
def review_preview_plan(body: PlanReviewInput):
    """Validate a locally edited plan and recompute its pin; no model or target I/O."""
    try:
        spec = RunSpec.model_validate({**body.spec.model_dump(),
                                       'approved_plan': body.plan,
                                       'approved_plan_expires_at': None})
        plan = pinned_plan(spec)
        return {'plan': plan.model_dump(), 'fingerprint': plan_fingerprint(plan),
                'policy_version': active_policy_version()}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post('/runs', status_code=201)
async def create_run(spec: RunSpec, request: Request):
    manager = get_manager()
    if sum(not task.done() for task in manager.tasks.values()) >= 2:
        raise HTTPException(409, '동시에 최대 두 개 실행할 수 있습니다.')
    try:
        run_id = manager.create(spec, owner=_principal(request))
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return manager.snapshot(run_id)


@router.get('/runs/{run_id}')
def get_run(run_id: str, request: Request):
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return manager.snapshot(run_id)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')


@router.patch('/runs/{run_id}/metadata')
def update_run_metadata(run_id: str, body: RunMetadata, request: Request):
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return manager.store.set_run_metadata(run_id, body.name.strip(), body.category.strip())
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.post('/runs/{run_id}/stop')
async def stop_run(run_id: str, request: Request):
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return await manager.stop(run_id)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')


@router.post('/runs/{run_id}/plan/skip')
def skip_plan_step(run_id: str, body: PlanSkipRequest, request: Request):
    """Audit an explicit skip while paused; the caller resumes separately."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return manager.skip_plan_step(run_id, body.reason)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.post('/runs/{run_id}/plan/hold')
async def hold_plan_step(run_id: str, body: PlanSkipRequest, request: Request):
    """Pause an active plan with a durable reason; never resume automatically."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return await manager.hold_plan(run_id, body.reason)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.post('/runs/{run_id}/plan/step/approve')
def approve_plan_step(run_id: str, body: PlanSkipRequest, request: Request):
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return manager.review_plan_step(run_id, True, body.reason, _principal(request))
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.post('/runs/{run_id}/plan/step/deny')
def deny_plan_step(run_id: str, body: PlanSkipRequest, request: Request):
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return manager.review_plan_step(run_id, False, body.reason, _principal(request))
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.post('/runs/{run_id}/plan/revoke')
async def revoke_plan(run_id: str, body: PlanSkipRequest, request: Request):
    """Cancel and durably revoke a pinned plan approval with an audit reason."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return await manager.revoke_plan(run_id, body.reason)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.delete('/runs/{run_id}')
async def delete_run(run_id: str, request: Request):
    """run 과 증거를 영구 삭제(보존/삭제 정책, 리뷰 F6)."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return await manager.delete(run_id)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')


@router.post('/runs/{run_id}/archive')
def archive_run(run_id: str, request: Request):
    """작업을 보관(목록에서 숨김, 증거 보존). 삭제와 달리 복원 가능(리뷰 N5)."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return manager.set_archived(run_id, True)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.post('/runs/{run_id}/unarchive')
def unarchive_run(run_id: str, request: Request):
    """보관한 작업을 목록으로 복원한다(리뷰 N5)."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return manager.set_archived(run_id, False)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')


@router.get('/runs/{run_id}/archive.zip')
def download_run_archive(run_id: str, request: Request):
    """Download a local, raw-evidence archive for an inactive run."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        payload = manager.store.export_run_archive(run_id)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return Response(payload, media_type='application/zip', headers={
        'Content-Disposition': 'attachment; filename="eventprobe-run-archive.zip"',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@router.post('/archives/import', status_code=201)
async def import_run_archive(request: Request):
    """Restore a bounded archive without starting its run or sending target requests."""
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_ARCHIVE_BYTES:
            raise HTTPException(413, '보관 패키지는 25 MiB 이하여야 합니다.')
        chunks.append(chunk)
    try:
        return get_manager().store.import_run_archive(b''.join(chunks), owner=_principal(request))
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.patch('/runs/{run_id}/findings/{finding_id}')
def update_finding(run_id: str, finding_id: str, patch: FindingPatch, request: Request):
    """발견의 상태/심각도/메모를 append-only 로 기록한다(원본 verification 불변)."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        view = manager.update_finding(run_id, finding_id, patch.model_dump(exclude_none=True))
        from routers.agent_history import run_status
        return {**run_status(run_id, request), **view, 'compact': True}
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post('/runs/{run_id}/findings/{finding_id}/retest')
async def retest_finding(run_id: str, finding_id: str, req: ResumeRequest, request: Request):
    """발견을 새 실행으로 재검증한다(리뷰 P2). 원본 증거 불변, 자격증명은 재주입."""
    manager = get_manager()
    _guard(manager, run_id, request)
    if sum(not task.done() for task in manager.tasks.values()) >= 2:
        raise HTTPException(409, '동시에 최대 두 개 실행할 수 있습니다.')
    try:
        return manager.retest_finding(run_id, finding_id, req.request_headers, req.actor_headers,
                                      owner=_principal(request))
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get('/runs/{run_id}/report', response_class=HTMLResponse)
def run_report(run_id: str, request: Request):
    """로컬 생성 HTML 보고서. 외부 AI/대상 요청 없이 저장된 증거만으로 렌더링한다."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        return HTMLResponse(build_report_html(manager.snapshot(run_id)))
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')


@router.get('/runs/{run_id}/findings/{finding_id}/evidence.zip')
def download_finding_evidence(run_id: str, finding_id: str, request: Request, raw: bool = False):
    """Download one finding's linked evidence locally; raw bodies require explicit selection."""
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        archive = build_finding_evidence_zip(manager.snapshot(run_id), finding_id, include_raw=raw)
    except KeyError:
        raise HTTPException(404, '작업 또는 발견을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return Response(archive, media_type='application/zip', headers={
        'Content-Disposition': 'attachment; filename="finding-evidence.zip"',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    })


@router.post('/runs/{run_id}/resume')
async def resume_run(run_id: str, req: ResumeRequest, request: Request):
    manager = get_manager()
    _guard(manager, run_id, request)
    try:
        if sum(not task.done() for task in manager.tasks.values()) >= 2:
            raise ValueError('동시에 최대 두 개 실행할 수 있습니다.')
        manager.start(run_id, req.request_headers, req.actor_headers,
                      acknowledge_writes=req.acknowledge_writes)
        return manager.snapshot(run_id)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))
