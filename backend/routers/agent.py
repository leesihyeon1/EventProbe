import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from core.agent import get_manager, generate_plan
from core.agent_findings import build_report_html
from core.agent_models import RunSpec
from core.plan import plan_fingerprint

router = APIRouter(prefix='/api/agent', tags=['context-agent'])


class ResumeRequest(BaseModel):
    request_headers: dict[str, str] | None = None
    actor_headers: dict[str, dict[str, str]] | None = None


class FindingPatch(BaseModel):
    status: str | None = None
    severity: str | None = None
    note: str | None = None


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
def list_runs():
    return {'runs': get_manager().store.list()}


@router.get('/deletions')
def list_deletions(limit: int = 100):
    """증거 삭제 감사(수동/보존). 삭제된 run 자체는 사라져도 기록은 남는다(리뷰 P4)."""
    return {'deletions': get_manager().store.deletions(limit)}


@router.post('/plan')
async def preview_plan(spec: RunSpec):
    """비식별 입력으로 조건부 검증 계획을 1회 생성·검증해 돌려준다(실행하지 않음, 리뷰 Stage 3).
    실행 중 분기는 로컬에서 처리되며 응답은 외부로 나가지 않는다."""
    try:
        plan = await generate_plan(spec)
        # fingerprint 로 승인본을 실행에 고정할 수 있다(리뷰 P3). 같은 계획을 approved_plan 으로
        # 보내 run 을 만들면 재생성 없이 그대로 실행되고, plan 이벤트의 fingerprint 로 대조한다.
        return {'plan': plan.model_dump(), 'fingerprint': plan_fingerprint(plan)}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post('/runs', status_code=201)
async def create_run(spec: RunSpec):
    manager = get_manager()
    if sum(not task.done() for task in manager.tasks.values()) >= 2:
        raise HTTPException(409, '동시에 최대 두 개 실행할 수 있습니다.')
    run_id = manager.create(spec)
    return manager.snapshot(run_id)


@router.get('/runs/{run_id}')
def get_run(run_id: str):
    try:
        return get_manager().snapshot(run_id)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')


@router.post('/runs/{run_id}/stop')
async def stop_run(run_id: str):
    try:
        return await get_manager().stop(run_id)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')


@router.delete('/runs/{run_id}')
async def delete_run(run_id: str):
    """run 과 증거를 영구 삭제(보존/삭제 정책, 리뷰 F6)."""
    try:
        return await get_manager().delete(run_id)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')


@router.patch('/runs/{run_id}/findings/{finding_id}')
def update_finding(run_id: str, finding_id: str, patch: FindingPatch):
    """발견의 상태/심각도/메모를 append-only 로 기록한다(원본 verification 불변)."""
    try:
        return get_manager().update_finding(run_id, finding_id, patch.model_dump(exclude_none=True))
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get('/runs/{run_id}/report', response_class=HTMLResponse)
def run_report(run_id: str):
    """로컬 생성 HTML 보고서. 외부 AI/대상 요청 없이 저장된 증거만으로 렌더링한다."""
    try:
        return HTMLResponse(build_report_html(get_manager().snapshot(run_id)))
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')


@router.post('/runs/{run_id}/resume')
async def resume_run(run_id: str, req: ResumeRequest):
    try:
        manager = get_manager()
        if sum(not task.done() for task in manager.tasks.values()) >= 2:
            raise ValueError('동시에 최대 두 개 실행할 수 있습니다.')
        manager.start(run_id, req.request_headers, req.actor_headers)
        return manager.snapshot(run_id)
    except KeyError:
        raise HTTPException(404, '실행 기록을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))
