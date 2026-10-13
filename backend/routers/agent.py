import os

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.agent import get_manager, generate_plan
from core.agent_models import RunSpec

router = APIRouter(prefix='/api/agent', tags=['context-agent'])


class ResumeRequest(BaseModel):
    request_headers: dict[str, str] | None = None
    actor_headers: dict[str, dict[str, str]] | None = None


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


@router.post('/plan')
async def preview_plan(spec: RunSpec):
    """비식별 입력으로 조건부 검증 계획을 1회 생성·검증해 돌려준다(실행하지 않음, 리뷰 Stage 3).
    실행 중 분기는 로컬에서 처리되며 응답은 외부로 나가지 않는다."""
    try:
        plan = await generate_plan(spec)
        return {'plan': plan.model_dump()}
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
