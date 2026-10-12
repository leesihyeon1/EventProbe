from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.agent import get_manager
from core.agent_models import RunSpec

router = APIRouter(prefix='/api/agent', tags=['context-agent'])


class ResumeRequest(BaseModel):
    request_headers: dict[str, str] | None = None
    actor_headers: dict[str, dict[str, str]] | None = None


@router.on_event('startup')
async def recover_runs():
    get_manager().store.recover()


@router.on_event('shutdown')
async def stop_runs():
    await get_manager().shutdown()


@router.get('/runs')
def list_runs():
    return {'runs': get_manager().store.list()}


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
