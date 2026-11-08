"""Local model administration and owner-guarded task routing/usage metadata."""
import hmac
import ipaddress
import os

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from core.agent import get_manager
from core.model_profiles import ModelProfile, resolve_key

router = APIRouter()


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int = Field(ge=1)
    profile: ModelProfile


class ChainUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_revision: int = Field(ge=0)
    profile_ids: list[str] = Field(max_length=8)


def require_admin(request):
    token = os.getenv('EVENTPROBE_TOKEN', '').strip()
    if token:
        supplied = request.headers.get('x-access-token') or request.cookies.get('ep_token') or ''
        if not supplied or not hmac.compare_digest(supplied, token):
            raise HTTPException(403, '모델 설정 변경에는 서버 접근 인증이 필요합니다.')
    else:
        try:
            local = ipaddress.ip_address(request.client.host).is_loopback
        except (ValueError, AttributeError):
            local = False
        if not local:
            raise HTTPException(403, '접근 토큰 미설정 시 모델 설정은 서버의 로컬 접속에서만 변경할 수 있습니다.')


def public_profile(store, profile):
    return {**profile, 'format': 'openai-chat', 'key_configured': bool(resolve_key(profile)),
            'health': store.model_health(profile['id'])}


@router.get('/model-profiles')
def list_profiles():
    store = get_manager().store
    return {'profiles': [public_profile(store, p) for p in store.model_profile_list()]}


@router.post('/model-profiles', status_code=201)
def create_profile(body: ModelProfile, request: Request):
    require_admin(request)
    store = get_manager().store
    return public_profile(store, store.save_model_profile(body.model_dump()))


@router.put('/model-profiles/{profile_id}')
def update_profile(profile_id: str, body: ProfileUpdate, request: Request):
    require_admin(request)
    store = get_manager().store
    try:
        return public_profile(store, store.save_model_profile(body.profile.model_dump(), profile_id,
                                                             body.expected_revision))
    except KeyError:
        raise HTTPException(404, '모델 프로파일을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.delete('/model-profiles/{profile_id}')
def delete_profile(profile_id: str, request: Request, expected_revision: int = Query(ge=1)):
    require_admin(request)
    try:
        get_manager().store.delete_model_profile(profile_id, expected_revision)
    except KeyError:
        raise HTTPException(404, '모델 프로파일을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {'deleted': True}


@router.post('/model-profiles/{profile_id}/health/reset')
def reset_health(profile_id: str, request: Request):
    require_admin(request)
    store = get_manager().store
    try:
        profile = store.model_profile(profile_id)
    except KeyError:
        raise HTTPException(404, '모델 프로파일을 찾을 수 없습니다.')
    store.record_model_health(profile, '')
    return {'health': store.model_health(profile_id)}


def run_guard(run_id, request):
    from routers.agent import _guard
    manager = get_manager()
    _guard(manager, run_id, request)
    return manager


@router.get('/runs/{run_id}/model-chain')
def get_chain(run_id: str, request: Request):
    manager = run_guard(run_id, request)
    try:
        return manager.store.run_model_chain(run_id)
    except KeyError:
        raise HTTPException(404, '작업을 찾을 수 없습니다.')


@router.put('/runs/{run_id}/model-chain')
def update_chain(run_id: str, body: ChainUpdate, request: Request):
    manager = run_guard(run_id, request)
    try:
        run = manager.store.get(run_id)
        if run['state'] not in ('running', 'queued', 'paused', 'interrupted') or (
                run['data'].get('archived') or run['data'].get('restored_at')):
            raise ValueError('진행 중이거나 중단된 원본 작업에서만 모델 순서를 변경할 수 있습니다.')
        return manager.store.set_run_model_chain(run_id, body.profile_ids, body.expected_revision)
    except KeyError:
        raise HTTPException(404, '작업 또는 모델 프로파일을 찾을 수 없습니다.')
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@router.get('/runs/{run_id}/model-calls')
def model_calls(run_id: str, request: Request, offset: int = Query(0, ge=0),
                limit: int = Query(50, ge=1, le=100)):
    manager = run_guard(run_id, request)
    try:
        manager.store.get(run_id)
    except KeyError:
        raise HTTPException(404, '작업을 찾을 수 없습니다.')
    return manager.store.model_call_page(run_id, offset, limit)
