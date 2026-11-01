"""Local SIEM analysis, opt-in retention and workspace-scoped inventory."""
from fastapi import APIRouter, HTTPException, Request
from core.triage import analyze, MAX_BYTES

import asyncio
import contextlib
from contextlib import asynccontextmanager


@asynccontextmanager
async def retention_lifespan(app):
    task=asyncio.create_task(_retention_loop())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


router = APIRouter(prefix='/api/triage', tags=['triage'],lifespan=retention_lifespan)

async def read_text(request):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BYTES:
            raise HTTPException(413, '입력은 2MB 이하로 제한됩니다.')
    try:
        return body.decode('utf-8-sig')
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post('/analyze')
async def analyze_logs(request: Request):
    try:
        return get_store().enrich(_owner(request), analyze(await read_text(request)))
    except ValueError as exc:
        raise HTTPException(422,str(exc)) from exc


from pydantic import BaseModel, Field, ConfigDict
from core.triage_planning import canonical_request, prepare
from core.agent_assets import asset_shape


class Preparation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    url: str = Field(max_length=4096)
    category: str = Field(max_length=20)
    param: str = Field(max_length=120)
    event_id: str = Field(max_length=120)
    summary: str = Field(default='', max_length=2000)


@router.post('/prepare')
def prepare_validation(body: Preparation):
    try:
        return prepare(**body.model_dump())
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get('/asset-match')
def match_asset(request: Request, url: str):
    from core.agent import get_manager, owner_scope_enabled
    from routers.agent import _principal
    try:
        shape=asset_shape(canonical_request(url))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    owner=_principal(request) if owner_scope_enabled() else None
    page=get_manager().store.asset_page(asset_id=shape[0],owner=owner,limit=1)
    return {'asset_id':shape[0], 'match':page['assets'][0] if page['assets'] else None,
            'note':'관측된 엔드포인트 대조이며 회사 전체 자산 등록 여부를 의미하지 않습니다.'}


import os
from pathlib import Path
from fastapi import Query
from core.triage_store import TriageStore
from core import analyzer
from urllib.parse import urlsplit
import httpx


def _owner(request):
    # Same workspace identity as existing agent APIs; it is not independent authentication.
    return (request.headers.get('x-eventprobe-user') or request.cookies.get('ep_user') or '').strip()[:64]


def get_store():
    agent_path=Path(os.getenv('AGENT_DB_PATH') or Path(__file__).resolve().parents[1]/'data'/'agent'/'runs.sqlite3')
    return TriageStore(os.getenv('TRIAGE_DB_PATH') or agent_path.with_name('triage.sqlite3'))


class TechnologyProbe(BaseModel):
    model_config = ConfigDict(extra='forbid')
    origin: str = Field(max_length=4096)


@router.post('/technology-probe')
async def technology_probe(body: TechnologyProbe, request: Request):
    """One bounded GET, analyzed locally using the request/analysis engine."""
    target = body.origin.strip()
    parsed = urlsplit(target)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
            parsed.username or parsed.password or parsed.path not in ('', '/') or
            parsed.query or parsed.fragment or target.endswith('/') or
            any(ord(c) < 33 for c in target)):
        raise HTTPException(422, '유효한 HTTP(S) 접속 주소(scheme·host, 경로/쿼리 없이)만 사용할 수 있습니다.')
    # One bounded request; no external enrichment, redirects or exploit probes.
    limit = 128 * 1024
    try:
        async with asyncio.timeout(10):
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0), follow_redirects=False,
                                         trust_env=False) as client:
                async with client.stream('GET', target + '/') as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    raw = bytearray()
                    truncated = False
                    content_type = headers.get('content-type', '').lower()
                    if any(kind in content_type for kind in ('text/', 'html', 'json', 'xml', 'javascript')):
                        async for chunk in response.aiter_bytes(chunk_size=8192):
                            room = limit - len(raw)
                            raw.extend(chunk[:room])
                            if len(chunk) > room or len(raw) >= limit:
                                truncated = True
                                break
                    body_text = bytes(raw).decode('utf-8', errors='replace')
                    # Reuse the request/analysis engine locally, returning only
                    # technology observations, never raw body/cookies/findings.
                    # Reuse discovery components only. The full attack analyzer
                    # evaluates exploit matchers and is unnecessary for discovery.
                    stack = analyzer.detect_stack(headers)
                    analysis = {'waf_detected': analyzer.detect_waf(headers),
                                'spa_shell': analyzer._detect_spa_shell(body_text, headers)}
                    technologies = list(dict.fromkeys(item['name'] for item in stack))
                    evidence = [{'name': item['name'], 'source': 'response-header'} for item in stack]
                    shell = analysis.get('spa_shell')
                    if shell and shell.get('framework'):
                        name = shell['framework']
                        if name not in technologies:
                            technologies.append(name)
                            evidence.append({'name': name, 'source': 'html-pattern', 'confidence': 'tentative'})
                    return {'origin': target, 'status': response.status_code,
                            'technologies': technologies, 'evidence': evidence,
                            'waf': analysis.get('waf_detected'), 'body_bytes_examined': len(raw),
                            'body_truncated': truncated, 'requests': 1,
                            'note': 'GET / 1회 · 본문 최대 128KiB 로컬 분석 · 리다이렉트/추가 경로/외부 서비스 없음. 기술 관측은 제품 버전이나 CVE 취약 여부의 확증이 아닙니다.'}
    except (httpx.RequestError, TimeoutError) as exc:
        raise HTTPException(502, f'기술 확인 요청 실패: {type(exc).__name__}') from exc



@router.post('/batches',status_code=201)
async def save_batch(request: Request, days: int=Query(7,ge=1,le=30)):
    text=await read_text(request)
    try:
        result=get_store().enrich(_owner(request),analyze(text))
        return get_store().save(_owner(request),text,result,days)
    except ValueError as exc:
        raise HTTPException(422,str(exc)) from exc


@router.get('/batches')
def list_batches(request: Request):
    return {'batches':get_store().batches(_owner(request))}


@router.get('/batches/{batch_id}')
def load_batch(batch_id: str, request: Request):
    try:return get_store().batch(_owner(request),batch_id)
    except KeyError:raise HTTPException(404,'저장 기록을 찾을 수 없습니다.')


@router.delete('/batches/{batch_id}')
def delete_batch(batch_id: str, request: Request):
    if not get_store().delete(_owner(request),batch_id):raise HTTPException(404,'저장 기록을 찾을 수 없습니다.')
    return {'deleted':True}


@router.get('/inventory')
def list_inventory(request: Request):
    return {'assets':get_store().inventory(_owner(request))}


@router.post('/inventory')
async def import_inventory(request: Request):
    text=await read_text(request)
    try:return {'imported':get_store().import_inventory(_owner(request),text)}
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc


@router.delete('/inventory')
def delete_inventory(request: Request, origin: str=Query(max_length=4096)):
    if not get_store().delete_inventory(_owner(request),origin):raise HTTPException(404,'자산을 찾을 수 없습니다.')
    return {'deleted':True}


async def _retention_loop():
    import logging
    def cleanup():
        get_store().cleanup()
    while True:
        try:
            await asyncio.to_thread(cleanup)
        except Exception:
            logging.getLogger(__name__).exception('SIEM retention cleanup failed')
        await asyncio.sleep(60)
