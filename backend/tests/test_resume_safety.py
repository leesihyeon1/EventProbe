"""재개 안전장치(리뷰 P3): 처리 여부가 불명확한 쓰기 요청은 명시적 확인 없이 재개하지 않는다.
완료 관측이 없는 쓰기(POST/PUT/PATCH/DELETE) request_started 는 '결과 미확인'으로 보고,
재개 시 자동 재전송을 막아 중복 변경을 방지한다. 실 HTTP 는 MockTransport."""
import asyncio

import httpx
import pytest

import core.agent as agent_mod
from core.agent import AgentManager, AmbiguousWrite, ambiguous_writes
from core.agent_store import Store
from core.agent_models import RunSpec, Action


def _started(request_id, method='POST'):
    return {'id': request_id, 'kind': 'request_started', 'step_id': 's1', 'created': 1.0,
            'data': {'actor_id': 'current', 'request': {'url': 'https://app.test/', 'method': method}}}


def _obs(request_id):
    return {'id': 'o_' + request_id, 'kind': 'observation', 'step_id': 's1', 'created': 2.0,
            'data': {'id': 'o_' + request_id, 'request_id': request_id, 'actor_id': 'current'}}


def test_ambiguous_writes_detection():
    # 완료 관측 없는 쓰기 → 불명확; 관측 있으면 해소; GET 은 대상 아님.
    assert ambiguous_writes([_started('r1')]) == ['r1']
    assert ambiguous_writes([_started('r1'), _obs('r1')]) == []
    assert ambiguous_writes([_started('r2', 'GET')]) == []
    mixed = [_started('w', 'DELETE'), _started('g', 'GET'), _obs('g')]
    assert ambiguous_writes(mixed) == ['w']


def _resumable_run(manager, with_write=True):
    spec = RunSpec.model_validate({'goal': 't', 'request': {'url': 'https://app.test/', 'method': 'GET'}})
    data = {'spec': spec.model_dump(), 'needs_credentials': False, 'owner': '', 'reason': '', 'stop_code': '',
            'requests': 1, 'ai_calls': 0, 'steps': 1, 'elapsed': 0,
            'endpoints': {'seed': {'url': 'https://app.test/', 'method': 'GET', 'params': {}, 'body': '', 'headers': {}}}}
    rid = manager.store.create(data)   # state 'paused'
    if with_write:
        manager.store.event(rid, 'request_started',
                            {'actor_id': 'current', 'request': {'url': 'https://app.test/', 'method': 'POST'}}, 's1')
    return rid


def _finish_planner():
    async def choose(ctx):
        return Action(kind='finish', hypothesis='종료',
                      basis=[ctx['observations'][-1]['id']] if ctx['observations'] else [])
    return choose


def test_resume_blocks_ambiguous_write_without_ack(tmp_path):
    m = AgentManager(Store(tmp_path / 'a.db'), planner=_finish_planner(),
                     transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
    rid = _resumable_run(m)
    with pytest.raises(AmbiguousWrite):
        m.start(rid)                                  # 확인 없이 재개 → 차단
    assert rid not in m.tasks                         # 작업이 시작되지 않음
    assert m.store.get(rid)['state'] == 'paused'      # 상태 그대로


def test_resume_proceeds_with_ack_and_records_marker(tmp_path):
    async def go():
        m = AgentManager(Store(tmp_path / 'a.db'), planner=_finish_planner(),
                         transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
        rid = _resumable_run(m)
        m.start(rid, acknowledge_writes=True)         # 확인 후 재개 → 진행
        await m.tasks[rid]
        return m.store.events(rid)
    events = asyncio.run(go())
    assert any(e['kind'] == 'resume_ack' for e in events)


def test_resume_without_writes_is_unaffected(tmp_path):
    async def go():
        m = AgentManager(Store(tmp_path / 'a.db'), planner=_finish_planner(),
                         transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
        rid = _resumable_run(m, with_write=False)
        m.start(rid)                                  # 쓰기 없음 → 확인 없이도 재개
        await m.tasks[rid]
        return m.store.events(rid)
    events = asyncio.run(go())
    assert not any(e['kind'] == 'resume_ack' for e in events)   # 확인 마커 불필요


def test_resume_endpoint_409_then_ok(tmp_path, monkeypatch):
    m = AgentManager(Store(tmp_path / 'ep.db'), planner=_finish_planner(),
                     transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
    monkeypatch.setattr(agent_mod, '_manager', m)
    rid = _resumable_run(m)
    from fastapi.testclient import TestClient
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    client = TestClient(main.app)
    assert client.post(f'/api/agent/runs/{rid}/resume', json={}).status_code == 409
    assert client.post(f'/api/agent/runs/{rid}/resume', json={'acknowledge_writes': True}).status_code == 200
