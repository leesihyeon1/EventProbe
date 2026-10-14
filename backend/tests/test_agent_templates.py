"""재사용 검증 템플릿(리뷰 N1). 검증 설정(목표/범위/예산/계획)을 템플릿으로 저장하고 새
실행으로 복제한다. 비밀값(자격증명)은 템플릿에 저장하지 않고 실행 시 재주입한다.
실 HTTP 는 MockTransport, 실제 대상/LLM 호출 없음."""
import asyncio

import httpx
import pytest

import core.agent as agent_mod
from core.agent import AgentManager, template_spec
from core.agent_store import Store
from core.agent_models import RunSpec, Action


def _spec():
    return RunSpec.model_validate({
        'goal': '템플릿 목표', 'request': {'url': 'https://app.test/?id=1', 'headers': {'Cookie': 's=SECRET'}},
        'actors': [{'id': 'current', 'headers': {'X-Auth': 'SECRET'}}]})


def _finish_planner():
    async def choose(ctx):
        return Action(kind='finish', hypothesis='종료',
                      basis=[ctx['observations'][-1]['id']] if ctx['observations'] else [])
    return choose


def test_template_spec_strips_credentials_but_keeps_structure():
    d = template_spec(_spec())
    assert d['request']['headers'] == {}
    assert all(a['headers'] == {} for a in d['actors'])
    assert d['goal'] == '템플릿 목표' and d['request']['url'] == 'https://app.test/?id=1'
    assert 'SECRET' not in str(d)


def test_store_template_crud(tmp_path):
    s = Store(tmp_path / 't.db')
    tid = s.save_template('로그인 점검', 'auth', template_spec(_spec()))
    lst = s.templates()
    assert len(lst) == 1 and lst[0]['name'] == '로그인 점검' and lst[0]['goal'] == '템플릿 목표'
    assert s.template(tid)['spec']['request']['headers'] == {}
    assert s.delete_template(tid) is True
    with pytest.raises(KeyError):
        s.template(tid)
    assert s.delete_template(tid) is False


def test_run_template_clones_run_and_reinjects_credentials(tmp_path):
    seen = []
    def handler(req):
        seen.append(req.headers.get('cookie'))
        return httpx.Response(200, text='ok')

    async def go():
        m = AgentManager(Store(tmp_path / 't.db'), planner=_finish_planner(), transport=httpx.MockTransport(handler))
        tid = m.store.save_template('t', 'c', template_spec(_spec()))
        snap = m.run_template(tid, request_headers={'Cookie': 'fresh=1'}, owner='alice')
        await m.tasks[snap['id']]
        return snap, seen
    snap, seen = asyncio.run(go())
    assert snap['data']['owner'] == 'alice'                 # principal 소유 기록
    assert snap['data']['spec']['goal'] == '템플릿 목표'     # 템플릿 구조 복제
    assert seen and any('fresh=1' in (c or '') for c in seen)   # 실행 시 재주입된 자격증명 사용
    assert 'SECRET' not in str(seen)                        # 템플릿엔 원 비밀값이 없다


def test_template_endpoints(tmp_path, monkeypatch):
    m = AgentManager(Store(tmp_path / 'ep.db'), planner=_finish_planner(),
                     transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
    monkeypatch.setattr(agent_mod, '_manager', m)
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)
    saved = client.post('/api/agent/templates',
                        json={'name': '스캔', 'category': 'xss',
                              'spec': {'goal': 'g', 'request': {'url': 'https://app.test/', 'headers': {'Cookie': 'x=SECRET'}}}})
    assert saved.status_code == 201
    tid = saved.json()['id']
    listed = client.get('/api/agent/templates').json()['templates']
    assert any(t['id'] == tid for t in listed)
    assert 'SECRET' not in str(m.store.template(tid)['spec'])   # 저장 시 비밀값 제거
    run = client.post(f'/api/agent/templates/{tid}/run', json={})
    assert run.status_code == 201 and run.json()['data']['spec']['goal'] == 'g'
    assert client.delete(f'/api/agent/templates/{tid}').status_code == 200
    assert client.delete(f'/api/agent/templates/{tid}').status_code == 404
