"""발견 재검증(리뷰 P2): 발견을 '새 실행'으로 다시 검증한다. 원본 run/증거는 불변,
새 run 은 발견의 엔드포인트·공격 유형·행위자에 대한 고정 confirm 계획을 실행한다.
실 HTTP 는 MockTransport, 실제 대상/LLM 은 호출하지 않는다."""
import asyncio

import httpx

from core.agent import AgentManager
from core.agent_store import Store
from core.agent_findings import build_findings


def _manager(tmp_path, handler=lambda r: httpx.Response(200, text='normal')):
    return AgentManager(Store(tmp_path / 'a.db'), transport=httpx.MockTransport(handler))


def _seed(manager, kind='probe', category='sqli'):
    data = {'spec': {'goal': 'orig'}, 'needs_credentials': False,
            'endpoints': {'seed': {'url': 'https://app.test/?id=1', 'method': 'GET', 'params': {}, 'body': ''}}}
    rid = manager.store.create(data)
    manager.store.event(rid, 'action', {'kind': kind, 'category': category, 'param': 'id',
                                        'location': 'param', 'endpoint_id': 'seed', 'actor_id': 'current'}, 's1')
    manager.store.event(rid, 'observation', {'id': 'o1'}, 's1', 'o1')
    manager.store.event(rid, 'verification', {'status': 'confirmed', 'evidence_ids': ['o1'], 'category': category}, 's1')
    fid = build_findings(rid, manager.store.get(rid)['data'], manager.store.events(rid))[0]['id']
    return rid, fid


def test_retest_creates_linked_new_run_without_touching_original(tmp_path):
    async def go():
        m = _manager(tmp_path)
        orig, fid = _seed(m)
        before = len(m.store.events(orig))
        snap = m.retest_finding(orig, fid)
        new_id = snap['id']
        assert new_id != orig
        await m.tasks[new_id]
        new = m.snapshot(new_id)
        assert new['data']['retest_of'] == {'finding_id': fid, 'run_id': orig, 'category': 'sqli'}
        assert new['data']['spec']['mode'] == 'plan'               # 고정 계획으로 실행
        assert new['data']['spec']['approved_plan']['steps'][0]['action']['kind'] == 'confirm'
        assert any(e['kind'] == 'verification' for e in new['events'])   # 재검증이 실제로 실행됨
        assert len(m.store.events(orig)) == before                 # 원본 증거 불변
    asyncio.run(go())


def test_retest_reinjects_credentials(tmp_path):
    seen = []
    def handler(req):
        seen.append(req.headers.get('x-auth'))
        return httpx.Response(200, text='normal')
    async def go():
        m = _manager(tmp_path, handler)
        orig, fid = _seed(m)
        snap = m.retest_finding(orig, fid, actor_headers={'current': {'X-Auth': 'retest-token'}})
        await m.tasks[snap['id']]
        assert seen and all(h == 'retest-token' for h in seen)      # 재주입된 자격증명으로 요청
    asyncio.run(go())


def test_retest_rejects_non_vuln_finding(tmp_path):
    m = _manager(tmp_path)
    orig, fid = _seed(m, kind='observe', category='')              # 관측 발견 → 재검증 불가
    try:
        m.retest_finding(orig, fid)
        assert False, 'expected ValueError'
    except ValueError:
        pass


def test_retest_unknown_finding_raises(tmp_path):
    m = _manager(tmp_path)
    orig, _ = _seed(m)
    try:
        m.retest_finding(orig, 'deadbeefdeadbeef')
        assert False, 'expected ValueError'
    except ValueError:
        pass


def test_retest_endpoint_404_for_unknown_run(tmp_path):
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)
    r = client.post('/api/agent/runs/nope/findings/x/retest', json={})
    assert r.status_code == 404
