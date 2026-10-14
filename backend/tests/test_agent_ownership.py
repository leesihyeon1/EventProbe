"""작업 소유권 범위(리뷰 P4). 기본 off(기존 단일 작업공간과 동일), 켜면 작업은 생성한
principal 만 조회·조작하고 소유자 미기록(레거시) 작업은 모두에게 보인다. 접근 토큰이 보안
경계이며 principal 은 협업 작업공간 구분용이다. 실제 대상/LLM 호출 없음."""
import pytest

import core.agent as agent_mod
from core.agent import AgentManager, owns, owner_scope_enabled
from core.agent_store import Store
from core.agent_models import RunSpec


def _data(owner='', goal='t'):
    return {'spec': {'goal': goal}, 'owner': owner, 'needs_credentials': False, 'reason': '',
            'requests': 0, 'ai_calls': 0, 'steps': 0, 'elapsed': 0,
            'endpoints': {'seed': {'url': 'https://app.test/', 'method': 'GET'}}}


# ── 순수 로직 ──────────────────────────────────────────────────────────────────
def test_scope_off_allows_everyone(monkeypatch):
    monkeypatch.delenv('AGENT_SCOPE_OWNER', raising=False)
    assert not owner_scope_enabled()
    assert owns({'owner': 'alice'}, 'bob') is True        # off → 항상 허용


def test_scope_on_owner_matching(monkeypatch):
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    assert owner_scope_enabled()
    assert owns({'owner': 'alice'}, 'alice') is True
    assert owns({'owner': 'alice'}, 'bob') is False
    assert owns({'owner': ''}, 'bob') is True             # 소유자 미기록 → 모두 허용


def test_create_stamps_owner(tmp_path):
    import asyncio
    import httpx

    async def go():
        m = AgentManager(Store(tmp_path / 'o.db'), planner=lambda c: None,
                         transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        rid = m.create(RunSpec.model_validate({'goal': 't', 'request': {'url': 'https://app.test/'}}), owner='alice')
        await m.tasks[rid]
        return m.store.get(rid)['data']['owner']
    assert asyncio.run(go()) == 'alice'


def test_check_access_enforced_only_when_scoped(tmp_path, monkeypatch):
    m = AgentManager(Store(tmp_path / 'o.db'))
    rid = m.store.create(_data(owner='alice'))
    monkeypatch.delenv('AGENT_SCOPE_OWNER', raising=False)
    m.check_access(rid, 'bob')                            # off → 통과
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    m.check_access(rid, 'alice')                          # 소유자 → 통과
    with pytest.raises(PermissionError):
        m.check_access(rid, 'bob')                        # 타인 → 거부
    with pytest.raises(KeyError):
        m.check_access('missing', 'alice')               # 없는 run → KeyError(→404)


# ── 라우터(소유권 범위 ON) ─────────────────────────────────────────────────────
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_mod, '_manager', AgentManager(Store(tmp_path / 'own.db')))
    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app)


def _insert(owner):
    return agent_mod.get_manager().store.create(_data(owner))


def test_list_unfiltered_when_scope_off(client, monkeypatch):
    monkeypatch.delenv('AGENT_SCOPE_OWNER', raising=False)
    a, b = _insert('alice'), _insert('bob')
    ids = [r['id'] for r in client.get('/api/agent/runs').json()['runs']]
    assert a in ids and b in ids


def test_scope_on_filters_list_and_guards_access(client, monkeypatch):
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    a, legacy, bob = _insert('alice'), _insert(''), _insert('bob')
    H = {'X-EventProbe-User': 'alice'}
    ids = [r['id'] for r in client.get('/api/agent/runs', headers=H).json()['runs']]
    assert a in ids and legacy in ids and bob not in ids          # 내 것 + 미기록만
    assert client.get('/api/agent/runs/' + a, headers=H).status_code == 200
    assert client.get('/api/agent/runs/' + a, headers={'X-EventProbe-User': 'bob'}).status_code == 403
    assert client.get('/api/agent/runs/' + legacy, headers={'X-EventProbe-User': 'bob'}).status_code == 200
    assert client.delete('/api/agent/runs/' + a, headers={'X-EventProbe-User': 'bob'}).status_code == 403
    assert client.post('/api/agent/runs/' + a + '/findings/x/retest', json={},
                       headers={'X-EventProbe-User': 'bob'}).status_code == 403


def test_create_via_endpoint_records_principal(client, monkeypatch):
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    # 생성 시 principal 이 소유자로 기록되고, 생성자만 조회된다. 작업은 즉시 멈춰 네트워크를 쓰지 않게 한다.
    import httpx
    agent_mod.get_manager().transport = httpx.MockTransport(lambda r: httpx.Response(200, text='ok'))
    r = client.post('/api/agent/runs', json={'goal': 't', 'request': {'url': 'https://app.test/'}, 'max_steps': 1},
                    headers={'X-EventProbe-User': 'carol'})
    assert r.status_code == 201
    assert r.json()['data']['owner'] == 'carol'
