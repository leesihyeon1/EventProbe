"""작업 보관/복원(리뷰 N5). 삭제와 달리 증거를 보존한 채 목록에서 숨기고 되돌릴 수 있다.
실제 대상/LLM 호출 없음."""
import pytest

import core.agent as agent_mod
from core.agent import AgentManager
from core.agent_store import Store


def _data(goal='t', archived=False):
    return {'spec': {'goal': goal}, 'owner': '', 'archived': archived, 'needs_credentials': False, 'reason': '',
            'requests': 0, 'ai_calls': 0, 'steps': 0, 'elapsed': 0,
            'endpoints': {'seed': {'url': 'https://app.test/', 'method': 'GET'}}}


def test_set_archived_toggles(tmp_path):
    m = AgentManager(Store(tmp_path / 'a.db'))
    rid = m.store.create(_data())
    assert m.set_archived(rid, True)['archived'] is True
    assert m.store.get(rid)['data']['archived'] is True
    assert m.set_archived(rid, False)['archived'] is False
    assert m.store.get(rid)['data']['archived'] is False


def test_cannot_archive_running(tmp_path):
    m = AgentManager(Store(tmp_path / 'a.db'))
    rid = m.store.create(_data())
    with m.store.connect() as db:
        db.execute("UPDATE runs SET state='running' WHERE id=?", (rid,))
    with pytest.raises(ValueError):
        m.set_archived(rid, True)


def test_list_filters_archived(tmp_path):
    s = Store(tmp_path / 'a.db')
    a = s.create(_data('active'))
    b = s.create(_data('archived', archived=True))
    default_ids = [r['id'] for r in s.list()]
    assert a in default_ids and b not in default_ids
    archived_ids = [r['id'] for r in s.list(include_archived=True)]
    assert b in archived_ids and a not in archived_ids


def test_archive_endpoints(tmp_path, monkeypatch):
    m = AgentManager(Store(tmp_path / 'ep.db'))
    monkeypatch.setattr(agent_mod, '_manager', m)
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)
    rid = m.store.create(_data('x'))
    assert client.post(f'/api/agent/runs/{rid}/archive').status_code == 200
    assert rid not in [r['id'] for r in client.get('/api/agent/runs').json()['runs']]          # 기본 목록에서 숨김
    assert rid in [r['id'] for r in client.get('/api/agent/runs?archived=1').json()['runs']]   # 보관함에 표시
    assert client.post(f'/api/agent/runs/{rid}/unarchive').status_code == 200
    assert rid in [r['id'] for r in client.get('/api/agent/runs').json()['runs']]              # 복원
    assert client.post('/api/agent/runs/nope/archive').status_code == 404
