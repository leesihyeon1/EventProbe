"""저장/보존 경계 — run·증거 삭제와 보존 기간 정리 (리뷰 F6).

증거를 로컬에 무한 보관하지 않도록 삭제 API 와 보존(prune) 기능을 검증한다.
실제 대상/AI 호출 없이 store·manager·엔드포인트만 확인한다.
"""
import asyncio
import time

import httpx
import pytest

from core.agent_store import Store
from core.agent import AgentManager
from core.agent_models import RunSpec


def _spec():
    return RunSpec.model_validate({'goal': 't', 'request': {'url': 'https://app.test/?id=1'}})


def test_store_delete_removes_run_and_events(tmp_path):
    s = Store(tmp_path / 'a.db')
    rid = s.create({'spec': {'goal': 't'}})
    s.event(rid, 'observation', {'x': 1})
    assert s.get(rid)
    assert s.delete(rid) is True
    with pytest.raises(KeyError):
        s.get(rid)
    assert s.events(rid) == []
    assert s.delete(rid) is False          # 이미 없음


def test_store_prune_by_age(tmp_path):
    s = Store(tmp_path / 'a.db')
    old = s.create({'spec': {'goal': 'old'}})
    new = s.create({'spec': {'goal': 'new'}})
    with s.connect() as db:                 # old 를 10일 전으로
        db.execute('UPDATE runs SET updated=? WHERE id=?', (time.time() - 10 * 86400, old))
    assert s.prune(0) == 0                   # 0 = 비활성(무제한 보관)
    assert s.prune(7) == 1                   # 7일 초과 1건
    with pytest.raises(KeyError):
        s.get(old)
    assert s.get(new)                        # 최근 것은 유지


def test_manager_delete_clears_memory(tmp_path):
    async def go():
        m = AgentManager(Store(tmp_path / 'a.db'), planner=lambda ctx: None,
                         transport=httpx.MockTransport(lambda r: httpx.Response(200)))
        rid = m.store.create({'spec': {'goal': 't'}})
        m.specs[rid] = _spec()
        res = await m.delete(rid)
        assert res['deleted'] is True
        with pytest.raises(KeyError):
            m.store.get(rid)
        assert rid not in m.specs
        with pytest.raises(KeyError):        # 없는 run 삭제 → KeyError(→ API 404)
            await m.delete('nope')
    asyncio.run(go())


def test_delete_endpoint(tmp_path):
    from fastapi.testclient import TestClient
    from main import app
    from core.agent import get_manager
    client = TestClient(app)
    rid = get_manager().store.create({'spec': {'goal': 't'}})
    assert client.delete('/api/agent/runs/' + rid).status_code == 200
    assert client.delete('/api/agent/runs/' + rid).status_code == 404   # 이미 삭제됨


# ── 삭제 감사(P4): 삭제돼도 '무엇을·언제·왜'는 남는다 ──────────────────────────
def test_delete_records_audit_that_survives(tmp_path):
    s = Store(tmp_path / 'a.db')
    rid = s.create({'spec': {'goal': '민감 작업'}})
    s.event(rid, 'observation', {'x': 1}); s.event(rid, 'verification', {'status': 'confirmed'})
    s.delete(rid)
    audit = s.deletions()
    assert len(audit) == 1
    rec = audit[0]
    assert rec['run_id'] == rid and rec['reason'] == 'manual'
    assert rec['events'] == 2 and rec['goal'] == '민감 작업'
    s.delete(rid)                                  # 없는 run 재삭제 → 감사 추가 없음
    assert len(s.deletions()) == 1


def test_prune_records_retention_audit(tmp_path):
    s = Store(tmp_path / 'a.db')
    old = s.create({'spec': {'goal': 'old'}})
    s.event(old, 'observation', {'x': 1})
    with s.connect() as db:
        db.execute('UPDATE runs SET updated=? WHERE id=?', (time.time() - 10 * 86400, old))
    assert s.prune(7) == 1
    audit = s.deletions()
    assert len(audit) == 1 and audit[0]['reason'] == 'retention' and audit[0]['events'] == 1
    assert s.prune(7) == 0 and len(s.deletions()) == 1   # 감사는 보존 정리의 대상이 아니다


def test_deletions_newest_first_and_endpoint(tmp_path):
    from fastapi.testclient import TestClient
    from main import app
    from core.agent import get_manager
    store = get_manager().store
    a = store.create({'spec': {'goal': 'A'}}); store.delete(a)
    b = store.create({'spec': {'goal': 'B'}}); store.delete(b)
    client = TestClient(app)
    data = client.get('/api/agent/deletions').json()['deletions']
    ids = [r['run_id'] for r in data]
    assert ids.index(b) < ids.index(a)             # 최신 삭제가 먼저
