"""ARTEX-style FIFO admission, durable counters and crash-safe session recovery."""
import asyncio
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from core.agent import AgentManager
from core.agent_models import RunSpec, Action
from core.agent_runtime_store import RequestBudgetExceeded, RunConflict
from core.agent_store import Store


def seed(store, maximum=7, **extra):
    spec = RunSpec(goal='synthetic', request={'url': 'https://example.test/'},
                   max_requests=maximum)
    return store.create({'spec': spec.model_dump(), 'requests': 0, 'ai_calls': 0,
                         'steps': 0, 'elapsed': 0, 'endpoints': {},
                         'needs_credentials': False, **extra})


def test_fifo_survives_reopen_and_never_skips_unready_head(tmp_path):
    path = tmp_path / 'fifo.db'
    store = Store(path)
    ids = [seed(store) for _ in range(3)]
    for rid in ids:
        store.enqueue(rid)
    other = Store(path)
    assert other.queued_runs() == ids
    assert other.queue_position(ids[-1]) == 3
    assert other.admit_next(1, ids[1:]) is None
    assert other.admit_next(1, ids) == ids[0]
    assert other.admit_next(1, ids) is None
    other.update(ids[0], other.get(ids[0])['data'], 'completed')
    assert other.admit_next(1, ids) == ids[1]


def test_two_stores_compete_for_one_slot_atomically(tmp_path):
    path = tmp_path / 'compete.db'
    first, second = Store(path), Store(path)
    ids = [seed(first) for _ in range(4)]
    for rid in ids:
        first.enqueue(rid)
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda s: s.admit_next(1, ids), [first, second]))
    assert sorted(x for x in results if x is not None) == [ids[0]]
    assert first.queued_runs() == ids[1:]


def test_queue_cancel_is_idempotent_and_requeue_goes_to_tail(tmp_path):
    store = Store(tmp_path / 'cancel.db')
    a, b = seed(store), seed(store)
    store.enqueue(a)
    store.enqueue(b)
    assert store.cancel_queued(a)
    assert not store.cancel_queued(a)
    store.enqueue(a)
    assert store.queued_runs() == [b, a]
    with pytest.raises(ValueError):
        store.enqueue(a)


def test_archive_delete_and_retention_cannot_leave_queued_orphans(tmp_path):
    store = Store(tmp_path / 'delete.db')
    rid = seed(store)
    store.enqueue(rid)
    with pytest.raises(ValueError):
        store.set_archived(rid, True)
    with store.connect() as db:
        db.execute('UPDATE runs SET updated=1 WHERE id=?', (rid,))
    assert store.prune(1) == 0
    store.delete(rid)
    assert store.queued_runs() == []
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM run_revisions').fetchone()[0] == 0


def test_reservations_are_idempotent_bounded_and_durable(tmp_path):
    path = tmp_path / 'budget.db'
    store = Store(path)
    rid = seed(store, maximum=3)
    assert store.claim(rid)
    assert store.reserve_requests(rid, 'one', 2) == 2
    assert Store(path).reserve_requests(rid, 'one', 2) == 2
    with pytest.raises(RunConflict):
        store.reserve_requests(rid, 'one', 1)
    with pytest.raises(RequestBudgetExceeded):
        store.reserve_requests(rid, 'two', 2)
    assert store.reserve_requests(rid, 'three') == 3
    assert store.get(rid)['data']['requests'] == 3
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM request_reservations').fetchone()[0] == 2


def test_concurrent_reservations_do_not_overspend(tmp_path):
    store = Store(tmp_path / 'atomic.db')
    rid = seed(store, maximum=7)
    assert store.claim(rid)
    def reserve(index):
        try:
            store.reserve_requests(rid, str(index))
            return True
        except RequestBudgetExceeded:
            return False
    with ThreadPoolExecutor(4) as pool:
        assert sum(pool.map(reserve, range(24))) == 7
    assert store.get(rid)['data']['requests'] == 7


def test_stale_json_cannot_refund_reserved_requests_and_cas_rolls_back(tmp_path):
    store = Store(tmp_path / 'cas.db')
    rid = seed(store)
    assert store.claim(rid)
    before = store.get(rid)
    store.reserve_requests(rid, 'sent')
    with pytest.raises(RunConflict):
        store.update(rid, before['data'], expected_revision=before['revision'])
    store.update(rid, before['data'])
    assert store.get(rid)['data']['requests'] == 1
    latest = store.get(rid)
    next_revision = store.update(rid, latest['data'], expected_revision=latest['revision'])
    assert store.get(rid)['revision'] == next_revision


@pytest.mark.parametrize('state', ['paused', 'interrupted', 'queued', 'completed'])
def test_new_reservation_requires_running_state(tmp_path, state):
    store = Store(tmp_path / 'state.db')
    rid = seed(store)
    store.update(rid, store.get(rid)['data'], state)
    with pytest.raises(RunConflict):
        store.reserve_requests(rid, 'never-sent')


def test_manager_services_share_admission_and_cancel_sends_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENT_MAX_CONCURRENT_RUNS', '1')
    async def scenario():
        store = Store(tmp_path / 'manager.db')
        gate = asyncio.Event()
        requests = []
        async def planner(ctx):
            await gate.wait()
            return Action(kind='finish', hypothesis='done', basis=[ctx['observations'][-1]['id']])
        manager = AgentManager(store, planner, httpx.MockTransport(
            lambda r: (requests.append(str(r.url)) or httpx.Response(200, text='synthetic'))))
        spec = RunSpec(goal='synthetic', request={'url': 'https://example.test/'})
        a, b, c = [manager.create(spec) for _ in range(3)]
        assert store.get(a)['state'] == 'running'
        assert store.get(b)['state'] == store.get(c)['state'] == 'queued'
        assert manager.snapshot(c)['queue_position'] == 2
        await manager.stop(b)
        assert store.get(b)['state'] == 'paused'
        assert b not in manager.tasks
        gate.set()
        await manager.tasks[a]
        for _ in range(100):
            if c in manager.tasks:
                break
            await asyncio.sleep(.01)
        await manager.tasks[c]
        assert len(requests) == 2
        assert store.get(c)['state'] == 'completed'
        await manager.shutdown()
    asyncio.run(scenario())


def test_restart_preserves_fifo_but_requires_credentials_or_uncertain_session(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENT_MAX_CONCURRENT_RUNS', '1')
    async def scenario():
        store = Store(tmp_path / 'recover.db')
        credentialed = seed(store, needs_credentials=True)
        uncertain = seed(store)
        fresh = seed(store)
        store.event(uncertain, 'request_started', {'request': {'method': 'POST'}})
        for rid in [credentialed, uncertain, fresh]:
            store.enqueue(rid)
        manager = AgentManager(Store(store.path))
        gate = asyncio.Event()
        async def execute(rid):
            await gate.wait()
            store.update(rid, store.get(rid)['data'], 'completed')
        manager._run = execute
        manager.restore_queue()
        assert store.get(credentialed)['state'] == 'paused'
        assert store.get(uncertain)['state'] == 'paused'
        assert store.get(fresh)['state'] == 'running'
        assert fresh in manager.tasks
        gate.set()
        await manager.tasks[fresh]
        await manager.shutdown()
    asyncio.run(scenario())


def test_shutdown_does_not_start_waiting_jobs(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENT_MAX_CONCURRENT_RUNS', '1')
    async def scenario():
        manager = AgentManager(Store(tmp_path / 'shutdown.db'))
        started = []
        async def execute(rid):
            started.append(rid)
            await asyncio.Event().wait()
        manager._run = execute
        spec = RunSpec(goal='synthetic', request={'url': 'https://example.test/'})
        a, b = manager.create(spec), manager.create(spec)
        await asyncio.sleep(0)
        await manager.shutdown()
        assert started == [a]
        assert manager.store.get(b)['state'] == 'queued'
        assert b not in manager.tasks
    asyncio.run(scenario())


def test_runtime_lock_blocks_second_startup_and_releases(tmp_path):
    from core.agent_runtime_lock import RuntimeLock
    first = RuntimeLock(tmp_path / 'one.db')
    second = RuntimeLock(tmp_path / 'one.db')
    first.acquire()
    try:
        with pytest.raises(RuntimeError, match='단일 서버'):
            second.acquire()
    finally:
        first.release()
    second.acquire()
    second.release()


def test_expired_queued_plan_never_sends_its_first_request(tmp_path, monkeypatch):
    import time
    monkeypatch.setenv('AGENT_MAX_CONCURRENT_RUNS', '1')
    async def scenario():
        gate = asyncio.Event()
        urls = []
        async def planner(ctx):
            await gate.wait()
            return Action(kind='finish', hypothesis='done', basis=[ctx['observations'][-1]['id']])
        manager = AgentManager(Store(tmp_path / 'expiry.db'), planner,
            httpx.MockTransport(lambda r: (urls.append(str(r.url)) or httpx.Response(200,text='synthetic'))))
        first = manager.create(RunSpec(goal='synthetic',request={'url':'https://example.test/first'}))
        pinned = RunSpec(goal='synthetic',request={'url':'https://example.test/queued'},
            approved_plan={'entry':'a','steps':[{'action_id':'a','action':{
                'kind':'observe','hypothesis':'synthetic'}}]})
        waiting = manager.create(pinned)
        manager.specs[waiting].approved_plan_expires_at = time.time()-1
        gate.set()
        await manager.tasks[first]
        for _ in range(100):
            if waiting in manager.tasks:break
            await asyncio.sleep(.01)
        await manager.tasks[waiting]
        assert urls == ['https://example.test/first']
        assert manager.store.get(waiting)['state'] == 'paused'
        assert manager.store.get(waiting)['data']['stop_code'] == 'plan_rejected'
        await manager.shutdown()
    asyncio.run(scenario())


def test_revoking_queued_plan_removes_it_before_admission(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENT_MAX_CONCURRENT_RUNS', '1')
    async def scenario():
        manager = AgentManager(Store(tmp_path / 'revoke.db'))
        gate = asyncio.Event()
        executed = []
        async def execute(rid):
            executed.append(rid)
            await gate.wait()
            manager.store.update(rid,manager.store.get(rid)['data'],'completed')
        manager._run=execute
        first=manager.create(RunSpec(goal='synthetic',request={'url':'https://example.test/'}))
        plan={'entry':'a','steps':[{'action_id':'a','action':{'kind':'observe','hypothesis':'synthetic'}}]}
        waiting=manager.create(RunSpec(goal='synthetic',request={'url':'https://example.test/'},approved_plan=plan))
        await asyncio.sleep(0)
        await manager.revoke_plan(waiting,'synthetic cancellation')
        gate.set()
        await manager.tasks[first]
        assert executed == [first]
        assert manager.store.get(waiting)['state']=='paused'
        assert manager.store.get(waiting)['data']['spec']['approved_plan_revoked_at'] is not None
        assert manager.store.queued_runs()==[]
        await manager.shutdown()
    asyncio.run(scenario())


def test_delete_barrier_rejects_readmission_during_cancellation(tmp_path):
    async def scenario():
        manager=AgentManager(Store(tmp_path/'barrier.db'))
        cancelling=asyncio.Event()
        release=asyncio.Event()
        async def execute(rid):
            try:
                await asyncio.Event().wait()
            finally:
                cancelling.set()
                await release.wait()
        manager._run=execute
        rid=manager.create(RunSpec(goal='synthetic',request={'url':'https://example.test/'}))
        await asyncio.sleep(0)
        deletion=asyncio.create_task(manager.delete(rid))
        await cancelling.wait()
        with pytest.raises(ValueError,match='삭제 중'):
            manager.start(rid)
        release.set()
        await deletion
        with pytest.raises(KeyError):manager.store.get(rid)
        assert rid not in manager.specs
        await manager.shutdown()
    asyncio.run(scenario())


def test_stop_before_coroutine_enters_try_releases_slot_without_io(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENT_MAX_CONCURRENT_RUNS','1')
    async def scenario():
        manager=AgentManager(Store(tmp_path/'early-stop.db'),transport=httpx.MockTransport(
            lambda r: pytest.fail('No target request may be sent')))
        rid=manager.create(RunSpec(goal='synthetic',request={'url':'https://example.test/'}))
        await manager.stop(rid)
        assert manager.store.get(rid)['state']=='paused'
        assert manager.store.get(rid)['data']['requests']==0
        await manager.shutdown()
    asyncio.run(scenario())
