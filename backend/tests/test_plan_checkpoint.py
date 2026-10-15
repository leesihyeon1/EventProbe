"""A restarted plan resumes from durable branches without replaying uncertain steps."""
import asyncio

import httpx

from core.agent import AgentManager
from core.agent_models import RunSpec
from core.agent_store import Store
from core import plan as plan_mod


def _plan():
    return plan_mod.Plan.model_validate({
        'entry': 'first', 'steps': [
            {'action_id': 'first', 'action': {'kind': 'observe', 'hypothesis': 'first'},
             'default_next': 'second'},
            {'action_id': 'second', 'action': {'kind': 'observe', 'hypothesis': 'second'},
             'default_next': ''},
        ],
    })


def _interrupted(manager, branched, fingerprint_override=None):
    plan = _plan()
    spec = RunSpec.model_validate({'goal': 'synthetic',
                                   'request': {'url': 'https://app.test/'},
                                   'approved_plan': plan.model_dump()})
    data = {'spec': spec.model_dump(), 'requests': 1, 'ai_calls': 0, 'steps': 1,
            'elapsed': 0, 'seen': [], 'needs_credentials': False,
            'endpoints': {'seed': spec.request.model_dump()}, 'reason': ''}
    rid = manager.store.create(data)
    manager.store.event(rid, 'plan', {**plan.model_dump(),
                                     'fingerprint': fingerprint_override or plan_mod.plan_fingerprint(plan),
                                     'pinned': True})
    manager.store.event(rid, 'action', plan.steps[0].action.model_dump(), 'step-one')
    if branched:
        manager.store.event(rid, 'plan_branch',
                            {'action_id': 'first', 'verdict': 'observed', 'next': 'second'}, 'step-one')
    return rid


def test_restart_continues_at_next_step(tmp_path):
    async def run():
        requests = []
        def reply(request):
            requests.append(str(request.url))
            return httpx.Response(200, text='ok')
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        rid = _interrupted(manager, branched=True)
        manager.start(rid)
        await manager.tasks[rid]
        return manager.snapshot(rid), requests

    result, requests = asyncio.run(run())
    assert result['state'] == 'completed'
    assert len(requests) == 1
    assert result['data']['requests'] == 2
    assert result['data']['plan_checkpoint']['phase'] == 'done'
    assert sum(e['kind'] == 'plan' for e in result['events']) == 1


def test_restart_blocks_unfinished_step(tmp_path):
    async def run():
        requests = []
        def reply(request):
            requests.append(str(request.url))
            return httpx.Response(200, text='ok')
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        rid = _interrupted(manager, branched=False)
        manager.start(rid)
        await manager.tasks[rid]
        return manager.snapshot(rid), requests

    result, requests = asyncio.run(run())
    assert result['state'] == 'paused'
    assert result['data']['stop_code'] == 'plan_step_uncertain'
    assert result['tool_summary']['http_unresolved'] == 1
    assert requests == []
    assert any(e['kind'] == 'plan_resume_blocked' for e in result['events'])


def test_restart_rejects_changed_plan_fingerprint(tmp_path):
    async def run():
        requests = []
        def reply(request):
            requests.append(request)
            return httpx.Response(200, text='ok')
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        rid = _interrupted(manager, branched=True, fingerprint_override='invalid')
        manager.start(rid)
        await manager.tasks[rid]
        return manager.snapshot(rid), requests

    result, requests = asyncio.run(run())
    assert result['state'] == 'paused'
    assert '지문' in result['data']['reason']
    assert requests == []


def test_human_skip_of_uncertain_step_does_not_replay_it(tmp_path):
    async def run():
        requests = []
        def reply(request):
            requests.append(request)
            return httpx.Response(200, text='ok')
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        rid = _interrupted(manager, branched=False)
        manager.store.event(rid, 'request_started',
                            {'request': {'url': 'https://app.test/', 'method': 'POST'}}, 'step-one')
        paused = manager.skip_plan_step(rid, '첫 단계의 처리 결과를 알 수 없어 건너뜀')
        assert paused['state'] == 'paused'
        assert requests == []
        manager.start(rid)  # The skipped write is never resent, so no write acknowledgement is needed.
        await manager.tasks[rid]
        return manager.snapshot(rid), requests

    result, requests = asyncio.run(run())
    assert result['state'] == 'completed'
    assert len(requests) == 1  # Only the second observe step runs.
    skip = next(e for e in result['events'] if e['kind'] == 'plan_skip')
    assert skip['data']['action_id'] == 'first'
    assert skip['data']['pending_action'] is True
    assert result['data']['plan_checkpoint']['phase'] == 'done'


def test_human_skip_of_next_queued_step_finishes_plan(tmp_path):
    async def run():
        requests = []
        def reply(request):
            requests.append(request)
            return httpx.Response(200, text='ok')
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        rid = _interrupted(manager, branched=True)
        manager.skip_plan_step(rid, '두 번째 관측은 필요하지 않음')
        manager.start(rid)
        await manager.tasks[rid]
        return manager.snapshot(rid), requests

    result, requests = asyncio.run(run())
    assert result['state'] == 'completed'
    assert requests == []
    assert sum(e['kind'] == 'plan_skip' for e in result['events']) == 1


def test_restart_uses_latest_legacy_plan_segment(tmp_path):
    async def run():
        requests = []
        def reply(request):
            requests.append(request)
            return httpx.Response(200, text='ok')
        manager = AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))
        rid = _interrupted(manager, branched=True)
        # Older versions generated a new plan on resume; only the newest segment
        # determines the next action for a subsequent restart.
        plan = _plan()
        manager.store.event(rid, 'plan', {**plan.model_dump(),
                                          'fingerprint': plan_mod.plan_fingerprint(plan), 'pinned': True})
        manager.start(rid)
        await manager.tasks[rid]
        return manager.snapshot(rid), requests

    result, requests = asyncio.run(run())
    assert result['state'] == 'completed'
    assert len(requests) == 2


def test_process_restart_recovery_uses_persisted_branch_without_replay(tmp_path):
    async def run():
        path = tmp_path / 'recovered.db'
        before = AgentManager(Store(path))
        rid = _interrupted(before, branched=True)
        assert before.store.claim(rid)

        # Startup in a new process marks the abandoned running row interrupted.
        recovered_store = Store(path)
        recovered_store.recover()
        assert recovered_store.get(rid)['state'] == 'interrupted'
        requests = []

        def reply(request):
            requests.append(str(request.url))
            return httpx.Response(200, text='ok')

        after = AgentManager(recovered_store, transport=httpx.MockTransport(reply))
        after.start(rid)
        await after.tasks[rid]
        return after.snapshot(rid), requests

    result, requests = asyncio.run(run())
    assert result['state'] == 'completed'
    assert len(requests) == 1
    assert result['data']['requests'] == 2
