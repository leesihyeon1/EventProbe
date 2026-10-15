"""A flagged plan step waits for a local decision before target I/O."""

import asyncio

import httpx
import pytest

from core.agent import AgentManager
from core.agent_models import RunSpec
from core.agent_store import Store


PLAN = {'entry': 'observe', 'steps': [{
    'action_id': 'observe', 'requires_approval': True,
    'action': {'kind': 'observe', 'hypothesis': 'local review test'}}]}


def test_step_approval_waits_without_io_and_requires_separate_resume(tmp_path):
    async def run():
        sent = []

        def reply(request):
            sent.append(request)
            return httpx.Response(200, text='synthetic')

        manager = AgentManager(Store(tmp_path / 'review.sqlite3'),
                               transport=httpx.MockTransport(reply))
        spec = RunSpec.model_validate({'goal': 'reviewed synthetic plan',
                                       'request': {'url': 'https://example.test/'},
                                       'approved_plan': PLAN})
        rid = manager.create(spec)
        await manager.tasks[rid]
        paused = manager.snapshot(rid)
        assert paused['state'] == 'paused'
        assert paused['data']['plan_checkpoint']['phase'] == 'approval_required'
        assert sent == []
        assert len([e for e in paused['events'] if e['kind'] == 'plan_step_approval_requested']) == 1
        with pytest.raises(ValueError, match='검토 결정'):
            manager.start(rid)
        reviewed = manager.review_plan_step(rid, True, '허용 범위 확인', 'declared-reviewer')
        assert reviewed['state'] == 'paused' and sent == []
        approval = next(e for e in reviewed['events'] if e['kind'] == 'plan_step_approval')
        assert approval['data']['declared_actor'] == 'declared-reviewer'
        assert approval['data']['identity_assurance'] == 'self_declared'
        manager.start(rid)
        await manager.tasks[rid]
        final = manager.snapshot(rid)
        assert len(sent) == 1 and final['state'] == 'completed'
        assert len([e for e in final['events'] if e['kind'] == 'action']) == 1

    asyncio.run(run())


def test_step_denial_is_final_for_that_run(tmp_path):
    async def run():
        sent = []

        def reply(request):
            sent.append(request)
            return httpx.Response(200)

        manager = AgentManager(Store(tmp_path / 'deny.sqlite3'),
                               transport=httpx.MockTransport(reply))
        rid = manager.create(RunSpec.model_validate({
            'goal': 'deny synthetic plan', 'request': {'url': 'https://example.test/'},
            'approved_plan': PLAN}))
        await manager.tasks[rid]
        denied = manager.review_plan_step(rid, False, '추가 검사 제외', 'reviewer')
        assert denied['data']['plan_checkpoint']['phase'] == 'denied'
        assert len([e for e in denied['events'] if e['kind'] == 'plan_step_denied']) == 1
        with pytest.raises(ValueError, match='거절된 계획 단계'):
            manager.start(rid)
        with pytest.raises(ValueError, match='거절된 계획 단계'):
            manager.skip_plan_step(rid, '건너뛰기 시도')
        assert sent == []

    asyncio.run(run())
