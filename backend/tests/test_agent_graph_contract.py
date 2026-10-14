"""탐색 그래프가 의존하는 '실제 링크' 계약을 백엔드 이벤트에 대해 고정한다(리뷰 2026-10-14 F1).

새 라우트는 없다 — 그래프는 스냅샷(run.events)에서 클라이언트가 만든다. 이 테스트는
백엔드 이벤트가 그 링크(step_id·request_id·evidence_ids·plan_branch)를 계속 내보내는지 지킨다.
실제 대상/AI 호출 없이 MockTransport + 모의 planner/계획만 쓴다.
"""
import asyncio

import httpx
import pytest

from core import agent as agent_mod
from core.agent import AgentManager
from core.agent_store import Store
from core.agent_models import RunSpec, Action
from core import plan as plan_mod


def _iter_planner(*actions):
    it = iter(actions)

    async def choose(ctx):
        value = dict(next(it, {'kind': 'finish', 'hypothesis': '종료'}))
        obs = ctx.get('observations') or []
        if obs:
            value.setdefault('basis', [obs[-1]['id']])
        return Action.model_validate(value)
    return choose


def _run(tmp_path, handler, planner, cfg):
    async def go():
        m = AgentManager(Store(tmp_path / 'g.db'), planner, httpx.MockTransport(handler))
        rid = m.create(cfg)
        await m.tasks[rid]
        return m.store.events(rid)
    return asyncio.run(go())


def _assert_links(events):
    req_ids = {e['id'] for e in events if e['kind'] == 'request_started'}
    obs_ids = {e['id'] for e in events if e['kind'] == 'observation'}
    oob_ids = {e['id'] for e in events if e['kind'] == 'oob'}
    for e in events:
        if e['kind'] == 'observation':
            assert e['data']['request_id'] in req_ids, 'observation.request_id → request_started 미연결'
            assert e['id'] == e['data']['id'], 'observation 이벤트 id == data.id'
        if e['kind'] == 'verification':
            assert set(e['data'].get('evidence_ids', [])) <= (obs_ids | oob_ids), 'evidence_ids ⊆ 관측∪OOB'


def test_iterative_event_links(tmp_path):
    cfg = RunSpec.model_validate({'goal': 'g', 'request': {'url': 'https://app.test/?id=1'}})
    events = _run(tmp_path, lambda r: httpx.Response(200, text='<html>ok</html>'),
                  _iter_planner({'kind': 'probe', 'hypothesis': 'h', 'category': 'sqli',
                                 'param': 'id', 'payload': "'"}), cfg)
    _assert_links(events)
    # 한 probe 단계의 action/request/observation/verification 가 같은 비어있지 않은 step_id 를 공유
    steps = {e['step_id'] for e in events if e['kind'] == 'action' and e['data'].get('kind') == 'probe'}
    assert steps and all(steps)
    sid = next(iter(steps))
    kinds = {e['kind'] for e in events if e['step_id'] == sid}
    assert {'action', 'request_started', 'observation', 'verification'} <= kinds


def test_plan_event_links(tmp_path, monkeypatch):
    plan = plan_mod.Plan(entry='p1', steps=[plan_mod.PlanStep(
        action_id='p1',
        action=Action(kind='probe', hypothesis='h', category='sqli', param='id',
                      payload="'", actor_id='current', endpoint_id='seed'),
        branches=[], default_next='')])

    async def gen(spec):
        return plan
    monkeypatch.setattr(agent_mod, 'generate_plan', gen)

    cfg = RunSpec.model_validate({'goal': 'g', 'request': {'url': 'https://app.test/?id=1'}, 'mode': 'plan'})
    events = _run(tmp_path, lambda r: httpx.Response(200, text='ok'), lambda ctx: None, cfg)
    _assert_links(events)

    plan_evs = [e for e in events if e['kind'] == 'plan']
    assert plan_evs and plan_evs[0]['step_id'] == '', 'plan 이벤트 step_id 는 빈 문자열'
    dsl_ids = {s['action_id'] for s in plan_evs[0]['data']['steps']}
    action_steps = {e['step_id'] for e in events if e['kind'] == 'action'}
    branches = [e for e in events if e['kind'] == 'plan_branch']
    assert branches, 'plan 모드는 plan_branch 를 내보낸다'
    for pb in branches:
        assert pb['data']['action_id'] in dsl_ids, 'plan_branch.action_id ∈ plan.steps[].action_id'
        assert pb['step_id'] in action_steps, 'plan_branch.step_id 가 실행된 action 과 매칭'
