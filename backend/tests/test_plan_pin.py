"""승인된 계획 고정 실행 (리뷰 P3). 미리보기에서 승인한 계획을 재생성 없이 그대로 실행하고,
실행 계획이 승인본과 동일함을 fingerprint 로 대조한다. 범위를 벗어난 승인본은 동작 실행 전에
안전 정지한다. 실 HTTP 는 MockTransport, 실제 대상/LLM 은 호출하지 않는다."""
import asyncio

import httpx

from core import agent as agent_mod
from core.agent import AgentManager, pinned_plan
from core.agent_store import Store
from core.agent_models import RunSpec, Action
from core import plan as plan_mod


def _observe_plan(actor_id='current'):
    return plan_mod.Plan(entry='observe', steps=[plan_mod.PlanStep(
        action_id='observe', action=Action(kind='observe', hypothesis='관측', actor_id=actor_id, endpoint_id='seed'))])


def _run_with_approved(tmp_path, approved):
    async def execute():
        m = AgentManager(Store(tmp_path / 'pin.db'),
                         transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
        spec = RunSpec.model_validate({'goal': 't', 'request': {'url': 'https://app.test/?id=1'},
                                       'approved_plan': approved})
        rid = m.create(spec)
        await m.tasks[rid]
        return m.snapshot(rid)
    return asyncio.run(execute())


def test_approved_plan_runs_without_regeneration(tmp_path, monkeypatch):
    async def boom(spec):
        raise AssertionError('승인된 계획은 재생성하면 안 된다')
    monkeypatch.setattr(agent_mod, 'generate_plan', boom)   # 호출되면 즉시 실패
    plan = _observe_plan()
    run = _run_with_approved(tmp_path, plan.model_dump())
    assert run['state'] == 'completed'
    assert run['data']['ai_calls'] == 0                     # 실행은 AI 호출 0 (미리보기에서 이미 생성)
    plan_evt = [e for e in run['events'] if e['kind'] == 'plan'][0]
    assert plan_evt['data']['pinned'] is True
    assert plan_evt['data']['fingerprint'] == plan_mod.plan_fingerprint(plan)   # 실행 == 승인본
    assert run['data']['spec']['mode'] == 'plan'            # approved_plan → plan 모드 자동


def test_out_of_scope_approved_plan_safe_stops(tmp_path):
    # 알 수 없는 계정을 참조하는 승인본 → 실행 전 거부(안전 정지), 어떤 동작도 실행하지 않는다.
    run = _run_with_approved(tmp_path, _observe_plan(actor_id='ghost').model_dump())
    assert run['state'] == 'paused'
    assert run['data']['stop_code'] == 'plan_rejected'
    assert not [e for e in run['events'] if e['kind'] == 'action']
    assert any(e['kind'] == 'plan_rejected' for e in run['events'])
    assert run['conclusion']['completion'] == 'partial'
    assert run['events'][-1]['kind'] == 'conclusion'


def test_malformed_approved_plan_safe_stops(tmp_path):
    run = _run_with_approved(tmp_path, {'entry': 'x', 'steps': []})   # 스키마 위반(steps 비었음)
    assert run['state'] == 'paused' and run['data']['stop_code'] == 'plan_rejected'
    assert not [e for e in run['events'] if e['kind'] == 'action']


def test_approved_plan_persists_in_spec_for_restart(tmp_path):
    plan = _observe_plan()
    stored = _run_with_approved(tmp_path, plan.model_dump())['data']['spec']
    assert stored['approved_plan'] is not None and stored['mode'] == 'plan'
    rebuilt = RunSpec.model_validate(stored)                # 재시작 경로의 spec 재구성
    assert plan_mod.plan_fingerprint(pinned_plan(rebuilt)) == plan_mod.plan_fingerprint(plan)


def test_plan_fingerprint_is_stable():
    assert plan_mod.plan_fingerprint(_observe_plan()) == plan_mod.plan_fingerprint(_observe_plan())
    assert len(plan_mod.plan_fingerprint(_observe_plan())) == 16


def test_approved_plan_forces_plan_mode_even_if_iterative_requested():
    spec = RunSpec.model_validate({'goal': 't', 'request': {'url': 'https://app.test/'},
                                   'mode': 'iterative', 'approved_plan': _observe_plan().model_dump()})
    assert spec.mode == 'plan'
