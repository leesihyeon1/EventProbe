"""응답-블라인드 계획 실행(로컬 분기) — AgentManager plan 모드 (리뷰 Stage 3 s3).

계획을 1회 생성한 뒤, 실행 중 분기는 로컬 select_next 만으로 처리하고 응답은 외부로
보내지 않는다. 실 HTTP 는 MockTransport, 판정은 probe_verdict 를 모의해 분기 제어만 검증한다.
"""
import asyncio

import httpx
import pytest

from core import agent as agent_mod
from core.agent import AgentManager
from core.agent_store import Store
from core.agent_models import RunSpec, Action
from core import plan as plan_mod


def _two_step_plan():
    def probe(aid, payload):
        return plan_mod.PlanStep(
            action_id=aid,
            action=Action(kind='probe', hypothesis='h', category='sqli',
                          location='param', param='id', payload=payload, actor_id='current', endpoint_id='seed'),
            branches=[plan_mod.Branch(
                predicate=plan_mod.Predicate(kind='verdict_in', verdicts=['suspicious', 'confirmed']),
                next='p2' if aid == 'p1' else '')],
            default_next='')
    return plan_mod.Plan(entry='p1', max_hops=8, steps=[probe('p1', "'"), probe('p2', "' OR 1=1")])


def _run_plan_mode(tmp_path, monkeypatch, verdict_statuses):
    statuses = iter(verdict_statuses)
    monkeypatch.setattr(agent_mod, 'probe_verdict',
                        lambda *a, **k: {'status': next(statuses), 'confirmed': [], 'evidence_ids': [], 'limitations': []})

    async def gen(spec):
        return _two_step_plan()
    monkeypatch.setattr(agent_mod, 'generate_plan', gen)

    async def execute():
        m = AgentManager(Store(tmp_path / 'a.db'), planner=lambda c: None,
                         transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
        spec = RunSpec.model_validate({'goal': 't', 'request': {'url': 'https://app.test/?id=1'}, 'mode': 'plan'})
        rid = m.create(spec)
        await m.tasks[rid]
        return m.snapshot(rid)
    return asyncio.run(execute())


def test_plan_mode_branches_and_confirms(tmp_path, monkeypatch):
    run = _run_plan_mode(tmp_path, monkeypatch, ['suspicious', 'confirmed'])
    kinds = [e['kind'] for e in run['events']]
    assert 'plan' in kinds                         # 계획 1회 생성
    assert kinds.count('action') == 2              # p1 → p2 로 분기해 2단계 실행
    assert kinds.count('verification') == 2
    assert run['state'] == 'completed'
    pr = [e for e in run['events'] if e['kind'] == 'plan_result'][0]
    assert pr['data']['outcome'] == 'confirmed'    # 관측된 최강 판정


def test_plan_mode_stops_when_no_branch_matches(tmp_path, monkeypatch):
    # p1 이 'safe' → 어느 분기도 안 맞고 default STOP → 한 단계만 실행하고 멈춘다(미확정).
    run = _run_plan_mode(tmp_path, monkeypatch, ['safe'])
    kinds = [e['kind'] for e in run['events']]
    assert kinds.count('action') == 1
    pr = [e for e in run['events'] if e['kind'] == 'plan_result'][0]
    assert pr['data']['outcome'] == 'inconclusive'


def test_plan_mode_does_not_use_iterative_planner(tmp_path, monkeypatch):
    # plan 모드에서는 self.planner(반복 planner)가 호출되지 않아야 한다.
    calls = {'n': 0}

    async def boom(ctx):
        calls['n'] += 1
        raise AssertionError('plan 모드에서 반복 planner 를 부르면 안 된다')

    statuses = iter(['safe'])
    monkeypatch.setattr(agent_mod, 'probe_verdict',
                        lambda *a, **k: {'status': next(statuses), 'confirmed': [], 'evidence_ids': [], 'limitations': []})

    async def gen(spec):
        return _two_step_plan()
    monkeypatch.setattr(agent_mod, 'generate_plan', gen)

    async def execute():
        m = AgentManager(Store(tmp_path / 'a.db'), planner=boom,
                         transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
        spec = RunSpec.model_validate({'goal': 't', 'request': {'url': 'https://app.test/?id=1'}, 'mode': 'plan'})
        rid = m.create(spec)
        await m.tasks[rid]
        return m.snapshot(rid)
    run = asyncio.run(execute())
    assert calls['n'] == 0
    assert run['state'] == 'completed'
