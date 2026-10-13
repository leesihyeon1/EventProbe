"""조건부 계획 DSL + 로컬 분기 엔진 (리뷰 Stage 3 / 전체 F4).

외부 모델 없이, 로컬 판정(StepResult)만으로 다음 action 을 고르고 종료 조건을 지키는지 검증한다.
"""
import pytest
from pydantic import ValidationError

from core.agent_models import Action
from core.plan import (Plan, PlanStep, Branch, Predicate, StepResult,
                       evaluate_predicate, select_next, validate_plan, run_plan)


def _act(kind="probe", **kw):
    base = dict(hypothesis="h", category="sqli", param="id", payload="'", actor_id="current")
    base.update(kw)
    return Action(kind=kind, **base)


def _step(aid, branches=(), default_next="", **akw):
    return PlanStep(action_id=aid, action=_act(**akw), branches=list(branches), default_next=default_next)


# ── Predicate 검증/평가 ─────────────────────────────────────────────────────────
def test_predicate_validation():
    with pytest.raises(ValidationError):
        Predicate(kind="verdict_in", verdicts=[])
    with pytest.raises(ValidationError):
        Predicate(kind="verdict_in", verdicts=["bogus"])
    with pytest.raises(ValidationError):
        Predicate(kind="status_in", statuses=[])
    with pytest.raises(ValidationError):
        Predicate(kind="signal_present", signal="")
    Predicate(kind="always")   # OK


def test_evaluate_predicate():
    r = StepResult(verdict="suspicious", status_code=500, signals=["sql_error"])
    assert evaluate_predicate(Predicate(kind="always"), r)
    assert evaluate_predicate(Predicate(kind="verdict_in", verdicts=["suspicious", "confirmed"]), r)
    assert not evaluate_predicate(Predicate(kind="verdict_in", verdicts=["safe"]), r)
    assert evaluate_predicate(Predicate(kind="status_in", statuses=[500, 503]), r)
    assert not evaluate_predicate(Predicate(kind="status_in", statuses=[200]), r)
    assert evaluate_predicate(Predicate(kind="signal_present", signal="sql_error"), r)
    assert not evaluate_predicate(Predicate(kind="signal_present", signal="xss"), r)


def test_select_next_first_match_then_default():
    step = _step("a1", branches=[
        Branch(predicate=Predicate(kind="verdict_in", verdicts=["confirmed"]), next="win"),
        Branch(predicate=Predicate(kind="verdict_in", verdicts=["suspicious"]), next="more"),
    ], default_next="end")
    assert select_next(step, StepResult(verdict="confirmed")) == "win"
    assert select_next(step, StepResult(verdict="suspicious")) == "more"
    assert select_next(step, StepResult(verdict="safe")) == "end"   # 기본 분기


# ── Plan 참조 무결성 ────────────────────────────────────────────────────────────
def test_plan_requires_valid_entry_and_refs():
    with pytest.raises(ValidationError):   # entry 없음
        Plan(entry="x", steps=[_step("a1")])
    with pytest.raises(ValidationError):   # 중복 id
        Plan(entry="a1", steps=[_step("a1"), _step("a1")])
    with pytest.raises(ValidationError):   # 알 수 없는 next
        Plan(entry="a1", steps=[_step("a1", default_next="ghost")])
    Plan(entry="a1", steps=[_step("a1", default_next="")])   # OK(STOP)


# ── validate_plan: 범위/ID ─────────────────────────────────────────────────────
def test_validate_plan_scope():
    plan = Plan(entry="a1", steps=[
        _step("a1", category="ssrf", actor_id="attacker", endpoint_id="seed")])
    errs = validate_plan(plan, allowed_categories={"sqli", "xss"},
                         known_actor_ids={"current"}, known_endpoint_ids={"seed"})
    assert any("허용되지 않은 공격 유형" in e for e in errs)
    assert any("알 수 없는 계정" in e for e in errs)
    # 범위 안이면 위반 없음
    ok = Plan(entry="a1", steps=[_step("a1", category="sqli", actor_id="current", endpoint_id="seed")])
    assert validate_plan(ok, allowed_categories={"sqli"}, known_actor_ids={"current"},
                         known_endpoint_ids={"seed"}) == []


# ── run_plan: 로컬 분기 실행 ────────────────────────────────────────────────────
def _runner(script):
    """action_id 가 아니라 호출 순서대로 스크립트된 StepResult 를 돌려주는 execute."""
    it = iter(script)
    seq = []

    def execute(action):
        seq.append(action)
        return next(it)
    execute.seq = seq
    return execute


def test_run_plan_confirms_then_stops():
    plan = Plan(entry="probe", steps=[
        _step("probe", branches=[Branch(predicate=Predicate(kind="verdict_in", verdicts=["suspicious"]), next="confirm")],
              default_next=""),
        _step("confirm", kind="confirm", branches=[
            Branch(predicate=Predicate(kind="verdict_in", verdicts=["confirmed"]), next="")]),
    ])
    out = run_plan(plan, _runner([StepResult(verdict="suspicious"), StepResult(verdict="confirmed")]))
    assert [t["action_id"] for t in out["trace"]] == ["probe", "confirm"]
    assert out["outcome"] == "confirmed" and out["stopped"] == "finish"


def test_run_plan_dead_end_is_inconclusive():
    plan = Plan(entry="probe", steps=[
        _step("probe", branches=[Branch(predicate=Predicate(kind="verdict_in", verdicts=["confirmed"]), next="")],
              default_next="")])
    out = run_plan(plan, _runner([StepResult(verdict="safe")]))
    assert out["outcome"] == "inconclusive" and out["stopped"] == "dead_end"


def test_run_plan_loop_guard():
    plan = Plan(entry="a1", steps=[
        _step("a1", branches=[Branch(predicate=Predicate(kind="always"), next="a2")]),
        _step("a2", branches=[Branch(predicate=Predicate(kind="always"), next="a1")]),
    ])
    out = run_plan(plan, _runner([StepResult(verdict="inconclusive"), StepResult(verdict="inconclusive")]))
    assert out["stopped"] == "loop"


def test_run_plan_budget_cap():
    plan = Plan(entry="a1", max_hops=1, steps=[
        _step("a1", branches=[Branch(predicate=Predicate(kind="always"), next="a2")]),
        _step("a2", branches=[Branch(predicate=Predicate(kind="always"), next="")]),
    ])
    out = run_plan(plan, _runner([StepResult(verdict="inconclusive"), StepResult(verdict="inconclusive")]))
    assert out["stopped"] == "budget"
    assert len(out["trace"]) == 1   # max_hops=1 → 한 단계만


def test_run_plan_outcome_keeps_strongest():
    plan = Plan(entry="a1", steps=[
        _step("a1", branches=[Branch(predicate=Predicate(kind="always"), next="a2")]),
        _step("a2", branches=[Branch(predicate=Predicate(kind="always"), next="")]),
    ])
    # 첫 단계 confirmed, 둘째 safe → 최종 outcome 은 가장 강한 confirmed
    out = run_plan(plan, _runner([StepResult(verdict="confirmed"), StepResult(verdict="safe")]))
    assert out["outcome"] == "confirmed"
