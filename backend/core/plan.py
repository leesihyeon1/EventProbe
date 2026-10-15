"""조건부 검증 계획 DSL + 로컬 분기 엔진 (리뷰 Stage 3 / 전체 F4).

반복 planner 는 매 단계 응답을 외부 모델에 되먹였다. 요구사항(응답 비반출)과 충돌하므로,
외부 모델은 '첫 관측 이전'에 조건부 JSON 계획을 한 번 생성하고, 실행 중의 분기는 전적으로
로컬에서 처리한다:

  - 계획 = action_id 로 식별되는 단계들의 그래프. 각 단계는 실행할 동작과, 로컬 판정 결과에
    따라 다음 action_id 를 고르는 분기(열거된 predicate)를 가진다.
  - predicate 는 '열거된 종류'만 허용한다. 모델이 돌려준 임의 코드/표현식을 eval 하거나
    셸에서 실행하지 않는다(리뷰).
  - 분기 평가 입력(StepResult)은 로컬 엔진(analyzer/confirm)이 만든 판정·상태·신호다.
    외부 모델로 되돌아가는 경로가 없다.
  - 막다른 상황(어느 분기도 안 맞고 기본 분기도 없음)은 '미확정'으로 멈춘다 — 결과 없음을
    안전으로 취급하지 않는다(리뷰).

이 모듈은 순수하다(네트워크·AI 없음). 실제 실행은 run_plan 에 execute 콜백으로 주입한다.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.agent_models import Action

# 로컬 판정 어휘(기존 엔진 status 와 정렬) — predicate 가 참조할 수 있는 값.
VERDICTS = ("confirmed", "suspicious", "inconclusive", "observed", "pending", "safe", "error")

_ID = r"^[a-zA-Z0-9_-]{1,40}$"
STOP = ""   # next 가 빈 문자열이면 계획 종료


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Predicate(_Contract):
    """로컬 결과에 대한 열거형 조건. 임의 표현식이 아니다."""
    kind: Literal["verdict_in", "status_in", "signal_present", "always"]
    verdicts: list[str] = Field(default_factory=list, max_length=8)
    statuses: list[int] = Field(default_factory=list, max_length=16)
    signal: str = Field(default="", max_length=80)

    @model_validator(mode="after")
    def _check(self):
        if self.kind == "verdict_in":
            bad = [v for v in self.verdicts if v not in VERDICTS]
            if not self.verdicts or bad:
                raise ValueError(f"verdict_in 의 verdicts 가 비었거나 알 수 없는 값: {bad or '[]'}")
        elif self.kind == "status_in" and not self.statuses:
            raise ValueError("status_in 은 statuses 가 필요합니다.")
        elif self.kind == "signal_present" and not self.signal.strip():
            raise ValueError("signal_present 는 signal 이 필요합니다.")
        return self


class Branch(_Contract):
    """predicate 가 참이면 next(action_id 또는 STOP)로 이동."""
    predicate: Predicate
    next: str = Field(default=STOP, max_length=40)


class PlanStep(_Contract):
    action_id: str = Field(pattern=_ID)
    action: Action
    requires_approval: bool = False
    branches: list[Branch] = Field(default_factory=list, max_length=8)
    default_next: str = Field(default=STOP, max_length=40)   # 어느 분기도 안 맞을 때


class Plan(_Contract):
    entry: str = Field(pattern=_ID)
    steps: list[PlanStep] = Field(min_length=1, max_length=40)
    max_hops: int = Field(default=16, ge=1, le=100)

    @model_validator(mode="after")
    def _check_refs(self):
        ids = [s.action_id for s in self.steps]
        if len(set(ids)) != len(ids):
            raise ValueError("action_id 가 중복됩니다.")
        idset = set(ids)
        if self.entry not in idset:
            raise ValueError("entry 가 존재하지 않는 action_id 입니다.")
        for step in self.steps:
            targets = [b.next for b in step.branches] + [step.default_next]
            for t in targets:
                if t != STOP and t not in idset:
                    raise ValueError(f"'{step.action_id}' 가 알 수 없는 action_id '{t}' 로 분기합니다.")
        return self

    def by_id(self) -> dict:
        return {s.action_id: s for s in self.steps}


def plan_fingerprint(plan: Plan) -> str:
    """승인된 계획을 실행에 '고정'하기 위한 안정적 지문. 미리보기와 실제 실행이 같은 계획인지
    로컬에서 대조하는 감사 용도이며, 외부로 나가지 않는다(리뷰 P3: 승인본 버전/해시 고정)."""
    payload = plan.model_dump()
    for step in payload['steps']:
        if not step['requires_approval']:
            del step['requires_approval']  # preserve fingerprints of older stored plans
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclass
class StepResult:
    """한 단계 실행 결과(로컬 엔진이 만든 판정). 외부 모델 산출이 아니다."""
    verdict: str = "inconclusive"
    status_code: int = 0
    signals: list = field(default_factory=list)   # finding 이름/라벨


def evaluate_predicate(pred: Predicate, result: StepResult) -> bool:
    if pred.kind == "always":
        return True
    if pred.kind == "verdict_in":
        return result.verdict in set(pred.verdicts)
    if pred.kind == "status_in":
        return result.status_code in set(pred.statuses)
    if pred.kind == "signal_present":
        return pred.signal in set(result.signals or [])
    return False


def select_next(step: PlanStep, result: StepResult) -> str:
    """첫 번째로 참이 되는 분기의 next. 없으면 default_next. (STOP 이면 종료)"""
    for branch in step.branches:
        if evaluate_predicate(branch.predicate, result):
            return branch.next
    return step.default_next


def validate_plan(plan: Plan, allowed_categories: Optional[set] = None,
                  known_actor_ids: Optional[set] = None,
                  known_endpoint_ids: Optional[set] = None) -> list:
    """계획을 실행 범위에 비춰 검증한다(스키마는 Pydantic 이 이미 보장). 위반 목록 반환(빈=OK).
    범위 밖 카테고리·알 수 없는 actor/endpoint ID 를 걸러 '허용되지 않은 계획'을 거부한다(리뷰)."""
    errors: list = []
    for step in plan.steps:
        a = step.action
        if allowed_categories is not None and a.category and a.category not in allowed_categories:
            errors.append(f"{step.action_id}: 허용되지 않은 공격 유형 '{a.category}'")
        if known_actor_ids is not None and a.actor_id and a.actor_id not in known_actor_ids:
            errors.append(f"{step.action_id}: 알 수 없는 계정 '{a.actor_id}'")
        if known_endpoint_ids is not None and a.endpoint_id and a.endpoint_id not in known_endpoint_ids:
            errors.append(f"{step.action_id}: 알 수 없는 엔드포인트 '{a.endpoint_id}'")
    return errors


def run_plan(plan: Plan, execute: Callable[[Action], StepResult]) -> dict:
    """로컬 분기 실행. execute 가 한 동작을 실제로 수행하고 로컬 판정(StepResult)을 돌려준다.
    응답/판정은 execute 안(사내)에서만 쓰이고 외부로 나가지 않는다.

    반환: {trace, outcome, stopped}.
      - trace: [{action_id, verdict, status_code, next}]
      - outcome: 관측된 판정 중 가장 강한 것(confirmed>suspicious>그외) — 결과 없음은 'inconclusive'
      - stopped: 'finish'|'budget'|'dead_end'|'loop'
    """
    steps = plan.by_id()
    current = plan.entry
    trace: list = []
    visited: set = set()
    rank = {"confirmed": 3, "suspicious": 2}
    best, best_rank = "inconclusive", 0
    stopped = "finish"
    for _ in range(plan.max_hops):
        if current == STOP:
            stopped = "finish"
            break
        step = steps[current]
        result = execute(step.action)
        r = rank.get(result.verdict, 0)
        if r > best_rank:
            best, best_rank = result.verdict, r
        nxt = select_next(step, result)
        trace.append({"action_id": current, "verdict": result.verdict,
                      "status_code": result.status_code, "next": nxt})
        visited.add(current)
        if nxt == STOP:
            stopped = "dead_end" if not step.branches and step.default_next == STOP else "finish"
            # 분기가 하나라도 있었는데 아무것도 안 맞아 STOP 이면 막다른 상황(미확정)로 본다.
            if step.branches and not any(evaluate_predicate(b.predicate, result) for b in step.branches) \
                    and step.default_next == STOP:
                stopped = "dead_end"
            break
        if nxt in visited:
            stopped = "loop"
            break
        current = nxt
    else:
        stopped = "budget"
    return {"trace": trace, "outcome": best, "stopped": stopped}
