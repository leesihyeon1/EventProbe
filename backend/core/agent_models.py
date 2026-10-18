"""Validated contracts for a bounded, HTTP context-aware test agent."""
import time
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, model_validator, ConfigDict
from core.agent_intent import requested_categories


def origin(url: str) -> tuple:
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('HTTP(S) URL만 지원하며 URL 안의 인증정보는 허용하지 않습니다.')
    return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80)


class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid')


class AgentRequest(Contract):
    method: Literal['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'] = 'GET'
    url: str = Field(max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default='', max_length=100000)


class Actor(Contract):
    id: str = Field(pattern=r'^[a-zA-Z0-9_-]{1,32}$')
    label: str = Field(default='', max_length=100)
    headers: dict[str, str] = Field(default_factory=dict)


class ObjectPolicy(Contract):
    id: str = Field(pattern=r'^[a-zA-Z0-9_-]{1,32}$')
    url: str = Field(max_length=4096)
    owner_actor: str
    allowed_actors: list[str] = Field(default_factory=list, max_length=8)
    identity_pointer: str = Field(pattern=r'^/', max_length=200)
    identity_value: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=500)


class VerificationGoal(Contract):
    """A local completion condition; goal text is never added to model context."""
    id: str = Field(pattern=r'^[a-zA-Z0-9_-]{1,32}$')
    title: str = Field(min_length=1, max_length=200)
    category: Literal['sqli', 'auth', 'xss', 'ssti', 'lfi', 'ssrf', 'cmdi', 'redirect', 'nosql', 'access']
    completion: Literal['tested', 'confirmed'] = 'tested'
    endpoint_id: str = Field(default='', max_length=40)
    actor_id: str = Field(default='', max_length=32)


class IncidentEvent(Contract):
    """A manually-ingested SIEM/SOAR event (리뷰 P2/N4). The source body — title/summary —
    stays local and is never added to model context; only the request skeleton drives a
    fixed re-verification run. 사건 입력은 제품 연동 전 수동 JSON/파일 계약이다."""
    source: str = Field(min_length=1, max_length=80)          # 'siem' | 'soar' | 'manual' | ...
    external_id: str = Field(default='', max_length=120)      # the source system's own event id
    observed_at: float | None = None                         # field observation time (epoch seconds)
    asset_id: str = Field(default='', max_length=120)         # common asset correlation id
    traffic_id: str = Field(default='', max_length=120)       # request/flow correlation id
    category: Literal['sqli', 'auth', 'xss', 'ssti', 'lfi', 'ssrf', 'cmdi', 'redirect', 'nosql', 'access']
    title: str = Field(min_length=1, max_length=200)          # local-only description
    summary: str = Field(default='', max_length=2000)         # local-only description
    request: AgentRequest | None = None                      # optional skeleton to re-verify
    location: Literal['param', 'body', 'header'] = 'param'    # where the attacked input is
    param: str = Field(default='', max_length=120)            # which field; '' → derive from request

    @model_validator(mode='after')
    def check_time(self):
        # 과거 증거를 새 확증으로 오인하지 않기 위해 사건 '관측 시각' 은 입력만 받고 판정 근거로 쓰지
        # 않는다. 미래/음수 시각은 잘못된 입력이므로 거부한다.
        if self.observed_at is not None and (self.observed_at < 0 or self.observed_at > time.time() + 60):
            raise ValueError('관측 시각(observed_at)이 유효하지 않습니다(미래 시각 불가).')
        return self


class RunSpec(Contract):
    goal: str = Field(min_length=1, max_length=2000)
    goals: list[VerificationGoal] = Field(default_factory=list, max_length=20)
    request: AgentRequest
    protected_marker: str = Field(default='', max_length=200)
    target_scope: Literal['request_only', 'same_origin'] = 'same_origin'
    actors: list[Actor] = Field(default_factory=lambda: [Actor(id='current')], min_length=1, max_length=8)
    objects: list[ObjectPolicy] = Field(default_factory=list, max_length=20)
    max_steps: int = Field(default=8, ge=1, le=50)
    max_requests: int = Field(default=24, ge=1, le=150)
    max_ai_calls: int = Field(default=8, ge=0, le=50)
    max_seconds: int = Field(default=300, ge=10, le=1800)
    timeout: int = Field(default=15, ge=1, le=60)
    allow_write_methods: bool = False
    policy_version: int = Field(default=1, ge=1, le=1000000)
    allowed_path_prefixes: list[str] = Field(default_factory=list, max_length=40)
    denied_path_prefixes: list[str] = Field(default_factory=list, max_length=40)
    allowed_methods: list[Literal['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']] = Field(default_factory=list, max_length=6)
    allowed_categories: list[Literal['sqli', 'auth', 'xss', 'ssti', 'lfi', 'ssrf', 'cmdi', 'redirect', 'nosql']] = Field(default_factory=list, max_length=9)
    share_response_context: bool = False
    # 'iterative'(기본): 매 단계 planner 호출(응답 되먹임). 'plan': 응답-블라인드 — 비식별 입력으로
    # 계획을 1회 생성하고 실행 중 분기는 로컬에서 처리(리뷰 Stage 3).
    mode: Literal['iterative', 'plan'] = 'iterative'
    # 사용자가 미리보기에서 승인한 계획을 실행에 고정한다(리뷰 P3). 있으면 plan 모드에서 이
    # 계획을 재생성 없이 그대로 실행한다. 스키마/범위 검증은 실행 직전에 수행한다(core.plan).
    approved_plan: dict | None = None
    approved_plan_expires_at: float | None = None
    approved_plan_revoked_at: float | None = None

    @model_validator(mode='after')
    def check_scope(self):
        if self.protected_marker and len(self.protected_marker) < 8:
            raise ValueError('보호 콘텐츠 표식은 8자 이상이어야 합니다.')
        if self.approved_plan is not None:
            self.mode = 'plan'   # 승인된 계획은 응답-블라인드 실행에만 의미가 있다
            if self.approved_plan_expires_at is None:
                self.approved_plan_expires_at = time.time() + 3600
            if self.approved_plan_expires_at > time.time() + 3600:
                raise ValueError('승인 계획의 유효 시간은 최대 1시간입니다.')
        elif self.approved_plan_expires_at is not None or self.approved_plan_revoked_at is not None:
            raise ValueError('승인 계획 없이 만료/철회 시각을 지정할 수 없습니다.')
        root = origin(self.request.url)
        if self.target_scope == 'request_only' and (self.objects or any(g.category == 'access' for g in self.goals)):
            raise ValueError('객체 접근 검증은 같은 출처 탐색 범위에서만 사용할 수 있습니다.')
        for prefix in [*self.allowed_path_prefixes, *self.denied_path_prefixes]:
            if (not prefix.startswith('/') or '?' in prefix or '#' in prefix or '//' in prefix
                    or '%' in prefix or '\\' in prefix or ';' in prefix
                    or any(s in ('.', '..') for s in prefix.split('/'))):
                raise ValueError('경로 제약은 /로 시작하는 경로 접두사만 허용합니다.')
        if len(set(self.allowed_methods)) != len(self.allowed_methods) or len(set(self.allowed_categories)) != len(self.allowed_categories):
            raise ValueError('중복된 허용 메서드/검사 유형이 있습니다.')
        requested = requested_categories(self.goal, [g.category for g in self.goals]) - {'access'}
        if self.allowed_categories and requested - set(self.allowed_categories):
            raise ValueError('요청한 검사 유형과 허용 검사 유형이 충돌합니다. 목표 또는 허용 유형을 확인하세요.')
        ids = [a.id for a in self.actors]
        if len(set(ids)) != len(ids):
            raise ValueError('계정 ID는 중복될 수 없습니다.')
        if len({o.id for o in self.objects}) != len(self.objects):
            raise ValueError('객체 정책 ID는 중복될 수 없습니다.')
        if len({g.id for g in self.goals}) != len(self.goals):
            raise ValueError('검증 목표 ID는 중복될 수 없습니다.')
        for goal in self.goals:
            if goal.actor_id and goal.actor_id not in ids:
                raise ValueError('검증 목표에 알 수 없는 계정이 있습니다.')
            if self.allowed_categories and goal.category != 'access' and goal.category not in self.allowed_categories:
                raise ValueError('검증 목표의 유형이 허용 검사 유형에 없습니다.')
        if self.request.method not in ('GET', 'HEAD') and not self.allow_write_methods:
            raise ValueError('현재 요청 메서드를 사용하려면 쓰기 메서드 허용을 켜세요.')
        for obj in self.objects:
            if origin(obj.url) != root:
                raise ValueError('객체 URL은 시작 URL과 같은 출처여야 합니다.')
            if obj.owner_actor not in ids or any(a not in ids for a in obj.allowed_actors):
                raise ValueError('객체 정책에 알 수 없는 계정이 있습니다.')
        return self


class Action(Contract):
    kind: Literal['observe', 'probe', 'confirm', 'access', 'wait_oob', 'finish']
    hypothesis: str = Field(min_length=1, max_length=1000)
    expected: str = Field(default='', max_length=500)
    endpoint_id: str = 'seed'
    actor_id: str = 'current'
    category: Literal['', 'sqli', 'auth', 'xss', 'ssti', 'lfi', 'ssrf', 'cmdi', 'redirect', 'nosql'] = ''
    confirmation_profile: Literal['full', 'sql_string', 'sql_numeric', 'sql_comment', 'sql_login'] = 'full'
    location: Literal['param', 'body', 'header'] = 'param'
    param: str = Field(default='', max_length=100)
    payload: str = Field(default='', max_length=4000)
    object_id: str = ''
    basis: list[str] = Field(default_factory=list, max_length=12)

    @model_validator(mode='after')
    def check_confirmation_profile(self):
        if self.confirmation_profile != 'full' and (self.kind != 'confirm' or
            (self.category != 'sqli' and not (self.category == 'auth' and self.confirmation_profile == 'sql_login'))):
            raise ValueError('SQL 대조 프로필은 SQL confirm 행동에만 사용할 수 있습니다.')
        return self
