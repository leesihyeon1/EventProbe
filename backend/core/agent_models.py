"""Validated contracts for a bounded, HTTP context-aware test agent."""
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, model_validator, ConfigDict


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


class RunSpec(Contract):
    goal: str = Field(min_length=1, max_length=2000)
    request: AgentRequest
    actors: list[Actor] = Field(default_factory=lambda: [Actor(id='current')], min_length=1, max_length=8)
    objects: list[ObjectPolicy] = Field(default_factory=list, max_length=20)
    max_steps: int = Field(default=8, ge=1, le=50)
    max_requests: int = Field(default=24, ge=1, le=150)
    max_ai_calls: int = Field(default=8, ge=0, le=50)
    max_seconds: int = Field(default=300, ge=10, le=1800)
    timeout: int = Field(default=15, ge=1, le=60)
    allow_write_methods: bool = False
    share_response_context: bool = False

    @model_validator(mode='after')
    def check_scope(self):
        root = origin(self.request.url)
        ids = [a.id for a in self.actors]
        if len(set(ids)) != len(ids):
            raise ValueError('계정 ID는 중복될 수 없습니다.')
        if len({o.id for o in self.objects}) != len(self.objects):
            raise ValueError('객체 정책 ID는 중복될 수 없습니다.')
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
    category: Literal['', 'sqli', 'xss', 'ssti', 'lfi', 'ssrf', 'cmdi', 'redirect', 'nosql'] = ''
    location: Literal['param', 'body', 'header'] = 'param'
    param: str = Field(default='', max_length=100)
    payload: str = Field(default='', max_length=4000)
    object_id: str = ''
    basis: list[str] = Field(default_factory=list, max_length=12)
