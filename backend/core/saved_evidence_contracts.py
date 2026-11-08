"""Bounded metadata contracts shared by preservation and portable restore."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.agent_models import AgentRequest, origin

Severity = Literal['info', 'low', 'medium', 'high', 'critical']
Status = Literal['open', 'triaged', 'resolved', 'false_positive', 'ignored']


class FindingSnapshot(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=r'^[a-f0-9]{16}$')
    category: str = Field(min_length=1, max_length=100)
    endpoint_id: str = Field(max_length=100)
    actor_id: str = Field(max_length=32)
    verdict: Literal['confirmed', 'suspicious', 'inconclusive']
    evidence_ids: list[str] = Field(max_length=250)
    verification_ids: list[str] = Field(max_length=250)
    step_ids: list[str] = Field(max_length=250)
    created: float = Field(allow_inf_nan=False)
    updated: float = Field(allow_inf_nan=False)
    incomplete_evidence: bool
    origin: str = Field(max_length=4096)
    path: str = Field(max_length=4096)
    query_keys: list[str] = Field(max_length=500)
    asset_id: str = Field(max_length=120)
    traffic_id: str = Field(max_length=120)
    method: Literal['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']
    default_severity: Severity
    severity: Severity
    status: Status
    note: str = Field(max_length=2000)
    history: list[dict] = Field(max_length=10000)


class SourceSnapshot(BaseModel):
    model_config = ConfigDict(extra='forbid')
    goal: str = Field(max_length=2000)
    source_state: str = Field(max_length=32)
    request: AgentRequest

    @model_validator(mode='after')
    def credentials_and_origin(self):
        origin(self.request.url)
        if self.request.headers:
            raise ValueError('원본 실행 명세의 인증 헤더는 보존하지 않습니다.')
        return self
