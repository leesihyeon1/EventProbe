"""응답-블라인드 계획 생성·검증 통합 (리뷰 Stage 3 s2).

외부 모델에 '비식별 입력'만 보내 조건부 계획을 1회 생성하고, 스키마·실행 범위를 검증한다.
모의 planner 로 네트워크 없이 검증하며, 입력에 host·실제 값·목표 원문·객체 식별값이
포함되지 않는지 확인한다.
"""
import asyncio
import json

import pytest

from core.agent_models import RunSpec
from core import agent as agent_mod


def _spec(**kw):
    base = {'goal': 'SQL 인젝션으로 인증 우회 확인',
            'request': {'url': 'https://shop.corp.example/api/orders/42?ref=https://evil.test',
                        'params': {'q': 'x'}}}
    base.update(kw)
    return RunSpec.model_validate(base)


def _valid_plan():
    return {'entry': 'p1', 'max_hops': 8, 'steps': [
        {'action_id': 'p1',
         'action': {'kind': 'probe', 'hypothesis': '주입 신호 확인', 'category': 'sqli',
                    'location': 'param', 'param': 'q', 'payload': "'", 'actor_id': 'current', 'endpoint_id': 'seed'},
         'branches': [{'predicate': {'kind': 'verdict_in', 'verdicts': ['suspicious']}, 'next': 'c1'}],
         'default_next': ''},
        {'action_id': 'c1',
         'action': {'kind': 'confirm', 'hypothesis': '차등 확증', 'category': 'sqli',
                    'location': 'param', 'param': 'q', 'payload': "' OR '1'='1", 'actor_id': 'current', 'endpoint_id': 'seed'},
         'branches': [{'predicate': {'kind': 'verdict_in', 'verdicts': ['confirmed']}, 'next': ''}],
         'default_next': ''}]}


def test_generate_plan_valid_and_deidentified():
    captured = {}

    async def planner(ctx):
        captured['ctx'] = ctx
        return _valid_plan()

    plan = asyncio.run(agent_mod.generate_plan(_spec(), planner=planner))
    assert plan.entry == 'p1' and len(plan.steps) == 2

    blob = json.dumps(captured['ctx'], ensure_ascii=False)
    assert 'shop.corp.example' not in blob         # host 제거
    assert 'evil.test' not in blob                 # 쿼리 값(도메인) 제거
    assert 'SQL 인젝션으로 인증 우회' not in blob     # 목표 원문 제거
    assert captured['ctx']['goal_purpose'] == 'access-control'
    assert captured['ctx']['request_shape']['path_template'] == '/api/orders/{id}'
    assert captured['ctx']['actors'] == ['current']


def test_generate_plan_rejects_unknown_actor():
    bad = _valid_plan()
    bad['steps'][0]['action']['actor_id'] = 'ghost'

    async def planner(ctx):
        return bad

    with pytest.raises(ValueError, match='허용되지 않은 계획'):
        asyncio.run(agent_mod.generate_plan(_spec(), planner=planner))


def test_generate_plan_rejects_malformed_schema():
    async def planner(ctx):
        return {'steps': []}        # entry 없음 + 빈 steps

    with pytest.raises(ValueError, match='계획 스키마 오류'):
        asyncio.run(agent_mod.generate_plan(_spec(), planner=planner))


def test_plan_endpoint_ok(monkeypatch):
    from fastapi.testclient import TestClient
    from main import app

    async def planner(ctx):
        return _valid_plan()
    monkeypatch.setattr(agent_mod, '_default_plan_planner', planner)

    r = TestClient(app).post('/api/agent/plan',
                             json={'goal': 't', 'request': {'url': 'https://app.test/?q=1'}})
    assert r.status_code == 200
    assert r.json()['plan']['entry'] == 'p1'


def test_plan_endpoint_rejects_bad_plan(monkeypatch):
    from fastapi.testclient import TestClient
    from main import app

    async def planner(ctx):
        return {'nope': True}
    monkeypatch.setattr(agent_mod, '_default_plan_planner', planner)

    r = TestClient(app).post('/api/agent/plan',
                             json={'goal': 't', 'request': {'url': 'https://app.test/?q=1'}})
    assert r.status_code == 400
