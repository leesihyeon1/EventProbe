"""strict 반출 모드에서 agent planner 입력 비식별화 검증 (리뷰 F4, Stage 1 범위).

반복 planner 는 유지하되, strict 에서는 planner 로 나가는 context 에서 고민감 필드를 제거한다:
목표 원문 → 목적 코드, 계정 라벨 제거, 객체 identity_value/description/pointer 제거,
엔드포인트/객체 경로 템플릿화, 응답 발췌 제거. 전체 F4(응답-블라인드 계획)는 3단계 몫.
모의 HTTP·모의 planner 만 사용 — 실제 대상/LLM 없음.
"""
import asyncio
import json

import httpx
import pytest

from core.agent import AgentManager, _purpose_code, _strict_context
from core.agent_models import RunSpec, Action
from core.agent_store import Store


def _spec(**kw):
    return RunSpec.model_validate({'goal': '테스트', 'request': {'url': 'https://app.test/?id=1'}, **kw})


def _capturing(captured):
    async def choose(ctx):
        captured.append(json.loads(json.dumps(ctx, ensure_ascii=False)))   # 스냅샷
        return Action.model_validate({'kind': 'finish', 'hypothesis': '종료',
                                      'basis': [ctx['observations'][-1]['id']]})
    return choose


def _run(tmp_path, handler, cfg, planner):
    async def go():
        m = AgentManager(Store(tmp_path / 'a.db'), planner, httpx.MockTransport(handler))
        rid = m.create(cfg)
        await m.tasks[rid]
        return m.snapshot(rid)
    return asyncio.run(go())


@pytest.mark.parametrize("goal,code", [
    ("SQL 인젝션 확인", "injection"),
    ("인증 우회 / 권한 상승", "access-control"),
    ("반사형 XSS 점검", "xss"),
    ("내부망 SSRF 메타데이터", "ssrf"),
    ("경로 조작 LFI", "traversal"),
    ("무언가 모호한 목표", "general-verification"),
])
def test_purpose_code(goal, code):
    assert _purpose_code(goal) == code


def test_strict_context_unit_drops_sensitive_fields():
    ctx = {
        'goal': 'SQL 인젝션으로 인증 우회',
        'actors': [{'id': 'A', 'label': '관리자'}],
        'objects': [{'id': 'o1', 'url': '/orders/42', 'owner_actor': 'A', 'allowed_actors': [],
                     'identity_pointer': '/id', 'identity_value': '42', 'description': '비밀 설명'}],
        'endpoints': [{'id': 'seed', 'path': '/orders/42', 'method': 'GET',
                       'query_fields': ['id'], 'body_fields': []}],
        'observations': [{'id': 'ob1', 'path': '/orders/42', 'status': 200,
                          'untrusted_response_excerpt': 'SECRET'}],
    }
    out = _strict_context(ctx)
    assert 'goal' not in out and out['goal_purpose'] == 'access-control'
    assert out['actors'] == [{'id': 'A'}]
    o = out['objects'][0]
    assert 'identity_value' not in o and 'description' not in o and 'identity_pointer' not in o
    assert o['path'] == '/orders/{id}'
    assert out['endpoints'][0]['path'] == '/orders/{id}'
    assert 'untrusted_response_excerpt' not in out['observations'][0]
    assert out['observations'][0]['path'] == '/orders/{id}'
    blob = json.dumps(out, ensure_ascii=False)
    assert '관리자' not in blob and '비밀 설명' not in blob and 'SECRET' not in blob


def test_strict_run_deidentifies_planner_input(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    cap = []
    policy = {'id': 'orderB', 'url': 'https://app.test/orders/42', 'owner_actor': 'B',
              'identity_pointer': '/id', 'identity_value': '42', 'description': '소유자만 조회'}
    cfg = _spec(goal="SQL 인젝션으로 인증 우회",
                request={'url': 'https://app.test/orders/12345?id=1'},
                actors=[{'id': 'A', 'label': '관리자', 'headers': {'Authorization': 'Bearer AAA'}},
                        {'id': 'B', 'label': '사용자', 'headers': {'Authorization': 'Bearer BBB'}}],
                objects=[policy])
    _run(tmp_path, lambda r: httpx.Response(200, text='BODY'), cfg, _capturing(cap))
    assert cap, "planner 가 최소 1회 호출되어야 한다"
    ctx = cap[0]
    assert 'goal' not in ctx and ctx['goal_purpose'] == 'access-control'
    assert all('label' not in a for a in ctx['actors'])
    o = ctx['objects'][0]
    assert 'identity_value' not in o and 'description' not in o
    assert o['path'] == '/orders/{id}'
    assert any(e['path'] == '/orders/{id}' for e in ctx['endpoints'])
    blob = json.dumps(ctx, ensure_ascii=False)
    assert '관리자' not in blob and '소유자만 조회' not in blob


def test_strict_run_drops_response_excerpt_even_if_shared(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "strict")
    cap = []
    cfg = _spec(share_response_context=True)
    _run(tmp_path, lambda r: httpx.Response(200, text='TOPSECRETBODY'), cfg, _capturing(cap))
    assert cap
    blob = json.dumps(cap[0], ensure_ascii=False)
    assert 'TOPSECRETBODY' not in blob
    assert all('untrusted_response_excerpt' not in o for o in cap[0]['observations'])


def test_permissive_run_retains_identifiers(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_EXPORT_MODE", "permissive")
    cap = []
    cfg = _spec(goal="그대로유지", actors=[{'id': 'A', 'label': '관리자'}], share_response_context=True)
    _run(tmp_path, lambda r: httpx.Response(200, text='VISIBLE'), cfg, _capturing(cap))
    ctx = cap[0]
    assert ctx.get('goal') == '그대로유지'
    assert any(a.get('label') == '관리자' for a in ctx['actors'])
