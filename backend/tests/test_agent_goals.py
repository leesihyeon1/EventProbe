"""Multiple verification goals resolve only from current, linked local evidence."""
import asyncio

import httpx
import pytest

from core.agent import AgentManager
from core.agent_models import RunSpec
from core.agent_outcome import build_conclusion
from core.agent_findings import build_report_html
from core.agent_store import Store


def _spec(goals):
    return RunSpec.model_validate({'goal': 'synthetic',
                                   'request': {'url': 'https://app.test/api'},
                                   'goals': goals})


def _events(with_evidence=True):
    events = [
        {'id': 'action-1', 'kind': 'action', 'step_id': 'step-1',
         'data': {'kind': 'confirm', 'category': 'sqli', 'endpoint_id': 'seed', 'actor_id': 'current'}},
        {'id': 'observation-1', 'kind': 'observation', 'step_id': 'step-1', 'data': {}},
        {'id': 'verification-1', 'kind': 'verification', 'step_id': 'step-1',
         'data': {'status': 'confirmed', 'evidence_ids': ['observation-1' if with_evidence else 'missing']}},
    ]
    return events


def test_two_goals_have_independent_evidence_and_incomplete_reason():
    spec = _spec([
        {'id': 'sql', 'title': 'SQL 입력 검증', 'category': 'sqli', 'completion': 'confirmed'},
        {'id': 'xss', 'title': 'XSS 입력 검증', 'category': 'xss', 'completion': 'tested'},
    ])
    result = build_conclusion({'spec': spec.model_dump()}, _events(), 'completed')
    assert result['completion'] == 'partial'
    assert result['goals'][0]['status'] == 'met'
    assert result['goals'][0]['evidence_ids'] == ['observation-1']
    assert result['goals'][1]['status'] == 'unmet'
    assert result['goals'][1]['evidence_ids'] == []
    assert '검증 기록' in result['goals'][1]['reason']


def test_missing_evidence_never_satisfies_tested_or_confirmed_goal():
    spec = _spec([
        {'id': 'tested', 'title': '검사 실시', 'category': 'sqli', 'completion': 'tested'},
        {'id': 'confirmed', 'title': '취약성 확증', 'category': 'sqli', 'completion': 'confirmed'},
    ])
    result = build_conclusion({'spec': spec.model_dump()}, _events(with_evidence=False), 'completed')
    assert result['verdict'] == 'inconclusive'
    assert all(g['status'] == 'unmet' for g in result['goals'])


def test_goal_actor_filter_and_duplicate_id_validation():
    spec = RunSpec.model_validate({'goal': 'synthetic', 'request': {'url': 'https://app.test/api'},
                                   'actors': [{'id': 'current'}, {'id': 'other'}],
                                   'goals': [{'id': 'other', 'title': '다른 계정', 'category': 'sqli',
                                              'completion': 'confirmed', 'actor_id': 'other'}]})
    assert build_conclusion({'spec': spec.model_dump()}, _events(), 'completed')['goals'][0]['status'] == 'unmet'
    with pytest.raises(ValueError, match='알 수 없는 계정'):
        _spec([{'id': 'other', 'title': '다른 계정', 'category': 'sqli', 'actor_id': 'other'}])
    with pytest.raises(ValueError, match='중복'):
        _spec([{'id': 'same', 'title': '첫 목표', 'category': 'sqli'},
               {'id': 'same', 'title': '둘째 목표', 'category': 'xss'}])


def test_report_renders_goal_status_without_markup_or_network():
    spec = _spec([{'id': 'sql', 'title': '<script>alert(1)</script>',
                   'category': 'sqli', 'completion': 'confirmed'}])
    data = {'spec': spec.model_dump(), 'endpoints': {'seed': spec.request.model_dump()}}
    events = _events()
    report = build_report_html({'id': 'synthetic', 'state': 'completed', 'data': data,
                                'events': events, 'conclusion': build_conclusion(data, events, 'completed'),
                                'findings': []})
    assert '<script>alert(1)</script>' not in report
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in report
    assert '세부 검증 목표' in report


def test_unmet_goal_survives_restart_without_model_or_target_calls(tmp_path):
    async def run():
        calls = []
        def reply(request):
            calls.append(request)
            return httpx.Response(200, text='synthetic')
        store = Store(tmp_path / 'goals.db')
        manager = AgentManager(store, transport=httpx.MockTransport(reply))
        spec = RunSpec.model_validate({'goal': 'synthetic',
            'request': {'url': 'https://app.test/'},
            'goals': [{'id': 'xss', 'title': 'XSS 검증', 'category': 'xss', 'completion': 'tested'}],
            'approved_plan': {'entry': 'observe', 'steps': [
                {'action_id': 'observe', 'action': {'kind': 'observe', 'hypothesis': 'synthetic'}}]}})
        rid = manager.create(spec)
        await manager.tasks[rid]
        restarted = AgentManager(store, transport=httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(AssertionError('조회가 요청을 보내면 안 됩니다.'))))
        return restarted.snapshot(rid), calls

    snapshot, calls = asyncio.run(run())
    assert len(calls) == 1
    assert snapshot['state'] == 'completed'
    assert snapshot['conclusion']['completion'] == 'partial'
    assert snapshot['conclusion']['goals'][0]['status'] == 'unmet'
