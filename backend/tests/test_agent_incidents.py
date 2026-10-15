"""SIEM/SOAR incidents link read-only to verification runs; status comes only from runs.

Guards (리뷰 P2/N4):
  - 과거 증거를 새 확증으로 오인하지 않음: the incident report is an input, never evidence.
  - 미관측을 해결로 표시하지 않음: no run / untested category never becomes 'resolved'.
  - 내부 이벤트 본문은 외부 AI 로 반출되지 않음: fixed plan, max_ai_calls=0, body stays local.
"""
import asyncio
import time

import httpx
import pytest

import core.agent as agent_mod
from core.agent import AgentManager
from core.agent_incidents import build_asset_trace, build_incident_trace
from core.agent_models import IncidentEvent
from core.agent_store import Store


# ── 1) 읽기 전용 상태 도출(순수 함수) — 연결 실행의 현재 판정에서만 상태를 만든다 ──────────
_INC = {'id': 'inc-1', 'source': 'siem', 'category': 'sqli', 'title': 'SQLi 경보',
        'asset_id': 'app-7', 'traffic_id': 'flow-42', 'observed_at': 100.0}


def _run(state, verdict, *, category='sqli', evidence=('obs-1',), exercised=True):
    verifs = [{'id': 'v1', 'category': category, 'status': verdict,
               'evidence_ids': list(evidence)}] if exercised else []
    return {'id': 'r1', 'state': state, 'created': 1.0,
            'conclusion': {'verdict': verdict, 'verifications': verifs, 'completion': 'complete'}}


def test_no_runs_is_unverified_never_resolved():
    trace = build_incident_trace(_INC, [])
    assert trace['status'] == 'unverified'
    assert '해결로 표시하지 않' in trace['reason']
    assert trace['asset_id'] == 'app-7' and trace['traffic_id'] == 'flow-42'


def test_linked_confirmation_reproduces():
    trace = build_incident_trace(_INC, [_run('completed', 'confirmed')])
    assert trace['status'] == 'reproduced'
    assert trace['runs'][0]['evidence_ids'] == ['obs-1']


def test_active_run_is_verifying():
    assert build_incident_trace(_INC, [_run('running', 'inconclusive')])['status'] == 'verifying'


def test_completed_tested_but_unconfirmed_is_not_reproduced_not_resolved():
    trace = build_incident_trace(_INC, [_run('completed', 'inconclusive')])
    assert trace['status'] == 'not_reproduced'
    assert '안전' not in trace['status'] and '해결' not in trace['status']
    assert '안전/해결을 의미하지 않' in trace['reason']


def test_suspicious_without_confirmation():
    assert build_incident_trace(_INC, [_run('completed', 'suspicious')])['status'] == 'suspicious'


def test_completed_without_category_coverage_is_inconclusive():
    # 완료됐지만 사건 유형을 검사하지 못함 → 미관측을 해결로 표시하지 않고 판정불가로 남긴다.
    trace = build_incident_trace(_INC, [_run('completed', 'inconclusive', exercised=False)])
    assert trace['status'] == 'inconclusive'


def test_confirmation_requires_linked_evidence():
    # 확증 판정이라도 연결 증거가 없으면 재현으로 올리지 않는다(과거 증거 오인 방지).
    trace = build_incident_trace(_INC, [_run('completed', 'confirmed', evidence=())])
    assert trace['status'] != 'reproduced'


def test_other_category_confirmation_does_not_reproduce_incident():
    trace = build_incident_trace(_INC, [_run('completed', 'confirmed', category='xss')])
    assert trace['status'] == 'inconclusive'
    assert trace['runs'][0]['verdict'] == 'inconclusive'


def test_latest_retest_controls_status_and_keeps_historical_confirmation():
    old = _run('completed', 'confirmed')
    old['id'], old['created'] = 'old', 1.0
    recent = _run('completed', 'inconclusive')
    recent['id'], recent['created'] = 'recent', 2.0
    trace = build_incident_trace(_INC, [old, recent])
    assert trace['status'] == 'not_reproduced'
    assert trace['latest_verification_run_id'] == 'recent'
    assert trace['previously_reproduced'] is True


def test_latest_uncovered_retest_does_not_reuse_historical_confirmation():
    old = _run('completed', 'confirmed')
    old['id'], old['created'] = 'old', 1.0
    recent = _run('completed', 'inconclusive', exercised=False)
    recent['id'], recent['created'] = 'recent', 2.0
    trace = build_incident_trace(_INC, [old, recent])
    assert trace['status'] == 'inconclusive'
    assert trace['latest_verification_run_id'] == 'recent'
    assert trace['previously_reproduced'] is True


def test_findings_group_only_explicit_asset_and_matching_category_evidence():
    old = _run('completed', 'confirmed')
    old['id'], old['created'] = 'old', 1.0
    recent = _run('completed', 'suspicious')
    recent['id'], recent['created'] = 'recent', 2.0
    for run in (old, recent):
        run['findings'] = [
            {'id': 'finding-' + run['id'], 'category': 'sqli', 'endpoint_id': 'seed',
             'actor_id': 'current', 'verdict': run['conclusion']['verdict'],
             'method': 'GET', 'origin': 'https://app.test', 'path': '/items',
             'query_keys': ['q'], 'evidence_ids': ['obs-1']},
            {'id': 'wrong-category', 'category': 'xss', 'endpoint_id': 'seed',
             'evidence_ids': ['obs-1']},
            {'id': 'wrong-evidence', 'category': 'sqli', 'endpoint_id': 'seed',
             'evidence_ids': ['unlinked']},
        ]
    trace = build_incident_trace(_INC, [old, recent])
    assert len(trace['finding_groups']) == 1
    group = trace['finding_groups'][0]
    assert group['asset_id'] == 'app-7'
    assert [f['finding_id'] for f in group['findings']] == ['finding-recent', 'finding-old']
    assert (group['first_seen'], group['last_seen']) == (1.0, 2.0)
    assert trace['runs'][0]['finding_refs'][0]['evidence_ids'] == ['obs-1']
    no_asset = build_incident_trace({**_INC, 'asset_id': ''}, [old, recent])
    assert no_asset['finding_groups'] == []
    assert len(no_asset['runs'][0]['finding_refs']) == 1


def test_asset_trace_merges_only_explicit_matching_asset_and_preserves_incident_status():
    def trace(iid, asset, status, finding_id, created):
        return {'incident_id': iid, 'asset_id': asset, 'source': 'siem', 'category': 'sqli',
                'status': status, 'latest_verification_run_id': 'run-' + iid,
                'finding_groups': [{'asset_id': asset, 'category': 'sqli', 'method': 'GET',
                    'origin': 'https://app.test', 'path': '/items', 'query_keys': ['q'],
                    'actor_id': 'current', 'findings': [{'run_id': 'run-' + iid,
                        'finding_id': finding_id, 'verdict': 'confirmed', 'created': created,
                        'evidence_ids': ['obs-' + iid]}]}]}
    result = build_asset_trace('app-7', [
        trace('old', 'app-7', 'reproduced', 'f-old', 1.0),
        trace('recent', 'app-7', 'not_reproduced', 'f-new', 2.0),
        trace('other', 'app-8', 'reproduced', 'f-other', 3.0)])
    assert {i['incident_id']: i['status'] for i in result['incidents']} == {
        'old': 'reproduced', 'recent': 'not_reproduced'}
    assert len(result['finding_groups']) == 1
    group = result['finding_groups'][0]
    assert group['incident_ids'] == ['old', 'recent']
    assert [ref['finding_id'] for ref in group['findings']] == ['f-new', 'f-old']
    assert (group['first_seen'], group['last_seen']) == (1.0, 2.0)
    assert 'status' not in group and 'verdict' not in result
    assert build_asset_trace('', [trace('old', 'app-7', 'reproduced', 'f-old', 1.0)])['finding_groups'] == []


def test_asset_trace_integrates_two_synthetic_incident_runs(tmp_path):
    async def run():
        manager = _manager(tmp_path, lambda request: httpx.Response(200, text='ok'))
        for external_id in ('EVT-1', 'EVT-2'):
            inc = manager.create_incident({'source': 'siem', 'category': 'sqli',
                'external_id': external_id, 'title': 'local only', 'asset_id': 'app-7',
                'request': {'method': 'GET', 'url': 'https://app.test/items', 'params': {'q': '1'}}})
            snap = manager.verify_incident(inc['id'])
            await manager.tasks[snap['id']]
        return manager.asset_trace('app-7')

    trace = asyncio.run(run())
    assert len(trace['incidents']) == 2
    assert len(trace['finding_groups']) == 1
    group = trace['finding_groups'][0]
    assert len(group['incident_ids']) == 2 and len(group['findings']) == 2
    assert all(ref['evidence_ids'] for ref in group['findings'])
    assert 'verdict' not in trace


# ── 2) 입력 계약 검증 ──────────────────────────────────────────────────────────
def test_future_observed_at_rejected():
    with pytest.raises(ValueError, match='관측 시각'):
        IncidentEvent.model_validate({'source': 'siem', 'category': 'sqli', 'title': 't',
                                      'observed_at': time.time() + 99999})


def test_past_observed_at_accepted():
    IncidentEvent.model_validate({'source': 'siem', 'category': 'sqli', 'title': 't',
                                  'observed_at': 1000.0})


# ── 3) 통합: 수집 → 재검증 실행 연결(AI 호출 0) → 읽기 전용 상태 ─────────────────────
def _manager(tmp_path, reply):
    return AgentManager(Store(tmp_path / 'runs.db'), transport=httpx.MockTransport(reply))


def test_verify_links_run_without_model_calls(tmp_path):
    async def run():
        def reply(request):
            return httpx.Response(200, text='ok')
        manager = _manager(tmp_path, reply)
        inc = manager.create_incident({'source': 'soar', 'category': 'sqli', 'title': '비밀 사건 본문',
                                       'summary': '내부 전용 요약', 'asset_id': 'app-7', 'traffic_id': 'flow-42',
                                       'request': {'method': 'GET', 'url': 'https://app.test/api/items',
                                                   'params': {'q': '1'}}})
        snap = manager.verify_incident(inc['id'])
        new_id = snap['id']
        await manager.tasks[new_id]
        return manager.snapshot(new_id), manager.incident_trace(inc['id']), inc['id']

    run_snap, trace, iid = asyncio.run(run())
    # 실행이 사건에 읽기 전용으로 연결되고, 공통 자산/트래픽 ID 를 보존한다.
    assert run_snap['data']['incident'] == {'incident_id': iid, 'asset_id': 'app-7',
                                            'traffic_id': 'flow-42', 'category': 'sqli'}
    # AI 호출 0(고정 계획) — 사건 본문이 모델 문맥에 들어가지 않는다.
    assert run_snap['data']['spec']['max_ai_calls'] == 0
    assert run_snap['data']['ai_calls'] == 0
    assert '비밀 사건 본문' not in run_snap['data']['spec']['goal']
    assert '내부 전용 요약' not in run_snap['data']['spec']['goal']
    # 상관 상태는 연결 실행 하나를 반영하며, 재현/미연결 상태가 아니다(양성 응답 없음 → 재현 안 됨).
    assert len(trace['runs']) == 1
    assert trace['status'] not in ('reproduced', 'unverified', 'verifying')
    assert len(trace['finding_groups']) == 1
    assert trace['finding_groups'][0]['asset_id'] == 'app-7'
    assert trace['finding_groups'][0]['findings'][0]['run_id'] == run_snap['id']
    assert run_snap['findings'][0]['asset_id'] == 'app-7'
    assert run_snap['findings'][0]['traffic_id'] == 'flow-42'


def test_verify_unknown_incident_raises_keyerror(tmp_path):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    with pytest.raises(KeyError):
        manager.verify_incident('missing')


def _access_inc(manager, url='https://app.test/api/orders/7'):
    return manager.create_incident({'source': 'siem', 'category': 'access', 'title': 'IDOR 의심',
                                    'asset_id': 'orders', 'request': {'method': 'GET', 'url': url}})


def test_access_incident_needs_identity_policy(tmp_path):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    inc = _access_inc(manager)
    with pytest.raises(ValueError, match='identity_pointer'):
        manager.verify_incident(inc['id'])                      # access 입력 없음
    with pytest.raises(ValueError, match='다르게'):
        manager.verify_incident(inc['id'], access={'owner_actor': 'o', 'intruder_actor': 'o',
                                                   'identity_pointer': '/id', 'identity_value': '7'})
    with pytest.raises(ValueError, match='identity_pointer'):
        manager.verify_incident(inc['id'], access={'identity_pointer': 'id', 'identity_value': '7'})


def test_access_incident_reproduces_unauthorized_read(tmp_path):
    async def run():
        def reply(request):
            return httpx.Response(200, json={'id': '7'})          # 소유자/비소유자 모두 객체 조회 성공
        manager = _manager(tmp_path, reply)
        inc = _access_inc(manager)
        snap = manager.verify_incident(inc['id'], access={
            'owner_actor': 'owner', 'intruder_actor': 'intruder',
            'identity_pointer': '/id', 'identity_value': '7', 'description': '주문 #7'})
        await manager.tasks[snap['id']]
        return manager.snapshot(snap['id']), manager.incident_trace(inc['id'])

    run_snap, trace = asyncio.run(run())
    actors = [a['id'] for a in run_snap['data']['spec']['actors']]
    assert set(actors) == {'owner', 'intruder'}                   # 소유자/비소유자 세션 분리
    assert run_snap['data']['spec']['max_ai_calls'] == 0          # 모델 호출 없음
    assert run_snap['data']['incident']['incident_id']            # 사건에 읽기 전용 연결
    assert trace['status'] == 'reproduced'                        # 무단 조회 재현 → 확증


def test_access_incident_not_reproduced_on_identity_mismatch(tmp_path):
    async def run():
        def reply(request):
            return httpx.Response(200, json={'id': '999'})        # 다른 객체 → 무단 조회 아님
        manager = _manager(tmp_path, reply)
        inc = _access_inc(manager)
        snap = manager.verify_incident(inc['id'], access={
            'identity_pointer': '/id', 'identity_value': '7'})
        await manager.tasks[snap['id']]
        return manager.incident_trace(inc['id'])

    trace = asyncio.run(run())
    assert trace['status'] == 'not_reproduced'                    # 재현 안 됨(해결/안전 아님)


def test_verify_requires_request_skeleton(tmp_path):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    inc = manager.create_incident({'source': 'siem', 'category': 'sqli', 'title': '요청 없음'})
    with pytest.raises(ValueError, match='요청 정보'):
        manager.verify_incident(inc['id'])


def test_verify_needs_an_injectable_param(tmp_path):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    inc = manager.create_incident({'source': 'siem', 'category': 'sqli', 'title': '파라미터 없음',
                                   'request': {'method': 'GET', 'url': 'https://app.test/api/items'}})
    with pytest.raises(ValueError, match='주입 파라미터'):
        manager.verify_incident(inc['id'])


def test_verify_honors_explicit_param_and_location(tmp_path):
    async def run():
        sent = []
        def reply(request):
            sent.append(str(request.url))
            return httpx.Response(200, text='ok')
        manager = _manager(tmp_path, reply)
        inc = manager.create_incident({'source': 'siem', 'category': 'sqli', 'title': '폼 필드',
                                       'location': 'body', 'param': 'name',
                                       'request': {'method': 'POST', 'url': 'https://app.test/login',
                                                   'body': 'name=admin&pw=x'}})
        snap = manager.verify_incident(inc['id'])
        await manager.tasks[snap['id']]
        return manager.snapshot(snap['id'])

    snap = asyncio.run(run())
    action = next(e['data'] for e in snap['events'] if e['kind'] == 'action')
    assert action['location'] == 'body' and action['param'] == 'name'
    assert snap['state'] == 'completed'


def test_incident_list_and_get_roundtrip(tmp_path):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    inc = manager.create_incident({'source': 'siem', 'category': 'xss', 'title': '반사형 XSS',
                                   'summary': '로컬 전용', 'asset_id': 'web-1'})
    listed = manager.store.incidents()
    assert any(i['id'] == inc['id'] and i['title'] == '반사형 XSS' for i in listed)
    assert all('summary' not in i for i in listed)          # 목록엔 본문 요약을 싣지 않는다
    assert manager.store.incident(inc['id'])['summary'] == '로컬 전용'   # 상세엔 로컬 보관
    assert manager.store.delete_incident(inc['id']) is True
    with pytest.raises(KeyError):
        manager.store.incident(inc['id'])
    audit = manager.store.incident_deletions()
    assert len(audit) == 1 and audit[0]['incident_id'] == inc['id']
    assert audit[0]['category'] == 'xss'
    assert 'summary' not in audit[0] and 'title' not in audit[0] and 'request' not in audit[0]
    assert manager.store.delete_incident(inc['id']) is False
    assert len(manager.store.incident_deletions()) == 1


def test_incident_deletion_audit_respects_owner_before_limit(tmp_path):
    store = Store(tmp_path / 'runs.db')
    alice = store.create_incident({'source': 'siem', 'category': 'sqli', 'title': 'private'}, owner='alice')
    store.delete_incident(alice)
    for n in range(101):
        other = store.create_incident({'source': 'siem', 'category': 'xss', 'title': str(n)}, owner='bob')
        store.delete_incident(other)
    visible = store.incident_deletions(limit=1, owner='alice')
    assert [row['incident_id'] for row in visible] == [alice]
    assert store.incident_deletions(limit=1, owner='bob')[0]['owner'] == 'bob'


def test_incident_link_survives_many_unrelated_runs(tmp_path):
    store = Store(tmp_path / 'runs.db')
    linked = store.create({'incident': {'incident_id': 'inc-1'}})
    for _ in range(501):
        store.create({'incident': {'incident_id': 'other'}})
    assert [run['id'] for run in store.runs_for_incident('inc-1')] == [linked]


# ── 4) HTTP 엔드포인트(API·저장·권한) ────────────────────────────────────────────
def test_incident_endpoints(tmp_path, monkeypatch):
    m = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    monkeypatch.setattr(agent_mod, '_manager', m)
    from fastapi.testclient import TestClient
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    app = main.app
    client = TestClient(app)

    created = client.post('/api/agent/incidents', json={
        'source': 'soar', 'external_id': 'EVT-9', 'category': 'sqli', 'title': '사건 본문',
        'asset_id': 'app-7', 'traffic_id': 'flow-42',
        'request': {'method': 'GET', 'url': 'https://app.test/api/items', 'params': {'q': '1'}}})
    assert created.status_code == 201
    iid = created.json()['id']

    listed = client.get('/api/agent/incidents').json()['incidents']
    assert any(i['id'] == iid and i['external_id'] == 'EVT-9' for i in listed)

    verify = client.post(f'/api/agent/incidents/{iid}/verify', json={})
    assert verify.status_code == 201
    assert verify.json()['data']['incident']['incident_id'] == iid

    trace = client.get(f'/api/agent/incidents/{iid}').json()
    assert trace['asset_id'] == 'app-7' and trace['traffic_id'] == 'flow-42'
    assert len(trace['runs']) == 1 and trace['status'] != 'unverified'

    # 잘못된 계약(미래 시각)은 본문 검증 단계에서 거부(422), 없는 사건 → 404.
    bad = client.post('/api/agent/incidents', json={'source': 's', 'category': 'sqli',
                                                    'title': 't', 'observed_at': time.time() + 99999})
    assert bad.status_code == 422
    assert client.get('/api/agent/incidents/missing').status_code == 404
    assert client.delete(f'/api/agent/incidents/{iid}').status_code == 200
    assert client.get(f'/api/agent/incidents/{iid}').status_code == 404
    audit = client.get('/api/agent/incidents/deletions')
    assert audit.status_code == 200
    assert any(row['incident_id'] == iid for row in audit.json()['deletions'])


def test_incident_deletion_audit_api_scopes_to_workspace(tmp_path, monkeypatch):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    monkeypatch.setattr(agent_mod, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    alice = {'x-eventprobe-user': 'alice'}
    bob = {'x-eventprobe-user': 'bob'}
    created = client.post('/api/agent/incidents', headers=alice,
                          json={'source': 'siem', 'category': 'sqli', 'title': '내부 사건'})
    assert created.status_code == 201
    iid = created.json()['id']
    assert client.delete(f'/api/agent/incidents/{iid}', headers=bob).status_code == 403
    assert client.delete(f'/api/agent/incidents/{iid}', headers=alice).status_code == 200
    assert [r['incident_id'] for r in client.get('/api/agent/incidents/deletions', headers=alice).json()['deletions']] == [iid]
    assert client.get('/api/agent/incidents/deletions', headers=bob).json()['deletions'] == []


def test_incident_list_scopes_before_recent_limit(tmp_path, monkeypatch):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    monkeypatch.setattr(agent_mod, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    incident = {'source': 'siem', 'category': 'sqli', 'title': 'synthetic'}
    own = manager.store.create_incident(incident, owner='alice')
    legacy = manager.store.create_incident(incident)
    for _ in range(105):
        manager.store.create_incident(incident, owner='bob')
    result = client.get('/api/agent/incidents',
                        headers={'x-eventprobe-user': 'alice'})
    assert result.status_code == 200
    assert {row['id'] for row in result.json()['incidents']} == {own, legacy}
    assert result.json()['total'] == 2


def test_incident_pages_reach_older_rows_without_original_body(tmp_path, monkeypatch):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    monkeypatch.setattr(agent_mod, '_manager', manager)
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    incident = {'source': 'siem', 'category': 'sqli', 'title': 'synthetic',
                'summary': 'SYNTHETIC_PRIVATE_' + 'x' * 200_000}
    ids = [manager.store.create_incident(incident)]
    ids.extend(manager.store.create_incident({**incident, 'summary': 'small'}) for _ in range(124))
    first = client.get('/api/agent/incidents', params={'limit': 100})
    second = client.get('/api/agent/incidents', params={'limit': 100, 'offset': 100})
    assert first.status_code == second.status_code == 200
    assert first.json()['has_more'] is True and second.json()['has_more'] is False
    rows = first.json()['incidents'] + second.json()['incidents']
    assert len(rows) == len({row['id'] for row in rows}) == 125
    assert {row['id'] for row in rows} == set(ids)
    assert 'SYNTHETIC_PRIVATE_' not in first.text + second.text
    assert len(first.content) < 30_000
    assert client.get('/api/agent/incidents', params={'limit': 101}).status_code == 422


def test_incident_cursor_keeps_page_boundary_after_new_insert(tmp_path, monkeypatch):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    monkeypatch.setattr(agent_mod, '_manager', manager)
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    incident = {'source': 'siem', 'category': 'sqli', 'title': 'synthetic'}
    ids = [manager.store.create_incident(incident) for _ in range(5)]
    url = '/api/agent/incidents'
    first = client.get(url, params={'limit': 2}).json()
    inserted = manager.store.create_incident(incident)
    rows = list(first['incidents'])
    cursor = first['next_cursor']
    while cursor:
        page = client.get(url, params={'limit': 2, 'before_created': cursor['created'],
                                       'before_id': cursor['id']}).json()
        rows.extend(page['incidents'])
        cursor = page['next_cursor'] if page['has_more'] else None
    assert len(rows) == len({row['id'] for row in rows}) == 5
    assert {row['id'] for row in rows} == set(ids)
    assert inserted not in {row['id'] for row in rows}
    assert client.get(url, params={'before_id': ids[0]}).status_code == 422


def test_asset_trace_api_scopes_before_correlating(tmp_path, monkeypatch):
    manager = _manager(tmp_path, lambda r: httpx.Response(200, text='ok'))
    monkeypatch.setattr(agent_mod, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    for owner in ('alice', 'bob'):
        response = client.post('/api/agent/incidents', headers={'x-eventprobe-user': owner},
                               json={'source': 'siem', 'category': 'sqli', 'title': owner,
                                     'asset_id': 'shared'})
        assert response.status_code == 201
    alice = client.get('/api/agent/incidents/asset-trace?asset_id=shared',
                       headers={'x-eventprobe-user': 'alice'})
    assert alice.status_code == 200
    assert len(alice.json()['incidents']) == 1
    assert alice.json()['incidents'][0]['status'] == 'unverified'
    assert alice.json()['finding_groups'] == []
    assert client.get('/api/agent/incidents/asset-trace?asset_id=').status_code == 400
