"""재사용 검증 템플릿(리뷰 N1). 검증 설정(목표/범위/예산/계획)을 템플릿으로 저장하고 새
실행으로 복제한다. 비밀값(자격증명)은 템플릿에 저장하지 않고 실행 시 재주입한다.
실 HTTP 는 MockTransport, 실제 대상/LLM 호출 없음."""
import asyncio
import json
import sqlite3

import httpx
import pytest

import core.agent as agent_mod
from core.agent import AgentManager, template_spec
from core.agent_store import Store
from core.agent_models import RunSpec, Action


def _spec():
    return RunSpec.model_validate({
        'goal': '템플릿 목표', 'request': {'url': 'https://app.test/?id=1', 'headers': {'Cookie': 's=SECRET'}},
        'actors': [{'id': 'current', 'headers': {'X-Auth': 'SECRET'}}]})


def _finish_planner():
    async def choose(ctx):
        return Action(kind='finish', hypothesis='종료',
                      basis=[ctx['observations'][-1]['id']] if ctx['observations'] else [])
    return choose


def test_template_spec_strips_credentials_but_keeps_structure():
    d = template_spec(_spec())
    assert d['request']['headers'] == {}
    assert all(a['headers'] == {} for a in d['actors'])
    assert d['goal'] == '템플릿 목표' and d['request']['url'] == 'https://app.test/?id=1'
    assert 'SECRET' not in str(d)


def test_store_template_crud(tmp_path):
    s = Store(tmp_path / 't.db')
    tid = s.save_template('로그인 점검', 'auth', template_spec(_spec()))
    lst = s.templates()
    assert len(lst) == 1 and lst[0]['name'] == '로그인 점검' and lst[0]['goal'] == '템플릿 목표'
    assert lst[0]['version'] == 1
    assert s.template(tid)['spec']['request']['headers'] == {}
    updated = s.update_template(tid, '로그인 재점검', 'auth', template_spec(_spec()))
    assert updated['version'] == 2
    assert [row['version'] for row in s.template_revisions(tid)] == [2, 1]
    assert s.restore_template_revision(tid, 1)['version'] == 3
    assert s.template(tid)['name'] == '로그인 점검'
    assert s.delete_template(tid) is True
    with s.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM template_revisions WHERE template_id=?', (tid,)).fetchone()[0] == 0
    with pytest.raises(KeyError):
        s.template(tid)
    assert s.delete_template(tid) is False


def test_store_scrubs_headers_for_direct_saves_and_legacy_revisions(tmp_path):
    path = tmp_path / 'credential-legacy.db'
    raw = {'goal': 'synthetic', 'request': {'url': 'https://app.test/',
           'headers': {'Cookie': 'legacy=SECRET'}},
           'actors': [{'id': 'current', 'headers': {'Authorization': 'Bearer SECRET'}}]}
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE templates (id TEXT PRIMARY KEY, created REAL NOT NULL, '
                   'name TEXT NOT NULL, category TEXT NOT NULL, spec TEXT NOT NULL)')
        db.execute('INSERT INTO templates VALUES (?,?,?,?,?)',
                   ('legacy', 1, 'legacy', '', json.dumps(raw)))
    store = Store(path)
    with store.connect() as db:
        saved = db.execute("SELECT spec FROM templates WHERE id='legacy'").fetchone()['spec']
        revision = db.execute("SELECT spec FROM template_revisions WHERE template_id='legacy'").fetchone()['spec']
    assert 'SECRET' not in saved + revision
    assert store.restore_template_revision('legacy', 1)['version'] == 2
    direct = store.save_template('direct', '', raw)
    store.update_template(direct, 'changed', '', raw)
    with store.connect() as db:
        specs = [row['spec'] for row in db.execute('SELECT spec FROM template_revisions')]
    assert all('SECRET' not in spec for spec in specs)
    assert store.template(direct)['spec']['request']['headers'] == {}


def test_template_search_filters_before_list_limit_and_reports_policy(tmp_path):
    s = Store(tmp_path / 'search.db')
    spec = template_spec(_spec())
    wanted = s.save_template('오래된 로그인', 'auth', spec)
    for index in range(105):
        s.save_template(f'다른 템플릿 {index}', 'misc', spec)
    matches = s.templates(search='오래된', category='auth')
    assert [item['id'] for item in matches] == [wanted]
    assert matches[0]['policy_version'] == 1
    assert matches[0]['pinned_plan'] is False


def test_template_api_pages_beyond_first_hundred(tmp_path, monkeypatch):
    store = Store(tmp_path / 'template-pages.db')
    spec = template_spec(_spec())
    ids = [store.save_template(f'template {index}', 'auth', spec) for index in range(125)]
    monkeypatch.setattr(agent_mod, '_manager', AgentManager(store))
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    first = client.get('/api/agent/templates', params={'category': 'auth', 'limit': 100})
    second = client.get('/api/agent/templates', params={'category': 'auth', 'limit': 100,
                                                         'offset': 100})
    assert first.status_code == second.status_code == 200
    assert first.json()['has_more'] is True and second.json()['has_more'] is False
    rows = first.json()['templates'] + second.json()['templates']
    assert len(rows) == len({row['id'] for row in rows}) == 125
    assert {row['id'] for row in rows} == set(ids)
    assert client.get('/api/agent/templates', params={'offset': -1}).status_code == 422


def test_batch_template_category_checks_each_owner_and_preserves_revisions(tmp_path, monkeypatch):
    store = Store(tmp_path / 'template-batch.db')
    spec = template_spec(_spec())
    alice = [store.save_template(f'alice {index}', 'old', spec, owner='alice') for index in range(2)]
    bob = store.save_template('bob', 'old', spec, owner='bob')
    manager = AgentManager(store, transport=httpx.MockTransport(lambda r: pytest.fail('target request')))
    monkeypatch.setattr(agent_mod, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    result = client.post('/api/agent/templates/batch/category',
                         headers={'x-eventprobe-user': 'alice'},
                         json={'ids': [alice[0], bob, 'missing', alice[1], alice[0]],
                               'category': 'access'})
    assert result.status_code == 200
    assert result.json()['succeeded'] == 2 and result.json()['failed'] == 2
    assert [row['status'] for row in result.json()['results'] if not row['ok']] == [403, 404]
    assert all(store.template(tid)['category'] == 'access' for tid in alice)
    assert store.template(bob)['category'] == 'old'
    assert [row['version'] for row in store.template_revisions(alice[0])] == [2, 1]
    assert manager.tasks == {}


def test_run_template_clones_run_and_reinjects_credentials(tmp_path):
    seen = []
    def handler(req):
        seen.append(req.headers.get('cookie'))
        return httpx.Response(200, text='ok')

    async def go():
        m = AgentManager(Store(tmp_path / 't.db'), planner=_finish_planner(), transport=httpx.MockTransport(handler))
        tid = m.store.save_template('t', 'c', template_spec(_spec()))
        snap = m.run_template(tid, request_headers={'Cookie': 'fresh=1'}, owner='alice')
        await m.tasks[snap['id']]
        return m.snapshot(snap['id']), seen
    snap, seen = asyncio.run(go())
    assert snap['data']['owner'] == 'alice'                 # principal 소유 기록
    assert snap['data']['spec']['goal'] == '템플릿 목표'     # 템플릿 구조 복제
    assert seen and any('fresh=1' in (c or '') for c in seen)   # 실행 시 재주입된 자격증명 사용
    assert 'SECRET' not in str(seen)                        # 템플릿엔 원 비밀값이 없다
    assert len(snap['data']['procedure_sha256']['agent']) == 64
    assert snap['data']['planner_attempts'][0]['model'] == ''  # custom planner is not mislabelled as AI model
    assert snap['data']['planner_attempts'][0]['status'] == 'accepted'
    assert snap['tool_summary']['http_observed'] == 1
    assert snap['tool_summary']['http_unresolved'] == 0


def test_template_endpoints(tmp_path, monkeypatch):
    m = AgentManager(Store(tmp_path / 'ep.db'), planner=_finish_planner(),
                     transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
    monkeypatch.setattr(agent_mod, '_manager', m)
    from fastapi.testclient import TestClient
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    client = TestClient(main.app)
    saved = client.post('/api/agent/templates',
                        json={'name': '스캔', 'category': 'xss',
                              'spec': {'goal': 'g', 'request': {'url': 'https://app.test/', 'headers': {'Cookie': 'x=SECRET'}}}})
    assert saved.status_code == 201
    tid = saved.json()['id']
    listed = client.get('/api/agent/templates').json()['templates']
    assert any(t['id'] == tid for t in listed)
    filtered = client.get('/api/agent/templates', params={'search': '스캔', 'category': 'xss'}).json()
    assert [t['id'] for t in filtered['templates']] == [tid]
    assert filtered['policy_version'] == 1
    assert client.get('/api/agent/templates', params={'category': 'access'}).json()['templates'] == []
    assert 'SECRET' not in str(m.store.template(tid)['spec'])   # 저장 시 비밀값 제거
    revised = client.patch(f'/api/agent/templates/{tid}',
                           json={'name': '스캔 개정', 'category': 'xss',
                                 'spec': {'goal': 'g2', 'request': {'url': 'https://app.test/',
                                            'headers': {'Cookie': 'new=SECRET'}}}})
    assert revised.status_code == 200 and revised.json()['version'] == 2
    assert [row['version'] for row in client.get(f'/api/agent/templates/{tid}/revisions').json()['revisions']] == [2, 1]
    assert 'SECRET' not in str(m.store.template(tid)['spec'])
    run = client.post(f'/api/agent/templates/{tid}/run', json={})
    assert run.status_code == 201 and run.json()['data']['spec']['goal'] == 'g2'
    restored = client.post(f'/api/agent/templates/{tid}/revisions/1/restore', json={})
    assert restored.status_code == 200 and restored.json()['version'] == 3
    assert m.store.template(tid)['spec']['goal'] == 'g'
    assert client.delete(f'/api/agent/templates/{tid}').status_code == 200
    assert client.delete(f'/api/agent/templates/{tid}').status_code == 404


def test_template_owner_scope_and_legacy_schema_migration(tmp_path, monkeypatch):
    path = tmp_path / 'legacy.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE templates (id TEXT PRIMARY KEY, created REAL NOT NULL, '
                   'name TEXT NOT NULL, category TEXT NOT NULL, spec TEXT NOT NULL)')
        db.execute("INSERT INTO templates VALUES ('legacy', 1, 'legacy', '', '{}')")
    store = Store(path)
    assert store.template('legacy')['name'] == 'legacy'
    assert store.template_revisions('legacy')[0]['version'] == 1
    manager = AgentManager(store, transport=httpx.MockTransport(lambda r: pytest.fail('target request')))
    monkeypatch.setattr(agent_mod, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    import main
    monkeypatch.setattr(main, '_access_token', lambda: '')
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    payload = {'name': 'private', 'category': 'auth',
               'spec': {'goal': 'synthetic', 'request': {'url': 'https://app.test/'}}}
    saved = client.post('/api/agent/templates', json=payload,
                        headers={'x-eventprobe-user': 'alice'})
    assert saved.status_code == 201
    tid = saved.json()['id']
    assert [row['id'] for row in client.get('/api/agent/templates',
           headers={'x-eventprobe-user': 'alice'}).json()['templates']] == [tid]
    assert client.get('/api/agent/templates', headers={'x-eventprobe-user': 'bob'}).json()['templates'] == []
    assert client.get('/api/agent/templates').status_code == 403
    assert client.post('/api/agent/templates', json=payload).status_code == 403
    assert client.post('/api/agent/templates/legacy/run', json={},
                       headers={'x-eventprobe-user': 'alice'}).status_code == 403
    assert client.post(f'/api/agent/templates/{tid}/run', json={},
                       headers={'x-eventprobe-user': 'bob'}).status_code == 403
    assert client.delete(f'/api/agent/templates/{tid}',
                         headers={'x-eventprobe-user': 'bob'}).status_code == 403
    assert client.get(f'/api/agent/templates/{tid}/revisions',
                      headers={'x-eventprobe-user': 'bob'}).status_code == 403
    assert client.patch(f'/api/agent/templates/{tid}', json=payload,
                        headers={'x-eventprobe-user': 'bob'}).status_code == 403
    assert client.post(f'/api/agent/templates/{tid}/revisions/1/restore', json={},
                       headers={'x-eventprobe-user': 'bob'}).status_code == 403
    assert store.template(tid)['name'] == 'private'
    assert manager.tasks == {}
