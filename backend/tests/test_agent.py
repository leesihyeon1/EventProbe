"""Agent regressions use fake HTTP and a fake planner, never a live target or LLM."""
import asyncio
import json

import httpx
import pytest

from core.agent import AgentManager, access_verdict, inject, discover
from core.agent_models import RunSpec, Action, origin
from core.agent_store import Store
from core.xss_confirm import marker_executed


def spec(**kwargs):
    return RunSpec.model_validate({'goal': '테스트', 'request': {'url': 'https://app.test/?id=1'}, **kwargs})


def planner(*actions):
    pending = iter(actions)
    async def choose(ctx):
        value = next(pending, {'kind': 'finish', 'hypothesis': '검증 종료'})
        value.setdefault('basis', [ctx['observations'][-1]['id']])
        return Action.model_validate(value)
    return choose


def run_agent(tmp_path, handler, plans=(), config=None):
    async def execute():
        manager = AgentManager(Store(tmp_path / 'agent.db'), planner(*plans), httpx.MockTransport(handler))
        run_id = manager.create(config or spec())
        await manager.tasks[run_id]
        return manager, manager.snapshot(run_id)
    return asyncio.run(execute())


def test_observe_probe_persists_chain_and_counts(tmp_path):
    manager, run = run_agent(tmp_path, lambda r: httpx.Response(200, text='normal'),
        [{'kind': 'probe', 'hypothesis': '반사 여부', 'category': 'xss', 'param': 'id', 'payload': '<svg onload=alert(1)>'}])
    assert run['state'] == 'completed'
    assert run['data']['requests'] == 4
    assert run['data']['ai_calls'] == 2
    observations = [e for e in run['events'] if e['kind'] == 'observation']
    verifications = [e for e in run['events'] if e['kind'] == 'verification']
    assert len(verifications[0]['data']['evidence_ids']) == 3
    assert set(verifications[0]['data']['evidence_ids']) <= {e['id'] for e in observations}
    assert Store(manager.store.path).events(run['id']) == run['events']


def test_redirect_is_recorded_but_not_followed(tmp_path):
    requested = []
    def handler(req):
        requested.append(str(req.url))
        return httpx.Response(302, headers={'location': 'https://outside.test/private'})
    _, run = run_agent(tmp_path, handler)
    assert len(requested) == 1
    assert len(run['data']['endpoints']) == 1


def test_discovery_provenance_is_persisted_without_fetching_links(tmp_path):
    requested = []
    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(200, text='<a href="/next">next</a><a href="https://outside.test/">outside</a>',
                              headers={'content-type': 'text/html'})
    manager, run = run_agent(tmp_path, handler)
    assert len(requested) == 1
    discoveries = [e for e in run['events'] if e['kind'] == 'discovery']
    assert len(discoveries) == 1
    item = discoveries[0]
    observation = next(e for e in run['events'] if e['id'] == item['data']['source_observation_id'])
    assert observation['kind'] == 'observation'
    assert observation['step_id'] == item['step_id']
    assert run['data']['endpoints'][item['data']['endpoint_id']]['url'] == 'https://app.test/next'
    assert Store(manager.store.path).events(run['id']) == run['events']


def test_discovery_cap_is_reported_and_does_not_expand_request_budget(tmp_path):
    html = ''.join(f'<a href="/item/{i}">item</a>' for i in range(50))
    _, run = run_agent(tmp_path, lambda request: httpx.Response(200, text=html, headers={'content-type': 'text/html'}))
    assert len(run['data']['endpoints']) == 40
    assert run['data']['requests'] == 1
    assert len([e for e in run['events'] if e['kind'] == 'discovery']) == 39
    limit = next(e for e in run['events'] if e['kind'] == 'discovery_limit')
    assert limit['data'] == {'limit': 40, 'skipped': 11}


def test_request_budget_rejects_incomplete_test_before_http(tmp_path):
    _, run = run_agent(tmp_path, lambda r: httpx.Response(200, text='OK'),
        [{'kind': 'probe', 'hypothesis': '입력 확인', 'category': 'sqli', 'param': 'id', 'payload': "'"}] * 3,
        spec(max_requests=2))
    assert run['state'] == 'limited'
    assert run['data']['requests'] == 1
    assert not any(e['kind'] == 'verification' for e in run['events'])


def test_unauthorized_object_requires_known_policy_and_two_reads(tmp_path):
    policy = {'id': 'orderB', 'url': 'https://app.test/orders/42', 'owner_actor': 'B',
              'identity_pointer': '/id', 'identity_value': '42', 'description': '소유자만 조회 가능'}
    cfg = spec(actors=[{'id': 'A', 'headers': {'Authorization': 'Bearer AAA'}},
                       {'id': 'B', 'headers': {'Authorization': 'Bearer BBB'}}], objects=[policy])
    seen = []
    def handler(req):
        seen.append(req.headers.get('authorization'))
        return httpx.Response(200, json={'id': 42, 'owner': 'B'})
    _, run = run_agent(tmp_path, handler, [{'kind': 'access', 'hypothesis': '타인 주문 접근',
                                        'actor_id': 'A', 'object_id': 'orderB'}], cfg)
    ver = next(e['data'] for e in run['events'] if e['kind'] == 'verification')
    assert ver['status'] == 'confirmed'
    assert seen == ['Bearer AAA', 'Bearer BBB', 'Bearer AAA', 'Bearer AAA']
    assert 'Bearer AAA' not in json.dumps(run)
    assert 'Bearer BBB' not in json.dumps(run)


def test_wrong_identity_or_permitted_actor_never_idor():
    policy = {'id': 'x', 'owner_actor': 'B', 'allowed_actors': ['A'],
              'identity_pointer': '/id', 'identity_value': '42', 'description': '공유 객체'}
    observations = [{'id': str(i), 'response': {'status': 200, 'body': '{"id":42}'}} for i in range(3)]
    assert access_verdict(policy, 'A', observations)['status'] == 'inconclusive'
    policy['allowed_actors'] = []
    observations[2]['response']['body'] = '{"id":43}'
    assert access_verdict(policy, 'A', observations)['status'] == 'inconclusive'


def test_cookie_rotation_and_actor_isolation(tmp_path):
    seen = []
    def handler(req):
        seen.append(req.headers.get('cookie'))
        return httpx.Response(200, text='OK', headers={'set-cookie': 'sid=rotated; Path=/; Secure'})
    cfg = spec(request={'url': 'https://app.test/?id=1', 'headers': {'Cookie': 'sid=initial'}},
               actors=[{'id': 'A'}, {'id': 'B'}])
    _, run = run_agent(tmp_path, handler, [
        {'kind': 'observe', 'hypothesis': '다른 계정', 'actor_id': 'B'},
        {'kind': 'probe', 'hypothesis': '세션 유지', 'actor_id': 'A', 'category': 'sqli', 'param': 'id', 'payload': 'x'}], cfg)
    assert seen[:3] == ['sid=initial', None, 'sid=rotated']
    assert 'sid=initial' not in json.dumps(run)


def test_outside_and_unknown_fields_are_rejected():
    with pytest.raises(ValueError):
        origin('https://user:pass@app.test/')
    with pytest.raises(ValueError):
        spec(objects=[{'id': 'x', 'url': 'https://outside.test/', 'owner_actor': 'current',
                       'identity_pointer': '/id', 'identity_value': '1', 'description': 'x'}])
    with pytest.raises(ValueError):
        inject({'url': 'https://app.test/?id=1', 'params': {}, 'headers': {}, 'body': ''},
               Action(kind='probe', hypothesis='test', param='invented', payload='x'))


def test_hallucinated_evidence_pauses(tmp_path):
    _, run = run_agent(tmp_path, lambda r: httpx.Response(200, text='OK'),
        [{'kind': 'finish', 'hypothesis': '완료', 'basis': ['other-run-evidence']}])
    assert run['state'] == 'paused'
    assert run['data']['requests'] == 1


def test_cancel_and_resume_retains_evidence_and_budget(tmp_path):
    async def scenario():
        ready = asyncio.Event()
        async def blocked(ctx):
            ready.set()
            await asyncio.Event().wait()
        manager = AgentManager(Store(tmp_path / 'agent.db'), blocked,
                               httpx.MockTransport(lambda r: httpx.Response(200, text='OK')))
        run_id = manager.create(spec())
        await ready.wait()
        stopped = await manager.stop(run_id)
        assert stopped['state'] == 'paused'
        assert stopped['conclusion']['completion'] == 'partial'
        assert stopped['events'][-1]['kind'] == 'conclusion'
        assert stopped['data']['ai_calls'] == 1
        manager.planner = planner()
        manager.start(run_id)
        await manager.tasks[run_id]
        result = manager.snapshot(run_id)
        assert result['state'] == 'completed'
        assert result['data']['requests'] == 1
        assert result['data']['ai_calls'] == 2
    asyncio.run(scenario())


def test_recovery_requires_credentials_without_storing_them(tmp_path):
    async def scenario():
        cfg = spec(request={'url': 'https://app.test/', 'headers': {'Authorization': 'Bearer secret'}})
        manager = AgentManager(Store(tmp_path / 'agent.db'), planner(),
                               httpx.MockTransport(lambda r: httpx.Response(200, text='OK')))
        run_id = manager.create(cfg)
        await manager.tasks[run_id]
        data = manager.store.get(run_id)['data']
        manager.store.update(run_id, data, 'running')
        other = AgentManager(Store(manager.store.path))
        other.store.recover()
        assert other.snapshot(run_id)['state'] == 'interrupted'
        with pytest.raises(ValueError, match='세션'):
            other.start(run_id)
    asyncio.run(scenario())


def test_ordinary_dialog_is_not_xss_proof():
    assert not marker_executed([['alert', 'hello']], 'unique_test_marker')
    assert not marker_executed([['alert', '1']], '')
    assert marker_executed([['alert', 'unique_test_marker']], 'unique_test_marker')


def test_discovery_keeps_only_same_origin_links_and_get_forms():
    result = discover({'url': 'https://app.test/'}, {'body': '<a href="/next">next</a><a href="https://other.test/">other</a>'
                      '<form action="/search"><input name="q" value="hello"></form>',
                      'headers': {'content-type': 'text/html'}})
    assert len(result) == 2
    assert result[1]['url'] == 'https://app.test/search?q=hello'
