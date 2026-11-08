"""Model configuration requires the real access boundary, never a workspace name."""
import asyncio
import json

import httpx
from fastapi import FastAPI

from core import agent as agent_module
from core.agent import AgentManager
from core.agent_store import Store
from routers.model_profiles import router


def test_configuration_auth_revision_and_credential_free_responses(tmp_path, monkeypatch):
    store = Store(tmp_path / 'routes.db')
    manager = AgentManager(store)
    monkeypatch.setattr(agent_module, '_manager', manager)
    monkeypatch.setenv('EVENTPROBE_TOKEN', 'synthetic-server-access')
    monkeypatch.setenv('EVENTPROBE_MODEL_TEST', 'synthetic-provider-secret')
    app = FastAPI()
    app.include_router(router, prefix='/api/agent')
    body = {'name': 'synthetic', 'model': 'synthetic', 'base_url': 'https://model.example.invalid/v1',
            'key_env': 'EVENTPROBE_MODEL_TEST'}
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            assert (await client.post('/api/agent/model-profiles', json=body,
                                      headers={'x-eventprobe-user': 'admin'})).status_code == 403
            headers = {'x-access-token': 'synthetic-server-access'}
            response = await client.post('/api/agent/model-profiles', json=body, headers=headers)
            assert response.status_code == 201
            saved = response.json()
            assert saved['key_configured']
            assert 'synthetic-provider-secret' not in response.text
            profile_id = saved['id']
            route = '/api/agent/model-profiles/' + profile_id
            change = {'profile': {**body, 'name': 'updated'}, 'expected_revision': 1}
            assert (await client.put(route, json=change, headers=headers)).json()['revision'] == 2
            assert (await client.put(route, json=change, headers=headers)).status_code == 409
            assert (await client.delete(route + '?expected_revision=2', headers=headers)).status_code == 200
    asyncio.run(scenario())


def test_remote_without_token_cannot_change_profiles(tmp_path, monkeypatch):
    monkeypatch.delenv('EVENTPROBE_TOKEN', raising=False)
    monkeypatch.setattr(agent_module, '_manager', AgentManager(Store(tmp_path / 'remote.db')))
    app = FastAPI()
    app.include_router(router)
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('192.0.2.1', 1)),
                                    base_url='http://test') as client:
            result = await client.post('/model-profiles', json={
                'name': 'n', 'model': 'm', 'base_url': 'https://example.invalid/v1'})
            assert result.status_code == 403
    asyncio.run(scenario())


def test_chain_and_usage_are_owner_guarded_and_readonly_imports_cannot_change(tmp_path, monkeypatch):
    store = Store(tmp_path / 'owner.db')
    manager = AgentManager(store)
    monkeypatch.setattr(agent_module, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    rid = store.create({'spec': {'goal': 'synthetic'}, 'owner': 'alice'})
    app = FastAPI()
    app.include_router(router)
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            for tail in ('model-chain', 'model-calls'):
                assert (await client.get(f'/runs/{rid}/{tail}', headers={'x-eventprobe-user': 'bob'})).status_code == 403
            path = f'/runs/{rid}/model-chain'
            body = {'expected_revision': 0, 'profile_ids': []}
            assert (await client.put(path, json=body, headers={'x-eventprobe-user': 'alice'})).status_code == 200
            assert (await client.put(path, json=body, headers={'x-eventprobe-user': 'alice'})).status_code == 409
            data = store.get(rid)['data']
            data['restored_at'] = 1
            store.update(rid, data)
            body['expected_revision'] = 1
            assert (await client.put(path, json=body, headers={'x-eventprobe-user': 'alice'})).status_code == 409
    asyncio.run(scenario())
