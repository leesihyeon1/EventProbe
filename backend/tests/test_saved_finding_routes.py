"""Preserved evidence is authorized independently of a deleted source run."""
import asyncio
import io
import zipfile

import httpx
from fastapi import FastAPI

from core import agent as agent_module
from core.agent import AgentManager
from core.agent_store import Store
from routers.saved_findings import router
from test_saved_evidence import source


def setup(tmp_path, monkeypatch):
    store = Store(tmp_path / 'routes.db')
    manager = AgentManager(store, transport=httpx.MockTransport(lambda r: httpx.Response(200, text='synthetic')))
    monkeypatch.setattr(agent_module, '_manager', manager)
    monkeypatch.setenv('AGENT_SCOPE_OWNER', '1')
    app = FastAPI()
    app.include_router(router, prefix='/api/agent')
    return store, manager, app


def test_preserve_lazy_body_export_and_acl_survive_source_deletion(tmp_path, monkeypatch):
    store, manager, app = setup(tmp_path, monkeypatch)
    rid, fid, _ = source(store)
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test',
                                     headers={'x-eventprobe-user': 'alice'}) as client:
            response = await client.post(f'/api/agent/runs/{rid}/findings/{fid}/preserve', json={})
            assert response.status_code == 200
            saved_id = response.json()['id']
            path = '/api/agent/saved-findings/' + saved_id
            detail = await client.get(path)
            assert detail.status_code == 200
            assert 'PRIVATE_EVIDENCE_BODY' not in detail.text
            assert 'private-query-value' not in detail.text
            sid = next(e['id'] for e in detail.json()['evidence'] if e['kind'] == 'observation')
            await manager.delete(rid)
            assert (await client.get(path)).status_code == 200
            body = await client.get(path + '/evidence/' + sid)
            assert body.json()['data']['response']['body'] == 'PRIVATE_EVIDENCE_BODY'
            assert (await client.get(path, headers={'x-eventprobe-user': 'bob'})).status_code == 403
            assert (await client.get(path+'/evidence/'+sid, headers={'x-eventprobe-user': 'bob'})).status_code == 403
            assert (await client.get(path+'/archive.zip', headers={'x-eventprobe-user': 'bob'})).status_code == 403
            report = await client.get(path+'/report')
            assert report.status_code == 200 and 'PRIVATE_EVIDENCE_BODY' not in report.text
            redacted = await client.get(path+'/evidence.zip')
            with zipfile.ZipFile(io.BytesIO(redacted.content)) as archive:
                assert b'PRIVATE_EVIDENCE_BODY' not in b''.join(archive.read(n) for n in archive.namelist())
            assert (await client.get('/api/agent/saved-findings', headers={'x-eventprobe-user': 'bob'})).json()['total'] == 0
            patch = await client.patch(path, json={'expected_revision': 1, 'status': 'triaged'})
            assert patch.status_code == 200 and patch.json()['revision'] == 2
            assert (await client.delete(path+'?expected_revision=1')).status_code == 409
            assert (await client.delete(path+'?expected_revision=2')).status_code == 200
    asyncio.run(scenario())


def test_saved_retest_after_source_delete_uses_new_session_and_keeps_original_verdict(tmp_path, monkeypatch):
    store, manager, app = setup(tmp_path, monkeypatch)
    rid, fid, _ = source(store)
    saved = store.preserve_finding(rid, fid, 'alice')
    store.delete(rid)
    sent = []
    manager.transport = httpx.MockTransport(lambda r: (sent.append(r) or httpx.Response(200, text='synthetic')))
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test',
                                     headers={'x-eventprobe-user': 'alice'}) as client:
            path = '/api/agent/saved-findings/' + saved['id']
            response = await client.post(path+'/retest', json={})
            assert response.status_code == 200, response.text
            new_id = response.json()['id']
            await manager.tasks[new_id]
            assert manager.snapshot(new_id)['data']['ai_calls'] == 0
            assert store.saved_finding(saved['id'])['finding']['verdict'] == 'confirmed'
            history = (await client.get(path+'/retests')).json()
            assert history['items'][0]['run_id'] == new_id
            assert history['items'][0]['evidence_available']
            await manager.delete(new_id)
            history = (await client.get(path+'/retests')).json()
            assert not history['items'][0]['evidence_available']
            await manager.shutdown()
    asyncio.run(scenario())
    assert sent
    assert all('synthetic-secret' not in str(r.headers) for r in sent)


def test_write_retest_requires_explicit_method_and_body_reentry(tmp_path, monkeypatch):
    store, manager, app = setup(tmp_path, monkeypatch)
    rid, fid, _ = source(store, method='POST', body='password=old-value')
    saved = store.preserve_finding(rid, fid, 'alice')
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test',
                                     headers={'x-eventprobe-user': 'alice'}) as client:
            path = '/api/agent/saved-findings/' + saved['id'] + '/retest'
            assert (await client.post(path, json={})).status_code == 409
            assert (await client.post(path, json={'allow_write_methods': True})).status_code == 409
            assert manager.tasks == {}
    asyncio.run(scenario())


def test_import_requires_workspace_and_never_restores_original_owner_or_execution(tmp_path, monkeypatch):
    store, manager, app = setup(tmp_path, monkeypatch)
    rid, fid, _ = source(store)
    saved = store.preserve_finding(rid, fid, 'alice')
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test',
                                     headers={'x-eventprobe-user': 'alice'}) as client:
            path = '/api/agent/saved-findings/' + saved['id']
            archive = await client.get(path+'/archive.zip')
            await client.delete(path+'?expected_revision=1')
            assert (await client.post('/api/agent/saved-findings/import', content=archive.content,
                                      headers={'x-eventprobe-user': ''})).status_code == 403
            result = await client.post('/api/agent/saved-findings/import', content=archive.content,
                                       headers={'x-eventprobe-user': 'bob'})
            assert result.status_code == 200, result.text
            assert not result.json()['execution_started']
            assert store.saved_finding(saved['id'])['owner'] == 'bob'
            assert manager.tasks == {}
    asyncio.run(scenario())
