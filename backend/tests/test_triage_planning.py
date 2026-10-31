"""Preparation tests never send target requests."""
import pytest
from core.triage_planning import prepare, canonical_request
from core import confirm


def test_plan_preserves_values_and_matches_execution_budget():
    p=prepare('https://example.test/item?id=42','sqli','id','event-1','local evidence')
    assert p['incident']['source']=='siem'
    assert p['incident']['external_id']=='event-1'
    assert p['incident']['request']['params']=={'id':'42'}
    assert p['incident']['request']['url']=='https://example.test/item'
    assert p['max_requests']==min(150,3+2*len(confirm.probe_plan('sqli','')))
    assert p['max_ai_calls']==0


@pytest.mark.parametrize('url',[
    'file:///etc/passwd', 'https://user:secret@example.test/x?id=1',
    'https://example.test/x?id=1&id=2', 'https://example.test/x?id=1#frag',
    'https://example.test/x?id=hello world', 'https://example.test:invalid/x?id=1',
])
def test_ambiguous_or_non_http_url_rejected(url):
    with pytest.raises(ValueError): canonical_request(url)


@pytest.mark.parametrize('category,param,url',[
    ('authbypass','id','https://example.test/x?id=1'),
    ('sqli','missing','https://example.test/x?id=1'),
    ('lfi','','https://example.test/.env'),
])
def test_missing_injection_context_rejected(category,param,url):
    with pytest.raises(ValueError): prepare(url,category,param,'event-1')


def test_prepare_endpoint_and_owner_scoped_asset_lookup(monkeypatch):
    import asyncio
    import httpx
    from fastapi import FastAPI
    from routers.triage import router
    from core import agent
    calls=[]
    class Store:
        def asset_page(self,**kwargs):
            calls.append(kwargs)
            return {'assets':[]}
    class Manager:
        store=Store()
    monkeypatch.setattr(agent,'get_manager',lambda:Manager())
    monkeypatch.setattr(agent,'owner_scope_enabled',lambda:True)
    app=FastAPI();app.include_router(router)
    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
            response=await client.post('/api/triage/prepare',json=dict(url='https://example.test/x?id=1',category='sqli',param='id',event_id='e1'))
            assert response.status_code==200 and response.json()['max_ai_calls']==0
            response=await client.get('/api/triage/asset-match',params={'url':'https://example.test/x?id=1'},headers={'x-eventprobe-user':'alice'})
            assert response.status_code==200 and response.json()['match'] is None
            assert calls[0]['owner']=='alice' and calls[0]['asset_id']
    asyncio.run(check())
