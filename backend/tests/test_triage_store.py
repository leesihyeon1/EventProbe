import asyncio
import json
import time
import pytest
from core.triage import analyze
from core.triage_store import TriageStore

LOG='act=Permit dhost=example.test request=/x requestMethod=GET'
CSV='origin,service,contact,importance,stack,environment,verified_at\nhttps://example.test,Portal,SOC,high,nginx,prod,2026-01-01T00:00:00+09:00'


def test_opt_in_duplicate_overlap_and_owner_scope(tmp_path):
    store=TriageStore(tmp_path/'triage.db')
    r=analyze(LOG)
    a=store.save('alice',LOG,r,7)
    duplicate=store.save('alice',LOG,r,30)
    assert duplicate['id']==a['id'] and duplicate['expires']==a['expires']
    assert duplicate['duplicate']
    second=store.save('alice',LOG+'\n',r,7)
    assert second['overlap_events']==1
    assert store.batches('bob')==[]
    with pytest.raises(KeyError):store.batch('bob',a['id'])
    assert not store.delete('bob',a['id'])
    assert store.batch('alice',a['id'])['persisted']
    assert store.delete('alice',a['id'])
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM triage_event_refs WHERE batch_id=?',(a['id'],)).fetchone()[0]==0


def test_expiration_removes_raw_and_refs(tmp_path):
    store=TriageStore(tmp_path/'triage.db');a=store.save('alice',LOG,analyze(LOG),1)
    with store.connect() as db:db.execute('UPDATE triage_batches SET expires=0')
    store.cleanup()
    assert store.batches('alice')==[]
    with store.connect() as db:assert db.execute('SELECT COUNT(*) FROM triage_event_refs').fetchone()[0]==0


def test_inventory_is_atomic_and_scoped(tmp_path):
    store=TriageStore(tmp_path/'triage.db')
    assert store.import_inventory('alice',CSV)==1
    assert store.inventory('bob')==[]
    with pytest.raises(ValueError):store.import_inventory('alice',CSV+'\nhttps://other.test,X,Y,invalid,N,prod,broken')
    assert len(store.inventory('alice'))==1
    assert not store.delete_inventory('bob','https://example.test')
    assert store.delete_inventory('alice','https://example.test')


def test_stale_and_missing_inventory_never_downrank(tmp_path):
    store=TriageStore(tmp_path/'triage.db');store.import_inventory('alice',CSV)
    r=store.enrich('alice',analyze(LOG))
    assert r['events'][0]['inventory']['stale']
    assert r['events'][0]['priority']=='information'
    assert 'INVENTORY_STALE' in r['events'][0]['reasons']
    r=store.enrich('bob',analyze(LOG))
    assert r['events'][0]['inventory'] is None and r['events'][0]['priority']=='information'


def test_fresh_important_asset_promotes_review(tmp_path):
    from datetime import datetime,timezone
    store=TriageStore(tmp_path/'triage.db')
    store.import_inventory('alice',CSV.replace('2026-01-01T00:00:00+09:00',datetime.now(timezone.utc).isoformat()))
    r=store.enrich('alice',analyze(LOG))
    assert r['summary']['review']==1 and r['summary']['information']==0


def test_api_save_load_delete_and_inventory(tmp_path,monkeypatch):
    import httpx
    from fastapi import FastAPI
    from routers.triage import router
    monkeypatch.setenv('TRIAGE_DB_PATH',str(tmp_path/'api.db'))
    app=FastAPI();app.include_router(router)
    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test',headers={'x-eventprobe-user':'alice'}) as client:
            r=await client.post('/api/triage/batches',content=LOG)
            assert r.status_code==201
            bid=r.json()['id']
            assert (await client.post('/api/triage/batches?days=0',content=LOG)).status_code==422
            assert (await client.get('/api/triage/batches/'+bid,headers={'x-eventprobe-user':'bob'})).status_code==404
            assert (await client.get('/api/triage/batches/'+bid)).json()['persisted']
            assert (await client.post('/api/triage/inventory',content=CSV)).json()['imported']==1
            assert len((await client.get('/api/triage/inventory')).json()['assets'])==1
            assert (await client.delete('/api/triage/batches/'+bid)).status_code==200
            assert (await client.get('/api/triage/batches')).json()['batches']==[]
    asyncio.run(check())
