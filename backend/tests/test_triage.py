import json
import pytest
from core.triage import analyze


def test_vendor_action_and_count():
    r=analyze('disposition="Block", action="N/A", httpHost="example.test", url="/.env", webMethod="GET", resultCode="404", occurrences="13"')
    e=r['events'][0]
    assert (e['action'],e['status'],e['occurrences'],e['priority'])==('blocked',404,13,'low')
    assert r['summary']['records']==1
    assert r['target_requests']==0 and not r['persisted']


def test_permit_is_not_blocked():
    e=analyze('CEF:0|TippingPoint|UnityOne|1|1|Curl|1| act=Permit dhost=example.test request=/download requestMethod=GET cnt=1')['events'][0]
    assert e['action']=='allowed' and e['status'] is None and e['priority']=='information'


def test_ids_nested_padding_and_unknown_status():
    e=analyze('attack_name="ZGrab" result_status="Inconclusive" layer_7_data="HTTP Host == example.test;;; HTTP URI == /owa/auth/x.js?x=abc==;;; HTTP Request Method == GET;;;"')['events'][0]
    assert e['path'].endswith('abc==') and e['status'] is None and e['action']=='unknown'


def test_host_conflict_and_errors_are_visible():
    r=analyze('httpHost="example.test", url="/.env", Header-Value=Host: other.test, Accept: */*\nbroken')
    assert 'HOST_CONFLICT' in r['events'][0]['reasons']
    assert len(r['errors'])==1 and r['summary']['records']==2


def test_mixed_evidence_is_not_hidden():
    rows=[dict(host='example.test',url='/x',act=a,timestamp='2026-11-01T01:00:00+09:00') for a in ['Block','Permit']]
    r=analyze(json.dumps(rows))
    assert all(e['priority']=='review' for e in r['events'])


@pytest.mark.parametrize('status',[403,429,500])
def test_not_all_error_statuses_are_low(status):
    e=analyze(json.dumps(dict(host='example.test',url='/x',method='GET',status=status)))['events'][0]
    assert e['priority']!='low'


def test_malformed_and_limits():
    assert analyze('{bad')['summary']['errors']==1
    with pytest.raises(ValueError): analyze('x'*2000001)


def test_unknown_times_do_not_merge_as_campaign():
    r=analyze('act=Block dhost=example.test request=/x\nact=Permit dhost=example.test request=/y')
    assert len(r['groups'])==2


def test_api_is_stateless_and_limits_input(monkeypatch,tmp_path):
    monkeypatch.setenv("TRIAGE_DB_PATH",str(tmp_path/"triage.db"))
    import asyncio
    import httpx
    from fastapi import FastAPI
    from routers.triage import router
    app=FastAPI(); app.include_router(router)
    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
            response=await client.post('/api/triage/analyze',content='act=Permit dhost=example.test request=/x')
            assert response.status_code==200 and response.json()['persisted'] is False
            assert (await client.post('/api/triage/analyze',content=b'\xff')).status_code==422
            assert (await client.post('/api/triage/analyze',content='x'*2000001)).status_code==413
    asyncio.run(check())


def test_siem_csv_arbitrary_header_and_multiline_raw():
    import csv,io
    output=io.StringIO(newline='')
    writer=csv.writer(output)
    writer.writerow(['ActorInfoString','_time','_raw','httpHost'])
    writer.writerow(['','2026-11-01T03:07:55+09:00','disposition="Block", httpHost="example.test", url="/.env", webMethod="GET", Header-Value="Host: example.test\r\nAccept: */*"',''])
    writer.writerow(['','2026-11-01T03:07:55+09:00',json.dumps({'Operation':'MailItemsAccessed'}),''])
    r=analyze('\ufeff'+output.getvalue())
    assert r['summary']['records']==2 and r['summary']['parsed']==1
    assert r['summary']['unsupported']==1 and r['summary']['errors']==0
    assert r['events'][0]['action']=='blocked'
    assert r['events'][0]['window']!='unknown'


def test_csv_extracted_fields_fill_raw_gaps():
    r=analyze('other,_raw,httpHost,url,webMethod\nvalue,"act=Permit",example.test,/x,GET\n')
    assert r['summary']['parsed']==1 and r['events'][0]['host']=='example.test'
