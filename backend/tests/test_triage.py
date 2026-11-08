import json
import pytest
from core.triage import analyze, MAX_BYTES


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
    with pytest.raises(ValueError): analyze('x'*(MAX_BYTES+1))


def test_default_input_limits_are_20mb_100k():
    import os
    from core.triage import MAX_BYTES as mb, MAX_RECORDS as mr, MAX_MB as m
    if not os.getenv('TRIAGE_MAX_BYTES'):
        assert mb == 20_000_000 and m == 20
    if not os.getenv('TRIAGE_MAX_RECORDS'):
        assert mr == 100_000


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
            assert (await client.post('/api/triage/analyze',content='x'*(MAX_BYTES+1))).status_code==413
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


def test_sensor_host_does_not_override_http_target_or_dst():
    import json
    from core.triage import analyze
    rows = [
        dict(device_type='IDS', host='sensor.test', dst='192.0.2.10', layer_7_data='HTTP Host == app.test;;;HTTP URI == /login;;;'),
        dict(device_type='IPS', host='sensor.test', dst='192.0.2.20', evtname='Port Scan'),
        dict(device_type='IPS', host='sensor.test', http_hostname='other.test', url='/x'),
    ]
    events = analyze(json.dumps(rows))['events']
    assert events[0]['host'] == 'app.test'
    assert events[1]['host'] == '' and events[1]['destination'] == '192.0.2.20'
    assert events[2]['host'] == 'other.test'


def test_uds_block_pattern_is_excluded_before_analysis():
    import json
    from core.triage import analyze
    result = analyze(json.dumps([
        dict(evtname='UDS_SCAN_Block'),
        dict(evtname='uds_http_block', host='a.test', url='/x'),
        dict(evtname='UDS_SCAN_Permit', host='a.test', url='/x'),
        dict(evtname='Other_Block', host='b.test', url='/x'),
    ]))
    assert result['summary']['excluded_detections'] == 2
    assert result['summary']['parsed'] == 2
    assert result['statistics']['total'] == 2
    assert not result['unsupported']
    assert [e['event_name'] for e in result['events']] == ['UDS_SCAN_Permit', 'Other_Block']


def _src(**row):
    return analyze(json.dumps([{**dict(host='a.test', url='/x', method='GET'), **row}]))['events'][0]['source']


def test_source_is_connection_src_when_no_proxy():
    assert _src(src='203.0.113.9') == '203.0.113.9'
    assert _src(source_ip='203.0.113.9') == '203.0.113.9'


def test_source_strips_port_and_drops_placeholders():
    assert _src(src='203.0.113.9:51234') == '203.0.113.9'
    # N/A / 0.0.0.0 are not real sources: fall through, not counted as distinct values
    assert _src(src='N/A', source_ip='203.0.113.9') == '203.0.113.9'
    assert _src(src='0.0.0.0', source_ip='203.0.113.9') == '203.0.113.9'
    assert _src(src='N/A') == ''


def test_hostname_source_is_kept_verbatim():
    assert _src(src='scanner.example.test') == 'scanner.example.test'


def test_xff_leftmost_wins_over_proxy_src():
    # Proxy/LB-fronted sensor: connection src is the proxy, true client is XFF-leftmost.
    assert _src(src='10.9.194.72', xff='23.227.167.225,34.110.173.207,10.9.180.0') == '23.227.167.225'
    assert _src(src='34.96.13.2', x_forwarded_for='23.227.167.225') == '23.227.167.225'


def test_xff_recovered_from_raw_headers_and_packet_capture():
    import base64
    assert _src(src='34.96.13.2', Header_Value='Via: 1.1 google\nX-Forwarded-For: 23.227.167.225\n') == '23.227.167.225'
    packet = base64.b64encode(
        b'GET / HTTP/1.1\r\nhost: a.test\r\nx-forwarded-for: 23.227.167.225,34.160.180.79\r\n\r\n').decode()
    assert _src(src='34.96.13.2', TrendMicroDsPacketData=packet) == '23.227.167.225'


def test_device_resolved_client_beats_spoofed_packet_xff():
    # Scanner spoofs an XFF header in the request body; the device-resolved pre-NAT
    # address is authoritative and must win so a spoofed value is not a second source.
    import base64
    packet = base64.b64encode(
        b'GET / HTTP/1.1\r\nx-forwarded-for: 172.56.152.138,34.160.180.79\r\n\r\n').decode()
    assert _src(src='34.96.13.2', sourceTranslatedAddress='23.227.167.225',
                TrendMicroDsPacketData=packet) == '23.227.167.225'
    assert _src(src='34.96.13.2', client_ip='23.227.167.225') == '23.227.167.225'


def test_one_client_behind_mixed_devices_aggregates_to_one_source():
    # Same external client across IDS (direct src), IPS (xff field), WAF (header xff).
    rows = [
        dict(device_type='IDS', evtname='x', host='a.test', url='/a', source_ip='23.227.167.225'),
        dict(device_type='IPS', evtname='x', host='a.test', url='/b', src='10.9.194.72', xff='23.227.167.225,34.1.1.1'),
        dict(device_type='WAF', evtname='x', host='a.test', url='/c', src='34.96.13.2',
             Header_Value='X-Forwarded-For: 23.227.167.225'),
    ]
    sources = {e['source'] for e in analyze(json.dumps(rows))['events']}
    assert sources == {'23.227.167.225'}


def test_host_default_port_is_normalized_but_other_ports_kept():
    # Same asset logged with and without the default port must aggregate as one host.
    rows = [dict(httpHost=h, url='/x', method='GET')
            for h in ('a.test', 'a.test:443', 'a.test:80')]
    assert {e['host'] for e in analyze(json.dumps(rows))['events']} == {'a.test'}
    # A non-default port genuinely distinguishes a service and is preserved.
    assert analyze(json.dumps([dict(httpHost='a.test:8080', url='/x', method='GET')]))['events'][0]['host'] == 'a.test:8080'
