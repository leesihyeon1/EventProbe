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


def test_ips_block_is_screened_but_mixed_and_important_are_retained():
    assert screen_event(event(device='IPS', action='blocked'))['code'] == 'IPS_BLOCKED'
    assert not screen_event(event(device='IPS', action='blocked', reasons=['MIXED_ALLOWED_BLOCKED']))['screened']
    assert not screen_event(event(device='IPS', action='blocked', reasons=['IMPORTANT_ASSET']))['screened']


def test_only_proven_origin_404_410_simple_scan_is_screened():
    assert screen_event(event())['code'] == 'ORIGIN_NOT_FOUND_SCAN'
    assert screen_event(event(status=410))['screened']
    for changes in (dict(status=403), dict(status_source='unknown'), dict(status_source='edge'),
                    dict(path='/.env?x=1'), dict(method='POST'), dict(reasons=['HOST_CONFLICT'])):
        assert not screen_event(event(**changes))['screened']


def test_technology_positive_match_retains_event_without_claiming_absence():
    matched = event(path='/wp-login.php', category='', technologies=['WordPress'])
    assert screen_event(matched)['code'] == 'TECH_MATCH'
    # A missing WordPress fingerprint never proves WordPress is absent.
    unknown = event(path='/wp-login.php', category='', technologies=['Next.js'], status_source='unknown')
    assert not screen_event(unknown)['screened']


def test_analyze_preserves_screened_events_in_statistics_and_export():
    result = analyze(json.dumps([
        dict(device_type='IPS', evtname='Port Scan', host='a.test', url='/x', act='Block'),
        dict(device_type='WAF', evtname='File scan', host='b.test', url='/.env',
             method='GET', act='Permit', status=404, response_source='origin'),
        dict(device_type='WAF', evtname='File scan', host='c.test', url='/.env',
             method='GET', act='Permit', status=404),
    ]))
    assert result['summary']['parsed'] == result['statistics']['total'] == 3
    assert [e['screening']['screened'] for e in result['events']] == [True, True, False]
    assert result['screening_summary'] == {'screened': 2, 'actionable': 1}
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
