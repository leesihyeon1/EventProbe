import json

from core.triage import analyze
from core.triage_statistics import device_kind


def test_device_event_family_and_response_statistics():
    records = [
        {'device_type': 'WAF', 'evtname': 'Environment file access', 'httpHost': 'web.test',
         'url': '/.env', 'method': 'GET', 'disposition': 'Block', 'resultCode': '404', 'occurrences': '13'},
        {'device_type': 'IDS', 'evtname': 'ZGrab scanner', 'destination_ip': '192.0.2.10',
         'src_ip': '203.0.113.1', 'result_status': 'Inconclusive'},
        {'device_type': 'IPS', 'evtname': 'Port Scan', 'dst': '192.0.2.11',
         'src': '203.0.113.2', 'act': 'Permit'},
        {'device_type': 'WAF', 'evtname': 'SQL injection', 'httpHost': 'web.test',
         'url': '/search?q=1 UNION SELECT password FROM users', 'method': 'GET',
         'disposition': 'Permit', 'resultCode': '200'},
    ]
    result = analyze(json.dumps(records))
    stats = result['statistics']
    assert result['summary']['parsed'] == 4
    assert stats['total'] == 4
    assert stats['event_names'][0] == {'label': 'Environment file access', 'count': 1}
    assert {x['label']: x['count'] for x in stats['families']} == {
        '정보 수집성': 1, '웹 공격': 1, '네트워크 공격': 2}
    assert stats['targets'][0] == {'label': 'web.test', 'count': 2}
    waf = next(d for d in stats['devices'] if d['name'] == 'WAF')
    assert waf['actions'] == {'blocked': 1, 'allowed': 1}
    assert waf['http_status'] == [{'label': '200', 'count': 1}, {'label': '404', 'count': 1}]
    ids = next(d for d in stats['devices'] if d['name'] == 'IDS')
    assert ids['http_status'] == [{'label': 'HTTP 응답 미기록', 'count': 1}]
    assert ids['response_result'] == [{'label': 'Inconclusive', 'count': 1}]
    assert result['events'][1]['path'] == ''
    assert result['events'][1]['destination'] == '192.0.2.10'


def test_bounded_top_items_and_correlation_candidates():
    records = []
    for index in range(12):
        records.append({'device_type': 'IPS', 'evtname': f'Event {index}',
                        'dst': f'192.0.2.{index+1}', 'src': '203.0.113.10',
                        'url': f'/path/{index}', 'method': 'GET'})
    stats = analyze(json.dumps(records))['statistics']
    assert len(stats['event_names']) == 11
    assert stats['event_names'][-1] == {'label': '기타', 'count': 2}
    assert len(stats['targets']) == 11
    assert stats['correlations'][0]['type'] == 'multi_target_source'
    assert stats['correlations'][0]['count'] == 12


def test_unknown_device_is_not_assigned_to_ids_and_pathless_audit_still_unsupported():
    result = analyze(json.dumps([
        {'evtname': 'SQL injection', 'host': 'web.test', 'url': '/?q=1'},
        {'Operation': 'MailItemsAccessed', 'destination_ip': '192.0.2.1'},
    ]))
    assert result['summary']['parsed'] == 1
    assert result['summary']['unsupported'] == 1
    assert result['statistics']['devices'][0]['name'] == '미확인'
    assert device_kind({'deviceProduct': 'TippingPoint UnityOne'}) == 'IPS'


def test_device_raw_actions_and_nested_ids_response_codes():
    from core.triage import analyze
    import json
    rows = [
        dict(device_type='IPS', host='a.test', url='/x', act='Permit'),
        dict(device_type='WAF', host='a.test', url='/x', act='None'),
        dict(device_type='WAF', host='a.test', url='/x'),
        dict(device_type='IDS', layer_7_data='HTTP URI == /x;;;HTTP Host == a.test;;;HTTP Return Code == 302 Found;;;', result_status='Inconclusive'),
        dict(device_type='IDS', host='a.test', url='/x', status='Inconclusive', http_status='404'),
    ]
    result = analyze(json.dumps(rows))
    devices = {d['name']: d for d in result['statistics']['devices']}
    assert devices['IPS']['action_values'] == [{'label': 'Permit', 'count': 1}]
    assert {v['label'] for v in devices['WAF']['action_values']} == {'None', '처리 값 미기록'}
    assert {v['label'] for v in devices['IDS']['http_status']} == {'302', '404'}
    assert result['events'][1]['action'] == 'unknown'


def test_product_vulnerability_precedes_web_technique_or_disclosure():
    from core.triage_statistics import event_family
    assert event_family(dict(products=['cisco-asa'], category='lfi', event_name='Directory Traversal')) == '애플리케이션 공격'
    assert event_family(dict(products=['exchange'], category='ssrf')) == '애플리케이션 공격'
    assert event_family(dict(products=['confluence'], event_name='Information Disclosure')) == '애플리케이션 공격'
    assert event_family(dict(cve=['CVE-2099-1234'], category='sqli')) == '애플리케이션 공격'
    assert event_family(dict(category='sqli')) == '웹 공격'
    assert event_family(dict(event_name='Port Scan', device='IPS')) == '네트워크 공격'
