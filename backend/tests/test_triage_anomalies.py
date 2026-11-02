import json

from core.triage import analyze
from core.triage_anomalies import summarize_anomalies
from core.triage_summary import refresh_attack_summary


def record(path, **extra):
    return dict(host='app.test', src='192.0.2.1', timestamp='2026-11-02T01:01:00Z',
                method='GET', url=path, evtname='File scan', device_type='WAF',
                status=404, act='Permit', dport=443, **extra)


def parse(records):
    return analyze(json.dumps(records))


def rules(result):
    return {f['rule']: f for f in result['anomaly_analysis']['findings']}


def test_failed_scans_are_evidence_but_only_exception_is_candidate():
    rows = [record('/scan/' + str(i)) for i in range(3)]
    rows.append({**record('/backup.zip'), 'status': 200})
    result = parse(rows)
    finding = rules(result)['scan_response']
    assert len(finding['event_ids']) == 4
    assert finding['candidate_ids'] == [result['events'][-1]['id']]
    assert result['screening_summary'] == {'screened': 3, 'actionable': 1}
    assert finding['outcome'] == '공격 성공 여부 미확인'
    json.dumps(result)


def test_response_difference_does_not_join_clients_or_unknown_times():
    rows = [record('/scan/' + str(i)) for i in range(3)]
    rows.append({**record('/backup.zip'), 'status': 200, 'src': '192.0.2.2'})
    assert 'scan_response' not in rules(parse(rows))
    for row in rows:
        row['timestamp'] = '2026-11-02T01:01:00'
    result = parse(rows)
    assert result['anomaly_analysis']['coverage']['missing_time'] == 4
    assert not rules(result)


def test_mixed_action_requires_same_path_and_device_kind():
    rows = [{**record('/a'), 'act': 'Block'}, record('/b')]
    assert 'mixed_action' not in rules(parse(rows))
    rows[1]['url'] = '/a'
    assert 'mixed_action' in rules(parse(rows))
    rows[1]['device_type'] = 'IDS'
    assert 'mixed_action' not in rules(parse(rows))


def test_sequence_uses_timestamps_not_input_order_and_respects_window():
    probe = record('/scan')
    attack = {**record('/x?id=1%20UNION%20SELECT%20password'), 'timestamp': '2026-11-02T01:02:00Z',
              'status': 200}
    assert 'scan_to_attack' in rules(parse([attack, probe]))
    attack['timestamp'] = '2026-11-02T01:00:00Z'
    assert 'scan_to_attack' not in rules(parse([probe, attack]))
    attack['timestamp'] = '2026-11-02T02:02:00Z'
    assert 'scan_to_attack' not in rules(parse([probe, attack]))


def test_error_sensitive_and_fanout_rules_and_inventory_priority():
    errors = [{**record('/x?id=1%20UNION%20SELECT%20password'), 'status': 500} for _ in range(3)]
    result = parse(errors)
    assert 'attack_errors' in rules(result)
    result['events'][0]['reasons'].append('IMPORTANT_ASSET')
    refresh_attack_summary(result)
    assert rules(result)['attack_errors']['priority'] == 'high'
    assert 'sensitive_probe' in rules(parse([record('/.env') for _ in range(3)]))
    rows = [{**record('/scan'), 'host': f'{i}.test'} for i in range(3)]
    assert 'multi_target_scan' in rules(parse(rows))
    rows = [{**record(f'/scan/{i}'), 'src': f'192.0.2.{i % 3 + 1}'} for i in range(5)]
    assert 'distributed_scan' in rules(parse(rows))


def test_conflicting_targets_are_not_correlated_and_empty_is_supported():
    result = parse([record('/scan')])
    event = result['events'][0]
    event['reasons'].append('HOST_CONFLICT')
    answer = summarize_anomalies([event])
    assert answer['coverage']['missing_target'] == 1
    assert not answer['findings']
    assert not summarize_anomalies([])['findings']
