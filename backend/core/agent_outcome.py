"""Deterministic, local run conclusions. Never calls an LLM or reads response bodies."""
from .agent_intent import requested_categories


def build_conclusion(data, events, state):
    observations = {e['id'] for e in events if e['kind'] == 'observation'}
    actions = {e['step_id']: e['data'] for e in events if e['kind'] == 'action'}
    counts = {'confirmed': 0, 'suspicious': 0, 'inconclusive': 0}
    evidence_ids, verified_steps = set(), set()
    verifications = []
    for event in events:
        if event['kind'] != 'verification':
            continue
        verdict = event['data']
        refs = set(verdict.get('evidence_ids') or []) & observations
        status = verdict.get('status', 'inconclusive')
        # A label without linked evidence is not an established finding.
        status = status if refs and status in ('confirmed', 'suspicious') else 'inconclusive'
        counts[status] += 1
        evidence_ids.update(refs)
        verified_steps.add(event['step_id'])
        action = actions.get(event['step_id'], {})
        verifications.append({'id': event['id'], 'status': status,
                              'category': action.get('category') or action.get('kind') or 'verification',
                              'endpoint_id': action.get('endpoint_id') or '',
                              'actor_id': action.get('actor_id') or '',
                              'evidence_ids': sorted(refs)})
    goals = []
    for goal in ((data.get('spec') or {}).get('goals') or []):
        candidates = [v for v in verifications if v['category'] == goal.get('category')
                      and (not goal.get('endpoint_id') or v['endpoint_id'] == goal['endpoint_id'])
                      and (not goal.get('actor_id') or v['actor_id'] == goal['actor_id'])]
        proven = [v for v in candidates if v['evidence_ids'] and
                  (goal.get('completion') == 'tested' or v['status'] == 'confirmed')]
        linked = sorted({eid for v in proven for eid in v['evidence_ids']})
        met = bool(proven)
        goal_status = 'met' if met else 'pending' if state == 'running' else 'unmet'
        goals.append({'id': goal.get('id', ''), 'title': goal.get('title', ''),
                      'category': goal.get('category', ''), 'completion': goal.get('completion', 'tested'),
                      'status': goal_status, 'evidence_ids': linked,
                      'verification_ids': [v['id'] for v in proven],
                      'reason': '' if met else '검증 진행 중입니다.' if state == 'running' else ('연결 증거가 있는 확증 판정이 없습니다.'
                                                 if goal.get('completion') == 'confirmed'
                                                 else '연결 증거가 있는 검증 기록이 없습니다.')})
    unfinished = [e['step_id'] for e in events if e['kind'] == 'action'
                  and e['data'].get('kind') in ('probe', 'confirm', 'access')
                  and e['step_id'] not in verified_steps]
    stop_code = data.get('stop_code', '')
    spec = data.get('spec') or {}
    requested = requested_categories(spec.get('goal', ''), [g['category'] for g in spec.get('goals', [])])
    requested_checks = [{'category': category, 'status': 'tested' if any(
        v['category'] == category and v['evidence_ids'] for v in verifications) else 'not_tested'}
        for category in sorted(requested)]
    missing = [c['category'] for c in requested_checks if c['status'] == 'not_tested']
    legacy_repeat = data.get('reason', '').startswith('동일 행동 반복')
    complete = state == 'completed' and not unfinished and not legacy_repeat and all(g['status'] == 'met' for g in goals)
    if missing or stop_code in ('plan_dead_end', 'planner_stalled', 'plan_loop'):
        complete = False
    outcome = 'confirmed' if counts['confirmed'] else 'suspicious' if counts['suspicious'] else 'inconclusive'
    text = {
        'confirmed': '연결된 증거에서 취약 동작이 확증됐습니다. 확증된 입력과 동작에 한정된 결과입니다.',
        'suspicious': '의심 신호가 있으나 취약성 확증은 완료되지 않았습니다.',
        'inconclusive': '취약성을 확증할 증거가 부족합니다. 안전 판정이 아닙니다.',
    }[outcome]
    if missing:
        text = '요청한 검사 미실행: ' + ', '.join(missing) + '. ' + text
    next_steps = []
    if state == 'running':
        next_steps.append('실행 중인 관측 결과이며 최종 결론이 아닙니다.')
    elif state == 'limited':
        next_steps.append('미완료 검증의 필요 예산과 허용 범위를 검토한 뒤 새 작업으로 이어가세요.')
    elif legacy_repeat:
        next_steps.append('이전 버전에서 반복 행동으로 종료된 작업입니다. 검증 범위를 확인한 뒤 새 작업으로 이어가세요.')
    elif state in ('paused', 'interrupted'):
        next_steps.append('중단 사유를 해결한 뒤 재개하세요. 이전 증거는 유지됩니다.')
    if unfinished:
        next_steps.append(f'시작했지만 판정하지 못한 검사 {len(unfinished)}개가 있습니다.')
    if any(g['status'] == 'unmet' for g in goals):
        next_steps.append(f'증거 조건을 충족하지 못한 목표 {sum(g["status"] == "unmet" for g in goals)}개가 있습니다.')
    if not counts['confirmed']:
        next_steps.append('의심 항목의 차등 확증 또는 로컬 증거 검토가 필요합니다.')
    return {
        'version': 1, 'completion': 'running' if state == 'running' else 'complete' if complete else 'partial',
        'verdict': outcome, 'text': text, 'counts': counts, 'observation_count': len(observations),
        'evidence_ids': sorted(evidence_ids), 'unfinished_steps': unfinished,
        'verifications': verifications, 'goals': goals, 'requested_checks': requested_checks,
        'stop_code': stop_code or ('legacy_repeat' if legacy_repeat else 'legacy'),
        'stop_reason': data.get('reason', ''), 'next_steps': next_steps,
        'scope_note': '작업 종료는 전체 대상의 안전 또는 모든 목표의 달성을 의미하지 않습니다.',
    }
