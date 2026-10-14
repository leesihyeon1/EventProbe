"""Deterministic, local run conclusions. Never calls an LLM or reads response bodies."""


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
                              'evidence_ids': sorted(refs)})
    unfinished = [e['step_id'] for e in events if e['kind'] == 'action'
                  and e['data'].get('kind') in ('probe', 'confirm', 'access')
                  and e['step_id'] not in verified_steps]
    stop_code = data.get('stop_code', '')
    legacy_repeat = data.get('reason', '').startswith('동일 행동 반복')
    complete = state == 'completed' and not unfinished and not legacy_repeat
    if stop_code in ('plan_dead_end', 'planner_stalled', 'plan_loop'):
        complete = False
    outcome = 'confirmed' if counts['confirmed'] else 'suspicious' if counts['suspicious'] else 'inconclusive'
    text = {
        'confirmed': '연결된 증거에서 취약 동작이 확증됐습니다. 확증된 입력과 동작에 한정된 결과입니다.',
        'suspicious': '의심 신호가 있으나 취약성 확증은 완료되지 않았습니다.',
        'inconclusive': '취약성을 확증할 증거가 부족합니다. 안전 판정이 아닙니다.',
    }[outcome]
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
    if not counts['confirmed']:
        next_steps.append('의심 항목의 차등 확증 또는 로컬 증거 검토가 필요합니다.')
    return {
        'version': 1, 'completion': 'running' if state == 'running' else 'complete' if complete else 'partial',
        'verdict': outcome, 'text': text, 'counts': counts, 'observation_count': len(observations),
        'evidence_ids': sorted(evidence_ids), 'unfinished_steps': unfinished,
        'verifications': verifications,
        'stop_code': stop_code or ('legacy_repeat' if legacy_repeat else 'legacy'),
        'stop_reason': data.get('reason', ''), 'next_steps': next_steps,
        'scope_note': '작업 종료는 전체 대상의 안전 또는 모든 목표의 달성을 의미하지 않습니다.',
    }
