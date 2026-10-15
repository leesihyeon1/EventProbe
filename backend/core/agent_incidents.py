"""Read-only correlation of a SIEM/SOAR incident to its verification runs (리뷰 P2/N4).

The status is derived ONLY from the linked runs' current local conclusions. Two guards:
  - 과거 증거를 새 확증으로 오인하지 않음: the incident's own report (title/observed_at) is
    an input, never evidence. Only a linked run's current confirmation sets 'reproduced'.
  - 미관측을 해결로 표시하지 않음: no run, or a run that never exercised this category, never
    becomes 'resolved/safe' — it stays 'unverified'/'inconclusive'.
This module never sends a request and never calls a model.
"""


def build_incident_trace(incident, runs):
    """incident: the stored incident record. runs: [{id, state, created, conclusion}] for runs
    linked to it (conclusion = core.agent_outcome.build_conclusion output). Returns a trace dict."""
    category = incident.get('category', '')
    entries, latest_completed, latest_active, previously_reproduced = [], None, None, False
    groups = {}
    for run in sorted(runs, key=lambda r: (r.get('created') or 0, r.get('id') or ''), reverse=True):
        concl = run.get('conclusion') or {}
        state = run.get('state', '')
        # 전체 run 판정에는 다른 유형의 확증이 섞일 수 있다. 사건 유형과 연결 증거가
        # 모두 일치하는 verification 만 현재 사건의 판정 근거로 사용한다.
        verifs = [v for v in (concl.get('verifications') or [])
                  if v.get('category') == category and v.get('evidence_ids')]
        exercised = bool(verifs)
        linked_evidence = sorted({e for v in verifs for e in (v.get('evidence_ids') or [])})
        refs = []
        for finding in run.get('findings') or []:
            shared_evidence = sorted(set(finding.get('evidence_ids') or []) & set(linked_evidence))
            if finding.get('category') != category or not shared_evidence:
                continue
            ref = {'run_id': run.get('id', ''), 'finding_id': finding.get('id', ''),
                   'endpoint_id': finding.get('endpoint_id', ''),
                   'actor_id': finding.get('actor_id', ''),
                   'verdict': finding.get('verdict', 'inconclusive'),
                   'method': finding.get('method', ''), 'origin': finding.get('origin', ''),
                   'path': finding.get('path', ''), 'query_keys': finding.get('query_keys') or [],
                   'evidence_ids': shared_evidence, 'created': run.get('created')}
            refs.append(ref)
            # An asset ID is an explicit correlation key. Without one, do not guess
            # that identical paths from different runs belong to the same asset.
            asset_id = incident.get('asset_id', '')
            if asset_id:
                key = (asset_id, category, ref['method'], ref['origin'], ref['path'],
                       tuple(ref['query_keys']), ref['actor_id'])
                group = groups.setdefault(key, {'asset_id': asset_id, 'category': category,
                    'method': ref['method'], 'origin': ref['origin'], 'path': ref['path'],
                    'query_keys': ref['query_keys'], 'actor_id': ref['actor_id'], 'findings': []})
                group['findings'].append(ref)
        verdict = ('confirmed' if any(v.get('status') == 'confirmed' for v in verifs)
                   else 'suspicious' if any(v.get('status') == 'suspicious' for v in verifs)
                   else 'inconclusive')
        confirmed_here = state == 'completed' and verdict == 'confirmed'
        entries.append({'run_id': run.get('id', ''), 'state': state, 'verdict': verdict,
                        'completion': concl.get('completion', ''), 'exercised': exercised,
                        'evidence_ids': linked_evidence, 'finding_refs': refs,
                        'created': run.get('created')})
        if confirmed_here:
            previously_reproduced = True
        if state in ('running', 'paused', 'interrupted') and latest_active is None:
            latest_active = run
        if state == 'completed' and latest_completed is None:
            latest_completed = (run, verdict, exercised)

    if not runs:
        status, reason = 'unverified', '재검증 실행이 아직 연결되지 않았습니다. 미관측은 해결로 표시하지 않습니다.'
    elif latest_active and (latest_completed is None or
                            (latest_active.get('created') or 0) >= (latest_completed[0].get('created') or 0)):
        status, reason = 'verifying', '연결된 재검증 실행이 진행/대기 중입니다.'
    elif latest_completed and not latest_completed[2]:
        status, reason = 'inconclusive', '최신 실행이 이 사건 유형을 검사하지 못했습니다.'
    elif latest_completed and latest_completed[1] == 'confirmed':
        status, reason = 'reproduced', '연결된 현재 실행에서 취약이 재현(확증)되었습니다.'
    elif latest_completed and latest_completed[1] == 'suspicious':
        status, reason = 'suspicious', '연결된 실행에서 의심 신호가 있으나 확증되지 않았습니다.'
    elif latest_completed:
        status, reason = 'not_reproduced', '이번 재검증에서 재현되지 않았습니다(대상 전체의 안전/해결을 의미하지 않습니다).'
    else:
        status, reason = 'inconclusive', '연결된 실행이 이 사건 유형을 확정적으로 검사하지 못했습니다.'

    finding_groups = []
    for group in groups.values():
        times = [ref['created'] for ref in group['findings'] if ref['created'] is not None]
        group['first_seen'] = min(times) if times else None
        group['last_seen'] = max(times) if times else None
        group['findings'].sort(key=lambda ref: (ref['created'] or 0, ref['run_id']), reverse=True)
        finding_groups.append(group)
    finding_groups.sort(key=lambda group: (group['last_seen'] or 0, group['path']), reverse=True)

    return {
        'incident_id': incident.get('id', ''), 'source': incident.get('source', ''),
        'external_id': incident.get('external_id', ''), 'observed_at': incident.get('observed_at'),
        'asset_id': incident.get('asset_id', ''), 'traffic_id': incident.get('traffic_id', ''),
        'category': category, 'title': incident.get('title', ''),
        'status': status, 'reason': reason, 'runs': entries, 'finding_groups': finding_groups,
        'previously_reproduced': previously_reproduced,
        'latest_verification_run_id': latest_completed[0].get('id', '') if latest_completed else '',
        'note': '상태는 연결된 현재 실행의 판정에서만 도출되며, 사건 보고 자체는 증거가 아닙니다. '
                '작업 종료가 대상 전체의 안전을 뜻하지 않습니다.',
    }


def build_asset_trace(asset_id, traces):
    """Read-only cross-incident finding lineage for one explicit asset ID.

    This does not derive a global vulnerability verdict: each incident retains its
    own latest-run status, while old findings remain historical references.
    """
    incidents, groups = [], {}
    for trace in traces:
        if not asset_id or trace.get('asset_id') != asset_id:
            continue
        iid = trace.get('incident_id', '')
        incidents.append({'incident_id': iid, 'source': trace.get('source', ''),
                          'category': trace.get('category', ''),
                          'traffic_id': trace.get('traffic_id', ''),
                          'observed_at': trace.get('observed_at'),
                          'status': trace.get('status', 'unverified'),
                          'latest_verification_run_id': trace.get('latest_verification_run_id', ''),
                          'previously_reproduced': trace.get('previously_reproduced', False)})
        for source_group in trace.get('finding_groups') or []:
            if source_group.get('asset_id') != asset_id:
                continue
            key = (source_group.get('category', ''), source_group.get('method', ''),
                   source_group.get('origin', ''), source_group.get('path', ''),
                   tuple(source_group.get('query_keys') or []), source_group.get('actor_id', ''))
            group = groups.setdefault(key, {'asset_id': asset_id, 'category': key[0],
                'method': key[1], 'origin': key[2], 'path': key[3],
                'query_keys': list(key[4]), 'actor_id': key[5], 'findings': []})
            for ref in source_group.get('findings') or []:
                group['findings'].append({**ref, 'incident_id': iid})
    result_groups = []
    for group in groups.values():
        times = [ref['created'] for ref in group['findings'] if ref.get('created') is not None]
        group['first_seen'] = min(times) if times else None
        group['last_seen'] = max(times) if times else None
        group['incident_ids'] = sorted({ref['incident_id'] for ref in group['findings']})
        group['findings'].sort(key=lambda ref: (ref.get('created') or 0, ref['run_id']), reverse=True)
        result_groups.append(group)
    result_groups.sort(key=lambda group: (group['last_seen'] or 0, group['path']), reverse=True)
    return {'asset_id': asset_id, 'incidents': incidents, 'finding_groups': result_groups,
            'note': '사건별 판정은 각 사건의 최신 실행에서만 도출됩니다. 이 목록의 과거 발견은 현재 확증이나 자산 전체의 안전을 뜻하지 않습니다.'}
