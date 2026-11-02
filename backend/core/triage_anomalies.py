"""Local, bounded correlation of observed records; never a compromise verdict."""
from collections import defaultdict
from datetime import datetime
import hashlib

from core.classify import is_direct_file_probe
from core.triage_filter import simple_scan_request


def _time(event):
    try:
        value = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
        return value.timestamp() if value.tzinfo else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def summarize_anomalies(events):
    targets, sources = defaultdict(list), defaultdict(list)
    missing_time = missing_target = 0
    for event in events:
        target = event.get('host') or event.get('destination')
        stamp = _time(event)
        if stamp is None:
            missing_time += 1
        if not target or 'HOST_CONFLICT' in event.get('reasons', []):
            missing_target += 1
            continue
        if stamp is None:
            continue
        window = int(stamp // 900)
        targets[(target, window)].append(event)
        if event.get('source'):
            sources[(event['source'], window)].append(event)
    findings = []

    def add(rule, title, items, candidates, fact, followup, priority='medium'):
        ordered = sorted(items, key=lambda e: (_time(e), e['id']))
        important = any('IMPORTANT_ASSET' in e.get('reasons', []) for e in items)
        if important:
            priority = 'high'
        ids = [e['id'] for e in ordered]
        impacts = sorted({e.get('assessment', {}).get('impact') for e in candidates
                          if e.get('assessment', {}).get('impact')})
        findings.append(dict(
            id=hashlib.sha256((rule + '|'.join(ids)).encode()).hexdigest()[:20],
            rule=rule, title=title, priority=priority, confidence='medium',
            evidence=fact, next_action=followup,
            impact=' / '.join(impacts) or '요청 응답과 서비스 영향을 추가 확인해야 합니다.',
            context='중요 운영 자산 포함' if important else '입력 로그의 동일 15분 구간에서 관측',
            outcome='공격 성공 여부 미확인',
            event_ids=ids, candidate_ids=list(dict.fromkeys(e['id'] for e in candidates)),
            targets=sorted({e.get('host') or e.get('destination') for e in items}),
            start=ordered[0]['timestamp'], end=ordered[-1]['timestamp']))

    for (target, window), items in targets.items():
        streams = defaultdict(list)
        for e in items:
            # Separate clients, device kinds and reported response provenance.
            if e.get('source'):
                streams[(e['source'], e.get('device', ''), e.get('status_source', 'unknown'))].append(e)
        for stream in streams.values():
            probes = [e for e in stream if simple_scan_request(e)]
            failed = [e for e in probes if e.get('status') == 404]
            success = [e for e in probes if e.get('status') in (200, 206)]
            if len({e.get('path') for e in failed}) >= 3 and success:
                add('scan_response', '경로 탐색 중 다른 응답 발견', probes, success,
                    f'{target}: 탐색 {len(probes)}건 중 404 {len(failed)}건, 200·206 {len(success)}건.',
                    '200·206 경로의 응답 본문·크기와 서버 접근 로그를 확인하세요. 공통 오류 페이지일 수 있습니다.', 'high')
            attacks = [e for e in stream if not simple_scan_request(e) and
                       (e.get('category') or e.get('cve'))]
            if probes and attacks:
                first = min(_time(e) for e in probes)
                later = [e for e in attacks if _time(e) > first]
                if later:
                    add('scan_to_attack', '탐색 이후 공격 요청 관측', probes + later, later,
                        f'{target}: 같은 출발지·장비 종류에서 탐색 이후 공격 유형이 식별된 요청 {len(later)}건.',
                        '탐색 경로와 후속 공격의 관련성, 사용 기술 및 서버 실행·접근 로그를 확인하세요.')
            similar = defaultdict(list)
            for e in stream:
                if e.get('path'):
                    similar[(e.get('method'), e['path'], e.get('category') or e.get('event_name'))].append(e)
            for group in similar.values():
                blocked = [e for e in group if e.get('action') == 'blocked']
                allowed = [e for e in group if e.get('action') == 'allowed']
                if blocked and allowed:
                    add('mixed_action', '같은 요청 경로의 차단·허용 혼재', group, allowed,
                        f'{target} {group[0]["path"]}: 차단 {len(blocked)}건, 허용 {len(allowed)}건. 본문·헤더는 다를 수 있습니다.',
                        '요청 본문·헤더와 장비 정책 변경을 비교하고 허용 요청의 처리 결과를 확인하세요.', 'high')
        errors = [e for e in items if isinstance(e.get('status'), int) and 500 <= e['status'] < 600
                  and (e.get('category') or e.get('cve'))]
        if len(errors) >= 3:
            add('attack_errors', '공격 탐지 요청에 5XX 응답 반복', errors, errors,
                f'{target}: 공격 유형이 식별된 요청 {len(errors)}건에 5XX 기록.',
                '같은 시간대 애플리케이션 오류·가용성 지표를 확인하세요. 공격이 오류를 유발했는지는 미확인입니다.')
        scan = [e for e in items if simple_scan_request(e)]
        clients = {e['source'] for e in scan if e.get('source')}
        if len(clients) >= 3 and len({e.get('path') for e in scan}) >= 5:
            add('distributed_scan', '여러 출발지의 경로 탐색 집중', scan, scan,
                f'{target}: 출발지 {len(clients)}개에서 서로 다른 경로 {len({e.get("path") for e in scan})}개 탐색.',
                '출발지별 요청 순서와 프록시·공유 주소 여부를 확인하세요. 동일 행위자 여부는 알 수 없습니다.')
        sensitive = [e for e in scan if is_direct_file_probe(e.get('path') or '')]
        if len(sensitive) >= 3:
            add('sensitive_probe', '민감 파일·경로 탐색 반복', sensitive, sensitive,
                f'{target}: 민감 파일·경로 탐색 {len(sensitive)}건, 경로 {len({e["path"] for e in sensitive})}개.',
                '허용·응답 미확인 요청과 실제 파일 반환 여부를 확인하세요. 중복 장비 관측일 수 있습니다.')
    for (source, window), items in sources.items():
        scan = [e for e in items if simple_scan_request(e)]
        hosts = {e.get('host') or e.get('destination') for e in scan}
        if len(hosts) >= 3:
            add('multi_target_scan', '같은 출발지의 여러 대상 탐색', scan, scan,
                f'{source}: 대상 {len(hosts)}개에 경로 탐색 기록.',
                '대상별 응답 차이와 공통 공격 경로를 확인하세요. 공유 출발지일 수 있습니다.')
    findings.sort(key=lambda f: (f['priority'] != 'high', -len(f['event_ids']), f['id']))
    return dict(version=1, findings=findings,
                coverage=dict(records=len(events), missing_time=missing_time, missing_target=missing_target),
                policy=dict(window_seconds=900, scan_404_paths=3, error_records=3, distributed_sources=3,
                            distributed_paths=5, sensitive_records=3, scan_targets=3),
                limitation='현재 입력의 고정 15분 구간별 규칙 분석입니다. 구간 경계·수집 누락으로 놓칠 수 있으며 과거 대비 급증이나 침해 성공을 판단하지 않습니다. 시간대가 없는 시각·대상 불명 기록은 상관 분석에서 제외합니다. 신호 간 근거 로그는 중복될 수 있습니다.')
