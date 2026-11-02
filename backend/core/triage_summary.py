"""Evidence-based attack summaries, independent of replay eligibility."""
import re
from collections import Counter


PROFILES = {
    'cmdi': ('명령 실행 공격', '서버 명령 실행 및 시스템 장악', '프로세스 실행·외부 연결·애플리케이션 오류 로그를 확인하세요.'),
    'sqli': ('SQL 인젝션', '데이터 조회·변조 또는 인증 우회', 'DB 쿼리·오류 로그와 응답 본문에서 데이터 노출 여부를 확인하세요.'),
    'lfi': ('파일 접근 공격', '설정·소스·인증정보 등 민감 파일 노출', '응답 본문과 전송량에서 실제 파일 내용 반환 여부를 확인하세요.'),
    'authbypass': ('인증 우회 공격', '보호된 기능과 데이터에 대한 무단 접근', '인증 로그와 보호된 기능의 실행·변경 이력을 확인하세요.'),
    'ssrf': ('서버 측 요청 위조', '내부 서비스 접근 및 메타데이터·자격정보 노출', '서버의 외부·내부 연결 로그와 메타데이터 접근 이력을 확인하세요.'),
    'ssti': ('템플릿 주입', '서버 측 표현식 평가 및 코드 실행', '템플릿 오류·실행 로그와 응답의 표현식 평가 결과를 확인하세요.'),
    'xss': ('스크립트 주입', '사용자 브라우저에서 스크립트 실행 및 세션 악용', '응답 반사·저장 위치와 브라우저 실행 조건을 확인하세요.'),
    'nosql': ('NoSQL 인젝션', '데이터 접근 및 인증 조건 우회', 'DB 조회와 인증 결과를 확인하세요.'),
}
SIGNATURES = [
    ('cmdi', r'\brce\b|remote.code.execution|command.injection|log4shell|shellshock|명령.*실행'),
    ('sqli', r'\bsqli\b|sql.injection|SQL.*인젝션'),
    ('lfi', r'\blfi\b|path.traversal|directory.traversal|경로.*탐색'),
    ('authbypass', r'auth(?:entication|orization)?.bypass|인증.*우회'),
    ('ssrf', r'\bssrf\b|server.side.request.forgery'),
    ('xss', r'\bxss\b|cross.site.script'),
]


def signature_category(signature):
    return next((category for category, pattern in SIGNATURES if re.search(pattern, signature, re.I)), '')


def assessment(event):
    category = event.get('category', '')
    title, impact, followup = PROFILES.get(category, (
        event.get('signature') or event.get('event_name') or category or '공격 유형 미확인',
        '현재 요청 정보만으로 구체적인 영향을 판단할 수 없음',
        '탐지 규칙 설명과 원본 요청·응답, 장비 처리 내역을 확보하세요.'))
    evidence = list(event.get('attack_evidence', []))
    severity = str(event.get('severity', '')).lower().strip()
    severe = severity in ('critical', 'high', '심각', '높음', '상', '치명적')
    if severity:
        evidence.append(f'장비 심각도: {event["severity"]} (장비 기준)')
    important = 'IMPORTANT_ASSET' in event.get('reasons', [])
    mixed = 'MIXED_ALLOWED_BLOCKED' in event.get('reasons', [])
    high_impact = category in ('cmdi', 'sqli', 'lfi', 'authbypass', 'ssrf', 'ssti')
    if important:
        evidence.append('운영 인벤토리에 등록된 중요 자산')
    if mixed:
        evidence.append('동일 대상·시간대에 허용과 차단 기록이 혼재')
    blocked = event.get('action') == 'blocked'
    level = 'high' if high_impact or severe or important else 'medium' if category or event.get('signature') or mixed else 'unknown'
    # This is investigation order, not a probability of compromise or replay permission.
    rank = (0 if level == 'high' and (not blocked or mixed) else
            1 if level == 'high' or (level == 'medium' and not blocked) else
            2 if level == 'medium' else 3)
    outcome = {'blocked': '장비에 차단으로 기록됨', 'allowed': '장비에 허용으로 기록됨'}.get(event.get('action'), '장비 처리 결과 불명')
    if event.get('status') is not None:
        outcome += f' · 장비 기록 HTTP {event["status"]}'
    outcome += ' · 공격 성공 여부 미확인'
    if blocked:
        followup = '차단 적용 범위와 같은 대상의 허용·우회 요청을 확인하세요. ' + followup
    return dict(title=title, impact=impact, importance=level, rank=rank,
                evidence=evidence or ['공격을 특정할 요청 근거가 부족합니다.'], outcome=outcome, next_action=followup)


def refresh_attack_summary(result):
    groups = {}
    for event in result['events']:
        event['assessment'] = item = assessment(event)
        target = event['host'] or event.get('destination') or ''
        key = (target, event.get('category') or event.get('signature') or event.get('event_name') or 'unknown', item['importance'])
        if key not in groups:
            groups[key] = dict(host=target, **item, record_count=0, reported_occurrences=0,
                               occurrence_records=0, sources=set(), paths=set(), event_ids=[], actions=Counter())
        group = groups[key]
        if item['rank'] < group['rank']:
            group.update(item)
        group['record_count'] += 1
        group['event_ids'].append(event['id'])
        group['actions'][event['action']] += 1
        if event.get('source'): group['sources'].add(event['source'])
        group['paths'].add(event['path'])
        if event.get('occurrences') is not None:
            group['reported_occurrences'] += event['occurrences']
            group['occurrence_records'] += 1
    ordered = sorted(groups.values(), key=lambda g: (g['rank'], -g['record_count'], g['host']))
    for group in ordered:
        group['source_count'] = len(group['sources'])
        group['path_count'] = len(group['paths'])
        group['sources'] = sorted(group['sources'])[:3]
        group['paths'] = sorted(group['paths'])[:3]
        group['actions'] = dict(group['actions'])
    result['attack_summary'] = dict(groups=ordered, high=sum(e['assessment']['importance']=='high' for e in result['events']),
        limitation='요청 패턴과 장비 탐지에 근거한 분석입니다. 허용이나 HTTP 2xx만으로 침해 성공을 확정하지 않습니다. 장비 발생 횟수는 중복을 포함할 수 있습니다.')
    from core.triage_anomalies import summarize_anomalies
    result['anomaly_analysis'] = summarize_anomalies(result['events'])
    return result
