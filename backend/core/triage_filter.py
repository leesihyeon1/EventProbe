"""Conservative screening of observed security events.

Screened events remain in the result and statistics; screening only controls the
default investigation view, never the historical evidence or impact assessment.
"""
import re
from core.classify import is_direct_file_probe


ORIGIN_STATUS = {'origin', 'backend', 'application', 'server'}
TECH_PATHS = (
    (r'^/wp-(?:admin|content|includes|login\.php)|^/xmlrpc\.php', 'wordpress'),
    (r'^/phpmyadmin(?:/|$)', 'phpmyadmin'),
    (r'^/_next(?:/|$)|^/next\.js(?:/|$)', 'next.js'),
    (r'^/actuator(?:/|$)', 'spring'),
    (r'^/owa(?:/|$)|^/ecp(?:/|$)', 'exchange'),
)


def matching_technology(event):
    path = event.get('path') or ''
    tech = ' '.join(event.get('technologies') or []).lower()
    return next((name for pattern, name in TECH_PATHS if re.search(pattern, path, re.I) and name in tech), '')


def status_provenance(value):
    raw = str(value or '').strip().lower()
    return 'origin' if raw in ORIGIN_STATUS else 'edge' if raw in {'edge', 'waf', 'proxy', 'cdn'} else 'unknown'


def screen_event(event):
    reasons = event.get('reasons') or []
    if 'MIXED_ALLOWED_BLOCKED' in reasons or 'IMPORTANT_ASSET' in reasons:
        return {'screened': False, 'code': '', 'explanation': '혼재 기록 또는 중요 자산으로 우선 확인합니다.'}
    if event.get('device') == 'IPS' and event.get('action') == 'blocked':
        return {'screened': True, 'code': 'IPS_BLOCKED',
                'explanation': 'IPS 차단 기록입니다. 동일 대상의 허용 기록이나 우회 정황이 없으면 재요청 우선순위가 낮습니다.'}
    match = matching_technology(event)
    if match:
        return {'screened': False, 'code': 'TECH_MATCH',
                'explanation': f'관측된 웹 기술과 요청 경로가 일치합니다: {match}. 실제 취약 여부는 별도 확인이 필요합니다.'}
    path = event.get('path') or ''
    simple_file = is_direct_file_probe(path) or (event.get('family') == '정보 수집성' and
                   bool(path) and '?' not in path and not event.get('category'))
    if (simple_file and event.get('status') in (404, 410) and
            event.get('status_source') == 'origin' and
            event.get('method') in ('GET', 'HEAD') and
            event.get('action') != 'blocked' and
            not any(r in reasons for r in ('HOST_CONFLICT', 'HOST_MISSING'))):
        return {'screened': True, 'code': 'ORIGIN_NOT_FOUND_SCAN',
                'explanation': '원 서버가 404/410을 반환한 단순 파일·경로 탐색입니다. 다른 경로의 허용·노출은 별도 확인이 필요합니다.'}
    return {'screened': False, 'code': '', 'explanation': ''}


def refresh_screening(result):
    for event in result['events']:
        event['screening'] = screen_event(event)
    result['screening_summary'] = {
        'screened': sum(event['screening']['screened'] for event in result['events']),
        'actionable': sum(not event['screening']['screened'] for event in result['events']),
    }
    return result
