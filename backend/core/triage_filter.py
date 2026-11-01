"""Conservative screening of observed security events.

Screened events remain in the result and statistics; screening only controls the
default investigation view, never the historical evidence or impact assessment.
"""
import re
from urllib.parse import unquote, urlsplit
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


def implied_technology(event):
    """요청 경로가 특정 제품을 겨냥함을 뜻하는 기술명(존재 여부와 무관). 없으면 ''."""
    path = event.get('path') or ''
    return next((name for pattern, name in TECH_PATHS if re.search(pattern, path, re.I)), '')


def status_provenance(value):
    raw = str(value or '').strip().lower()
    return 'origin' if raw in ORIGIN_STATUS else 'edge' if raw in {'edge', 'waf', 'proxy', 'cdn'} else 'unknown'


def simple_scan_request(event):
    """A lookup-only probe, excluding query/body/header exploitation evidence.

    A 4xx is used only to reduce default replay work, not to prove that a file
    does not exist or that the service is secure. Raw fields are retained.
    """
    if event.get('method') not in ('GET', 'HEAD'):
        return False
    path = event.get('path') or ''
    if not path:
        return False
    try:
        parsed = urlsplit(path)
        decoded = unquote(unquote(parsed.path))
    except ValueError:
        return False
    if parsed.query or '?' in decoded or '..' in decoded or '\\' in decoded:
        return False
    fields = event.get('fields') or {}
    if any(event.get(k) or fields.get(k) for k in (
            'request_body', 'body', 'http_body', 'payload', 'webQuery', 'query', 'uri_query')):
        return False
    # IDS nested data can carry a request body without a top-level body field.
    for segment in str(fields.get('layer_7_data') or '').split(';;;'):
        key, sep, value = segment.partition('==')
        if sep and key.strip().lower() == 'http request body' and value.strip():
            return False
    if event.get('cve'):
        return False
    if any(str(evidence).startswith('header:') for evidence in event.get('attack_evidence') or []):
        return False
    direct = is_direct_file_probe(path)
    category = event.get('category') or ''
    # Direct sensitive-file lookups may be labelled LFI by a vendor. Other
    # attack categories and traversal/injection requests must remain visible.
    if category and not (category == 'lfi' and direct):
        return False
    name = ' '.join(str(event.get(k) or '') for k in ('event_name', 'signature'))
    scan_name = bool(re.search(r'(?:file|directory|path|web|application.layer)[ ._-]*(?:scan|probe|retrieval)|'
                               r'(?:scan|probe).*?(?:file|directory|path)|\bzgrab\b|\bscanner\b', name, re.I))
    return direct or event.get('family') == '정보 수집성' or scan_name


def screen_event(event):
    # Screening affects replay selection only. Important/mixed events stay in
    # overall statistics and assessments even when this specific request is blocked.
    if event.get('device') == 'IPS' and event.get('action') == 'blocked':
        return {'screened': True, 'code': 'IPS_BLOCKED',
                'explanation': 'IPS 차단 기록으로 기본 검증 대상에서 제외합니다. 동일 대상의 허용 이벤트는 별도로 검토합니다.'}
    status = event.get('status')
    if isinstance(status, int) and 400 <= status < 500 and simple_scan_request(event):
        return {'screened': True, 'code': 'SIMPLE_SCAN_4XX',
                'explanation': '4xx가 기록된 단순 파일·경로 탐색으로 기본 검증 대상에서 제외합니다. 응답 생성 주체나 자산의 안전을 확정하는 판단은 아닙니다.'}
    reasons = event.get('reasons') or []
    if 'MIXED_ALLOWED_BLOCKED' in reasons or 'IMPORTANT_ASSET' in reasons:
        return {'screened': False, 'code': '', 'explanation': '혼재 기록 또는 중요 자산으로 우선 확인합니다.'}
    match = matching_technology(event)
    if match:
        return {'screened': False, 'code': 'TECH_MATCH',
                'explanation': f'관측된 웹 기술과 요청 경로가 일치합니다: {match}. 실제 취약 여부는 별도 확인이 필요합니다.'}
    implied = implied_technology(event)
    known = [str(t).lower() for t in (event.get('technologies') or [])]
    if implied and known and implied not in known:
        # 관측된 웹 기술을 아는 경우에만 '미사용' 판단 — 기술 미관측은 부재의 증거가 아니다(三상태 준수).
        return {'screened': True, 'code': 'TECH_MISMATCH',
                'explanation': f'요청 경로는 {implied} 대상이지만 관측된 웹 기술에 {implied}가 없어 기본 검증 대상에서 제외합니다. '
                               '기술 미관측은 부재의 증거가 아니며 전체 목록에서 확인할 수 있습니다.'}
    return {'screened': False, 'code': '', 'explanation': ''}


def refresh_screening(result):
    for event in result['events']:
        event['screening'] = screen_event(event)
    result['screening_summary'] = {
        'screened': sum(event['screening']['screened'] for event in result['events']),
        'actionable': sum(not event['screening']['screened'] for event in result['events']),
    }
    return result
