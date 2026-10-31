"""Local preparation for SIEM verification. Preparing never sends a target request."""
from urllib.parse import urlsplit, parse_qsl, urlunsplit
from core import confirm
from core.agent_assets import asset_shape
from core.agent_models import origin, IncidentEvent

SUPPORTED = {'sqli','xss','ssti','lfi','ssrf','cmdi','redirect','nosql'}


def canonical_request(url):
    if any(ord(c) < 33 for c in url) or len(url)>4096:
        raise ValueError('공백/제어문자 없는 4096자 이하 URL이 필요합니다.')
    origin(url)
    u=urlsplit(url)
    if u.fragment: raise ValueError('URL fragment는 지원하지 않습니다.')
    pairs=parse_qsl(u.query,keep_blank_values=True)
    if len({k for k,v in pairs}) != len(pairs):
        raise ValueError('중복 쿼리 키는 수동 요청에서 검토하세요.')
    return {'method':'GET', 'url':urlunsplit((u.scheme,u.netloc,u.path or '/', '', '')), 'params':dict(pairs)}


def prepare(url, category, param, event_id, summary=''):
    req=canonical_request(url)
    if category not in SUPPORTED or not confirm.is_supported(category):
        raise ValueError('이 검증 방식은 현재 지원하지 않습니다.')
    if not param or param not in req['params']:
        raise ValueError('검증할 쿼리 파라미터를 선택하세요. 파라미터 없는 요청은 수동 검토가 필요합니다.')
    shape=asset_shape(req)
    incident=IncidentEvent(source='siem', external_id=event_id, asset_id=shape[0],
        category=category, title=f'SIEM 선별 검증: {category}', summary=summary,
        request=req, location='param', param=param).model_dump()
    # Same upper limit as the existing incident verification path.
    budget=min(150, 1+2*len(confirm.probe_plan(category,''))+2)
    return {'incident':incident,'max_requests':budget,'max_seconds':120,'max_ai_calls':0,
            'target_origin':shape[1],'method':'GET','redirects':False,
            'notice':'실행하면 사건과 실행 이력이 서버에 저장됩니다. 현재 재현은 과거 침해 성공을 입증하지 않습니다.'}
