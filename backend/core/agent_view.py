"""Bounded metadata for local graph, sitemap, and coverage views."""

import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def request_field_keys(request):
    if not isinstance(request, dict):
        return []
    body = request.get('body')
    if not isinstance(body, str) or len(body) > 65536:
        return []
    headers = request.get('headers') or {}
    content_type = str(headers.get('Content-Type', headers.get('content-type', ''))).lower() if isinstance(headers, dict) else ''
    try:
        if 'json' in content_type:
            parsed = json.loads(body)
            keys = parsed.keys() if isinstance(parsed, dict) else []
        elif 'application/x-www-form-urlencoded' in content_type:
            keys = [key for key, _ in parse_qsl(body, keep_blank_values=True)]
        else:
            return []
        return sorted({key[:100] for key in keys if isinstance(key, str) and key})[:100]
    except (ValueError, TypeError):
        return []


def map_request(request):
    """Keep address structure and query keys, never request values or headers."""
    if not isinstance(request, dict):
        return {}
    result = {'method': str(request.get('method') or 'GET')[:16]}
    try:
        parsed = urlsplit(request.get('url') or '')
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            return result
        keys = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        result['url'] = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/',
                                   urlencode([(key, '') for key in keys]), ''))
        params = request.get('params') or {}
        result['params'] = {key: '' for key in params} if isinstance(params, dict) else {}
        result['body_fields'] = request_field_keys(request)
    except (TypeError, ValueError):
        pass
    return result


def map_event(event):
    """Keep fields required by the three passive models; all other bodies vanish."""
    kind = event['kind']
    data = event.get('data') or {}
    out = {key: event[key] for key in ('id', 'created', 'kind', 'step_id')}
    if kind == 'action':
        fields = ('kind', 'category', 'endpoint_id', 'actor_id', 'basis',
                  'confirmation_profile', 'param')
        out['data'] = {key: data[key] for key in fields if key in data}
    elif kind == 'request_started':
        out['data'] = {'request': map_request(data.get('request')),
                       'actor_id': data.get('actor_id')}
    elif kind == 'observation':
        response = data.get('response') or {}
        out['data'] = {'request': map_request(data.get('request')),
                       'response': {key: response[key] for key in ('status', 'truncated', 'time_ms')
                                    if key in response},
                       'request_id': data.get('request_id'), 'actor_id': data.get('actor_id'),
                       'id': data.get('id'),
                       'analysis': {'attack_outcome': (data.get('analysis') or {}).get('attack_outcome')}}
    elif kind == 'verification':
        out['data'] = {key: data[key] for key in ('status', 'evidence_ids', 'category') if key in data}
    elif kind == 'discovery':
        out['data'] = {key: data[key] for key in ('endpoint_id', 'source_observation_id') if key in data}
    elif kind == 'browser_discovery':
        out['data'] = {key: data[key] for key in ('endpoint_id', 'request_id', 'resource_type') if key in data}
    elif kind == 'browser_request':
        out['data'] = {'request': map_request(data.get('request')),
                       'resource_type': data.get('resource_type')}
    elif kind == 'browser_response':
        out['data'] = {key: data[key] for key in ('request_id', 'status') if key in data}
    elif kind == 'verification_skipped':
        out['data'] = {key: data[key] for key in ('endpoint_id', 'category', 'code') if key in data}
    elif kind == 'request_error':
        out['data'] = {'request_id': data.get('request_id'), 'reason': '요청 실패'}
    elif kind == 'plan':
        out['data'] = {'entry': data.get('entry'), 'steps': [
            {'action_id': step.get('action_id'),
             'action': {'kind': (step.get('action') or {}).get('kind')},
             'branches': [{'predicate': {key: branch['predicate'][key] for key in
                                          ('kind', 'verdicts', 'statuses', 'signal')
                                          if key in branch.get('predicate', {})},
                           'next': branch.get('next')}
                          for branch in (step.get('branches') or []) if isinstance(branch, dict)
                          and isinstance(branch.get('predicate'), dict)],
             'default_next': step.get('default_next')}
            for step in (data.get('steps') or []) if isinstance(step, dict)]}
    elif kind == 'plan_branch':
        out['data'] = {key: data[key] for key in ('action_id', 'verdict', 'next') if key in data}
    elif kind == 'plan_result':
        out['data'] = {'outcome': data.get('outcome')}
    elif kind == 'oob':
        out['data'] = {'protocol': data.get('protocol') or (data.get('data') or {}).get('protocol')}
    elif kind == 'error':
        out['data'] = {'reason': '오류'}
    else:
        out['data'] = {}
    return out
