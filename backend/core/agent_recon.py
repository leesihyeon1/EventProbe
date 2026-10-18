"""Local reconnaissance state and an allowlisted planner view."""
import re
from urllib.parse import urlsplit

from core import analyzer, public_shape, agent_sql
from core.agent_view import request_field_keys


_KNOWN_STACKS = {name for name, _, _ in analyzer._STACK_SIGNATURES}
_FIELD = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,63}$')
_OUTCOMES = {'blocked', 'allowed', 'inconclusive', 'unknown', 'success', 'failure'}
_VERDICTS = {'confirmed', 'suspicious', 'inconclusive', 'observed', 'pending'}
_PURPOSES = {'access-control', 'injection', 'xss', 'ssrf', 'traversal', 'redirect',
             'general-verification'}


def snapshot(data, events, state='running'):
    endpoints = data.get('endpoints') or {}
    actions = {event['step_id']: event['data'] for event in events if event['kind'] == 'action'}
    observed = [event for event in events if event['kind'] == 'observation']
    browser = [event for event in events if event['kind'] == 'browser_request']
    verified = [event for event in events if event['kind'] == 'verification']
    evidence_ids = {event['id'] for event in observed}
    observed_steps = {event['step_id'] for event in observed}
    touched = {action.get('endpoint_id', 'seed') for step_id, action in actions.items()
               if step_id in observed_steps and action.get('kind') in ('observe', 'probe', 'confirm')}
    if observed:
        touched.add('seed')
    technologies = set(data.get('recon_technologies') or [])
    servers = set(data.get('recon_servers') or [])
    for event in observed:
        response = event['data'].get('response') or {}
        headers = {str(k).lower(): str(v) for k, v in (response.get('headers') or {}).items()}
        if headers.get('server'):
            servers.add(headers['server'][:120])
        for item in (event['data'].get('analysis') or {}).get('tech_stack') or []:
            if item.get('name') in _KNOWN_STACKS:
                technologies.add(item['name'])
    phase = 'finished' if state not in ('running', 'queued') else (
        'verification' if verified else 'testing' if any(a.get('kind') in ('probe', 'confirm') for a in actions.values())
        else 'reconnaissance')
    discoveries = {event['data'].get('endpoint_id'): 'rendered_dom'
                   for event in events if event['kind'] == 'browser_discovery'
                   and event['data'].get('resource_type') == 'form'}
    discoveries.update({event['data'].get('endpoint_id'): 'html'
                        for event in events if event['kind'] == 'discovery'
                        and event['data'].get('endpoint_id') not in discoveries})
    skipped = {event['data'].get('endpoint_id') for event in events
               if event['kind'] == 'verification_skipped'}
    forms = []
    for eid, request in endpoints.items():
        fields = request_field_keys(request)
        if request.get('method') != 'POST' or not fields:
            continue
        checks = [(step_id, action) for step_id, action in actions.items()
                  if action.get('endpoint_id') == eid and action.get('kind') in ('probe', 'confirm')]
        verdicts = []
        for event in verified:
            if not any(event['step_id'] == step_id for step_id, _ in checks):
                continue
            refs = event['data'].get('evidence_ids') or []
            verdicts.append(event['data'].get('status') if refs and
                            all(ref in evidence_ids for ref in refs) else 'inconclusive')
        status = next((name for name in ('confirmed', 'suspicious', 'inconclusive')
                       if name in verdicts), None) or (
            'testing' if checks and state == 'running' else
            'interrupted' if checks else 'skipped_budget' if eid in skipped else
            'untested' if state not in ('running', 'queued') else 'pending')
        form_meta = (data.get('form_schema') or {}).get(eid) or {}
        forms.append({'endpoint_id': eid, 'fields': fields,
                      'field_schema': form_meta.get('fields') or [],
                      'login': bool(agent_sql.login_user_fields(request)),
                      'source': discoveries.get(eid, 'registered'), 'status': status})
    return {'phase': phase, 'endpoint_count': len(endpoints),
            'observed_endpoint_count': len(touched & endpoints.keys()),
            'unobserved_get_count': sum(eid not in touched and req.get('method') == 'GET'
                                        for eid, req in endpoints.items()),
            'request_count': data.get('requests', 0), 'verification_count': len(verified),
            'browser_request_count': len(browser),
            'browser_endpoint_count': sum(event['kind'] == 'browser_discovery' for event in events),
            'technologies': sorted(technologies), 'server_headers': sorted(servers),
            'form_candidates': forms}


def next_read_action(spec, data, events, *, limit=3):
    if spec.target_scope != 'same_origin' or spec.max_steps - data['steps'] <= 2:
        return None
    if spec.max_requests - data['requests'] <= 10:
        return None
    explored = {'seed'}
    for event in events:
        if event['kind'] == 'action' and event['data'].get('kind') == 'observe':
            explored.add(event['data'].get('endpoint_id', 'seed'))
    if len(explored) - 1 >= limit:
        return None
    for eid, request in data['endpoints'].items():
        if eid != 'seed' and eid not in explored and request.get('method') == 'GET':
            return eid
    return None


def planner_view(ctx):
    """Construct a new object from approved metadata; never forward response-derived text."""
    endpoints = []
    for item in ctx.get('endpoints') or []:
        endpoints.append({'id': item.get('id'), 'method': item.get('method'),
                          'path': public_shape.template_path(item.get('path', '')),
                          'query_fields': [x for x in item.get('query_fields', []) if _FIELD.fullmatch(str(x))][:40],
                          'body_fields': [x for x in item.get('body_fields', []) if _FIELD.fullmatch(str(x))][:40]})
    observations = []
    for item in ctx.get('observations') or []:
        count = item.get('signal_count', len(item.get('signals') or []))
        observations.append({'id': item.get('id'), 'actor': item.get('actor'),
                             'path': public_shape.template_path(item.get('path', '')),
                             'status': item.get('status'), 'truncated': bool(item.get('truncated')),
                             'outcome': item.get('outcome') if item.get('outcome') in _OUTCOMES else 'unknown',
                             'signal_count': min(8, count) if isinstance(count, int) else 0})
    actions = [{'kind': a.get('kind'), 'category': a.get('category'), 'endpoint_id': a.get('endpoint_id'),
                'location': a.get('location'), 'param': a.get('param')}
               for a in (ctx.get('previous_actions') or [])]
    results = [{'category': v.get('category'), 'endpoint_id': v.get('endpoint_id'),
                'status': v.get('status') if v.get('status') in _VERDICTS else 'inconclusive'}
               for v in (ctx.get('verification_summary') or ctx.get('verified_results') or [])]
    recon = ctx.get('recon') or {}
    purpose = ctx.get('goal_purpose')
    result = {'export_mode': 'structured',
            'goal_purpose': purpose if isinstance(purpose, str) and purpose in _PURPOSES else 'general-verification',
            'requested_categories': ctx.get('requested_categories') or [],
            'allowed_categories': ctx.get('allowed_categories') or [],
            'target_scope': ctx.get('target_scope'),
            'actors': [{'id': a.get('id')} for a in (ctx.get('actors') or [])],
            'objects': [{'id': o.get('id'), 'path': public_shape.template_path(o.get('url', o.get('path', ''))),
                         'owner_actor': o.get('owner_actor'), 'allowed_actors': o.get('allowed_actors') or []}
                        for o in (ctx.get('objects') or [])],
            'endpoints': endpoints, 'observations': observations,
            'previous_actions': actions, 'verified_results': results,
            'recon': {'phase': recon.get('phase'), 'endpoint_count': recon.get('endpoint_count', 0),
                      'observed_endpoint_count': recon.get('observed_endpoint_count', 0),
                      'unobserved_get_count': recon.get('unobserved_get_count', 0),
                      'browser_endpoint_count': recon.get('browser_endpoint_count', 0),
                      'technologies': [name for name in recon.get('technologies', []) if name in _KNOWN_STACKS]},
            'remaining_requests': ctx.get('remaining_requests', 0)}
    costs = ctx.get('request_costs') or {}
    if isinstance(costs, dict):
        result['request_costs'] = {name: value for name, value in costs.items()
                                   if name in ('observe', 'probe', 'access', 'finish')
                                   and isinstance(value, int) and 0 <= value <= 150}
        confirmations = costs.get('confirm') or {}
        if isinstance(confirmations, dict):
            result['request_costs']['confirm'] = {
                name: value for name, value in confirmations.items()
                if name in ('sqli', 'auth', 'xss', 'ssti', 'lfi', 'ssrf', 'cmdi', 'redirect', 'nosql')
                and isinstance(value, int) and 0 <= value <= 150}
    feedback = ctx.get('planner_feedback') or {}
    if isinstance(feedback, dict) and feedback.get('code') in (
            'category_out_of_scope', 'missing_evidence_basis', 'invalid_evidence_basis', 'duplicate_action',
            'insufficient_request_budget', 'provider_temporary', 'invalid_action_schema'):
        result['planner_feedback'] = {'code': feedback['code'],
                                      'attempt': feedback.get('attempt'),
                                      'remaining_requests': feedback.get('remaining_requests')}
    return result
