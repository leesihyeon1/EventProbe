"""Build a local ZIP for one finding using only its stored evidence."""

import io
import json
import zipfile
from urllib.parse import parse_qsl, urlsplit

from core.agent_findings import build_findings


MAX_RAW_BYTES = 10 * 1024 * 1024


def _request_summary(request):
    request = request or {}
    try:
        url = urlsplit(request.get('url') or '')
        depth = len([segment for segment in (url.path or '/').split('/') if segment])
        query_count = len({key for key, _ in parse_qsl(url.query, keep_blank_values=True)} |
                          set(request.get('params') or {}))
    except (TypeError, ValueError):
        depth, query_count = 0, 0
    return {'method': request.get('method') or 'GET', 'path_depth': depth,
            'query_key_count': query_count, 'url_omitted': True}


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode('utf-8')


def build_finding_evidence_zip(run, finding_id, *, include_raw=False):
    """Return local ZIP bytes. Default export omits body, header values and URL values.

    Raw export is explicit and bounded. This function performs no I/O except
    writing to its in-memory ZIP; callers enforce access to the containing run.
    """
    data = run.get('data') or {}
    events = run.get('events') or []
    findings = run.get('findings')
    if findings is None:
        findings = build_findings(run.get('id', ''), data, events)
    finding = next((item for item in findings if item['id'] == finding_id), None)
    if finding is None:
        raise KeyError(finding_id)

    observations = {event['id']: event for event in events if event['kind'] == 'observation'}
    verifications = {event['id']: event for event in events if event['kind'] == 'verification'}
    evidence_ids = list(dict.fromkeys(finding.get('evidence_ids') or []))
    verification_ids = list(dict.fromkeys(finding.get('verification_ids') or []))
    if any(ref not in observations for ref in evidence_ids):
        raise ValueError('발견 근거 관측이 저장소에 없습니다.')
    if any(ref not in verifications for ref in verification_ids):
        raise ValueError('발견 판정이 저장소에 없습니다.')

    manifest = {
        'format': 'eventprobe-finding-evidence-v1',
        'scope': 'internal_raw' if include_raw else 'redacted',
        'run_id': run.get('id'), 'finding_id': finding_id,
        'finding': {key: finding.get(key) for key in
                    (('category', 'verdict', 'severity', 'status', 'actor_id',
                      'method', 'path', 'query_keys', 'incomplete_evidence') if include_raw else
                     ('category', 'verdict', 'severity', 'status', 'method', 'incomplete_evidence'))},
        'evidence': [], 'verifications': [],
    }
    files = []
    raw_size = 0
    for index, event_id in enumerate(evidence_ids, start=1):
        event = observations[event_id]
        observation = event.get('data') or {}
        request = observation.get('request') or {}
        response = observation.get('response') or {}
        name = f'evidence/{index:03d}.json'
        item = {
            'event_id': event_id,
            'step_id': event.get('step_id'), 'created': event.get('created'),
            'request': request if include_raw else _request_summary(request),
            'response': response if include_raw else {
                'status': response.get('status'), 'time_ms': response.get('time_ms'),
                'truncated': bool(response.get('truncated')),
                'body_omitted': True, 'headers_omitted': True,
            },
        }
        if include_raw:
            item['actor_id'] = observation.get('actor_id')
        content = _json_bytes(item)
        raw_size += len(content)
        if raw_size > MAX_RAW_BYTES:
            raise ValueError('증거 패키지 크기 한도를 초과했습니다.')
        files.append((name, content))
        manifest['evidence'].append({'event_id': event_id, 'file': name})
    for index, event_id in enumerate(verification_ids, start=1):
        event = verifications[event_id]
        verdict = event.get('data') or {}
        name = f'verifications/{index:03d}.json'
        item = verdict if include_raw else {
            'status': verdict.get('status'),
            'evidence_ids': [ref for ref in verdict.get('evidence_ids') or [] if ref in observations],
            'missing_evidence_count': sum(ref not in observations for ref in verdict.get('evidence_ids') or []),
        }
        content = _json_bytes(item)
        raw_size += len(content)
        if raw_size > MAX_RAW_BYTES:
            raise ValueError('증거 패키지 크기 한도를 초과했습니다.')
        files.append((name, content))
        manifest['verifications'].append({'event_id': event_id, 'file': name})

    files.insert(0, ('manifest.json', _json_bytes(manifest)))
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files:
            archive.writestr(name, content)
    return output.getvalue()
