"""Finding packages use synthetic stored events and no target or model I/O."""

import io
import json
import zipfile

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from core.agent_evidence_export import build_finding_evidence_zip
from core.agent_findings import build_findings
from routers import agent as agent_router


def fixture_run():
    secret = 'SECRET_RESPONSE_TOKEN'
    request = {'method': 'GET', 'url': 'https://internal.example.test/customer/123?q=SECRET_QUERY',
               'params': {}, 'headers': {'Authorization': 'SECRET_HEADER'}, 'body': ''}
    events = [
        {'id': 'action', 'kind': 'action', 'step_id': 'step', 'created': 1,
         'data': {'kind': 'probe', 'category': 'xss', 'endpoint_id': 'seed', 'actor_id': 'owner'}},
        {'id': 'obs1', 'kind': 'observation', 'step_id': 'step', 'created': 2,
         'data': {'request': request, 'actor_id': 'owner', 'response': {
             'status': 200, 'headers': {'X-Private': 'SECRET_RESPONSE_HEADER'},
             'body': secret, 'time_ms': 8}}},
        {'id': '../unrelated', 'kind': 'observation', 'step_id': 'other', 'created': 3,
         'data': {'request': {'url': 'https://other.example.test/'},
                  'response': {'status': 200, 'body': 'UNRELATED_PRIVATE_BODY'}}},
        {'id': 'ver1', 'kind': 'verification', 'step_id': 'step', 'created': 4,
         'data': {'status': 'confirmed', 'evidence_ids': ['obs1', 'missing'],
                  'limitations': ['SECRET_NOTE']}},
    ]
    data = {'spec': {'goal': 'SECRET_GOAL'}, 'endpoints': {'seed': request}}
    run = {'id': 'synthetic-run', 'state': 'completed', 'data': data, 'events': events}
    run['findings'] = build_findings(run['id'], data, events)
    return run


def entries(content):
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.testzip() is None
        return {name: archive.read(name) for name in archive.namelist()}


def test_default_package_is_scoped_and_omits_values_and_unrelated_evidence():
    run = fixture_run()
    exported = entries(build_finding_evidence_zip(run, run['findings'][0]['id']))
    assert sorted(exported) == ['evidence/001.json', 'manifest.json', 'verifications/001.json']
    content = b''.join(exported.values())
    for secret in (b'SECRET_RESPONSE_TOKEN', b'SECRET_HEADER', b'SECRET_RESPONSE_HEADER',
                   b'SECRET_QUERY', b'SECRET_GOAL', b'SECRET_NOTE', b'UNRELATED_PRIVATE_BODY',
                   b'internal.example.test', b'customer/123'):
        assert secret not in content
    manifest = json.loads(exported['manifest.json'])
    assert manifest['scope'] == 'redacted'
    assert manifest['finding']['incomplete_evidence'] is True
    verdict = json.loads(exported['verifications/001.json'])
    assert verdict['evidence_ids'] == ['obs1'] and verdict['missing_evidence_count'] == 1
    assert json.loads(exported['evidence/001.json'])['response']['body_omitted'] is True


def test_raw_package_explicitly_includes_only_selected_originals():
    run = fixture_run()
    exported = entries(build_finding_evidence_zip(run, run['findings'][0]['id'], include_raw=True))
    content = b''.join(exported.values())
    assert b'SECRET_RESPONSE_TOKEN' in content and b'SECRET_QUERY' in content
    assert b'SECRET_NOTE' in content
    assert b'UNRELATED_PRIVATE_BODY' not in content
    assert json.loads(exported['manifest.json'])['scope'] == 'internal_raw'


def test_unknown_finding_or_missing_selected_evidence_fails_closed():
    run = fixture_run()
    with pytest.raises(KeyError):
        build_finding_evidence_zip(run, 'missing')
    run['events'] = [event for event in run['events'] if event['id'] != 'obs1']
    with pytest.raises(ValueError, match='관측'):
        build_finding_evidence_zip(run, run['findings'][0]['id'])


def test_route_checks_run_access_and_returns_local_attachment(monkeypatch):
    run = fixture_run()
    calls = []

    class Manager:
        def check_access(self, run_id, principal):
            calls.append(('access', run_id, principal))
            if principal == 'blocked':
                raise PermissionError('denied')

        def snapshot(self, run_id):
            calls.append(('snapshot', run_id))
            return run

    monkeypatch.setattr(agent_router, 'get_manager', lambda: Manager())
    fid = run['findings'][0]['id']
    request = Request({'type': 'http', 'headers': [(b'x-eventprobe-user', b'owner')]})
    response = agent_router.download_finding_evidence(run['id'], fid, request)
    assert response.media_type == 'application/zip'
    assert response.headers['cache-control'] == 'no-store'
    assert response.headers['content-disposition'].startswith('attachment;')
    assert json.loads(entries(response.body)['manifest.json'])['scope'] == 'redacted'
    assert calls == [('access', run['id'], 'owner'), ('snapshot', run['id'])]
    blocked = Request({'type': 'http', 'headers': [(b'x-eventprobe-user', b'blocked')]})
    with pytest.raises(HTTPException) as exc:
        agent_router.download_finding_evidence(run['id'], fid, blocked)
    assert exc.value.status_code == 403
    assert calls[-1] == ('access', run['id'], 'blocked')
