"""Completion wrappers write only safe projections and do not send another request."""

import asyncio

from routers import api


def test_raw_route_records_parsed_shape_once(monkeypatch):
    calls = []

    async def fake_send(_):
        return {'status_code': 204, 'parsed_request': {
            'method': 'POST', 'url': 'https://example.test/path?token=SECRET_VALUE'},
            'body': 'SECRET_BODY'}

    monkeypatch.setattr(api, 'send_request_raw', fake_send)
    monkeypatch.setattr(api, '_record_traffic_batch', lambda request, entries: calls.extend(entries))
    result = asyncio.run(api.send_request_raw_endpoint(api.RawRequest(raw='placeholder'), object()))
    assert result['status_code'] == 204
    assert len(calls) == 1
    assert calls[0][0] == {'url': 'https://example.test/path?token=SECRET_VALUE', 'method': 'POST'}
    assert calls[0][1:] == (204, 'raw')

    async def rejected(_):
        return {'error': 'raw parse rejected'}

    monkeypatch.setattr(api, 'send_request_raw', rejected)
    asyncio.run(api.send_request_raw_endpoint(api.RawRequest(raw='invalid'), object()))
    assert len(calls) == 1


def test_multi_route_records_each_completed_result_without_payload(monkeypatch):
    calls = []

    async def fake_send(_):
        first = {'url': 'https://one.test/path?token=SECRET_URL', 'results': [
            {'status_code': 200, 'payload': 'SECRET_PAYLOAD'},
            {'status_code': 0, 'payload': ''}]}
        return {'targets': [first, first, {'url': 'https://two.test/path', 'results': [
                {'status_code': 404, 'payload': 'SECRET_PAYLOAD'}]}], 'target_count': 3}

    monkeypatch.setattr(api, 'multi_target_test', fake_send)
    monkeypatch.setattr(api, '_record_traffic_batch', lambda request, entries: calls.extend(entries))
    req = api.MultiTargetRequest(method='GET', urls=['https://one.test', 'https://two.test'],
                                  target_param='id', payload_ids=[], category='test')
    result = asyncio.run(api.multi_target_test_endpoint(req, object()))
    assert result['target_count'] == 3
    assert len(calls) == 3
    assert calls[0] == ({'url': 'https://one.test/path?token=SECRET_URL',
                         'method': 'GET', 'params': {'id': ''}}, 200, 'multi')
    assert calls[1][0]['params'] == {}
    assert calls[2][1:] == (404, 'multi')
    assert 'SECRET_PAYLOAD' not in str(calls)
