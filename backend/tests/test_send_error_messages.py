"""전송 실패 예외를 사용자용 메시지로 분류한다(요청/분석 탭).

httpx 는 socket 예외를 감싸므로(ConnectError → gaierror), 원인 체인을 훑어
DNS/거부/도달불가/TLS/타임아웃을 구분하고 기술 원문을 중복 없이 한 번만 붙인다.
"""
import socket

import httpx

from routers.api import _friendly_send_error


def _raise(exc, cause=None):
    try:
        if cause is not None:
            raise exc from cause
        raise exc
    except Exception as e:  # noqa: BLE001 — 분류 대상 예외를 그대로 받는다
        return e


def test_dns_failure_is_explained_not_raw_getaddrinfo():
    # 사용자 케이스: ConnectError 가 socket.gaierror(11001) 를 감쌈.
    e = _raise(httpx.ConnectError('[Errno 11001] getaddrinfo failed'),
               socket.gaierror(11001, 'getaddrinfo failed'))
    msg = _friendly_send_error(e)
    assert 'DNS 조회 실패' in msg and '호스트명' in msg
    # 기술 원문은 참고용으로 한 번만(중복 'ConnectError ... (ConnectError ...)' 금지).
    assert msg.count('getaddrinfo failed') == 1
    assert msg.count('ConnectError') == 1


def test_linux_style_dns_text_also_classified():
    e = _raise(httpx.ConnectError('[Errno -2] Name or service not known'))
    assert 'DNS 조회 실패' in _friendly_send_error(e)


def test_connection_refused():
    e = _raise(httpx.ConnectError('[Errno 10061] Connection refused'))
    assert '연결 거부' in _friendly_send_error(e)


def test_network_unreachable():
    e = _raise(httpx.ConnectError('[Errno 10051] Network is unreachable'))
    assert '도달 불가' in _friendly_send_error(e)


def test_tls_error():
    e = _raise(httpx.ConnectError('certificate verify failed: self signed certificate'))
    assert 'TLS' in _friendly_send_error(e) or '인증서' in _friendly_send_error(e)


def test_generic_connect_error_without_detail_still_actionable():
    e = _raise(httpx.ConnectError(''))
    msg = _friendly_send_error(e)
    assert '연결 실패' in msg and 'ConnectError' in msg


def test_bulk_test_uses_friendly_dns_error(monkeypatch):
    """일괄 테스트도 페이로드별 전송 실패를 친화적 메시지로 표시(단일 전송과 동일)."""
    import asyncio
    from routers import api as api_mod
    from routers.api import bulk_test, BulkRequest

    class _MockClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def request(self, *a, **k):
            raise httpx.ConnectError('[Errno 11001] getaddrinfo failed')

    monkeypatch.setattr(httpx, 'AsyncClient', lambda *a, **k: _MockClient())
    monkeypatch.setattr(api_mod, '_record_traffic_batch', lambda *a, **k: None)  # 로컬 DB 미접촉

    class _Req:   # 트래픽 기록용 최소 request 대역
        headers = {}
        cookies = {}

    req = BulkRequest(method='GET', url='http://no-such-host.invalid/', category='sqli',
                      payload_ids=['sqli_01'], target_param='q', inject_in='params')
    out = asyncio.run(bulk_test(req, _Req()))
    r0 = out['results'][0]
    assert r0['status_code'] == 0
    assert 'DNS 조회 실패' in r0['error']
    assert r0['analysis']['verdict'] == 'error'
    assert any('DNS 조회 실패' in d for d in r0['analysis']['details'])
    assert 'getaddrinfo failed' not in r0['analysis']['details'][0].split('·')[0]  # 원문이 앞에 나오지 않음


def test_send_endpoint_returns_structured_dns_error(monkeypatch):
    """단일 전송 엔드포인트가 DNS 실패를 500 이 아니라 구조화된 error 로 반환한다."""
    import asyncio
    from routers.api import send_request, SingleRequest

    class _Boom:
        async def __aenter__(self):
            raise httpx.ConnectError('[Errno 11001] getaddrinfo failed')
        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(httpx, 'AsyncClient', lambda *a, **k: _Boom())
    req = SingleRequest(method='GET', url='http://no-such-host.invalid/', inline_ai=False)
    out = asyncio.run(send_request(req))
    assert out['status_code'] == 0
    assert 'DNS 조회 실패' in out['error']
    assert out['analysis']['verdict'] == 'error'
    assert any('DNS 조회 실패' in d for d in out['analysis']['details'])
