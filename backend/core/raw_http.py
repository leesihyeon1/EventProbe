"""
Raw 소켓 HTTP 전송 — 요청라인의 HTTP 버전 문자열을 그대로(비정상 포함) 송신.
httpx 는 요청라인 버전을 임의 지정할 수 없어, HTTP/1.0·변형 버전 등
스캐너 흉내 요청을 위해 소켓 레벨에서 직접 전송한다.

주의: httpx 의 안전장치를 거치지 않음 — 리다이렉트 자동추적 없음, 최선 노력 파싱.
"""
import socket
import ssl
import gzip
import zlib
import time
from urllib.parse import urlsplit

try:
    import brotli  # 선택
except Exception:
    brotli = None


def _decompress(body: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if "br" in enc and brotli:
            return brotli.decompress(body)
    except Exception:
        return body
    return body


def _recv_all(sock, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            b = sock.recv(65536)
            if not b:
                break
            chunks.append(b)
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    return b"".join(chunks)


def raw_send(method: str, url: str, headers: dict, body, http_version: str, timeout: float = 10.0):
    """소켓으로 직접 요청 전송 후 응답 파싱. 실패 시 예외 발생(호출부에서 처리)."""
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    # 경로는 urlsplit 이 원문 유지(%2e·../ 정규화 안 함)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    version = (http_version or "HTTP/1.1").strip()
    body_bytes = body.encode() if isinstance(body, str) else (body or b"")

    # 헤더 정리(대소문자 무시로 존재 여부 판단). 사용자 헤더는 최대한 그대로 송신.
    hdrs = dict(headers or {})
    lower = {k.lower() for k in hdrs}
    if "host" not in lower:
        hdrs["Host"] = host if port in (80, 443) else f"{host}:{port}"
    if body_bytes and "content-length" not in lower:
        hdrs["Content-Length"] = str(len(body_bytes))
    if "connection" not in lower:
        hdrs["Connection"] = "close"   # 응답 끝까지 읽기 위해

    # 요청 바이트 구성
    req_line = f"{method.upper()} {path} {version}\r\n"
    head = req_line + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    raw_request = head + (body_bytes.decode("latin1") if body_bytes else "")
    data = head.encode("latin1", "ignore") + body_bytes

    start = time.time()
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock
        sock.sendall(data)
        resp = _recv_all(sock, timeout)
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass
    elapsed = (time.time() - start) * 1000

    # 응답 파싱
    sep = resp.find(b"\r\n\r\n")
    if sep == -1:
        head_bytes, body_raw = resp, b""
    else:
        head_bytes, body_raw = resp[:sep], resp[sep + 4:]
    head_text = head_bytes.decode("latin1", "replace")
    lines = head_text.split("\r\n")
    status_line = lines[0] if lines else ""
    status_code = 0
    m = status_line.split(" ")
    if len(m) >= 2 and m[1].isdigit():
        status_code = int(m[1])

    resp_headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip()] = v.strip()

    # chunked / gzip 등 최선 노력 처리
    te = resp_headers.get("Transfer-Encoding", "") or resp_headers.get("transfer-encoding", "")
    if "chunked" in te.lower():
        body_raw = _dechunk(body_raw)
    ce = ""
    for k, v in resp_headers.items():
        if k.lower() == "content-encoding":
            ce = v
    if ce:
        body_raw = _decompress(body_raw, ce)

    body_text = body_raw.decode("utf-8", "replace")
    return {
        "status_code": status_code,
        "status_line": status_line,
        "headers": resp_headers,
        "body": body_text[:50000],
        "response_time": round(elapsed, 2),
        "body_size": len(body_raw),
        "request_line": req_line.strip(),
        "raw_request": raw_request[:8000],
    }


def _dechunk(data: bytes) -> bytes:
    out = b""
    i = 0
    try:
        while i < len(data):
            j = data.find(b"\r\n", i)
            if j == -1:
                break
            size = int(data[i:j].split(b";")[0], 16)
            if size == 0:
                break
            out += data[j + 2:j + 2 + size]
            i = j + 2 + size + 2
    except Exception:
        return data
    return out
