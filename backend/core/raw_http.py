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


# ── Raw HTTP 요청 패킷 파싱(SOAR 등 외부 연동용) ──────────────────────────────
# 프론트엔드 parseRawHttp(app.js)의 서버측 포팅. SOAR incident 에서 만든 raw 패킷을
# 그대로 받아 {method, url, headers, body, http_version} 로 분해한다. 그 뒤 기존 전송·판정
# 흐름을 그대로 재사용한다(구조화 재입력 불필요).
import re as _re

# 유효한 헤더 이름 토큰(RFC 7230 tchar) + ':' — JSON 본문 {"q":"..."} 이 헤더로 오인되지 않게 한다.
_HDR_LINE = _re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+:")
_HTTP_VER = _re.compile(r"^HTTP/[\d.]+$", _re.I)

# 헤더 경계 후보: 공백 + '헤더이름:' + 공백. SOAR/티켓이 줄바꿈을 다 지워 한 줄로 만든 패킷을
# 복원(reflow)할 때 이 앞에 개행을 넣는다. URL 스킴(https:)은 ':'뒤가 '//'라 매칭 안 됨(안전).
_HDR_BOUNDARY = _re.compile(r"\s+(?=[!#$%&'*+.^_`|~0-9A-Za-z-]+:[ \t])")


def _reflow_single_line(text: str) -> str:
    """줄바꿈이 소실돼 한 줄로 붙은 HTTP 패킷을 헤더 경계마다 개행 삽입해 복원(best-effort).

    'GET /p Accept-Language: en Host: h ...' → 'GET /p\\nAccept-Language: en\\nHost: h\\n...'
    헤더 값 안에 우연히 'Word: ' 패턴이 있으면 과분할될 수 있는 휴리스틱이라, 이미 줄바꿈이
    있는 정상 패킷에는 절대 적용하지 않는다(호출부에서 단일 라인일 때만 호출).
    """
    return _HDR_BOUNDARY.sub("\n", text)


def parse_raw_request(raw: str, scheme: str = "https", host_override: str = "") -> dict:
    """raw HTTP 요청 패킷 → {method, url, headers, body, http_version, host}.

    - 요청라인: 'METHOD URI [HTTP/x.x]'. URI 에 인코딩 안 된 공백(SQLi ' OR 1=1 -- ')이 있어도
      첫 토큰=메서드 / 마지막이 HTTP/x.x 면 버전 / 그 사이 전체(공백 포함)=URI 로 파싱.
    - 헤더/본문 경계: 빈 줄 또는 '헤더 형식이 아닌 첫 줄'. (빈 줄이 collapse 된 붙여넣기 대응)
    - URL: URI 가 절대 URL 이면 그대로, 아니면 scheme://<Host 헤더>+URI.
    """
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n")
    # 줄바꿈이 다 사라진 한 줄 패킷(SOAR/티켓 flatten)이고 헤더 경계가 보이면 복원한다.
    if "\n" not in text.strip() and _HDR_BOUNDARY.search(text):
        text = _reflow_single_line(text)
    lines = text.split("\n")
    req_line = (lines.pop(0) if lines else "").strip()

    header_lines, body_start = [], len(lines)
    for i, ln in enumerate(lines):
        t = ln.strip()
        if t == "":
            body_start = i + 1
            break
        if not _HDR_LINE.match(t):
            body_start = i
            break
        header_lines.append(t)
    body = "\n".join(lines[body_start:])

    method, target, http_version = "GET", "/", ""
    tokens = [t for t in _re.split(r"\s+", req_line) if t]
    if len(tokens) >= 2 and tokens[0].isalpha():
        method = tokens[0].upper()
        end = len(tokens)
        if _HTTP_VER.match(tokens[end - 1]):
            http_version = tokens[end - 1]
            end -= 1
        target = " ".join(tokens[1:end]) or "/"

    headers = {}
    for h in header_lines:
        idx = h.find(":")
        if idx <= 0:
            continue
        headers[h[:idx].strip()] = h[idx + 1:].strip()

    host = host_override or next(
        (v for k, v in headers.items() if k.lower() == "host"), "")

    if _re.match(r"^https?://", target, _re.I):
        url = target                                   # 절대 URL(프록시 스타일)은 그대로
    else:
        sch = (scheme or "https").lower()
        path = target if target.startswith("/") else "/" + target
        url = f"{sch}://{host}{path}" if host else path

    return {"method": method, "url": url, "headers": headers, "body": body,
            "http_version": http_version, "host": host}
