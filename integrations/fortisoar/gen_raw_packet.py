"""FortiSOAR → 검증도구 연동 (1단계) : incident 데이터로 raw HTTP 패킷 생성.

FortiSOAR '버튼①(패킷 생성)' 플레이북의 Execute Python Block 에 이 파일 내용을 붙여넣고,
스텝 마지막에서 main(params) 를 호출한다. 반환된 raw_request 를 편집 가능한 레코드 필드
(예: raw_request)에 Set 해두면, 분석가가 그 필드를 눈으로 수정한 뒤 '버튼②(검증)' 를 누른다.

입력(params) — incident/alert 필드에서 채워 넘긴다. 전부 선택이며 있는 것만 쓴다:
    method   : "GET" | "POST" ...            (기본 GET)
    url      : "https://target/path?q=1"      (전체 URL 권장 — Host·경로 자동 분해)
    path     : "/path?q=1"                     (url 대신 경로만 줄 때)
    host     : "target.com"                    (url 없이 path 만 줄 때 Host 헤더용)
    headers  : dict | ["K: V", ...] | "K: V\\nK2: V2"  (셋 다 허용)
    body     : "..."                           (POST 등 본문)
    http_version : "HTTP/1.1"                  (기본 HTTP/1.1)

반환: {"raw_request": "<요청라인+헤더+본문>"}  — CRLF 로 조립한 표준 패킷.

로컬 테스트:  python gen_raw_packet.py '{"url":"https://t/admin","method":"GET"}'
"""
from urllib.parse import urlsplit

_CRLF = "\r\n"


def _norm_headers(headers):
    """dict / ["K: V"] / "K: V\\nK2: V2" 어느 형태든 [(name, value)] 리스트로."""
    out = []
    if not headers:
        return out
    if isinstance(headers, dict):
        return [(str(k), str(v)) for k, v in headers.items()]
    items = headers if isinstance(headers, (list, tuple)) else str(headers).splitlines()
    for line in items:
        line = str(line).strip()
        if not line:
            continue
        idx = line.find(":")
        if idx <= 0:
            continue
        out.append((line[:idx].strip(), line[idx + 1:].strip()))
    return out


def build_raw_packet(method="GET", url="", path="", host="", headers=None,
                     body="", http_version="HTTP/1.1"):
    """구조화 입력 → raw HTTP 요청 패킷 문자열(CRLF)."""
    method = (method or "GET").upper().strip()
    http_version = (http_version or "HTTP/1.1").strip()

    # URL 이 있으면 host/path 를 거기서 뽑는다(직접 준 host/path 보다 우선).
    if url:
        u = urlsplit(url if "://" in url else "//" + url)
        host = u.netloc or host
        target = u.path or "/"
        if u.query:
            target += "?" + u.query
    else:
        target = path or "/"
        if not target.startswith("/"):
            target = "/" + target

    hdrs = _norm_headers(headers)
    have = {k.lower() for k, _ in hdrs}

    # Host 헤더 보장(요청라인이 상대경로일 때 필수). 입력 host 를 최우선으로 얹는다.
    if "host" not in have and host:
        hdrs.insert(0, ("Host", host))

    body = body or ""
    if body and "content-length" not in have:
        hdrs.append(("Content-Length", str(len(body.encode("utf-8")))))

    lines = [f"{method} {target} {http_version}"]
    lines += [f"{k}: {v}" for k, v in hdrs]
    head = _CRLF.join(lines) + _CRLF + _CRLF        # 헤더 끝 빈 줄
    return head + body


def main(params):
    """FortiSOAR Execute Python Block 진입점. params = 스텝 arguments(dict)."""
    params = params or {}
    raw = build_raw_packet(
        method=params.get("method", "GET"),
        url=params.get("url", ""),
        path=params.get("path", ""),
        host=params.get("host", ""),
        headers=params.get("headers"),
        body=params.get("body", ""),
        http_version=params.get("http_version", "HTTP/1.1"),
    )
    return {"raw_request": raw}


if __name__ == "__main__":   # 로컬 테스트용
    import json
    import sys
    p = json.loads(sys.argv[1]) if len(sys.argv) > 1 else json.loads(sys.stdin.read() or "{}")
    print(main(p)["raw_request"])
