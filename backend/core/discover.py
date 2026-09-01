"""SPA 정적 API 발견 — JS 번들을 받아 앱이 호출하는 실제 API를 추출한다.

SPA는 서버가 빈 껍데기만 주고 실제 API는 브라우저가 JS로 호출한다. 하지만 그 JS 번들
자체는 평범한 HTTP로 받을 수 있고, 번들 안에는 axios/fetch 호출의 **호스트·엔드포인트
경로가 문자열 리터럴**로 남아 있는 경우가 많다. 이를 정적으로 긁어 "이 앱이 어떤 백엔드의
어떤 엔드포인트를 부르는지"를 자동으로 알려준다(헤드리스 브라우저 불필요).

한계: 파라미터 값·경로/호스트의 정확한 결합은 정적으로 100% 복원되지 않는다 → '추정 리드'.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
_BASE_HREF_RE = re.compile(r'<base[^>]+href=["\']([^"\']+)["\']', re.I)
# api 를 포함하는 호스트 + 선택적 /v1.0 버전 접두
_BASE_RE   = re.compile(r'https?://[a-z0-9.\-]*api[a-z0-9.\-]*\.[a-z]{2,}(?:/v[\d.]+)?', re.I)
# axios/fetch 스타일 호출: .get("/path") .post("/path") …
_CALL_RE   = re.compile(r'\.(get|post|put|delete|patch)\(\s*["\'`](/[^"\'`\s){]{1,60})', re.I)
# 폰트·트래킹 등 노이즈 호스트 제외(googleapis 는 'api' 를 포함하므로 명시 제외)
_NOISE_RE  = re.compile(r'(google|gstatic|analytics|doubleclick|facebook|sentry|newrelic|hotjar|clarity)', re.I)

_MAX_SCRIPTS = 5
_MAX_TOTAL   = 12_000_000   # 번들 총 스캔 바이트 상한(~12MB)


def extract_apis(js: str) -> tuple[set, set]:
    bases, endpoints = set(), set()
    for m in _BASE_RE.finditer(js):
        b = m.group(0)
        if not _NOISE_RE.search(b):
            bases.add(b)
    for m in _CALL_RE.finditer(js):
        endpoints.add(m.group(1).upper() + " " + m.group(2))
    return bases, endpoints


async def discover(client, url: str, timeout: float = 15) -> dict:
    """페이지의 JS 번들을 받아 API 백엔드·엔드포인트를 추출."""
    try:
        r = await client.get(url, timeout=timeout)
        html = r.text
    except Exception as e:
        return {"error": str(e)[:120], "bases": [], "endpoints": [], "scripts_scanned": 0}

    # <base href> 반영(SPA는 흔히 <base href="/"> 로 상대경로 기준을 루트로 바꾼다)
    bh = _BASE_HREF_RE.search(html)
    base_url = urljoin(url, bh.group(1)) if bh else url

    srcs, seen = [], set()
    for m in _SCRIPT_RE.finditer(html):
        u = urljoin(base_url, m.group(1))
        if u not in seen:
            seen.add(u)
            srcs.append(u)

    bases, endpoints, total, scanned = set(), set(), 0, 0
    for s in srcs[:_MAX_SCRIPTS]:
        try:
            jr = await client.get(s, timeout=timeout)
        except Exception:
            continue
        js = jr.text
        scanned += 1
        total += len(js)
        b, e = extract_apis(js)
        bases |= b
        endpoints |= e
        if total > _MAX_TOTAL:
            break

    eps = []
    for e in sorted(endpoints):
        meth, _, path = e.partition(" ")
        eps.append({"method": meth, "path": path})

    return {
        "bases": sorted(bases),
        "endpoints": eps[:60],
        "scripts_scanned": scanned,
    }
