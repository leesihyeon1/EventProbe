"""헤드리스 브라우저로 SPA의 실제 API 호출을 캡처 (Playwright).

정적 분석과 달리 페이지를 실제로 실행하므로, 앱이 보내는 XHR/fetch 를 **파라미터까지
그대로** 잡을 수 있다. 결과는 HAR 과 동일한 엔트리 형식으로 돌려주어 프론트의 기존
HAR 처리(harEntryToNorm/fillFromParsed)를 그대로 재사용한다.

Windows 참고: uvicorn 의 asyncio 루프(SelectorEventLoop)에서는 서브프로세스를 못 띄워
Playwright **비동기** API 가 NotImplementedError 를 낸다. 그래서 **동기 API 를 별도
워커 스레드**(자체 이벤트 루프)에서 돌리고, FastAPI 는 asyncio.to_thread 로 대기한다.
"""
from __future__ import annotations

import asyncio


def _capture_sync(url: str, timeout: float) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"error": f"playwright 미설치: {e}", "entries": []}

    captured: list[dict] = []
    responses: dict[str, dict] = {}

    def on_request(request):
        try:
            if request.resource_type in ("xhr", "fetch"):
                captured.append({
                    "method": request.method,
                    "url": request.url,
                    "headers": dict(request.headers or {}),
                    "post_data": request.post_data,
                })
        except Exception:
            pass

    def on_response(response):
        try:
            responses[response.url] = {
                "status": response.status,
                "mime": (response.headers or {}).get("content-type", ""),
            }
        except Exception:
            pass

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True, locale="ko-KR")
            page = context.new_page()
            page.on("request", on_request)
            page.on("response", on_response)
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
            except Exception:
                pass   # networkidle 미달(폴링 등)이어도 캡처분 사용
            try:
                page.wait_for_timeout(1500)   # 지연 발화 XHR 여유
            except Exception:
                pass
            browser.close()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"[:300], "entries": []}

    entries = []
    for c in captured:
        resp = responses.get(c["url"], {})
        entries.append({
            "request": {
                "method": c["method"],
                "url": c["url"],
                "headers": [{"name": k, "value": v} for k, v in (c["headers"] or {}).items()],
                "postData": ({"text": c["post_data"]} if c["post_data"] else None),
            },
            "response": {
                "status": resp.get("status", 0),
                "content": {"mimeType": resp.get("mime", "")},
            },
        })
    return {"entries": entries, "captured": len(entries)}


async def capture_apis(url: str, timeout: float = 25) -> dict:
    """동기 Playwright 캡처를 워커 스레드에서 실행(이벤트 루프 충돌 회피)."""
    return await asyncio.to_thread(_capture_sync, url, timeout)
