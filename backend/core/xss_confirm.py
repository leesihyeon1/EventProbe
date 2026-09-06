"""브라우저(헤드리스) 기반 XSS 확증 — 실제 실행을 관측해 반사형/DOM XSS 를 확정한다.

정적 분석은 '소스→싱크 흐름'까지만 볼 수 있고, 실제 스크립트 실행은 브라우저에서만
확인된다(예: 트래커의 document.write 가 location.search 를 인코딩 없이 써서 payload 가
실행되는 DOM XSS). 이 모듈은 대상 URL(payload 포함)을 헤드리스 크로미움으로 로드해
alert/confirm/prompt/print 실행 훅과 주입된 실행형 요소로 '실제 실행'을 관측한다.

- api.py 가 전송 계층(스레드에서 실행). 이 모듈은 순수 브라우저 관측.
- 대상 페이지의 JS 를 실제 실행하므로, 허가된 테스트 대상에만 사용해야 한다.
"""
from __future__ import annotations

# 실행 훅: alert/confirm/prompt/print 를 '원본 호출 없이' 기록만 → 실제 대화상자 없이 실행 관측.
# (eval 훅은 우리 page.evaluate 호출까지 잡는 자기오염이 있어 제외 — alert 계열+주입요소로 충분)
_INIT_SCRIPT = r"""
(() => {
  window.__xss__ = [];
  const rec = (k, v) => { try { window.__xss__.push([k, String(v).slice(0,120)]); } catch(e){} };
  for (const f of ['alert','confirm','prompt','print']) {
    try { window[f] = function(){ rec(f, arguments[0]); return undefined; }; } catch(e){}
  }
})();
"""


def _confirm_sync(url: str, timeout: float) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"error": f"playwright 미설치: {e}", "supported": False}

    fired, console_errs = [], []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(ignore_https_errors=True, locale="ko-KR")
            page = ctx.new_page()
            page.add_init_script(_INIT_SCRIPT)
            # 네이티브 대화상자(우리가 못 감싼 경로)도 백업으로 포착 후 자동 닫기
            page.on("dialog", lambda d: (fired.append(["dialog", (d.message or "")[:120]]), d.dismiss()))
            page.on("console", lambda m: console_errs.append(m.text[:120]) if m.type == "error" else None)
            try:
                page.goto(url, wait_until="load", timeout=timeout * 1000)
            except Exception:
                pass
            try:
                page.wait_for_timeout(1500)   # onload/지연 실행 여유
            except Exception:
                pass
            hooks = []
            try:
                hooks = page.evaluate("window.__xss__ || []")
            except Exception:
                pass
            injected = 0
            try:
                injected = page.evaluate(
                    "document.querySelectorAll("
                    "'svg[onload],img[onerror],body[onload],iframe[onload],video[onerror],"
                    "audio[onerror],details[ontoggle],marquee[onstart],object[onerror]').length")
            except Exception:
                pass
            browser.close()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:200]}", "supported": True}

    hooks = list(hooks or [])
    executed = bool(fired) or bool(hooks)
    return {
        "supported": True,
        "executed": executed,
        "signals": (fired + hooks)[:5],           # [['alert','1'], ...]
        "injected_elements": injected,             # 실행형 이벤트 핸들러 요소 수
    }


async def confirm_xss(url: str, timeout: float = 15) -> dict:
    """동기 Playwright 확증을 워커 스레드에서 실행(이벤트 루프 충돌 회피)."""
    import asyncio
    return await asyncio.to_thread(_confirm_sync, url, timeout)
