"""Bounded, read-only browser reconnaissance for autonomous runs."""
import asyncio
from pathlib import Path
import threading
from urllib.parse import urlencode, urlsplit

from core import analyzer


def _launch(playwright):
    """Use the bundled browser when present, otherwise installed Chromium channels."""
    errors = []
    candidates = [({}, 'chromium'), ({'channel': 'msedge'}, 'edge'),
                  ({'channel': 'chrome'}, 'chrome')]
    for options, label in candidates:
        if not options and not Path(playwright.chromium.executable_path).is_file():
            continue
        try:
            return playwright.chromium.launch(headless=True, **options), label
        except Exception:
            errors.append(label)
    return None, 'browser_launch_failed' if errors else 'browser_missing'


def readiness():
    """Local preflight. Does not navigate or capture a target page."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {'ready': False, 'code': 'playwright_unavailable'}
    try:
        with sync_playwright() as playwright:
            browser, label = _launch(playwright)
            if browser is None:
                return {'ready': False, 'code': label}
            try:
                page = browser.new_page()
                guarded = hasattr(page, 'route_web_socket')
                return {'ready': guarded, 'code': 'ready' if guarded else 'websocket_guard_unavailable',
                        'engine': label, 'version': browser.version,
                        'capabilities': ['same_origin_get', 'document', 'script', 'xhr', 'fetch'] if guarded else []}
            finally:
                browser.close()
    except Exception:
        return {'ready': False, 'code': 'browser_launch_failed'}


def _origin(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            return None
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == 'https' else 80)
    except ValueError:
        return None


def _capture_sync(url, pages, limit, timeout, permit, reserve=None, cancelled=None):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {'requests': [], 'error': 'playwright_unavailable'}

    found, responses, forms = [], {}, []
    timed_out = False
    root = _origin(url)
    try:
        with sync_playwright() as playwright:
            browser, launch_status = _launch(playwright)
            if browser is None:
                return {'requests': [], 'error': launch_status}
            try:
                context = browser.new_context(service_workers='block', accept_downloads=False)
                page = context.new_page()
                if not hasattr(page, 'route_web_socket'):
                    return {'requests': [], 'error': 'websocket_guard_unavailable'}
                page.route_web_socket('**/*', lambda route: route.close())

                def route_request(route):
                    request = route.request
                    method = request.method.upper()
                    target = request.url
                    if ((cancelled is not None and cancelled.is_set()) or
                            _origin(target) != root or method not in ('GET', 'HEAD') or
                            request.resource_type not in ('document', 'script', 'xhr', 'fetch') or
                            len(found) >= limit or not permit(method, target)):
                        route.abort()
                        return
                    try:
                        request_id = reserve(method, target, request.resource_type) if reserve else None
                    except Exception:
                        route.abort()
                        return
                    if reserve and not request_id:
                        route.abort()
                        return
                    found.append({'method': method, 'url': target,
                                  'resource_type': request.resource_type,
                                  'request_id': request_id})
                    route.continue_()

                def on_response(response):
                    nonlocal timed_out
                    try:
                        headers = {k.lower(): v for k, v in response.headers.items()}
                        responses[response.url] = {
                            'status': response.status,
                            'technologies': [item['name'] for item in analyzer.detect_stack(headers)],
                            'server': headers.get('server', '')[:120],
                        }
                    except Exception as exc:
                        timed_out |= type(exc).__name__ == 'TimeoutError'

                context.route('**/*', route_request)
                page.on('response', on_response)
                for target in [url, *pages[:2]]:
                    if len(found) >= limit or (cancelled is not None and cancelled.is_set()):
                        break
                    try:
                        page.goto(target, wait_until='domcontentloaded', timeout=int(timeout * 1000))
                        page.wait_for_timeout(350)
                        for form in page.locator('form').evaluate_all("""forms => forms.slice(0,10).map(form => ({
                            method: form.method.toUpperCase(), url: form.action, enctype: form.enctype,
                            source_url: form.ownerDocument.URL,
                            fields: Array.from(form.elements).filter(el => el.name && !el.disabled &&
                                !['file','reset','button','submit'].includes(el.type) &&
                                (!['checkbox','radio'].includes(el.type) || el.checked)).slice(0,40)
                                .map(el => ({name:el.name, type:el.type || 'text',
                                    required:!!el.required, value:el.type === 'hidden' ? el.value : ''}))
                        }))"""):
                            if (form.get('method') == 'POST' and
                                    form.get('enctype') == 'application/x-www-form-urlencoded' and
                                    _origin(form.get('url', '')) == root and
                                    permit('POST', form['url'])):
                                forms.append({'method': 'POST', 'url': form['url'],
                                              'params': {}, 'headers': {'content-type': form['enctype']},
                                              'body': urlencode([(f['name'],f['value']) for f in form['fields']]),
                                              'field_schema': [{'name':f['name'][:100], 'type':f['type'][:30],
                                                                'required':f['required']} for f in form['fields']],
                                              'source_url': form['source_url']})
                    except Exception as exc:
                        timed_out = timed_out or type(exc).__name__ == 'TimeoutError'
            finally:
                browser.close()
    except Exception as exc:
        code = 'browser_timeout' if type(exc).__name__ == 'TimeoutError' else 'browser_launch_failed'
        return {'requests': found, 'error': code}
    for item in found:
        item.update(responses.get(item['url']) or {})
    return {'requests': found, 'forms': forms[:10],
            **({'error': 'browser_timeout'} if timed_out else {})}


async def capture(url, pages, limit, timeout, permit, reserve=None):
    cancelled = threading.Event()
    task = asyncio.create_task(asyncio.to_thread(
        _capture_sync, url, pages, limit, timeout, permit, reserve, cancelled))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        cancelled.set()
        await task
        raise
