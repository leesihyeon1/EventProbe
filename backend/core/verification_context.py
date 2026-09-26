"""검증 이력 요약을 AI 설명용 문맥으로 제한한다. 이력은 확정 근거가 아니다."""

import re
from urllib.parse import urlsplit


_OUTCOMES = {"success", "safe", "blocked", "suspicious", "inconclusive"}
_KINDS = {"request", "confirmation"}


def compact(events, *, session_id, current_url):
    """동일 세션/출처만 허용하고 민감한 원문 필드는 버린다."""
    if not session_id or not current_url:
        return []
    try:
        target = urlsplit(current_url)
        if target.scheme.lower() not in {"http", "https"} or not target.netloc:
            return []
        origin = (target.scheme.lower(), target.netloc.lower())
    except ValueError:
        return []
    out = []
    for item in (events or [])[:20]:
        if not isinstance(item, dict) or item.get("session_id") != session_id:
            continue
        try:
            url = urlsplit(str(item.get("url") or ""))
            if (url.scheme.lower(), url.netloc.lower()) != origin:
                continue
        except ValueError:
            continue
        kind = str(item.get("kind") or "")
        outcome = str(item.get("outcome") or "")
        category = str(item.get("category") or "")
        if kind not in _KINDS or outcome not in _OUTCOMES:
            continue
        if not re.fullmatch(r"[a-zA-Z0-9_-]{0,40}", category):
            category = ""
        try:
            status = int(item.get("status") or 0)
        except (TypeError, ValueError):
            status = 0
        path = re.sub(r"/(?:(?:\d+)|(?:[A-Za-z0-9_-]{16,}))(?=/|$)", "/{id}", url.path or "/")
        method = str(item.get("method") or "").upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = ""
        out.append({"kind": kind, "method": method,
                    "path": path[:160], "status": status if 100 <= status <= 599 else 0,
                    "outcome": outcome, "category": category,
                    "confirmed_reported": item.get("confirmed") is True,
                    "baseline_valid_reported": item.get("baseline_valid") is True})
        if len(out) == 5:
            break
    return out
