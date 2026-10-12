"""대조군과 공격 요청이 같은 조건에서 실행됐는지 검증한다."""

from urllib.parse import parse_qsl, urlsplit


_AUTH_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}


def _headers(value):
    return {str(k).lower(): str(v) for k, v in (value or {}).items()
            if str(k).lower() not in {"content-length", "connection", "transfer-encoding"}}


def validate(baseline, *, method, url, headers=None, body=None):
    """검증 결과와 사유를 반환한다. 이전 형식의 대조군은 검증되지 않은 것으로 표시한다."""
    if not baseline or not baseline.get("status_code"):
        return {"valid": False, "code": "missing", "reason": "대조군 응답이 없습니다."}
    source = baseline.get("request")
    if not isinstance(source, dict):
        return {"valid": False, "code": "no_request", "reason": "대조군의 원본 요청 조건이 없어 비교할 수 없습니다."}
    if source.get("payload"):
        return {"valid": False, "code": "tainted_control", "reason": "대조군 요청에도 공격 페이로드가 포함돼 있습니다."}
    if not source.get("method") or not source.get("url") or not method or not url:
        return {"valid": False, "code": "incomplete_request", "reason": "대조군 또는 공격 요청의 메소드·URL이 없습니다."}
    try:
        old, new = urlsplit(str(source.get("url") or "")), urlsplit(str(url or ""))
        same_target = old.scheme.lower() in {"http", "https"} and (
            old.scheme.lower(), old.netloc.lower(), old.path or "/") == (
            new.scheme.lower(), new.netloc.lower(), new.path or "/")
    except ValueError:
        same_target = False
    if not same_target or str(source.get("method") or "").upper() != str(method or "").upper():
        return {"valid": False, "code": "target_changed", "reason": "대조군과 공격 요청의 메소드·대상 경로가 다릅니다."}

    old_headers, new_headers = _headers(source.get("headers")), _headers(headers)
    if any(old_headers.get(k) != new_headers.get(k) for k in _AUTH_HEADERS):
        return {"valid": False, "code": "auth_changed", "reason": "인증/세션 헤더가 달라 같은 권한의 응답인지 알 수 없습니다."}

    # 동일 조건에서는 공격 변수만 한 곳에서 달라질 수 있다. 헤더 공격도 한 헤더만 허용.
    changes = []
    old_q, new_q = {}, {}
    for key, value in parse_qsl(old.query, keep_blank_values=True):
        old_q.setdefault(key, []).append(value)
    for key, value in parse_qsl(new.query, keep_blank_values=True):
        new_q.setdefault(key, []).append(value)
    changes.extend("query:" + k for k in old_q.keys() | new_q.keys() if old_q.get(k) != new_q.get(k))
    if str(source.get("body") or "") != str(body or ""):
        changes.append("body")
    changes.extend("header:" + k for k in old_headers.keys() | new_headers.keys()
                   if old_headers.get(k) != new_headers.get(k))
    if len(changes) > 1:
        return {"valid": False, "code": "multiple_changes", "reason": "대조군과 공격 요청에서 둘 이상의 조건이 달라 차이의 원인을 특정할 수 없습니다.",
                "changes": sorted(changes)[:8]}
    return {"valid": True, "code": "comparable", "reason": "대상·인증 조건이 같고 변경 변수는 최대 하나입니다.",
            "changes": changes}
