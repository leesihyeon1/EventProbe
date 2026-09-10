"""리다이렉트 판정 — '우리 요청에 대한 첫 응답' 기준.

회귀 방지(핵심):
    단일 전송 경로가 follow_redirects=True 였던 탓에 analyzer 는 언제나 '최종 응답'만 봤다.
    최종 응답엔 3xx/Location 이 없으므로 오픈 리다이렉트는 **영영 탐지되지 않았고**,
    category=redirect 테스트가 취약한 대상에서도 "취약 신호 미검출 — 영향 없음"(안전)으로
    떴다. 즉 위음성을 '안전'이라고 보고했다.

이제 추적을 끄는 것이 기본이고, 켜서 따라간 경우엔 호출부가 redirect_chain 을 넘겨
첫 홉으로 판정한다. 2번째 이후 홉(사이트→CDN 등)은 오픈 리다이렉트 근거가 아니다.

네트워크 요청 없음 — 전부 순수 함수 단위 테스트.
"""
import pytest

from core.analyzer import analyze_response

_EVIL = "https://evil.example.com/steal"
_TARGET = "https://t.example.com/go?next=//evil.example.com"


def _names(r):
    return [f["name"] for f in r["findings"]]


def _hop(status, location, url="https://t.example.com/go"):
    return {"status_code": status, "location": location, "url": url}


# ─────────────────────────────────────────────────────────────────────────────
# 추적 OFF(기본) — 3xx 응답을 그대로 본다
# ─────────────────────────────────────────────────────────────────────────────
def test_direct_3xx_external_is_success():
    r = analyze_response(302, {"location": _EVIL}, "", 50,
                         payload="//evil.example.com", category="redirect", url=_TARGET)
    assert any("외부 리다이렉트" in n for n in _names(r))
    assert r["attack_outcome"] == "success"


def test_direct_3xx_same_host_is_not_open_redirect():
    r = analyze_response(302, {"location": "https://t.example.com/login"}, "", 50,
                         payload="//evil.example.com", category="redirect", url=_TARGET)
    assert not any("외부 리다이렉트" in n for n in _names(r))


# ─────────────────────────────────────────────────────────────────────────────
# 추적 ON — 최종 응답은 200 이지만 첫 홉으로 판정한다
# ─────────────────────────────────────────────────────────────────────────────
def test_followed_chain_first_hop_external_is_success():
    """핵심 회귀: 최종 200 + 본문만 보면 놓치던 오픈 리다이렉트를 첫 홉으로 잡는다."""
    r = analyze_response(200, {"content-type": "text/html"}, "<html>evil landing</html>", 80,
                         payload="//evil.example.com", category="redirect", url=_TARGET,
                         redirect_chain=[_hop(302, _EVIL)])
    hit = [f for f in r["findings"] if "외부 리다이렉트" in f["name"]]
    assert hit, "따라간 경우에도 첫 홉의 Location 으로 판정해야 한다"
    assert hit[0]["verdict"] == "성공"
    assert "302" in hit[0]["evidence"] and "evil.example.com" in hit[0]["evidence"]
    assert "체인의 첫 홉" in hit[0]["why"]          # 무엇을 보고 판정했는지 서술
    assert r["attack_outcome"] == "success"


def test_followed_chain_dangerous_scheme_is_success():
    r = analyze_response(200, {}, "ok", 80,
                         payload="javascript:alert(1)", category="redirect",
                         url="https://t.example.com/go?next=javascript:alert(1)",
                         redirect_chain=[_hop(302, "javascript:alert(1)")])
    assert any("위험 스킴 리다이렉트" in n for n in _names(r))


def test_followed_chain_same_host_first_hop_is_safe():
    """로그인 리다이렉트를 따라간 경우 — 오픈 리다이렉트가 아니다."""
    r = analyze_response(200, {}, "<html>login</html>", 80,
                         payload="//evil.example.com", category="redirect", url=_TARGET,
                         redirect_chain=[_hop(302, "https://t.example.com/login")])
    assert not any("외부 리다이렉트" in n for n in _names(r))
    assert any("오픈 리다이렉트 취약 신호 미검출" in n for n in _names(r))


def test_only_first_hop_counts_not_later_hops():
    """사이트→CDN 같은 2번째 이후 홉은 대상 내부 사정 → 오픈 리다이렉트 근거가 아니다."""
    r = analyze_response(200, {}, "ok", 80,
                         payload="//evil.example.com", category="redirect", url=_TARGET,
                         redirect_chain=[_hop(302, "https://t.example.com/login"),
                                         _hop(302, "https://cdn.other.example/asset",
                                              url="https://t.example.com/login")])
    assert not any("외부 리다이렉트" in n for n in _names(r))


def test_chain_takes_precedence_over_final_headers():
    """최종 응답에 (드물게) Location 이 남아 있어도 첫 홉이 판정 기준이다."""
    r = analyze_response(200, {"location": _EVIL}, "ok", 80,
                         payload="//evil.example.com", category="redirect", url=_TARGET,
                         redirect_chain=[_hop(302, "https://t.example.com/login")])
    assert not any("외부 리다이렉트" in n for n in _names(r))


def test_malformed_chain_entry_does_not_crash():
    for bad in ([{}], [{"status_code": "x", "location": None}], [None]):
        r = analyze_response(200, {}, "ok", 80,
                             payload="//evil.example.com", category="redirect", url=_TARGET,
                             redirect_chain=bad)
        assert not any("외부 리다이렉트" in n for n in _names(r))


# ─────────────────────────────────────────────────────────────────────────────
# 리다이렉트 힌트가 '대상 URL 자체'로 발동하지 않아야 한다(오탐 방지)
# ─────────────────────────────────────────────────────────────────────────────
def test_target_host_alone_does_not_trigger_redirect_check():
    """_REDIRECT_HINT 의 //host.tld 패턴이 대상 URL 에 매칭돼 평범한 사이트→CDN 리다이렉트를
    오픈 리다이렉트로 오탐하던 문제. 요청에 리다이렉트 의도가 없으면 판정하지 않는다."""
    r = analyze_response(302, {"location": "https://cdn.other.example/x"}, "", 50,
                         payload="", category=None, url="https://t.example.com/page")
    assert not any("외부 리다이렉트" in n for n in _names(r))


def test_redirect_payload_in_query_still_triggers():
    """반대로 주입값에 //evil 이 들어오면 카테고리가 없어도 판정한다."""
    r = analyze_response(302, {"location": _EVIL}, "", 50,
                         payload=None, category=None,
                         url="https://t.example.com/go?next=//evil.example.com")
    assert any("외부 리다이렉트" in n for n in _names(r))


@pytest.mark.parametrize("hint_url", [
    "https://t.example.com/x?redirect=/a",
    "https://t.example.com/x?returnUrl=/a",
    "https://t.example.com/x?goto=/a",
])
def test_named_redirect_params_still_trigger(hint_url):
    r = analyze_response(302, {"location": _EVIL}, "", 50, payload=None, category=None, url=hint_url)
    assert any("외부 리다이렉트" in n for n in _names(r))


# ─────────────────────────────────────────────────────────────────────────────
# API 계층 — 기본값과 체인 추출
# ─────────────────────────────────────────────────────────────────────────────
def test_single_request_defaults_to_not_following_redirects():
    """보안 도구 기본값: 서버가 준 응답을 그대로 본다."""
    from routers.api import SingleRequest
    assert SingleRequest(method="GET", url="https://t/").follow_redirects is False


def test_redirect_chain_helper_extracts_hops():
    from routers.api import _redirect_chain

    class _H:
        def __init__(self, status, loc, url):
            self.status_code, self.headers, self.url = status, {"location": loc}, url

    class _Resp:
        history = [_H(302, "/b", "https://t/a"), _H(301, "/c", "https://t/b")]

    assert _redirect_chain(_Resp()) == [
        {"status_code": 302, "location": "/b", "url": "https://t/a"},
        {"status_code": 301, "location": "/c", "url": "https://t/b"},
    ]


def test_redirect_chain_helper_empty_when_not_followed():
    from routers.api import _redirect_chain

    class _Resp:
        history = []

    assert _redirect_chain(_Resp()) == []
    assert _redirect_chain(object()) == []
