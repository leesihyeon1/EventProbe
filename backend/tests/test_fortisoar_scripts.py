"""FortiSOAR 연동 스크립트(integrations/fortisoar) 단위 테스트.

네트워크 없이: gen_raw_packet 는 순수 조립, verify_packet 는 _post 를 monkeypatch 로 대체.
"""
import os
import sys

import pytest

_FS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                   "integrations", "fortisoar")
sys.path.insert(0, _FS)

import gen_raw_packet as gen      # noqa: E402
import verify_packet as vp        # noqa: E402


# ── gen_raw_packet ────────────────────────────────────────────────────────────
def test_build_from_url_splits_host_and_path():
    raw = gen.build_raw_packet(method="get", url="https://target.com/admin?x=1")
    lines = raw.split("\r\n")
    assert lines[0] == "GET /admin?x=1 HTTP/1.1"
    assert "Host: target.com" in lines
    assert raw.endswith("\r\n\r\n")          # 본문 없음 → 빈 줄로 끝


def test_build_headers_dict_and_list_and_string():
    for h in ({"A": "1", "B": "2"}, ["A: 1", "B: 2"], "A: 1\nB: 2"):
        raw = gen.build_raw_packet(url="http://h/p", headers=h)
        assert "A: 1" in raw and "B: 2" in raw


def test_build_post_adds_content_length():
    raw = gen.build_raw_packet(method="POST", url="http://h/login", body='{"a":1}')
    assert "Content-Length: 7" in raw
    assert raw.endswith('\r\n\r\n{"a":1}')


def test_build_host_not_duplicated_when_in_headers():
    raw = gen.build_raw_packet(url="http://h/p", headers={"Host": "override.com"})
    assert raw.count("Host:") == 1
    assert "Host: override.com" in raw


def test_gen_main_returns_raw_request():
    out = gen.main({"url": "https://t/x", "method": "GET"})
    assert out["raw_request"].startswith("GET /x HTTP/1.1")


# ── verify_packet.summarize ───────────────────────────────────────────────────
def _tool_response(findings, outcome="success", risk="high"):
    return {"status_code": 200, "parsed_request": {"method": "GET", "url": "http://t/a",
            "http_version": "HTTP/1.1"},
            "analysis": {"attack_outcome": outcome, "risk_level": risk, "verdict": "bypass",
                         "findings": findings}}


def test_summarize_prefers_success_over_suspicion():
    r = vp.summarize(_tool_response([
        {"name": "차분 판정", "verdict": "의심", "confidence": 60, "why": "..."},
        {"name": "미들웨어 우회 성공", "verdict": "성공", "confidence": 88, "why": "..."},
    ]))
    assert r["ok"] is True
    assert r["outcome"] == "success"
    assert r["findings"][0]["verdict"] == "성공"          # 성공이 먼저
    assert "미들웨어 우회 성공" in r["summary"]
    assert "위험도 high" in r["summary"]


def test_summarize_filters_non_positive_findings():
    r = vp.summarize(_tool_response([
        {"name": "안전 신호", "verdict": "안전", "confidence": 75, "why": "..."},
    ], outcome="safe"))
    assert r["findings"] == []                            # 성공/의심만 남김


def test_summarize_surfaces_tool_error():
    r = vp.summarize({"error": "raw 파싱 실패"})
    assert r["ok"] is False and "파싱" in r["error"]


# ── verify_packet.main (전송은 monkeypatch) ──────────────────────────────────
def test_main_posts_and_summarizes(monkeypatch):
    captured = {}

    def _fake_post(url, payload, verify_tls, timeout):
        captured["url"] = url
        captured["payload"] = payload
        return 200, _tool_response([{"name": "우회 성공", "verdict": "성공",
                                     "confidence": 88, "why": "..."}])

    monkeypatch.setattr(vp, "_post", _fake_post)
    r = vp.main({"tester_url": "http://tool:8000/", "raw_request": "GET /a HTTP/1.1\r\nHost: t\r\n\r\n",
                 "scheme": "http", "category": "cve", "baseline": {"status_code": 302}})
    assert captured["url"] == "http://tool:8000/api/request/raw"
    assert captured["payload"]["raw"].startswith("GET /a")
    assert captured["payload"]["baseline"] == {"status_code": 302}
    assert r["ok"] and r["outcome"] == "success"


def test_main_requires_raw_and_tester():
    assert vp.main({"tester_url": "http://t"})["ok"] is False
    assert vp.main({"raw_request": "GET / HTTP/1.1\r\n\r\n"})["ok"] is False


def test_main_reports_non_200(monkeypatch):
    monkeypatch.setattr(vp, "_post", lambda *a, **k: (500, {"detail": "boom"}))
    r = vp.main({"tester_url": "http://t", "raw_request": "GET / HTTP/1.1\r\nHost: t\r\n\r\n"})
    assert r["ok"] is False and "500" in r["error"]
