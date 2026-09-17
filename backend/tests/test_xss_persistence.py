# -*- coding: utf-8 -*-
"""XSS 저장형/반사형 구분 표기(지속성 확인) 단위 테스트."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from routers.api import (_xss_success_findings, _relabel_xss_stored,
                         _payload_marker)


def test_xss_success_findings_picks_only_success_xss():
    analysis = {"findings": [
        {"name": "반사형 XSS(실행 컨텍스트)", "verdict": "성공"},
        {"name": "payload 미인코딩 반사", "verdict": "성공"},
        {"name": "payload 반사", "verdict": "미확정"},              # 성공 아님 → 제외
        {"name": "payload 인코딩 반사 (응답 본문 — 여기선 안전)", "verdict": "안전"},  # 제외
        {"name": "SQL 오류 노출", "verdict": "성공"},               # XSS 아님 → 제외
    ]}
    picked = [f["name"] for f in _xss_success_findings(analysis)]
    assert picked == ["반사형 XSS(실행 컨텍스트)", "payload 미인코딩 반사"]


def test_relabel_stored_promotes_name_and_why():
    f = {"name": "반사형 XSS(실행 컨텍스트)", "verdict": "성공", "why": "실행 가능"}
    _relabel_xss_stored(f, True)
    assert f["xss_persistence"] == "stored"
    assert "저장형 XSS(실행 컨텍스트)" == f["name"]
    assert "저장형(지속) XSS 확증" in f["why"]


def test_relabel_reflected_keeps_reflected():
    f = {"name": "반사형 XSS(실행 컨텍스트)", "verdict": "성공", "why": "실행 가능"}
    _relabel_xss_stored(f, False)
    assert f["xss_persistence"] == "reflected"
    assert "반사형 XSS" in f["name"] and "저장형" not in f["name"]
    assert "반사형(요청 시에만 반영)" in f["why"]


def test_relabel_stored_on_unescaped_name():
    f = {"name": "payload 미인코딩 반사", "verdict": "성공", "why": "x"}
    _relabel_xss_stored(f, True)
    assert f["name"].startswith("저장형 XSS")     # 반사형 문자열이 없어도 저장형 접두
    assert f["xss_persistence"] == "stored"


def test_payload_marker_requires_min_length():
    assert _payload_marker("<script>alert(1)</script>") == "<script>alert(1)</script>"
    assert _payload_marker("a<b") == ""            # 너무 짧으면 오탐 방지로 빈 값
