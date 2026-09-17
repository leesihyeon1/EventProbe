# -*- coding: utf-8 -*-
"""SQL/DBMS 오류 코퍼스 단일 소스(core.error_signatures) 회귀 테스트.

analyzer 와 confirm 이 각자 별도 목록을 들지 않고 이 모듈을 단일 소스로 공유하는지,
scope(global/sqli) 분리가 유지되는지 검증한다.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import error_signatures as es
from core import analyzer as A
from core import confirm as C


def test_analyzer_corpus_from_single_source():
    """analyzer 의 ERROR_LEAK_PATTERNS/SQLI_ERROR_PATTERNS 는 error_signatures 로더 결과와 동일."""
    g, s = es.load_error_patterns()
    assert A.ERROR_LEAK_PATTERNS == g
    assert A.SQLI_ERROR_PATTERNS == g + s


def test_confirm_sql_error_regex_covers_all_dbms():
    """confirm._SQL_ERROR_RE 가 공유 코퍼스 기반 — 주요 DBMS 오류를 모두 인식."""
    samples = [
        "You have an error in your SQL syntax near 'x'",
        "ERROR: syntax error at or near \"x\"",
        "function extractvalue(integer, text) does not exist",  # 예전 confirm 전용 → 이제 코퍼스에
        "'EXTRACTVALUE' is not a recognized built-in function name.",
        "Unclosed quotation mark after the character string",
        "ORA-00933: SQL command not properly ended",
        "unrecognized token: near syntax error",
    ]
    for s in samples:
        assert C._SQL_ERROR_RE.search(s), f"미인식: {s}"
    assert not C._SQL_ERROR_RE.search("just a normal home page with content")


def test_scope_separation_keeps_global_low_fp():
    """공격적 패턴(SqlException 등)은 scope=sqli 라 전역(verdict=bypass) 경로엔 안 들어간다 —
    일반 응답에 그런 문자열이 있어도 verdict 가 bypass 로 격상되면 안 됨."""
    g, s = es.load_error_patterns()
    global_regexes = {rx for rx, _ in g}
    assert "SqlException" not in global_regexes          # sqli-scope 여야
    assert r"function .{0,40} does not exist" not in global_regexes
    r = A.analyze_response(200, {}, "System.Data.SqlException occurred in log viewer", 30,
                           payload="", category="")
    assert r["verdict"] != "bypass"


def test_sql_error_regex_no_empty_alternative():
    """빈 대안(||)이 섞이면 모든 문자열에 매칭되는 대형 오탐 — 방지되는지."""
    assert not es.sql_error_regex().search("")            # 빈 문자열엔 매칭 안 됨
