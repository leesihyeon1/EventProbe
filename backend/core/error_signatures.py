# -*- coding: utf-8 -*-
"""DBMS/SQL 오류 시그니처 단일 소스.

응답 본문의 DB 오류 노출을 인식하는 정규식 코퍼스를 한 곳에서 로드한다.
예전엔 analyzer(_load_error_patterns) 와 confirm(_SQL_ERROR_RE) 이 각자 별도 목록을
들고 있어 드리프트했다 — 이제 둘 다 이 모듈을 통해 backend/data/dbms_error_signatures.json
을 단일 소스로 사용한다. (저수준 모듈: json/re/os 만 의존해 순환 임포트가 없다.)
"""
from __future__ import annotations

import json
import os
import re
from typing import List, Pattern, Tuple

_JSON = os.path.join(os.path.dirname(__file__), "..", "data", "dbms_error_signatures.json")

# JSON 로드 실패 시 최소 폴백(전체 탐지 실패 방지).
_FALLBACK: List[Tuple[str, str]] = [
    (r"SQL syntax.*?MySQL", "MySQL 에러 노출"),
    (r"You have an error in your SQL syntax", "MySQL/MariaDB 문법 에러"),
    (r"ORA-\d{5}", "Oracle DB 에러 코드"),
    (r"PostgreSQL.*?ERROR", "PostgreSQL 에러"),
    (r"Microsoft SQL Server", "MSSQL 에러"),
    (r"SQLSTATE\[", "SQL(PDO/SQLSTATE) 에러"),
    (r"Traceback \(most recent", "Python 트레이스백"),
    (r"stack trace", "스택 트레이스 노출"),
]


def load_error_patterns() -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """(global_list, sqli_only_list) 반환. 각 원소는 (정규식문자열, 라벨).
    global = 모든 응답에 적용(오탐 낮은 특이 패턴), sqli = SQLi 문맥 전용(scope=='sqli').
    손상된 정규식은 스킵해 전체 실패를 막는다."""
    try:
        with open(_JSON, encoding="utf-8") as f:
            sigs = json.load(f).get("error_signatures", [])
        g: List[Tuple[str, str]] = []
        s_only: List[Tuple[str, str]] = []
        for s in sigs:
            rx, lbl = s.get("regex"), s.get("label", "")
            if not rx:
                continue
            try:
                re.compile(rx)
            except re.error:
                continue
            (s_only if s.get("scope") == "sqli" else g).append((rx, lbl))
        return (g or list(_FALLBACK)), s_only
    except Exception:
        return list(_FALLBACK), []


def sql_error_regex() -> Pattern:
    """확증용으로 컴파일된 단일 SQL/DBMS 오류 정규식(전역+sqli scope 를 모두 합침).
    각 패턴을 (?:...) 로 감싸 인접 대안이 서로 삼키지 않게 하고, 빈 대안(||)을 배제한다
    (빈 대안이 하나라도 있으면 모든 문자열에 매칭돼 대형 오탐)."""
    g, s = load_error_patterns()
    pats = [rx for rx, _ in (g + s) if rx]
    if not pats:
        return re.compile(r"(?!x)x")          # 어떤 것에도 매칭 안 됨(안전한 no-op)
    return re.compile("|".join(f"(?:{p})" for p in pats), re.I)
