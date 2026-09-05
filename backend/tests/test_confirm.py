"""오라클 확증 스캔(confirm.py) 단위 테스트.

confirm 모듈은 순수 지식 계층이다 — HTTP 전송 없이, 프로브 응답 dict 목록을 받아
'대조군 vs 실험군' 차이로 취약을 확증한다. 여기서는 응답을 직접 합성해 판정 로직만
검증한다(네트워크 없음).

decide() 에 넘기는 결과 항목 형식:
  {"role", "status", "time_ms", "body", "headers", "value"}
"""
from core import confirm


def _r(role, status=200, time_ms=100.0, body="", headers=None, value=""):
    return {"role": role, "status": status, "time_ms": time_ms,
            "body": body, "headers": headers or {}, "value": value}


# ─────────────────────────────────────────────────────────────────────────────
# 지원 여부 / 프로브 계획
# ─────────────────────────────────────────────────────────────────────────────
def test_is_supported():
    assert confirm.is_supported("sqli")
    assert confirm.is_supported("SQLI")        # 대소문자 무관
    assert not confirm.is_supported("xxe")     # 미지원
    assert not confirm.is_supported("")


def test_probe_plan_has_baseline_first():
    plan = confirm.probe_plan("sqli", "1")
    assert plan[0]["role"] == "baseline"
    roles = [p["role"] for p in plan]
    assert "time5" in roles and "bool_false" in roles


def test_probe_plan_empty_for_unsupported():
    assert confirm.probe_plan("xxe", "x") == []


# ─────────────────────────────────────────────────────────────────────────────
# SQLi — 시간 기반
# ─────────────────────────────────────────────────────────────────────────────
def test_sqli_time_based_confirmed():
    """SLEEP(5)가 SLEEP(0)보다 임계값 이상 느리고, 대조가 충분히 빠르면 확증."""
    results = [
        _r("baseline"),
        _r("time0", time_ms=200),
        _r("time5", time_ms=5200),   # Δ5000 >= 3500, 대조 200 < 2500
    ]
    d = confirm.decide("sqli", results)
    assert d["confirmed"]
    assert any("시간 기반" in t["name"] for t in d["techniques"])


def test_sqli_time_based_rejected_when_control_slow():
    """대조(SLEEP 0)가 이미 느리면 회선 지연으로 보고 기각한다."""
    results = [
        _r("baseline"),
        _r("time0", time_ms=3000),   # 대조 > 2500 → 기각
        _r("time5", time_ms=7000),
    ]
    d = confirm.decide("sqli", results)
    assert not any("시간 기반" in t["name"] for t in d["techniques"])


def test_sqli_time_based_rejected_when_delta_small():
    results = [
        _r("baseline"),
        _r("time0", time_ms=200),
        _r("time5", time_ms=1000),   # Δ800 < 3500
    ]
    d = confirm.decide("sqli", results)
    assert not any("시간 기반" in t["name"] for t in d["techniques"])


# ─────────────────────────────────────────────────────────────────────────────
# SQLi — 불린 기반
# ─────────────────────────────────────────────────────────────────────────────
def test_sqli_boolean_confirmed_by_length_diff():
    results = [
        _r("baseline"),
        _r("bool_true", body="X" * 1000),
        _r("bool_false", body="X" * 500),   # 길이차 500 >= 40
    ]
    d = confirm.decide("sqli", results)
    assert any("불린 기반" in t["name"] for t in d["techniques"])


def test_sqli_boolean_confirmed_by_status_diff():
    results = [
        _r("baseline"),
        _r("bool_true", status=200, body="same"),
        _r("bool_false", status=500, body="same"),
    ]
    d = confirm.decide("sqli", results)
    assert any("불린 기반" in t["name"] for t in d["techniques"])


def test_sqli_error_based_confirmed_by_marker():
    """EXTRACTVALUE 로 넣은 hex 마커가 DB 에러로 평문 반환되면 error-based 확증."""
    body = "XPATH syntax error: '~" + confirm._SQL_ERR_MARKER + "~'"
    results = [_r("baseline", body="normal"), _r("err", body=body)]
    d = confirm.decide("sqli", results)
    assert d["confirmed"]
    assert any("에러 기반" in t["name"] for t in d["techniques"])


def test_sqli_error_based_confirmed_by_db_error():
    """대조엔 없던 SQL 에러가 주입 시 발생하면 error-based 확증."""
    results = [_r("baseline", body="normal page"),
               _r("errn", body="You have an error in your SQL syntax near line 1")]
    d = confirm.decide("sqli", results)
    assert d["confirmed"]


def test_sqli_error_based_cross_dbms():
    """대상 DB 를 몰라도, 주입으로 깨진 각 DBMS 의 에러 문구를 폭넓게 인식해 확증."""
    errors = {
        "mysql": "You have an error in your SQL syntax near 'x'",
        "postgres": "ERROR: syntax error at or near \"x\"",
        "postgres_func": "ERROR: function extractvalue(integer, text) does not exist",
        "mssql": "'EXTRACTVALUE' is not a recognized built-in function name.",
        "mssql_quote": "Unclosed quotation mark after the character string",
        "oracle": "ORA-00933: SQL command not properly ended",
        "sqlite": "unrecognized token: near syntax error",
    }
    for db, err in errors.items():
        d = confirm.decide("sqli", [_r("baseline", body="normal home page"), _r("err", body=err)])
        assert d["confirmed"], f"{db} 에러가 확증되지 않음"


def test_sqli_error_based_not_confirmed_when_baseline_already_errors():
    """항상 SQL 에러를 뱉는 페이지는 error-based 로 오확증하지 않는다."""
    err = "You have an error in your SQL syntax"
    results = [_r("baseline", body=err), _r("err", body=err)]
    # 시간/불린 신호도 없음
    d = confirm.decide("sqli", results)
    assert not any("에러 기반" in t["name"] for t in d["techniques"])


def test_sqli_clean_target_not_confirmed():
    """참/거짓 응답이 동일하고 지연도 없으면 확증되지 않아야 한다(오탐 방지)."""
    results = [
        _r("baseline", body="same body"),
        _r("time0", time_ms=150),
        _r("time5", time_ms=170),
        _r("time0n", time_ms=150),
        _r("time5n", time_ms=170),
        _r("bool_true", status=200, body="same body"),
        _r("bool_false", status=200, body="same body"),
    ]
    d = confirm.decide("sqli", results)
    assert not d["confirmed"]
    assert d["techniques"] == []


# ─────────────────────────────────────────────────────────────────────────────
# 그 외 카테고리
# ─────────────────────────────────────────────────────────────────────────────
def test_cmdi_id_command_confirmed():
    results = [_r("baseline"), _r("idcmd", body="uid=0(root) gid=0(root) groups=0(root)")]
    d = confirm.decide("cmdi", results)
    assert d["confirmed"]
    assert any("id 실행" in t["name"] for t in d["techniques"])


def test_ssti_evaluation_confirmed():
    results = [_r("baseline"), _r("e_curly", body="output 49 done")]
    d = confirm.decide("ssti", results)
    assert d["confirmed"]


def test_ssti_not_confirmed_when_expression_echoed():
    """응답에 '7*7' 원문이 그대로 있으면(미평가) 확증하지 않는다."""
    results = [_r("baseline"), _r("e_curly", body="you typed 7*7 which is 49")]
    d = confirm.decide("ssti", results)
    assert not d["confirmed"]


def test_xss_marker_reflection_confirmed():
    body = f"<div>{confirm._XSS_BREAK}</div>"   # 마커가 인코딩 없이 반사
    results = [_r("baseline"), _r("probe", body=body)]
    d = confirm.decide("xss", results)
    assert d["confirmed"]


def test_xss_not_confirmed_when_encoded():
    body = "<div>zqx7k&quot;&gt;&lt;svg&gt;</div>"   # 인코딩되어 반사
    results = [_r("baseline"), _r("probe", body=body)]
    d = confirm.decide("xss", results)
    assert not d["confirmed"]


def test_lfi_passwd_confirmed():
    results = [_r("baseline"), _r("trav1", body="root:x:0:0:root:/root:/bin/bash")]
    d = confirm.decide("lfi", results)
    assert d["confirmed"]


def test_redirect_confirmed_by_location_header():
    results = [_r("baseline"), _r("probe", status=302, headers={"Location": "//evil.example.com/"})]
    d = confirm.decide("redirect", results)
    assert d["confirmed"]


def test_redirect_not_confirmed_for_internal_location():
    results = [_r("baseline"), _r("probe", status=302, headers={"Location": "/dashboard"})]
    d = confirm.decide("redirect", results)
    assert not d["confirmed"]


# ─────────────────────────────────────────────────────────────────────────────
# NoSQL — 불린 기반($where/문자열 보간)
# ─────────────────────────────────────────────────────────────────────────────
def test_nosql_supported_and_probe_plan():
    assert confirm.is_supported("nosql")
    plan = confirm.probe_plan("nosql", "admin")
    roles = [p["role"] for p in plan]
    assert roles[0] == "baseline"
    assert "n_true" in roles and "n_false" in roles


def test_nosql_boolean_confirmed_by_status_diff():
    results = [
        _r("baseline"),
        _r("n_true", status=200, body="X" * 500),
        _r("n_false", status=401, body="denied"),
        _r("n_true2", status=200, body="y"),
        _r("n_false2", status=200, body="y"),
    ]
    d = confirm.decide("nosql", results)
    assert d["confirmed"]
    assert any("NoSQL" in t["name"] for t in d["techniques"])


def test_nosql_clean_not_confirmed():
    same = [_r("baseline"), _r("n_true", body="same"), _r("n_false", body="same"),
            _r("n_true2", body="same"), _r("n_false2", body="same")]
    assert not confirm.decide("nosql", same)["confirmed"]


# ─────────────────────────────────────────────────────────────────────────────
# IDOR — 이웃 객체 ID 차등 (category 'business' 별칭 포함)
# ─────────────────────────────────────────────────────────────────────────────
def test_idor_supported_via_business_alias():
    assert confirm.is_supported("business")
    assert confirm.is_supported("idor")


def test_idor_probe_plan_numeric_only():
    roles = [p["role"] for p in confirm.probe_plan("business", "123")]
    assert roles == ["baseline", "id_down", "id_up", "nonexistent"]
    assert confirm.probe_plan("idor", "abc-uuid") == []   # 숫자형만 열거 가능


def test_idor_confirmed_when_neighbor_accessible():
    results = [
        _r("baseline", status=200, body="A" * 400),
        _r("id_down", status=200, body="B" * 380),      # 다른 실제 객체
        _r("id_up", status=404, body="nf"),
        _r("nonexistent", status=404, body="not found"),  # 대조군 실패
    ]
    d = confirm.decide("business", results)
    assert d["confirmed"]
    assert any("IDOR" in t["name"] for t in d["techniques"])


def test_idor_not_confirmed_when_all_same_spa():
    """모든 ID 가 같은 껍데기(SPA)면 확증하지 않는다(오탐 방지)."""
    big = "A" * 400
    results = [_r("baseline", body=big), _r("id_down", body=big),
               _r("id_up", body=big), _r("nonexistent", body=big)]
    assert not confirm.decide("idor", results)["confirmed"]


def test_idor_not_confirmed_when_nonexistent_also_ok():
    """없는 ID 도 200·유사 크기면 대조가 안 돼 확증하지 않는다."""
    results = [
        _r("baseline", status=200, body="A" * 400),
        _r("id_up", status=200, body="B" * 390),
        _r("nonexistent", status=200, body="C" * 395),   # 대조 실패 안 함
    ]
    assert not confirm.decide("business", results)["confirmed"]


# ─────────────────────────────────────────────────────────────────────────────
# LDAP — 불린 기반(와일드카드 / 필터 브레이크아웃)
# ─────────────────────────────────────────────────────────────────────────────
def test_ldap_supported_and_probe_plan():
    assert confirm.is_supported("ldap")
    roles = [p["role"] for p in confirm.probe_plan("ldap", "john")]
    assert roles[0] == "baseline"
    assert "l_wild" in roles and "l_true" in roles


def test_ldap_boolean_confirmed_by_wildcard():
    results = [
        _r("baseline"),
        _r("l_wild", status=200, body="USER " * 300),   # * → 전체 매칭
        _r("l_none", status=200, body="no results"),
        _r("l_true", status=200, body="x"),
        _r("l_false", status=200, body="x"),
    ]
    d = confirm.decide("ldap", results)
    assert d["confirmed"]
    assert any("LDAP" in t["name"] for t in d["techniques"])


def test_ldap_clean_not_confirmed():
    same = [_r("baseline"), _r("l_wild", body="s"), _r("l_none", body="s"),
            _r("l_true", body="s"), _r("l_false", body="s")]
    assert not confirm.decide("ldap", same)["confirmed"]


# ─────────────────────────────────────────────────────────────────────────────
# 인증 우회 (auth)
# ─────────────────────────────────────────────────────────────────────────────
def test_auth_supported_and_probe_plan():
    assert confirm.is_supported("auth")
    roles = [p["role"] for p in confirm.probe_plan("auth", "")]
    assert roles[0] == "baseline"
    assert "byp_sql" in roles


def test_auth_confirmed_by_session_and_redirect():
    ctrl = _r("baseline", status=401, body="Invalid credentials")
    byp = _r("byp_sql", status=302, body="",
             headers={"Set-Cookie": "session=abc; HttpOnly"}, value="' OR '1'='1'-- -")
    d = confirm.decide("auth", [ctrl, byp])
    assert d["confirmed"]
    assert any("인증 우회" in t["name"] for t in d["techniques"])


def test_auth_confirmed_by_failure_message_gone():
    ctrl = _r("baseline", status=200, body="로그인 실패: 올바르지 않은 정보")
    byp = _r("byp_or", status=200, body="환영합니다 대시보드", value="' OR 1=1#")
    assert confirm.decide("auth", [ctrl, byp])["confirmed"]


def test_auth_not_confirmed_when_bypass_also_fails():
    ctrl = _r("baseline", status=401, body="Invalid")
    byp = _r("byp_sql", status=401, body="Invalid")
    assert not confirm.decide("auth", [ctrl, byp])["confirmed"]


def test_auth_not_confirmed_when_session_is_shared():
    """앱이 대조군에도 세션 쿠키를 주면(게스트 세션) 우회로 보지 않는다."""
    ctrl = _r("baseline", status=200, body="login form", headers={"Set-Cookie": "session=guest"})
    byp = _r("byp_sql", status=200, body="login form", headers={"Set-Cookie": "session=guest2"})
    assert not confirm.decide("auth", [ctrl, byp])["confirmed"]


def test_decide_ignores_failed_probes():
    """전송 실패(status=0)한 프로브는 오라클이 무시해야 한다."""
    results = [_r("baseline"), _r("time0", status=0, time_ms=0), _r("time5", status=0, time_ms=0)]
    d = confirm.decide("sqli", results)
    assert not d["confirmed"]
