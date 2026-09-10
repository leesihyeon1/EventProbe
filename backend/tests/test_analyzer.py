"""analyze_response / detect_waf / attack_findings / generate_summary 단위 테스트.

이 도구의 핵심 가치는 '판정의 정확성'이다. 특히 다음 원칙을 회귀로부터 지킨다:

    차단되지 않음(방어장비 미탐) ≠ 대상이 취약함.

증거가 없는 단순 통과(200)를 '취약'으로 격상하지 않고, 실제 성공 증거
(파일 읽기·명령 출력·타이밍 일치·실행 컨텍스트 반사 등)가 있을 때만 격상한다.
"""
from core.analyzer import analyze_response, detect_waf, generate_summary, detect_stack


# ─────────────────────────────────────────────────────────────────────────────
# 오탐 방지: '차단 안 됨'을 '취약'으로 오해하지 않는다 (구 high/65 휴리스틱 회귀 방지)
# ─────────────────────────────────────────────────────────────────────────────
def test_sqli_unblocked_no_evidence_is_low():
    """SQLi 페이로드가 막히지 않았지만(200) 성공 증거가 전혀 없으면 low 여야 한다."""
    r = analyze_response(200, {"content-type": "text/html"},
                         "<html><body>일반 게시판 페이지</body></html>", 120,
                         payload="1' OR '1'='1", category="sqli")
    assert r["risk_level"] == "low"
    assert r["verdict"] == "passed"
    assert r["attack_outcome"] == "inconclusive"


def test_cmdi_unblocked_no_evidence_is_low():
    r = analyze_response(200, {}, "<html>ok</html>", 100,
                         payload=";whoami", category="cmdi")
    assert r["risk_level"] == "low"
    assert r["attack_outcome"] == "inconclusive"


def test_no_signal_attack_is_marked_unknown_not_safe():
    """신호가 전혀 없는 공격 시도는 '안전'이 아니라 '미확인(수동 확인 필요)'로 명시."""
    r = analyze_response(200, {}, "<html>normal page</html>", 60,
                         payload="{{7*7}}", category="ssti")
    assert r["attack_outcome"] == "inconclusive"
    assert any(f["verdict"] == "미확인" for f in r["findings"])


def test_unknown_evidence_matches_attack_type_not_file():
    """GPON(명령 주입) 미확인 증거는 '파일 노출'이 아니라 '명령 실행 출력' 검색으로 서술."""
    r = analyze_response(200, {"server": "Apache"}, "<html>router page</html>", 60,
                         payload="/GponForm/diag_Form?images/", category="cve",
                         url="http://h/GponForm/diag_Form?images/",
                         req_body="wan_conlist=0&dest_host=;id;&ipv=0")
    ev = next(f["evidence"] for f in r["findings"] if f["verdict"] == "미확인")
    assert "명령 실행 출력" in ev
    assert "root:x:0:0" not in ev   # 파일 노출로 오해하지 않음


def test_mislabeled_category_uses_payload_attack_type():
    """category=sqli 라벨이어도 payload 가 파일읽기(/proc/self/environ)면 lfi 로 인식하고
    미확인 증거에 SQL 시그니처를 끼워넣지 않는다."""
    r = analyze_response(200, {}, "<html>generic page</html>", 200,
                         payload="/../../../../proc/self/environ", category="sqli",
                         url="http://h/x")
    assert r["attack_type"] == "lfi"
    ev = next(f["evidence"] for f in r["findings"] if f["verdict"] == "미확인")
    assert "파일 내용" in ev
    assert "SQL" not in ev   # 틀린 카테고리의 SQL 시그니처가 섞이지 않음


def test_git_config_access_is_file_read_not_authbypass():
    """/.git/config 직접 접근은 정보 노출(파일읽기)로 인식 — authbypass 로 오분류하지 않음."""
    from core.analyzer import infer_attack_type
    assert infer_attack_type("/site/.git/config", "authbypass") == "lfi"
    assert infer_attack_type("/site/.git/HEAD", "authbypass") == "lfi"
    assert infer_attack_type("/.env", "") == "lfi"


def test_put_upload_2xx_is_success_not_unknown():
    """PUT 으로 파일 올려 2xx 면 임의 파일 쓰기 성공 — '미확인'이 아니라 취약."""
    r = analyze_response(200, {}, "OK", 40, url="http://h/test22.txt", method="PUT")
    assert r["attack_outcome"] == "success"
    f = next(x for x in r["findings"] if "PUT" in x["name"])
    assert f["verdict"] == "성공"
    assert not any(x["verdict"] == "미확인" for x in r["findings"])


def test_put_denied_405_is_safe():
    r = analyze_response(405, {}, "", 40, url="http://h/x.txt", method="PUT")
    assert any(x["verdict"] == "안전" and "PUT" in x["name"] for x in r["findings"])


def test_javascript_scheme_redirect_is_xss():
    """Location 이 javascript: 스킴으로 나가는 오픈리다이렉트는 XSS 성공으로 탐지."""
    r = analyze_response(302, {"location": "javascript:alert(1)"}, "", 40,
                         url="http://h/go?redirect=javascript:alert(1)", category="redirect")
    assert r["attack_outcome"] == "success"
    assert any("스킴" in f["name"] and f["verdict"] == "성공" for f in r["findings"])


def test_javascript_void_bare_path_is_inconclusive():
    """javascript:void(0) 를 경로로 보내 404 면 실제 신호 없음 → 미확인(허위 성공 금지)."""
    r = analyze_response(404, {"server": "Apache"}, "not found", 40,
                         url="http://h/javascript:void(0)", category="")
    assert not any(f["verdict"] == "성공" for f in r["findings"])


def test_attack_type_classification_matrix():
    """대표 payload 가 올바른 공격 유형으로 분류되는지 전수 검증(유형 간 오분류 방지)."""
    from core.analyzer import infer_attack_type as f
    cases = {
        "sqli": ["' OR '1'='1", "1' UNION SELECT NULL-- -", "1 AND SLEEP(5)-- -",
                 "admin'-- -", "1'; DROP TABLE users-- -", "1' ORDER BY 5-- -"],
        "cmdi": [";id", "| id", "$(id)", "`id`", "& whoami", "dest_host=;id;"],
        "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"],
        "lfi":  ["../../../../etc/passwd", "/proc/self/environ", "..%2f..%2fetc%2fpasswd",
                 "....//....//etc/passwd", ";cat /etc/passwd"],   # cat passwd 는 파일내용이 증거 → lfi
        "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/", "gopher://127.0.0.1"],
        "xss":  ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
                 "<svg/onload=alert(1)>", "javascript:alert(1)"],
    }
    for expected, payloads in cases.items():
        for p in payloads:
            assert f(p, "") == expected, f"{p!r} → {f(p,'')} (expected {expected})"


def test_xss_payload_with_semicolon_is_not_cmdi():
    """XSS payload 는 ';'(alert(1);) 를 흔히 포함 — cmdi 로 오분류하지 말 것."""
    from core.analyzer import infer_attack_type, _checked_desc_for
    for p in ["<script>alert(1);</script>", '"><img src=x onerror=alert(1)>', "<svg/onload=alert(1)>"]:
        assert infer_attack_type(p, "") == "xss", p
        assert "명령 실행" not in _checked_desc_for(p, "")   # cmdi 시그니처 혼입 금지


def test_get_has_no_method_finding():
    r = analyze_response(200, {}, "<html>ok</html>", 40, url="http://h/p", method="GET")
    assert not any("메소드" in x["name"] for x in r["findings"])


def test_success_signal_has_no_unknown_finding():
    r = analyze_response(200, {}, "root:x:0:0:root", 60,
                         payload="../../etc/passwd", category="lfi")
    assert not any(f["verdict"] == "미확인" for f in r["findings"])


def test_safe_signal_has_no_unknown_finding():
    r = analyze_response(200, {}, "<html>app</html>", 60,
                         payload="/.git/config", category="cve", url="http://h/.git/config")
    assert not any(f["verdict"] == "미확인" for f in r["findings"])


def test_non_attack_request_has_no_unknown_finding():
    """payload·category 없는 일반 요청은 '미확인' 신호를 붙이지 않는다."""
    r = analyze_response(200, {}, "<html>home</html>", 60, payload="", category="")
    assert not any(f["verdict"] == "미확인" for f in r["findings"])


def test_reflection_without_success_is_medium():
    """특수문자 없는 값이 그대로 반사되면(미확정 신호) low 가 아니라 medium 이다."""
    r = analyze_response(200, {}, "<div>검색어: harmless_marker_123 결과없음</div>", 100,
                         payload="harmless_marker_123", category="xss")
    assert r["risk_level"] == "medium"
    assert r["attack_outcome"] == "inconclusive"
    assert r["findings"], "미확정이라도 반사 신호(findings)는 남아야 한다"


# ─────────────────────────────────────────────────────────────────────────────
# 차단 판정
# ─────────────────────────────────────────────────────────────────────────────
def test_status_403_is_blocked_info():
    r = analyze_response(403, {}, "Forbidden", 50, payload="1' OR 1=1", category="sqli")
    assert r["verdict"] == "blocked"
    assert r["risk_level"] == "info"


def test_blocked_without_baseline_hedges_path_vs_payload():
    """403 을 '공격 차단 성공'으로 단정하지 않고, baseline 비교를 안내해야 한다."""
    r = analyze_response(403, {}, "403 Forbidden", 234,
                         payload="../../../../etc/passwd", category="lfi")
    why = next(f["why"] for f in r["findings"] if f["name"] == "차단됨")
    assert "경로 자체" in why          # payload 특정 차단이라 단정하지 않음
    assert "baseline" in why           # 구분 방법 안내


def test_blocked_with_baseline_no_hint():
    r = analyze_response(403, {}, "403", 234, payload="../../etc/passwd", category="lfi",
                         baseline={"status_code": 403, "body": "403"})
    why = next(f["why"] for f in r["findings"] if f["name"] == "차단됨")
    assert "baseline" not in why


def test_status_400_is_blocked():
    r = analyze_response(400, {}, "Bad Request", 40, payload="x", category="sqli")
    assert r["verdict"] == "blocked"


def test_block_keyword_in_short_body_marks_blocked():
    r = analyze_response(200, {}, "Request blocked by security policy", 60,
                         payload="x", category="xss")
    assert r["verdict"] == "blocked"


def test_block_keyword_in_large_200_page_is_not_blocked():
    """84KB 정상 페이지에 'forbidden' 단어가 우연히 있어도 차단으로 오판하지 않는다."""
    body = "<html><body>" + ("<div>content forbidden action list</div> " * 1500) + "</body></html>"
    assert len(body) > 40000
    r = analyze_response(200, {"content-type": "text/html"}, body, 48,
                         payload="../../etc/passwd", category="lfi",
                         url="http://h/?lang=../../etc/passwd")
    assert r["verdict"] != "blocked"
    assert r["attack_outcome"] != "blocked"
    assert r["block_reason"] == []


# ─────────────────────────────────────────────────────────────────────────────
# 증거 기반 성공 → 격상 (핵심 기능이 살아있는지)
# ─────────────────────────────────────────────────────────────────────────────
def test_lfi_passwd_leak_is_critical():
    """/etc/passwd 내용이 응답에 있으면 민감정보 노출 → critical."""
    r = analyze_response(200, {}, "root:x:0:0:root:/root:/bin/bash\n", 100,
                         payload="../../../../etc/passwd", category="lfi")
    assert r["risk_level"] == "critical"
    assert r["verdict"] == "bypass"


def test_private_key_leak_is_critical():
    r = analyze_response(200, {}, "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...", 100,
                         payload="x", category="sqli")
    assert r["risk_level"] == "critical"
    assert r["sensitive_data"]


def test_time_based_sqli_success_is_high():
    """SLEEP(5) 요청에 실제 5초 이상 지연이면 blind time-based 성공 → high."""
    r = analyze_response(200, {}, "ok", 5200,
                         payload="1' AND SLEEP(5)-- -", category="sqli")
    assert r["attack_outcome"] == "success"
    assert r["verdict"] == "bypass"
    assert r["risk_level"] == "high"


def test_time_based_sqli_no_delay_is_not_success():
    """지연 payload지만 응답이 빠르면 성공이 아니어야 한다(오탐 방지)."""
    r = analyze_response(200, {}, "ok", 120,
                         payload="1' AND SLEEP(5)-- -", category="sqli")
    assert r["attack_outcome"] != "success"
    assert r["risk_level"] in ("low", "medium")


def test_ssti_evaluation_success():
    """7*7 이 응답에 49(원문 7*7 아님)로 나오면 서버 템플릿 평가 성공."""
    r = analyze_response(200, {}, "<p>result 49 end</p>", 100,
                         payload="{{7*7}}", category="ssti")
    assert r["attack_outcome"] == "success"
    assert r["risk_level"] == "high"


def test_cmdi_id_output_success():
    r = analyze_response(200, {}, "uid=33(www-data) gid=33(www-data)", 100,
                         payload=";id", category="cmdi")
    assert r["attack_outcome"] == "success"
    assert r["verdict"] == "bypass"


def test_xss_exec_context_reflection_success():
    r = analyze_response(200, {}, "<div><svg onload=alert(1)></div>", 100,
                         payload="<svg onload=alert(1)>", category="xss")
    assert r["attack_outcome"] == "success"
    assert r["risk_level"] == "high"


def test_sql_error_leak_is_escalated():
    """SQL 문법 에러가 응답에 노출되면 error-based 성공/누출 → high 이상."""
    body = "You have an error in your SQL syntax; check the manual for MySQL"
    r = analyze_response(200, {}, body, 100, payload="1'", category="sqli")
    assert r["error_leaks"]
    assert r["risk_level"] in ("high", "critical")


# ─────────────────────────────────────────────────────────────────────────────
# 민감 파일 노출 — 상태코드가 아니라 '실제 파일 내용'으로 판정
# ─────────────────────────────────────────────────────────────────────────────
def _names(r):
    return [f["name"] for f in r["findings"]]


def test_git_config_not_exposed_is_low_and_explicit():
    """`.git/config` 에 200이 와도 실제 git 내용이 없으면 '미노출(안전)'로 명확히 판정.

    회귀 방지: 예전에는 신호가 비어 AI가 CSP/쿠키 위생만 결과처럼 서술했다.
    """
    r = analyze_response(200, {"content-type": "text/html"},
                         "<!doctype html><html><body><div id=app></div></body></html>", 80,
                         payload="/.git/config", category="cve")
    assert r["risk_level"] == "low"
    assert r["verdict"] == "passed"
    assert r["attack_outcome"] == "safe"   # 미노출=영향없음(안전)
    assert any("미노출" in n for n in _names(r)), "미노출 사실이 신호로 남아야 한다"


def test_git_config_exposed_is_success():
    r = analyze_response(200, {},
                         "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n", 80,
                         payload="/.git/config", category="cve")
    assert r["attack_outcome"] == "success"
    assert r["verdict"] == "bypass"
    assert r["risk_level"] == "high"
    # 노출을 성공 신호로 보고하되, '미노출(안전)'로 잘못 보고하지 않는다
    assert any(f["verdict"] == "성공" for f in r["findings"])
    assert not any("미노출" in n for n in _names(r))


def test_env_file_not_exposed_is_low():
    r = analyze_response(200, {}, "<html>Not Found</html>", 80,
                         payload="/.env", category="cve")
    assert r["risk_level"] == "low"
    assert any("미노출" in n for n in _names(r))


def test_env_file_exposed_is_critical():
    """.env 실제 노출은 자격증명 유출 → critical."""
    r = analyze_response(200, {}, "APP_ENV=production\nDB_PASSWORD=s3cr3t\nAPI_KEY=abc\n", 80,
                         payload="/.env", category="cve")
    assert r["attack_outcome"] == "success"
    assert r["risk_level"] == "critical"


def test_unrelated_path_is_not_a_sensitive_file_probe():
    """payload 에 .env 유사어(environment)가 있어도 오탐하지 않는다."""
    r = analyze_response(200, {}, "<html>ok</html>", 80,
                         payload="/api/environment", category="cve")
    assert r["risk_level"] == "low"
    # .env 로 오탐(민감 파일/파일 읽기)하지 않아야 한다(미확인 신호는 무방).
    assert not any(("민감 파일" in f["name"]) or ("파일 읽기" in f["name"]) for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# 파일 읽기 성공 — 카테고리(lfi/xxe)에 갇히지 않고 내용으로 확증
# ─────────────────────────────────────────────────────────────────────────────
_PASSWD = "root:x:0:0:root:/root:/bin/bash\n"
_SHADOW = "root:$6$abcXYZ$hashhashhash:19412:0:99999:7:::\n"


def test_passwd_leak_via_cve_traversal_is_success():
    """경로 트래버설 익스플로잇은 흔히 cve 카테고리로 들어온다 — 그래도 탐지돼야 한다."""
    r = analyze_response(200, {}, _PASSWD, 90,
                         payload="/index.php?option=com_x&controller=../../../../etc/passwd",
                         category="cve")
    assert r["attack_outcome"] == "success"
    assert any("파일 읽기" in n for n in _names(r))


def test_shadow_leak_via_lfi_is_success():
    r = analyze_response(200, {}, _SHADOW, 90, payload="../../../etc/shadow", category="lfi")
    assert r["attack_outcome"] == "success"


def test_hosts_leak_is_success():
    r = analyze_response(200, {}, "127.0.0.1 localhost\n10.0.0.5 internal", 90,
                         payload="../../etc/hosts", category="lfi")
    assert r["attack_outcome"] == "success"


def test_loadfile_passwd_via_sqli_is_success():
    r = analyze_response(200, {}, _PASSWD, 90,
                         payload="' UNION SELECT LOAD_FILE('/etc/passwd')-- -", category="sqli")
    assert r["attack_outcome"] == "success"


def test_actuator_env_exposure_is_success():
    r = analyze_response(200, {}, '{"activeProfiles":["prod"],"propertySources":[{}]}', 90,
                         payload="/actuator/env", category="cve")
    assert r["attack_outcome"] == "success"


def test_traversal_not_exposed_stays_low():
    r = analyze_response(200, {}, "<html>Not Found</html>", 90,
                         payload="/x?c=../../../../etc/passwd", category="cve")
    assert r["risk_level"] == "low"
    assert r["attack_outcome"] == "inconclusive"


def test_proc_self_environ_exposed_is_success():
    """/proc/self/environ 덤프(CGI 환경변수)가 응답에 있으면 파일 읽기 성공."""
    environ = ("USER=www-data\x00HOME=/var/www\x00SCRIPT_FILENAME=/var/www/index.php\x00"
               "DOCUMENT_ROOT=/var/www\x00HTTP_USER_AGENT=Mozilla\x00PATH=/usr/bin\x00")
    r = analyze_response(200, {}, environ, 60,
                         payload="/proc/self/environ", category="lfi",
                         url="http://h/?f=/proc/self/environ")
    assert r["attack_outcome"] == "success"


def test_proc_self_environ_not_exposed_is_low():
    r = analyze_response(200, {}, "<html>home</html>", 60,
                         payload="/proc/self/environ", category="lfi")
    assert r["risk_level"] == "low"
    assert r["attack_outcome"] == "inconclusive"


def test_proc_environ_mention_no_false_positive():
    """일반 페이지에 'PATH=' 문구가 있어도 오탐하지 않는다(널바이트/CGI 변수 필요)."""
    r = analyze_response(200, {}, "<html>set your PATH= in docs</html>", 60,
                         payload="x", category="xss")
    assert not any("environ" in n for n in _names(r))


def test_reflected_file_path_is_not_false_file_read():
    """payload 경로 문자열이 반사돼도 실제 파일 '내용'이 아니면 파일 읽기 성공이 아니다."""
    r = analyze_response(200, {}, "<div>you searched: ../../etc/passwd</div>", 90,
                         payload="../../etc/passwd", category="xss")
    assert not any("파일 읽기" in n for n in _names(r))


# ─────────────────────────────────────────────────────────────────────────────
# 강한 시그니처는 전역(요청 형태 무관), 약한 시그니처는 파일 접근 맥락에서만
# ─────────────────────────────────────────────────────────────────────────────
def test_strong_signature_detected_on_any_endpoint():
    """평범한 API 응답이라도 passwd 내용이 유출되면(강한 시그니처) 전역 탐지."""
    r = analyze_response(200, {}, '{"note":"root:x:0:0:root:/root:/bin/bash"}', 80,
                         payload="", category="", url="http://h/api/user/1")
    assert r["attack_outcome"] == "success"


def test_strong_git_config_detected_on_any_path():
    r = analyze_response(200, {}, "[core]\nrepositoryformatversion = 0", 80,
                         payload="", category="", url="http://h/backup/x")
    assert r["attack_outcome"] == "success"


def test_weak_signature_no_false_positive_on_docs():
    """약한 시그니처(hosts, <?php)는 파일 접근 맥락이 아니면 오탐하지 않는다."""
    r = analyze_response(200, {}, "설정 예시: 127.0.0.1 localhost 를 hosts 에 추가하세요", 80,
                         payload="", category="", url="http://h/docs/setup")
    assert r["findings"] == []
    assert r["risk_level"] == "low"


def test_weak_signature_detected_in_file_access_context():
    r = analyze_response(200, {}, "127.0.0.1 localhost\n10.0.0.5 db", 80,
                         payload="../../etc/hosts", category="lfi")
    assert r["attack_outcome"] == "success"


def test_no_duplicate_finding_when_strong_and_path_overlap():
    """git 경로 요청 + git 내용 노출 시, 강한 마커와 민감파일 탐지가 중복 보고하지 않는다."""
    r = analyze_response(200, {}, "[core]\nrepositoryformatversion = 0", 80,
                         payload="", category="", url="http://h/public/.git/config")
    success = [f for f in r["findings"] if f["verdict"] == "성공"]
    assert len(success) == 1


# ─────────────────────────────────────────────────────────────────────────────
# URL 직접 접근 — payload 를 고르지 않고 주소만으로 민감 파일을 GET 한 경우
# ─────────────────────────────────────────────────────────────────────────────
def test_url_only_git_config_exposed():
    """payload 없이 /public/.git/config 를 직접 GET 해도 노출을 탐지한다."""
    r = analyze_response(200, {}, "[core]\n\trepositoryformatversion = 0\n", 80,
                         payload="", category="", url="http://h/public/.git/config")
    assert r["attack_outcome"] == "success"
    assert any(f["verdict"] == "성공" for f in r["findings"])
    assert not any("미노출" in n for n in _names(r))


def test_url_only_git_config_not_exposed_is_low():
    """사용자 신고 케이스: 주소만으로 GET, 실제 내용 없으면 '미노출(안전)' + low."""
    r = analyze_response(200, {}, "<html>app shell</html>", 80,
                         payload="", category="", url="http://h/public/.git/config")
    assert r["risk_level"] == "low"
    assert r["attack_outcome"] == "safe"   # 미노출=영향없음(안전)
    assert any("미노출" in n for n in _names(r))


def test_url_query_traversal_passwd_exposed():
    r = analyze_response(200, {}, "root:x:0:0:root:/root:/bin/bash", 80,
                         payload="", category="", url="http://h/dl?file=../../../../etc/passwd")
    assert r["attack_outcome"] == "success"


def test_plain_url_has_no_false_finding():
    r = analyze_response(200, {}, "<html>홈페이지</html>", 80,
                         payload="", category="", url="http://h/products/list?page=2")
    assert r["risk_level"] == "low"
    assert r["findings"] == []


def test_analyze_response_backward_compatible_without_url():
    """url 인자 없이 호출하던 기존 코드도 그대로 동작한다."""
    r = analyze_response(200, {}, "<html>ok</html>", 80, payload="x", category="sqli")
    assert r["risk_level"] == "low"


# ─────────────────────────────────────────────────────────────────────────────
# 카테고리 무관 결과 확인 — PoC·붙여넣기·기타 페이로드(카테고리 미설정)
# ─────────────────────────────────────────────────────────────────────────────
def test_rce_output_detected_without_category():
    """명령 출력(uid/gid)은 카테고리 없이도 전역 탐지."""
    r = analyze_response(200, {}, "uid=0(root) gid=0(root) groups=0(root)", 80,
                         payload="", category="", url="http://h/ping?ip=1;id")
    assert r["attack_outcome"] == "success"
    assert any("명령 실행" in n for n in _names(r))


def test_ssti_detected_in_body_without_category():
    r = analyze_response(200, {}, "result: 49", 80,
                         payload="", category="", req_body="name={{7*7}}")
    assert r["attack_outcome"] == "success"


def test_sqli_error_detected_urlencoded_body_without_category():
    """붙여넣기 요청의 URL 인코딩 본문(%27)도 디코딩해 SQLi 로 인식."""
    r = analyze_response(200, {}, "You have an error in your SQL syntax; check MySQL", 80,
                         payload="", category="", req_body="q=1%27 OR %271%27=%271")
    assert r["attack_outcome"] == "success"
    assert any("SQL" in n for n in _names(r))


def test_ssrf_metadata_detected_with_hint_without_category():
    r = analyze_response(200, {}, "ami-id: ami-123\ninstance-id: i-abc", 80,
                         payload="", category="",
                         url="http://h/fetch?u=http://169.254.169.254/latest/meta-data")
    assert r["attack_outcome"] == "success"


def test_lfi_double_encoded_body_without_category():
    r = analyze_response(200, {}, "root:x:0:0:root:/root:/bin/bash", 80,
                         payload="", category="", req_body="file=..%252f..%252fetc%252fpasswd")
    assert r["attack_outcome"] == "success"


def test_normal_json_post_no_false_finding():
    r = analyze_response(200, {}, '{"ok":true}', 80,
                         payload="", category="", req_body='{"name":"kim","age":20}')
    assert r["findings"] == []


def test_ssrf_metadata_text_without_hint_not_flagged():
    """SSRF 시도 흔적이 없으면 응답에 metadata 유사 문구가 있어도 SSRF 성공으로 보지 않는다."""
    r = analyze_response(200, {}, "our instance-id format is i-xxx", 80,
                         payload="", category="", url="http://h/docs")
    assert not any("메타데이터" in n for n in _names(r))


# ─────────────────────────────────────────────────────────────────────────────
# WAF 지문 탐지
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# 기술 스택/인프라 지문 (Envoy 프록시 등)
# ─────────────────────────────────────────────────────────────────────────────
def test_detect_stack_envoy_and_nextjs():
    h = {"server": "envoy", "x-envoy-upstream-service-time": "54",
         "x-powered-by": "Next.js", "content-type": "text/html"}
    names = {s["name"] for s in detect_stack(h)}
    assert "Envoy" in names
    assert "Next.js" in names


def test_detect_stack_envoy_via_xheader_only():
    """server 헤더가 없어도 x-envoy-* 만으로 Envoy 인식."""
    names = {s["name"] for s in detect_stack({"x-envoy-decorator-operation": "x"})}
    assert "Envoy" in names


def test_detect_stack_cdn_and_server():
    assert "Cloudflare" in {s["name"] for s in detect_stack({"cf-ray": "abc", "server": "cloudflare"})}
    assert "nginx" in {s["name"] for s in detect_stack({"server": "nginx/1.25.0"})}
    assert "IIS" in {s["name"] for s in detect_stack({"server": "Microsoft-IIS/10.0"})}


def test_detect_stack_none_when_generic():
    assert detect_stack({"content-type": "text/html", "date": "..."}) == []


def test_analyze_response_includes_tech_stack():
    r = analyze_response(200, {"server": "envoy", "x-powered-by": "Next.js"}, "<html>ok</html>", 50,
                         payload="x", category="xss")
    names = {s["name"] for s in r["tech_stack"]}
    assert "Envoy" in names and "Next.js" in names


def test_detect_waf_cloudflare():
    assert detect_waf({"server": "cloudflare", "cf-ray": "abc123"}) == "Cloudflare"


def test_detect_waf_none_when_clean():
    assert detect_waf({"server": "nginx"}) is None


def test_waf_header_recorded_in_analysis():
    r = analyze_response(200, {"server": "cloudflare"}, "<html>ok</html>", 100,
                         payload="x", category="xss")
    assert r["waf_detected"] == "Cloudflare"


# ─────────────────────────────────────────────────────────────────────────────
# 요약 집계
# ─────────────────────────────────────────────────────────────────────────────
def test_generate_summary_counts_and_rate():
    results = [
        {"analysis": {"verdict": "blocked", "risk_level": "info"}},
        {"analysis": {"verdict": "blocked", "risk_level": "info"}},
        {"analysis": {"verdict": "passed", "risk_level": "low"}},
        {"analysis": {"verdict": "bypass", "risk_level": "critical", "waf_detected": "Cloudflare"}},
    ]
    s = generate_summary(results)
    assert s["total"] == 4
    assert s["blocked"] == 2
    assert s["bypass"] == 1
    assert s["detection_rate"] == 50.0
    assert s["risk_counts"]["critical"] == 1
    assert s["waf_detected"] == ["Cloudflare"]


def test_generate_summary_empty():
    assert generate_summary([]) == {}


# ─────────────────────────────────────────────────────────────────────────────
# XML-RPC (WordPress xmlrpc.php 등) 위험 응답 탐지
# ─────────────────────────────────────────────────────────────────────────────
def _has_finding(r, needle):
    return any(needle in f["name"] for f in r["findings"])


def test_xmlrpc_incorrect_password_is_bruteforce_surface():
    """multicall 응답에 'Incorrect username or password' fault → 인증 메서드 활성(brute-force 표면) 성공 신호."""
    body = ('<?xml version="1.0" encoding="UTF-8"?>\n<methodResponse><params><param><value>'
            '<array><data><value><struct>'
            '<member><name>faultCode</name><value><int>403</int></value></member>'
            '<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>'
            '</struct></value></data></array></value></param></params></methodResponse>')
    r = analyze_response(200, {"content-type": "text/xml"}, body, 90,
                         payload="", category="", url="https://t.example.com/xmlrpc.php")
    assert _has_finding(r, "XML-RPC 인증 메서드 노출")
    assert r["attack_outcome"] == "success"


def test_xmlrpc_dangerous_methods_from_listmethods():
    """system.listMethods 응답에 pingback.ping / system.multicall 노출 → 위험 메서드 성공 신호."""
    body = ('<?xml version="1.0"?><methodResponse><params><param><value><array><data>'
            '<value><string>system.multicall</string></value>'
            '<value><string>pingback.ping</string></value>'
            '<value><string>wp.getUsersBlogs</string></value>'
            '</data></array></value></param></params></methodResponse>')
    r = analyze_response(200, {"content-type": "text/xml"}, body, 80,
                         payload="", category="", url="https://t.example.com/xmlrpc.php")
    assert _has_finding(r, "system.multicall")
    assert _has_finding(r, "pingback.ping")
    assert r["attack_outcome"] == "success"


def test_xmlrpc_bare_methodresponse_is_info_only():
    """공격 신호 없는 단순 methodResponse → 엔드포인트 활성(미확정) 정보만, 성공으로 격상 안 함."""
    body = ('<?xml version="1.0"?><methodResponse><params><param>'
            '<value><string>hello</string></value></param></params></methodResponse>')
    r = analyze_response(200, {"content-type": "text/xml"}, body, 50,
                         payload="", category="", url="https://t.example.com/xmlrpc.php")
    assert _has_finding(r, "XML-RPC 엔드포인트 활성")
    assert r["attack_outcome"] != "success"


def test_non_xmlrpc_body_no_false_positive():
    """일반 HTML 응답은 XML-RPC 신호를 만들지 않는다(오탐 방지)."""
    r = analyze_response(200, {"content-type": "text/html"},
                         "<html><body>Incorrect username or password.</body></html>", 60,
                         payload="", category="")
    assert not _has_finding(r, "XML-RPC")


# ─────────────────────────────────────────────────────────────────────────────
# 검증 내역(method/where) — 모든 finding이 "어떻게/어디서 검증했는지"를 갖는다
# ─────────────────────────────────────────────────────────────────────────────
def test_every_finding_has_verification_meta():
    """성공/미확정/미확인 등 어떤 신호든 method·where 가 채워져야 한다(향후 추가분도)."""
    cases = [
        # (status, headers, body, time, payload, category, url)
        (200, {}, "root:x:0:0:root:/root:/bin/bash", 100, "../../etc/passwd", "lfi", None),
        (200, {}, "<html>uid=0(root) gid=0(root)</html>", 100, ";id", "cmdi", None),
        (200, {}, "search: <script>alert(1)</script>", 100, "<script>alert(1)</script>", "xss", None),
        (200, {"content-type": "text/xml"},
         '<methodResponse><params><param><value><array><data><value><struct>'
         '<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>'
         '</struct></value></data></array></value></param></params></methodResponse>', 90, "", "", "https://t/xmlrpc.php"),
        (200, {}, "<html>normal</html>", 60, "{{7*7}}", "ssti", None),   # 자동 판정 불가
    ]
    for st, h, b, t, p, c, u in cases:
        r = analyze_response(st, h, b, t, payload=p, category=c, url=u)
        for f in r["findings"]:
            assert f.get("method"), f"method 누락: {f['name']}"
            assert f.get("where"), f"where 누락: {f['name']}"


def test_verification_meta_maps_known_finding():
    """알려진 신호는 표에 정의된 검증 방법으로 매핑된다."""
    r = analyze_response(200, {}, "root:x:0:0:root:/root:/bin/bash", 100,
                         payload="../../etc/passwd", category="lfi")
    fr = next(f for f in r["findings"] if "파일 읽기" in f["name"])
    assert fr["method"] == "콘텐츠 시그니처"
    assert "응답" in fr["where"]


# ─────────────────────────────────────────────────────────────────────────────
# 오탐 수정: PNG/이미지 base64 를 '토큰'으로 오탐하지 않는다 (JWT 만 정밀 탐지)
# ─────────────────────────────────────────────────────────────────────────────
def test_png_base64_is_not_flagged_as_token():
    png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAANAAAAAwCAYAAABg4PT2" + "A"*200
    r = analyze_response(200, {"content-type": "text/html"},
                         f"<html><img src='{png}'></html>", 120, payload="", category="")
    assert not any("토큰" in s or "Base64" in s for s in r["sensitive_data"])


def test_jwt_is_flagged_as_token():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
    r = analyze_response(200, {}, f"token={jwt}", 100, payload="", category="")
    assert any("JWT" in s for s in r["sensitive_data"])


def test_xmlrpc_post_only_banner_is_endpoint_active():
    r = analyze_response(200, {"content-type": "text/html"},
                         "XML-RPC server accepts POST requests only.", 90,
                         payload="", category="", url="https://t.example.com/xmlrpc.php")
    assert any("XML-RPC 엔드포인트 활성" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# XML-RPC: 취약 패턴 미검출 시 200이어도 '영향 없음(안전)'으로 판정 (시그니처 기반)
# ─────────────────────────────────────────────────────────────────────────────
def test_xmlrpc_probe_no_signal_is_safe_not_unknown():
    """xmlrpc.php 를 겨냥했는데 위험 신호가 없으면 '영향 없음(안전)', '미확인' 아님."""
    r = analyze_response(200, {"content-type": "text/html"},
                         "<html><body>일반 페이지</body></html>", 120,
                         payload="", category="",
                         url="https://t.example.com/xmlrpc.php",
                         req_body="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>",
                         method="POST")
    assert any("영향 없음" in f["name"] and f["verdict"] == "안전" for f in r["findings"])
    assert not any(f["verdict"] == "미확인" for f in r["findings"])


def test_xmlrpc_probe_with_signal_is_not_safe():
    """위험 신호가 있으면 '영향 없음' 안전 판정을 내리지 않는다."""
    body = ('<methodResponse><params><param><value><array><data><value><struct>'
            '<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>'
            '</struct></value></data></array></value></param></params></methodResponse>')
    r = analyze_response(200, {"content-type": "text/xml"}, body, 90,
                         payload="", category="", url="https://t.example.com/xmlrpc.php")
    assert not any("영향 없음" in f["name"] for f in r["findings"])
    assert r["attack_outcome"] == "success"


def test_non_xmlrpc_request_no_safe_noise():
    """XML-RPC 와 무관한 요청엔 XML-RPC '영향 없음' 신호가 붙지 않는다."""
    r = analyze_response(200, {}, "<html>ok</html>", 100, payload="", category="",
                         url="https://t.example.com/index.html")
    assert not any("XML-RPC" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# 미검출=영향 없음 확장: 비-blind 시그니처 검사(오픈 리다이렉트)는 안전, blind 계열은 미확인 유지
# ─────────────────────────────────────────────────────────────────────────────
def test_redirect_probe_no_signal_is_safe():
    """오픈 리다이렉트를 겨냥했는데 외부 Location·클라이언트 리다이렉트가 없으면 '영향 없음'."""
    r = analyze_response(200, {"content-type": "text/html"},
                         "<html><body>홈</body></html>", 80,
                         payload="//evil.example.com", category="redirect",
                         url="https://t.example.com/go?next=//evil.example.com")
    assert any("오픈 리다이렉트 취약 신호 미검출" in f["name"] and f["verdict"] == "안전"
               for f in r["findings"])


def test_redirect_actual_external_is_success_not_safe():
    r = analyze_response(302, {"location": "https://evil.example.com"}, "", 50,
                         payload="//evil.example.com", category="redirect")
    assert any("외부 리다이렉트" in f["name"] for f in r["findings"])
    assert not any("영향 없음" in f["name"] for f in r["findings"])


def test_same_host_redirect_is_not_open_redirect():
    """'외부' 리다이렉트여야 성공이다 — 같은 호스트로의 절대 URL 이동(로그인 페이지 등)은 아니다.

    회귀 방지: probe 에는 대상 URL 자체(//host.tld/)가 섞여 리다이렉트 힌트로 오인되므로,
    평범한 SSO/로그인 리다이렉트가 '오픈 리다이렉트 성공'으로 뜨던 문제.
    """
    r = analyze_response(302, {"location": "https://t.example.com/login"}, "", 50,
                         payload="/plugin", category="cve", url="https://t.example.com/plugin")
    assert not any("외부 리다이렉트" in f["name"] for f in r["findings"])
    assert r["attack_outcome"] != "success"


def test_same_host_redirect_ignores_default_port_difference():
    r = analyze_response(302, {"location": "https://t.example.com:443/login"}, "", 50,
                         payload="//evil.example.com", category="redirect",
                         url="https://t.example.com/go?next=//evil.example.com")
    assert not any("외부 리다이렉트" in f["name"] for f in r["findings"])


def test_external_redirect_with_known_request_host_is_success():
    """요청 호스트를 알아도 실제로 다른 호스트로 나가면 오픈 리다이렉트 성공."""
    r = analyze_response(302, {"location": "https://evil.example.com/"}, "", 50,
                         payload="//evil.example.com", category="redirect",
                         url="https://t.example.com/go?next=//evil.example.com")
    assert any("외부 리다이렉트" in f["name"] for f in r["findings"])
    assert r["attack_outcome"] == "success"


def test_blind_prone_sqli_miss_stays_unknown_not_safe():
    """blind 가능 계열(SQLi)은 증거 미검출 시 '영향 없음'으로 단정하지 않고 미확인 유지."""
    r = analyze_response(200, {}, "<html>일반 페이지</html>", 100,
                         payload="1' OR '1'='1", category="sqli")
    assert not any("영향 없음" in f["name"] for f in r["findings"])
    assert any(f["verdict"] == "미확인" for f in r["findings"])


def test_cmdi_miss_stays_unknown_not_safe():
    r = analyze_response(200, {}, "<html>ok</html>", 100, payload=";id", category="cmdi")
    assert not any("영향 없음" in f["name"] for f in r["findings"])
    assert any(f["verdict"] == "미확인" for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# 실제 확인한 시그니처(checked) — 미검출/미확인 판정에 무엇을 검색했는지 명시
# ─────────────────────────────────────────────────────────────────────────────
def test_xmlrpc_safe_lists_checked_signatures():
    r = analyze_response(200, {"content-type": "text/html"}, "<html>ok</html>", 90,
                         payload="", category="", url="https://t.example.com/xmlrpc.php",
                         req_body="<methodCall><methodName>system.listMethods</methodName></methodCall>",
                         method="POST")
    f = next(x for x in r["findings"] if "영향 없음" in x["name"])
    assert f.get("checked")
    assert "methodResponse" in f["checked"] and "pingback.ping" in f["checked"]


def test_unknown_finding_lists_checked_signatures():
    r = analyze_response(200, {}, "<html>일반 페이지</html>", 100,
                         payload="1' OR '1'='1", category="sqli")
    f = next(x for x in r["findings"] if x["verdict"] == "미확인")
    assert f.get("checked")   # SQL/DB 에러 등 검색 시그니처가 명시돼야


def test_sensitive_file_miss_has_checked():
    r = analyze_response(200, {}, "<html>page</html>", 80,
                         payload="/.git/config", category="cve",
                         url="https://t.example.com/.git/config")
    f = next((x for x in r["findings"] if "민감 파일" in x["name"]), None)
    if f:   # 프로브가 민감파일로 인식된 경우
        assert f.get("checked")


# ─────────────────────────────────────────────────────────────────────────────
# L1(not-HTML) + L2(형식 검증) — 파일별 시그니처 없이 형식으로 노출 확증
# ─────────────────────────────────────────────────────────────────────────────
def test_serverless_yaml_valid_format_is_exposed():
    body = "service: my-api\nprovider:\n  name: aws\nfunctions:\n  hello:\n    handler: h.main\n"
    r = analyze_response(200, {"content-type": "application/x-yaml"}, body, 80,
                         payload="/serverless.yaml", category="cve",
                         url="https://t.example.com/serverless.yaml")
    f = next(x for x in r["findings"] if "설정/시크릿" in x["name"] or "노출" in x["name"])
    assert f["verdict"] == "성공"
    assert f.get("checked")


def test_serverless_yaml_html_catchall_is_safe():
    """catch-all 이 200+HTML 을 줘도 노출로 오탐하지 않음(L1)."""
    body = "<!doctype html><html><head><title>App</title></head><body>home</body></html>"
    r = analyze_response(200, {"content-type": "text/html"}, body, 80,
                         payload="/serverless.yaml", category="cve",
                         url="https://t.example.com/serverless.yaml")
    assert not any(f["verdict"] == "성공" and "노출" in f["name"] for f in r["findings"])
    assert any("미노출" in f["name"] or "영향 없음" in f["name"] or f["verdict"] == "안전"
               for f in r["findings"])


def test_env_file_keyvalue_is_exposed():
    body = "APP_KEY=base64:xxxx\nDB_PASSWORD=secret\nDB_HOST=localhost\n"
    r = analyze_response(200, {"content-type": "text/plain"}, body, 60,
                         payload="/.env", category="cve", url="https://t.example.com/.env")
    assert any(f["verdict"] == "성공" for f in r["findings"] if "파일" in f["name"] or "env" in f["name"])


def test_dotenv_403_is_protected_safe():
    r = analyze_response(403, {"content-type": "text/html"}, "Forbidden", 40,
                         payload="/.env", category="cve", url="https://t.example.com/.env")
    assert not any(f["verdict"] == "성공" for f in r["findings"])


def test_normal_json_api_not_flagged_as_file():
    """일반 API 의 JSON 응답(설정 파일명 아님)은 파일 노출로 오탐하지 않음."""
    r = analyze_response(200, {"content-type": "application/json"},
                         '{"users":[{"id":1}],"total":1}', 50,
                         payload="", category="", url="https://t.example.com/api/users")
    assert not any("설정/시크릿" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# L3 catch-all 차분 확증 — 순수 판정(decide_file_exposure) + 파일형 판정(looks_real)
# ─────────────────────────────────────────────────────────────────────────────
def test_l3_decide_confirms_only_when_sibling_not_file():
    from core.confirm import decide_file_exposure
    # 대상=파일형, 형제=파일형 아님 → 노출 확증
    assert decide_file_exposure("yaml", True, False)
    # 형제도 파일형(catch-all) → 확증 안 함(오탐 방지)
    assert decide_file_exposure("yaml", True, True) == []
    # 대상이 파일형 아님 → 확증 안 함
    assert decide_file_exposure("yaml", False, False) == []


def test_l3_looks_real_yaml_vs_html():
    from core.analyzer import file_exposure_looks_real
    yaml_body = "service: api\nprovider:\n  name: aws\n"
    assert file_exposure_looks_real(yaml_body, {"content-type": "application/x-yaml"}, 200, "yaml")
    # HTML(catch-all) → 파일형 아님
    assert not file_exposure_looks_real("<!doctype html><html></html>", {"content-type": "text/html"}, 200, "yaml")
    # 404 → 파일형 아님
    assert not file_exposure_looks_real(yaml_body, {"content-type": "application/x-yaml"}, 404, "yaml")


# ─────────────────────────────────────────────────────────────────────────────
# nuclei exposure 매처 임포트 소비 — 경로 매칭 + word/status 로 노출 확증
# ─────────────────────────────────────────────────────────────────────────────
def test_exposure_sig_aws_credentials_detected():
    body = "[default]\naws_access_key_id = AKIAxxxx\naws_secret_access_key = secret\n"
    r = analyze_response(200, {"content-type": "text/plain"}, body, 60,
                         payload="/.aws/credentials", category="cve",
                         url="https://t.example.com/.aws/credentials")
    assert any("노출 확인" in f["name"] and f["verdict"] == "성공" for f in r["findings"])
    assert r["attack_outcome"] == "success"


def test_exposure_sig_path_gated_no_false_positive():
    """시그니처 경로와 무관한 요청엔 exposure 신호가 붙지 않는다(경로 게이팅)."""
    r = analyze_response(200, {}, "aws_access_key_id=x aws_secret_access_key=y", 50,
                         payload="", category="", url="https://t.example.com/api/data")
    assert not any("노출 확인" in f["name"] for f in r["findings"])


def test_exposure_sig_requires_all_matchers_when_and():
    """matchers_condition=and 인데 word 만 있고 status 불일치면 확증하지 않는다."""
    # AWS 시그니처는 and(word+status200). status 404 면 미매칭.
    r = analyze_response(404, {}, "aws_access_key_id=x\naws_secret_access_key=y", 50,
                         payload="/.aws/credentials", category="cve",
                         url="https://t.example.com/.aws/credentials")
    assert not any("노출 확인" in f["name"] for f in r["findings"])


def test_convert_exposure_parses_nuclei_matchers():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
    import import_nuclei as N
    tpl = {"id": "svn-entries", "info": {"name": "SVN", "severity": "medium"},
           "http": [{"method": "GET", "path": ["{{BaseURL}}/.svn/entries"],
                     "matchers-condition": "and",
                     "matchers": [{"type": "word", "part": "body", "words": ["dir"], "condition": "or"},
                                  {"type": "status", "status": [200]}]}]}
    s = N.convert_exposure(tpl)
    assert s and s["path_contains"] == ["/.svn/entries"]
    assert s["matchers_condition"] == "and" and len(s["matchers"]) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 결정적 서술(det_verdict) — AI 없이도 요약·우선확인·조치 제공
# ─────────────────────────────────────────────────────────────────────────────
def test_det_verdict_always_present():
    r = analyze_response(200, {}, "<html>ok</html>", 80, payload="1' OR '1'='1", category="sqli")
    d = r["det_verdict"]
    assert d["summary"] and d["priority"] and d["remediation"]


def test_det_verdict_success_gives_type_remediation():
    body = "You have an error in your SQL syntax; check the manual near '1''"
    r = analyze_response(200, {}, body, 100, payload="1'", category="sqli")
    d = r["det_verdict"]
    assert r["attack_outcome"] == "success"
    assert "쿼리" in d["remediation"] or "바인딩" in d["remediation"]


def test_det_verdict_safe_no_type_remediation():
    r = analyze_response(404, {}, "<html>404</html>", 60, payload="/serverless.yaml",
                         category="cve", url="https://t/serverless.yaml")
    d = r["det_verdict"]
    assert r["attack_outcome"] == "safe"
    assert "불필요" in d["remediation"]


def test_sql_error_variants_detected():
    from core.analyzer import ERROR_LEAK_PATTERNS
    import re
    for msg in ["You have an error in your SQL syntax",
                "check the manual that corresponds to your MariaDB server version",
                "SQLSTATE[42000]: Syntax error"]:
        assert any(re.search(p, msg, re.I) for p, _ in ERROR_LEAK_PATTERNS), msg


# ─────────────────────────────────────────────────────────────────────────────
# URL 직접 입력(payload 필드 빈값)에서도 반사형 XSS 탐지 — 요청 실제 값으로 반사 검사
# ─────────────────────────────────────────────────────────────────────────────
def test_reflected_xss_from_url_when_payload_empty():
    body = "<h1>0 search results for 'test\"><svg onload=alert(1)>'</h1>"
    r = analyze_response(200, {"content-type": "text/html"}, body, 100,
                         payload="", category="",
                         url="https://t/?search=test\"><svg onload=alert(1)>")
    assert r["attack_outcome"] == "success"
    assert any("반사형 XSS" in f["name"] and f["verdict"] == "성공" for f in r["findings"])


def test_benign_url_reflection_no_false_positive():
    r = analyze_response(200, {"content-type": "text/html"}, "<h1>results for hello world</h1>", 80,
                         payload="", category="", url="https://t/?search=hello world")
    assert not any("XSS" in f["name"] for f in r["findings"])


def test_reflected_xss_from_body_value():
    body = "<div>comment: <img src=x onerror=alert(1)></div>"
    r = analyze_response(200, {"content-type": "text/html"}, body, 90,
                         payload="", category="", url="https://t/comment",
                         req_body='{"comment":"<img src=x onerror=alert(1)>"}', method="POST")
    assert any("반사형 XSS" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# XSS 인코딩/문자열 변형에도 일관 탐지 — 실행형 구성요소가 인코딩 없이 반사되면 성공,
# 전체 HTML 인코딩(방어)이면 안전
# ─────────────────────────────────────────────────────────────────────────────
def test_xss_partial_encoding_still_detected():
    # 서버가 따옴표만 인코딩, <svg onload=…> 는 원문 반사 → 실행 가능
    body = "<h1>x&quot;><svg onload=alert(1)></h1>"
    r = analyze_response(200, {"content-type": "text/html"}, body, 50,
                         payload="", category="", url='https://t/?q="><svg onload=alert(1)>')
    assert r["attack_outcome"] == "success"
    assert any("반사형 XSS" in f["name"] for f in r["findings"])


def test_xss_full_html_encoding_is_safe():
    body = "<h1>&lt;svg onload=alert(1)&gt;</h1>"   # 완전 인코딩 = 방어됨
    r = analyze_response(200, {"content-type": "text/html"}, body, 50,
                         payload="", category="", url="https://t/?q=<svg onload=alert(1)>")
    assert not any("반사형 XSS" in f["name"] for f in r["findings"])


def test_xss_transport_urlencoded_reflected_decoded():
    body = "<h1>'<svg onload=alert(1)>'</h1>"
    r = analyze_response(200, {"content-type": "text/html"}, body, 50,
                         payload="", category="", url="https://t/?q=%3Csvg%20onload%3Dalert(1)%3E")
    assert r["attack_outcome"] == "success"


# ─────────────────────────────────────────────────────────────────────────────
# UNION 기반 SQLi — 버전/배너 데이터가 응답에 추출되면 성공(에러 아님)
# ─────────────────────────────────────────────────────────────────────────────
def test_union_sqli_oracle_extraction_success():
    body = ("<table><tr><th>Oracle Database 11g Express Edition Release 11.2.0.2.0</th></tr>"
            "<tr><th>PL/SQL Release 11.2.0.2.0 - Production</th></tr></table>")
    r = analyze_response(200, {"content-type": "text/html"}, body, 1200, payload="", category="",
                         url="https://t/filter?category=x' UNION SELECT BANNER,NULL FROM v$version--")
    assert r["attack_outcome"] == "success"
    assert any("UNION 기반 SQLi" in f["name"] for f in r["findings"])


def test_union_sqli_various_dbms():
    u = "https://t/?id=1 UNION SELECT version()--"
    for banner in ["8.0.32-0ubuntu0.22.04.2", "10.5.18-MariaDB-0+deb11u1",
                   "PostgreSQL 14.5 on x86_64-pc-linux-gnu", "Microsoft SQL Server 2019 (RTM)"]:
        r = analyze_response(200, {}, banner, 50, payload="", category="sqli", url=u)
        assert any("UNION 기반 SQLi" in f["name"] for f in r["findings"]), banner


def test_db_name_mention_without_sqli_probe_no_fp():
    r = analyze_response(200, {}, "<p>Powered by Oracle Database</p>", 50,
                         payload="", category="", url="https://t/about")
    assert not any("UNION" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# DBMS 에러 시그니처 보강(sqlmap errors.xml 참조) — 다수 DBMS 에러 탐지 + 단순 언급 무탐
# ─────────────────────────────────────────────────────────────────────────────
def test_expanded_dbms_error_signatures():
    import re
    from core.analyzer import ERROR_LEAK_PATTERNS
    def hit(s): return any(re.search(p, s, re.I) for p, _ in ERROR_LEAK_PATTERNS)
    for s in [
        "org.postgresql.util.PSQLException: ERROR: syntax error at or near",
        "com.mysql.jdbc.exceptions.MySQLSyntaxErrorException",
        "Incorrect syntax near ')'.",
        "ORA-00933: SQL command not properly ended",
        "[SQLITE_ERROR] near \"'\": syntax error",
        "DB2 SQL error: SQLCODE=-104, SQLSTATE=42601",
        "Code: 62. DB::Exception: Syntax error",
    ]:
        assert hit(s), s


def test_dbms_name_mention_not_flagged():
    import re
    from core.analyzer import ERROR_LEAK_PATTERNS
    for s in ["We use PostgreSQL and MySQL in production.",
              "<h1>Oracle Database consulting services</h1>",
              "Learn SQL Server administration"]:
        assert not any(re.search(p, s, re.I) for p, _ in ERROR_LEAK_PATTERNS), s


def test_error_based_sqli_detected_via_expanded_patterns():
    body = "<pre>org.postgresql.util.PSQLException: ERROR: syntax error at or near \"'\"</pre>"
    r = analyze_response(200, {}, body, 80, payload="1'", category="sqli", url="https://t/?id=1'")
    assert any("SQL/DB 에러 노출" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# 인코딩 반사 설명 신호 — 응답 본문에 HTML 엔티티로 반사되면 '여기선 안전'을 명시
# ─────────────────────────────────────────────────────────────────────────────
def test_encoded_reflection_marked_safe_with_explanation():
    body = "<h1>0 results for '&quot;&gt;&lt;svg onload=alert(&apos;XSS&apos;)&gt;'</h1>"
    r = analyze_response(200, {"content-type": "text/html"}, body, 50, payload="",
                         category="", url="https://t/?search=\"><svg onload=alert('XSS')>")
    assert any("인코딩 반사" in f["name"] and f["verdict"] == "안전" for f in r["findings"])


def test_encoded_reflection_plus_dom_sink_shows_both():
    body = ("<h1>'&quot;&gt;&lt;svg onload=alert(1)&gt;'</h1>"
            "<script>document.write(location.search)</script>")
    r = analyze_response(200, {"content-type": "text/html"}, body, 50, payload="",
                         category="xss", url="https://t/?search=\"><svg onload=alert(1)>")
    names = [f["name"] for f in r["findings"]]
    assert any("인코딩 반사" in n for n in names)
    assert any("DOM 기반 XSS" in n for n in names)


def test_unencoded_reflection_not_marked_as_encoded():
    body = "<h1>x\"><svg onload=alert(1)></h1>"
    r = analyze_response(200, {"content-type": "text/html"}, body, 50, payload="",
                         category="", url="https://t/?q=\"><svg onload=alert(1)>")
    assert any("반사형 XSS" in f["name"] and f["verdict"] == "성공" for f in r["findings"])
    assert not any("인코딩 반사" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# robots.txt 파일 스캔 — 노출된 경로(관리/백업 등) 분석
# ─────────────────────────────────────────────────────────────────────────────
def test_robots_txt_interesting_path_disclosed():
    r = analyze_response(200, {"content-type": "text/plain"},
                         "User-agent: *\nDisallow: /backup\n", 50,
                         payload="", category="", url="https://t/robots.txt")
    f = next(f for f in r["findings"] if "robots.txt" in f["name"])
    assert "민감 경로" in f["name"]
    assert "/backup" in f["evidence"]


def test_robots_txt_mundane_paths_low_key():
    r = analyze_response(200, {}, "User-agent: *\nDisallow: /css\nDisallow: /images\n", 50,
                         payload="", category="", url="https://t/robots.txt")
    assert any("robots.txt 경로 노출" == f["name"] for f in r["findings"])
    assert not any("민감 경로" in f["name"] for f in r["findings"])


def test_robots_content_on_non_robots_path_no_fp():
    r = analyze_response(200, {}, "User-agent: *\nDisallow: /admin", 50,
                         payload="", category="", url="https://t/index.html")
    assert not any("robots.txt" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# OS/시스템/앱 설정 파일 노출 — 내용 시그니처로 확증(경로+내용), 오탐 방지
# ─────────────────────────────────────────────────────────────────────────────
def test_os_config_files_detected_by_content():
    cases = [
        ("https://t/..%2f..%2fetc/passwd", "root:x:0:0:root:/root:/bin/bash"),
        ("https://t/etc/shadow", "root:$6$abcd$hashvalue:19000:0:99999"),
        ("https://t/ssh/sshd_config", "Port 22\nPermitRootLogin yes"),
        ("https://t/php.ini", "[PHP]\ndisplay_errors = On"),
        ("https://t/..\windows\win.ini", "[fonts]\n[extensions]"),
        ("https://t/unattend.xml", "<AutoLogon><Password>x</Password></AutoLogon>"),
        ("https://t/settings.py", "SECRET_KEY = 'x'\nDATABASES = {}"),
        ("https://t/nginx.conf", "worker_processes auto;\nhttp {"),
    ]
    for url, body in cases:
        r = analyze_response(200, {}, body, 50, payload="", category="", url=url)
        assert any("노출" in f["name"] and f["verdict"] == "성공" for f in r["findings"]), url


def test_os_config_path_without_content_no_fp():
    # 경로는 config 파일이지만 응답이 catch-all HTML → 노출 아님
    r = analyze_response(200, {"content-type": "text/html"},
                         "<!doctype html><html><body>Not Found</body></html>", 50,
                         payload="", category="", url="https://t/etc/passwd")
    assert not any("노출" in f["name"] and f["verdict"] == "성공" for f in r["findings"])


def test_config_content_on_unrelated_path_no_fp():
    r = analyze_response(200, {}, "how to read /etc/passwd tutorial root:x:0:0 example", 50,
                         payload="", category="", url="https://t/blog/article")
    assert not any("etc/passwd" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# 클라우드 자격증명/설정 및 백업·덤프 파일 노출 (경로+내용 확증)
# ─────────────────────────────────────────────────────────────────────────────
def test_cloud_and_backup_files_detected():
    cases = [
        ("https://t/.aws/config", "[default]\nregion = us-east-1\noutput = json"),
        ("https://t/service-account.json", '{"type": "service_account","private_key":"-----BEGIN","client_email":"a@b"}'),
        ("https://t/.kube/config", "apiVersion: v1\nclusters:\n- cluster:\ncurrent-context: prod"),
        ("https://t/terraform.tfstate", '{"terraform_version":"1.5","resources":[],"lineage":"x"}'),
        ("https://t/.netrc", "machine ftp.example.com login admin password secret"),
        ("https://t/.pgpass", "db.host:5432:mydb:admin:s3cret"),
        ("https://t/.ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn"),
        ("https://t/backup.sql", "-- MySQL dump 10.13\nCREATE TABLE users (id int);\nINSERT INTO users"),
        ("https://t/wp-config.php.bak", "define('DB_PASSWORD','root');\ndefine('DB_NAME','wp');"),
        ("https://t/index.php.old", "<?php\n$password='admin';\ndefine('DB_HOST','x');"),
        ("https://t/.env.bak", "DB_PASSWORD=secret\nAPI_KEY=abc\nSECRET=x"),
        ("https://t/.vscode/sftp.json", '{"host":"1.2.3.4","password":"pw","remotePath":"/var/www"}'),
    ]
    for url, body in cases:
        r = analyze_response(200, {}, body, len(body), payload="", category="", url=url)
        assert any("노출" in f["name"] and f["verdict"] == "성공" for f in r["findings"]), url


def test_cloud_backup_no_fp_on_html_or_mention():
    # 경로는 백업 파일이지만 catch-all HTML → 노출 아님
    r = analyze_response(200, {"content-type": "text/html"},
                         "<!doctype html><html><body>404 Not Found</body></html>", 40,
                         payload="", category="", url="https://t/backup.sql")
    assert not any("노출" in f["name"] and f["verdict"] == "성공" for f in r["findings"])
    # 무관 경로에서 aws 설정 언급만 → 노출 아님
    r2 = analyze_response(200, {}, "put your keys in .aws/config with region = us-east-1", 40,
                          payload="", category="", url="https://t/blog/aws-guide")
    assert not any("AWS config" in f["name"] for f in r2["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# CONNECT(오픈 프록시/터널) 및 비표준 메소드 스캔 인식
# ─────────────────────────────────────────────────────────────────────────────
def test_connect_cisco_webvpn_tunnel_scan():
    url = "https://test.com/cscosslc/tunnel"
    # 빈/짧은 본문 2xx → 터널 수립(성공), Cisco 라벨
    r = analyze_response(200, {}, "", 0, payload="", category="", url=url, method="CONNECT")
    f = next(f for f in r["findings"] if "CONNECT" in f["name"])
    assert "Cisco" in f["name"] and f["verdict"] == "성공"
    # 405 거부 → 안전
    r2 = analyze_response(405, {}, "Method Not Allowed", 18, payload="", category="", url=url, method="CONNECT")
    assert any("CONNECT" in f["name"] and f["verdict"] == "안전" for f in r2["findings"])


def test_connect_generic_open_proxy():
    r = analyze_response(200, {}, "", 0, payload="", category="", url="https://t/", method="CONNECT")
    assert any("CONNECT" in f["name"] and "프록시" in f["name"] for f in r["findings"])


def test_nonstandard_method_scan_recognized():
    # 임의/비표준 메소드도 최소 '메소드 스캔'으로 인식돼야 함(누락 방지)
    r = analyze_response(200, {}, "ok", 2, payload="", category="", url="https://t/api", method="OPTIONS")
    assert any("메소드 스캔" in f["name"] for f in r["findings"])
    r2 = analyze_response(405, {}, "no", 2, payload="", category="", url="https://t/api", method="PATCH")
    assert any("PATCH 메소드 스캔" in f["name"] and f["verdict"] == "안전" for f in r2["findings"])


def test_get_post_no_method_finding():
    r = analyze_response(200, {}, "hello", 5, payload="", category="", url="https://t/", method="GET")
    assert not any("메소드" in f["name"] for f in r["findings"])
