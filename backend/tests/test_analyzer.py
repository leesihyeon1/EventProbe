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
    assert r["attack_outcome"] == "inconclusive"
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
    assert r["attack_outcome"] == "inconclusive"
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
