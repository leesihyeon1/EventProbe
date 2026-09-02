"""analyze_response / detect_waf / attack_findings / generate_summary 단위 테스트.

이 도구의 핵심 가치는 '판정의 정확성'이다. 특히 다음 원칙을 회귀로부터 지킨다:

    차단되지 않음(방어장비 미탐) ≠ 대상이 취약함.

증거가 없는 단순 통과(200)를 '취약'으로 격상하지 않고, 실제 성공 증거
(파일 읽기·명령 출력·타이밍 일치·실행 컨텍스트 반사 등)가 있을 때만 격상한다.
"""
from core.analyzer import analyze_response, detect_waf, generate_summary


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


def test_status_400_is_blocked():
    r = analyze_response(400, {}, "Bad Request", 40, payload="x", category="sqli")
    assert r["verdict"] == "blocked"


def test_block_keyword_in_body_marks_blocked():
    r = analyze_response(200, {}, "Request blocked by security policy", 60,
                         payload="x", category="xss")
    assert r["verdict"] == "blocked"


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
# WAF 지문 탐지
# ─────────────────────────────────────────────────────────────────────────────
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
