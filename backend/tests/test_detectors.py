"""탐지기 추상화 + 차분(대조군) 판정 — '판정' 문제 해결.

배경:
    기존 판정은 attack_findings 안 고정 시그니처(~409개)가 전부라, 시그니처 없는 공격과
    '정상 대비 차이로만 드러나는' 공격(블라인드 SQLi·인증우회·IDOR·불리언)은 언제나
    '베이스라인 대비 변화(미확정)'에 묻혔다. 이제 core.detectors 의 차분 탐지기가:
      - 인증 상태 전이(401/403→200) / 실패문구 소멸 → '성공'(확증)
      - 본문 크기 변화·상태 변화·에러 유발 → '의심'(suspicious, 추가 확인)
      - 사소한 차이 → '안전'
    으로 등급화한다. 분류(무슨 공격)를 넓혀도 판정(통했는가)은 증거·차분으로만 하므로
    허위 성공은 늘지 않는다.
"""
import base64
import json

import pytest

from core import detectors as D
from core.detectors import DetectionContext, run_registered, DifferentialDetector
from core.analyzer import analyze_response


def _ctx(**kw):
    kw.setdefault("body_lower", (kw.get("body") or "").lower())
    kw.setdefault("response_time", 50)
    return DetectionContext(**kw)


# ─────────────────────────────────────────────────────────────────────────────
# 추상화 계약
# ─────────────────────────────────────────────────────────────────────────────
def test_registry_has_differential():
    ids = [d.id for d in D.REGISTRY]
    assert "differential" in ids and "jwt_none_alg" in ids


def test_run_registered_survives_broken_detector():
    class Boom(D.Detector):
        id = "boom"; tier = 2
        def applies(self, ctx): return True
        def detect(self, ctx): raise RuntimeError("x")
    D.register(Boom())
    try:
        out = run_registered(_ctx(status_code=200, body="x", payload="p", category="sqli",
                                   baseline={"status_code": 401, "body": "invalid"}))
        assert any(f["verdict"] == "성공" for f in out)   # 나머지 탐지기는 정상 동작
    finally:
        D.REGISTRY[:] = [d for d in D.REGISTRY if d.id != "boom"]


def test_tier_filter():
    """max_tier 로 계층을 제한할 수 있다(tier1 만 돌리기)."""
    ctx = _ctx(status_code=200, body="x", payload="' OR 1=1", category="sqli",
               baseline={"status_code": 401, "body": "invalid password"})
    assert run_registered(ctx, max_tier=1) == []          # differential 은 tier2 → 제외
    assert any(f["verdict"] == "성공" for f in run_registered(ctx, max_tier=2))


# ─────────────────────────────────────────────────────────────────────────────
# 차분 탐지기 — 강/중/약 등급
# ─────────────────────────────────────────────────────────────────────────────
def test_diff_auth_bypass_status_is_success():
    ctx = _ctx(status_code=200, body="welcome", payload="' OR '1'='1", category="sqli",
               baseline={"status_code": 403, "body": "forbidden"})
    out = run_registered(ctx)
    assert out and out[0]["verdict"] == "성공"
    assert "401" in out[0]["evidence"] or "403" in out[0]["evidence"]


def test_diff_fail_message_disappears_is_success():
    ctx = _ctx(status_code=200, body="Dashboard", payload="admin'-- -", category="sqli",
               baseline={"status_code": 200, "body": "Invalid username or password"})
    out = run_registered(ctx)
    assert out and out[0]["verdict"] == "성공"


def test_diff_body_size_delta_is_suspicious():
    ctx = _ctx(status_code=200, body="R" * 3000, payload="1 AND 1=1", category="sqli",
               baseline={"status_code": 200, "body": "none"})
    out = run_registered(ctx)
    assert out and out[0]["verdict"] == "의심"


def test_diff_5xx_error_is_suspicious():
    ctx = _ctx(status_code=500, body="SQL syntax error near ''", payload="'", category="sqli",
               baseline={"status_code": 200, "body": "ok page"})
    out = run_registered(ctx)
    assert out and out[0]["verdict"] == "의심"


def test_diff_no_change_is_safe():
    ctx = _ctx(status_code=200, body="identical", payload="x' OR 1=1", category="sqli",
               baseline={"status_code": 200, "body": "identical"})
    out = run_registered(ctx)
    assert out and out[0]["verdict"] == "안전"


def test_diff_requires_baseline():
    """대조군이 없으면 차분 탐지기는 아무것도 내지 않는다."""
    assert run_registered(_ctx(status_code=200, body="x", payload="' OR 1=1", category="sqli")) == []


def test_diff_requires_attack_intent():
    """공격 시도가 아니면(payload/category/type 모두 없음) 돌지 않는다."""
    ctx = _ctx(status_code=200, body="x", baseline={"status_code": 401, "body": "invalid"})
    assert not any(f["detector_id"] == "differential" for f in run_registered(ctx))


# ─────────────────────────────────────────────────────────────────────────────
# JWT alg=none 탐지기 (tier-1, 요청 구조)
# ─────────────────────────────────────────────────────────────────────────────
def _jwt(alg, sig=""):
    h = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps({"user": "admin"}).encode()).decode().rstrip("=")
    return f"{h}.{p}.{sig}"


def test_jwt_none_alg_flagged_suspicious():
    ctx = _ctx(status_code=200, body="ok", category="jwt",
               req_headers={"authorization": f"Bearer {_jwt('none')}"})
    out = [f for f in run_registered(ctx) if f["detector_id"] == "jwt_none_alg"]
    assert out and out[0]["verdict"] == "의심"


def test_jwt_none_alg_confirmed_by_diff():
    """대조군이 거부(401)인데 alg=none 토큰이 통과(200) → 서명 우회 확증(성공)."""
    ctx = _ctx(status_code=200, body="admin area", category="jwt",
               req_headers={"authorization": f"Bearer {_jwt('none')}"},
               baseline={"status_code": 401, "body": "unauthorized"})
    out = [f for f in run_registered(ctx) if f["detector_id"] == "jwt_none_alg"]
    assert out and out[0]["verdict"] == "성공"


def test_jwt_valid_alg_not_flagged():
    ctx = _ctx(status_code=200, body="ok", category="jwt",
               req_headers={"authorization": f"Bearer {_jwt('HS256', 'abc123sig')}"})
    assert not any(f["detector_id"] == "jwt_none_alg" for f in run_registered(ctx))


def test_no_jwt_no_finding():
    ctx = _ctx(status_code=200, body="ok", category="jwt", req_headers={"authorization": "Bearer notajwt"})
    assert not any(f["detector_id"] == "jwt_none_alg" for f in run_registered(ctx))


# ─────────────────────────────────────────────────────────────────────────────
# analyze_response 통합 — suspicious outcome 신설
# ─────────────────────────────────────────────────────────────────────────────
def test_analyze_auth_bypass_is_success():
    r = analyze_response(200, {"content-type": "text/html"}, "<html>admin dashboard</html>", 60,
                         payload="' OR '1'='1-- -", category="sqli",
                         baseline={"status_code": 401, "body": "Invalid username or password"})
    assert r["attack_outcome"] == "success"
    assert r["risk_level"] in ("high", "critical")


def test_analyze_boolean_is_suspicious():
    r = analyze_response(200, {}, "row " * 800, 60, payload="1 AND 1=1", category="sqli",
                         baseline={"status_code": 200, "body": "no results"})
    assert r["attack_outcome"] == "suspicious"
    assert r["risk_level"] == "medium"
    assert any(f["verdict"] == "의심" for f in r["findings"])


def test_analyze_no_baseline_stays_inconclusive():
    r = analyze_response(200, {}, "<html>page</html>", 60, payload="1 AND 1=1", category="sqli")
    assert r["attack_outcome"] == "inconclusive"


def test_analyze_identical_baseline_is_safe():
    r = analyze_response(200, {}, "same body here", 60, payload="x' OR 1=1", category="sqli",
                         baseline={"status_code": 200, "body": "same body here"})
    assert r["attack_outcome"] == "safe"


def test_suspicious_does_not_upgrade_to_bypass_verdict():
    """의심은 '성공'이 아니다 — verdict=bypass 로 격상하지 않는다(오탐 억제)."""
    r = analyze_response(200, {}, "row " * 800, 60, payload="1 AND 1=1", category="sqli",
                         baseline={"status_code": 200, "body": "x"})
    assert r["verdict"] != "bypass"


def test_det_narrative_has_suspicious_summary():
    r = analyze_response(200, {}, "row " * 800, 60, payload="1 AND 1=1", category="sqli",
                         baseline={"status_code": 200, "body": "x"})
    assert "의심" in r["det_verdict"]["summary"]


# ─────────────────────────────────────────────────────────────────────────────
# Canary(자가 마커) 탐지기 — 대조군 없이 단일 응답으로 표현식 평가 확증
# 7*7=49 하드코딩을 일반화(임의 피연산자의 곱). '49' 우연 일치로 인한 오탐 제거.
# ─────────────────────────────────────────────────────────────────────────────
from core.detectors import CanaryEvalDetector


def _canary(payload, body):
    ctx = _ctx(status_code=200, body=body, payload=payload, category="ssti",
               probe=payload)
    return [f for f in run_registered(ctx) if f["detector_id"] == "canary_eval"]


@pytest.mark.parametrize("payload,body,product", [
    ("{{7*7}}", "result 49 end", "49"),               # Jinja2/Twig
    ("${8*8}", "val=64", "64"),                        # JSP/Spring EL
    ("#{5*5}", "=25=", "25"),                          # Freemarker/JSF
    ("<%= 9*9 %>", "x81y", "81"),                      # ERB/JSP
    ("%{6*6}", "36", "36"),                            # OGNL(Struts)
    ("{{1337*1337}}", "a 1787569 b", "1787569"),       # 자릿수 큰 곱 = 우연 일치 없음
])
def test_canary_eval_confirms_multiple_engines(payload, body, product):
    out = _canary(payload, body)
    assert out and out[0]["verdict"] == "성공"
    assert product in out[0]["evidence"]


def test_canary_rejects_unevaluated_reflection():
    """원문 표현식이 그대로 반사되면(평가 안 됨) 성공이 아니다."""
    assert _canary("{{7*7}}", "you sent {{7*7}} back") == []


def test_canary_rejects_coincidental_number():
    """곱 결과가 응답에 없으면 성공 아님(대형 곱이라 우연 일치 없음)."""
    assert _canary("{{99*99}}", "<html>order 12345</html>") == []      # 9801 없음


def test_canary_result_present_but_literal_too_is_rejected():
    """결과와 원문이 둘 다 있으면 반사일 수 있어 확증하지 않는다."""
    assert _canary("{{7*7}}", "input {{7*7}} output 49") == []


def test_canary_via_request_body_paste():
    """붙여넣기 요청 본문의 표현식도 확증(카테고리 없이)."""
    from core.analyzer import analyze_response
    r = analyze_response(200, {}, "result: 49", 80, payload="", category="",
                         req_body="name={{7*7}}")
    assert r["attack_outcome"] == "success"


def test_canary_no_expression_no_finding():
    assert _canary("just a normal value", "49 appears here") == []


def test_canary_dedups_repeated_expression():
    out = _canary("{{7*7}} and {{7*7}}", "49")
    assert len(out) == 1


def test_canary_is_tier1():
    det = next(d for d in D.REGISTRY if d.id == "canary_eval")
    assert det.tier == 1
    # tier1 만 돌려도 canary 는 동작(대조군 불필요)
    ctx = _ctx(status_code=200, body="49", payload="{{7*7}}", category="ssti", probe="{{7*7}}")
    assert any(f["detector_id"] == "canary_eval" for f in run_registered(ctx, max_tier=1))


# ─────────────────────────────────────────────────────────────────────────────
# 응답 시그니처 탐지기 (tier-1, 대조군 없이 단일 응답 확증) — 고아 카테고리 판정
# ─────────────────────────────────────────────────────────────────────────────
def _find(ctx, det_id):
    return [f for f in run_registered(ctx) if f["detector_id"] == det_id]


# CORS
def test_cors_reflected_origin_with_credentials_is_success():
    ctx = _ctx(status_code=200, body="{}", category="cors",
               headers_lower={"access-control-allow-origin": "https://evil.com",
                              "access-control-allow-credentials": "true"},
               req_headers={"Origin": "https://evil.com"})
    out = _find(ctx, "cors_misconfig")
    assert out and out[0]["verdict"] == "성공"


def test_cors_reflected_without_credentials_is_suspicious():
    ctx = _ctx(status_code=200, body="{}", category="cors",
               headers_lower={"access-control-allow-origin": "https://evil.com"},
               req_headers={"Origin": "https://evil.com"})
    out = _find(ctx, "cors_misconfig")
    assert out and out[0]["verdict"] == "의심"


def test_cors_no_origin_request_not_flagged():
    """요청이 Origin 을 안 보냈으면 판정하지 않는다(정상 동일출처 요청 오탐 방지)."""
    ctx = _ctx(status_code=200, body="{}", category="cors",
               headers_lower={"access-control-allow-origin": "*"}, req_headers={})
    assert _find(ctx, "cors_misconfig") == []


def test_cors_non_reflected_origin_not_success():
    """ACAO 가 요청 Origin 과 다르면(고정 신뢰 출처) 반사가 아니므로 성공 아님."""
    ctx = _ctx(status_code=200, body="{}", category="cors",
               headers_lower={"access-control-allow-origin": "https://trusted.example",
                              "access-control-allow-credentials": "true"},
               req_headers={"Origin": "https://evil.com"})
    assert _find(ctx, "cors_misconfig") == []


# GraphQL
def test_graphql_introspection_exposed_is_success():
    ctx = _ctx(status_code=200, body='{"data":{"__schema":{"types":[{"name":"User"}]}}}',
               category="graphql", url="http://t/graphql", probe="{__schema{types{name}}}")
    out = _find(ctx, "graphql_introspection")
    assert out and out[0]["verdict"] == "성공"


def test_graphql_data_return_is_recon_not_success():
    """스키마는 없지만 data 봉투로 실제 데이터가 오면 '엔드포인트 활성(미확정 recon)' — 성공은 아님."""
    ctx = _ctx(status_code=200, body='{"data":{"user":{"id":1}}}', category="graphql",
               url="http://t/graphql", probe="{user{id}}")
    out = _find(ctx, "graphql_introspection")
    assert out and out[0]["verdict"] == "미확정"
    assert "활성" in out[0]["name"] and out[0]["verdict"] != "성공"


# CRLF
def test_crlf_injected_header_reflected_is_success():
    ctx = _ctx(status_code=200, body="ok", category="crlf",
               payload="val%0d%0aX-Injected: pwned",
               headers_lower={"x-injected": "pwned"})
    out = _find(ctx, "crlf_injection")
    assert out and out[0]["verdict"] == "성공"


def test_crlf_not_reflected_not_flagged():
    ctx = _ctx(status_code=200, body="ok", category="crlf",
               payload="val%0d%0aX-Injected: pwned", headers_lower={})
    assert _find(ctx, "crlf_injection") == []


# LDAP / XPath error-based
def test_ldap_parser_error_is_success():
    ctx = _ctx(status_code=200, body="Error: javax.naming.NameNotFoundException near filter",
               category="ldap", probe=")(uid=*")
    out = _find(ctx, "ldap_xpath_error")
    assert out and out[0]["verdict"] == "성공" and "LDAP" in out[0]["name"]


def test_xpath_parser_error_is_success():
    ctx = _ctx(status_code=200, body="Warning: SimpleXMLElement::xpath(): Invalid expression",
               category="xpath", probe="' or '1'='1")
    out = _find(ctx, "ldap_xpath_error")
    assert out and out[0]["verdict"] == "성공" and "XPath" in out[0]["name"]


def test_ldap_error_without_injection_markers_not_flagged():
    """인젝션다운 특수문자도, 카테고리도 없으면 우연한 에러 문구로 오탐하지 않는다."""
    ctx = _ctx(status_code=200, body="javax.naming.NameNotFoundException", category="",
               probe="normalvalue")
    assert _find(ctx, "ldap_xpath_error") == []


# analyze_response 통합
def test_analyze_cors_success_integration():
    r = analyze_response(200, {"access-control-allow-origin": "https://evil.com",
                               "access-control-allow-credentials": "true"},
                         "{}", 50, category="cors", req_headers={"Origin": "https://evil.com"})
    assert r["attack_outcome"] == "success"
    assert r["risk_level"] in ("high", "critical")


# ─────────────────────────────────────────────────────────────────────────────
# 요청 구조 탐지기 (tier-1) — deserial / upload (JWT 계열: 요청만으로 시도 판정)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("req_body,lang", [
    ("obj=rO0ABXNyABQ", "Java"),
    ('o=O:8:"stdClass":1:{}', "PHP"),
    ("state=AAEAAAD/////AQAAAAAAAAAM", ".NET"),
    ("y=!ruby/object:Gem::Requirement", "Ruby"),
    ("y=!!python/object/apply:os.system", "Python-YAML"),
])
def test_deserial_structure_detected(req_body, lang):
    ctx = _ctx(status_code=200, body="ok", category="deserial", req_body=req_body)
    out = [f for f in run_registered(ctx) if f["detector_id"] == "deserialization"]
    assert out and out[0]["verdict"] == "의심" and lang in out[0]["name"]


def test_deserial_5xx_raises_confidence():
    lo = [f for f in run_registered(_ctx(status_code=200, body="ok", category="deserial",
                                         req_body="rO0AB")) if f["detector_id"] == "deserialization"][0]
    hi = [f for f in run_registered(_ctx(status_code=500, body="err", category="deserial",
                                         req_body="rO0AB")) if f["detector_id"] == "deserialization"][0]
    assert hi["confidence"] > lo["confidence"]


def test_deserial_no_gadget_no_finding():
    ctx = _ctx(status_code=200, body="ok", category="deserial", req_body="user=john&id=5")
    assert not any(f["detector_id"] == "deserialization" for f in run_registered(ctx))


_MP = {"Content-Type": "multipart/form-data; boundary=x"}


@pytest.mark.parametrize("fn,reason", [
    ("shell.php", "위험 실행 확장자"),
    ("a.php.jpg", "이중 확장자"),
    ("x.phtml", "위험 실행 확장자"),
    ("web.jsp", "위험 실행 확장자"),
    ("stored.svg", "SVG/HTML"),
])
def test_upload_dangerous_filename_detected(fn, reason):
    ctx = _ctx(status_code=200, body="ok", category="upload", req_headers=_MP,
               req_body=f'Content-Disposition: form-data; name="f"; filename="{fn}"')
    out = [f for f in run_registered(ctx) if f["detector_id"] == "file_upload"]
    assert out and out[0]["verdict"] == "의심"
    assert reason in out[0]["evidence"]


def test_upload_safe_image_not_flagged():
    ctx = _ctx(status_code=200, body="ok", category="upload", req_headers=_MP,
               req_body='filename="photo.jpg"')
    assert not any(f["detector_id"] == "file_upload" for f in run_registered(ctx))


def test_upload_accepted_2xx_higher_confidence():
    lo = [f for f in run_registered(_ctx(status_code=403, body="no", category="upload",
          req_headers=_MP, req_body='filename="s.php"')) if f["detector_id"] == "file_upload"][0]
    hi = [f for f in run_registered(_ctx(status_code=200, body="ok", category="upload",
          req_headers=_MP, req_body='filename="s.php"')) if f["detector_id"] == "file_upload"][0]
    assert hi["confidence"] > lo["confidence"]


# ─────────────────────────────────────────────────────────────────────────────
# 검증 경로 안내 (OOB/클라이언트) — 판정 불가를 정직하게 라벨(허위 성공 금지)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("cat", ["email", "cache", "csv", "prototype", "domclob", "cssinj"])
def test_verification_route_labels_oob_client(cat):
    ctx = _ctx(status_code=200, body="ok", category=cat, attack_type=cat)
    out = [f for f in run_registered(ctx) if f["detector_id"] == "verification_route"]
    assert out and out[0]["verdict"] == "미확정"
    assert out[0]["method"]                       # 검증 경로가 명시됨


def test_verification_route_never_claims_success():
    for cat in ("email", "cache", "csv", "prototype", "domclob", "cssinj"):
        ctx = _ctx(status_code=200, body="ok", category=cat, attack_type=cat)
        assert all(f["verdict"] != "성공" for f in run_registered(ctx))


def test_verification_route_not_for_judgeable_categories():
    """판정 가능한 카테고리(sqli 등)엔 안내 라벨을 붙이지 않는다."""
    ctx = _ctx(status_code=200, body="ok", category="sqli", attack_type="sqli")
    assert not any(f["detector_id"] == "verification_route" for f in run_registered(ctx))


# analyze_response 통합
def test_analyze_email_shows_route_not_generic_fallback():
    r = analyze_response(200, {}, "Message sent", 50, payload="a@b.com%0aBcc: evil@x.com",
                         category="email")
    assert r["attack_outcome"] == "inconclusive"
    names = [f["name"] for f in r["findings"]]
    assert any("검증 경로" in n for n in names)
    assert not any("자동 판정 불가 — 수동 확인 필요" == n for n in names)   # 구체 안내가 대체


def test_analyze_deserial_is_suspicious():
    r = analyze_response(200, {}, "ok", 50, category="deserial", req_body="obj=rO0ABXNy")
    assert r["attack_outcome"] == "suspicious"


def test_analyze_upload_is_suspicious():
    r = analyze_response(200, {}, "uploaded", 50, category="upload",
                         req_headers={"Content-Type": "multipart/form-data; boundary=x"},
                         req_body='filename="shell.php"')
    assert r["attack_outcome"] == "suspicious"


# ─────────────────────────────────────────────────────────────────────────────
# 307/3xx 인증우회 판정 — Location 을 봐야 한다(로그인/에러 리다이렉트는 우회 아님)
# 307/308 은 메소드·본문 보존(RFC 7538)이라 증거에 표기.
# ─────────────────────────────────────────────────────────────────────────────
from core.detectors import _redirect_is_auth_reject


def _diff(status, location, b_status=401):
    ctx = _ctx(status_code=status, body="", payload="' OR '1'='1", category="sqli",
               headers_lower={"location": location} if location else {},
               baseline={"status_code": b_status, "body": "unauthorized"})
    return [f for f in run_registered(ctx) if f["detector_id"] == "differential"]


def test_auth_reject_helper():
    assert _redirect_is_auth_reject("/login?error=1")
    assert _redirect_is_auth_reject("/sso/authorize")
    assert _redirect_is_auth_reject("https://x/account/login")
    assert _redirect_is_auth_reject("/error")
    assert not _redirect_is_auth_reject("/app/dashboard")
    assert not _redirect_is_auth_reject("")


def test_401_to_login_redirect_is_not_bypass():
    """핵심: 401→302 Location:/login 은 거부-리다이렉트지 우회가 아니다(예전엔 성공 오판)."""
    assert _diff(302, "/login?error=1") == []
    assert _diff(307, "/signin") == []


def test_401_to_resource_redirect_is_bypass():
    """401→302 Location:/dashboard 은 로그인 성공 리다이렉트 → 우회(성공)."""
    out = _diff(302, "/app/dashboard")
    assert out and out[0]["verdict"] == "성공"


def test_307_preserves_method_noted_in_evidence():
    out = _diff(307, "/app/admin")
    assert out and out[0]["verdict"] == "성공"
    assert "307" in out[0]["evidence"]
    assert "메소드" in out[0]["why"]      # 307/308 메소드 보존 명시


def test_401_to_200_direct_bypass_still_success():
    out = _diff(200, "")
    assert out and out[0]["verdict"] == "성공"
    assert "직접 통과" in out[0]["why"]


def test_308_to_login_not_bypass():
    assert _diff(308, "/auth") == []


# JWT 탐지기도 같은 기준(307/308 포함, Location 인지)
def test_jwt_bypass_via_307_to_resource():
    ctx = _ctx(status_code=307, body="admin", category="jwt",
               req_headers={"authorization": f"Bearer {_jwt('none')}"},
               headers_lower={"location": "/admin/panel"},
               baseline={"status_code": 401, "body": "unauthorized"})
    out = [f for f in run_registered(ctx) if f["detector_id"] == "jwt_none_alg"]
    assert out and out[0]["verdict"] == "성공"


def test_jwt_no_bypass_via_login_redirect():
    ctx = _ctx(status_code=302, body="", category="jwt",
               req_headers={"authorization": f"Bearer {_jwt('none')}"},
               headers_lower={"location": "/login"},
               baseline={"status_code": 401, "body": "unauthorized"})
    out = [f for f in run_registered(ctx) if f["detector_id"] == "jwt_none_alg"]
    assert out and out[0]["verdict"] == "의심"     # 성공 아님(로그인 리다이렉트)


# ─────────────────────────────────────────────────────────────────────────────
# 파일 스캔 3xx 응답 — Location 으로 '파일 존재/제공'을 판정(위음성 방지)
# 예전엔 3xx 본문에 파일 내용이 없어 무조건 '미노출(안전)' → CDN/스토리지로 리다이렉트되는
# '존재하는 파일'을 놓쳤다.
# ─────────────────────────────────────────────────────────────────────────────
def _fsr(status, location, path):
    ctx = _ctx(status_code=status, body="", category="cve", payload=path, url="http://t" + path,
               headers_lower={"location": location} if location else {})
    return [f for f in run_registered(ctx) if f["detector_id"] == "filescan_redirect"]


def test_filescan_redirect_to_same_file_is_suspicious():
    """.env → 302 Location:.../.env (CDN) = 파일 존재·제공 → 의심(예전엔 미노출 오판)."""
    out = _fsr(302, "https://cdn.x/backup/.env", "/.env")
    assert out and out[0]["verdict"] == "의심"


def test_filescan_redirect_to_storage_file_is_suspicious():
    out = _fsr(301, "https://storage.x/backup.zip", "/backup.zip")
    assert out and out[0]["verdict"] == "의심"


def test_filescan_trailing_slash_dir_is_suspicious():
    """/.git → 301 /.git/ = 경로(디렉터리) 존재 recon."""
    out = _fsr(301, "/.git/", "/.git")
    assert out and out[0]["verdict"] == "의심"


def test_filescan_redirect_to_login_is_safe():
    """.git/config → 302 /login = 보호됨(우회/노출 아님) → 안전."""
    out = _fsr(302, "/login", "/.git/config")
    assert out and out[0]["verdict"] == "안전"


def test_filescan_redirect_to_home_is_safe():
    out = _fsr(302, "/", "/.env")
    assert out and out[0]["verdict"] == "안전"


def test_filescan_redirect_unrelated_is_inconclusive():
    out = _fsr(302, "/somewhere-else", "/secret.sql")
    assert out and out[0]["verdict"] == "미확정"


def test_filescan_redirect_not_for_normal_paths():
    """파일 스캔이 아닌 일반 경로 리다이렉트엔 안 붙는다."""
    ctx = _ctx(status_code=302, body="", category="", payload="/page", url="http://t/page",
               headers_lower={"location": "/login"})
    assert [f for f in run_registered(ctx) if f["detector_id"] == "filescan_redirect"] == []


def test_filescan_redirect_needs_3xx():
    """200 응답엔 이 탐지기가 관여하지 않는다(본문 내용 판정이 담당)."""
    ctx = _ctx(status_code=200, body="", category="cve", payload="/.env", url="http://t/.env")
    assert [f for f in run_registered(ctx) if f["detector_id"] == "filescan_redirect"] == []


# analyze_response 통합 — 3xx 파일 스캔이 '미노출' 로 조용히 안전해지지 않는다
def test_analyze_env_redirect_to_cdn_is_suspicious():
    r = analyze_response(302, {"location": "https://cdn.x/.env"}, "", 60,
                         payload="/.env", category="cve", url="http://t/.env")
    assert r["attack_outcome"] == "suspicious"
    # 3xx 에선 인라인 '민감 파일 미노출(안전)' 이 붙지 않는다(리다이렉트 탐지기가 판정)
    assert not any("민감 파일 미노출" in f["name"] for f in r["findings"])


def test_analyze_git_config_redirect_to_login_stays_safe():
    r = analyze_response(302, {"location": "/login"}, "", 60,
                         payload="/.git/config", category="cve", url="http://t/.git/config")
    assert r["attack_outcome"] == "safe"


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL introspection — 프로브에 스키마가 안 오면 '영향 없음(안전)'으로 확정
# (404·introspection 차단·미노출). 예전엔 아무것도 안 내고 inconclusive 로 빠졌다.
# ─────────────────────────────────────────────────────────────────────────────
_IQ = '{"query":"query IntrospectionQuery { __schema { queryType { name } types { name } } }"}'


def _gql(status, body, req_body=_IQ, probe="__schema"):
    ctx = _ctx(status_code=status, body=body, category="graphql", url="http://t/graphql",
               req_body=req_body, probe=probe, method="POST")
    return [f for f in run_registered(ctx) if f["detector_id"] == "graphql_introspection"]


def test_graphql_schema_object_is_success():
    out = _gql(200, '{"data":{"__schema":{"types":[{"name":"User"}]}}}')
    assert out and out[0]["verdict"] == "성공"


def test_graphql_schema_null_is_not_success():
    """__schema:null = introspection 비활성 → 성공 아님, 안전."""
    out = _gql(200, '{"data":{"__schema":null}}')
    assert out and out[0]["verdict"] == "안전"


def test_graphql_404_probe_is_safe():
    out = _gql(404, "Not Found")
    assert out and out[0]["verdict"] == "안전"
    assert "404" in out[0]["evidence"]


def test_graphql_introspection_disabled_error_is_safe():
    out = _gql(200, '{"errors":[{"message":"GraphQL introspection is not allowed"}]}')
    assert out and out[0]["verdict"] == "안전"


def test_graphql_generic_error_no_schema_is_safe():
    out = _gql(400, '{"errors":[{"message":"Syntax error"}]}')
    assert out and out[0]["verdict"] == "안전"


def test_graphql_non_introspection_error_not_judged():
    """introspection 프로브가 아니고 데이터도 없으면(에러) 안전/노출 어느 쪽도 판정하지 않는다."""
    out = _gql(400, '{"errors":[{"message":"Syntax error"}]}',
               req_body='{"query":"{user{id}}"}', probe="{user{id}}")
    assert out == []


def test_graphql_empty_response_is_inconclusive():
    """빈 응답은 불명확 → 판정 보류(안전이라 단정하지 않음)."""
    assert _gql(200, "") == []


def test_analyze_graphql_404_outcome_safe():
    r = analyze_response(404, {}, "Not Found", 60, category="graphql", url="http://t/graphql",
                         req_body=_IQ, method="POST")
    assert r["attack_outcome"] == "safe"
    assert not any("자동 판정 불가" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL data 봉투 — 쿼리가 실제 데이터를 반환하면 '엔드포인트 활성(공격 표면 확인)'
# (예시 1: 단일 객체, 예시 2: 배열=다건 나열). __schema 없이도 API 가 쿼리에 응답함을 확인.
# ─────────────────────────────────────────────────────────────────────────────
def test_graphql_data_object_envelope_detected():
    body = '{"data":{"product":{"id":3,"name":"Product 3","listed":true}}}'
    out = _gql(200, body, req_body='{"query":"{product(id:3){id name listed}}"}', probe="{product}")
    assert out and out[0]["verdict"] == "미확정"
    assert "활성" in out[0]["name"]


def test_graphql_data_array_envelope_flags_enumeration():
    body = ('{"data":{"products":[{"id":1,"name":"P1","listed":true},'
            '{"id":2,"name":"P2","listed":true},{"id":4,"name":"P4","listed":true}]}}')
    out = _gql(200, body, req_body='{"query":"{products{id name listed}}"}', probe="{products}")
    assert out and out[0]["verdict"] == "미확정"
    assert "배열" in out[0]["evidence"] or "list" in out[0]["evidence"]


def test_graphql_data_null_is_not_data_return():
    """data:null(빈 결과)은 데이터 반환이 아니다 → 활성 신호 안 냄."""
    out = _gql(200, '{"data":null}', req_body='{"query":"{user{id}}"}', probe="{user{id}}")
    assert out == []


def test_graphql_data_all_null_is_not_data_return():
    out = _gql(200, '{"data":{"user":null}}', req_body='{"query":"{user{id}}"}', probe="{user{id}}")
    assert out == []


def test_graphql_data_envelope_truncated_json():
    """잘린 JSON 도 보수적으로 data 봉투를 인식(필드가 있고 null 아님)."""
    body = '{"data":{"products":[{"id":1,"name":"Product 1","listed":tr'   # 잘림
    out = _gql(200, body, req_body='{"query":"{products{id name}}"}', probe="{products}")
    assert out and out[0]["verdict"] == "미확정"


def test_graphql_schema_beats_data_envelope():
    """__schema 노출이면 데이터 봉투보다 introspection 노출(성공)이 우선."""
    body = '{"data":{"__schema":{"types":[{"name":"User"}]},"products":[{"id":1}]}}'
    out = _gql(200, body, req_body='{"query":"{__schema{types{name}}}"}', probe="__schema")
    assert out and out[0]["verdict"] == "성공"


def test_graphql_data_helper_units():
    from core.detectors import _graphql_returned_data
    assert _graphql_returned_data('{"data":{"x":1}}') == "dict"
    assert _graphql_returned_data('{"data":[{"x":1}]}') == "list"
    assert _graphql_returned_data('{"data":null}') == ""
    assert _graphql_returned_data('{"data":{}}') == ""
    assert _graphql_returned_data('{"errors":[{"message":"x"}]}') == ""
    assert _graphql_returned_data('{"data":{"__schema":null}}') == ""
