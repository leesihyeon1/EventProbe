"""테스트 유효성 게이트 단위 테스트 — 거짓음성(안전 오판) 방지 신호."""
from core import test_validity as V
from core.analyzer import analyze_response


def _codes(r):
    return {w["code"] for w in r["warnings"]}


def test_waf_challenge_page_is_block():
    r = V.assess(status_code=403, headers_lower={"cf-ray": "x"},
                 body="Just a moment... checking your browser", url="http://t/x?id=1",
                 payload="' OR 1=1", category="sqli", attack_type="sqli", waf="Cloudflare")
    assert "waf_challenge" in _codes(r) and not r["ok"]


def test_rate_limited_is_block():
    r = V.assess(status_code=429, headers_lower={"retry-after": "30"}, body="",
                 url="http://t/x", payload="x", category="sqli", attack_type="sqli")
    assert "rate_limited" in _codes(r) and not r["ok"]


def test_auth_required_is_block_for_app_attack():
    r = V.assess(status_code=401, headers_lower={"www-authenticate": "Basic"}, body="",
                 url="http://t/api/data?id=1", payload="' OR 1=1", category="sqli", attack_type="sqli")
    assert "auth_required" in _codes(r) and not r["ok"]


def test_auth_wall_redirect_is_block_for_app_attack():
    r = V.assess(status_code=302, headers_lower={"location": "/login?returnUrl=/admin"}, body="",
                 url="http://t/admin/users?id=1", payload="' OR 1=1", category="sqli", attack_type="sqli")
    assert "auth_wall" in _codes(r) and not r["ok"]


def test_resource_probe_401_is_not_block():
    """CVE/파일 프로브의 401·302 는 '미해당=안전'이라 미도달 경고를 내지 않는다."""
    r = V.assess(status_code=401, headers_lower={}, body="Unauthorized",
                 url="http://t/plugin", payload="/plugin", category="cve", attack_type="cve")
    assert "auth_required" not in _codes(r)
    r2 = V.assess(status_code=302, headers_lower={"location": "/login"}, body="",
                  url="http://t/.git/config", payload="/.git/config", category="lfi", attack_type="lfi")
    assert "auth_wall" not in _codes(r2)


def test_payload_not_sent_warn():
    r = V.assess(status_code=200, headers_lower={}, body="normal", url="http://t/search?q=hello",
                 req_body="", payload="<script>alert(31337)</script>", category="xss", attack_type="xss")
    assert "payload_not_sent" in _codes(r)


def test_payload_present_no_warn():
    r = V.assess(status_code=200, headers_lower={}, body="", url="http://t/s?q=alert(31337)",
                 payload="alert(31337)", category="xss", attack_type="xss")
    assert "payload_not_sent" not in _codes(r)


def test_no_baseline_warn_for_authbypass():
    r = V.assess(status_code=200, headers_lower={}, body="ok", url="http://t/login",
                 payload="' OR '1'='1", category="authbypass", attack_type="authbypass", baseline=None)
    assert "no_baseline" in _codes(r)


def test_clean_safe_has_no_warnings():
    r = V.assess(status_code=200, headers_lower={"content-type": "application/json"},
                 body='{"ok":true}', url="http://t/api?id=1", payload="1", category="sqli",
                 attack_type="sqli", baseline={"status_code": 200, "body": "{}"})
    assert r["ok"] and not r["warnings"]


# ── analyze_response 통합: 판정 가드(안전→판정불가 강등) ──────────────────────
def test_analyze_downgrades_safe_to_inconclusive_on_challenge():
    r = analyze_response(200, {}, "Please enable cookies and captcha to continue", 40,
                         payload="' OR 1=1", category="sqli", url="http://t/x?id=1",
                         baseline={"status_code": 200, "body": "ok"})
    assert r["attack_outcome"] == "inconclusive"
    assert any("테스트 유효성" in f["name"] for f in r["findings"])
    assert r["validity"]["warnings"]


def test_analyze_success_not_downgraded():
    """실제 성공 증거가 있으면 유효성 경고로 강등하지 않는다."""
    LF = '<form><input name="u"><input type="password" name="p"></form>'
    LI = '<div>Welcome</div><a href="/logout">Logout</a>' * 40
    r = analyze_response(200, {"content-type": "text/html"}, LI, 120,
                         payload="admin'--", category="sqli",
                         baseline={"status_code": 200, "body": LF},
                         url="http://t/login.aspx", req_body="u=admin'--&p=", method="POST")
    assert r["attack_outcome"] == "success"
