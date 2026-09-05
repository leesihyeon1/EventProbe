"""로컬 CVE 매처(cve_matcher.py) 단위 테스트.

전부 로컬 매칭이라 외부로 전송되는 데이터가 없다. 요청 경로/파라미터/응답 지문에
맞는 알려진 익스플로잇을 점수순으로 고르는 로직을 검증한다.

payloads.json 실제 내용에 의존하지 않도록, 테스트용 저장소 dict 를 합성해서 넣는다.
"""
from core.cve_matcher import match_cve_payloads


def _store(*payloads):
    """applies_to 힌트를 가진 페이로드들로 최소 저장소 구조를 만든다."""
    return {"categories": [{"id": "cve", "name": "CVE", "payloads": list(payloads)}]}


def test_path_contains_match():
    data = _store({
        "name": "Struts RCE", "payload": "%{(#a)}", "cve": "CVE-2017-5638",
        "applies_to": {"path_contains": ["/struts", "action"]},
    })
    out = match_cve_payloads(data, path="/app/struts/login.action")
    assert len(out) == 1
    assert out[0]["cve"] == "CVE-2017-5638"
    assert out[0]["source"] == "cve"


def test_no_match_excluded():
    data = _store({
        "name": "Struts RCE", "payload": "%{(#a)}",
        "applies_to": {"path_contains": ["/struts"]},
    })
    out = match_cve_payloads(data, path="/totally/unrelated")
    assert out == []


def test_param_names_alone_does_not_match():
    """정밀도: 파라미터 이름 단독은 매칭 근거로 인정하지 않는다(무관 CVE 대량 출력 방지)."""
    data = _store({
        "name": "param CVE", "payload": "X",
        "applies_to": {"param_names": ["redirect_uri"]},
    })
    out = match_cve_payloads(data, path="/x", params={"redirect_uri": "http://a"})
    assert out == []


def test_generic_path_fragment_excluded():
    """확장자(.do)·짧은(/env)·인코딩(%5c..) 경로 조각은 비특정 → 제외."""
    data = _store(
        {"name": "ext", "payload": "E", "applies_to": {"path_contains": [".do"]}},
        {"name": "short", "payload": "H", "applies_to": {"path_contains": ["/env"]}},
        {"name": "enc", "payload": "C", "applies_to": {"path_contains": ["%5c.."]}},
    )
    out = match_cve_payloads(data, path="/app/order.do/env/%5c..")
    assert out == []


def test_specific_path_still_matches():
    data = _store({"name": "gpon", "payload": "P",
                   "applies_to": {"path_contains": ["/GponForm/diag_Form"]}})
    out = match_cve_payloads(data, path="/x/GponForm/diag_Form")
    assert len(out) == 1 and out[0]["specific"] is True


def test_fingerprint_server_match_scores_higher():
    """서버 지문 매칭(+3)이 경로 매칭(+2)보다 앞 순위로 정렬돼야 한다."""
    data = _store(
        {"name": "by-path", "payload": "P", "applies_to": {"path_contains": ["/api"]}},
        {"name": "by-server", "payload": "S", "applies_to": {"server": ["nginx"]}},
    )
    out = match_cve_payloads(data, path="/api/v1",
                             fingerprint={"server": "nginx/1.18.0"})
    assert out[0]["name"] == "by-server"    # 강한 지문 매칭이 먼저


def test_always_filler_excluded():
    """always 필러는 정밀도를 위해 더 이상 출력하지 않는다(특정 매칭만)."""
    data = _store(
        {"name": "specific", "payload": "S", "applies_to": {"path_contains": ["/adminconsole"]}},
        {"name": "always", "payload": "A", "applies_to": {"always": True}},
    )
    out = match_cve_payloads(data, path="/adminconsole/login")
    names = [c["name"] for c in out]
    assert names == ["specific"]       # 특정 경로만, always 제외


def test_empty_payload_skipped():
    data = _store({"name": "no-payload", "payload": "", "applies_to": {"always": True}})
    assert match_cve_payloads(data, path="/x") == []


def test_dedup_same_location_param_payload():
    dup = {"name": "dup", "payload": "SAME", "location": "path", "param": "q",
           "applies_to": {"path_contains": ["/dupendpoint"]}}
    data = _store(dict(dup), dict(dup))
    out = match_cve_payloads(data, path="/dupendpoint/x")
    assert len(out) == 1


def test_real_bank_matches_gpon_endpoint():
    """실제 payloads.json 에서 /GponForm/diag_Form 이 정확한 CVE 익스플로잇(POST+dest_host)에 매칭."""
    import json
    import os
    p = os.path.join(os.path.dirname(__file__), "..", "data", "payloads.json")
    data = json.load(open(p, encoding="utf-8"))
    out = match_cve_payloads(data, path="/GponForm/diag_Form", limit=8)
    gpon = [c for c in out if "GponForm" in (c.get("payload") or "")]
    assert gpon, "GPON 엔드포인트가 CVE 뱅크에 매칭되어야 한다"
    top = gpon[0]
    assert top["method"] == "POST"
    assert "dest_host" in (top.get("body") or "")
    assert top["cve"].startswith("CVE-2018-1056")


def test_real_bank_curated_cves_present():
    """수동 큐레이션한 유명 CVE 들이 지문에 맞게 매칭되는지."""
    import json
    import os
    p = os.path.join(os.path.dirname(__file__), "..", "data", "payloads.json")
    data = json.load(open(p, encoding="utf-8"))

    nextjs = {c.get("cve") for c in match_cve_payloads(data, path="/dashboard",
                                                       fingerprint={"powered_by": "next.js"}, limit=15)}
    assert "CVE-2025-29927" in nextjs

    iis = {c.get("cve") for c in match_cve_payloads(data, path="/",
                                                    fingerprint={"server": "Microsoft-IIS/8.5"}, limit=15)}
    assert "CVE-2015-1635" in iis

    # PHPUnit eval-stdin — /vendor/phpunit 경로에서 매칭(POST + md5 마커 본문)
    php = [c for c in match_cve_payloads(data, path="/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", limit=20)
           if c.get("cve") == "CVE-2017-9841"]
    assert php and php[0].get("method") == "POST" and "md5" in (php[0].get("body") or "")

    # Shellshock — 여러 헤더 벡터(User-Agent/Referer/Cookie)로 확장됨
    ss = [c for c in match_cve_payloads(data, path="/cgi-bin/test.cgi", limit=30)
          if c.get("cve") == "CVE-2014-6271"]
    params = {c.get("param") for c in ss}
    assert {"User-Agent", "Referer", "Cookie"} <= params


def test_real_bank_matches_nginx_by_fingerprint():
    """실제 뱅크: Server 지문이 nginx 일 때만 nginx 전용 CVE/오설정이 매칭된다."""
    import json
    import os
    p = os.path.join(os.path.dirname(__file__), "..", "data", "payloads.json")
    data = json.load(open(p, encoding="utf-8"))

    with_fp = match_cve_payloads(data, path="/app/file", fingerprint={"server": "nginx/1.13.1"}, limit=15)
    cves = {c.get("cve") for c in with_fp}
    assert "CVE-2017-7529" in cves     # Range 정수 오버플로우
    assert "CVE-2013-4547" in cves     # URI 공백/널 우회
    assert any("alias" in (c.get("name") or "") for c in with_fp)  # off-by-slash 오설정

    without_fp = match_cve_payloads(data, path="/app/file", fingerprint={}, limit=15)
    assert "CVE-2017-7529" not in {c.get("cve") for c in without_fp}  # 지문 없으면 안 뜸


def test_limit_respected():
    payloads = [
        {"name": f"p{i}", "payload": f"v{i}", "applies_to": {"path_contains": ["/vulnpath"]}}
        for i in range(20)
    ]
    data = _store(*payloads)
    out = match_cve_payloads(data, path="/vulnpath/x", limit=5)
    assert len(out) == 5
