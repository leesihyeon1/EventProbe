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


def test_param_names_match():
    data = _store({
        "name": "param CVE", "payload": "X",
        "applies_to": {"param_names": ["redirect_uri"]},
    })
    out = match_cve_payloads(data, path="/x", params={"redirect_uri": "http://a"})
    assert len(out) == 1


def test_fingerprint_server_match_scores_higher():
    """서버 지문 매칭(+3)이 경로 매칭(+2)보다 앞 순위로 정렬돼야 한다."""
    data = _store(
        {"name": "by-path", "payload": "P", "applies_to": {"path_contains": ["/api"]}},
        {"name": "by-server", "payload": "S", "applies_to": {"server": ["nginx"]}},
    )
    out = match_cve_payloads(data, path="/api/v1",
                             fingerprint={"server": "nginx/1.18.0"})
    assert out[0]["name"] == "by-server"    # 강한 지문 매칭이 먼저


def test_always_included_as_weak_after_specific():
    data = _store(
        {"name": "specific", "payload": "S", "applies_to": {"path_contains": ["/x"]}},
        {"name": "always", "payload": "A", "applies_to": {"always": True}},
    )
    out = match_cve_payloads(data, path="/x/y")
    names = [c["name"] for c in out]
    assert names[0] == "specific"      # 특정 매칭 우선
    assert "always" in names           # always 는 뒤에서 채움


def test_empty_payload_skipped():
    data = _store({"name": "no-payload", "payload": "", "applies_to": {"always": True}})
    assert match_cve_payloads(data, path="/x") == []


def test_dedup_same_location_param_payload():
    dup = {"name": "dup", "payload": "SAME", "location": "path", "param": "q",
           "applies_to": {"always": True}}
    data = _store(dict(dup), dict(dup))
    out = match_cve_payloads(data, path="/x")
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


def test_limit_respected():
    payloads = [
        {"name": f"p{i}", "payload": f"v{i}", "applies_to": {"always": True}}
        for i in range(20)
    ]
    data = _store(*payloads)
    out = match_cve_payloads(data, path="/x", limit=5)
    assert len(out) == 5
