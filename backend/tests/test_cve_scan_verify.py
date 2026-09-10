"""CVE 스캔 '검증' 단위 테스트 — CVE 는 자기 매처로만 확증한다.

회귀 방지(핵심):
    CVE 는 취약점마다 성공 신호가 전혀 다르다. 예전에는 CVE 전용 매처가 없어
    모든 CVE 를 /etc/passwd(root:x:0:0) 같은 공용 파일읽기 시그니처로 '검증'했고,
    그 결과 `/plugin` 302 · 빈 응답에도 "미확인 + 무관한 확인 시그니처" 가 붙었다.

이제:
  - 응답이 3xx·401/403·404·빈 본문이면 → "CVE 프로브 — 취약 징후 없음(미해당)" (안전)
  - 확증은 오직 그 CVE 항목이 들고 있는 nuclei matcher(status/word/regex) 로만
  - '확인 시그니처(checked)' 에는 무관한 파일읽기 시그니처가 절대 등장하지 않는다

네트워크 요청 없음 — 전부 순수 함수 단위 테스트.
"""
import pytest

from core import analyzer
from core.analyzer import analyze_response

# 무관한 파일읽기 시그니처가 CVE 판정에 새어 나오면 안 된다(회귀 감시 문자열).
_IRRELEVANT = ("root:x:0:0", "uid=0(root)", "개인키", "BEGIN PRIVATE KEY")


def _f(r, stem):
    return [f for f in r["findings"] if stem in f["name"]]


def _all_checked(r):
    return " ".join((f.get("checked") or "") + " " + (f.get("evidence") or "") for f in r["findings"])


def _cve(status, headers=None, body="", payload="/plugin", url="https://t.example.com/plugin"):
    return analyze_response(status, headers or {}, body, 60,
                            payload=payload, category="cve", url=url)


# ─────────────────────────────────────────────────────────────────────────────
# (B) 응답 형태만으로 '미해당' 판정 — 무관한 시그니처로 검증하지 않는다
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("status,headers,body,expect_in_evidence", [
    (302, {"location": "https://t.example.com/login"}, "", "리다이렉트"),
    (301, {"location": "/elsewhere"}, "", "리다이렉트"),
    (401, {}, "Unauthorized", "인증/접근 거부"),
    (403, {}, "Forbidden", "인증/접근 거부"),
    (404, {}, "<html>Not Found</html>", "존재하지 않음"),
    (200, {}, "", "빈 응답 본문"),
    (200, {}, "   \n  ", "빈 응답 본문"),
])
def test_cve_probe_non_applicable(status, headers, body, expect_in_evidence):
    """3xx·401/403·404·빈 본문 → '취약 징후 없음(미해당)' 로 정직하게 판정."""
    r = _cve(status, headers, body)
    na = _f(r, "CVE 프로브 — 취약 징후 없음(미해당)")
    assert na, f"HTTP {status} 는 '미해당' 으로 판정돼야 한다"
    assert na[0]["verdict"] == "안전"
    assert expect_in_evidence in na[0]["evidence"]
    assert r["attack_outcome"] == "safe"
    # '미확인' 으로 남지 않는다
    assert not _f(r, "자동 판정 불가")


@pytest.mark.parametrize("status", [302, 401, 403, 404, 200])
def test_cve_probe_never_reports_irrelevant_file_read_signature(status):
    """핵심 회귀: 어떤 응답에서도 무관한 파일읽기 시그니처를 '확인 시그니처'로 붙이지 않는다."""
    r = _cve(status, {"location": "https://t.example.com/login"} if status == 302 else {}, "")
    blob = _all_checked(r)
    for bad in _IRRELEVANT:
        assert bad not in blob, f"HTTP {status}: 무관한 시그니처 '{bad}' 가 노출됨"


def test_cve_probe_5xx_empty_body_stays_inconclusive():
    """5xx 는 익스플로잇이 서버를 흔든 신호일 수 있다 → 빈 본문이어도 '미해당'으로 단정하지 않는다."""
    for status in (500, 502, 503):
        r = _cve(status, {}, "")
        assert not _f(r, "CVE 프로브 — 취약 징후 없음(미해당)"), f"HTTP {status}"
        assert r["attack_outcome"] != "safe", f"HTTP {status}"


def test_cve_probe_403_is_non_applicable_not_blocked():
    """401/403 은 'WAF 차단' 보다 'CVE 미해당' 이 정확한 서술 → outcome=safe."""
    r = _cve(403, {}, "Forbidden")
    assert r["attack_outcome"] == "safe"
    assert not _f(r, "차단됨")


def test_cve_probe_200_with_body_and_no_matcher_stays_inconclusive():
    """200 + 내용 있는 응답인데 확증 매처가 없으면 '미해당' 이라 단정하지 않는다(미확인 유지)."""
    r = _cve(200, {"content-type": "text/html"}, "<html><body>hello</body></html>")
    assert r["attack_outcome"] == "inconclusive"
    assert not _f(r, "CVE 프로브 — 취약 징후 없음(미해당)")
    unk = _f(r, "자동 판정 불가")
    assert unk, "판정 근거가 없으면 미확인으로 남아야 한다"
    assert "확증 매처 없음" in unk[0]["checked"]     # 정직한 서술
    for bad in _IRRELEVANT:
        assert bad not in unk[0]["checked"]


def test_cve_label_with_traversal_payload_keeps_file_read_semantics():
    """payload 가 트래버설이면(attack_type=lfi) CVE '미해당' 규칙을 적용하지 않는다."""
    r = analyze_response(404, {}, "<html>Not Found</html>", 60,
                         payload="/x?c=../../../../etc/passwd", category="cve")
    assert not _f(r, "CVE 프로브 — 취약 징후 없음(미해당)")


def test_sensitive_file_probe_unaffected():
    """.git/config 같은 민감 파일 프로브(카테고리 cve)는 기존 미노출 판정을 유지한다."""
    r = analyze_response(404, {}, "<html>Not Found</html>", 60,
                         payload="/.git/config", category="cve", url="https://t/.git/config")
    assert any("미노출" in f["name"] for f in r["findings"])


# ─────────────────────────────────────────────────────────────────────────────
# (A)+(B) CVE 자기 매처로 확증 — import_nuclei 가 담아둔 matcher 를 그대로 소비
# ─────────────────────────────────────────────────────────────────────────────
_ENTRY = {
    "id": "nuclei_cve_2024_9999", "cve": "CVE-2024-9999",
    "name": "CVE-2024-9999 ExampleApp 설정 노출",
    "payload": "/exampleapp/config.action",
    "matchers": [
        {"type": "word", "part": "body", "words": ["db_password", "secret_key"], "condition": "and"},
        {"type": "status", "status": [200]},
    ],
    "matchers_condition": "and",
}


@pytest.fixture
def cve_bank(monkeypatch):
    """payloads.json 실제 내용에 의존하지 않도록 CVE 시그니처 캐시를 합성해 주입."""
    def _install(*entries):
        sigs = [s for s in (analyzer._cve_entry_to_sig(e) for e in entries) if s]
        monkeypatch.setattr(analyzer, "_CVE_SIGS", sigs)
        return sigs
    return _install


def test_cve_matcher_confirms_exploit(cve_bank):
    cve_bank(_ENTRY)
    r = analyze_response(200, {}, "DB_PASSWORD=hunter2\nSECRET_KEY=abc\n", 60,
                         payload="/exampleapp/config.action", category="cve",
                         url="https://t/exampleapp/config.action")
    hit = _f(r, "CVE 확증 — CVE-2024-9999")
    assert hit and hit[0]["verdict"] == "성공"
    assert r["attack_outcome"] == "success"
    # 확인 시그니처는 그 CVE 자신의 매처여야 한다
    assert "db_password" in hit[0]["checked"]
    for bad in _IRRELEVANT:
        assert bad not in hit[0]["checked"]


def test_cve_matcher_and_condition_requires_all_words(cve_bank):
    """condition=and — 단어 하나만 있으면 확증하지 않는다(오탐 방지)."""
    cve_bank(_ENTRY)
    r = analyze_response(200, {}, "DB_PASSWORD=hunter2\n", 60,
                         payload="/exampleapp/config.action", category="cve",
                         url="https://t/exampleapp/config.action")
    assert not _f(r, "CVE 확증")
    assert r["attack_outcome"] != "success"


def test_cve_matcher_status_gate_respected(cve_bank):
    """매처가 맞아도 status 매처(200)가 어긋나면 확증하지 않고 '미해당' 으로 간다."""
    cve_bank(_ENTRY)
    r = analyze_response(404, {}, "DB_PASSWORD=hunter2\nSECRET_KEY=abc\n", 60,
                         payload="/exampleapp/config.action", category="cve",
                         url="https://t/exampleapp/config.action")
    assert not _f(r, "CVE 확증")
    assert _f(r, "CVE 프로브 — 취약 징후 없음(미해당)")


def test_cve_matcher_not_applied_to_other_paths(cve_bank):
    """경로가 다르면 그 CVE 매처를 평가하지 않는다(전 CVE 무차별 검증 금지)."""
    cve_bank(_ENTRY)
    r = analyze_response(200, {}, "DB_PASSWORD=hunter2\nSECRET_KEY=abc\n", 60,
                         payload="/unrelated/page", category="cve",
                         url="https://t/unrelated/page")
    assert not _f(r, "CVE 확증")


def test_status_only_matcher_is_not_trusted(cve_bank):
    """상태코드만 있는 매처는 '200=성공' 오탐이라 확증 근거로 쓰지 않는다."""
    sigs = cve_bank({"cve": "CVE-2024-1", "name": "status only", "payload": "/statusonly/path",
                     "matchers": [{"type": "status", "status": [200]}]})
    assert sigs == []
    r = analyze_response(200, {}, "anything at all", 60,
                         payload="/statusonly/path", category="cve", url="https://t/statusonly/path")
    assert not _f(r, "CVE 확증")


def test_regex_matcher_confirms_and_reports_own_signature(cve_bank):
    cve_bank({"cve": "CVE-2024-2", "name": "regex CVE", "payload": "/regexapp/status",
              "matchers": [{"type": "regex", "part": "body", "regex": [r"ver:\s*1\.2\.\d+"]}],
              "matchers_condition": "and"})
    r = analyze_response(200, {}, "ver: 1.2.34", 60,
                         payload="/regexapp/status", category="cve", url="https://t/regexapp/status")
    hit = _f(r, "CVE 확증 — CVE-2024-2")
    assert hit and "정규식" in hit[0]["checked"]
    assert "ver: 1.2.34" in hit[0]["evidence"]


def test_header_part_matcher(cve_bank):
    cve_bank({"cve": "CVE-2024-3", "name": "header CVE", "payload": "/hdrapp/probe",
              "matchers": [{"type": "word", "part": "header", "words": ["x-vulnerable-app"]}],
              "matchers_condition": "and"})
    r = analyze_response(200, {"X-Vulnerable-App": "yes"}, "ok", 60,
                         payload="/hdrapp/probe", category="cve", url="https://t/hdrapp/probe")
    assert _f(r, "CVE 확증 — CVE-2024-3")


def test_broken_regex_does_not_crash(cve_bank):
    """커뮤니티 정규식이 파이썬에서 컴파일 실패해도 분석이 죽지 않는다."""
    cve_bank({"cve": "CVE-2024-4", "name": "bad regex", "payload": "/badregex/path",
              "matchers": [{"type": "regex", "part": "body", "regex": ["(?<bad"]}],
              "matchers_condition": "and"})
    r = analyze_response(200, {}, "whatever", 60,
                         payload="/badregex/path", category="cve", url="https://t/badregex/path")
    assert not _f(r, "CVE 확증")


def test_unsupported_dsl_matcher_with_and_is_skipped(cve_bank):
    """and 조건에 dsl 등 미지원 매처가 섞이면 제약을 무시하게 되므로 확증하지 않는다."""
    cve_bank({"cve": "CVE-2024-5", "name": "dsl CVE", "payload": "/dslapp/path",
              "matchers": [{"type": "word", "part": "body", "words": ["marker"]},
                           {"type": "dsl", "dsl": ["len(body) < 100"]}],
              "matchers_condition": "and"})
    r = analyze_response(200, {}, "marker", 60,
                         payload="/dslapp/path", category="cve", url="https://t/dslapp/path")
    assert not _f(r, "CVE 확증")


def test_checked_desc_lists_own_matchers_when_available(cve_bank):
    """확증 실패(200·내용 있음)여도 '무엇을 확인했는지' 는 그 CVE 자신의 매처로 서술."""
    cve_bank(_ENTRY)
    r = analyze_response(200, {}, "<html>nothing interesting</html>", 60,
                         payload="/exampleapp/config.action", category="cve",
                         url="https://t/exampleapp/config.action")
    unk = _f(r, "자동 판정 불가")
    assert unk
    assert "CVE-2024-9999" in unk[0]["checked"] and "db_password" in unk[0]["checked"]
    for bad in _IRRELEVANT:
        assert bad not in unk[0]["checked"]


def test_real_bank_cve_sigs_are_well_formed():
    """실제 payloads.json 에서 로드한 CVE 시그니처는 항상 내용 매처(word/regex)를 가진다."""
    analyzer._CVE_SIGS = None            # 캐시 초기화 후 실제 파일 로드
    sigs = analyzer._load_cve_sigs()
    analyzer._CVE_SIGS = None
    assert isinstance(sigs, list)
    for s in sigs:
        assert s["path_contains"]
        assert any(m.get("type") in ("word", "regex") for m in s["matchers"])
