"""Nuclei 임포터 convert() 단위 테스트 — 네트워크/파일 없이 템플릿 dict 만 변환 검증."""
import importlib.util
import json
import os

_spec = importlib.util.spec_from_file_location(
    "import_nuclei",
    os.path.join(os.path.dirname(__file__), "..", "tools", "import_nuclei.py"),
)
import_nuclei = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(import_nuclei)
convert = import_nuclei.convert
convert_matchers = import_nuclei.convert_matchers
convert_exposure = import_nuclei.convert_exposure
backfill_matchers = import_nuclei.backfill_matchers


def test_convert_basic_post_with_body_and_tags():
    tpl = {
        "id": "CVE-2024-9999",
        "info": {"name": "ExampleApp RCE", "severity": "critical",
                 "tags": "cve,rce,wordpress", "reference": ["https://x/adv"]},
        "http": [{"method": "POST",
                  "path": ["{{BaseURL}}/wp-content/plugins/exampleapp/run.php"],
                  "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                  "body": "cmd=id"}],
    }
    e = convert(tpl)
    assert e["cve"] == "CVE-2024-9999"
    assert e["method"] == "POST"
    assert e["payload"] == "/wp-content/plugins/exampleapp/run.php"
    assert e["body"] == "cmd=id"
    assert e["risk"] == "critical"
    assert e["applies_to"].get("powered_by") == ["wordpress"]
    assert e["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


def test_convert_skips_helper_interpolation():
    """{{BaseURL}} 외의 helper 가 남는 경로는 그대로 전송 불가 → 변환 스킵(None)."""
    tpl = {"id": "CVE-2024-1111", "info": {"name": "x", "severity": "high"},
           "http": [{"method": "GET", "path": ["{{BaseURL}}/x?token={{randstr}}"]}]}
    assert convert(tpl) is None


def test_convert_skips_raw_templates():
    tpl = {"id": "CVE-2024-2", "info": {"name": "x", "severity": "high"},
           "http": [{"raw": ["GET / HTTP/1.1"]}]}
    assert convert(tpl) is None


def test_convert_get_default_no_method_field():
    tpl = {"id": "CVE-2024-3", "info": {"name": "Info Disc", "severity": "medium", "tags": "cve,tomcat"},
           "http": [{"method": "GET", "path": ["{{BaseURL}}/manager/status/all"]}]}
    e = convert(tpl)
    assert e["payload"] == "/manager/status/all"
    assert "method" not in e                      # GET 은 method 필드 생략
    assert e["applies_to"].get("server") == ["tomcat"]


def test_convert_supports_legacy_requests_key():
    tpl = {"id": "CVE-2024-4", "info": {"name": "Legacy", "severity": "high"},
           "requests": [{"method": "GET", "path": ["{{BaseURL}}/legacy/path/thing"]}]}
    e = convert(tpl)
    assert e and e["payload"] == "/legacy/path/thing"
# ─────────────────────────────────────────────────────────────────────────────
# 매처 임포트 — CVE 는 자기 매처로만 확증할 수 있어야 한다(공용 파일읽기 시그니처 금지).
# analyzer 의 _eval_matchers 가 이 스키마를 그대로 소비한다.
# ─────────────────────────────────────────────────────────────────────────────
def test_convert_carries_nuclei_matchers():
    tpl = {
        "id": "CVE-2024-5555",
        "info": {"name": "ExampleApp 설정 노출", "severity": "high"},
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/exampleapp/config.action"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "word", "part": "body", "words": ["db_password", "secret_key"],
                 "condition": "and"},
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "header", "regex": ["ExampleApp/1\\.[0-2]"]},
            ],
        }],
    }
    e = convert(tpl)
    assert e["cve"] == "CVE-2024-5555"
    assert e["matchers_condition"] == "and"
    kinds = [m["type"] for m in e["matchers"]]
    assert kinds == ["word", "status", "regex"]
    w, st, rx = e["matchers"]
    assert w["words"] == ["db_password", "secret_key"] and w["condition"] == "and" and w["part"] == "body"
    assert st["status"] == [200]
    assert rx["part"] == "header" and rx["regex"] == ["ExampleApp/1\\.[0-2]"]


def test_convert_without_matchers_omits_fields():
    """매처가 없는 템플릿은 필드를 만들지 않는다(analyzer 가 '확증 매처 없음'으로 정직하게 서술)."""
    tpl = {"id": "CVE-2024-6666", "info": {"name": "x", "severity": "high"},
           "http": [{"method": "GET", "path": ["{{BaseURL}}/nomatcher/path"]}]}
    e = convert(tpl)
    assert "matchers" not in e and "matchers_condition" not in e


def test_convert_matchers_defaults_condition_or_and_and():
    """condition 미지정 → word/regex 는 'or', matchers-condition 미지정 → 'and'(nuclei 기본)."""
    tpl = {"id": "CVE-2024-7777", "info": {"name": "x", "severity": "high"},
           "http": [{"method": "GET", "path": ["{{BaseURL}}/defaults/path"],
                     "matchers": [{"type": "word", "words": ["marker"]}]}]}
    e = convert(tpl)
    assert e["matchers"][0]["condition"] == "or"
    assert e["matchers"][0]["part"] == "body"
    assert e["matchers_condition"] == "and"


def test_convert_matchers_drops_interpolated_and_unsupported():
    """{{helper}} 가 남은 word/regex 와 dsl 등 미지원 타입은 담지 않는다."""
    ms = convert_matchers({"matchers": [
        {"type": "word", "words": ["{{randstr}}", "real_marker"]},
        {"type": "regex", "regex": ["{{interactsh-url}}"]},
        {"type": "dsl", "dsl": ["len(body) < 100"]},
        {"type": "status", "status": [200, "abc"]},
    ]})
    assert [m["type"] for m in ms] == ["word", "status"]
    assert ms[0]["words"] == ["real_marker"]     # 인터폴레이션 단어만 제거
    assert ms[1]["status"] == [200]              # 숫자가 아닌 상태코드는 제외


def test_convert_matchers_caps_list_sizes():
    ms = convert_matchers({"matchers": [
        {"type": "word", "words": [f"w{i}" for i in range(20)]},
        {"type": "regex", "regex": [f"r{i}" for i in range(20)]},
    ]})
    assert len(ms[0]["words"]) == 8 and len(ms[1]["regex"]) == 5


def test_convert_exposure_still_uses_shared_matcher_converter():
    """exposure 임포터도 같은 헬퍼를 쓴다(중복 로직 제거 회귀 방지)."""
    tpl = {"id": "exposed-thing", "info": {"name": "Exposed Thing", "severity": "medium"},
           "http": [{"method": "GET", "path": ["{{BaseURL}}/exposed/thing.json"],
                     "matchers-condition": "and",
                     "matchers": [{"type": "word", "words": ["\"secret\""]},
                                  {"type": "status", "status": [200]}]}]}
    sig = convert_exposure(tpl)
    assert sig["path_contains"] == ["/exposed/thing.json"]
    assert [m["type"] for m in sig["matchers"]] == ["word", "status"]
    assert sig["matchers_condition"] == "and"


def test_converted_entry_is_consumable_by_analyzer():
    """(A)→(B) 연결: convert() 결과를 analyzer 가 그대로 CVE 시그니처로 소비할 수 있어야 한다."""
    from core import analyzer

    tpl = {"id": "CVE-2024-8888", "info": {"name": "Consumable", "severity": "high"},
           "http": [{"method": "GET", "path": ["{{BaseURL}}/consumable/probe"],
                     "matchers-condition": "and",
                     "matchers": [{"type": "word", "words": ["vulnerable_marker"]},
                                  {"type": "status", "status": [200]}]}]}
    entry = convert(tpl)
    sig = analyzer._cve_entry_to_sig(entry)
    assert sig and sig["id"] == "CVE-2024-8888"
    assert sig["path_contains"] == ["/consumable/probe"]

    hdr = ""
    assert analyzer._eval_matchers(sig, "... vulnerable_marker ...", hdr, 200)[0] is True
    assert analyzer._eval_matchers(sig, "... vulnerable_marker ...", hdr, 404)[0] is False
    assert analyzer._eval_matchers(sig, "nothing here", hdr, 200)[0] is False
# ─────────────────────────────────────────────────────────────────────────────
# 매처 백필 — 기존 뱅크(수백 건)는 매처 없이 임포트돼 있어, 중복이라 건너뛰더라도
# 매처를 채워줘야 analyzer 의 CVE 별 확증이 실제로 동작한다.
# ─────────────────────────────────────────────────────────────────────────────
def test_backfill_adds_matchers_to_existing_entry():
    tgt = {"id": "nuclei_cve_2024_1", "cve": "CVE-2024-1", "payload": "/keep/this/path",
           "method": "POST", "body": "keep=me"}
    fresh = {"matchers": [{"type": "word", "words": ["marker"]}], "matchers_condition": "and"}
    assert backfill_matchers(tgt, fresh) is True
    assert tgt["matchers"] == fresh["matchers"] and tgt["matchers_condition"] == "and"
    assert tgt["payload"] == "/keep/this/path" and tgt["body"] == "keep=me"   # 요청 정의 불변


def test_backfill_never_overwrites_existing_matchers():
    tgt = {"matchers": [{"type": "word", "words": ["original"]}], "matchers_condition": "or"}
    fresh = {"matchers": [{"type": "word", "words": ["replacement"]}], "matchers_condition": "and"}
    assert backfill_matchers(tgt, fresh) is False
    assert tgt["matchers"][0]["words"] == ["original"] and tgt["matchers_condition"] == "or"


def test_backfill_noop_when_template_has_no_matchers():
    tgt = {"payload": "/x/y/z"}
    assert backfill_matchers(tgt, {"payload": "/x/y/z"}) is False
    assert "matchers" not in tgt


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_import_run_backfills_and_adds(tmp_path, monkeypatch, capsys):
    """main() 실전 경로: 중복 항목은 매처만 보강, 새 항목은 매처와 함께 추가."""
    import sys

    tdir = tmp_path / "nuclei-templates" / "http" / "cves" / "2024"
    _write(tdir / "existing.yaml", """
id: CVE-2024-1000
info:
  name: Existing App RCE
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/existing/vuln.action"]
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words: ["pwned_marker"]
      - type: status
        status: [200]
""")
    _write(tdir / "brandnew.yaml", """
id: CVE-2024-2000
info:
  name: Brand New Leak
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/brandnew/leak.json"]
    matchers:
      - type: regex
        part: body
        regex: ["api_secret_[a-f0-9]{8}"]
""")

    # 매처 없이 임포트돼 있던 기존 뱅크(현재 payloads.json 상태 재현)
    bank = tmp_path / "payloads.json"
    bank.write_text(json.dumps({"categories": [{"id": "cve", "name": "CVE", "payloads": [
        {"id": "nuclei_cve_2024_1000", "name": "CVE-2024-1000 Existing App RCE",
         "payload": "/existing/vuln.action", "cve": "CVE-2024-1000",
         "location": "path", "param": "", "risk": "high"},
    ]}]}, ensure_ascii=False), encoding="utf-8")

    monkeypatch.setattr(import_nuclei, "_PAYLOADS", str(bank))
    monkeypatch.setattr(sys, "argv",
                        ["import_nuclei.py", str(tmp_path / "nuclei-templates"), "--severity", "high"])
    import_nuclei.main()
    assert "매처 보강: 1" in capsys.readouterr().out

    out = json.loads(bank.read_text(encoding="utf-8"))["categories"][0]["payloads"]
    old = next(p for p in out if p["cve"] == "CVE-2024-1000")
    new = next(p for p in out if p["cve"] == "CVE-2024-2000")
    assert old["matchers"][0]["words"] == ["pwned_marker"]     # 보강됨
    assert old["matchers_condition"] == "and"
    assert old["payload"] == "/existing/vuln.action"           # 요청 정의는 그대로
    assert old["id"] == "nuclei_cve_2024_1000"                 # 중복 추가 아님
    assert new["matchers"][0]["type"] == "regex"
    assert len(out) == 2


def test_import_run_backfilled_entry_is_verifiable_by_analyzer(tmp_path, monkeypatch):
    """(A)→(B) 전체 사슬: 백필된 뱅크를 analyzer 가 로드해 그 CVE 를 확증한다."""
    from core import analyzer

    bank = tmp_path / "payloads.json"
    bank.write_text(json.dumps({"categories": [{"id": "cve", "payloads": [
        {"id": "nuclei_cve_2024_1000", "name": "CVE-2024-1000 Existing App RCE",
         "cve": "CVE-2024-1000", "payload": "/existing/vuln.action",
         "matchers": [{"type": "word", "part": "body", "words": ["pwned_marker"]},
                      {"type": "status", "status": [200]}],
         "matchers_condition": "and"},
    ]}]}, ensure_ascii=False), encoding="utf-8")

    monkeypatch.setattr(analyzer, "_PAYLOADS_PATH", str(bank))
    monkeypatch.setattr(analyzer, "_CVE_SIGS", None)      # 같은 테스트 끝나면 자동 복원
    r = analyzer.analyze_response(200, {}, "... pwned_marker ...", 50,
                                  payload="/existing/vuln.action", category="cve",
                                  url="https://t/existing/vuln.action")
    assert r["attack_outcome"] == "success"
    assert any("CVE 확증 — CVE-2024-1000" in f["name"] for f in r["findings"])
