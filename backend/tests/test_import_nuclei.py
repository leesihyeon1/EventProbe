"""Nuclei 임포터 convert() 단위 테스트 — 네트워크/파일 없이 템플릿 dict 만 변환 검증."""
import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "import_nuclei",
    os.path.join(os.path.dirname(__file__), "..", "tools", "import_nuclei.py"),
)
import_nuclei = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(import_nuclei)
convert = import_nuclei.convert


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
