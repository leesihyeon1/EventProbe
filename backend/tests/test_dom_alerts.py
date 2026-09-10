"""DOM 기반 취약점 싱크 → 보안 Alert 탐지(run_dom_alerts).

PortSwigger 분류의 위험 싱크가 응답 스크립트에 있고 오염 가능 소스가 함께 있으면
(source→sink 흐름 가능) 클래스별 Alert 을 낸다. 소스가 없으면 흔한 싱크로 오탐하지 않는다.
"""
import pytest

from core.analyzer import run_dom_alerts, analyze_response


def _classes(body):
    return {a["name"] for a in run_dom_alerts(body)}


def _js(body):
    return f"<html><script>{body}</script></html>"


@pytest.mark.parametrize("sink,vuln", [
    ('document.write("<b>"+location.hash+"</b>")', "DOM XSS"),
    ('eval(window.name)', "JavaScript 주입"),
    ('window.location = document.referrer', "오픈 리디렉션"),
    ('document.cookie = location.search', "쿠키 조작"),
    ('document.domain = location.hash', "문서 도메인 조작"),
    ('new WebSocket(location.hash)', "WebSocket URL 포이즈닝"),
    ('x.postMessage(location.hash, "*")', "웹 메시지 조작"),
    ('xhr.setRequestHeader("X", location.hash)', "Ajax 요청 헤더 조작"),
    ('new FileReader().readAsText(location.hash)', "로컬 파일 경로 조작"),
    ('db.executeSql(location.hash)', "클라이언트측 SQL 인젝션"),
    ('sessionStorage.setItem("k", location.hash)', "HTML5 저장소 조작"),
    ('document.evaluate(location.hash, document, null, 0, null)', "클라이언트측 XPath 주입"),
    ('JSON.parse(localStorage.getItem("k"))', "클라이언트측 JSON 주입"),
    ('el.setAttribute("data-x", location.hash)', "DOM 데이터 조작"),
    ('new RegExp(location.hash)', "서비스 거부(ReDoS)"),
])
def test_each_dom_sink_class_detected(sink, vuln):
    names = _classes(_js(sink))
    assert any(vuln in n for n in names), (vuln, names)


def test_no_source_no_alert():
    """오염 가능 소스가 없으면(정적 값) 흔한 싱크라도 Alert 안 냄."""
    body = _js('var x = JSON.parse(\'{"a":1}\'); el.setAttribute("id","y"); document.write("static");')
    assert run_dom_alerts(body) == []


def test_no_script_no_alert():
    assert run_dom_alerts("<html><body>no script</body></html>") == []


def test_dedup_per_class():
    body = _js('document.write(location.hash); document.write(location.search); el.innerHTML=location.hash;')
    xss = [a for a in run_dom_alerts(body) if "DOM XSS" in a["name"]]
    assert len(xss) == 1


def test_risk_levels():
    body = _js('document.write(location.hash); JSON.parse(location.search);')
    al = {a["name"]: a["risk"] for a in run_dom_alerts(body)}
    assert any("DOM XSS" in n and r == "high" for n, r in al.items())
    assert any("JSON" in n and r == "low" for n, r in al.items())


def test_alerts_merged_into_analyze_response():
    body = _js('document.write("<b>"+location.hash+"</b>"); eval(window.name);')
    r = analyze_response(200, {"content-type": "text/html"}, body, 60, url="http://t/p")
    dom = [a for a in r["alerts"] if a.get("_dom")]
    assert any("DOM XSS" in a["name"] for a in dom)
    assert any("JavaScript 주입" in a["name"] for a in dom)


def test_dom_alert_has_evidence_and_solution():
    body = _js('document.write(location.hash)')
    a = run_dom_alerts(body)[0]
    assert a["evidence"] and a["solution"] and a["reference"]


# ─────────────────────────────────────────────────────────────────────────────
# 확장 싱크(저오탐만 추가) + 제외한 고오탐 싱크 + 비교연산 오탐 방지
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("sink,vuln", [
    ('f.srcdoc = location.hash', "DOM XSS"),
    ('document.execCommand("insertHTML", false, location.hash)', "DOM XSS"),
    ('range.createContextualFragment(location.hash)', "DOM XSS"),
    ('$.globalEval(location.hash)', "JavaScript 주입"),
    ('execScript(location.hash)', "JavaScript 주입"),
    ('setImmediate("x="+location.hash)', "JavaScript 주입"),
    ('window.open(location.hash)', "오픈 리디렉션"),
    ('location.host = location.hash', "오픈 리디렉션"),
    ('fr.readAsArrayBuffer(location.hash)', "로컬 파일 경로 조작"),
    ('form.action = location.hash', "링크 조작"),
    ('$.parseJSON(location.hash)', "클라이언트측 JSON 주입"),
    ('el.evaluate(location.hash)', "클라이언트측 XPath 주입"),
])
def test_extended_lowfp_sinks(sink, vuln):
    names = _classes(_js(sink))
    assert any(vuln in n for n in names), (vuln, names)


@pytest.mark.parametrize("code", [
    'el.value = location.hash',          # 흔한 속성 대입 — 제외
    'el.textContent = location.hash',
    'el.innerText = location.hash',
    'el.name = location.hash',
    'el.type = location.hash',
    'xhr.open("GET", location.hash)',    # 모든 AJAX 에 존재 — 제외
    'xhr.send(location.hash)',
    'document.title = location.hash',
])
def test_high_fp_sinks_excluded(code):
    """정적 정규식으로 정상 코드와 구분 불가한 고오탐 싱크는 Alert 안 냄."""
    assert run_dom_alerts(_js(code)) == []


@pytest.mark.parametrize("code", [
    'if (location.host == "evil.com") {}',
    'if (document.cookie === "x") {}',
    'if (document.domain == "a") {}',
])
def test_comparison_not_flagged_as_assignment(code):
    """비교 연산(==/===)을 대입 싱크로 오탐하지 않는다."""
    assert run_dom_alerts(_js(code)) == []
