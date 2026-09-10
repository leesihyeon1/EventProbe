"""API 문서/스펙·엔드포인트 식별 노출 → 보안 Alert(run_api_doc_alerts).

Swagger UI·OpenAPI 스펙·GraphiQL·WSDL 등이 노출되면 전체 API 공격 표면이 열거된다.
응답 시그니처(강한 확증) 우선, 없으면 알려진 문서 경로 + 2xx 로 보강. bare /api 는 오탐이
커서 디스커버리 인덱스 마커(_links/routes/endpoints)가 있을 때만.
"""
import pytest

from core.analyzer import run_api_doc_alerts, analyze_response


def _names(url, body, ct="application/json", st=200):
    return [a["name"] for a in run_api_doc_alerts(url, body, {"content-type": ct}, st)]


# 응답 시그니처
@pytest.mark.parametrize("url,body,ct,kind", [
    ("http://t/swagger/index.html", '<title>Swagger UI</title><div id="swagger-ui"></div>', "text/html", "Swagger UI"),
    ("http://t/openapi.json", '{"openapi":"3.0.1","paths":{}}', "application/json", "OpenAPI"),
    ("http://t/v2/api-docs", '{"swagger":"2.0","paths":{}}', "application/json", "OpenAPI"),
    ("http://t/graphiql", '<html>graphiql</html>', "text/html", "GraphiQL"),
    ("http://t/svc?wsdl", '<wsdl:definitions xmlns:wsdl="x">', "text/xml", "WSDL"),
])
def test_api_doc_signature_detected(url, body, ct, kind):
    names = _names(url, body, ct)
    assert names and "API 문서/스펙 노출" in names[0]


# 경로 기반 (사용자 요청분)
@pytest.mark.parametrize("path", [
    "/swagger/index.html", "/openapi.json", "/api/swagger/v1", "/api/swagger",
    "/api-docs", "/v3/api-docs", "/redoc",
])
def test_known_doc_paths_flagged(path):
    names = _names("http://t" + path, '{"x":1}')
    assert names, path


def test_bare_api_with_index_markers():
    assert run_api_doc_alerts("http://t/api", '{"_links":{"u":"/api/users"}}', {}, 200)
    assert run_api_doc_alerts("http://t/api", '{"routes":["/a","/b"]}', {}, 200)


def test_bare_api_with_real_data_not_flagged():
    """/api 가 실제 데이터를 주면(디스커버리 인덱스 아님) 오탐하지 않는다."""
    assert run_api_doc_alerts("http://t/api", '{"data":[{"id":1}]}', {}, 200) == []


def test_normal_page_not_flagged():
    assert run_api_doc_alerts("http://t/home", "<html>welcome</html>", {"content-type": "text/html"}, 200) == []


def test_doc_path_404_not_flagged():
    assert run_api_doc_alerts("http://t/swagger", "<html>Not Found</html>", {}, 404) == []


def test_doc_path_empty_body_not_flagged():
    assert run_api_doc_alerts("http://t/api-docs", "", {}, 200) == []


def test_signature_beats_path_and_dedups():
    """시그니처가 있으면 그것만(경로 기반과 중복 알림 없음)."""
    out = run_api_doc_alerts("http://t/openapi.json", '{"openapi":"3.0.0","paths":{}}', {}, 200)
    assert len(out) == 1 and "노출" in out[0]["name"]


def test_merged_into_analyze_response():
    r = analyze_response(200, {"content-type": "application/json"},
                         '{"openapi":"3.0.1","paths":{"/u":{}}}', 60, url="http://t/openapi.json")
    assert any(a.get("_apidoc") for a in r["alerts"])
