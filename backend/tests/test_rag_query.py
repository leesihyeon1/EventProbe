from routers.api import _rag_body_keys, _rag_safe_terms, build_rag_query


def test_body_keys_extract_json_form_and_xml_without_values():
    assert _rag_body_keys('{"user":{"name":"alice","password":"secret"}}') == [
        "user", "user.name", "user.password"]
    assert _rag_body_keys("dest_host=127.0.0.1&diag_action=ping") == ["dest_host", "diag_action"]
    assert "Envelope" in _rag_body_keys("<Envelope><Token>secret</Token></Envelope>")


def test_query_uses_structure_and_drops_sensitive_values():
    query = build_rag_query(
        "POST", "https://secret.example/api/login?returnUrl=/admin&token=very-secret",
        {"user_id": "42"}, '{"username":"alice","password":"super-secret-value"}',
        {"Authorization": "Bearer hidden", "X-Original-URL": "/admin"},
        "authbypass", "confirm authorization bypass")
    assert "POST" in query and "api" in query and "login" in query
    assert "returnUrl" in query and "token" in query and "user_id" in query
    assert "username" in query and "password" in query and "X-Original-URL" in query
    assert "very-secret" not in query and "super-secret-value" not in query
    assert "Authorization" not in query and "hidden" not in query


def test_safe_terms_drops_long_token_like_values():
    secret = "A" * 40
    assert secret not in _rag_safe_terms(f"sqli union select {secret}")
