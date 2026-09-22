from fastapi.testclient import TestClient

from main import app
from routers import api as api_mod


def test_rag_sources_keeps_list_and_status_counts(monkeypatch):
    source = {"id": "src_a", "title": "Guide", "chunks": 3, "embedded": True}
    monkeypatch.setattr(api_mod.rag, "list_sources", lambda: [source])
    monkeypatch.setattr(api_mod.rag, "embeddings_enabled", lambda: True)
    monkeypatch.setattr(api_mod.rag, "has_sources", lambda: True)
    monkeypatch.setattr(api_mod.rag, "status", lambda sources=None: {
        "mode": "hybrid", "source_count": 1, "chunk_count": 3,
        "embedded_sources": 1, "stale_sources": 0,
        "embeddings_configured": True, "embedding_model": "embed-test"})
    monkeypatch.setattr(api_mod, "ai_enabled", lambda: True)
    response = TestClient(app).get("/api/rag/sources")
    assert response.status_code == 200
    body = response.json()
    assert body["sources"] == [source]
    assert body["source_count"] == 1 and body["chunk_count"] == 3
    assert body["mode"] == "hybrid" and body["cloud_context"] is True
