"""RAG 스토어 단위 테스트 — 임시 디렉터리에서 텍스트 인제스트/검색/삭제(네트워크 없음)."""
import importlib

import pytest

from core import rag


@pytest.fixture(autouse=True)
def _tmp_rag_dir(tmp_path, monkeypatch):
    # 실제 data/rag 를 건드리지 않도록 임시 디렉터리로 격리
    monkeypatch.setattr(rag, "_RAG_DIR", str(tmp_path / "rag"))
    monkeypatch.setattr(rag, "_embed", lambda texts, input_type: None)
    rag._INDEX["sig"] = None
    rag._VINDEX.update({"sig": None, "mat": None, "chunks": []})
    yield
    rag._INDEX["sig"] = None
    rag._VINDEX.update({"sig": None, "mat": None, "chunks": []})


def test_tokenize_preserves_security_tokens():
    toks = rag._tokenize("Inject into dest_host=;id; and read /etc/passwd via EXTRACTVALUE")
    assert "dest_host" in toks
    assert "etc/passwd" in toks       # 선행 '/' 는 토큰 시작에서 제외(색인·쿼리 일관)
    assert "extractvalue" in toks


def test_chunking_overlap():
    text = "A" * 2000
    chunks = rag._chunk(text, {"loc": ""})
    assert len(chunks) >= 2
    assert all(len(c["text"]) <= rag._CHUNK_SIZE for c in chunks)


def test_bm25_ranks_relevant_doc_first():
    docs = [rag._tokenize("template injection 7*7 jinja2 config"),
            rag._tokenize("sql injection union select from users")]
    bm = rag._BM25(docs)
    top = bm.topk(rag._tokenize("7*7 template"), 2)
    assert top and top[0][1] == 0     # 첫 문서가 최상위


def test_ingest_text_search_delete_roundtrip():
    s1 = rag.ingest_text("GPON", "CVE-2018-10562 dest_host command injection /GponForm/diag_Form")
    s2 = rag.ingest_text("SSTI", "template injection {{7*7}} evaluates to 49 jinja2")
    assert {x["id"] for x in rag.list_sources()} == {s1["id"], s2["id"]}

    hits = rag.search("GponForm dest_host", k=2)
    assert hits and hits[0]["title"] == "GPON"

    assert rag.delete_source(s1["id"]) is True
    assert {x["id"] for x in rag.list_sources()} == {s2["id"]}


def test_search_empty_when_no_sources():
    assert rag.search("anything", k=5) == []


def test_delete_rejects_bad_id():
    assert rag.delete_source("../etc/passwd") is False
    assert rag.delete_source("not_a_valid_id") is False


def test_hybrid_merge_rewards_results_found_by_both_retrievers():
    both = {"source_id": "s1", "loc": "p1", "title": "Both", "text": "shared", "score": .8}
    semantic = [both, {"source_id": "s2", "loc": "", "title": "Dense", "text": "dense", "score": .7}]
    lexical = [{**both, "bm25_score": 4.2},
               {"source_id": "s3", "loc": "", "title": "Lexical", "text": "lexical",
                "score": 1.0, "bm25_score": 3.0}]
    out = rag._hybrid_merge(semantic, lexical, 5)
    assert out[0]["title"] == "Both"
    assert out[0]["retrieval"] == "semantic+bm25"


def test_diversity_deduplicates_and_limits_each_source():
    hits = [
        {"source_id": "large", "text": "same", "score": 1.0},
        {"source_id": "large", "text": "same", "score": .9},
        {"source_id": "large", "text": "another", "score": .8},
        {"source_id": "large", "text": "third", "score": .7},
        {"source_id": "small", "text": "independent", "score": .6},
    ]
    out = rag._select_diverse(hits, 5, max_per_source=2)
    assert [h["text"] for h in out] == ["same", "another", "independent"]


def test_embedding_metadata_invalidates_changed_model(tmp_path, monkeypatch):
    chunks = [{"loc": "", "text": "security guide"}]
    src = {"id": "src_aaaaaaaaaaaa", "chunks": chunks}
    monkeypatch.setattr(rag, "_embed_cfg", lambda: ("key", "base", "model-a"))
    mat = __import__("numpy").ones((1, 4), dtype="float32")
    rag._ensure_dir()
    rag._atomic_save_npy(rag._vec_path(src["id"]), mat)
    src["embedding"] = rag._embedding_meta(chunks, mat)
    assert rag._embedding_state(src) == (True, "current")
    monkeypatch.setattr(rag, "_embed_cfg", lambda: ("key", "base", "model-b"))
    assert rag._embedding_state(src) == (False, "model-changed")


def test_reindex_refreshes_stale_metadata(monkeypatch):
    np = __import__("numpy")
    model = {"name": "model-a"}
    monkeypatch.setattr(rag, "_embed_cfg", lambda: ("key", "base", model["name"]))
    monkeypatch.setattr(rag, "_embed", lambda texts, input_type:
                        np.ones((len(texts), 4), dtype="float32"))
    source = rag.ingest_text("guide", "SQL injection prepared statements")
    assert source["embedded"] is True
    assert rag.list_sources()[0]["embedded"] is True
    model["name"] = "model-b"
    assert rag.list_sources()[0]["embedding_state"] == "model-changed"
    result = rag.reindex_embeddings()
    assert result["embedded"] == 1 and result["failed"] == 0
    refreshed = rag._load_all_sources()[0]
    assert refreshed["embedding"]["model"] == "model-b"
    assert rag._embedding_state(refreshed) == (True, "current")


def test_status_uses_count_names_that_do_not_collide_with_source_list():
    rag.ingest_text("guide", "SQL injection prepared statements")
    state = rag.status()
    assert state["source_count"] == 1
    assert state["chunk_count"] == 1
    assert "sources" not in state and "chunks" not in state


def test_chat_key_alone_does_not_claim_embedding_support(monkeypatch):
    for name in ("EMBEDDING_API_KEY", "EMBEDDING_BASE_URL", "EMBEDDING_MODEL", "NVIDIA_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AI_API_KEY", "chat-only")
    monkeypatch.setenv("AI_BASE_URL", "http://chat.local/v1")
    assert rag._embed_cfg()[0] == ""


def test_explicit_embedding_config_can_reuse_ai_credentials(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.setenv("AI_API_KEY", "shared-key")
    monkeypatch.setenv("AI_BASE_URL", "http://provider.local/v1")
    monkeypatch.setenv("EMBEDDING_MODEL", "embed-model")
    assert rag._embed_cfg() == ("shared-key", "http://provider.local/v1", "embed-model")
