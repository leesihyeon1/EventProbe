"""RAG 스토어 단위 테스트 — 임시 디렉터리에서 텍스트 인제스트/검색/삭제(네트워크 없음)."""
import importlib

import pytest

from core import rag


@pytest.fixture(autouse=True)
def _tmp_rag_dir(tmp_path, monkeypatch):
    # 실제 data/rag 를 건드리지 않도록 임시 디렉터리로 격리
    monkeypatch.setattr(rag, "_RAG_DIR", str(tmp_path / "rag"))
    rag._INDEX["sig"] = None
    yield
    rag._INDEX["sig"] = None


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
