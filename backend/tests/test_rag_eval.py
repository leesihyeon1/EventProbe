from core.rag_eval import evaluate_cases


def test_recall_and_mrr_are_computed():
    corpus = {
        "one": [{"source_id": "a"}, {"source_id": "b"}],
        "two": [{"source_id": "x"}, {"source_id": "c"}],
        "miss": [{"source_id": "z"}],
    }

    def search(query, k, category=""):
        return corpus[query][:k]

    out = evaluate_cases([
        {"query": "one", "expected_sources": ["a"]},
        {"query": "two", "expected_sources": ["c"]},
        {"query": "miss", "expected_sources": ["none"]},
    ], search, k=2)
    assert out["recall_at_k"] == 0.6667
    assert out["mrr"] == 0.5
    assert [m["id"] for m in out["misses"]] == ["miss"]
