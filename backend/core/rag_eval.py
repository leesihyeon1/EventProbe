"""Offline retrieval evaluation helpers for the EventProbe RAG corpus."""
from __future__ import annotations


def evaluate_cases(cases: list[dict], search_fn, k: int = 5) -> dict:
    rows, reciprocal_sum, hits = [], 0.0, 0
    for case in cases:
        results = search_fn(case["query"], k, case.get("category", "")) or []
        expected = set(case.get("expected_sources") or [])
        rank = next((i for i, hit in enumerate(results, 1)
                     if hit.get("source_id") in expected), None)
        if rank:
            hits += 1
            reciprocal_sum += 1.0 / rank
        rows.append({
            "id": case.get("id", case["query"][:40]),
            "rank": rank,
            "returned_sources": [hit.get("source_id") for hit in results],
        })
    total = len(cases)
    return {
        "cases": total,
        "recall_at_k": round(hits / total, 4) if total else 0.0,
        "mrr": round(reciprocal_sum / total, 4) if total else 0.0,
        "misses": [row for row in rows if row["rank"] is None],
        "results": rows,
    }
