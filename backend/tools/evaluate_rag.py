"""Run the checked-in retrieval golden set without contacting target systems."""
from __future__ import annotations

import argparse
import json
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, BACKEND)

from core import rag
from core.rag_eval import evaluate_cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate EventProbe RAG retrieval")
    parser.add_argument("--golden", default=os.path.join(BACKEND, "data", "rag_golden.json"))
    parser.add_argument("--k", type=int)
    parser.add_argument("--min-recall", type=float)
    args = parser.parse_args()
    with open(args.golden, encoding="utf-8") as f:
        suite = json.load(f)
    k = args.k or int(suite.get("k", 5))
    threshold = args.min_recall if args.min_recall is not None else float(suite.get("minimum_recall_at_k", 0))
    result = evaluate_cases(suite.get("cases", []), rag.search, k)
    result["k"] = k
    result["minimum_recall_at_k"] = threshold
    result["retrieval_status"] = rag.status()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["recall_at_k"] >= threshold else 1


if __name__ == "__main__":
    raise SystemExit(main())
