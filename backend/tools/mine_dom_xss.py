#!/usr/bin/env python3
"""RAG 코퍼스 → DOM XSS 소스/싱크 시그니처 마이너.

이미 인제스트한 RAG 코퍼스(PortSwigger·WAHH·OWASP 등)에서 DOM XSS 관련 청크를 검색해,
AI 로 '소스(source)'와 '싱크(sink)' 후보를 추출하고, 정규식으로 변환·검증한 뒤
backend/data/dom_xss_signatures.json 에 병합한다. 런타임 판정은 여전히 결정적(추출된 룰 기반).

원칙:
  - RAG/AI 는 '시그니처 소스'로만 사용(오프라인). 런타임 verdict 는 바꾸지 않는다.
  - 추출 후보는 정규식 컴파일·중복·형태 검증을 통과해야 채택. dry-run + git diff 검토 권장.

사용법:
  python backend/tools/mine_dom_xss.py --dry-run
  python backend/tools/mine_dom_xss.py            # 실제 병합
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env"),
            override=True)

import httpx
from core import rag
from core.ai_analyzer import _api_key, _model, _base_url, _timeout, _apply_model_opts, _extract_json

_JSON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "dom_xss_signatures.json")

_QUERIES = [
    "DOM-based XSS sources and sinks",
    "dangerous JavaScript sinks innerHTML document.write eval",
    "DOM XSS sources location.hash location.search document.referrer",
    "jQuery DOM XSS sink html() attr() sink",
    "client-side XSS sink insertAdjacentHTML setTimeout",
]

_SYSTEM = (
    "You extract DOM-based XSS SOURCES and SINKS from security documentation excerpts. "
    "A SOURCE is attacker-controllable client input (e.g., location.hash, document.referrer, window.name). "
    "A SINK is a JS API that turns a string into code/markup (e.g., innerHTML, document.write, eval, setTimeout). "
    "Return ONLY JSON: "
    '{"sources":["location.hash", ...], '
    '"sinks":[{"name":"document.write","kind":"call"},{"name":"innerHTML","kind":"assign"}]}. '
    "kind is 'call' for functions/methods, 'assign' for properties assigned to, 'attr' for HTML attributes. "
    "Only real, well-known DOM XSS sources/sinks. No prose, no explanations, no invented APIs."
)

# 정규식으로 부적합하거나 오탐 큰 토큰 제외
_VALID_NAME = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$")
_BAD_SINK = {"log", "console.log", "text", "val", "value", "onevent", "on", "onx", "handler"}
# 단독으로 쓰면 너무 넓어 오탐되는 소스(구체 속성 없이 이 단어만이면 거부)
_BROAD_SOURCE = {"location", "document", "window", "self", "top", "parent", "event", "this", "name"}


def _norm_token(s: str) -> str:
    """정규식/이름 → 핵심 JS 식별자(소문자, 앵커·이스케이프 제거)."""
    s = re.sub(r"\\s\*|\\b|\\\(|\(\?:.*?\)|[\\(){}\[\]$^*+?=\"'`]", "", s or "")
    s = s.strip(". ").lower()
    return s


def _covered_tokens(store: dict) -> set:
    toks = set()
    for s in store.get("sources", []) + store.get("sinks", []):
        t = _norm_token(s.get("regex", ""))
        if t:
            toks.add(t)
            toks.add(t.split(".")[-1])   # 꼬리 토큰(innerhtml, write 등)도 커버로 간주
    return toks


def _rag_chunks():
    if not rag.has_sources():
        sys.exit("RAG 소스가 없습니다 — 먼저 문서를 인제스트하세요.")
    seen, chunks = set(), []
    for q in _QUERIES:
        for h in rag.search(q, 6, "xss"):
            key = (h.get("title"), h.get("loc"), h.get("text", "")[:60])
            if key in seen:
                continue
            seen.add(key)
            chunks.append(h.get("text", ""))
    return chunks[:20]


def _ask_ai(chunks: list) -> dict:
    key = _api_key()
    if not key:
        sys.exit("AI 미설정(.env NVIDIA_API_KEY) — 마이닝엔 AI 추출이 필요합니다.")
    corpus = "\n---\n".join(re.sub(r"\s+", " ", c)[:600] for c in chunks)[:6000]
    payload = {
        "model": _model(),
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": "EXCERPTS:\n" + corpus + "\n\nExtract sources and sinks as JSON."},
        ],
        "temperature": 0.1, "max_tokens": 1200,
    }
    r = httpx.post(f"{_base_url()}/chat/completions",
                   headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                   json=_apply_model_opts(payload), timeout=_timeout())
    if r.status_code != 200:
        sys.exit(f"AI 오류 {r.status_code}: {r.text[:200]}")
    try:
        return _extract_json(r.json()["choices"][0]["message"]["content"])
    except Exception as e:
        sys.exit(f"AI 응답 파싱 실패: {e}")


def _src_regex(name: str, covered: set) -> str | None:
    if not _VALID_NAME.match(name):
        return None
    low = name.lower()
    # 단독 광범위 토큰(location 등, 구체 속성 없음) 거부 — 오탐 방지
    if "." not in low and low in _BROAD_SOURCE:
        return None
    tok = _norm_token(name)
    if tok in covered or tok.split(".")[-1] in covered:   # 이미 커버된 토큰이면 스킵
        return None
    return re.escape(name)


def _sink_regex(name: str, kind: str, covered: set):
    tail = name.split(".")[-1]
    if name.lower() in _BAD_SINK or tail.lower() in _BAD_SINK or not _VALID_NAME.match(name):
        return None, None
    if _norm_token(name) in covered or tail.lower() in covered:   # 기존 싱크와 토큰 중복 스킵
        return None, None
    if kind == "call":
        return re.escape(name) + r"\s*\(", name + "()"
    if kind == "assign":
        return r"\." + re.escape(tail) + r"\s*=", name
    if kind == "attr":
        return r"(?:\.|\bsetAttribute\([\"']?)" + re.escape(tail) + r"\s*[=\"']", name + "(attr)"
    return None, None


def main():
    ap = argparse.ArgumentParser(description="RAG 코퍼스 → DOM XSS 소스/싱크 마이너")
    ap.add_argument("--dry-run", action="store_true", help="파일 미변경, 후보만 출력")
    args = ap.parse_args()

    store = json.load(open(_JSON, encoding="utf-8")) if os.path.isfile(_JSON) else {"sources": [], "sinks": []}
    have_src = {s.get("regex") for s in store.get("sources", [])}
    have_sink = {s.get("regex") for s in store.get("sinks", [])}
    covered = _covered_tokens(store)   # 토큰 기반 중복 제거용(약한 재중복 방지)

    chunks = _rag_chunks()
    print(f"RAG 청크 {len(chunks)}개로 추출…")
    ai = _ask_ai(chunks)

    new_src, new_sink = [], []
    for name in dict.fromkeys(ai.get("sources", [])):
        rx = _src_regex(str(name).strip(), covered)
        if rx and rx not in have_src:
            have_src.add(rx); covered.add(_norm_token(name)); new_src.append({"regex": rx, "label": name, "source": "rag-mined"})
    for item in ai.get("sinks", []):
        if not isinstance(item, dict):
            continue
        nm = str(item.get("name", "")).strip()
        rx, lbl = _sink_regex(nm, str(item.get("kind", "call")).strip(), covered)
        if rx and rx not in have_sink:
            have_sink.add(rx); covered.add(_norm_token(nm)); new_sink.append({"regex": rx, "label": lbl, "source": "rag-mined"})

    print(f"신규 소스 {len(new_src)} · 신규 싱크 {len(new_sink)} (중복 제외)")
    for s in new_src:
        print(f"  + source  {s['label']:24} /{s['regex']}/")
    for s in new_sink:
        print(f"  + sink    {s['label']:24} /{s['regex']}/")
    if not new_src and not new_sink:
        print("추가할 항목 없음.")
        return
    if args.dry_run:
        print("\n[dry-run] 파일 미변경. 실제 병합하려면 --dry-run 을 빼세요. (병합 후 git diff·pytest 검토)")
        return
    store.setdefault("sources", []).extend(new_src)
    store.setdefault("sinks", []).extend(new_sink)
    with open(_JSON, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"\n병합 완료 → {_JSON}. git diff 로 검토하고 pytest 를 돌리세요.")


if __name__ == "__main__":
    main()
