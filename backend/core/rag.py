"""로컬 RAG 스토어 — 공개 테스트 문서(PDF/URL/텍스트)를 청킹·BM25 색인해 검색.

무거운 임베딩/벡터DB 없이 순수 파이썬 BM25 로 동작(설계 1단계). 인제스트한 문서는
data/rag/ 에 JSON 으로 영속화하고, 프로세스 시작/변경 시 인메모리 색인을 재구성한다.

검색·색인·저장은 전부 로컬. (검색 결과를 클라우드 LLM 프롬프트에 주입하는 것은 상위
계층의 정책이며, 공개 문서면 유출이 아니다.)
"""
from __future__ import annotations

import glob
import hashlib
import json
import math
import os
import re
import time
from collections import Counter
from typing import Optional

_RAG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "rag")

_TOKEN_RE = re.compile(r"[a-z0-9_][a-z0-9_./:\-]*", re.I)
_CHUNK_SIZE = 900
_CHUNK_OVERLAP = 120


def _ensure_dir():
    os.makedirs(_RAG_DIR, exist_ok=True)


def _tokenize(text: str) -> list:
    # 보안 토큰 보존: /etc/passwd, dest_host, extractvalue, x-forwarded-for 등
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


def _chunk(text: str, base_meta: dict) -> list:
    """텍스트를 겹침 있는 청크로 분할. base_meta 에 loc 만 덧붙인다."""
    text = re.sub(r"[ \t]+", " ", (text or "")).strip()
    if not text:
        return []
    out, i, n = [], 0, len(text)
    while i < n:
        piece = text[i:i + _CHUNK_SIZE]
        out.append({**base_meta, "text": piece})
        if i + _CHUNK_SIZE >= n:
            break
        i += _CHUNK_SIZE - _CHUNK_OVERLAP
    return out


# ── BM25 (순수 파이썬) ────────────────────────────────────────────────────────
class _BM25:
    def __init__(self, docs_tokens: list, k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.docs = docs_tokens
        self.N = len(docs_tokens)
        self.dl = [len(d) for d in docs_tokens]
        self.avgdl = (sum(self.dl) / self.N) if self.N else 0.0
        self.tf = [Counter(d) for d in docs_tokens]
        df = Counter()
        for d in docs_tokens:
            for t in set(d):
                df[t] += 1
        self.idf = {t: math.log(1 + (self.N - n + 0.5) / (n + 0.5)) for t, n in df.items()}

    def score(self, q_tokens: list, i: int) -> float:
        if not self.dl or self.avgdl == 0:
            return 0.0
        tf, dl, s = self.tf[i], self.dl[i], 0.0
        for t in q_tokens:
            f = tf.get(t, 0)
            if not f:
                continue
            idf = self.idf.get(t, 0.0)
            s += idf * (f * (self.k1 + 1)) / (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
        return s

    def topk(self, q_tokens: list, k: int) -> list:
        scored = [(self.score(q_tokens, i), i) for i in range(self.N)]
        scored = [x for x in scored if x[0] > 0]
        scored.sort(reverse=True)
        return scored[:k]


# ── 색인 캐시(변경 시 재구성) ─────────────────────────────────────────────────
_INDEX = {"sig": None, "chunks": [], "bm25": None}


def _sources_signature() -> tuple:
    _ensure_dir()
    files = sorted(glob.glob(os.path.join(_RAG_DIR, "src_*.json")))
    return tuple((f, os.path.getmtime(f)) for f in files)


def _load_all_sources() -> list:
    _ensure_dir()
    out = []
    for f in sorted(glob.glob(os.path.join(_RAG_DIR, "src_*.json"))):
        try:
            out.append(json.load(open(f, encoding="utf-8")))
        except Exception:
            continue
    return out


def _ensure_index():
    sig = _sources_signature()
    if _INDEX["sig"] == sig and _INDEX["bm25"] is not None:
        return
    chunks = []
    for src in _load_all_sources():
        for c in src.get("chunks", []):
            chunks.append({
                "text": c.get("text", ""),
                "source_id": src.get("id"),
                "title": src.get("title", ""),
                "kind": src.get("kind", ""),
                "loc": c.get("loc", ""),
            })
    _INDEX["chunks"] = chunks
    _INDEX["bm25"] = _BM25([_tokenize(c["text"]) for c in chunks])
    _INDEX["sig"] = sig


# ── 텍스트 추출 ───────────────────────────────────────────────────────────────
def _extract_pdf(data: bytes) -> list:
    """PDF 바이트 → [(page_no, text)]. pypdf 우선, 실패 시 pdfplumber."""
    import io
    pages = []
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        for idx, pg in enumerate(reader.pages, 1):
            pages.append((idx, pg.extract_text() or ""))
        if any(t.strip() for _, t in pages):
            return pages
    except Exception:
        pages = []
    try:
        import pdfplumber
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            for idx, pg in enumerate(pdf.pages, 1):
                pages.append((idx, pg.extract_text() or ""))
    except Exception:
        pass
    return pages


def _extract_url(url: str, timeout: float = 15) -> tuple:
    """URL → (title, text). HTML 은 본문 텍스트만 추출."""
    import httpx
    r = httpx.get(url, timeout=timeout, follow_redirects=True,
                  headers={"User-Agent": "Mozilla/5.0 (EventProbe RAG)"})
    ctype = r.headers.get("content-type", "")
    raw = r.content
    if "pdf" in ctype.lower() or url.lower().endswith(".pdf"):
        pages = _extract_pdf(raw)
        return (url.rsplit("/", 1)[-1] or url, "\n".join(t for _, t in pages))
    html = r.text
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript", "svg"]):
            tag.decompose()
        title = (soup.title.string.strip() if soup.title and soup.title.string else url)
        text = soup.get_text("\n")
    except Exception:
        title = url
        text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\n{2,}", "\n", text)
    return (title, text)


# ── 인제스트 / 관리 / 검색 ────────────────────────────────────────────────────
def _new_id(ref: str) -> str:
    return "src_" + hashlib.sha1((ref + str(time.time())).encode()).hexdigest()[:12]


def _save_source(source_id: str, title: str, kind: str, ref: str, chunks: list) -> dict:
    _ensure_dir()
    rec = {"id": source_id, "title": title[:200], "kind": kind, "source_ref": ref[:500],
           "added": time.strftime("%Y-%m-%d %H:%M:%S"), "chunks": chunks}
    with open(os.path.join(_RAG_DIR, source_id + ".json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False)
    _INDEX["sig"] = None   # 다음 검색 때 재색인
    return {"id": source_id, "title": rec["title"], "kind": kind,
            "chunks": len(chunks), "added": rec["added"]}


def ingest_text(title: str, text: str, kind: str = "text", ref: str = "") -> dict:
    sid = _new_id(ref or title)
    chunks = _chunk(text, {"loc": ""})
    if not chunks:
        raise ValueError("텍스트에서 추출된 내용이 없습니다")
    return _save_source(sid, title or "text", kind, ref or title, chunks)


def ingest_pdf(filename: str, data: bytes) -> dict:
    pages = _extract_pdf(data)
    chunks = []
    for pno, ptext in pages:
        chunks.extend(_chunk(ptext, {"loc": f"p.{pno}"}))
    if not chunks:
        raise ValueError("PDF 에서 텍스트를 추출하지 못했습니다(스캔 이미지 PDF 일 수 있음)")
    return _save_source(_new_id(filename), filename or "PDF", "pdf", filename, chunks)


def ingest_url(url: str) -> dict:
    title, text = _extract_url(url)
    chunks = _chunk(text, {"loc": url})
    if not chunks:
        raise ValueError("URL 에서 텍스트를 추출하지 못했습니다")
    return _save_source(_new_id(url), title, "url", url, chunks)


def list_sources() -> list:
    out = []
    for src in _load_all_sources():
        out.append({"id": src.get("id"), "title": src.get("title", ""),
                    "kind": src.get("kind", ""), "chunks": len(src.get("chunks", [])),
                    "added": src.get("added", ""), "source_ref": src.get("source_ref", "")})
    out.sort(key=lambda s: s.get("added", ""), reverse=True)
    return out


def delete_source(source_id: str) -> bool:
    _ensure_dir()
    path = os.path.join(_RAG_DIR, source_id + ".json")
    if os.path.isfile(path) and re.fullmatch(r"src_[0-9a-f]{12}", source_id or ""):
        os.remove(path)
        _INDEX["sig"] = None
        return True
    return False


def has_sources() -> bool:
    return bool(_sources_signature())


def search(query: str, k: int = 6) -> list:
    """쿼리로 top-k 청크 검색. [{text, title, source_id, kind, loc, score}]."""
    _ensure_index()
    if not _INDEX["chunks"]:
        return []
    q = _tokenize(query)
    if not q:
        return []
    hits = []
    for score, i in _INDEX["bm25"].topk(q, k):
        c = _INDEX["chunks"][i]
        hits.append({**c, "score": round(score, 3)})
    return hits
