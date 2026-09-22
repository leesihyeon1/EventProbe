"""로컬 RAG 스토어 — 문서를 청킹하고 BM25·임베딩을 결합해 검색.

별도 벡터 DB 대신 NumPy 행렬을 사용하고, 인제스트한 문서는 data/rag/ 에 JSON과
.npy로 영속화한다. 임베딩이 없거나 오래되면 BM25만으로 계속 동작한다.

검색·색인·저장은 전부 로컬이다. 검색 결과를 클라우드 LLM 프롬프트에 주입할지는 상위
계층이 결정하며, 내부 문서라면 외부 전송 범위를 별도로 검토해야 한다.
"""
from __future__ import annotations

import glob
import hashlib
import json
import math
import os
import re
import tempfile
import time
from collections import Counter
from typing import Optional

import numpy as np

_RAG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "rag")

_TOKEN_RE = re.compile(r"[a-z0-9_][a-z0-9_./:\-]*", re.I)
_CHUNK_SIZE = 900
_CHUNK_OVERLAP = 120
_CHUNKER_VERSION = 1
_RRF_K = 60


def _ensure_dir():
    os.makedirs(_RAG_DIR, exist_ok=True)


def _tokenize(text: str) -> list:
    # 보안 토큰 보존: /etc/passwd, dest_host, extractvalue, x-forwarded-for 등
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


_HEADING_RE = re.compile(r"^\s{0,3}(?:#{1,6}\s+|={3,}\s*$|-{3,}\s*$)")


def _split_blocks(text: str) -> list:
    """마크다운 헤딩·빈 줄 문단 경계로 블록 분할(구조 인식). 헤딩은 새 블록을 연다."""
    blocks, cur = [], []
    for ln in text.split("\n"):
        if _HEADING_RE.match(ln):
            if cur:
                blocks.append("\n".join(cur)); cur = []
            cur.append(ln)
        elif ln.strip() == "":
            if cur:
                blocks.append("\n".join(cur)); cur = []
        else:
            cur.append(ln)
    if cur:
        blocks.append("\n".join(cur))
    return [b.strip() for b in blocks if b.strip()]


def _chunk(text: str, base_meta: dict) -> list:
    """구조 인식 청킹 — 헤딩/문단 경계를 존중해 개념이 중간에 잘리지 않게 한다.
    블록을 _CHUNK_SIZE 까지 모으고, 한 블록이 너무 크면 문자 단위로 겹침 분할."""
    text = re.sub(r"[ \t]+", " ", (text or "")).strip()
    if not text:
        return []
    blocks = _split_blocks(text)
    out, cur = [], []

    def _flush():
        joined = "\n".join(cur).strip()
        if joined:
            out.append({**base_meta, "text": joined})

    curlen = 0
    for b in blocks:
        if len(b) > _CHUNK_SIZE:                       # 초대형 블록 → 문자 겹침 분할
            _flush(); cur, curlen = [], 0
            i, n = 0, len(b)
            while i < n:
                out.append({**base_meta, "text": b[i:i + _CHUNK_SIZE].strip()})
                if i + _CHUNK_SIZE >= n:
                    break
                i += _CHUNK_SIZE - _CHUNK_OVERLAP
            continue
        if curlen + len(b) + 1 > _CHUNK_SIZE and cur:  # 현재 청크가 다 참 → 비우고 오버랩 유지
            _flush()
            tail = "\n".join(cur)[-_CHUNK_OVERLAP:]
            cur = [tail] if tail.strip() else []
            curlen = len(tail)
        cur.append(b)
        curlen += len(b) + 1
    _flush()
    return [c for c in out if c["text"]]


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


# ── NVIDIA 임베딩(의미 검색) ──────────────────────────────────────────────────
# 검색 정확도를 '키워드'에서 '의미'로 올린다. 이미 쓰는 NVIDIA API 재사용(torch 불필요).
# 실패/미설정 시 조용히 BM25 로 폴백한다.
def _embed_cfg():
    """Provider-neutral embedding configuration with backward-compatible fallbacks."""
    explicit = any(os.getenv(name) for name in
                   ("EMBEDDING_API_KEY", "EMBEDDING_BASE_URL", "EMBEDDING_MODEL"))
    if explicit:
        key = (os.getenv("EMBEDDING_API_KEY") or os.getenv("AI_API_KEY") or
               os.getenv("NVIDIA_API_KEY", "")).strip()
        base = (os.getenv("EMBEDDING_BASE_URL") or os.getenv("AI_BASE_URL") or
                os.getenv("NVIDIA_BASE_URL") or "https://integrate.api.nvidia.com/v1").strip().rstrip("/")
        model = (os.getenv("EMBEDDING_MODEL") or os.getenv("NVIDIA_EMBED_MODEL") or
                 "nvidia/nemotron-3-embed-1b").strip()
    else:
        # A chat-only OpenAI-compatible endpoint may not expose /embeddings. Do not silently
        # treat AI_API_KEY alone as embedding capability; NVIDIA remains the legacy default.
        key = os.getenv("NVIDIA_API_KEY", "").strip()
        base = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").strip().rstrip("/")
        model = os.getenv("NVIDIA_EMBED_MODEL", "nvidia/nemotron-3-embed-1b").strip()
    return key, base, model


def embeddings_enabled() -> bool:
    return bool(_embed_cfg()[0])


# NVIDIA VL 임베더는 텍스트 속 data:/http: 등 스킴 토큰을 이미지 입력으로 오인해
# 503("image inputs require VLM serving")을 낸다. 임베딩 전에만 스킴을 분리한다
# (저장 텍스트·BM25·표시는 원본 유지).
_SCHEME_RE = re.compile(r"(?i)\b(data|https?|ftp|file|blob):")


def _sanitize_for_embed(text: str) -> str:
    return _SCHEME_RE.sub(r"\1 :", text or "")[:2000]


def _embed_batch(base, headers, model, batch, input_type):
    """한 배치 → (행렬 or None, 치명오류 여부). 치명오류(인증/모델없음)면 폴백 중단."""
    import httpx
    payload = {"input": [_sanitize_for_embed(t) for t in batch], "model": model,
               "input_type": input_type, "encoding_format": "float", "truncate": "END"}
    try:
        with httpx.Client(timeout=60) as client:
            r = client.post(f"{base}/embeddings", headers=headers, json=payload)
    except Exception:
        return None, False
    if r.status_code == 200:
        data = sorted(r.json()["data"], key=lambda d: d["index"])
        return np.asarray([d["embedding"] for d in data], dtype="float32"), False
    if r.status_code in (401, 403, 404, 410):   # 키/모델 자체 불가 → 전체 폴백
        return None, True
    return None, False                          # 일시/콘텐츠 오류 → 청크 단위 재시도


def _embed(texts: list, input_type: str) -> Optional["np.ndarray"]:
    """텍스트 목록 → 정규화된 임베딩 행렬(N×D). input_type: 'query'|'passage'.
    배치 실패 시 청크 단위로 재시도하고, 끝내 실패한 청크는 0 벡터(검색에서 자연히 제외).
    임베딩 자체가 불가하면 None → 상위에서 BM25 폴백."""
    key, base, model = _embed_cfg()
    if not key or not texts:
        return None
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    dim, rows = None, [None] * len(texts)
    for i in range(0, len(texts), 50):
        batch = texts[i:i + 50]
        mat, fatal = _embed_batch(base, headers, model, batch, input_type)
        if fatal:
            return None
        if mat is not None:
            dim = mat.shape[1]
            for j in range(len(batch)):
                rows[i + j] = mat[j]
            continue
        for j, t in enumerate(batch):           # 청크 단위 재시도
            single, fatal = _embed_batch(base, headers, model, [t], input_type)
            if fatal:
                return None
            if single is not None:
                dim = single.shape[1]
                rows[i + j] = single[0]
    if dim is None:                             # 단 하나도 성공 못 함
        return None
    arr = np.asarray([(r if r is not None else np.zeros(dim, dtype="float32")) for r in rows],
                     dtype="float32")
    norms = np.linalg.norm(arr, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return arr / norms                          # 정규화 → 코사인 = 내적


def _vec_path(source_id: str) -> str:
    return os.path.join(_RAG_DIR, source_id + ".npy")


def _content_hash(chunks: list) -> str:
    h = hashlib.sha256()
    for chunk in chunks or []:
        h.update(str(chunk.get("loc", "")).encode("utf-8", "ignore"))
        h.update(b"\0")
        h.update(str(chunk.get("text", "")).encode("utf-8", "ignore"))
        h.update(b"\0")
    return h.hexdigest()


def _embedding_meta(chunks: list, mat: "np.ndarray") -> dict:
    return {
        "model": _embed_cfg()[2],
        "dimension": int(mat.shape[1]),
        "chunker_version": _CHUNKER_VERSION,
        "content_hash": _content_hash(chunks),
        "embedded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _manifest_embedding_meta(source_id: str) -> dict:
    """Read metadata for bundled vectors without rewriting large source JSON files."""
    path = os.path.join(_RAG_DIR, "embedding_manifest.json")
    try:
        with open(path, encoding="utf-8") as f:
            manifest = json.load(f)
        source = (manifest.get("sources") or {}).get(source_id) or {}
        if not source:
            return {}
        return {
            "model": manifest.get("model"),
            "dimension": manifest.get("dimension"),
            "chunker_version": manifest.get("chunker_version"),
            "content_hash": source.get("content_hash"),
            "embedded_at": manifest.get("created_at", "bundled"),
        }
    except Exception:
        return {}


def _atomic_save_npy(path: str, mat: "np.ndarray") -> None:
    fd, tmp = tempfile.mkstemp(prefix="rag_vec_", suffix=".npy", dir=os.path.dirname(path))
    os.close(fd)
    try:
        np.save(tmp, mat)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _atomic_save_json(path: str, value: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix="rag_src_", suffix=".json", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _embedding_state(src: dict) -> tuple[bool, str]:
    """Return whether a source vector matches current content, chunker and model."""
    sid, chunks = src.get("id"), src.get("chunks", [])
    path = _vec_path(sid) if sid else ""
    if not path or not os.path.isfile(path):
        return False, "missing"
    meta = src.get("embedding") or _manifest_embedding_meta(sid)
    if not meta:
        return False, "metadata-missing"
    if meta.get("model") != _embed_cfg()[2]:
        return False, "model-changed"
    if meta.get("chunker_version") != _CHUNKER_VERSION:
        return False, "chunker-changed"
    if meta.get("content_hash") != _content_hash(chunks):
        return False, "content-changed"
    try:
        mat = np.load(path, mmap_mode="r")
        if mat.ndim != 2 or mat.shape[0] != len(chunks):
            return False, "shape-mismatch"
        if int(meta.get("dimension") or 0) != int(mat.shape[1]):
            return False, "dimension-mismatch"
    except Exception:
        return False, "unreadable"
    return True, "current"


# ── 색인 캐시(변경 시 재구성) ─────────────────────────────────────────────────
_INDEX = {"sig": None, "chunks": [], "bm25": None}
_VINDEX = {"sig": None, "mat": None, "chunks": []}   # 의미 검색용(임베딩 행렬)


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
    # 임베딩(가능하면) — 실패해도 문서는 저장됨(BM25 로 동작)
    mat = _embed([c.get("text", "") for c in chunks], "passage")
    if mat is not None and mat.shape[0] == len(chunks):
        _atomic_save_npy(_vec_path(source_id), mat)
        rec["embedding"] = _embedding_meta(chunks, mat)
    _atomic_save_json(os.path.join(_RAG_DIR, source_id + ".json"), rec)
    _INDEX["sig"] = None    # 다음 검색 때 재색인
    _VINDEX["sig"] = None
    return {"id": source_id, "title": rec["title"], "kind": kind,
            "chunks": len(chunks), "added": rec["added"],
            "embedded": mat is not None}


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
        sid = src.get("id")
        current, reason = _embedding_state(src)
        out.append({"id": sid, "title": src.get("title", ""),
                    "kind": src.get("kind", ""), "chunks": len(src.get("chunks", [])),
                    "added": src.get("added", ""), "source_ref": src.get("source_ref", ""),
                    "embedded": current, "embedding_state": reason,
                    "embedding_model": ((src.get("embedding") or _manifest_embedding_meta(sid))
                                        .get("model", ""))})
    out.sort(key=lambda s: s.get("added", ""), reverse=True)
    return out


def delete_source(source_id: str) -> bool:
    _ensure_dir()
    path = os.path.join(_RAG_DIR, source_id + ".json")
    if os.path.isfile(path) and re.fullmatch(r"src_[0-9a-f]{12}", source_id or ""):
        os.remove(path)
        vp = _vec_path(source_id)
        if os.path.isfile(vp):
            os.remove(vp)
        _INDEX["sig"] = None
        _VINDEX["sig"] = None
        return True
    return False


def has_sources() -> bool:
    return bool(_sources_signature())


def _ensure_vindex():
    """Build a semantic index only from vectors valid for the current configuration."""
    files = sorted(glob.glob(os.path.join(_RAG_DIR, "src_*.npy")))
    sig = (_sources_signature(), tuple((f, os.path.getmtime(f)) for f in files),
           _embed_cfg()[2], _CHUNKER_VERSION)
    if _VINDEX["sig"] == sig:
        return
    mats, chunks = [], []
    for src in _load_all_sources():
        sid = src.get("id")
        vp = _vec_path(sid)
        src_chunks = src.get("chunks", [])
        current, _ = _embedding_state(src)
        if not (sid and current and src_chunks):
            continue
        try:
            m = np.load(vp)
        except Exception:
            continue
        if m.ndim != 2 or m.shape[0] != len(src_chunks):
            continue
        if mats and m.shape[1] != mats[0].shape[1]:
            continue
        mats.append(m)
        for c in src_chunks:
            chunks.append({"text": c.get("text", ""), "source_id": sid,
                           "title": src.get("title", ""), "kind": src.get("kind", ""),
                           "loc": c.get("loc", "")})
    _VINDEX["mat"] = np.vstack(mats) if mats else None
    _VINDEX["chunks"] = chunks
    _VINDEX["sig"] = sig


def _semantic_search(query: str, k: int) -> Optional[list]:
    """임베딩 기반 코사인 top-k. 임베딩/벡터 없으면 None → BM25 폴백."""
    if not embeddings_enabled():
        return None
    _ensure_vindex()
    if _VINDEX["mat"] is None or not _VINDEX["chunks"]:
        return None
    qm = _embed([query], "query")
    if qm is None:
        return None
    sims = _VINDEX["mat"] @ qm[0]                       # 정규화돼 있어 내적=코사인
    order = np.argsort(-sims)[:k]
    return [{**_VINDEX["chunks"][int(i)], "score": round(float(sims[int(i)]), 3)}
            for i in order if sims[int(i)] > 0]


def _bm25_search(query: str, k: int) -> list:
    _ensure_index()
    if not _INDEX["chunks"]:
        return []
    q = _tokenize(query)
    if not q:
        return []
    ranked = _INDEX["bm25"].topk(q, k)
    if not ranked:
        return []
    peak = ranked[0][0] or 1.0
    return [{**_INDEX["chunks"][i], "score": round(float(raw / peak), 3),
             "bm25_score": round(float(raw), 3)} for raw, i in ranked]


def _hit_key(hit: dict) -> tuple:
    return (hit.get("source_id"), hit.get("loc"),
            hashlib.sha1(str(hit.get("text", "")).encode("utf-8", "ignore")).hexdigest())


def _hybrid_merge(semantic: list, lexical: list, k: int) -> list:
    """Combine dense and lexical ranks using normalized reciprocal-rank fusion."""
    merged: dict[tuple, dict] = {}
    denom = 2.0 / (_RRF_K + 1)
    for label, hits in (("semantic", semantic or []), ("bm25", lexical or [])):
        for rank, hit in enumerate(hits, 1):
            key = _hit_key(hit)
            row = merged.setdefault(key, {**hit, "_rrf": 0.0, "retrieval": []})
            row["_rrf"] += 1.0 / (_RRF_K + rank)
            row["retrieval"].append(label)
            if label == "semantic":
                row["semantic_score"] = hit.get("score")
            else:
                row["bm25_score"] = hit.get("bm25_score")
    out = []
    for row in merged.values():
        row["score"] = round(min(1.0, row.pop("_rrf") / denom), 3)
        row["retrieval"] = "+".join(row["retrieval"])
        out.append(row)
    out.sort(key=lambda h: h.get("score", 0), reverse=True)
    return out[:k]


def _select_diverse(hits: list, k: int, max_per_source: int = 2) -> list:
    """Remove duplicate chunks and keep one large source from monopolizing results."""
    selected, per_source, seen_text = [], Counter(), set()
    for hit in hits:
        normalized = re.sub(r"\W+", " ", str(hit.get("text", "")).lower()).strip()
        fingerprint = hashlib.sha1(normalized.encode("utf-8", "ignore")).hexdigest()
        source = hit.get("source_id") or hit.get("title") or "unknown"
        if fingerprint in seen_text or per_source[source] >= max_per_source:
            continue
        selected.append(hit)
        seen_text.add(fingerprint)
        per_source[source] += 1
        if len(selected) >= k:
            break
    return selected


# 공격 카테고리 → 문서에서 그 주제를 가리키는 용어(리랭킹 부스트용).
_CATEGORY_TERMS = {
    "sqli":     ["sql injection", "sqli", "union select", "blind sql", "sqlmap", "boolean-based", "error-based"],
    "xss":      ["cross-site scripting", "xss", "dom xss", "reflected", "stored xss", "csp", "innerhtml"],
    "ssrf":     ["ssrf", "server-side request forgery", "metadata", "169.254", "internal request", "url parser"],
    "lfi":      ["local file inclusion", "lfi", "path traversal", "directory traversal", "/etc/passwd", "file read"],
    "xxe":      ["xxe", "xml external entity", "external entity", "doctype", "system \""],
    "cmdi":     ["command injection", "os command", "rce", "remote code execution", "shell", "; id"],
    "ssti":     ["template injection", "ssti", "server-side template", "jinja", "twig", "{{7*7}}"],
    "redirect": ["open redirect", "redirect", "location header", "//evil"],
    "jwt":      ["jwt", "json web token", "algorithm confusion", "alg none", "kid", "signature"],
    "idor":     ["idor", "access control", "authorization", "insecure direct object", "broken access", "privilege"],
    "nosql":    ["nosql", "mongodb", "nosql injection", "$where", "$ne"],
    "xmlrpc":   ["xml-rpc", "xmlrpc", "pingback", "system.multicall", "wordpress"],
    "csrf":     ["csrf", "cross-site request forgery", "samesite", "csrf token"],
    "auth":     ["authentication", "brute force", "credential", "session", "login", "mfa", "2fa"],
    "redos":    ["redos", "regular expression denial", "catastrophic backtracking"],
    "deserial": ["deserialization", "insecure deserialization", "pickle", "gadget"],
}


def _rerank_by_category(hits: list, category: str) -> list:
    """의미검색 후보를 공격 카테고리 용어 매칭으로 소폭 가산해 재정렬(관련도 우선 유지)."""
    terms = _CATEGORY_TERMS.get((category or "").lower())
    if not terms:
        return hits
    for h in hits:
        blob = (str(h.get("text", "")) + " " + str(h.get("loc", "")) + " " + str(h.get("title", ""))).lower()
        matched = sum(1 for t in terms if t in blob)
        boost = min(0.15, 0.04 * matched)              # 최대 +0.15 (의미점수 왜곡 최소화)
        if boost:
            h["score"] = round(float(h.get("score", 0)) + boost, 3)
            h["cat_boost"] = boost
    hits.sort(key=lambda x: x.get("score", 0), reverse=True)
    return hits


def search(query: str, k: int = 6, category: str = "") -> list:
    """Hybrid dense+BM25 retrieval with category and source-diversity reranking."""
    if not (query or "").strip():
        return []
    pool = max(k * 5, 20)
    sem = _semantic_search(query, pool) or []
    lexical = _bm25_search(query, pool)
    if sem and lexical:
        hits = _hybrid_merge(sem, lexical, pool * 2)
    elif sem:
        hits = [{**h, "retrieval": "semantic"} for h in sem]
    else:
        hits = [{**h, "retrieval": "bm25"} for h in lexical]
    if category:
        hits = _rerank_by_category(hits, category)
    return _select_diverse(hits, k)


def reindex_embeddings(force: bool = False) -> dict:
    """Create or refresh vectors whose model/content/chunker metadata is stale."""
    if not embeddings_enabled():
        return {"ok": False, "reason": "임베딩 API 키 미설정 — EMBEDDING_API_KEY/AI_API_KEY/NVIDIA_API_KEY 확인", "embedded": 0}
    done, failed, skipped = 0, 0, 0
    for src in _load_all_sources():
        sid = src.get("id")
        chunks = src.get("chunks", [])
        if not (sid and chunks):
            continue
        current, _ = _embedding_state(src)
        if current and not force:
            skipped += 1
            continue
        mat = _embed([c.get("text", "") for c in chunks], "passage")
        if mat is not None and mat.shape[0] == len(chunks):
            _atomic_save_npy(_vec_path(sid), mat)
            src["embedding"] = _embedding_meta(chunks, mat)
            _atomic_save_json(os.path.join(_RAG_DIR, sid + ".json"), src)
            done += 1
        else:
            failed += 1
    _VINDEX["sig"] = None
    return {"ok": failed == 0, "embedded": done, "skipped": skipped, "failed": failed}


def status(sources: list | None = None) -> dict:
    sources = list_sources() if sources is None else sources
    current = sum(1 for src in sources if src.get("embedded"))
    stale = len(sources) - current
    if embeddings_enabled() and current:
        mode = "hybrid"
    else:
        mode = "bm25"
    return {
        "mode": mode,
        "embeddings_configured": embeddings_enabled(),
        "embedding_model": _embed_cfg()[2] if embeddings_enabled() else "",
        "source_count": len(sources),
        "chunk_count": sum(src.get("chunks", 0) for src in sources),
        "embedded_sources": current,
        "stale_sources": stale,
    }
