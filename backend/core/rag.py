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

import numpy as np

_RAG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "rag")

_TOKEN_RE = re.compile(r"[a-z0-9_][a-z0-9_./:\-]*", re.I)
_CHUNK_SIZE = 900
_CHUNK_OVERLAP = 120


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
    return (os.getenv("NVIDIA_API_KEY", "").strip(),
            os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").strip().rstrip("/"),
            os.getenv("NVIDIA_EMBED_MODEL", "nvidia/nemotron-3-embed-1b").strip())


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
    with open(os.path.join(_RAG_DIR, source_id + ".json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False)
    # 임베딩(가능하면) — 실패해도 문서는 저장됨(BM25 로 동작)
    mat = _embed([c.get("text", "") for c in chunks], "passage")
    if mat is not None and mat.shape[0] == len(chunks):
        np.save(_vec_path(source_id), mat)
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
        out.append({"id": sid, "title": src.get("title", ""),
                    "kind": src.get("kind", ""), "chunks": len(src.get("chunks", [])),
                    "added": src.get("added", ""), "source_ref": src.get("source_ref", ""),
                    "embedded": bool(sid and os.path.isfile(_vec_path(sid)))})
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
    """저장된 .npy 벡터를 모아 의미 검색용 행렬을 구성. 벡터 없는 문서는 제외."""
    sig = _sources_signature()
    if _VINDEX["sig"] == sig and _VINDEX["mat"] is not None:
        return
    mats, chunks = [], []
    for src in _load_all_sources():
        sid = src.get("id")
        vp = _vec_path(sid)
        src_chunks = src.get("chunks", [])
        if not (sid and os.path.isfile(vp) and src_chunks):
            continue
        try:
            m = np.load(vp)
        except Exception:
            continue
        if m.shape[0] != len(src_chunks):
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
    """쿼리로 top-k 청크 검색. 의미 검색 우선, 실패 시 BM25 폴백.
    category 가 주어지면 후보 풀을 넓혀 카테고리 용어로 재정렬(기존 데이터에도 즉시 적용)."""
    if not (query or "").strip():
        return []
    pool = max(k, k * 3) if category else k             # 카테고리 리랭킹용 후보 확대
    sem = _semantic_search(query, pool)
    if sem:
        return _rerank_by_category(sem, category)[:k] if category else sem[:k]
    _ensure_index()
    if not _INDEX["chunks"]:
        return []
    q = _tokenize(query)
    if not q:
        return []
    hits = []
    for score, i in _INDEX["bm25"].topk(q, pool):
        c = _INDEX["chunks"][i]
        hits.append({**c, "score": round(score, 3)})
    return _rerank_by_category(hits, category)[:k] if category else hits[:k]


def reindex_embeddings() -> dict:
    """벡터(.npy)가 없는 기존 문서를 임베딩해 백필. 이미 있으면 건너뜀."""
    if not embeddings_enabled():
        return {"ok": False, "reason": "NVIDIA_API_KEY 미설정 — 임베딩 사용 불가", "embedded": 0}
    done, failed, skipped = 0, 0, 0
    for src in _load_all_sources():
        sid = src.get("id")
        chunks = src.get("chunks", [])
        if not (sid and chunks):
            continue
        if os.path.isfile(_vec_path(sid)):
            skipped += 1
            continue
        mat = _embed([c.get("text", "") for c in chunks], "passage")
        if mat is not None and mat.shape[0] == len(chunks):
            np.save(_vec_path(sid), mat)
            done += 1
        else:
            failed += 1
    _VINDEX["sig"] = None
    return {"ok": failed == 0, "embedded": done, "skipped": skipped, "failed": failed}
