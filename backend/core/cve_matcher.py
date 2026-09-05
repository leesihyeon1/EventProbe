"""
로컬 CVE/알려진취약점 페이로드 매처 (무유출).

페이로드 저장소(payloads.json 및 사용자 커스텀)에서 `applies_to` 지문 힌트를 가진
항목을 찾아, 현재 요청(경로/파라미터)과 — 있으면 — 직전 응답의 기술스택 지문에
맞는 알려진 익스플로잇을 골라 AI 페이로드 후보에 병합한다.

전부 로컬 매칭이라 외부(클라우드)로 전송되는 데이터가 없다.

applies_to 스키마(모두 선택):
  path_contains : [str]  요청 path 에 부분일치하면 매칭(강)
  param_names   : [str]  해당 이름의 쿼리/바디 파라미터가 있으면 매칭(강)
  server        : [str]  응답 Server 헤더에 부분일치(지문 있을 때, 강)
  powered_by    : [str]  응답 X-Powered-By/기술 라벨에 부분일치(지문 있을 때, 강)
  body_keywords : [str]  응답 본문 키워드(지문 있을 때, 약)
  always        : bool   항상 후보에 포함(약 — 특정 매칭 뒤에 채움)
"""
import re
from typing import Optional


def _any_in(needles, haystack: str) -> bool:
    return any(n.lower() in haystack for n in (needles or []))


def _is_specific_path(needle: str) -> bool:
    """경로 조각이 '특정 자산/엔드포인트'를 가리킬 만큼 구체적인가.
    파일 확장자(.do·.sh·.cgi), 너무 짧은 조각(/env·/rpc), 인코딩 조각(%5c..·.%2e)은
    아무 URL 에나 부분일치하므로 비특정으로 본다(오탐의 주원인)."""
    n = (needle or "").strip().lower()
    if len(n) < 5:
        return False
    if re.fullmatch(r"[.%][a-z0-9]{1,4}\.?", n):      # .do .sh .cgi .%2e %5c 등
        return False
    if "%" in n and "/" not in n:                      # 순수 인코딩 조각(%5c.. 등)
        return False
    return ("/" in n) or (len(n) >= 8)                 # 경로형이거나 충분히 고유한 토큰


def _entries_with_hints(payloads_data: dict):
    """저장소 전체에서 applies_to(또는 cve) 를 가진 페이로드 항목을 순회."""
    for cat in payloads_data.get("categories", []):
        for p in cat.get("payloads", []):
            if isinstance(p, dict) and (p.get("applies_to") or p.get("cve")):
                yield cat, p


def match_cve_payloads(payloads_data: dict, path: str, params: Optional[dict] = None,
                       body: str = "", fingerprint: Optional[dict] = None,
                       limit: int = 8) -> list:
    """요청/지문에 맞는 CVE 페이로드 후보 목록을 점수순으로 반환."""
    path_lc = (path or "").lower()
    param_keys = {str(k).lower() for k in (params or {}).keys()}
    fp = fingerprint or {}
    fp_server = str(fp.get("server", "")).lower()
    fp_powered = str(fp.get("powered_by", "")).lower()
    fp_body = str(fp.get("body", "")).lower()

    strong = []
    for cat, p in _entries_with_hints(payloads_data):
        ap = p.get("applies_to") or {}
        score = 0
        fp_hit = False       # 지문(자산 식별) 일치
        path_hit = False     # '특정' 경로 일치

        # 1) 지문 — 응답 스택으로 자산을 정확히 식별했을 때(강)
        if fp_server and ap.get("server") and _any_in(ap["server"], fp_server):
            score += 3; fp_hit = True
        if fp_powered and ap.get("powered_by") and _any_in(ap["powered_by"], fp_powered):
            score += 3; fp_hit = True
        if fp_body and ap.get("body_keywords") and _any_in(ap["body_keywords"], fp_body):
            score += 1; fp_hit = True

        # 2) 경로 — '특정' 경로가 URL 에 일치할 때만(확장자·짧은·인코딩 조각 제외)
        for needle in (ap.get("path_contains") or []):
            if needle and needle.lower() in path_lc and _is_specific_path(needle):
                score += 2; path_hit = True
                break

        # 파라미터 이름 단독·always 필러는 정밀도를 위해 매칭 근거로 인정하지 않는다.
        # 지문 또는 특정 경로가 맞아야만 후보로 채택(무관한 CVE 대량 출력 방지).
        if not (fp_hit or path_hit):
            continue

        cand = {
            "category": "cve",
            "location": p.get("location", "path"),
            "param": p.get("param", ""),
            "payload": p.get("payload", ""),
            "why": p.get("description", ""),
            "cve": p.get("cve", ""),
            "reference": p.get("reference", ""),
            "risk": p.get("risk", ""),
            "name": p.get("name", ""),
            "source": "cve",
            # 채택된 항목은 전부 특정 매칭(지문 또는 특정 경로) — always/param 단독은 이미 제외됨.
            "specific": True,
            "_score": score,
        }
        # 단일 POST/raw CVE: method·body·헤더까지 전달(폼에 그대로 세팅)
        if p.get("method"):
            cand["method"] = p["method"]
        if p.get("body"):
            cand["body"] = p["body"]
        if p.get("headers"):
            cand["headers"] = p["headers"]
        if not cand["payload"]:
            continue
        strong.append(cand)

    strong.sort(key=lambda c: c["_score"], reverse=True)
    seen, out = set(), []
    for c in strong:
        key = (c["location"], (c["param"] or "").lower(), c["payload"])
        if key in seen:
            continue
        seen.add(key)
        c.pop("_score", None)
        out.append(c)
        if len(out) >= limit:
            break
    return out
