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
from typing import Optional


def _any_in(needles, haystack: str) -> bool:
    return any(n.lower() in haystack for n in (needles or []))


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

    strong, weak = [], []
    for cat, p in _entries_with_hints(payloads_data):
        ap = p.get("applies_to") or {}
        score = 0
        matched = False

        if ap.get("path_contains") and _any_in(ap["path_contains"], path_lc):
            score += 2; matched = True
        if ap.get("param_names") and any(n.lower() in param_keys for n in ap["param_names"]):
            score += 2; matched = True
        if fp_server and ap.get("server") and _any_in(ap["server"], fp_server):
            score += 3; matched = True
        if fp_powered and ap.get("powered_by") and _any_in(ap["powered_by"], fp_powered):
            score += 3; matched = True
        if fp_body and ap.get("body_keywords") and _any_in(ap["body_keywords"], fp_body):
            score += 1; matched = True

        is_always = bool(ap.get("always"))
        if not matched and not is_always:
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
        (strong if matched else weak).append(cand)

    strong.sort(key=lambda c: c["_score"], reverse=True)
    merged = strong + weak            # 특정 매칭 우선, always 는 뒤에서 채움
    seen, out = set(), []
    for c in merged:
        key = (c["location"], (c["param"] or "").lower(), c["payload"])
        if key in seen:
            continue
        seen.add(key)
        c.pop("_score", None)
        out.append(c)
        if len(out) >= limit:
            break
    return out
