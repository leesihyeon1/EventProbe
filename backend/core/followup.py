"""
결과 기반 후속(승격) 페이로드 로직 (기능2) — 무유출.

공격 검증 후 보안분석에서 나온 '신호 라벨'(취약 신호/알림 이름·판정·탐지 기술)을
근거로, 같은 지점에 시도할 승격 페이로드를 페이로드 저장소에서 골라 제안한다.

라벨만 사용하므로(응답 본문·증거 문자열·시크릿 미사용) 외부 전송 없이 안전하다.
"""
from typing import Optional

# 신호(취약 유형) → 페이로드 카테고리(family) 매핑. 이름/설명 키워드로 판별.
_FAMILY_KEYWORDS = [
    (("sql", "union", "블라인드", "sqli", "구문 오류", "quotation"), "sqli"),
    (("반사", "reflect", "xss", "스크립트", "script"),               "xss"),
    (("파일 읽기", "passwd", "lfi", "traversal", "경로 조작", "디렉터리"), "lfi"),
    (("명령", "command", "cmd", "rce", "명령 실행"),                  "cmdi"),
    (("템플릿", "ssti", "7*7", "=49", "template"),                    "ssti"),
    (("메타데이터", "ssrf", "내부/", "internal", "metadata", "169.254"), "ssrf"),
    (("리다이렉트", "redirect", "open redirect"),                    "redirect"),
    (("xxe", "xml external", "외부 엔티티"),                          "xxe"),
    (("nosql", "mongo"),                                             "nosql"),
    (("crlf", "http 응답 분할"),                                     "crlf"),
    (("ssi",),                                                       "ssi"),
    (("xpath",),                                                     "xpath"),
]

# 승격으로 우선 노출할 페이로드 키워드(고급 변형). 매칭되면 앞으로.
_ESCALATION_HINTS = (
    "union", "블라인드", "blind", "시간", "time", "sleep", "waitfor", "order by",
    "서브쿼리", "우회", "bypass", "인코딩", "encode", "이중", "double", "널", "null byte",
    "out-of-band", "oob", "wrapper", "래퍼", "필터", "filter", "폴리글롯", "polyglot",
    "스택", "stack", "error", "오류", "추출", "extract",
)


def hot_families(signals: dict) -> list:
    """검증 '근거'에서 승격할 공격 계열(family)을 도출 — 근거 없으면 빈 목록.

    근거로 인정하는 것: (1) 실제 취약 신호(finding_names — 성공 판정/누출 라벨만 상위에서
    전달됨) 가 매핑되는 계열, (2) 공격이 성공(attack_outcome=success)했다면 시도한 카테고리.
    단지 '그 카테고리를 시도했다'는 사실만으로는(차단·판정불가) 승격하지 않는다 —
    이래야 결과와 무관한 무의미한 페이로드 덤프를 막는다."""
    fams, seen = [], set()

    def add(f):
        if f and f not in seen:
            seen.add(f); fams.append(f)

    outcome = (signals.get("attack_outcome") or "").strip().lower()
    cat = (signals.get("category") or "").strip().lower()

    # finding_names 는 상위(프런트/호출자)에서 '성공/누출' 등 실제 근거 라벨만 넘어온다.
    names = [str(x) for x in (signals.get("finding_names") or [])]
    blob = " ".join(names).lower()

    for kws, fam in _FAMILY_KEYWORDS:
        if any(k in blob for k in kws):
            add(fam)

    # 시간 지연 근거 → blind sqli/cmdi 로 승격
    if "시간 지연" in blob or "sleep" in blob or "지연" in blob:
        add("sqli"); add("cmdi")

    # 공격이 실제로 성공했다면 시도한 카테고리 자체가 근거 → 그 계열 승격(익스플로잇 심화)
    if outcome == "success" and cat:
        add(cat)

    return fams


def _rank(payload: dict) -> int:
    text = ((payload.get("name") or "") + " " + (payload.get("description") or "")).lower()
    return sum(1 for h in _ESCALATION_HINTS if h in text)


def escalation_candidates(payloads_data: dict, families: list, location: str = "param",
                          param: str = "", per_family: int = 5,
                          exclude_payload: Optional[str] = None) -> list:
    """뜨거운 family 별로 저장소에서 승격 페이로드를 골라 후보로 반환."""
    cats = {c["id"]: c for c in payloads_data.get("categories", [])}
    loc = location if location in ("param", "body", "path", "header") else "param"
    out = []
    for fam in families:
        cat = cats.get(fam)
        if not cat:
            continue
        items = [p for p in cat.get("payloads", [])
                 if isinstance(p, dict) and p.get("payload")
                 and p.get("payload") != exclude_payload]
        # 승격 힌트 점수 높은 것 우선, 그다음 원래 순서
        items = sorted(items, key=_rank, reverse=True)[:per_family]
        for p in items:
            out.append({
                "category": fam,
                "location": loc,
                "param": param,
                "payload": p["payload"],
                "why": p.get("description", ""),
                "risk": p.get("risk", ""),
                "name": p.get("name", ""),
                "source": "followup",
            })
    return out
