"""공격 카테고리 단일 소스(레지스트리).

분류·확증·후속·RAG 앵커·AI 화이트리스트가 제각각 하드코딩하던 카테고리 어휘를 한 곳에 모은다.
새 카테고리 추가 = 여기 한 줄. 각 소비처(api/confirm/followup/ai_analyzer)는 여기서 파생한다.

각 항목 필드:
  desc     : RAG 검색 앵커 설명(없으면 "")            → api._CATEGORY_DESC
  confirm  : 확증 스캔(오라클) 지원 여부              → confirm.SUPPORTED
  family   : 후속 승격 계열 매칭 키워드(없으면 None)  → followup._FAMILY_KEYWORDS (순서 보존)
  ai       : AI 분류(classify) 화이트리스트 포함 여부 → ai_analyzer._KNOWN_ATTACK_TYPES
  known    : AI 생성 카테고리 정규화 화이트리스트     → ai_analyzer._KNOWN_CATS

이 모듈은 core 의존이 없다(순수 데이터) — 어느 모듈에서든 안전하게 import.
"""

# dict 삽입 순서 = followup family 매칭 순서(결과 순서에만 영향). family 있는 것부터 나열.
_R: dict = {
    "sqli":     {"desc": "SQL injection database query error-based union blind order by",
                 "confirm": True,  "family": ("sql", "union", "블라인드", "sqli", "구문 오류", "quotation"),
                 "ai": True,  "known": True},
    "xss":      {"desc": "cross-site scripting XSS javascript injection reflected DOM",
                 "confirm": True,  "family": ("반사", "reflect", "xss", "스크립트", "script"),
                 "ai": True,  "known": True},
    "lfi":      {"desc": "local file inclusion path traversal directory traversal file read",
                 "confirm": True,  "family": ("파일 읽기", "passwd", "lfi", "traversal", "경로 조작", "디렉터리"),
                 "ai": True,  "known": True},
    "cmdi":     {"desc": "OS command injection remote code execution shell",
                 "confirm": True,  "family": ("명령", "command", "cmd", "rce", "명령 실행"),
                 "ai": True,  "known": True},
    "ssti":     {"desc": "server-side template injection expression evaluation",
                 "confirm": True,  "family": ("템플릿", "ssti", "7*7", "=49", "template"),
                 "ai": True,  "known": True},
    "ssrf":     {"desc": "server-side request forgery internal metadata endpoint",
                 "confirm": False, "family": ("메타데이터", "ssrf", "내부/", "internal", "metadata", "169.254"),
                 "ai": True,  "known": True},
    "redirect": {"desc": "open redirect location header",
                 "confirm": True,  "family": ("리다이렉트", "redirect", "open redirect"),
                 "ai": True,  "known": True},
    "xxe":      {"desc": "XML external entity injection",
                 "confirm": False, "family": ("xxe", "xml external", "외부 엔티티"),
                 "ai": True,  "known": False},
    "nosql":    {"desc": "NoSQL injection MongoDB operator",
                 "confirm": True,  "family": ("nosql", "mongo"),
                 "ai": True,  "known": True},
    "crlf":     {"desc": "", "confirm": False, "family": ("crlf", "http 응답 분할"), "ai": True, "known": False},
    "ssi":      {"desc": "", "confirm": False, "family": ("ssi",), "ai": True, "known": False},
    "xpath":    {"desc": "", "confirm": False, "family": ("xpath",), "ai": True, "known": False},
    # family 없음(승격 계열 아님)
    "idor":     {"desc": "access control IDOR authorization insecure direct object reference",
                 "confirm": True,  "family": None, "ai": True, "known": True},
    "jwt":      {"desc": "JSON web token JWT algorithm confusion signature",
                 "confirm": False, "family": None, "ai": True, "known": False},
    "xmlrpc":   {"desc": "XML-RPC pingback multicall wordpress",
                 "confirm": False, "family": None, "ai": True, "known": False},
    "csrf":     {"desc": "cross-site request forgery CSRF token",
                 "confirm": False, "family": None, "ai": True, "known": False},
    # confirm 전용 유사 카테고리(payload 카테고리라기보다 오라클 대상)
    "business": {"desc": "", "confirm": True,  "family": None, "ai": False, "known": False},
    "ldap":     {"desc": "", "confirm": True,  "family": None, "ai": True,  "known": False},
    "auth":     {"desc": "", "confirm": True,  "family": None, "ai": False, "known": False},
    # AI 분류 전용(확증/후속 없음)
    "cors":       {"desc": "", "confirm": False, "family": None, "ai": True, "known": False},
    "graphql":    {"desc": "", "confirm": False, "family": None, "ai": True, "known": False},
    "upload":     {"desc": "", "confirm": False, "family": None, "ai": True, "known": False},
    "deserial":   {"desc": "", "confirm": False, "family": None, "ai": True, "known": False},
    "prototype":  {"desc": "", "confirm": False, "family": None, "ai": True, "known": False},
    "log4shell":  {"desc": "", "confirm": False, "family": None, "ai": True, "known": False},
    "shellshock": {"desc": "", "confirm": False, "family": None, "ai": True, "known": False},
    "header":     {"desc": "", "confirm": False, "family": None, "ai": True, "known": False},
    "cache":      {"desc": "", "confirm": False, "family": None, "ai": True, "known": False},
    # 특수(실제 페이로드 카테고리 아님)
    "authbypass": {"desc": "", "confirm": False, "family": None, "ai": False, "known": True},
    "other":      {"desc": "", "confirm": False, "family": None, "ai": True,  "known": True},
}

# ── 소비처별 파생 뷰 ──────────────────────────────────────────
DESCRIPTIONS = {k: v["desc"] for k, v in _R.items() if v["desc"]}          # api._CATEGORY_DESC
CONFIRMABLE = {k for k, v in _R.items() if v["confirm"]}                   # confirm.SUPPORTED
FAMILY_KEYWORDS = [(v["family"], k) for k, v in _R.items() if v["family"]] # followup._FAMILY_KEYWORDS
AI_CLASSIFY_TYPES = [k for k, v in _R.items() if v["ai"]]                  # ai._KNOWN_ATTACK_TYPES
KNOWN_CATS = {k for k, v in _R.items() if v["known"]}                      # ai._KNOWN_CATS
