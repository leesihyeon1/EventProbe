"""
응답 분석 엔진 - WAF/IDS 차단 여부, 취약점 탐지, ZAP 스타일 Alert 생성
"""
import re
from typing import Optional


# ── WAF 차단 시그니처 ────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":   ["cloudflare", "cf-ray", "__cfduid"],
    "AWS WAF":      ["awselb", "x-amzn-requestid", "x-amz-cf-id"],
    "ModSecurity":  ["mod_security", "modsecurity", "NOYB"],
    "Akamai":       ["akamai", "akamaighost", "x-akamai"],
    "Imperva":      ["imperva", "incapsula", "visid_incap", "x-cdn"],
    "F5 BIG-IP":    ["bigip", "x-waf-status", "ts="],
    "Barracuda":    ["barracuda", "barra_counter_session"],
    "Fortinet":     ["fortigate", "fortiweb", "x-waf-event-info"],
    "Sucuri":       ["sucuri", "x-sucuri-id"],
    "Wordfence":    ["wordfence"],
}

# ── 차단 응답 바디 키워드 ────────────────────────────────────────────────────
BLOCK_KEYWORDS = [
    "blocked", "forbidden", "access denied", "not allowed",
    "security violation", "request blocked", "attack detected",
    "illegal request", "rejected", "차단", "금지", "접근 거부",
]

# ── 에러 누출 패턴 ────────────────────────────────────────────────────────────
ERROR_LEAK_PATTERNS = [
    (r"SQL syntax.*?MySQL",            "MySQL 에러 노출"),
    (r"Warning.*?\Wmysqli?_",          "MySQL 함수 에러"),
    (r"ORA-\d{5}",                     "Oracle DB 에러 코드"),
    (r"Microsoft SQL Server",          "MSSQL 에러"),
    (r"PostgreSQL.*?ERROR",            "PostgreSQL 에러"),
    (r"sqlite3\.OperationalError",     "SQLite 에러"),
    (r"ODBC.*?Driver",                 "ODBC 드라이버 에러"),
    (r"<b>Fatal error</b>",            "PHP Fatal 에러"),
    (r"stack trace",                   "스택 트레이스 노출"),
    (r"at java\.",                     "Java 스택 트레이스"),
    (r"Exception in thread",           "Java 예외"),
    (r"Traceback \(most recent",       "Python 트레이스백"),
    (r"ActiveRecord::.*Error",         "Ruby on Rails DB 에러"),
    (r"Uncaught TypeError",            "JavaScript 에러 노출"),
]

# ── 민감 정보 패턴 ────────────────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    (r"root:[x*]:0:0",                             "passwd 파일 내용"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",    "개인키 노출"),
    (r"password\s*[=:]\s*\S+",                     "패스워드 노출"),
    (r"api[_-]?key\s*[=:]\s*['\"]?\w{10,}",       "API 키 노출"),
    (r"secret[_-]?key\s*[=:]\s*['\"]?\w{10,}",    "Secret 키 노출"),
    (r"access[_-]?token\s*[=:]\s*['\"]?\S{10,}",  "Access Token 노출"),
    (r"[A-Za-z0-9+/]{60,}={0,2}",                 "Base64 인코딩 데이터 (토큰 의심)"),
    (r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b",
                                                   "내부 IP 주소 노출"),
]


# ════════════════════════════════════════════════════════════════════════════════
# ZAP 스타일 ALERT 룰셋
# ════════════════════════════════════════════════════════════════════════════════
# 각 룰: {
#   id, name, risk (high/medium/low/informational),
#   confidence (certain/firm/tentative),
#   description, solution, reference,
#   check: callable(headers_lower, body, body_lower, status_code) -> bool | str
# }

ALERT_RULES = [

    # ── 보안 헤더 누락 ─────────────────────────────────────────────────────────
    {
        "id": "10016",
        "name": "Content-Security-Policy 헤더 누락",
        "risk": "medium",
        "confidence": "certain",
        "description": "CSP 헤더가 없습니다. XSS 및 데이터 인젝션 공격에 취약할 수 있습니다.",
        "solution": "Content-Security-Policy 헤더를 응답에 추가하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "content-security-policy" not in h and s == 200,
    },
    {
        "id": "10035",
        "name": "Strict-Transport-Security 헤더 누락",
        "risk": "low",
        "confidence": "certain",
        "description": "HSTS 헤더가 없습니다. HTTPS 강제 설정이 되어있지 않아 다운그레이드 공격에 노출될 수 있습니다.",
        "solution": "Strict-Transport-Security: max-age=31536000; includeSubDomains 헤더를 추가하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "strict-transport-security" not in h and s == 200,
    },
    {
        "id": "10021",
        "name": "X-Content-Type-Options 헤더 누락",
        "risk": "low",
        "confidence": "certain",
        "description": "X-Content-Type-Options 헤더가 없어 MIME 스니핑 공격에 취약합니다.",
        "solution": "X-Content-Type-Options: nosniff 헤더를 추가하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "x-content-type-options" not in h and s == 200,
    },
    {
        "id": "10020",
        "name": "X-Frame-Options 헤더 누락",
        "risk": "medium",
        "confidence": "certain",
        "description": "X-Frame-Options 헤더가 없습니다. 클릭재킹(Clickjacking) 공격에 취약합니다.",
        "solution": "X-Frame-Options: DENY 또는 SAMEORIGIN 헤더를 추가하세요.",
        "reference": "https://owasp.org/www-community/attacks/Clickjacking",
        "check": lambda h, b, bl, s: "x-frame-options" not in h
                                      and "frame-ancestors" not in h.get("content-security-policy","")
                                      and s == 200,
    },
    {
        "id": "10038",
        "name": "Content-Security-Policy — unsafe-inline 허용",
        "risk": "medium",
        "confidence": "certain",
        "description": "CSP에 'unsafe-inline'이 허용되어 XSS 방어 효과가 크게 감소합니다.",
        "solution": "unsafe-inline 지시어를 제거하고 nonce 또는 hash 기반 CSP를 사용하세요.",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        "check": lambda h, b, bl, s: "unsafe-inline" in h.get("content-security-policy", ""),
    },
    {
        "id": "10036",
        "name": "Permissions-Policy 헤더 누락",
        "risk": "low",
        "confidence": "tentative",
        "description": "Permissions-Policy(Feature-Policy) 헤더가 없어 불필요한 브라우저 기능이 활성화될 수 있습니다.",
        "solution": "Permissions-Policy 헤더를 추가하여 카메라, 마이크 등의 권한을 제한하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "permissions-policy" not in h
                                      and "feature-policy" not in h
                                      and s == 200,
    },

    # ── 쿠키 보안 ─────────────────────────────────────────────────────────────
    {
        "id": "10010",
        "name": "쿠키 HttpOnly 플래그 누락",
        "risk": "medium",
        "confidence": "firm",
        "description": "Set-Cookie 헤더에 HttpOnly 플래그가 없습니다. JavaScript에서 쿠키 접근이 가능하여 XSS를 통한 세션 탈취가 가능합니다.",
        "solution": "모든 세션 쿠키에 HttpOnly 플래그를 설정하세요.",
        "reference": "https://owasp.org/www-community/HttpOnly",
        "check": lambda h, b, bl, s: "set-cookie" in h
                                      and "httponly" not in h.get("set-cookie", "").lower(),
    },
    {
        "id": "10011",
        "name": "쿠키 Secure 플래그 누락",
        "risk": "medium",
        "confidence": "firm",
        "description": "Set-Cookie 헤더에 Secure 플래그가 없습니다. HTTP로 쿠키가 전송될 수 있습니다.",
        "solution": "세션 쿠키에 Secure 플래그를 설정하세요.",
        "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute",
        "check": lambda h, b, bl, s: "set-cookie" in h
                                      and "secure" not in h.get("set-cookie", "").lower(),
    },
    {
        "id": "10054",
        "name": "쿠키 SameSite 속성 없음",
        "risk": "low",
        "confidence": "firm",
        "description": "Set-Cookie 헤더에 SameSite 속성이 없어 CSRF 공격에 취약할 수 있습니다.",
        "solution": "SameSite=Strict 또는 SameSite=Lax 속성을 쿠키에 추가하세요.",
        "reference": "https://owasp.org/www-community/SameSite",
        "check": lambda h, b, bl, s: "set-cookie" in h
                                      and "samesite" not in h.get("set-cookie", "").lower(),
    },

    # ── 프레임워크/서버 정보 노출 ─────────────────────────────────────────────
    {
        "id": "10036-server",
        "name": "Server 헤더 — 버전 정보 노출",
        "risk": "low",
        "confidence": "certain",
        "description": lambda h, **_: f"Server 헤더에 상세 버전 정보가 노출됩니다: {h.get('server','')}",
        "solution": "Server 헤더에서 버전 정보를 제거하거나 헤더 자체를 숨기세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: bool(re.search(
            r"(apache|nginx|iis|tomcat|jetty|lighttpd|gunicorn|uvicorn)[/\s]\d+",
            h.get("server", ""), re.I)),
    },
    {
        "id": "10037",
        "name": "X-Powered-By 헤더 — 프레임워크 노출",
        "risk": "low",
        "confidence": "certain",
        "description": lambda h, **_: f"X-Powered-By 헤더가 기술 스택을 노출합니다: {h.get('x-powered-by','')}",
        "solution": "X-Powered-By 헤더를 제거하거나 비활성화하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: "x-powered-by" in h,
    },
    {
        "id": "10054-asp",
        "name": "ASP.NET 버전 헤더 노출",
        "risk": "low",
        "confidence": "certain",
        "description": lambda h, **_: f"X-AspNet-Version 헤더가 노출됩니다: {h.get('x-aspnet-version','')}",
        "solution": "httpRuntime enableVersionHeader=\"false\" 설정으로 헤더를 비활성화하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: "x-aspnet-version" in h or "x-aspnetmvc-version" in h,
    },

    # ── 프레임워크 식별 (헤더 기반) ──────────────────────────────────────────
    {
        "id": "90005-fw",
        "name": "프레임워크 식별 — Django",
        "risk": "informational",
        "confidence": "firm",
        "description": "응답 헤더에서 Django 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "csrftoken" in h.get("set-cookie","") or "django" in h.get("x-powered-by",""),
    },
    {
        "id": "90005-laravel",
        "name": "프레임워크 식별 — Laravel/PHP",
        "risk": "informational",
        "confidence": "firm",
        "description": "Laravel 또는 PHP 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "laravel_session" in h.get("set-cookie","")
                                      or "php" in h.get("x-powered-by","").lower()
                                      or "laravel" in h.get("x-powered-by","").lower(),
    },
    {
        "id": "90005-spring",
        "name": "프레임워크 식별 — Spring (Java)",
        "risk": "informational",
        "confidence": "tentative",
        "description": "Spring Framework(Java) 가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "jsessionid" in h.get("set-cookie","").lower()
                                      or "spring" in h.get("x-application-context","").lower(),
    },
    {
        "id": "90005-express",
        "name": "프레임워크 식별 — Express.js (Node.js)",
        "risk": "informational",
        "confidence": "certain",
        "description": "Express.js 프레임워크가 식별되었습니다. (X-Powered-By: Express)",
        "solution": "app.disable('x-powered-by')로 헤더를 비활성화하세요.",
        "reference": "https://expressjs.com/en/advanced/best-practice-security.html",
        "check": lambda h, b, bl, s: "express" in h.get("x-powered-by","").lower(),
    },
    {
        "id": "90005-wp",
        "name": "CMS 식별 — WordPress",
        "risk": "informational",
        "confidence": "firm",
        "description": "WordPress CMS가 식별되었습니다. WordPress 고유 경로 및 메타 태그가 감지되었습니다.",
        "solution": "버전 정보 노출을 제거하고 보안 플러그인을 적용하세요.",
        "reference": "https://wordpress.org/support/article/hardening-wordpress/",
        "check": lambda h, b, bl, s: "wp-content" in bl or "wp-includes" in bl or "wordpress" in bl,
    },

    # ── 캐시 제어 ─────────────────────────────────────────────────────────────
    {
        "id": "10015",
        "name": "캐시 제어 헤더 미설정",
        "risk": "informational",
        "confidence": "tentative",
        "description": "민감한 데이터가 캐시될 수 있습니다. Cache-Control 또는 Pragma 헤더가 없습니다.",
        "solution": "Cache-Control: no-store, Pragma: no-cache 헤더를 민감한 페이지에 추가하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: "cache-control" not in h and "pragma" not in h and s == 200,
    },

    # ── 정보 노출 (바디 기반) ─────────────────────────────────────────────────
    {
        "id": "10095",
        "name": "Backup 파일 경로 노출",
        "risk": "medium",
        "confidence": "firm",
        "description": "응답에서 백업 파일 경로 또는 임시 파일 경로가 발견되었습니다.",
        "solution": "백업 파일을 웹 루트 외부로 이동하고 디렉터리 리스팅을 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(
            r"\.(bak|backup|old|orig|tmp|swp|sql|dump)\b", bl)),
    },
    {
        "id": "10096",
        "name": "내부 경로 노출",
        "risk": "low",
        "confidence": "firm",
        "description": "응답 바디에 서버 내부 파일 시스템 경로가 노출되었습니다.",
        "solution": "에러 메시지에서 경로 정보를 제거하고 커스텀 에러 페이지를 사용하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: bool(re.search(
            r"[Cc]:\\[\\a-zA-Z]+|/home/\w+/|/var/www/|/usr/local/", b)),
    },
    {
        "id": "10097",
        "name": "이메일 주소 노출",
        "risk": "informational",
        "confidence": "tentative",
        "description": "응답 바디에서 이메일 주소가 발견되었습니다.",
        "solution": "이메일 주소 노출을 최소화하거나 마스킹 처리하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", b)),
    },
    {
        "id": "10098",
        "name": "주석 내 민감 정보",
        "risk": "informational",
        "confidence": "tentative",
        "description": "HTML/JS 주석에 민감한 정보(TODO, 비밀번호 힌트, 내부 경로 등)가 포함되어 있습니다.",
        "solution": "프로덕션 코드에서 민감한 정보가 담긴 주석을 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(
            r"<!--.*?(password|secret|todo|fixme|hack|admin|key)[^>]*-->", bl, re.DOTALL)),
    },

    # ── CORS 설정 오류 ─────────────────────────────────────────────────────────
    {
        "id": "10098-cors",
        "name": "CORS — 와일드카드 허용 (Access-Control-Allow-Origin: *)",
        "risk": "medium",
        "confidence": "certain",
        "description": "모든 도메인에서의 크로스오리진 요청을 허용합니다. 민감한 API에 적용된 경우 심각한 보안 문제가 될 수 있습니다.",
        "solution": "신뢰할 수 있는 특정 도메인만 허용하도록 CORS 정책을 제한하세요.",
        "reference": "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
        "check": lambda h, b, bl, s: h.get("access-control-allow-origin","").strip() == "*",
    },
    {
        "id": "10099-cors-cred",
        "name": "CORS — 자격증명 + 와일드카드 허용",
        "risk": "high",
        "confidence": "certain",
        "description": "Access-Control-Allow-Credentials: true 와 Access-Control-Allow-Origin: * 가 동시에 설정되어 있습니다. 인증 토큰 탈취가 가능합니다.",
        "solution": "자격증명을 허용할 경우 특정 오리진만 명시하세요.",
        "reference": "https://portswigger.net/web-security/cors",
        "check": lambda h, b, bl, s: h.get("access-control-allow-origin","").strip() == "*"
                                      and "true" in h.get("access-control-allow-credentials","").lower(),
    },

    # ── 기타 취약점 힌트 ─────────────────────────────────────────────────────
    {
        "id": "10050",
        "name": "리디렉션 — 열린 리디렉션 가능성",
        "risk": "medium",
        "confidence": "tentative",
        "description": "외부 URL로의 리디렉션이 감지되었습니다. 열린 리디렉션 취약점이 존재할 수 있습니다.",
        "solution": "리디렉션 대상 URL을 화이트리스트로 검증하세요.",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        "check": lambda h, b, bl, s: s in [301,302,303,307,308]
                                      and bool(re.search(r"https?://", h.get("location",""))),
    },
    {
        "id": "10055",
        "name": "소스맵 파일 참조 노출",
        "risk": "low",
        "confidence": "tentative",
        "description": "응답에 JavaScript 소스맵 파일 참조가 포함되어 있습니다. 원본 소스코드가 노출될 수 있습니다.",
        "solution": "프로덕션 환경에서 소스맵 파일을 제거하거나 접근을 제한하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "//# sourcemappingurl=" in bl,
    },
    {
        "id": "10056",
        "name": "GraphQL 엔드포인트 노출",
        "risk": "informational",
        "confidence": "firm",
        "description": "GraphQL 엔드포인트가 노출되어 있습니다. 인트로스펙션이 활성화된 경우 스키마 전체가 유출될 수 있습니다.",
        "solution": "프로덕션 환경에서 GraphQL 인트로스펙션을 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r'"__schema"|"__type"|graphql', bl)),
    },
]


def run_alert_rules(headers_lower: dict, body: str, body_lower: str, status_code: int) -> list:
    """ALERT 룰셋 전체 실행 후 발견된 Alert 목록 반환"""
    alerts = []
    for rule in ALERT_RULES:
        try:
            matched = rule["check"](headers_lower, body, body_lower, status_code)
            if matched:
                # description이 callable이면 동적 생성
                desc = rule["description"]
                if callable(desc):
                    desc = desc(headers_lower)
                alerts.append({
                    "id":          rule["id"],
                    "name":        rule["name"],
                    "risk":        rule["risk"],
                    "confidence":  rule["confidence"],
                    "description": desc,
                    "solution":    rule["solution"],
                    "reference":   rule["reference"],
                })
        except Exception:
            pass
    # 위험도 순 정렬
    risk_order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    alerts.sort(key=lambda a: risk_order.get(a["risk"], 9))
    return alerts


# ════════════════════════════════════════════════════════════════════════════════
# 메인 분석 함수
# ════════════════════════════════════════════════════════════════════════════════

def analyze_response(
    status_code: int,
    headers: dict,
    body: str,
    response_time: float,
    payload: Optional[str] = None,
    category: Optional[str] = None,
) -> dict:
    """HTTP 응답을 분석하여 보안 판정 결과 반환"""

    result = {
        "verdict": "unknown",
        "confidence": 0,
        "waf_detected": None,
        "block_reason": [],
        "error_leaks": [],
        "sensitive_data": [],
        "response_anomalies": [],
        "risk_level": "info",
        "details": [],
        "score": 0,
        "alerts": [],          # ZAP 스타일 Alert 목록
    }

    body = body or ""
    body_lower = body.lower()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    # 1. 상태코드 분석
    if status_code in [403, 406, 429, 503]:
        result["verdict"] = "blocked"
        result["confidence"] = 75
        result["details"].append(f"HTTP {status_code} — 차단 응답")
        result["block_reason"].append(f"상태코드 {status_code}")
    elif status_code == 400:
        result["verdict"] = "blocked"
        result["confidence"] = 60
        result["details"].append("HTTP 400 — 잘못된 요청 (WAF 필터링 가능성)")
        result["block_reason"].append("상태코드 400")
    elif status_code == 200:
        result["verdict"] = "passed"
        result["confidence"] = 50
        result["details"].append("HTTP 200 — 요청 통과")
    elif status_code >= 500:
        result["verdict"] = "error"
        result["confidence"] = 40
        result["details"].append(f"HTTP {status_code} — 서버 에러")

    # 2. WAF 헤더 탐지
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            for hdr_val in headers_lower.values():
                if sig in hdr_val:
                    result["waf_detected"] = waf_name
                    result["details"].append(f"WAF 탐지: {waf_name}")
                    if result["verdict"] != "blocked":
                        result["verdict"] = "blocked"
                    result["confidence"] = min(result["confidence"] + 20, 95)
                    break

    # 3. 응답 바디 차단 키워드
    for kw in BLOCK_KEYWORDS:
        if kw in body_lower:
            result["block_reason"].append(f"바디 키워드: '{kw}'")
            result["verdict"] = "blocked"
            result["confidence"] = min(result["confidence"] + 15, 95)

    # 4. 에러 누출 탐지
    for pattern, desc in ERROR_LEAK_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            result["error_leaks"].append(desc)
            result["details"].append(f"⚠️ 에러 정보 누출: {desc}")
            if result["verdict"] == "passed":
                result["verdict"] = "bypass"
            result["risk_level"] = "high"

    # 5. 민감 정보 탐지
    for pattern, desc in SENSITIVE_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            result["sensitive_data"].append(desc)
            result["details"].append(f"🔴 민감 정보 노출: {desc}")
            result["verdict"] = "bypass"
            result["risk_level"] = "critical"

    # 6. 응답 시간 이상
    if response_time > 5000:
        result["response_anomalies"].append(f"응답 지연 {response_time:.0f}ms (Time-based 공격 가능성)")
        result["details"].append(f"⏱️ 응답 지연 탐지: {response_time:.0f}ms")

    # 7. 응답 크기 이상
    if len(body) < 50 and status_code == 200:
        result["response_anomalies"].append("비정상적으로 짧은 200 응답")

    # 8. ZAP 스타일 Alert 실행
    result["alerts"] = run_alert_rules(headers_lower, body, body_lower, status_code)

    # 9. Alert 위험도를 종합 risk_level에 반영
    alert_risks = [a["risk"] for a in result["alerts"]]
    if "high" in alert_risks and result["risk_level"] not in ("critical",):
        result["risk_level"] = "high"
    elif "medium" in alert_risks and result["risk_level"] in ("info", "low"):
        result["risk_level"] = "medium"

    # 10. 최종 위험도 산정
    if result["verdict"] == "bypass" or result["sensitive_data"]:
        result["risk_level"] = "critical"
        result["score"] = 90
    elif result["error_leaks"]:
        result["risk_level"] = "high"
        result["score"] = 70
    elif result["verdict"] == "passed" and category in ["sqli", "cmdi", "ssrf"]:
        result["risk_level"] = "high"
        result["score"] = 65
    elif result["verdict"] == "blocked":
        result["risk_level"] = "info"
        result["score"] = 10
    else:
        result["risk_level"] = "medium"
        result["score"] = 40

    return result


def generate_summary(results: list) -> dict:
    total = len(results)
    if total == 0:
        return {}

    blocked = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "blocked")
    passed  = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "passed")
    bypass  = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "bypass")
    error   = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "error")

    detection_rate = (blocked / total * 100) if total > 0 else 0

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        lvl = r.get("analysis", {}).get("risk_level", "info")
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    return {
        "total": total,
        "blocked": blocked,
        "passed": passed,
        "bypass": bypass,
        "error": error,
        "detection_rate": round(detection_rate, 1),
        "risk_counts": risk_counts,
        "waf_detected": list({
            r.get("analysis", {}).get("waf_detected")
            for r in results
            if r.get("analysis", {}).get("waf_detected")
        }),
    }
