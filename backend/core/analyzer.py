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

    # ── 웹 서버 식별 ──────────────────────────────────────────────────────────
    {
        "id": "90001-apache",
        "name": "웹서버 식별 — Apache",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Apache 웹서버가 식별되었습니다: {h.get('server','')}",
        "solution": "Server 헤더에서 버전 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"apache", h.get("server",""), re.I)),
    },
    {
        "id": "90001-nginx",
        "name": "웹서버 식별 — Nginx",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Nginx 웹서버가 식별되었습니다: {h.get('server','')}",
        "solution": "server_tokens off; 설정으로 버전 정보를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"nginx", h.get("server",""), re.I)),
    },
    {
        "id": "90001-iis",
        "name": "웹서버 식별 — Microsoft IIS",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Microsoft IIS가 식별되었습니다: {h.get('server','')}",
        "solution": "IIS Manager에서 HTTP 응답 헤더의 Server 값을 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"iis|microsoft-iis", h.get("server",""), re.I)),
    },
    {
        "id": "90001-tomcat",
        "name": "WAS 식별 — Apache Tomcat",
        "risk": "informational", "confidence": "firm",
        "description": lambda h, **_: f"Apache Tomcat이 식별되었습니다: {h.get('server','')}",
        "solution": "server.xml에서 Server 헤더를 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"tomcat", h.get("server",""), re.I))
                                      or "apache-coyote" in h.get("server","").lower(),
    },
    {
        "id": "90001-jetty",
        "name": "WAS 식별 — Jetty",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Eclipse Jetty가 식별되었습니다: {h.get('server','')}",
        "solution": "Server 헤더 노출을 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"jetty", h.get("server",""), re.I)),
    },
    {
        "id": "90001-weblogic",
        "name": "WAS 식별 — Oracle WebLogic",
        "risk": "low", "confidence": "firm",
        "description": "Oracle WebLogic 서버가 식별되었습니다. 알려진 취약점이 다수 존재합니다.",
        "solution": "Server 헤더를 제거하고 최신 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"weblogic", h.get("server",""), re.I))
                                      or "weblogic" in bl,
    },
    {
        "id": "90001-websphere",
        "name": "WAS 식별 — IBM WebSphere",
        "risk": "low", "confidence": "firm",
        "description": "IBM WebSphere 서버가 식별되었습니다.",
        "solution": "Server 헤더를 제거하고 최신 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"websphere|was/", h.get("server",""), re.I)),
    },
    {
        "id": "90001-jboss",
        "name": "WAS 식별 — JBoss / WildFly",
        "risk": "low", "confidence": "firm",
        "description": "JBoss 또는 WildFly 서버가 식별되었습니다.",
        "solution": "Server 헤더를 제거하고 최신 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"jboss|wildfly", h.get("server",""), re.I))
                                      or "jboss" in bl,
    },
    {
        "id": "90001-gunicorn",
        "name": "웹서버 식별 — Gunicorn (Python)",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Gunicorn WSGI 서버가 식별되었습니다: {h.get('server','')}",
        "solution": "reverse proxy 뒤에 배치하여 Server 헤더를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"gunicorn", h.get("server",""), re.I)),
    },
    {
        "id": "90001-uvicorn",
        "name": "웹서버 식별 — Uvicorn (Python ASGI)",
        "risk": "informational", "confidence": "certain",
        "description": "Uvicorn ASGI 서버가 식별되었습니다.",
        "solution": "reverse proxy 뒤에 배치하여 Server 헤더를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"uvicorn", h.get("server",""), re.I)),
    },
    {
        "id": "90001-lighttpd",
        "name": "웹서버 식별 — lighttpd",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"lighttpd 웹서버가 식별되었습니다: {h.get('server','')}",
        "solution": "server.tag 설정으로 버전 정보를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"lighttpd", h.get("server",""), re.I)),
    },
    {
        "id": "90001-caddy",
        "name": "웹서버 식별 — Caddy",
        "risk": "informational", "confidence": "certain",
        "description": "Caddy 웹서버가 식별되었습니다.",
        "solution": "Server 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"caddy", h.get("server",""), re.I)),
    },

    # ── 언어/런타임 식별 ──────────────────────────────────────────────────────
    {
        "id": "90002-php",
        "name": "언어 식별 — PHP",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"PHP 런타임이 노출됩니다: {h.get('x-powered-by','')}",
        "solution": "expose_php = Off (php.ini) 설정으로 헤더를 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"php", h.get("x-powered-by",""), re.I))
                                      or bool(re.search(r"php/\d", h.get("server",""), re.I)),
    },
    {
        "id": "90002-aspnet",
        "name": "언어 식별 — ASP.NET",
        "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"ASP.NET이 식별되었습니다: {h.get('x-powered-by','')}",
        "solution": "X-Powered-By 헤더를 제거하고 버전 정보를 숨기세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"asp\.net", h.get("x-powered-by",""), re.I)),
    },
    {
        "id": "90002-python",
        "name": "언어 식별 — Python",
        "risk": "informational", "confidence": "tentative",
        "description": "Python 기반 서버가 식별되었습니다.",
        "solution": "Server 헤더에서 언어 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"python|django|flask|fastapi|tornado|aiohttp",
                                           h.get("server","") + h.get("x-powered-by",""), re.I)),
    },
    {
        "id": "90002-ruby",
        "name": "언어 식별 — Ruby",
        "risk": "informational", "confidence": "firm",
        "description": "Ruby 기반 서버가 식별되었습니다.",
        "solution": "Server 헤더에서 언어 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"ruby|rails|phusion passenger",
                                           h.get("server","") + h.get("x-powered-by",""), re.I)),
    },
    {
        "id": "90002-java",
        "name": "언어 식별 — Java",
        "risk": "informational", "confidence": "tentative",
        "description": "Java 기반 서버가 식별되었습니다.",
        "solution": "Server 헤더에서 언어 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"java|jsessionid",
                                           h.get("server","") + h.get("set-cookie",""), re.I)),
    },
    {
        "id": "90002-nodejs",
        "name": "언어 식별 — Node.js",
        "risk": "informational", "confidence": "firm",
        "description": "Node.js 기반 서버가 식별되었습니다.",
        "solution": "Server 헤더에서 런타임 정보를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"node\.js|nodejs",
                                           h.get("server","") + h.get("x-powered-by",""), re.I)),
    },

    # ── 프레임워크 식별 ────────────────────────────────────────────────────────
    {
        "id": "90005-django",
        "name": "프레임워크 식별 — Django",
        "risk": "informational", "confidence": "firm",
        "description": "Django 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "csrftoken" in h.get("set-cookie","")
                                      or "django" in h.get("x-powered-by","").lower()
                                      or bool(re.search(r"django", bl)),
    },
    {
        "id": "90005-flask",
        "name": "프레임워크 식별 — Flask",
        "risk": "informational", "confidence": "firm",
        "description": "Flask 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "werkzeug" in h.get("server","").lower()
                                      or bool(re.search(r"flask|werkzeug", bl)),
    },
    {
        "id": "90005-fastapi",
        "name": "프레임워크 식별 — FastAPI",
        "risk": "informational", "confidence": "firm",
        "description": "FastAPI 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"fastapi", bl))
                                      or h.get("server","").lower().startswith("uvicorn"),
    },
    {
        "id": "90005-laravel",
        "name": "프레임워크 식별 — Laravel",
        "risk": "informational", "confidence": "firm",
        "description": "Laravel 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "laravel_session" in h.get("set-cookie","")
                                      or "laravel" in h.get("x-powered-by","").lower()
                                      or bool(re.search(r"laravel", bl)),
    },
    {
        "id": "90005-symfony",
        "name": "프레임워크 식별 — Symfony (PHP)",
        "risk": "informational", "confidence": "firm",
        "description": "Symfony 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "symfony" in h.get("x-powered-by","").lower()
                                      or bool(re.search(r"symfony|sfid=", h.get("set-cookie",""), re.I))
                                      or bool(re.search(r"symfony", bl)),
    },
    {
        "id": "90005-spring",
        "name": "프레임워크 식별 — Spring (Java)",
        "risk": "informational", "confidence": "tentative",
        "description": "Spring Framework가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "jsessionid" in h.get("set-cookie","").lower()
                                      or "spring" in h.get("x-application-context","").lower()
                                      or bool(re.search(r"whitelabel error|spring", bl)),
    },
    {
        "id": "90005-express",
        "name": "프레임워크 식별 — Express.js",
        "risk": "informational", "confidence": "certain",
        "description": "Express.js 프레임워크가 식별되었습니다.",
        "solution": "app.disable('x-powered-by')로 헤더를 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "express" in h.get("x-powered-by","").lower(),
    },
    {
        "id": "90005-nestjs",
        "name": "프레임워크 식별 — NestJS",
        "risk": "informational", "confidence": "tentative",
        "description": "NestJS 프레임워크가 식별되었습니다.",
        "solution": "프레임워크 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"nestjs|nest\.js", bl, re.I)),
    },
    {
        "id": "90005-rails",
        "name": "프레임워크 식별 — Ruby on Rails",
        "risk": "informational", "confidence": "firm",
        "description": "Ruby on Rails 프레임워크가 식별되었습니다.",
        "solution": "config.middleware.delete ActionDispatch::ServerTiming 등으로 정보 노출을 줄이세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"rails|_session_id|_rails",
                                           h.get("set-cookie",""), re.I))
                                      or bool(re.search(r"ruby on rails|rails", bl, re.I)),
    },
    {
        "id": "90005-nextjs",
        "name": "프레임워크 식별 — Next.js",
        "risk": "informational", "confidence": "firm",
        "description": "Next.js 프레임워크가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-nextjs-cache" in h or "x-nextjs-page" in h
                                      or bool(re.search(r"__next|_next/static", bl)),
    },
    {
        "id": "90005-nuxt",
        "name": "프레임워크 식별 — Nuxt.js",
        "risk": "informational", "confidence": "firm",
        "description": "Nuxt.js 프레임워크가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"__nuxt|_nuxt/", bl)),
    },
    {
        "id": "90005-aspnet-core",
        "name": "프레임워크 식별 — ASP.NET Core",
        "risk": "informational", "confidence": "firm",
        "description": "ASP.NET Core 프레임워크가 식별되었습니다.",
        "solution": "헤더 노출 설정을 검토하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"asp\.net core", h.get("x-powered-by",""), re.I))
                                      or "x-aspnetcore-env" in h,
    },
    {
        "id": "90005-struts",
        "name": "프레임워크 식별 — Apache Struts",
        "risk": "low", "confidence": "tentative",
        "description": "Apache Struts 프레임워크가 식별되었습니다. 심각한 취약점(CVE-2017-5638 등) 이력이 있습니다.",
        "solution": "최신 버전으로 패치하고 프레임워크 정보 노출을 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"struts|\.action\b|\.do\b", bl, re.I)),
    },

    # ── CMS / 플랫폼 식별 ─────────────────────────────────────────────────────
    {
        "id": "90006-wp",
        "name": "CMS 식별 — WordPress",
        "risk": "informational", "confidence": "firm",
        "description": "WordPress CMS가 식별되었습니다.",
        "solution": "버전 정보 노출을 제거하고 보안 플러그인을 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "wp-content" in bl or "wp-includes" in bl
                                      or bool(re.search(r"wordpress|wp-json", bl)),
    },
    {
        "id": "90006-drupal",
        "name": "CMS 식별 — Drupal",
        "risk": "informational", "confidence": "firm",
        "description": "Drupal CMS가 식별되었습니다.",
        "solution": "버전 정보를 숨기고 최신 보안 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-generator" in h and "drupal" in h.get("x-generator","").lower()
                                      or bool(re.search(r"drupal|/sites/default/files", bl)),
    },
    {
        "id": "90006-joomla",
        "name": "CMS 식별 — Joomla",
        "risk": "informational", "confidence": "firm",
        "description": "Joomla CMS가 식별되었습니다.",
        "solution": "버전 정보를 숨기고 최신 보안 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"joomla|/components/com_", bl)),
    },
    {
        "id": "90006-magento",
        "name": "E-Commerce 식별 — Magento",
        "risk": "informational", "confidence": "firm",
        "description": "Magento 전자상거래 플랫폼이 식별되었습니다.",
        "solution": "버전 정보를 숨기고 최신 보안 패치를 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"magento|mage-|/skin/frontend/", bl)),
    },
    {
        "id": "90006-shopify",
        "name": "E-Commerce 식별 — Shopify",
        "risk": "informational", "confidence": "certain",
        "description": "Shopify 플랫폼이 식별되었습니다.",
        "solution": "SaaS 플랫폼 특성상 추가 보안 설정을 검토하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "shopify" in h.get("server","").lower()
                                      or bool(re.search(r"shopify|cdn\.shopify", bl)),
    },

    # ── CDN / 클라우드 식별 ────────────────────────────────────────────────────
    {
        "id": "90007-cloudflare",
        "name": "CDN 식별 — Cloudflare",
        "risk": "informational", "confidence": "certain",
        "description": "Cloudflare CDN/WAF가 식별되었습니다.",
        "solution": "Cloudflare 설정에서 불필요한 헤더 노출을 검토하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "cloudflare" in h.get("server","").lower()
                                      or "cf-ray" in h or "cf-cache-status" in h,
    },
    {
        "id": "90007-aws-cf",
        "name": "CDN 식별 — AWS CloudFront",
        "risk": "informational", "confidence": "certain",
        "description": "AWS CloudFront CDN이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-amz-cf-id" in h or "x-amz-cf-pop" in h
                                      or "cloudfront" in h.get("server","").lower(),
    },
    {
        "id": "90007-fastly",
        "name": "CDN 식별 — Fastly",
        "risk": "informational", "confidence": "certain",
        "description": "Fastly CDN이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-fastly-request-id" in h or "fastly" in h.get("server","").lower()
                                      or "x-served-by" in h,
    },
    {
        "id": "90007-akamai",
        "name": "CDN 식별 — Akamai",
        "risk": "informational", "confidence": "firm",
        "description": "Akamai CDN이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "akamai" in h.get("server","").lower()
                                      or "x-akamai-transformed" in h or "x-check-cacheable" in h,
    },
    {
        "id": "90007-azure",
        "name": "클라우드 식별 — Microsoft Azure",
        "risk": "informational", "confidence": "firm",
        "description": "Microsoft Azure 인프라가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-ms-request-id" in h or "x-msedge-ref" in h
                                      or "azure" in h.get("server","").lower(),
    },
    {
        "id": "90007-aws-elb",
        "name": "클라우드 식별 — AWS ELB/ALB",
        "risk": "informational", "confidence": "certain",
        "description": "AWS Elastic Load Balancer가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "awselb" in h.get("set-cookie","").lower()
                                      or "x-amzn-requestid" in h or "x-amzn-trace-id" in h,
    },
    {
        "id": "90007-gcp",
        "name": "클라우드 식별 — Google Cloud",
        "risk": "informational", "confidence": "firm",
        "description": "Google Cloud 인프라가 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-goog-request-id" in h or "x-google-backends" in h
                                      or "google frontend" in h.get("server","").lower(),
    },
    {
        "id": "90007-vercel",
        "name": "플랫폼 식별 — Vercel",
        "risk": "informational", "confidence": "certain",
        "description": "Vercel 배포 플랫폼이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-vercel-id" in h or "x-vercel-cache" in h
                                      or "vercel" in h.get("server","").lower(),
    },
    {
        "id": "90007-netlify",
        "name": "플랫폼 식별 — Netlify",
        "risk": "informational", "confidence": "certain",
        "description": "Netlify 배포 플랫폼이 식별되었습니다.",
        "solution": "불필요한 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "x-nf-request-id" in h or "netlify" in h.get("server","").lower(),
    },

    # ── 보안 장비 / 프록시 식별 ────────────────────────────────────────────────
    {
        "id": "90008-nginx-proxy",
        "name": "리버스 프록시 식별",
        "risk": "informational", "confidence": "tentative",
        "description": "리버스 프록시 또는 로드밸런서가 식별되었습니다.",
        "solution": "프록시 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "via" in h or "x-forwarded-server" in h
                                      or "x-proxy-id" in h,
    },
    {
        "id": "90008-f5",
        "name": "보안장비 식별 — F5 BIG-IP",
        "risk": "informational", "confidence": "firm",
        "description": "F5 BIG-IP 로드밸런서/WAF가 식별되었습니다.",
        "solution": "BIG-IP 버전 정보 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"\bts\w+=", h.get("set-cookie",""), re.I))
                                      or "bigipserver" in h.get("set-cookie","").lower(),
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
