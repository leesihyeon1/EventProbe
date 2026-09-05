"""
응답 분석 엔진 - WAF/IDS 차단 여부, 취약점 탐지, ZAP 스타일 Alert 생성
"""
import ast
import re
from typing import Optional
from urllib.parse import unquote


def _ver_lt(body: str, pattern: str, target: tuple) -> bool:
    """body 에서 pattern(캡처그룹1=버전)을 찾아 target 미만이면 True (취약 라이브러리 판정용)."""
    m = re.search(pattern, body or "", re.I)
    if not m:
        return False
    try:
        parts = tuple(int(x) for x in re.findall(r"\d+", m.group(1))[:3])
        return parts < target
    except Exception:
        return False


# ── WAF 차단 시그니처 ────────────────────────────────────────────────────────
# 오탐을 줄이기 위해 매칭 대상을 3가지로 분리:
#   header_names : 응답 "헤더 이름"에 부분일치 (전용 헤더)
#   cookies      : Set-Cookie 값에 부분일치 (전용 세션 쿠키)
#   server       : Server / Via / X-Powered-By / X-CDN 값에 부분일치 (제품명)
WAF_SIGNATURES = {
    "Cloudflare":   {"header_names": ["cf-ray", "cf-cache-status"], "cookies": ["__cfduid", "__cf_bm"], "server": ["cloudflare"]},
    "AWS WAF":      {"header_names": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-waf-action"], "cookies": ["awsalb", "awselb"], "server": []},
    "ModSecurity":  {"header_names": [], "cookies": [], "server": ["mod_security", "modsecurity"]},
    "Akamai":       {"header_names": ["x-akamai-transformed", "akamai-grn"], "cookies": ["ak_bmsc"], "server": ["akamaighost"]},
    "Imperva":      {"header_names": ["x-iinfo", "x-cdn"], "cookies": ["visid_incap", "incap_ses", "nlbi_"], "server": ["incapsula"]},
    "F5 BIG-IP":    {"header_names": ["x-waf-status"], "cookies": ["bigipserver", "ts01"], "server": ["big-ip", "bigip"]},
    "Barracuda":    {"header_names": [], "cookies": ["barra_counter_session"], "server": ["barracuda"]},
    "Fortinet":     {"header_names": ["x-waf-event-info"], "cookies": ["fortiwafsid"], "server": ["fortiweb", "fortigate"]},
    "Sucuri":       {"header_names": ["x-sucuri-id", "x-sucuri-cache"], "cookies": [], "server": ["sucuri"]},
    "Wordfence":    {"header_names": [], "cookies": [], "server": ["wordfence"]},
}


def detect_waf(headers_lower: dict) -> Optional[str]:
    """응답 헤더에서 WAF 제품을 탐지. 헤더 이름/전용 쿠키/제품명 기준으로만 매칭."""
    header_names = list(headers_lower.keys())
    server_blob = " ".join(
        headers_lower.get(h, "") for h in ("server", "via", "x-powered-by", "x-cdn")
    )
    set_cookie = headers_lower.get("set-cookie", "")
    for waf, sig in WAF_SIGNATURES.items():
        if any(hn in name for hn in sig["header_names"] for name in header_names):
            return waf
        if any(cv in set_cookie for cv in sig["cookies"]):
            return waf
        if any(sv in server_blob for sv in sig["server"]):
            return waf
    return None


# ── 기술 스택/인프라 지문 ─────────────────────────────────────────────────────
# (라벨, 유형, [(헤더명 부분일치, 값 정규식 | None)]). 하나라도 매칭되면 감지.
# 값이 None 이면 '그 이름을 포함하는 헤더가 존재'하는 것만으로 매칭(예: x-envoy-* 계열).
_STACK_SIGNATURES = [
    # 프록시 / 게이트웨이 / 서비스메시
    ("Envoy",          "프록시",       [("server", r"\benvoy\b"), ("x-envoy-", None)]),
    ("Istio",          "서비스 메시",  [("x-istio", None), ("server", r"istio")]),
    ("Kong",           "API 게이트웨이", [("server", r"kong"), ("via", r"kong"), ("x-kong-", None)]),
    ("Traefik",        "프록시",       [("server", r"traefik")]),
    ("HAProxy",        "프록시",       [("server", r"haproxy")]),
    ("Varnish",        "캐시 프록시",  [("via", r"varnish"), ("x-varnish", None)]),
    ("Apache Traffic Server", "캐시 프록시", [("server", r"ats/|trafficserver")]),
    # CDN
    ("Cloudflare",     "CDN",          [("cf-ray", None), ("server", r"cloudflare")]),
    ("Fastly",         "CDN",          [("via", r"fastly"), ("x-served-by", r"cache-"), ("x-fastly", None)]),
    ("Amazon CloudFront", "CDN",       [("via", r"cloudfront"), ("x-amz-cf-id", None)]),
    ("Akamai",         "CDN",          [("server", r"akamai"), ("x-akamai", None)]),
    ("Vercel",         "호스팅/CDN",   [("server", r"vercel"), ("x-vercel-", None)]),
    # 웹서버
    ("nginx",          "웹서버",       [("server", r"nginx|openresty")]),
    ("Apache",         "웹서버",       [("server", r"apache")]),
    ("IIS",            "웹서버",       [("server", r"microsoft-iis|iis/")]),
    ("LiteSpeed",      "웹서버",       [("server", r"litespeed")]),
    # 프레임워크 / 런타임
    ("Next.js",        "프레임워크",   [("x-powered-by", r"next\.?js"), ("x-nextjs-", None)]),
    ("Express",        "프레임워크",   [("x-powered-by", r"express")]),
    ("ASP.NET",        "프레임워크",   [("x-powered-by", r"asp\.net"), ("x-aspnet-version", None), ("x-aspnetmvc-version", None)]),
    ("PHP",            "런타임",       [("x-powered-by", r"php/")]),
    ("Ruby on Rails",  "프레임워크",   [("x-powered-by", r"phusion passenger"), ("x-runtime", None)]),
    ("Django",         "프레임워크",   [("server", r"wsgiserver"), ("x-frame-options", r"__django__never__")]),
    ("Spring",         "프레임워크",   [("x-application-context", None)]),
    ("Laravel",        "프레임워크",   [("set-cookie", r"laravel_session")]),
]


def detect_stack(headers_lower: dict) -> list:
    """응답 헤더에서 프록시·CDN·웹서버·프레임워크 등 기술 스택을 식별.

    반환: [{"name","kind","evidence"}]. Envoy(server 또는 x-envoy-*) 같은 인프라도 인식한다.
    """
    items = list(headers_lower.items())
    out, seen = [], set()
    for label, kind, checks in _STACK_SIGNATURES:
        for name_needle, val_re in checks:
            hit = None
            for hk, hv in items:
                if name_needle in hk and (val_re is None or re.search(val_re, hv, re.I)):
                    hit = (hk, hv)
                    break
            if hit and label not in seen:
                seen.add(label)
                ev = f"{hit[0]}: {hit[1][:60]}" if hit[1] else hit[0]
                out.append({"name": label, "kind": kind, "evidence": ev})
                break
    return out

# ── 차단 응답 바디 키워드 ────────────────────────────────────────────────────
BLOCK_KEYWORDS = [
    "blocked", "forbidden", "access denied", "not allowed",
    "security violation", "request blocked", "attack detected",
    "illegal request", "rejected", "차단", "금지", "접근 거부",
]
# 차단 상태코드(성공 코드와 구분)
_BLOCK_STATUS = (400, 403, 406, 429, 503)


def _body_signals_block(status_code: int, body: str, body_lower: str) -> bool:
    """바디의 차단 키워드를 '차단'으로 볼지 판단.

    차단 페이지는 대개 짧다. 상태코드가 200 같은 성공인데 응답이 크면(예: 84KB 정상
    페이지에 'forbidden' 단어가 우연히 포함) 차단으로 오판하지 않는다.
    """
    if not any(k in body_lower for k in BLOCK_KEYWORDS):
        return False
    if status_code in _BLOCK_STATUS:
        return True
    # 성공 상태코드에서는 '짧은 차단 페이지'일 때만 인정(대형 정상 페이지 오탐 방지)
    return len(body or "") < 4096

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

    # ══════════════════════════════════════════════════════════════════
    # 확장 룰 (OWASP Secure Headers / Nuclei / ZAP / gitleaks 기준)
    # ══════════════════════════════════════════════════════════════════

    # ── 추가 보안 헤더 ─────────────────────────────────────────────────
    {
        "id": "10063-referrer", "name": "Referrer-Policy 헤더 누락", "risk": "low", "confidence": "certain",
        "description": "Referrer-Policy 헤더가 없어 외부 사이트로 Referer 를 통한 정보 유출 가능성이 있습니다.",
        "solution": "Referrer-Policy: no-referrer 또는 strict-origin-when-cross-origin 을 설정하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "referrer-policy" not in h and s == 200,
    },
    {
        "id": "90004-coop", "name": "Cross-Origin-Opener-Policy 누락", "risk": "low", "confidence": "firm",
        "description": "COOP 헤더가 없어 교차 오리진 창 간 격리가 되지 않습니다(XS-Leaks/Spectre 노출).",
        "solution": "Cross-Origin-Opener-Policy: same-origin 을 설정하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "cross-origin-opener-policy" not in h and s == 200,
    },
    {
        "id": "90004-corp", "name": "Cross-Origin-Resource-Policy 누락", "risk": "informational", "confidence": "tentative",
        "description": "CORP 헤더가 없어 리소스가 타 오리진에 임베드될 수 있습니다.",
        "solution": "Cross-Origin-Resource-Policy: same-origin 을 검토하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "cross-origin-resource-policy" not in h and s == 200,
    },
    {
        "id": "10063-xpcdp", "name": "X-Permitted-Cross-Domain-Policies 누락", "risk": "informational", "confidence": "tentative",
        "description": "Adobe 크로스도메인 정책 제어 헤더가 없습니다.",
        "solution": "X-Permitted-Cross-Domain-Policies: none 을 설정하세요.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "check": lambda h, b, bl, s: "x-permitted-cross-domain-policies" not in h and s == 200,
    },
    {
        "id": "10098-cors-methods", "name": "CORS — Allow-Methods 와일드카드", "risk": "low", "confidence": "certain",
        "description": "Access-Control-Allow-Methods 가 * 로 모든 메서드를 허용합니다.",
        "solution": "필요한 메서드만 명시하세요.",
        "reference": "https://portswigger.net/web-security/cors",
        "check": lambda h, b, bl, s: h.get("access-control-allow-methods", "").strip() == "*",
    },
    {
        "id": "10098-cors-headers", "name": "CORS — Allow-Headers 와일드카드", "risk": "low", "confidence": "certain",
        "description": "Access-Control-Allow-Headers 가 * 로 모든 헤더를 허용합니다.",
        "solution": "허용 헤더를 제한하세요.",
        "reference": "https://portswigger.net/web-security/cors",
        "check": lambda h, b, bl, s: h.get("access-control-allow-headers", "").strip() == "*",
    },
    {
        "id": "10038-cspro", "name": "CSP 가 Report-Only 로만 설정", "risk": "medium", "confidence": "firm",
        "description": "Content-Security-Policy-Report-Only 만 있고 실제 강제(CSP)가 없어 XSS 를 차단하지 못합니다.",
        "solution": "테스트 후 Content-Security-Policy 로 강제 적용하세요.",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        "check": lambda h, b, bl, s: "content-security-policy-report-only" in h and "content-security-policy" not in h,
    },
    {
        "id": "10054-samesite-none", "name": "쿠키 SameSite=None + Secure 누락", "risk": "medium", "confidence": "firm",
        "description": "SameSite=None 쿠키에 Secure 가 없어 최신 브라우저에서 거부되거나 평문 전송됩니다.",
        "solution": "SameSite=None 쿠키에는 반드시 Secure 를 함께 설정하세요.",
        "reference": "https://owasp.org/www-community/SameSite",
        "check": lambda h, b, bl, s: "samesite=none" in h.get("set-cookie", "").lower()
                                      and "secure" not in h.get("set-cookie", "").lower(),
    },
    {
        "id": "10037-via", "name": "Via 헤더 — 프록시 정보 노출", "risk": "informational", "confidence": "certain",
        "description": lambda h, **_: f"Via 헤더로 프록시/캐시 정보가 노출됩니다: {h.get('via','')}",
        "solution": "Via 헤더 노출을 최소화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "via" in h,
    },

    # ── 시크릿/토큰 노출 (gitleaks 계열) ───────────────────────────────
    {
        "id": "secret-aws", "name": "AWS Access Key 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 AWS Access Key ID(AKIA…) 로 보이는 문자열이 있습니다.",
        "solution": "키를 즉시 폐기·회전하고 응답에서 제거하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", b or "")),
    },
    {
        "id": "secret-gcp", "name": "Google API Key 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 Google API 키(AIza…) 로 보이는 문자열이 있습니다.",
        "solution": "키를 폐기·제한하고 응답에서 제거하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"\bAIza[0-9A-Za-z_\-]{35}\b", b or "")),
    },
    {
        "id": "secret-github", "name": "GitHub 토큰 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 GitHub 토큰(ghp_/gho_/github_pat_) 이 노출됩니다.",
        "solution": "토큰을 폐기하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|github_pat_[0-9A-Za-z_]{22,}", b or "")),
    },
    {
        "id": "secret-slack", "name": "Slack 토큰/웹훅 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 Slack 토큰(xox…) 또는 웹훅 URL 이 노출됩니다.",
        "solution": "토큰/웹훅을 폐기하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"xox[baprs]-[0-9A-Za-z-]{10,}|hooks\.slack\.com/services/", b or "")),
    },
    {
        "id": "secret-stripe", "name": "Stripe 라이브 키 노출", "risk": "high", "confidence": "firm",
        "description": "응답에 Stripe 라이브 시크릿 키(sk_live_) 가 노출됩니다.",
        "solution": "키를 즉시 폐기하세요.",
        "reference": "https://github.com/gitleaks/gitleaks",
        "check": lambda h, b, bl, s: bool(re.search(r"\bsk_live_[0-9A-Za-z]{24,}\b|\brk_live_[0-9A-Za-z]{24,}\b", b or "")),
    },
    {
        "id": "secret-jwt", "name": "JWT 토큰 노출", "risk": "medium", "confidence": "firm",
        "description": "응답 본문에 JWT 로 보이는 토큰이 노출됩니다(민감 클레임·세션 가능).",
        "solution": "토큰이 본문에 노출되지 않도록 하세요.",
        "reference": "https://portswigger.net/web-security/jwt",
        "check": lambda h, b, bl, s: bool(re.search(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", b or "")),
    },
    {
        "id": "secret-pw-json", "name": "패스워드 필드 노출(JSON)", "risk": "high", "confidence": "tentative",
        "description": "응답 JSON 에 password/passwd 값이 평문으로 포함되어 있을 수 있습니다.",
        "solution": "비밀번호 등 민감 필드를 응답에서 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r'"(password|passwd|pwd)"\s*:\s*"[^"]{3,}"', b or "", re.I)),
    },

    # ── 프레임워크 디버그/에러 페이지 ──────────────────────────────────
    {
        "id": "debug-django", "name": "Django DEBUG 페이지 노출", "risk": "high", "confidence": "certain",
        "description": "Django 디버그 페이지가 노출되어 소스·설정·환경변수가 유출됩니다.",
        "solution": "프로덕션에서 DEBUG=False 로 설정하세요.",
        "reference": "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
        "check": lambda h, b, bl, s: "you're seeing this error because you have" in bl or "django.core.exceptions" in bl,
    },
    {
        "id": "debug-flask", "name": "Werkzeug/Flask 디버거 노출", "risk": "high", "confidence": "certain",
        "description": "Werkzeug 대화형 디버거가 노출됩니다. PIN 우회 시 원격 코드 실행이 가능합니다.",
        "solution": "프로덕션에서 디버그 모드를 끄세요.",
        "reference": "https://werkzeug.palletsprojects.com/",
        "check": lambda h, b, bl, s: "werkzeug debugger" in bl or "the console has been disabled" in bl,
    },
    {
        "id": "debug-rails", "name": "Rails 예외 페이지 노출", "risk": "high", "confidence": "certain",
        "description": "Rails 상세 예외 페이지가 노출되어 소스/스택이 유출됩니다.",
        "solution": "config.consider_all_requests_local = false 로 설정하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "action controller: exception caught" in bl or "actionview::template::error" in bl,
    },
    {
        "id": "debug-laravel", "name": "Laravel 디버그(Ignition) 노출", "risk": "high", "confidence": "certain",
        "description": "Laravel Whoops/Ignition 디버그 페이지가 노출됩니다(CVE-2021-3129 이력).",
        "solution": "APP_DEBUG=false 로 설정하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: ("whoops" in bl and "laravel" in bl) or "illuminate\\" in bl or "ignition" in bl and "laravel" in bl,
    },
    {
        "id": "debug-spring", "name": "Spring Whitelabel 에러 노출", "risk": "medium", "confidence": "firm",
        "description": "Spring Boot Whitelabel 에러 페이지가 노출됩니다(스택/버전 유출 가능).",
        "solution": "server.error.whitelabel.enabled=false 및 상세 에러 숨김.",
        "reference": "",
        "check": lambda h, b, bl, s: "whitelabel error page" in bl,
    },
    {
        "id": "debug-aspnet", "name": "ASP.NET 상세 오류(YSOD) 노출", "risk": "high", "confidence": "certain",
        "description": "ASP.NET 노란 오류 화면이 노출되어 스택/소스가 유출됩니다.",
        "solution": "customErrors mode=On, <deployment retail=true> 설정.",
        "reference": "",
        "check": lambda h, b, bl, s: "server error in '/' application" in bl and "stack trace" in bl,
    },
    {
        "id": "debug-symfony", "name": "Symfony 프로파일러/예외 노출", "risk": "medium", "confidence": "firm",
        "description": "Symfony 디버그 툴바/예외 페이지가 노출됩니다.",
        "solution": "APP_ENV=prod, APP_DEBUG=0 으로 설정하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "symfony\\component" in bl or "sf-toolbar" in bl or "x-debug-token" in h,
    },
    {
        "id": "debug-php", "name": "PHP 오류/경고 노출", "risk": "medium", "confidence": "firm",
        "description": "PHP Fatal/Warning/Notice 등 오류가 노출되어 경로·코드가 유출됩니다.",
        "solution": "display_errors=Off 로 설정하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"<b>(fatal error|warning|notice|parse error)</b>|on line <b>\d+</b>", bl)),
    },
    {
        "id": "debug-phpinfo", "name": "phpinfo() 노출", "risk": "high", "confidence": "certain",
        "description": "phpinfo() 출력이 노출되어 서버 구성 전체가 유출됩니다.",
        "solution": "phpinfo 페이지를 제거하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "phpinfo()" in bl or (">php version<" in bl and "configuration" in bl and "php credits" in bl),
    },

    # ── 노출 파일/디렉토리 ─────────────────────────────────────────────
    {
        "id": "expose-dirlist", "name": "디렉토리 리스팅 노출", "risk": "medium", "confidence": "firm",
        "description": "디렉토리 인덱스가 노출되어 파일 구조가 공개됩니다.",
        "solution": "Options -Indexes 등으로 디렉토리 리스팅을 비활성화하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: ("<title>index of /" in bl or "directory listing for" in bl) and "parent directory" in bl or "<title>index of /" in bl,
    },
    {
        "id": "expose-git", "name": ".git 저장소 노출", "risk": "high", "confidence": "certain",
        "description": ".git 설정/객체가 노출되어 전체 소스 복원이 가능합니다.",
        "solution": ".git 디렉토리 외부 접근을 차단하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "[core]" in bl and "repositoryformatversion" in bl,
    },
    {
        "id": "expose-env", "name": ".env 환경파일 노출", "risk": "critical", "confidence": "certain",
        "description": ".env 파일이 노출되어 DB/API 키 등 시크릿이 유출됩니다.",
        "solution": ".env 접근을 차단하고 노출된 시크릿을 폐기하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r"(app_key|db_password|db_username|aws_secret|secret_key)\s*=", bl)),
    },
    {
        "id": "expose-swagger", "name": "API 문서(Swagger/OpenAPI) 노출", "risk": "informational", "confidence": "firm",
        "description": "Swagger/OpenAPI 문서가 노출되어 전체 API 표면이 공개됩니다.",
        "solution": "프로덕션에서 API 문서 접근을 제한하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r'"swagger"\s*:|"openapi"\s*:|swagger-ui', bl)),
    },
    {
        "id": "expose-actuator", "name": "Spring Actuator 노출", "risk": "high", "confidence": "firm",
        "description": "Spring Boot Actuator 엔드포인트(env/heapdump 등)가 노출됩니다.",
        "solution": "management.endpoints 노출을 제한하고 인증을 적용하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: bool(re.search(r'"_links"\s*:.*"(env|health|heapdump|beans|mappings)"|activeprofiles', bl)),
    },
    {
        "id": "expose-ds-store", "name": ".DS_Store / 백업 흔적 노출", "risk": "low", "confidence": "tentative",
        "description": "OS/에디터 임시·백업 파일 흔적이 노출됩니다.",
        "solution": "불필요한 파일을 제거하고 접근을 차단하세요.",
        "reference": "",
        "check": lambda h, b, bl, s: "bud1" in bl and ".ds_store" in bl,
    },

    # ══════════════════════════════════════════════════════════════════
    # 2차 확장 — 시크릿 패턴 대량 / 기술 지문 / 노출 서비스 / 정보 유출
    # ══════════════════════════════════════════════════════════════════

    # ── 시크릿/토큰 (gitleaks 계열 다수) ───────────────────────────────
    {"id": "sec-openai", "name": "OpenAI API 키 노출", "risk": "high", "confidence": "firm",
     "description": "OpenAI 키(sk-…) 로 보이는 문자열 노출.", "solution": "키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b|\bsk-proj-[A-Za-z0-9_-]{20,}\b", b or ""))},
    {"id": "sec-anthropic", "name": "Anthropic API 키 노출", "risk": "high", "confidence": "firm",
     "description": "Anthropic 키(sk-ant-…) 노출.", "solution": "키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", b or ""))},
    {"id": "sec-gitlab", "name": "GitLab PAT 노출", "risk": "high", "confidence": "firm",
     "description": "GitLab Personal Access Token(glpat-…) 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bglpat-[A-Za-z0-9_-]{20}\b", b or ""))},
    {"id": "sec-twilio", "name": "Twilio 자격증명 노출", "risk": "high", "confidence": "firm",
     "description": "Twilio Account SID/Auth Token 노출.", "solution": "자격증명 회전.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bAC[a-z0-9]{32}\b|\bSK[a-z0-9]{32}\b", b or "", re.I)) and "twilio" in bl},
    {"id": "sec-sendgrid", "name": "SendGrid API 키 노출", "risk": "high", "confidence": "firm",
     "description": "SendGrid 키(SG.…) 노출.", "solution": "키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", b or ""))},
    {"id": "sec-mailgun", "name": "Mailgun API 키 노출", "risk": "high", "confidence": "firm",
     "description": "Mailgun 키(key-…) 노출.", "solution": "키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bkey-[0-9a-f]{32}\b", b or "")) and "mailgun" in bl},
    {"id": "sec-square", "name": "Square 액세스 토큰 노출", "risk": "high", "confidence": "firm",
     "description": "Square 토큰(sq0atp/EAAA…) 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bsq0(atp|csp)-[A-Za-z0-9_-]{22,}\b|\bEAAA[A-Za-z0-9]{60}\b", b or ""))},
    {"id": "sec-paypal", "name": "PayPal Braintree 토큰 노출", "risk": "high", "confidence": "firm",
     "description": "Braintree 액세스 토큰 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", b or ""))},
    {"id": "sec-npm", "name": "npm 토큰 노출", "risk": "high", "confidence": "firm",
     "description": "npm 토큰(npm_…) 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bnpm_[A-Za-z0-9]{36}\b", b or ""))},
    {"id": "sec-heroku", "name": "Heroku API 키 노출", "risk": "high", "confidence": "tentative",
     "description": "Heroku API 키(UUID) 노출 의심.", "solution": "키 회전.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: "heroku" in bl and bool(re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", b or ""))},
    {"id": "sec-cloudflare", "name": "Cloudflare API 토큰 노출", "risk": "high", "confidence": "tentative",
     "description": "Cloudflare API 토큰 노출 의심.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: "cloudflare" in bl and bool(re.search(r"\b[A-Za-z0-9_-]{40}\b", b or "")) and "api_token" in bl},
    {"id": "sec-discord", "name": "Discord 토큰/웹훅 노출", "risk": "medium", "confidence": "firm",
     "description": "Discord 봇 토큰 또는 웹훅 URL 노출.", "solution": "폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"discord(app)?\.com/api/webhooks/\d+/", b or "")) or bool(re.search(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b", b or ""))},
    {"id": "sec-telegram", "name": "Telegram 봇 토큰 노출", "risk": "medium", "confidence": "firm",
     "description": "Telegram 봇 토큰 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", b or ""))},
    {"id": "sec-facebook", "name": "Facebook 액세스 토큰 노출", "risk": "medium", "confidence": "tentative",
     "description": "Facebook 토큰(EAACEdEose…) 노출.", "solution": "토큰 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"\bEAACEdEose0cBA[0-9A-Za-z]+\b", b or ""))},
    {"id": "sec-gcp-sa", "name": "GCP 서비스계정 키(JSON) 노출", "risk": "critical", "confidence": "certain",
     "description": "GCP 서비스계정 키 JSON(private_key 포함) 노출.", "solution": "즉시 키 폐기.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: '"type": "service_account"' in bl or ('"private_key_id"' in bl and '"client_email"' in bl)},
    {"id": "sec-azure-storage", "name": "Azure Storage 키/연결문자열 노출", "risk": "high", "confidence": "firm",
     "description": "Azure Storage 연결문자열/AccountKey 노출.", "solution": "키 회전.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: "accountkey=" in bl and "core.windows.net" in bl},
    {"id": "sec-s3url", "name": "S3 버킷 URL/리스팅 노출", "risk": "medium", "confidence": "firm",
     "description": "S3 버킷 리스팅(XML) 또는 버킷 URL 노출.", "solution": "버킷 권한을 검토하세요.", "reference": "",
     "check": lambda h, b, bl, s: "<listbucketresult" in bl or bool(re.search(r"[a-z0-9.-]+\.s3\.amazonaws\.com", bl))},
    {"id": "sec-basicurl", "name": "URL 내 자격증명 노출", "risk": "high", "confidence": "firm",
     "description": "응답에 user:pass@host 형태의 자격증명 포함 URL 이 있습니다.", "solution": "자격증명 제거.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"[a-z]+://[^/\s:@]+:[^/\s:@]+@[a-z0-9.-]+", b or "", re.I))},
    {"id": "sec-generic-key", "name": "일반 API/시크릿 키 할당 노출", "risk": "medium", "confidence": "tentative",
     "description": "api_key/secret/token 등에 값이 하드코딩된 형태가 노출됩니다.", "solution": "시크릿을 응답/코드에서 제거.", "reference": "https://github.com/gitleaks/gitleaks",
     "check": lambda h, b, bl, s: bool(re.search(r"(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", b or "", re.I))},
    {"id": "sec-authbearer", "name": "응답 내 Authorization Bearer 노출", "risk": "medium", "confidence": "tentative",
     "description": "응답 본문에 Authorization: Bearer 토큰이 노출됩니다.", "solution": "토큰 노출 제거.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"authorization['\"]?\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._-]{16,}", b or "", re.I))},

    # ── 노출 서비스/패널 ───────────────────────────────────────────────
    {"id": "svc-phpmyadmin", "name": "phpMyAdmin 노출", "risk": "medium", "confidence": "firm",
     "description": "phpMyAdmin 로그인/패널 노출.", "solution": "접근을 제한하세요.", "reference": "",
     "check": lambda h, b, bl, s: "phpmyadmin" in bl and ("pma_username" in bl or "phpmyadmin" in bl and "login" in bl)},
    {"id": "svc-adminer", "name": "Adminer 노출", "risk": "medium", "confidence": "firm",
     "description": "Adminer DB 관리 도구 노출.", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "adminer" in bl and "login" in bl},
    {"id": "svc-jenkins", "name": "Jenkins 노출", "risk": "medium", "confidence": "firm",
     "description": "Jenkins 대시보드 노출.", "solution": "인증/접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "x-jenkins" in h or "jenkins" in bl and "dashboard" in bl},
    {"id": "svc-grafana", "name": "Grafana 노출", "risk": "low", "confidence": "firm",
     "description": "Grafana 인스턴스 노출.", "solution": "인증/접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "grafana" in bl and ("grafanabootdata" in bl or "grafana" in h.get("set-cookie",""))},
    {"id": "svc-kibana", "name": "Kibana/Elasticsearch 노출", "risk": "medium", "confidence": "firm",
     "description": "Kibana 또는 Elasticsearch 정보가 노출됩니다.", "solution": "인증/접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "kbn-name" in h or '"cluster_name"' in bl or "kibana" in bl and "bootstrap" in bl},
    {"id": "svc-prometheus", "name": "Prometheus/메트릭 노출", "risk": "low", "confidence": "firm",
     "description": "Prometheus 메트릭 엔드포인트 노출.", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"# help \w+|# type \w+ (counter|gauge|histogram)", bl))},
    {"id": "svc-apachestatus", "name": "Apache server-status 노출", "risk": "medium", "confidence": "firm",
     "description": "mod_status(server-status) 가 노출되어 요청/워커 정보가 유출됩니다.", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "apache server status" in bl or ("server uptime" in bl and "requests currently being processed" in bl)},
    {"id": "svc-nginxstatus", "name": "Nginx stub_status 노출", "risk": "low", "confidence": "firm",
     "description": "Nginx stub_status 노출.", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "active connections:" in bl and "server accepts handled requests" in bl},
    {"id": "svc-wp-users", "name": "WordPress 사용자 열거(wp-json)", "risk": "medium", "confidence": "firm",
     "description": "wp-json/wp/v2/users 로 사용자 목록이 노출됩니다.", "solution": "REST users 엔드포인트를 제한하세요.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'"slug"\s*:.*"wp:author"|/wp-json/wp/v2/users', bl))},
    {"id": "svc-securitytxt", "name": "security.txt 존재", "risk": "informational", "confidence": "certain",
     "description": "security.txt 가 존재합니다(정보).", "solution": "정상적인 보안 연락처 공개입니다.", "reference": "https://securitytxt.org/",
     "check": lambda h, b, bl, s: "contact:" in bl and ("expires:" in bl or "encryption:" in bl) and len(bl) < 4000},

    # ── 추가 기술 지문 (Wappalyzer 계열) ──────────────────────────────
    {"id": "fp-jquery", "name": "라이브러리 식별 — jQuery", "risk": "informational", "confidence": "firm",
     "description": lambda h, **_: "jQuery 사용 감지.", "solution": "구버전 시 알려진 XSS 취약점 확인.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"jquery[.-]?\d|jquery\.min\.js|jquery\.js", bl))},
    {"id": "fp-react", "name": "프레임워크 식별 — React", "risk": "informational", "confidence": "firm",
     "description": "React 사용 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "data-reactroot" in bl or "react-dom" in bl or "__react" in bl},
    {"id": "fp-vue", "name": "프레임워크 식별 — Vue.js", "risk": "informational", "confidence": "firm",
     "description": "Vue.js 사용 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "data-v-" in bl or "vue.js" in bl or "__vue__" in bl},
    {"id": "fp-angular", "name": "프레임워크 식별 — Angular", "risk": "informational", "confidence": "firm",
     "description": "Angular 사용 감지.", "solution": "AngularJS 구버전은 CSTI 위험.", "reference": "",
     "check": lambda h, b, bl, s: "ng-version" in bl or "ng-app" in bl or "angular.js" in bl},
    {"id": "fp-bootstrap", "name": "라이브러리 식별 — Bootstrap", "risk": "informational", "confidence": "tentative",
     "description": "Bootstrap 사용 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "bootstrap.min.css" in bl or "bootstrap.min.js" in bl},
    {"id": "fp-ga", "name": "분석도구 — Google Analytics/GTM", "risk": "informational", "confidence": "firm",
     "description": "Google Analytics/Tag Manager 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "googletagmanager.com/gtm" in bl or "google-analytics.com/analytics" in bl or "gtag(" in bl},
    {"id": "fp-sentry", "name": "모니터링 — Sentry", "risk": "informational", "confidence": "firm",
     "description": "Sentry DSN/SDK 감지(DSN 노출 시 이벤트 위조 가능).", "solution": "공개 DSN 노출 검토.", "reference": "",
     "check": lambda h, b, bl, s: "sentry-cdn" in bl or "@sentry" in bl or bool(re.search(r"https://[0-9a-f]+@[a-z0-9.]*sentry", bl))},
    {"id": "fp-cloudfront-h", "name": "CDN 식별 — CloudFront(헤더)", "risk": "informational", "confidence": "firm",
     "description": "AWS CloudFront 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "x-amz-cf-id" in h or "cloudfront" in h.get("via","")},
    {"id": "fp-openresty", "name": "서버 식별 — OpenResty", "risk": "informational", "confidence": "certain",
     "description": "OpenResty(Nginx+Lua) 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "openresty" in h.get("server","")},
    {"id": "fp-kestrel", "name": "서버 식별 — Kestrel(.NET)", "risk": "informational", "confidence": "certain",
     "description": "Kestrel(.NET Core) 감지.", "solution": "리버스 프록시 뒤 배치 권장.", "reference": "",
     "check": lambda h, b, bl, s: "kestrel" in h.get("server","")},
    {"id": "fp-ghost", "name": "CMS 식별 — Ghost", "risk": "informational", "confidence": "firm",
     "description": "Ghost CMS 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "ghost" in h.get("x-powered-by","") or "content=\"ghost" in bl},
    {"id": "fp-mediawiki", "name": "플랫폼 식별 — MediaWiki", "risk": "informational", "confidence": "firm",
     "description": "MediaWiki 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "mediawiki" in bl or "x-powered-by" in h and "mediawiki" in h.get("x-powered-by","")},
    {"id": "fp-atlassian", "name": "플랫폼 식별 — Atlassian(Jira/Confluence)", "risk": "informational", "confidence": "firm",
     "description": "Jira/Confluence 감지.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "atl-traceid" in h or "x-confluence-request-time" in h or "jira.webresources" in bl},

    # ── 추가 정보 유출/설정 ────────────────────────────────────────────
    {"id": "info-xruntime", "name": "X-Runtime — 응답시간 노출(Rails)", "risk": "informational", "confidence": "certain",
     "description": "X-Runtime 헤더로 처리시간이 노출됩니다(타이밍 공격 보조).", "solution": "헤더 제거.", "reference": "",
     "check": lambda h, b, bl, s: "x-runtime" in h},
    {"id": "info-xgenerator", "name": "X-Generator/Generator — 제품·버전 노출", "risk": "low", "confidence": "certain",
     "description": lambda h, **_: f"Generator 정보 노출: {h.get('x-generator','')}", "solution": "제거.", "reference": "",
     "check": lambda h, b, bl, s: "x-generator" in h or bool(re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']+', bl))},
    {"id": "info-xdrupal", "name": "Drupal 캐시/동적 헤더 노출", "risk": "informational", "confidence": "firm",
     "description": "X-Drupal-* 헤더 노출.", "solution": "-", "reference": "",
     "check": lambda h, b, bl, s: "x-drupal-cache" in h or "x-drupal-dynamic-cache" in h},
    {"id": "info-xpingback", "name": "WordPress XML-RPC(Pingback) 노출", "risk": "low", "confidence": "certain",
     "description": "X-Pingback 헤더로 xmlrpc.php 노출(무차별/증폭 악용).", "solution": "xmlrpc 비활성화 검토.", "reference": "",
     "check": lambda h, b, bl, s: "x-pingback" in h or "xmlrpc.php" in bl},
    {"id": "info-etag-inode", "name": "ETag inode 노출(Apache)", "risk": "informational", "confidence": "tentative",
     "description": "ETag 에 inode 정보가 포함되어 있을 수 있습니다.", "solution": "FileETag MTime Size 로 변경.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'^"?[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"?$', h.get("etag","")))},
    {"id": "info-xssprotection-off", "name": "X-XSS-Protection 비활성(0)", "risk": "low", "confidence": "firm",
     "description": "X-XSS-Protection: 0 으로 브라우저 XSS 필터를 끕니다(레거시).", "solution": "CSP 로 대체 권장.", "reference": "",
     "check": lambda h, b, bl, s: h.get("x-xss-protection","").strip().startswith("0")},
    {"id": "info-allow-dangerous", "name": "위험 HTTP 메서드 허용(Allow)", "risk": "medium", "confidence": "firm",
     "description": lambda h, **_: f"Allow 헤더에 위험 메서드 노출: {h.get('allow','')}", "solution": "PUT/DELETE/TRACE 등 불필요 메서드 비활성화.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"\b(put|delete|trace|connect|patch)\b", h.get("allow","")))},
    {"id": "info-session-url", "name": "세션 ID URL 노출", "risk": "medium", "confidence": "firm",
     "description": "URL 에 세션 ID(jsessionid/phpsessid 등)가 노출됩니다.", "solution": "세션을 쿠키로만 전달하세요.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"(jsessionid|phpsessid|sid|sessionid)=[A-Za-z0-9]{8,}", bl))},
    {"id": "info-insecure-form", "name": "폼 action 이 평문(http) 전송", "risk": "medium", "confidence": "firm",
     "description": "form action 이 http:// 로 민감정보가 평문 전송될 수 있습니다.", "solution": "https 로 변경하세요.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'<form[^>]+action=["\']http://', bl))},
    {"id": "info-pw-autocomplete", "name": "패스워드 필드 autocomplete 미차단", "risk": "low", "confidence": "tentative",
     "description": "password 입력에 autocomplete=off 가 없어 브라우저 저장 위험.", "solution": "민감 필드에 autocomplete=off.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'<input[^>]+type=["\']?password["\']?(?![^>]*autocomplete)', bl))},
    {"id": "info-private-ip-body", "name": "내부 IP 노출(본문)", "risk": "low", "confidence": "tentative",
     "description": "응답 본문에 사설 IP 대역이 노출됩니다.", "solution": "내부 IP 노출을 제거하세요.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b", b or ""))},

    # ── 추가 DB/스택트레이스 ───────────────────────────────────────────
    {"id": "err-db2", "name": "DB2 에러 노출", "risk": "medium", "confidence": "firm",
     "description": "IBM DB2 오류 메시지 노출.", "solution": "상세 오류 숨김.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"sql\d{4}n|db2 sql error", bl))},
    {"id": "err-sybase", "name": "Sybase/ASE 에러 노출", "risk": "medium", "confidence": "firm",
     "description": "Sybase 오류 메시지 노출.", "solution": "상세 오류 숨김.", "reference": "",
     "check": lambda h, b, bl, s: "sybase message" in bl or "com.sybase.jdbc" in bl},
    {"id": "err-go-panic", "name": "Go 패닉/스택 노출", "risk": "medium", "confidence": "firm",
     "description": "Go 런타임 패닉 스택이 노출됩니다.", "solution": "recover 로 처리하고 상세 노출 제거.", "reference": "",
     "check": lambda h, b, bl, s: "goroutine " in bl and "runtime.gopanic" in bl or "panic: runtime error" in bl},
    {"id": "err-dotnet-stack", "name": ".NET 스택트레이스 노출", "risk": "medium", "confidence": "firm",
     "description": ".NET 예외/스택이 노출됩니다.", "solution": "customErrors 로 상세 숨김.", "reference": "",
     "check": lambda h, b, bl, s: "system.web." in bl and "at system." in bl or "microsoft.aspnetcore" in bl and "stack trace" in bl},

    # ══════════════════════════════════════════════════════════════════
    # 3차 확장 — 취약 라이브러리(Retire.js) / 제품 CVE 지문 / 노출 파일 추가
    # ══════════════════════════════════════════════════════════════════

    # ── 취약/구버전 라이브러리 (Retire.js 계열, tentative) ─────────────
    {"id": "lib-jquery-old", "name": "취약 jQuery(<3.5.0)", "risk": "medium", "confidence": "tentative",
     "description": "jQuery 3.5.0 미만은 XSS(CVE-2020-11022/11023) 취약.", "solution": "jQuery 3.5+ 로 업그레이드.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"jquery[/-]?(\d+\.\d+\.\d+)", (3, 5, 0))},
    {"id": "lib-angularjs", "name": "AngularJS(1.x) — EOL/CSTI 위험", "risk": "medium", "confidence": "tentative",
     "description": "AngularJS 1.x 는 지원 종료·클라이언트 템플릿 인젝션 위험.", "solution": "최신 Angular 로 마이그레이션.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"angular[.-]?(1\.\d+\.\d+)", (2, 0, 0))},
    {"id": "lib-bootstrap-old", "name": "취약 Bootstrap(<3.4/<4.3.1)", "risk": "low", "confidence": "tentative",
     "description": "구버전 Bootstrap XSS(CVE-2019-8331 등).", "solution": "최신 Bootstrap 사용.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"bootstrap[/-]?(\d+\.\d+\.\d+)", (4, 3, 1))},
    {"id": "lib-lodash-old", "name": "취약 Lodash(<4.17.21)", "risk": "medium", "confidence": "tentative",
     "description": "구버전 Lodash 프로토타입 오염(CVE-2020-8203 등).", "solution": "lodash 4.17.21+.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"lodash[/-]?(\d+\.\d+\.\d+)", (4, 17, 21))},
    {"id": "lib-moment-old", "name": "취약 Moment.js(<2.29.4)", "risk": "low", "confidence": "tentative",
     "description": "구버전 moment.js ReDoS/경로 취약.", "solution": "moment 2.29.4+ 또는 대체.", "reference": "https://retirejs.github.io/retire.js/",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"moment[/-]?(\d+\.\d+\.\d+)", (2, 29, 4))},
    {"id": "lib-vue2-eol", "name": "Vue 2 — EOL", "risk": "low", "confidence": "tentative",
     "description": "Vue 2.x 는 지원 종료.", "solution": "Vue 3 마이그레이션.", "reference": "",
     "check": lambda h, b, bl, s: _ver_lt(bl, r"vue[/-]?(2\.\d+\.\d+)", (3, 0, 0))},

    # ── 제품/CVE 지문 ─────────────────────────────────────────────────
    {"id": "cve-struts", "name": "Apache Struts 흔적", "risk": "medium", "confidence": "tentative",
     "description": "Struts(.action/.do) 흔적 — CVE-2017-5638(RCE) 등 이력.", "solution": "최신 패치 적용.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r"\.action(\?|\"|')|struts\.token|org\.apache\.struts", bl))},
    {"id": "cve-weblogic", "name": "Oracle WebLogic 콘솔 노출", "risk": "high", "confidence": "tentative",
     "description": "WebLogic 콘솔/uddiexplorer 노출 — 다수 RCE(CVE-2020-14882 등).", "solution": "콘솔 접근 제한·패치.", "reference": "",
     "check": lambda h, b, bl, s: "weblogic" in bl and ("console" in bl or "uddiexplorer" in bl)},
    {"id": "cve-exchange", "name": "MS Exchange OWA/ECP 노출", "risk": "medium", "confidence": "tentative",
     "description": "Exchange OWA/ECP/Autodiscover 노출 — ProxyLogon 등 이력.", "solution": "패치·접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: "x-owa-version" in h or "/owa/auth" in bl or "outlook web app" in bl},
    {"id": "cve-citrix", "name": "Citrix ADC/Gateway 흔적", "risk": "medium", "confidence": "tentative",
     "description": "Citrix Netscaler/Gateway 흔적 — CVE-2019-19781/CVE-2023-4966 이력.", "solution": "패치.", "reference": "",
     "check": lambda h, b, bl, s: "ns_af" in h.get("set-cookie","") or "citrix" in bl and "gateway" in bl or "/vpn/index.html" in bl},
    {"id": "cve-confluence", "name": "Atlassian Confluence 노출", "risk": "medium", "confidence": "tentative",
     "description": "Confluence 노출 — OGNL RCE(CVE-2021-26084/CVE-2022-26134) 이력.", "solution": "패치.", "reference": "",
     "check": lambda h, b, bl, s: "confluence" in bl and ("x-confluence-request-time" in h or "com.atlassian.confluence" in bl)},
    {"id": "cve-gitlab", "name": "GitLab 노출", "risk": "low", "confidence": "tentative",
     "description": "GitLab 노출 — 다수 취약점 이력.", "solution": "최신 버전 유지.", "reference": "",
     "check": lambda h, b, bl, s: "gitlab" in bl and ("gitlab_session" in h.get("set-cookie","") or "gon.gitlab" in bl)},
    {"id": "cve-spring4shell", "name": "Spring 프레임워크(Spring4Shell 표면)", "risk": "low", "confidence": "tentative",
     "description": "Spring MVC/WebFlux 흔적 — CVE-2022-22965(Spring4Shell) 대상 가능.", "solution": "Spring 패치 확인.", "reference": "",
     "check": lambda h, b, bl, s: "org.springframework" in bl and ("bindingresult" in bl or "class.module" in bl)},
    {"id": "cve-log4shell-refl", "name": "Log4Shell 페이로드 반사", "risk": "medium", "confidence": "tentative",
     "description": "응답에 ${jndi:...} 페이로드가 반사됩니다(로그 인젝션 표면).", "solution": "Log4j 패치.", "reference": "",
     "check": lambda h, b, bl, s: "${jndi:" in bl or "jndi:ldap" in bl},
    {"id": "svc-solr", "name": "Apache Solr 노출", "risk": "medium", "confidence": "firm",
     "description": "Solr 관리/쿼리 노출 — RCE 이력.", "solution": "접근 제한·패치.", "reference": "",
     "check": lambda h, b, bl, s: '"responseheader"' in bl and ("solr" in bl or '"qtime"' in bl)},
    {"id": "svc-couchdb", "name": "CouchDB/Redis 등 DB 응답 노출", "risk": "medium", "confidence": "tentative",
     "description": "CouchDB/Redis/Mongo 등의 응답 흔적이 노출됩니다.", "solution": "인증·접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: '"couchdb":"welcome"' in bl or "redis_version:" in bl or '"ismaster"' in bl},

    # ── 노출 파일/설정 추가 ────────────────────────────────────────────
    {"id": "expose-webconfig", "name": "web.config 노출", "risk": "high", "confidence": "firm",
     "description": "IIS web.config 노출 — 연결문자열/설정 유출.", "solution": "접근 차단.", "reference": "",
     "check": lambda h, b, bl, s: "<configuration>" in bl and ("<connectionstrings" in bl or "<system.web" in bl)},
    {"id": "expose-htaccess", "name": ".htaccess/.htpasswd 노출", "risk": "high", "confidence": "firm",
     "description": ".htaccess/.htpasswd 노출.", "solution": "접근 차단.", "reference": "",
     "check": lambda h, b, bl, s: "rewriteengine" in bl or bool(re.search(r"^[a-z0-9_-]+:\$apr1\$", b or "", re.I | re.M))},
    {"id": "expose-composer", "name": "composer.json/lock 노출", "risk": "low", "confidence": "firm",
     "description": "PHP composer 의존성 파일 노출(구성/버전 유출).", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: '"require"' in bl and ("composer" in bl or '"packages"' in bl and '"dist"' in bl)},
    {"id": "expose-packagejson", "name": "package.json 노출", "risk": "low", "confidence": "firm",
     "description": "Node package.json 노출(의존성/스크립트 유출).", "solution": "접근 제한.", "reference": "",
     "check": lambda h, b, bl, s: '"dependencies"' in bl and '"scripts"' in bl and '"name"' in bl},
    {"id": "expose-npmrc", "name": ".npmrc/.pypirc 노출", "risk": "high", "confidence": "firm",
     "description": ".npmrc/.pypirc 노출(레지스트리 토큰 유출 가능).", "solution": "접근 차단·토큰 폐기.", "reference": "",
     "check": lambda h, b, bl, s: "_authtoken" in bl or "//registry.npmjs.org/:_authToken".lower() in bl or "[pypi]" in bl and "password" in bl},
    {"id": "expose-wpconfig", "name": "wp-config 백업 노출", "risk": "critical", "confidence": "firm",
     "description": "wp-config 백업 노출 — DB 자격증명/솔트 유출.", "solution": "즉시 제거·자격증명 변경.", "reference": "",
     "check": lambda h, b, bl, s: "db_password" in bl and "wp_" in bl and "define(" in bl},
    {"id": "expose-sourcemap", "name": "JS 소스맵 파일 노출", "risk": "low", "confidence": "firm",
     "description": ".map 소스맵이 노출되어 원본 소스가 복원될 수 있습니다.", "solution": "프로덕션 소스맵 제거.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'\{"version"\s*:\s*3\s*,\s*"(file|sources|mappings)"', bl)) or "x-sourcemap" in h},
    {"id": "expose-idea", "name": "IDE 설정(.idea/.vscode) 노출", "risk": "low", "confidence": "tentative",
     "description": "IDE 프로젝트 설정 노출.", "solution": "접근 차단.", "reference": "",
     "check": lambda h, b, bl, s: "<project version" in bl and "component name" in bl or "workspace.xml" in bl},
    {"id": "expose-backup-archive", "name": "백업 아카이브 노출(.sql/.zip/.tar.gz)", "risk": "medium", "confidence": "tentative",
     "description": "본문/링크에 백업 아카이브 참조가 있습니다.", "solution": "백업 파일을 웹 루트 밖으로 이동.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'href=["\'][^"\']+\.(sql|zip|tar\.gz|tgz|bak|7z|rar)\b', bl))},
    {"id": "expose-crossdomain", "name": "crossdomain.xml 과대 허용", "risk": "medium", "confidence": "firm",
     "description": "crossdomain.xml 이 * 로 모든 도메인을 허용합니다.", "solution": "허용 도메인을 제한하세요.", "reference": "",
     "check": lambda h, b, bl, s: "cross-domain-policy" in bl and 'domain="*"' in bl},

    # ── 디버그/에러 추가 ───────────────────────────────────────────────
    {"id": "debug-nextjs", "name": "Next.js 에러/디버그 노출", "risk": "low", "confidence": "tentative",
     "description": "Next.js 상세 에러 오버레이/스택 노출.", "solution": "프로덕션 빌드로 배포.", "reference": "",
     "check": lambda h, b, bl, s: "__next_error__" in bl or ("nextjs" in bl and "call stack" in bl)},
    {"id": "debug-nuxt", "name": "Nuxt 에러 노출", "risk": "low", "confidence": "tentative",
     "description": "Nuxt 에러 페이지/스택 노출.", "solution": "프로덕션 설정.", "reference": "",
     "check": lambda h, b, bl, s: "nuxt" in bl and "stack" in bl and "statuscode" in bl},
    {"id": "debug-phoenix", "name": "Elixir/Phoenix 디버그 노출", "risk": "medium", "confidence": "tentative",
     "description": "Phoenix 상세 예외 페이지 노출.", "solution": "prod 설정으로 상세 숨김.", "reference": "",
     "check": lambda h, b, bl, s: "phoenix" in bl and ("plug.conn" in bl or "stacktrace" in bl)},
    {"id": "debug-graphql-verbose", "name": "GraphQL 상세 에러 노출", "risk": "low", "confidence": "tentative",
     "description": "GraphQL 응답에 상세 스택/디버그 에러가 포함됩니다.", "solution": "프로덕션에서 에러 마스킹.", "reference": "",
     "check": lambda h, b, bl, s: '"errors"' in bl and ("stacktrace" in bl or '"exception"' in bl)},
    {"id": "debug-node-stack", "name": "Node.js 스택트레이스 노출", "risk": "medium", "confidence": "firm",
     "description": "Node.js 예외 스택이 노출됩니다.", "solution": "상세 에러를 사용자에게 노출하지 마세요.", "reference": "",
     "check": lambda h, b, bl, s: "at object.<anonymous>" in bl or bool(re.search(r"at [\w.]+ \([^)]+:\d+:\d+\)", bl))},

    # ── 헤더/직렬화 추가 ───────────────────────────────────────────────
    {"id": "hdr-server-timing", "name": "Server-Timing 헤더 노출", "risk": "informational", "confidence": "certain",
     "description": "Server-Timing 으로 내부 처리시간/구성이 노출됩니다.", "solution": "프로덕션에서 상세 제거.", "reference": "",
     "check": lambda h, b, bl, s: "server-timing" in h},
    {"id": "hdr-deprecated-sec", "name": "폐기된 보안 헤더 사용", "risk": "informational", "confidence": "firm",
     "description": "Public-Key-Pins/Expect-CT/Feature-Policy 등 폐기된 헤더 사용.", "solution": "최신 대체 헤더(CSP/Permissions-Policy)로 전환.", "reference": "",
     "check": lambda h, b, bl, s: "public-key-pins" in h or "expect-ct" in h or "feature-policy" in h},
    {"id": "ser-java", "name": "Java 직렬화 객체 노출", "risk": "medium", "confidence": "firm",
     "description": "응답에 Java 직렬화 데이터(rO0AB / aced0005)가 노출됩니다.", "solution": "직렬화 데이터 노출 제거·역직렬화 보안 검토.", "reference": "",
     "check": lambda h, b, bl, s: "ro0ab" in bl or "\xac\xed\x00\x05" in (b or "")},
    {"id": "ser-php", "name": "PHP 직렬화 객체 노출", "risk": "low", "confidence": "tentative",
     "description": "응답에 PHP 직렬화 객체(O:n:) 흔적이 있습니다.", "solution": "역직렬화 입력 검증.", "reference": "",
     "check": lambda h, b, bl, s: bool(re.search(r'O:\d+:"[a-z_][\w]*":\d+:\{', b or "", re.I))},
    {"id": "leak-viewstate", "name": "ASP.NET ViewState 노출", "risk": "informational", "confidence": "firm",
     "description": "__VIEWSTATE 가 노출됩니다(MAC 미적용 시 역직렬화 위험).", "solution": "ViewState MAC/암호화 적용.", "reference": "",
     "check": lambda h, b, bl, s: "__viewstate" in bl and "value=" in bl},

    # ── 클라우드 메타데이터 응답(SSRF 성공 흔적) ───────────────────────
    {"id": "cloud-aws-meta", "name": "AWS 메타데이터 응답 노출", "risk": "critical", "confidence": "firm",
     "description": "응답에 AWS 메타데이터/IAM 자격증명 흔적이 있습니다(SSRF 성공 가능).", "solution": "SSRF 차단·IMDSv2 강제.", "reference": "",
     "check": lambda h, b, bl, s: "iam/security-credentials" in bl or "instance-identity" in bl or ('"accesskeyid"' in bl and '"secretaccesskey"' in bl)},
    {"id": "cloud-gcp-meta", "name": "GCP 메타데이터 응답 노출", "risk": "critical", "confidence": "firm",
     "description": "GCP 메타데이터 흔적이 있습니다(SSRF 성공 가능).", "solution": "SSRF 차단.", "reference": "",
     "check": lambda h, b, bl, s: "computemetadata" in bl or "metadata.google.internal" in bl},
]


# ════════════════════════════════════════════════════════════════════════════════
# ALERT 증거 추출 — 각 룰의 check 람다에서 정규식/문자열/헤더 키를 정적 분석으로 뽑아,
# 매칭 시 "응답에서 실제로 탐지된 문자열"을 evidence 로 함께 반환한다(사용자가 검색·검증용).
# 룰 196개를 수정하지 않고, 이 파일 소스를 AST 로 한 번만 파싱해 인덱스를 만든다.
# ════════════════════════════════════════════════════════════════════════════════

def _eval_re_flags(node) -> int:
    try:
        return int(eval(compile(ast.Expression(node), "<flags>", "eval"), {"re": re}))
    except Exception:
        return 0


def _build_evidence_index() -> dict:
    """자기 자신(analyzer.py) 소스를 AST 로 파싱해 rule id → 증거 추출 스펙 맵을 만든다."""
    index = {}
    try:
        with open(__file__, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
    except Exception:
        return index

    # ALERT_RULES 대입문의 값(리스트)만 대상으로 한다
    rules_node = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "ALERT_RULES":
                    rules_node = node.value
    if rules_node is None:
        return index

    def _lit(n):
        return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None

    for elt in getattr(rules_node, "elts", []):
        if not isinstance(elt, ast.Dict):
            continue
        rid = None
        check = None
        for k, v in zip(elt.keys, elt.values):
            key = _lit(k)
            if key == "id":
                rid = _lit(v)
            elif key == "check":
                check = v
        if not rid or not isinstance(check, ast.Lambda):
            continue

        spec = {"regex": [], "lit_b": [], "lit_bl": [], "hdr": []}
        for sub in ast.walk(check):
            # re.search / re.match / re.findall(pattern, target[, flags])
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                    and isinstance(sub.func.value, ast.Name) and sub.func.value.id == "re" \
                    and sub.func.attr in ("search", "match", "findall") and len(sub.args) >= 2:
                pat = _lit(sub.args[0])
                if pat is None:
                    continue
                tgt = sub.args[1]
                tgt_name = None
                if isinstance(tgt, ast.Name):
                    tgt_name = tgt.id
                elif isinstance(tgt, ast.BoolOp) and tgt.values and isinstance(tgt.values[0], ast.Name):
                    tgt_name = tgt.values[0].id  # `b or ""`
                is_bl = tgt_name in ("bl", "body_lower")
                flags = _eval_re_flags(sub.args[2]) if len(sub.args) >= 3 else 0
                spec["regex"].append((pat, flags, is_bl))
            # `"literal" in bl` / `in b` / `in h` / `in h.get("key",...)`
            elif isinstance(sub, ast.Compare) and len(sub.ops) == 1 and isinstance(sub.ops[0], ast.In):
                left = _lit(sub.left)
                right = sub.comparators[0]
                if left is None:
                    continue
                if isinstance(right, ast.Name) and right.id in ("bl", "body_lower"):
                    spec["lit_bl"].append(left)
                elif isinstance(right, ast.Name) and right.id in ("b", "body"):
                    spec["lit_b"].append(left)
                elif isinstance(right, ast.Name) and right.id == "h":
                    spec["hdr"].append(left)  # `"x-powered-by" in h`
                elif isinstance(right, ast.Call) and isinstance(right.func, ast.Attribute) \
                        and right.func.attr == "get" and isinstance(right.func.value, ast.Name) \
                        and right.func.value.id == "h" and right.args:
                    key = _lit(right.args[0])
                    if key:
                        spec["hdr"].append(key)  # `"unsafe-inline" in h.get("csp","")`
            # `h.get("key", ...)` 단독 사용(== "*", startswith 등)
            elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                    and sub.func.attr == "get" and isinstance(sub.func.value, ast.Name) \
                    and sub.func.value.id == "h" and sub.args:
                key = _lit(sub.args[0])
                if key:
                    spec["hdr"].append(key)

        # 중복 제거(순서 유지)
        for kk in ("lit_b", "lit_bl", "hdr"):
            spec[kk] = list(dict.fromkeys(spec[kk]))
        index[rid] = spec
    return index


_EVIDENCE_INDEX = _build_evidence_index()


def _clip_evidence(text: str, limit: int = 180) -> str:
    """증거 스니펫을 검색 가능한 형태로 정리(제어문자 정돈·길이 제한)."""
    if not text:
        return ""
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def _extract_alert_evidence(rule_id: str, headers_lower: dict, body: str, body_lower: str) -> str:
    """매칭된 룰에 대해 응답에서 실제 탐지된 증거 문자열을 뽑는다(없으면 "")."""
    spec = _EVIDENCE_INDEX.get(rule_id)
    if not spec:
        return ""
    body = body or ""
    body_lower = body_lower or ""

    # 1) 정규식 매칭(원본 body 로 실제 대소문자 보존; bl 대상이었으면 대소문자 무시)
    for pat, flags, is_bl in spec["regex"]:
        try:
            m = re.search(pat, body, flags | (re.I if is_bl else 0))
        except Exception:
            m = None
        if m:
            return _clip_evidence(m.group(0))

    # 2) body 리터럴(대소문자 유지 원본 슬라이스)
    for lit in spec["lit_b"]:
        idx = body.find(lit)
        if idx >= 0:
            return _clip_evidence(body[idx:idx + len(lit)])
    for lit in spec["lit_bl"]:
        idx = body_lower.find(lit)
        if idx >= 0:
            return _clip_evidence(body[idx:idx + len(lit)])

    # 3) 헤더 값(존재하는 헤더만; 누락 기반 룰은 여기서 자연히 빈 값)
    for key in spec["hdr"]:
        val = headers_lower.get(key)
        if val:
            return _clip_evidence(f"{key}: {val}")

    return ""


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
                    "evidence":    _extract_alert_evidence(rule["id"], headers_lower, body, body_lower),
                })
        except Exception:
            pass
    # 위험도 순 정렬
    risk_order = {"high": 0, "medium": 1, "low": 2, "informational": 3}
    alerts.sort(key=lambda a: risk_order.get(a["risk"], 9))
    return alerts


# ════════════════════════════════════════════════════════════════════════════════
# 공격 결과 분석 — "이 공격이 실제로 통했는가"를 증거 기반으로 판정 (결정적)
# ════════════════════════════════════════════════════════════════════════════════

# 파일 읽기 성공 마커 — 강/약으로 분리한다.
# 강한 마커: 매우 구체적이라 오탐이 거의 없다. 요청 형태와 무관하게 '모든 응답'에서
#   확인한다(어느 엔드포인트든 이 내용이 있으면 실제 파일/소스 유출).
_FILE_READ_MARKERS_STRONG = [
    (r"root:.*?:0:0:",                          "리눅스 /etc/passwd 내용"),
    (r"root:[^:\n]{0,80}:\d{4,5}:\d:\d{4,5}:",  "리눅스 /etc/shadow 내용(해시)"),
    (r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",  "개인키 노출"),
    (r"repositoryformatversion\s*=",            "Git 설정(.git/config) 내용"),
]
# 약한 마커: 정상 문서/코드 예제 페이지에도 나올 수 있어 오탐 위험이 있다. 요청이
#   파일 접근처럼 보일 때만(lfi/xxe 또는 _FILE_READ_HINT) 확인한다.
_FILE_READ_MARKERS_WEAK = [
    (r"\[extensions\]|\[fonts\]|16-bit app support", "Windows win.ini 내용"),
    (r"\[boot loader\]|\[operating systems\]", "Windows boot.ini 내용"),
    (r"(?m)^\s*127\.0\.0\.1\s+localhost",      "hosts 파일 내용"),
    (r"Linux version \d+\.\d+",                 "/proc/version 내용"),
    (r"\d+\.\d+\.\d+\.\d+ - - \[\d{2}/\w{3}/\d{4}", "웹서버 access 로그 내용"),
    (r"<\?php[\s\S]{0,40}",                     "PHP 소스코드 노출"),
    (r"DB_PASSWORD|DB_USERNAME|APP_KEY=",       ".env 설정 노출"),
    # /proc/self/environ — 프로세스 환경변수 덤프(웹 LFI 시 CGI 변수가 특징적으로 노출)
    (r"SCRIPT_FILENAME=|DOCUMENT_ROOT=|GATEWAY_INTERFACE=|SERVER_SOFTWARE=|HTTP_USER_AGENT=",
     "/proc/self/environ (환경변수) 노출"),
    (r"(?s)\bPATH=/[^\x00\n]{0,120}\x00",       "/proc/self/environ (환경변수) 노출"),
    # /proc/net/tcp — 커널 연결 테이블(로컬/원격 주소 hex)
    (r"sl\s+local_address\s+rem_address",       "/proc/net/tcp 내용"),
    # /proc/self/cmdline — 실행 커맨드라인(널 구분)
    (r"(?s)/[a-z]+/[a-z0-9._-]+\x00-{1,2}[a-z]", "/proc/self/cmdline 내용"),
]
# 파일 읽기 시도로 보이는 payload 지표 — 카테고리(lfi/xxe)와 무관하게 파일 내용
# 탐지를 켜기 위한 힌트. 수많은 경로 트래버설 익스플로잇이 'cve'·'sqli' 등으로 들어온다.
# 힌트는 '콘텐츠 마커 검사를 켤지'만 정하는 게이트다. 실제 성공 판정은 엄격한 파일
# '내용' 시그니처가 하므로, 힌트를 넉넉하게 잡아도 오탐이 늘지 않는다(인코딩 변형 포함).
_FILE_READ_HINT = re.compile(
    r"\.\.[\\/]|%2e|%252e|%c0%ae|"                 # 경로 트래버설(평문/단·이중 인코딩)
    r"%2f|%5c|%252f|%255c|"                        # 인코딩된 슬래시/백슬래시
    r"/etc/|etc%2f|/proc/|windows[\\/]|/windows/system32|win\.ini|boot\.ini|"
    r"passwd|shadow|/hosts\b|access\.log|/environ\b|/cmdline\b|"
    r"file://|LOAD_FILE|pg_read_file|xp_cmdshell",
    re.I,
)
# 공격 유형 추론 힌트 — 카테고리를 고르지 않은 요청(PoC·붙여넣기 등)에서도 payload·URL·
# 본문을 보고 어떤 공격인지 추정해, 맥락이 필요한 오라클(SSRF·SQLi·리다이렉트)을 켠다.
# (증거가 자명한 오라클—명령 출력·파일 내용—은 힌트 없이 전역으로 동작한다.)
_SSRF_HINT = re.compile(
    r"169\.254\.169\.254|/latest/meta-data|metadata\.google|metadata\.azure|"
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|file://|gopher://|dict://|"
    r"internal|/computeMetadata", re.I)
_SQLI_HINT = re.compile(
    r"\bUNION\b\s+SELECT|\bSELECT\b.+\bFROM\b|SLEEP\s*\(|pg_sleep|benchmark\s*\(|"
    r"waitfor\s+delay|information_schema|xp_cmdshell|load_file\s*\(|"
    r"'\s*OR\s*'|\"\s*OR\s*\"|\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+|"
    r"'--|\"--|--\s|/\*.*\*/", re.I)
_REDIRECT_HINT = re.compile(
    r"redirect|url=|next=|returnurl|return_to|dest=|goto=|callback=|//[a-z0-9.-]+\.", re.I)

# 명령 실행 출력 마커 (Command Injection)
_CMD_OUTPUT_MARKERS = [
    (r"uid=\d+\([^)]+\)\s+gid=\d+",            "id 출력(uid/gid)"),
    (r"Microsoft Windows \[Version",            "Windows ver 출력"),
    (r"Volume in drive [A-Z] |Directory of ",   "Windows dir 출력"),
]
# 클라우드 메타데이터 마커 (SSRF)
_SSRF_MARKERS = [
    (r"ami-id|instance-id|iam/security-credentials|InstanceProfileArn", "AWS 메타데이터"),
    (r"computeMetadata|metadata\.google\.internal",                     "GCP 메타데이터"),
    (r"\"compute\"\s*:|\"network\"\s*:.*macAddress",                    "Azure 메타데이터"),
]

# 민감 파일 탐색 프로브: (요청 payload 의 파일 지표, 노출 확증용 본문 시그니처, 파일 라벨)
# 상태코드가 아니라 '응답 본문에 실제 파일 내용이 있는가'로 노출을 판정하기 위한 표.
# 200 응답이라도 본문이 일반 페이지/오류 페이지/SPA 껍데기면 시그니처가 없어 '미노출'로 판정된다.
# (payload 지표, 노출 확증 정규식, 라벨, 응답에서 검색한 시그니처 설명)
_SENSITIVE_FILE_PROBES = [
    (r"\.git/config",  r"repositoryformatversion|\[remote\s+\"|\[branch\s+\"", "Git 설정(.git/config)", "repositoryformatversion / [remote \"…\"]"),
    (r"\.git/HEAD",    r"^\s*ref:\s*refs/heads/",                              "Git HEAD(.git/HEAD)", "ref: refs/heads/…"),
    (r"\.env(?![a-z])", r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\S",                      "환경파일(.env)", "KEY=값 형태의 환경변수 줄"),
    (r"wp-config\.php", r"DB_PASSWORD|DB_NAME|AUTH_KEY|define\(\s*['\"]DB_",   "WordPress wp-config.php", "DB_PASSWORD / define('DB_…')"),
    (r"web\.config",   r"<configuration[\s>]|<system\.web",                    "IIS web.config", "<configuration> / <system.web>"),
    (r"\.htaccess",    r"RewriteEngine|RewriteRule|AuthType|Require\s",        ".htaccess", "RewriteEngine / AuthType"),
    (r"id_rsa",        r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",             "SSH 개인키(id_rsa)", "BEGIN … PRIVATE KEY"),
    (r"\.DS_Store",    r"Bud1",                                                ".DS_Store", "Bud1 매직바이트"),
    (r"phpinfo",       r"<title>phpinfo\(\)|>PHP Version\s*<",                 "phpinfo()", "<title>phpinfo() / PHP Version"),
    (r"/actuator/(?:env|configprops|heapdump|gateway)",
     r'"propertySources"|"activeProfiles"|"systemProperties"|"predicate"|"route_id"', "Spring Actuator",
     "\"propertySources\" / \"activeProfiles\""),
]

# 카테고리별 '응답에서 검색한 성공 시그니처' 사람용 설명(미확인 증거에 사용).
_CHECKED_DESC = {
    "lfi":  "root:x:0:0(passwd) · shadow 해시 · BEGIN PRIVATE KEY · win.ini · /proc 환경변수",
    "xxe":  "root:x:0:0(passwd) · 파일 내용 · BEGIN PRIVATE KEY",
    "cmdi": "uid=0(root) gid=(id 출력) · Microsoft Windows [Version(cmd 출력)",
    "ssrf": "클라우드 메타데이터(ami-id · iam/security-credentials · computeMetadata)",
    "ssti": "표현식 계산 결과(예: 7*7=49)",
    "sqli": "SQL/DB 에러(문법 오류 · EXTRACTVALUE 마커) · 시간지연 · 참/거짓 차이",
    "xss":  "payload 의 실행 컨텍스트 반사",
    "redirect": "외부 도메인으로의 3xx Location",
    "nosql": "참/거짓 응답 차이 · $where 평가",
    "cve":  "root:x:0:0 · uid= · 개인키 · 소스/설정 파일 내용",
}
_CHECKED_DEFAULT = "root:x:0:0 · uid=0(root) · 개인키 · 에러/메타데이터 시그니처"


def _checked_desc(category: str) -> str:
    return _CHECKED_DESC.get((category or "").lower(), _CHECKED_DEFAULT)


# 명령 주입처럼 보이는 요청 지표(GPON dest_host, 셸 메타문자 등)
_CMDI_HINT = re.compile(r";|\||&&|\$\(|`|%0a|\bsleep\b|\bid\b|whoami|/bin/|dest_host|\bexec\b|\bcmd=", re.I)


# 공격유형 → '검색한 성공 시그니처' 서술
_SIG_DESC = {
    "cmdi": "명령 실행 출력(uid=0(root) 등)",
    "lfi":  "파일 내용(root:x:0:0 · 환경변수 · 개인키 등)",
    "xxe":  "파일 내용(root:x:0:0 · 개인키 등)",
    "ssti": "템플릿 계산 결과(예: 49)",
    "sqli": "SQL/DB 에러 · 시간지연 · 참/거짓 차이",
    "ssrf": "클라우드 메타데이터",
}


def infer_attack_type(probe: str, category: str) -> str:
    """payload+URL+본문으로 공격 유형을 추론. payload 가 특정 유형을 명확히 가리키면
    카테고리 라벨보다 그걸 신뢰한다(라벨이 틀리거나 뭉뚱그려진 cve 인 경우 오분류 방지).
    예: category=sqli 인데 payload=/proc/self/environ → 파일읽기(lfi)로 인식."""
    probe = probe or ""
    if _FILE_READ_HINT.search(probe):
        return "lfi"
    if _CMDI_HINT.search(probe):
        return "cmdi"
    if re.search(r"7\s*\*\s*7|\{\{|\$\{|#\{", probe):
        return "ssti"
    if _SSRF_HINT.search(probe):
        return "ssrf"
    if _SQLI_HINT.search(probe):
        return "sqli"
    return (category or "").lower()


def _checked_desc_for(probe: str, category: str) -> str:
    """'응답에서 무엇을 검색했는지' 서술 — payload 가 가리키는 유형을 카테고리보다 우선.

    payload 힌트가 하나라도 있으면 그것만 나열(틀린 카테고리가 SQL 등 무관한 시그니처를
    끼워넣지 않도록). 힌트가 전혀 없을 때만 카테고리 설명으로 폴백.
    """
    probe = probe or ""
    cat = (category or "").lower()
    parts = []
    # payload 가 직접 가리키는 유형(카테고리 라벨보다 우선)
    if _CMDI_HINT.search(probe):
        parts.append(_SIG_DESC["cmdi"])
    if _FILE_READ_HINT.search(probe):
        parts.append(_SIG_DESC["lfi"])
    if re.search(r"7\s*\*\s*7|\{\{|\$\{|#\{", probe):
        parts.append(_SIG_DESC["ssti"])
    if _SQLI_HINT.search(probe):
        parts.append(_SIG_DESC["sqli"])
    if _SSRF_HINT.search(probe):
        parts.append(_SIG_DESC["ssrf"])
    if parts:
        return " · ".join(parts)
    # payload 에 유형 힌트가 전혀 없을 때만 카테고리 기반 설명
    return _SIG_DESC.get(cat, _checked_desc(cat))


def _detect_sensitive_file(payload: Optional[str], body: str) -> Optional[dict]:
    """민감 파일 탐색 페이로드에 대해 '실제 노출' 여부를 본문 내용으로 판정.

    반환:
      - None                : 민감 파일 탐색 페이로드가 아님(해당 없음)
      - {"exposed": True,  ...}: 요청한 파일의 실제 내용이 응답에 있음 → 노출 확증
      - {"exposed": False, ...}: 파일을 요청했으나 내용이 없음 → 미노출(200이어도 안전)
    """
    p = payload or ""
    for path_re, sig_re, label, checked in _SENSITIVE_FILE_PROBES:
        if re.search(path_re, p, re.I):
            m = re.search(sig_re, body or "", re.I)
            if m:
                return {"targeted": label, "exposed": True, "checked": checked,
                        "evidence": _clip_evidence(m.group(0), 120)}
            return {"targeted": label, "exposed": False, "checked": checked, "evidence": ""}
    return None

# ── 클라이언트측(client-side) 취약점 탐지용 ──────────────────────────
# DOM XSS 소스: 공격자가 제어 가능한 클라이언트 입력
_DOM_SOURCES = [
    r"location\.hash", r"location\.search", r"location\.href", r"location\.pathname",
    r"document\.URL", r"document\.documentURI", r"document\.referrer",
    r"window\.name", r"URLSearchParams", r"\.searchParams",
    r"postMessage", r"event\.data",
]
# DOM XSS 싱크: 문자열을 코드/마크업으로 실행하는 위험 API
_DOM_SINKS = [
    (r"\.innerHTML\s*=",                 "innerHTML"),
    (r"\.outerHTML\s*=",                 "outerHTML"),
    (r"document\.write(?:ln)?\s*\(",     "document.write"),
    (r"\.insertAdjacentHTML\s*\(",       "insertAdjacentHTML"),
    (r"\beval\s*\(",                     "eval"),
    (r"\bnew\s+Function\s*\(",           "Function()"),
    (r"setTimeout\s*\(\s*[\"'`]",        "setTimeout(문자열)"),
    (r"setInterval\s*\(\s*[\"'`]",       "setInterval(문자열)"),
    (r"\.(?:html|append|prepend|before|after|replaceWith)\s*\(", "jQuery html/append"),
    (r"\$\(\s*(?:location|document\.URL|window\.name)", "jQuery $(source)"),
]
# 클라이언트 템플릿 프레임워크 마커 (CSTI 가능성)
_CLIENT_TPL_MARKERS = (
    "ng-app", "ng-version", "ng-controller", "ng-bind", "angular.js", "angular.min.js",
    "v-app", "data-v-", "__vue__", "vue.js", "vue.min.js", "x-data=", "alpinejs",
)


def _detect_dom_xss(body: str):
    """응답 <script> 안에서 클라이언트 입력 소스가 위험 싱크로 흐르는지 정적 탐지(휴리스틱).
    소스·싱크가 동시에 존재할 때만 보고하여 오탐을 줄인다."""
    if not body:
        return None
    scripts = re.findall(r"<script\b[^>]*>([\s\S]*?)</script>", body, re.I)
    js = "\n".join(scripts)
    if not js:
        return None
    src = next((re.search(s, js) for s in _DOM_SOURCES if re.search(s, js)), None)
    if not src:
        return None
    for pat, lbl in _DOM_SINKS:
        m = re.search(pat, js)
        if m:
            s = max(0, m.start() - 30)
            return {"source": src.group(0), "sink": lbl, "evidence": js[s:m.end() + 40]}
    return None


def _detect_csti(body: str, payload: str):
    """{{7*7}}·${..} 등 템플릿 표현식이 '미평가 원문'으로 반사 + 클라이언트 프레임워크 존재
    → 브라우저 렌더링 시 평가될 수 있음(CSTI). 서버가 평가했다면(49 등) SSTI 로 별도 처리."""
    if not body or not payload:
        return None
    if not any(t in payload for t in ("{{", "${", "#{")):
        return None
    if payload not in body:            # 원문 그대로(미평가) 반사됐는지
        return None
    if not any(m in body.lower() for m in _CLIENT_TPL_MARKERS):
        return None
    idx = body.find(payload)
    s = max(0, idx - 20)
    return {"evidence": body[s: idx + len(payload) + 20]}


def _detect_client_redirect(body: str):
    """서버 3xx 없이 meta refresh / JS location 대입으로 이동하는 클라이언트측 리다이렉트."""
    if not body:
        return None
    m = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', body, re.I)
    if m and re.match(r'(?:https?:)?//|javascript:', m.group(1).strip(), re.I):
        return {"how": "meta refresh", "target": m.group(1)[:100], "evidence": m.group(0)[:160]}
    m = re.search(r'(?:location\.(?:href|replace|assign)\s*=?\s*\(?|window\.location\s*=)\s*["\']((?:https?:)?//[^"\']+)', body, re.I)
    if m:
        return {"how": "JS location", "target": m.group(1)[:100], "evidence": m.group(0)[:160]}
    return None


# ── SPA 셸 감지 ──────────────────────────────────────────────
# 응답이 "빈 JS 마운트 지점 + 번들 스크립트"뿐이면 서버는 껍데기만 주고 본문은 브라우저가
# 렌더한다. 이 경우 파라미터 반사/주입이 서버 응답엔 안 나타나 HTTP 계층 테스트가 무의미하므로
# 실제 API(XHR)를 대상으로 하라고 경고한다.
_SPA_EMPTY_MOUNT_RE = re.compile(
    r'<div[^>]+id=["\'](?:root|app|__next|__nuxt)["\'][^>]*>\s*</div>', re.I)
_SPA_MOUNT_RE  = re.compile(r'id=["\'](?:root|app|__next|__nuxt)["\']', re.I)
_SPA_BUNDLE_RE = re.compile(r'<script[^>]+src=["\'][^"\']*\.js', re.I)
_SPA_TEXT_RE   = re.compile(r'<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>', re.I)


def _detect_spa_shell(body: str, headers_lower: dict) -> Optional[dict]:
    if not body or "html" not in (headers_lower.get("content-type") or ""):
        return None
    has_empty_mount = bool(_SPA_EMPTY_MOUNT_RE.search(body))
    has_mount  = bool(_SPA_MOUNT_RE.search(body))
    has_bundle = bool(_SPA_BUNDLE_RE.search(body))
    # 태그·스크립트 제거 후 가시 텍스트 길이
    visible = re.sub(r"\s+", " ", _SPA_TEXT_RE.sub(" ", body)).strip()
    thin = len(visible) < 200
    if not (has_empty_mount or (has_mount and has_bundle and thin)):
        return None
    b = body.lower()
    if "ng-version" in b:
        fw = "Angular"
    elif "__next" in b or "__next_data__" in b:
        fw = "Next.js"
    elif "__nuxt" in b:
        fw = "Vue/Nuxt"
    elif "reactroot" in b or 'id="root"' in b or "id='root'" in b:
        fw = "React"
    else:
        fw = "SPA"
    return {"framework": fw, "visible_len": len(visible)}


def _detect_reflection(body: str, payload: Optional[str]) -> Optional[dict]:
    """payload가 응답에 반사됐는지 + 미인코딩 여부 + 컨텍스트 추정."""
    if not payload or len(payload) < 3 or payload not in body:
        return None
    idx = body.find(payload)
    seg = body[:idx]
    # 컨텍스트 추정
    open_s = seg.rfind("<script")
    close_s = seg.rfind("</script")
    if open_s > close_s:
        ctx = "JavaScript(script 내부)"
    elif re.search(r'=\s*"[^"]*$', seg) or re.search(r"=\s*'[^']*$", seg):
        ctx = "HTML 속성값"
    else:
        ctx = "HTML 본문"
    # 미인코딩: payload에 특수문자가 있고 원문 그대로 존재하면 미인코딩(실행 위험)
    has_special = any(c in payload for c in "<>\"'")
    start = max(0, idx - 40)
    end = min(len(body), idx + len(payload) + 40)

    # 클라이언트측 XSS 실행 컨텍스트 정밀 판정 (반사 위치·payload 형태 기반)
    exec_ctx = None
    if re.search(r"\bon[a-z]+\s*=\s*[\"']?[^\"'>]*$", seg, re.I):
        exec_ctx = "이벤트 핸들러 속성"                       # ... onerror=" [여기]
    elif re.search(r"(?:href|src|action|formaction)\s*=\s*[\"']?\s*javascript:[^\"'>]*$", seg, re.I) \
            or payload.strip().lower().startswith("javascript:"):
        exec_ctx = "javascript: URI"
    elif ctx.startswith("JavaScript") and any(c in payload for c in "\"'`</"):
        exec_ctx = "script 내부(문자열 이탈)"                  # <script> 내부에서 문자열/블록 이탈 가능
    elif re.search(r"<\s*(?:script|img|svg|iframe|body|details|input|video|audio|object|embed|marquee)\b"
                   r"|on[a-z]+\s*=|javascript:", payload, re.I):
        exec_ctx = "HTML 본문(태그/핸들러 삽입)"               # 실행형 태그가 원문 삽입

    return {
        "reflected": True,
        "unescaped": bool(has_special),   # 특수문자 원문 반사 = 실행 가능성
        "exec_ctx": exec_ctx,             # 실행 가능 컨텍스트(없으면 None) — 클라이언트측 XSS 판정
        "context": ctx,
        "snippet": body[start:end],
        "payload": payload,
    }


def _extract_sleep_seconds(payload: str) -> Optional[int]:
    if not payload:
        return None
    for pat in (r"sleep\(\s*(\d+)", r"pg_sleep\(\s*(\d+)", r"WAITFOR\s+DELAY\s+'0:0:(\d+)",
                r"RECEIVE_MESSAGE\([^,]+,\s*(\d+)", r"\bsleep\s+(\d+)"):
        m = re.search(pat, payload, re.I)
        if m:
            return int(m.group(1))
    return None


def attack_findings(status_code, headers_lower, body, response_time, payload, category, baseline,
                    url=None, req_body=None):
    """공격별 성공 신호를 증거와 함께 수집. (findings, outcome, confidence) 반환.

    payload/카테고리에만 의존하지 않고, 요청 전체(payload+URL+본문)를 프로브로 삼아
    공격 유형을 추론한다. 그래서 PoC·붙여넣기 요청처럼 카테고리가 없어도 결과를 확인한다.
    """
    findings = []
    body_lower = (body or "").lower()
    # 공격 탐지용 프로브: payload 뿐 아니라 요청 URL(경로+쿼리)·본문까지 합친다.
    # 페이로드 미선택으로 주소/본문에만 공격이 들어간 경우(직접 GET·붙여넣기 POST)도 잡기 위함.
    # URL 인코딩된 요청(%27=', %2f=/ 등)도 매칭되도록 디코딩본을 함께 붙인다.
    _raw_probe = f"{payload or ''} {url or ''} {req_body or ''}"
    try:
        probe = _raw_probe + " " + unquote(unquote(_raw_probe))
    except Exception:
        probe = _raw_probe
    file_probe = probe

    # ① payload 반사 (클라이언트측 XSS 실행 컨텍스트 정밀 판정 포함)
    refl = _detect_reflection(body or "", payload)
    if refl:
        if refl.get("exec_ctx"):
            findings.append({"name": "반사형 XSS(실행 컨텍스트)", "verdict": "성공", "confidence": 92,
                             "why": f"payload가 {refl['exec_ctx']}에 실행 가능한 형태로 반영됨 → 브라우저에서 스크립트 실행 가능(반사형 XSS)",
                             "evidence": refl["snippet"]})
        elif refl["unescaped"]:
            findings.append({"name": "payload 미인코딩 반사", "verdict": "성공", "confidence": 88,
                             "why": f"payload가 {refl['context']}에 인코딩 없이 반영됨 → XSS 등 실행 가능",
                             "evidence": refl["snippet"]})
        else:
            findings.append({"name": "payload 반사", "verdict": "미확정", "confidence": 40,
                             "why": f"{refl['context']}에 반영되나 특수문자 없음/인코딩 가능",
                             "evidence": refl["snippet"]})

    # ② 카테고리별 성공 신호
    def _hit(markers):
        for pat, label in markers:
            m = re.search(pat, body or "", re.I)
            if m:
                s = max(0, m.start() - 20)
                return label, (body or "")[s:m.end() + 40]
        return None

    # 파일/소스 내용 노출 — 강한 시그니처는 요청 형태와 무관하게 '모든 응답'에서 확인하고,
    # 약한 시그니처는 파일 접근처럼 보일 때만(lfi/xxe 또는 _FILE_READ_HINT) 확인한다.
    h = _hit(_FILE_READ_MARKERS_STRONG)
    if not h and (category in ("lfi", "xxe") or _FILE_READ_HINT.search(file_probe)):
        h = _hit(_FILE_READ_MARKERS_WEAK)
    if h:
        findings.append({"name": "파일 읽기 성공", "verdict": "성공", "confidence": 92,
                         "why": h[0], "evidence": h[1]})
    # 명령 실행 출력 — uid/gid·Windows ver/dir 는 매우 구체적인 출력 시그니처라 요청 형태와
    # 무관하게 확인한다(어느 요청이든 이 출력이 있으면 명령 실행 성공).
    hc = _hit(_CMD_OUTPUT_MARKERS)
    if hc:
        findings.append({"name": "명령 실행 출력", "verdict": "성공", "confidence": 93,
                         "why": hc[0], "evidence": hc[1]})

    # 내부/클라우드 메타데이터 응답(SSRF) — 정상 API/문서에도 나올 수 있어, 요청이
    # SSRF 처럼 보일 때(내부주소·메타데이터 URL 등)만 성공 신호로 본다.
    if category == "ssrf" or _SSRF_HINT.search(probe):
        hs = _hit(_SSRF_MARKERS)
        if hs:
            findings.append({"name": "내부/메타데이터 응답", "verdict": "성공", "confidence": 85,
                             "why": hs[0], "evidence": hs[1]})

    # SSTI — 요청에 7*7 표현식이 있고 결과 49 가 나오면(원문 아님) 서버 평가 성공. 카테고리 무관.
    if re.search(r"7\s*\*\s*7|7\*'7'", probe) and "49" in (body or "") and "7*7" not in (body or ""):
        findings.append({"name": "템플릿 평가됨(7*7=49)", "verdict": "성공", "confidence": 90,
                         "why": "표현식이 서버에서 계산됨 → SSTI", "evidence": "응답에 '49' 포함"})

    # SQL/DB 에러 노출 — SQLi 처럼 보이는 요청일 때 error-based 성공 신호로 본다(카테고리 무관).
    if category == "sqli" or _SQLI_HINT.search(probe):
        for pat, desc in ERROR_LEAK_PATTERNS:
            if re.search(pat, body or "", re.I):
                findings.append({"name": "SQL/DB 에러 노출", "verdict": "성공", "confidence": 85,
                                 "why": f"{desc} — error-based 성공 가능", "evidence": desc})
                break

    # 외부 리다이렉트 — 3xx Location 이 외부로 나가면 오픈 리다이렉트 성공. 리다이렉트처럼
    # 보이는 요청일 때만(정상 SSO 리다이렉트 오탐 억제).
    if category == "redirect" or _REDIRECT_HINT.search(probe):
        loc = headers_lower.get("location", "")
        if status_code in (301, 302, 303, 307, 308) and re.search(r"^https?://|^//", loc):
            findings.append({"name": "외부 리다이렉트", "verdict": "성공", "confidence": 80,
                             "why": f"Location 헤더가 외부로 이동: {loc[:80]}", "evidence": loc[:120]})

    # ②-c 민감 파일 노출 — 상태코드가 아니라 '실제 파일 내용'으로 노출/미노출을 판정.
    #     (카테고리 무관: .git/config·.env 등은 cve/path 프로브로 들어온다)
    sf = _detect_sensitive_file(file_probe, body or "")
    if sf and sf["exposed"]:
        if not h:   # 강한 마커(위)로 이미 노출을 잡았으면 중복 표기하지 않음
            findings.append({"name": f"민감 파일 노출 — {sf['targeted']}", "verdict": "성공", "confidence": 92,
                             "why": f"요청한 {sf['targeted']} 의 실제 내용이 응답에 노출됨 → 소스/시크릿 유출",
                             "evidence": sf["evidence"]})
    elif sf:
        findings.append({"name": f"민감 파일 미노출 — {sf['targeted']}", "verdict": "안전", "confidence": 80,
                         "why": f"요청한 {sf['targeted']} 이(가) 응답 본문에 없음 → 파일 미노출"
                                " (200 응답은 일반 페이지·오류 페이지·SPA 껍데기일 수 있음)",
                         "evidence": f"응답에서 {sf['targeted']} 시그니처({sf.get('checked','')})를 "
                                     f"검색 → 없음 (HTTP {status_code} · {len(body or '')}B)"})

    # ②-b 클라이언트측(client-side) 취약점 신호
    # DOM 기반 XSS — 응답 스크립트에서 소스→싱크 흐름 (XSS 테스트 시)
    if category == "xss" or refl:
        dom = _detect_dom_xss(body or "")
        if dom:
            findings.append({"name": "DOM 기반 XSS 싱크", "verdict": "미확정", "confidence": 55,
                             "why": f"클라이언트 입력({dom['source']})이 위험 싱크({dom['sink']})로 흐름 → DOM XSS 가능(브라우저 실행 확인 필요)",
                             "evidence": dom["evidence"]})
    # 클라이언트 템플릿 인젝션(CSTI) — 템플릿 표현식 미평가 반사 + 프레임워크 존재
    if category in ("xss", "ssti") or any(t in probe for t in ("{{", "${", "#{")):
        csti = _detect_csti(body or "", payload or "")
        if csti:
            findings.append({"name": "클라이언트 템플릿 인젝션(CSTI) 가능", "verdict": "미확정", "confidence": 60,
                             "why": "템플릿 표현식이 미평가 원문으로 반사 + 클라이언트 프레임워크 존재 → 브라우저 렌더링 시 평가 가능",
                             "evidence": csti["evidence"]})
    # 클라이언트측 오픈 리다이렉트 — meta refresh / JS location (서버 3xx 아님)
    if category == "redirect":
        cr = _detect_client_redirect(body or "")
        if cr:
            findings.append({"name": "클라이언트측 오픈 리다이렉트", "verdict": "성공", "confidence": 78,
                             "why": f"{cr['how']}로 외부 이동: {cr['target']} → 클라이언트에서 리다이렉트 실행",
                             "evidence": cr["evidence"]})

    # ③ 타이밍 (time-based)
    n = _extract_sleep_seconds(payload)
    if n:
        if response_time >= n * 1000 * 0.8:
            findings.append({"name": "시간 지연 일치", "verdict": "성공", "confidence": 90,
                             "why": f"지연 {n}s 요청 → 실제 {response_time/1000:.1f}s 지연 (Blind time-based)",
                             "evidence": f"{response_time:.0f}ms ≈ {n}s"})
        else:
            findings.append({"name": "시간 지연 없음", "verdict": "미확정", "confidence": 30,
                             "why": f"{n}s 지연 payload지만 응답 {response_time:.0f}ms — 미영향/필터",
                             "evidence": f"{response_time:.0f}ms"})

    # ④ 베이스라인 Diff
    if baseline:
        b_status = baseline.get("status_code")
        b_body = baseline.get("body") or ""
        dl = len(body or "") - len(b_body)
        changed = []
        if b_status is not None and b_status != status_code:
            changed.append(f"상태 {b_status}→{status_code}")
        if abs(dl) >= 32:
            changed.append(f"본문 {'+' if dl > 0 else ''}{dl}B")
        if changed:
            findings.append({"name": "베이스라인 대비 변화", "verdict": "미확정", "confidence": 55,
                             "why": "정상 대비 응답이 달라짐 — boolean/인증우회 판단 근거: " + ", ".join(changed),
                             "evidence": ", ".join(changed)})

    # ⑤ 차단 신호
    blocked = status_code in (403, 406, 429, 503) or _body_signals_block(status_code, body, body_lower)

    # 종합 판정
    success = [f for f in findings if f["verdict"] == "성공"]
    if success:
        outcome = "success"
        conf = max(f["confidence"] for f in success)
    elif blocked:
        outcome = "blocked"
        conf = 70
        # 403 등은 WAF가 payload 를 막은 것일 수도, 경로 자체가 원래 거부되는 것일 수도 있다.
        # baseline(정상 값) 이 없으면 'payload 특정 차단'인지 단정할 수 없으므로 그렇게 서술.
        why = f"상태 {status_code} 또는 차단 응답 — WAF/필터 또는 경로 자체 접근제한으로 거부됨"
        if not baseline:
            why += " (정상 파라미터로 baseline 비교 시 payload 특정 차단인지 구분 가능)"
        findings.append({"name": "차단됨", "verdict": "차단", "confidence": 70,
                         "why": why, "evidence": f"HTTP {status_code}"})
    else:
        outcome = "inconclusive"
        conf = 30
    return findings, outcome, conf


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
    baseline: Optional[dict] = None,
    url: Optional[str] = None,
    req_body: Optional[str] = None,
) -> dict:
    """HTTP 응답을 분석하여 보안 판정 결과 반환.

    url: 요청 URL(경로+쿼리). payload 를 고르지 않고 주소만으로 민감 파일을
         직접 GET 한 경우(예: /public/.git/config)도 탐지하기 위해 함께 검사한다.
    """

    result = {
        "verdict": "unknown",
        "confidence": 0,
        "waf_detected": None,
        "tech_stack": [],       # 프록시/CDN/웹서버/프레임워크 지문(Envoy, Next.js 등)
        "block_reason": [],
        "error_leaks": [],
        "sensitive_data": [],
        "response_anomalies": [],
        "risk_level": "info",
        "details": [],
        "score": 0,
        "alerts": [],          # ZAP 스타일 Alert 목록
        "findings": [],        # 공격 결과 신호(증거 기반)
        "attack_outcome": None,  # success | blocked | inconclusive
        "reflection": None,
        "spa_shell": None,     # SPA 껍데기면 {framework, visible_len}
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
    result["tech_stack"] = detect_stack(headers_lower)
    waf_name = detect_waf(headers_lower)
    if waf_name:
        result["waf_detected"] = waf_name
        result["details"].append(f"WAF 탐지: {waf_name}")
        result["confidence"] = min(result["confidence"] + 20, 95)

    # 3. 응답 바디 차단 키워드 — 단, 대형 성공 응답의 우연한 매칭은 차단으로 보지 않는다
    if _body_signals_block(status_code, body, body_lower):
        for kw in BLOCK_KEYWORDS:
            if kw in body_lower:
                result["block_reason"].append(f"바디 키워드: '{kw}'")
                result["verdict"] = "blocked"
                result["confidence"] = min(result["confidence"] + 15, 95)

    # 4. 에러 누출 탐지 (실제 탐지된 증거 문자열을 함께 표기 → 응답에서 검색·검증 가능)
    for pattern, desc in ERROR_LEAK_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            ev = _clip_evidence(m.group(0), 120)
            result["error_leaks"].append(f"{desc}: {ev}" if ev else desc)
            result["details"].append(f"⚠️ 에러 정보 누출: {desc}" + (f" — {ev}" if ev else ""))
            if result["verdict"] == "passed":
                result["verdict"] = "bypass"
            result["risk_level"] = "high"

    # 5. 민감 정보 탐지 (실제 탐지된 증거 문자열을 함께 표기)
    for pattern, desc in SENSITIVE_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            ev = _clip_evidence(m.group(0), 120)
            result["sensitive_data"].append(f"{desc}: {ev}" if ev else desc)
            result["details"].append(f"🔴 민감 정보 노출: {desc}" + (f" — {ev}" if ev else ""))
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

    # 11. 공격 결과 분석(반사/카테고리 성공신호/타이밍/베이스라인) — 증거 기반.
    #     위험도 산정(10)보다 먼저 실행해, '차단 안 됨'이 아니라 '실제 증거'로 판정한다.
    findings, outcome, aconf = attack_findings(
        status_code, headers_lower, body, response_time, payload, category, baseline, url, req_body
    )
    result["reflection"] = _detect_reflection(body, payload)
    result["spa_shell"] = _detect_spa_shell(body, headers_lower)

    # 3-상태 명확화: 성공/안전(차단)이 아니고 아무 신호도 없는 '공격 시도'는 '안전'이 아니라
    # '자동 판정 불가(수동 검토 필요)'로 명시한다. (블라인드/OOB/로직/시그니처 없는 파일 등
    # 단일 응답으로 판정 못 하는 유형이 거짓 안심을 주지 않도록.)
    # payload/URL 로 실제 공격 유형을 추론(카테고리 라벨이 틀릴 수 있음) — 서술·AI 판정에 사용
    _probe_all = f"{payload or ''} {url or ''} {req_body or ''}"
    result["attack_type"] = infer_attack_type(_probe_all, category)

    is_attack_attempt = bool((payload and payload.strip()) or category)
    has_signal = any(f.get("verdict") in ("성공", "안전", "미확정") for f in findings)
    if (is_attack_attempt and outcome == "inconclusive" and not has_signal
            and not result["sensitive_data"] and not result["error_leaks"]):
        _mprobe = _probe_all
        _sigs = _checked_desc_for(_mprobe, category)
        _bn = "" if baseline else " · baseline 없음"
        findings.append({
            "name": "자동 판정 불가 — 수동 확인 필요", "verdict": "미확인", "confidence": 30,
            "why": "성공/실패를 단일 응답으로 판정할 근거(반사·에러·마커·시간차·베이스라인 변화 등)를 "
                   "찾지 못했습니다. 블라인드/OOB/로직 계열이거나 이 대상에 취약하지 않을 수 있습니다. "
                   "응답 본문을 직접 확인하고, 확증 스캔 또는 baseline 비교로 검증하세요.",
            "evidence": f"응답에서 성공 시그니처 [{_sigs}]를 검색 → 미검출; 반사·시간지연·baseline 변화도 없음 "
                        f"(HTTP {status_code} · {len(body)}B · {response_time:.0f}ms{_bn})",
        })

    result["findings"] = findings
    result["attack_outcome"] = outcome
    result["attack_confidence"] = aconf

    # 10. 최종 위험도 산정 — '차단되지 않음'이 아니라 '취약 증거'를 기준으로 한다.
    if result["verdict"] == "bypass" or result["sensitive_data"]:
        result["risk_level"] = "critical"
        result["score"] = 90
    elif result["error_leaks"]:
        result["risk_level"] = "high"
        result["score"] = 70
    elif result["verdict"] == "passed":
        # (구) '차단 안 됨 + sqli/cmdi/ssrf → high/65' 휴리스틱 제거: 차단되지 않았다고
        #  취약한 것은 아니다(방어장비 미탐 ≠ 대상 취약). 실제 성공은 아래 성공 격상에서
        #  처리하고, 증거가 없으면 미확정 신호 유무로만 위험도를 나눠 오탐을 막는다.
        if outcome == "success":
            pass   # 성공 격상 블록에서 risk/score 확정
        elif any(f.get("verdict") in ("성공", "미확정") for f in findings):
            result["risk_level"] = "medium"   # 반사·베이스라인 변화 등 추가 확인 필요 신호
            result["score"] = 40
        else:
            # 차단도 안 됐고 우려 신호도 없음(‘안전/미노출’ 신호만 있거나 무신호) → 낮음
            result["risk_level"] = "low"
            result["score"] = 25
    elif result["verdict"] == "blocked":
        result["risk_level"] = "info"
        result["score"] = 10
    else:
        result["risk_level"] = "medium"
        result["score"] = 40

    # 공격 성공이 증거로 확인되면 종합 판정/위험도 격상(상태코드 relabel보다 신뢰도 높음)
    if outcome == "success":
        result["verdict"] = "bypass"
        if result["risk_level"] not in ("critical",):
            result["risk_level"] = "high"
        result["score"] = max(result["score"], aconf)

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
