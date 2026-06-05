"""
응답 분석 엔진 - WAF/IDS 차단 여부 및 취약점 탐지 판정
"""
import re
from typing import Optional


# WAF 차단 시그니처
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
    "AWS WAF": ["aws", "awselb", "x-amzn-requestid"],
    "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
    "Akamai": ["akamai", "akamaighost"],
    "Imperva": ["imperva", "incapsula", "visid_incap"],
    "F5 BIG-IP": ["bigip", "f5", "ts="],
    "Barracuda": ["barracuda", "barra"],
    "Fortinet": ["fortigate", "fortiweb"],
    "Generic WAF": ["waf", "firewall", "blocked", "denied"],
}

# 차단 응답 바디 키워드
BLOCK_KEYWORDS = [
    "blocked", "forbidden", "access denied", "not allowed",
    "security violation", "request blocked", "attack detected",
    "illegal request", "bad request", "rejected",
    "차단", "금지", "접근 거부",
]

# 에러 누출 패턴 (취약점 힌트)
ERROR_LEAK_PATTERNS = [
    (r"SQL syntax.*?MySQL", "MySQL 에러 노출"),
    (r"Warning.*?\Wmysqli?_", "MySQL 함수 에러"),
    (r"ORA-\d{5}", "Oracle 에러 코드"),
    (r"Microsoft SQL Server", "MSSQL 에러"),
    (r"PostgreSQL.*?ERROR", "PostgreSQL 에러"),
    (r"sqlite3\.OperationalError", "SQLite 에러"),
    (r"ODBC.*?Driver", "ODBC 에러"),
    (r"<b>Fatal error</b>", "PHP Fatal 에러"),
    (r"stack trace", "스택 트레이스 노출"),
    (r"at java\.", "Java 스택 트레이스"),
    (r"Exception in thread", "Java 예외"),
    (r"Traceback \(most recent", "Python 트레이스백"),
]

# 민감 정보 패턴
SENSITIVE_PATTERNS = [
    (r"root:[x*]:0:0", "passwd 파일 내용"),
    (r"[A-Za-z0-9+/]{40,}={0,2}", "Base64 인코딩 데이터"),
    (r"-----BEGIN (RSA )?PRIVATE KEY-----", "개인키 노출"),
    (r"password\s*[=:]\s*\S+", "패스워드 노출"),
    (r"api[_-]?key\s*[=:]\s*\S+", "API 키 노출"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "내부 IP 노출"),
]


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
        "verdict": "unknown",       # blocked / passed / bypass / error
        "confidence": 0,            # 0-100
        "waf_detected": None,
        "block_reason": [],
        "error_leaks": [],
        "sensitive_data": [],
        "response_anomalies": [],
        "risk_level": "info",       # info / low / medium / high / critical
        "details": [],
        "score": 0,
    }

    body_lower = body.lower() if body else ""
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
    body_size = len(body) if body else 0
    if body_size < 50 and status_code == 200:
        result["response_anomalies"].append("비정상적으로 짧은 200 응답")

    # 8. 최종 위험도 산정
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
    """테스트 결과 목록에서 요약 통계 생성"""
    total = len(results)
    if total == 0:
        return {}

    blocked = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "blocked")
    passed = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "passed")
    bypass = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "bypass")
    error = sum(1 for r in results if r.get("analysis", {}).get("verdict") == "error")

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
