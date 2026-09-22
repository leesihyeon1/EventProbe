"""테스트 유효성 게이트 — '요청은 나갔지만 실제로 대상을 건드리지 못한' 상황을 인식해
거짓 음성(안전 오판)을 막는다. analyze_response 가 매 응답마다 호출한다.

보안 테스트 도구의 가장 위험한 실패는 '조용한 거짓 음성' — 요청이 방어장비/로그인 벽/
레이트리밋에 막히거나, 페이로드가 대상에 안 실렸는데 '안전'이라고 안심시키는 것이다.
이 모듈은 그런 '테스트 미도달·무효' 신호를 모아 노티하고, 심각하면(block) 판정을
'안전'으로 내리지 못하게 한다(호출부에서 inconclusive 로 강등).

반환: {"ok": bool, "warnings": [ {code, severity, why, fix} ]}
  severity "block" = 테스트가 유효하지 않을 가능성 높음 → '안전' 판정 금지
  severity "warn"  = 판정 신뢰도 저하 → 노티(강등까지는 아님)
"""
import re
from urllib.parse import urlsplit, unquote
from typing import Optional

from core.detectors import _LOGIN_FORM_RE, _LOGIN_REDIRECT_RE

# WAF/CDN 챌린지·차단 페이지 마커(응답이 앱이 아니라 방어장비)
_CHALLENGE_RE = re.compile(
    r"checking your browser|just a moment|attention required|/cdn-cgi/challenge|"
    r"cf-challenge|please (?:enable|turn on) (?:cookies|javascript)|"
    r"captcha|recaptcha|hcaptcha|are you (?:a )?human|bot ?detection|"
    r"access denied|request (?:blocked|unauthorized|rejected)|"
    r"이 ?요청(?:은|이) ?차단|비정상적?인? ?(?:접근|트래픽)|자동화된 ?(?:봇|접근)", re.I)

# 리소스 수준 프로브(파일 읽기·CVE 경로 등) — 여기선 302/401/403 이 '미도달'이 아니라
# '리소스 보호/부재/미해당 = 안전'이라는 정당한 결론이다. auth 관련 미도달 경고에서 제외.
_RESOURCE_PROBE = frozenset({"cve", "lfi", "file"})

# 대조군(baseline)이 있어야 단일 응답으로 판정 가능한 공격
_NEEDS_BASELINE = frozenset({"authbypass", "idor"})
# 블라인드/불리언/타임 계열(페이로드로 감지) — 역시 대조군 필요
_BLIND_HINT = re.compile(
    r"sleep\s*\(|pg_sleep|waitfor\s+delay|benchmark\s*\(|dbms_pipe|"
    r"'\s*(?:or|and)\s*'?\d|\b(?:or|and)\b\s+\d+\s*=\s*\d+", re.I)


def _hdr(h, name: str) -> str:
    if not h:
        return ""
    try:
        return str(h.get(name, "") or "")
    except Exception:
        return ""


def assess(*, status_code: int, headers_lower=None, body: str = "", body_lower: str = "",
           url: str = "", method: str = "", req_headers=None, req_body: str = "",
           payload: str = "", category: str = "", attack_type: str = "",
           baseline=None, redirect_chain=None, followed_redirects: bool = False,
           waf=None) -> dict:
    warnings = []
    body_lower = body_lower or (body or "").lower()
    loc = _hdr(headers_lower, "location")
    try:
        path = (urlsplit(url or "").path or "").lower()
    except Exception:
        path = ""
    cat = (category or "").lower()
    atype = (attack_type or "").lower()
    # 리소스 프로브면 302/401/403 은 정당한 '안전' 결론 → auth 관련 미도달 경고를 끈다.
    resource_probe = cat in _RESOURCE_PROBE or atype in _RESOURCE_PROBE

    # ── B. 대상 미도달(응답이 앱이 아니거나 벽에 막힘) ─────────────────────────
    # 1) WAF/CDN 챌린지·차단 페이지(본문 마커는 항상, 상태코드-only 휴리스틱은 리소스 프로브 제외)
    if _CHALLENGE_RE.search(body_lower) or (waf and not resource_probe
                                            and status_code in (403, 406, 503) and len(body or "") < 4000):
        warnings.append({
            "code": "waf_challenge", "severity": "block",
            "why": "응답이 대상 앱이 아니라 방어장비/CDN 차단·챌린지 페이지로 보임"
                   + (f" (WAF: {waf})" if waf else ""),
            "fix": "정상 브라우저 세션·쿠키를 실어 재시도하거나 접근 IP·속도를 조정. 이 응답으로는 취약 여부를 판정할 수 없음.",
        })

    # 2) 레이트리밋
    if status_code == 429 or _hdr(headers_lower, "retry-after"):
        warnings.append({
            "code": "rate_limited", "severity": "block",
            "why": f"레이트리밋 응답(HTTP {status_code}"
                   + (", Retry-After 있음" if _hdr(headers_lower, "retry-after") else "") + ")",
            "fix": "요청 속도를 낮추거나 잠시 후 재시도. 지금 응답은 공격 결과가 아님.",
        })

    # 3) 인증 필요인데 자격증명 미제공(리소스 프로브 제외 — 거기선 401 이 '미해당=안전')
    if not resource_probe and (status_code == 401 or _hdr(headers_lower, "www-authenticate")):
        warnings.append({
            "code": "auth_required", "severity": "block",
            "why": f"인증 필요(HTTP {status_code}"
                   + (", WWW-Authenticate" if _hdr(headers_lower, "www-authenticate") else "") + ") — 자격증명 미제공",
            "fix": "유효한 세션 쿠키 또는 Authorization 헤더를 요청에 추가한 뒤 재시도.",
        })

    # 4) 로그인 벽(리다이렉트/폼) — 이 요청 자체가 로그인 시도가 아니고 리소스 프로브도 아닐 때만
    is_login_probe = bool(_LOGIN_REDIRECT_RE.search(path)) or atype == "authbypass" or cat == "authbypass"
    if not is_login_probe and not resource_probe:
        redirect_to_login = status_code in (301, 302, 303, 307, 308) and bool(_LOGIN_REDIRECT_RE.search(loc))
        # 로그인 폼 페이지: 비밀번호 필드 + 작은 본문(전체 앱 페이지가 아니라 로그인 화면)
        body_is_login = bool(_LOGIN_FORM_RE.search(body or "")) and status_code == 200 and len(body or "") < 8000
        if redirect_to_login or body_is_login:
            warnings.append({
                "code": "auth_wall", "severity": "block",
                "why": ("응답이 로그인 페이지로 리다이렉트됨" if redirect_to_login
                        else "응답이 로그인 폼 화면") + " — 대상 엔드포인트가 아니라 인증 벽에 막힌 것",
                "fix": "로그인 후 세션 쿠키를 실어 재시도. 지금의 '안전'은 대상 미도달일 뿐임.",
            })

    # ── C. 판정 신뢰도 ─────────────────────────────────────────────────────────
    # 5) 페이로드가 실제 요청에 안 실림(위치·파라미터·인코딩 문제로 미착지)
    if payload and payload.strip():
        core = re.findall(r"[A-Za-z0-9_]{4,}", payload)   # 인코딩에 강한 핵심 토큰
        if core:
            hdr_vals = " ".join(str(v) for v in (req_headers or {}).values())
            hay = f"{url or ''} {req_body or ''} {hdr_vals}"
            hay = (hay + " " + unquote(hay)).lower()
            if not any(t.lower() in hay for t in core):
                warnings.append({
                    "code": "payload_not_sent", "severity": "warn",
                    "why": "지정한 페이로드가 실제 요청(URL/바디/헤더)에서 발견되지 않음 — 삽입 위치·파라미터·인코딩 문제로 대상에 미착지했을 수 있음",
                    "fix": "삽입 위치(path/param/body/header)와 파라미터 이름이 요청에 실제로 존재하는지 확인.",
                })

    # 6) 대조군 필요한 공격인데 baseline 없음
    needs_base = (atype in _NEEDS_BASELINE or cat in _NEEDS_BASELINE
                  or bool(payload and _BLIND_HINT.search(payload)))
    has_base = bool(baseline and baseline.get("status_code") is not None)
    if needs_base and not has_base:
        warnings.append({
            "code": "no_baseline", "severity": "warn",
            "why": "이 공격(인증우회·IDOR·블라인드/불리언)은 정상 대조군과 비교해야 판정 가능한데 baseline 이 없음",
            "fix": "정상(실패/권한없음) 요청을 먼저 보내 'baseline 저장' 후 공격을 재전송.",
        })

    # 7) 3xx 인데 리다이렉트 미추적 → 목적지 미확인(오픈리다이렉트·리소스 프로브는 미추적이 정상)
    if (status_code in (301, 302, 303, 307, 308) and not followed_redirects and loc
            and cat != "redirect" and atype != "redirect" and not resource_probe):
        warnings.append({
            "code": "redirect_not_followed", "severity": "warn",
            "why": f"3xx 리다이렉트({loc[:60]})를 따라가지 않아 최종 목적지 본문을 확인하지 못함",
            "fix": "필요하면 '리다이렉트 추적'을 켜 목적지에서 성공 여부를 확증.",
        })

    return {"ok": not any(w["severity"] == "block" for w in warnings), "warnings": warnings}
