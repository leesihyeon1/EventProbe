"""AI 반출(egress) 공통 정책 — 모든 외부 추론/임베딩 호출의 단일 검사 지점.

외부 AI provider 로 나가는 호출은 사실상 두 chokepoint 로만 모인다:
  - ai_analyzer._post_chat   → {base}/chat/completions  (agent.choose_action 도 재사용)
  - rag._embed_batch         → {base}/embeddings
이 모듈을 두 지점이 공통으로 호출하므로, 반출 규칙은 UI 옵션이나 기능별 플래그로
우회할 수 없다(리뷰 F1 "공통 외부 전송 정책 … 우회 불가").

모드(AI_EXPORT_MODE):
  permissive (기본) — 기존 동작. 스캐너는 돌지만 금지 데이터가 있어도 전송은 진행하고
    경고 로그 + 감사 레코드만 남긴다(비파괴적 전환).
  strict — 외부(사외) 목적지로 나가는 호출에 block 등급 금지 데이터가 있으면
    EgressBlocked 를 올려 전송 자체를 막는다. 사내/로컬 목적지는 외부 반출이 아니므로
    차단하지 않는다(로컬 모델·사내 임베딩 허용 — 리뷰 권장).

주의: 이 스캐너는 심층 방어용 2차 탐지 장치다. 1차 경계는 상위에서 만든다
(비식별 요청 구조·로컬 판정 템플릿·로컬 임베딩). 스캐너는 그 위를 빠져나온 유출을 잡는다.
설정 하나/정규식 하나로 모든 유출이 사라진다고 표현하지 않는다(리뷰).
"""
import collections
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

log = logging.getLogger("eventprobe.egress")

POLICY_VERSION = "1"

# ── 모드 ──────────────────────────────────────────────────────────────────────
def export_mode() -> str:
    """현재 반출 모드. AI_EXPORT_MODE 가 strict/1/true/on 이면 'strict', 아니면 'permissive'."""
    raw = (os.getenv("AI_EXPORT_MODE", "") or "").strip().lower()
    return "strict" if raw in ("strict", "1", "true", "yes", "on") else "permissive"


def is_strict() -> bool:
    return export_mode() == "strict"


# ── 사내/로컬 목적지 판별 ──────────────────────────────────────────────────────
# 외부 반출 경계는 '사외'로 나갈 때만 적용한다. 로컬 모델(AI_BASE_URL=localhost)이나
# 사내 임베딩 엔드포인트로 가는 트래픽은 반출이 아니므로 차단하지 않는다.
_RE_PRIVATE_IP = re.compile(
    r"^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})$")


def _is_internal_host(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    if h in ("localhost", "::1", "0.0.0.0"):
        return True
    if h.endswith(".local") or h.endswith(".internal") or h.endswith(".localhost"):
        return True
    if _RE_PRIVATE_IP.match(h):
        return True
    extra = os.getenv("AI_INTERNAL_HOSTS", "")
    return any(h == e.strip().lower() for e in extra.split(",") if e.strip())


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def is_internal_destination(url: str) -> bool:
    """URL 의 호스트가 사내/로컬이면 True(외부 반출 아님)."""
    return _is_internal_host(_host_of(url))


def embeddings_allowed(base_url: str) -> bool:
    """임베딩 호출 허용 여부. strict 에서 '외부' 엔드포인트면 False → 상위에서 로컬 BM25 폴백.
    내부 문서/질의를 외부 임베딩 API 로 보내는 경로를 원천 차단한다(리뷰 F3)."""
    if not is_strict():
        return True
    return is_internal_destination(base_url)


# ── 카나리 레지스트리 ──────────────────────────────────────────────────────────
# 절대 반출되면 안 되는 '정확히 알려진' 민감 문자열(실행별 대상 호스트·자격증명·응답 마커).
# 앱이 실행마다 등록하고(예: 대상 URL 의 호스트), 테스트가 합성 마커를 등록한다.
# 콘텐츠 패턴만으로는 공개 지식 속 example 도메인과 실제 대상 도메인을 구분할 수 없으므로,
# 대상 식별자는 이 고정밀 레지스트리로 막는다(리뷰: 실행별 임의 ID + 내부 매핑).
_canaries: set[str] = set()
_lock = threading.Lock()


def register_canary(*values) -> None:
    """반출 금지 문자열 등록(4자 미만은 대량 오탐 우려로 무시)."""
    with _lock:
        for v in values:
            s = str(v or "").strip()
            if len(s) >= 4:
                _canaries.add(s)


def clear_canaries() -> None:
    with _lock:
        _canaries.clear()


def _canary_hits(text: str) -> list:
    with _lock:
        snapshot = tuple(_canaries)
    if not snapshot:
        return []
    low = text.lower()
    return [c for c in snapshot if c.lower() in low]


# ── 패턴 탐지기 ────────────────────────────────────────────────────────────────
# block 등급: AI 프롬프트에 정상적으로는 거의 나타나지 않는 고정밀 민감 토큰.
# warn 등급: 공개 지식·페이로드에도 합법적으로 나타날 수 있어 감사만 한다
#            (예: SSRF 페이로드의 169.254.169.254, 문서 속 예시 URL).
_EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net", "example.edu",
                    "example.test", "example", "invalid", "localhost")

_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
_RE_AWS = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b")
_RE_COOKIE = re.compile(r"(?im)^\s*(?:set-)?cookie\s*:\s*\S")
_RE_AUTHZ = re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic|digest)\s+\S")
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_RE_URL = re.compile(r"(?i)\bhttps?://([A-Za-z0-9.\-]+)")
_RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

_SCAN_LIMIT = 100_000   # 스캔 대상 문자열 상한(성능 방어)


@dataclass
class Violation:
    kind: str        # canary|jwt|aws_key|cookie|authorization|email|url|ipv4
    severity: str    # "block" | "warn"
    sample: str      # 감사용 축약 샘플(원문 민감값을 그대로 로깅하지 않음)


def _redact(s: str, keep: int = 4) -> str:
    s = str(s)
    return (s[:keep] + f"…({len(s)})") if len(s) > keep else f"…({len(s)})"


def _example_domain(dom: str) -> bool:
    d = (dom or "").lower().rstrip(".")
    return any(d == e or d.endswith("." + e) for e in _EXAMPLE_DOMAINS)


def scan(text: str) -> list:
    """텍스트에서 금지 데이터 후보를 찾는다. 종류별 첫 매치만(감사 간결화)."""
    text = (text or "")[:_SCAN_LIMIT]
    out: list = []
    for c in _canary_hits(text):
        out.append(Violation("canary", "block", _redact(c)))
        break
    m = _RE_JWT.search(text)
    if m:
        out.append(Violation("jwt", "block", _redact(m.group(0))))
    m = _RE_AWS.search(text)
    if m:
        out.append(Violation("aws_key", "block", _redact(m.group(0))))
    if _RE_COOKIE.search(text):
        out.append(Violation("cookie", "block", "cookie-header"))
    if _RE_AUTHZ.search(text):
        out.append(Violation("authorization", "block", "authz-header"))
    for m in _RE_EMAIL.finditer(text):
        if not _example_domain(m.group(1)):
            out.append(Violation("email", "block", _redact(m.group(0))))
            break
    for m in _RE_URL.finditer(text):
        host = m.group(1)
        if not _example_domain(host) and not _is_internal_host(host):
            out.append(Violation("url", "warn", _redact(host)))
            break
    m = _RE_IPV4.search(text)
    if m:
        out.append(Violation("ipv4", "warn", _redact(m.group(0))))
    return out


# ── 감사 기록 ──────────────────────────────────────────────────────────────────
# 전송 시각·채널·모드·정책 버전·모델·길이·발견 종류·차단 여부만 남긴다.
# 탈락한 민감 원문은 기록하지 않는다(리뷰: "탈락한 민감 원문을 일반 로그에 다시 기록하지 않음").
_audit_buf = collections.deque(maxlen=500)


def _audit(channel: str, model: str, chars: int, host: str,
           violations: list, blocked: bool, trusted: bool) -> None:
    _audit_buf.append({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "channel": channel,
        "mode": export_mode(),
        "policy": POLICY_VERSION,
        "model": model,
        "dest_host": host,
        "trusted_dest": trusted,
        "chars": chars,
        "findings": [{"kind": v.kind, "severity": v.severity, "sample": v.sample}
                     for v in violations],
        "blocked": blocked,
    })


def audit_log(limit: int = 100) -> list:
    """최근 반출 감사 레코드(최신순 아님 — 기록순). 운영/디버그/테스트용."""
    return list(_audit_buf)[-limit:]


def clear_audit() -> None:
    _audit_buf.clear()


# ── 예외 ──────────────────────────────────────────────────────────────────────
class EgressBlocked(Exception):
    """strict 모드에서 금지 데이터가 외부 전송 직전 탐지돼 전송을 막았을 때."""

    def __init__(self, channel: str, violations: list):
        self.channel = channel
        self.violations = violations
        kinds = ", ".join(sorted({v.kind for v in violations})) or "?"
        super().__init__(
            f"반출 차단(strict): {channel} 채널에 금지 데이터({kinds})가 포함되어 "
            f"외부 전송을 중단했습니다.")


# ── 추출 + 관문 ────────────────────────────────────────────────────────────────
def _payload_text(payload: dict, channel: str) -> str:
    """검사 대상 텍스트만 뽑는다. provider 전송 헤더(우리 API 키)는 포함하지 않는다."""
    if not isinstance(payload, dict):
        return str(payload or "")
    if channel == "chat":
        msgs = payload.get("messages") or []
        return "\n".join(str(m.get("content", "")) for m in msgs if isinstance(m, dict))
    if channel == "embeddings":
        inp = payload.get("input")
        if isinstance(inp, list):
            return "\n".join(str(x) for x in inp)
        return str(inp or "")
    return str(payload)


def guard(payload: dict, *, channel: str, destination_url: str = "") -> dict:
    """외부 전송 직전 payload 를 검사한다.

    - 사내/로컬 목적지: 반출이 아니므로 차단하지 않고 감사만 한다.
    - strict + 외부 목적지 + block 등급 발견: EgressBlocked 를 올려 전송을 막는다.
    - permissive: 경고 로그 + 감사만 남기고 전송은 진행한다(비파괴적).
    payload 를 그대로 반환한다(호출부 편의)."""
    text = _payload_text(payload, channel)
    host = _host_of(destination_url)
    trusted = _is_internal_host(host)
    violations = scan(text)
    blockers = [v for v in violations if v.severity == "block"]
    will_block = bool(blockers) and is_strict() and not trusted
    _audit(channel, (payload or {}).get("model", "") if isinstance(payload, dict) else "",
           len(text), host, violations, will_block, trusted)
    if will_block:
        raise EgressBlocked(channel, blockers)
    if violations and not trusted:
        log.warning("egress[%s/%s→%s]: %d finding(s): %s", export_mode(), channel,
                    host or "?", len(violations),
                    "; ".join(f"{v.kind}:{v.severity}" for v in violations))
    return payload
