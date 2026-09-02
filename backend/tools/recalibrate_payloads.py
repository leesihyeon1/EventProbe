#!/usr/bin/env python3
"""페이로드 뱅크(비-CVE) 재보정 — risk 라벨 일관화 + header 페이로드 구조화.

배경: risk 의 68%가 high 로 몰려 변별력이 낮았고, header 카테고리는 param(대상 헤더)이
비어 있거나 'Header: value' 통짜 문자열이라 원클릭 적용이 부정확했다.

이 스크립트는 backend/data/payloads.json 의 'cve' 를 제외한 카테고리에 대해:
  1) risk = '성공 시 영향도' 기준으로 카테고리 베이스라인 재설정
     + 보수적 상향(RCE 신호) / 하향(단순 탐지·감지) 규칙.
  2) header 카테고리: 'Header: value' → param=Header, payload=value 로 정규화하고,
     값만 있는 항목은 name 에서 헤더명을 유추해 param 채움. 정규화 후 (param,payload)
     중복 제거.

멱등적(여러 번 돌려도 결과 동일). 실행 후 git diff 로 검토할 것.
"""
from __future__ import annotations

import json
import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PAYLOADS = os.path.join(_ROOT, "data", "payloads.json")

# ── ① risk 베이스라인: '이 취약점이 성공하면 어느 정도인가' ──────────────────
_BASELINE = {
    "cmdi": "critical", "ssti": "critical", "deserial": "critical",
    "sqli": "high", "ssrf": "high", "lfi": "high", "xxe": "high",
    "xpath": "high", "ldap": "high", "nosql": "high", "jwt": "high",
    "business": "high", "access403": "high", "upload": "high",
    "prototype": "high", "ssi": "high",
    "xss": "medium", "redirect": "medium", "header": "medium", "crlf": "medium",
    "cors": "medium", "hpp": "medium", "cache": "medium", "graphql": "medium",
    "csv": "medium", "cssinj": "medium", "domclob": "medium", "email": "medium",
}
_ORDER = ["info", "low", "medium", "high", "critical"]

# 성공 시 RCE/원격 실행이 명백한 신호 → 한 단계 상향
_UP_RE = re.compile(
    r"rce|원격\s*코드|코드\s*실행|명령\s*실행|역직렬화|xp_cmdshell|load_file|"
    r"out-?of-?band|\boob\b|webshell|웹셸|리버스\s*셸|reverse shell", re.I)
# 단순 탐지/감지/버전확인 등 → 한 단계 하향
_DOWN_RE = re.compile(
    r"탐지|감지|버전\s*확인|핑거프린|fingerprint|존재\s*확인|오류\s*유발|"
    r"에러\s*메시지\s*유발|테스트\s*문자열|probe", re.I)


def _shift(risk: str, delta: int) -> str:
    i = _ORDER.index(risk) if risk in _ORDER else 2
    return _ORDER[max(0, min(len(_ORDER) - 1, i + delta))]


def recalc_risk(cat_id: str, p: dict) -> str:
    base = _BASELINE.get(cat_id, "medium")
    text = f"{p.get('name', '')} {p.get('description', '')}"
    if _UP_RE.search(text):
        base = _shift(base, +1)
    elif _DOWN_RE.search(text):
        base = _shift(base, -1)
    return base


# ── ② header 정규화 ──────────────────────────────────────────────────────────
# 값만 있는 항목(name → 대상 헤더명) 유추표
_NAME_TO_HEADER = [
    ("host", "Host"), ("x-forwarded-for", "X-Forwarded-For"), ("x-real-ip", "X-Real-IP"),
    ("x-originating-ip", "X-Originating-IP"), ("user-agent", "User-Agent"),
    ("referer", "Referer"), ("x-http-method-override", "X-HTTP-Method-Override"),
    ("content-type", "Content-Type"), ("origin", "Origin"),
    ("x-custom-ip-authorization", "X-Custom-IP-Authorization"), ("x-remote-addr", "X-Remote-Addr"),
    ("x-forwarded-host", "X-Forwarded-Host"), ("x-forwarded-proto", "X-Forwarded-Proto"),
    ("x-forwarded-server", "X-Forwarded-Server"), ("x-client-ip", "X-Client-IP"),
    ("true-client-ip", "True-Client-IP"), ("x-host", "X-Host"),
    ("x-original-url", "X-Original-URL"), ("x-rewrite-url", "X-Rewrite-URL"),
]
# 한 줄 'Header: value' 판별(멀티라인/CRLF 인젝션 payload 는 제외).
# 헤더명에는 '-'/문자만, URL 스킴(http/https 등)은 헤더가 아니므로 제외.
_ONE_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]{1,40}):\s?(.+)$")
_URL_SCHEMES = {"http", "https", "ftp", "ws", "wss", "data", "javascript", "view-source", "file"}


def _header_name_from_name(name: str) -> str:
    n = (name or "").lower()
    for key, hdr in _NAME_TO_HEADER:
        if n.startswith(key) or key in n:
            return hdr
    return ""


def normalize_header(p: dict) -> dict:
    payload = p.get("payload", "")
    has_crlf = any(t in payload for t in ("\r", "\n", "%0d", "%0a"))
    if not has_crlf:
        m = _ONE_HEADER_RE.match(payload.strip())
        # 'Referer: https://x' 는 분해(토큰=Referer), 'https://x' 는 분해 안 함(토큰=스킴)
        if m and m.group(1).lower() not in _URL_SCHEMES and not p.get("param"):
            p["param"] = m.group(1)
            p["payload"] = m.group(2).strip()
            return p
    if not p.get("param"):
        hdr = _header_name_from_name(p.get("name", ""))
        if hdr and not has_crlf:
            p["param"] = hdr
    return p


def main():
    data = json.load(open(_PAYLOADS, encoding="utf-8"))
    risk_changed = 0
    hdr_paramed = 0
    hdr_removed = 0
    for cat in data["categories"]:
        cid = cat["id"]
        if cid == "cve":
            continue
        # ② header 정규화 + 중복 제거
        if cid == "header":
            seen, kept = set(), []
            for p in cat["payloads"]:
                before = p.get("param", "")
                normalize_header(p)
                if p.get("param") and not before:
                    hdr_paramed += 1
                key = ((p.get("param") or "").lower(), p.get("payload"))
                if key in seen:
                    hdr_removed += 1
                    continue
                seen.add(key)
                kept.append(p)
            cat["payloads"] = kept
        # ① risk 재보정
        for p in cat["payloads"]:
            new = recalc_risk(cid, p)
            if new != p.get("risk"):
                p["risk"] = new
                risk_changed += 1

    with open(_PAYLOADS, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")

    # 요약
    import collections
    rc = collections.Counter(p.get("risk", "") for c in data["categories"]
                             if c["id"] != "cve" for p in c["payloads"])
    print(f"risk 변경: {risk_changed} | header param 채움: {hdr_paramed} | header 중복 제거: {hdr_removed}")
    print("재보정 후 risk 분포(비-CVE):", dict(rc))


if __name__ == "__main__":
    main()
