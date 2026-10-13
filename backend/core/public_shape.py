"""비식별 요청 구조(PublicRequestShape) — 외부 AI 로 보낼 수 있는 '허용된 구조만' 담은 표현.

리뷰 F2: 원문에서 민감 부분을 '지우는' 방식 대신, 허용된 필드만 포함하는 새 구조를
생성한다. 경로의 동적 값, 쿼리/바디 값, 비허용 헤더는 애초에 포함하지 않는다. 알 수 없는
형식은 변환 불가(shapeable=False)로 표시해 strict 에서 전송을 거부한다.

무엇을 남기나(데이터 경계 표의 '허용'):
  - method, 동적 값을 제거한 경로 템플릿(/api/orders/{id})
  - 쿼리·바디의 '필드 이름 + 타입'(값은 제외)
  - 허용 목록에 있는 헤더 '이름'과 정규화된 Content-Type(표준 MIME)
  - 공격 신호 토큰: 값 중 인젝션 메타문자를 담은 부분(= 사용자가 넣은 테스트 페이로드).
    업무 값이 아니라 점검 입력이므로, 분류/후보 생성이 동작하도록 이것만 남긴다.

무엇을 빼나: 실제 도메인/호스트, 쿼리·바디의 실제 값, 비표준/민감 헤더와 그 값.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, parse_qsl

from core.ai_privacy import SENSITIVE_HEADERS

# 외부로 '이름'을 보내도 되는 헤더(값은 보내지 않거나 정규화). 그 외 이름은 제외한다.
# 표준 협상 헤더 + 인젝션이 의미 있는 헤더 이름(실제 주입은 하지 않고 '이름'만 구조로 전달).
_ALLOWED_HEADER_NAMES = frozenset({
    "accept", "accept-encoding", "accept-language", "content-type", "content-length",
    "user-agent", "referer", "origin", "connection", "cache-control", "pragma",
    "x-requested-with", "upgrade-insecure-requests", "dnt", "te",
    # 인젝션이 의미 있는 헤더 이름(ai_suggest 의 INJECTABLE_HEADERS 와 정렬)
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-original-url",
    "x-rewrite-url", "true-client-ip", "x-real-ip", "forwarded", "cf-connecting-ip",
    "x-host", "x-custom-ip-authorization",
})

# 표준 MIME 로 정규화할 Content-Type 기본형(파라미터/charset 제거 후). 그 외는 "other".
_KNOWN_MIME = frozenset({
    "application/json", "application/x-www-form-urlencoded", "multipart/form-data",
    "text/plain", "text/html", "text/xml", "application/xml", "application/octet-stream",
    "application/graphql", "application/ld+json",
})

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{8,}$", re.I)
_LONG_TOKEN = re.compile(r"^[A-Za-z0-9_\-]{16,}$")
_INT = re.compile(r"^-?\d+$")
_FLOAT = re.compile(r"^-?\d+\.\d+$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# 값에서 '공격 신호'를 식별하는 시그니처(이 토큰만 분류/후보 생성에 넘긴다).
_ATTACK_SIG = re.compile(
    r"""['"<>;|&$`()\\]|\bUNION\b|\bSELECT\b|\bINSERT\b|\bOR\b\s+\d|\bAND\b\s+\d|--|/\*|"""
    r"""\balert\(|\bon\w+\s*=|<script|javascript:|%[0-9a-fA-F]{2}|\$\{|\{\{|\.\./|\.\.\\|"""
    r"""/etc/|/proc/|\bexec\b|\bsleep\(|\bwaitfor\b|\bbenchmark\(|\|\||&&""", re.I)

_MAX_FIELDS = 40
_MAX_TOKENS = 20
_TOKEN_LEN = 200


@dataclass
class FieldShape:
    name: str
    type: str

    def as_tuple(self):
        return (self.name, self.type)


@dataclass
class PublicRequestShape:
    method: str = "GET"
    path_template: str = "/"
    query_fields: list = field(default_factory=list)   # [FieldShape]
    body_kind: str = "none"                             # none|json|form|xml|multipart|unknown
    body_fields: list = field(default_factory=list)     # [FieldShape]
    header_names: list = field(default_factory=list)     # 허용된 이름만
    content_type: str = ""                               # 정규화된 표준 MIME 또는 ""
    attack_tokens: list = field(default_factory=list)    # 값 중 공격 신호 부분
    dropped: list = field(default_factory=list)          # 제외/정규화된 항목(투명성)
    shapeable: bool = True                               # False → strict 에서 전송 거부

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path_template": self.path_template,
            "query_fields": [f.as_tuple() for f in self.query_fields],
            "body_kind": self.body_kind,
            "body_fields": [f.as_tuple() for f in self.body_fields],
            "header_names": self.header_names,
            "content_type": self.content_type,
            "attack_tokens": self.attack_tokens,
            "shapeable": self.shapeable,
        }

    def fields_json(self, fields: list) -> str:
        return json.dumps({f.name: f.type for f in fields}, ensure_ascii=False)[:800]

    def query_types(self) -> dict:
        return {f.name: f.type for f in self.query_fields}

    def prompt_body(self) -> str:
        """프롬프트용 바디 요약 — 구조(필드:타입) + 공격 신호 토큰(값은 제외)."""
        parts = []
        if self.body_kind != "none":
            flds = ", ".join(f"{f.name}:{f.type}" for f in self.body_fields) or "(opaque)"
            parts.append(f"[{self.body_kind}] fields={{{flds}}}")
        if self.attack_tokens:
            parts.append("signals=" + json.dumps(self.attack_tokens, ensure_ascii=False)[:300])
        return "; ".join(parts) or "(none)"


# ── 타입 추론 ──────────────────────────────────────────────────────────────────
def _value_type(v) -> str:
    s = str(v)
    if s == "":
        return "empty"
    if s.lower() in ("true", "false"):
        return "bool"
    if _INT.match(s):
        return "int"
    if _FLOAT.match(s):
        return "float"
    if _UUID.match(s):
        return "uuid"
    if _EMAIL.match(s):
        return "email"
    if s.startswith(("http://", "https://")):
        return "url"
    if s[:1] in ("{", "["):
        return "json"
    if _HEX.match(s):
        return "hex"
    return "string"


def _dynamic_segment(seg: str) -> bool:
    if not seg:
        return False
    if _INT.match(seg) or _UUID.match(seg) or _HEX.match(seg) or _LONG_TOKEN.match(seg):
        return True
    # 점(.) 포함 파일명이 아니고 숫자를 품은 토큰이면 식별자로 간주(예: v2 는 유지, order123 은 치환)
    if any(c.isdigit() for c in seg) and "." not in seg and not seg.lower().startswith("v"):
        return True
    return False


def _path_template(path: str) -> str:
    segs = (path or "/").split("/")
    out = ["{id}" if _dynamic_segment(s) else s for s in segs]
    return "/".join(out) or "/"


def _collect_attack_tokens(values) -> list:
    out, seen = [], set()
    for v in values:
        s = str(v)
        if s and _ATTACK_SIG.search(s):
            tok = s[:_TOKEN_LEN]
            if tok not in seen:
                seen.add(tok)
                out.append(tok)
        if len(out) >= _MAX_TOKENS:
            break
    return out


def _shape_fields(pairs) -> list:
    out, seen = [], set()
    for name, value in pairs:
        n = str(name)
        if n in seen:
            continue
        seen.add(n)
        out.append(FieldShape(n, _value_type(value)))
        if len(out) >= _MAX_FIELDS:
            break
    return out


def _parse_body(body: str):
    """(kind, pairs, shapeable, values). pairs=[(name,value)], values=모든 값(공격토큰 추출용)."""
    raw = (body or "").strip()
    if not raw:
        return "none", [], True, []
    # JSON
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            pairs = [(k, v) for k, v in data.items()]
            return "json", pairs, True, [v for _, v in pairs]
        if isinstance(data, list):
            return "json", [("[]", "array")], True, [json.dumps(data)]
    except (ValueError, TypeError):
        pass
    # XML
    if raw[:1] == "<":
        tags = re.findall(r"<([A-Za-z_][\w.\-]*)", raw)[:_MAX_FIELDS]
        # XML 요소 값(태그 사이 텍스트)도 공격토큰 추출 대상에 포함
        texts = re.findall(r">([^<]+)<", raw)
        pairs = [(t, "xml") for t in dict.fromkeys(tags)]
        return "xml", pairs, True, texts
    # form-urlencoded — '=' 가 있어야 폼으로 본다(keep_blank_values 가 산문을 폼으로
    # 오인하지 않도록). 예: "free prose" → unknown, "a=1&b=" → form.
    if "=" in raw:
        fields = parse_qsl(raw, keep_blank_values=True)
        if fields:
            return "form", fields, True, [v for _, v in fields]
    # 알 수 없는 형식 → 변환 불가
    return "unknown", [], False, []


def _norm_content_type(headers: dict) -> str:
    for k, v in (headers or {}).items():
        if str(k).strip().lower() == "content-type":
            base = str(v).split(";")[0].strip().lower()
            return base if base in _KNOWN_MIME else "other"
    return ""


def _shape_headers(headers: dict):
    """허용 목록에 있는 헤더 '이름'만 남기고, 제외된 이름을 dropped 로 반환."""
    names, dropped = [], []
    for k in (headers or {}).keys():
        low = str(k).strip().lower()
        if low in SENSITIVE_HEADERS:
            dropped.append(f"header:{low}")
        elif low in _ALLOWED_HEADER_NAMES:
            names.append(low)
        else:
            dropped.append(f"header:{low}")
    return names, dropped


def build(method: str = "GET", url: str = "", params=None, body: str = "",
          headers=None) -> PublicRequestShape:
    """요청 입력을 비식별 구조로 변환한다. host·실제 값은 포함하지 않는다."""
    params = params or {}
    headers = headers or {}
    parts = urlsplit(url or "")
    path = parts.path or "/"

    query_pairs = list(params.items()) + parse_qsl(parts.query, keep_blank_values=True)
    query_fields = _shape_fields(query_pairs)

    body_kind, body_pairs, body_ok, body_values = _parse_body(body)
    body_fields = _shape_fields(body_pairs)

    header_names, dropped = _shape_headers(headers)
    content_type = _norm_content_type(headers)

    attack_tokens = _collect_attack_tokens(
        [v for _, v in query_pairs] + body_values + [str(path)])

    dropped_extra = []
    if parts.hostname:
        dropped_extra.append("host")
    if parts.query:
        dropped_extra.append("query-values")
    if body_kind not in ("none", "unknown"):
        dropped_extra.append("body-values")

    return PublicRequestShape(
        method=(method or "GET").upper(),
        path_template=_path_template(path),
        query_fields=query_fields,
        body_kind=body_kind,
        body_fields=body_fields,
        header_names=header_names,
        content_type=content_type,
        attack_tokens=attack_tokens,
        dropped=dropped + dropped_extra,
        shapeable=body_ok,
    )
