"""OOB(out-of-band) 콜백 — interactsh 클라이언트.

blind 계열(cmdi·ssrf·xxe·log4shell 등)은 응답만으로 확증 못 하고, 대상이 우리 서버로
DNS/HTTP 콜백을 보내야 확인된다. interactsh 서버(공개 oast.fun 또는 self-host)에 붙어
콜백을 받아온다.

프로토콜(interactsh):
  register: POST /register {public-key(b64 PEM), secret-key(uuid), correlation-id(20자)}
  host    : <correlation-id><random13>.<domain>  (33자 라벨)
  poll    : GET /poll?id=<correlation-id>&secret=<secret> → {data:[b64...], aes_key:b64}
            aes_key = RSA-OAEP(SHA256) 로 암호화된 AES-256 키
            data 각 항목 = base64(IV(16) + AES-256-CFB(ciphertext))

설정(.env): OOB_ENABLED, OOB_SERVER, OOB_DOMAIN(선택), OOB_TOKEN(-auth 시), OOB_POLL_SEC
"""
import os
import re
import base64
import json
import uuid
import secrets
import threading
from urllib.parse import urlsplit
from typing import Optional

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
try:                                    # CFB 위치가 버전에 따라 다름(48+는 decrepit 로 이동)
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except Exception:                       # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.modes import CFB

_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"


def _rand(n: int) -> str:
    return "".join(secrets.choice(_ALNUM) for _ in range(n))


def _env(k: str, d: str = "") -> str:
    return (os.getenv(k) or d).strip()


def enabled() -> bool:
    return _env("OOB_ENABLED").lower() in ("1", "true", "yes", "on") and bool(_env("OOB_SERVER"))


def _server() -> str:
    return _env("OOB_SERVER").rstrip("/")


def _token() -> str:
    return _env("OOB_TOKEN")


def _domain() -> str:
    """OOB 호스트를 만들 도메인. OOB_DOMAIN 우선, 없으면 서버 URL 호스트."""
    d = _env("OOB_DOMAIN")
    if d:
        return d.lstrip(".")
    return (urlsplit(_server()).hostname or "").lstrip(".")


def poll_sec() -> int:
    try:
        return max(2, int(_env("OOB_POLL_SEC", "5")))
    except ValueError:
        return 5


class _Interactsh:
    """단일 세션 클라이언트 — 프로세스당 한 번 register 하고 여러 마커를 발급/폴링한다."""

    def __init__(self):
        self._lock = threading.Lock()
        self._priv = None
        self._corr = ""
        self._secret = ""
        self._registered = False
        self._markers: dict = {}        # 33자 unique-id → {url, payload, ts, location}
        self._seen: set = set()         # 중복 콜백 제거(interaction unique key)

    # ── 등록 ────────────────────────────────────────────────────────────────
    async def _ensure_registered(self) -> bool:
        if self._registered:
            return True
        with self._lock:
            if self._registered:
                return True
            self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub_pem = self._priv.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            self._corr = _rand(20)
            self._secret = str(uuid.uuid4())
            body = {"public-key": base64.b64encode(pub_pem).decode(),
                    "secret-key": self._secret, "correlation-id": self._corr}
            headers = {"Content-Type": "application/json"}
            if _token():
                headers["Authorization"] = _token()
            try:
                async with httpx.AsyncClient(timeout=20, verify=True) as c:
                    r = await c.post(f"{_server()}/register", json=body, headers=headers)
                if r.status_code != 200:
                    return False
                self._registered = True
                return True
            except Exception:
                return False

    # ── 마커 발급 ────────────────────────────────────────────────────────────
    async def mint(self, context: Optional[dict] = None) -> Optional[str]:
        """OOB 콜백 호스트를 하나 발급하고 (마커→요청컨텍스트) 매핑을 저장. host 문자열 반환."""
        if not await self._ensure_registered():
            return None
        dom = _domain()
        if not dom:
            return None
        uniq = self._corr + _rand(13)               # 33자 unique-id
        self._markers[uniq] = context or {}
        return f"{uniq}.{dom}"

    # ── 폴링·복호 ────────────────────────────────────────────────────────────
    async def poll(self) -> list:
        """서버에서 새 콜백을 받아 복호. [{protocol, remote_address, timestamp, full_id,
        raw_excerpt, marker_context}] 반환(새 것만)."""
        if not await self._ensure_registered():
            return []
        try:
            async with httpx.AsyncClient(timeout=20, verify=True) as c:
                r = await c.get(f"{_server()}/poll",
                                params={"id": self._corr, "secret": self._secret})
            if r.status_code != 200:
                return []
            body = r.json()
        except Exception:
            return []
        data = body.get("data") or []
        aes_key = None
        if data:
            try:
                aes_key = self._priv.decrypt(
                    base64.b64decode(body["aes_key"]),
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                 algorithm=hashes.SHA256(), label=None))
            except Exception:
                data = []
        out = []
        for item in data:
            try:
                raw = base64.b64decode(item)
                iv, ct = raw[:16], raw[16:]
                dec = Cipher(algorithms.AES(aes_key), CFB(iv)).decryptor()
                obj = json.loads((dec.update(ct) + dec.finalize()).decode("utf-8", "ignore"))
            except Exception:
                continue
            key = f"{obj.get('unique-id','')}-{obj.get('timestamp','')}-{obj.get('protocol','')}"
            if key in self._seen:
                continue
            self._seen.add(key)
            uid = str(obj.get("unique-id", ""))
            out.append({
                "protocol": (obj.get("protocol") or "").upper(),
                "remote_address": obj.get("remote-address", ""),
                "timestamp": obj.get("timestamp", ""),
                "full_id": obj.get("full-id", ""),
                "q_type": obj.get("q-type", ""),
                "raw_excerpt": re.sub(r"\s+", " ", str(obj.get("raw-request", "")))[:400],
                "context": self._markers.get(uid, {}),
            })
        # -wildcard sends apex-domain interactions as unencrypted JSON in tlddata.
        # Keep only the configured apex; ordinary marker callbacks arrive in data.
        apex = _domain().lower().rstrip(".")
        for item in body.get("tlddata") or []:
            try:
                obj = json.loads(item)
                full_id = str(obj.get("full-id", "")).lower().rstrip(".").split(":", 1)[0]
                if full_id != apex or obj.get("protocol", "").lower() not in ("http", "https"):
                    continue
                key = f"root-{obj.get('timestamp','')}-{obj.get('protocol','')}-{obj.get('raw-request','')}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                out.append({
                    "protocol": (obj.get("protocol") or "").upper(),
                    "remote_address": obj.get("remote-address", ""),
                    "timestamp": obj.get("timestamp", ""),
                    "full_id": obj.get("full-id", ""),
                    "q_type": obj.get("q-type", ""),
                    "raw_excerpt": re.sub(r"\s+", " ", str(obj.get("raw-request", "")))[:400],
                    "context": {"direct_domain": True},
                })
            except (TypeError, ValueError):
                continue
        return out

    def status(self) -> dict:
        return {"enabled": enabled(), "registered": self._registered,
                "server": _server(), "domain": _domain(), "markers": len(self._markers)}


_client: Optional[_Interactsh] = None
_client_lock = threading.Lock()


def _get() -> _Interactsh:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = _Interactsh()
    return _client


async def mint(context: Optional[dict] = None) -> Optional[str]:
    if not enabled():
        return None
    return await _get().mint(context)


async def poll() -> list:
    if not enabled():
        return []
    return await _get().poll()


def status() -> dict:
    if not enabled():
        return {"enabled": False, "registered": False, "server": _server(), "domain": _domain()}
    return _get().status()


# ── 내부 타깃 ↔ 공개 OOB 서버 유출 가드 ──────────────────────────────────────────
_PUBLIC_OOB = ("oast.fun", "oast.pro", "oast.live", "oast.online", "oast.site", "interact.sh")
_PRIVATE_IP_RE = re.compile(
    r"^(?:127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|::1$|fe80:|fc|fd)")


def is_public_server() -> bool:
    """OOB 서버가 공개(제3자) interactsh 인지 — 콜백/유출데이터가 외부로 나감."""
    h = (urlsplit(_server()).hostname or "").lower()
    return any(h == d or h.endswith("." + d) for d in _PUBLIC_OOB)


def target_is_internal(url: str) -> bool:
    """대상이 내부망/사내로 보이는지(RFC1918·loopback·내부 TLD·베어 호스트)."""
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    if host == "localhost" or _PRIVATE_IP_RE.match(host):
        return True
    if host.endswith((".local", ".internal", ".corp", ".lan", ".intranet", ".home")):
        return True
    return "." not in host          # 베어 호스트명(사내 단일 라벨)


def leak_warning(url: str) -> str:
    """내부 타깃인데 공개 OOB 서버면 유출 경고 문자열(아니면 '')."""
    if is_public_server() and target_is_internal(url):
        return ("내부/사내 대상인데 OOB 서버가 공개(제3자)입니다 — 콜백과 페이로드가 나르는 "
                "내부 데이터가 외부로 유출됩니다. self-host(사내) interactsh 로 바꾸세요.")
    return ""


# ── {{oob}} 템플릿 치환 ─────────────────────────────────────────────────────────
_OOB_TOKEN_RE = re.compile(r"\{\{\s*oob\s*\}\}", re.I)


def has_marker(*texts: str) -> bool:
    return any(t and _OOB_TOKEN_RE.search(t) for t in texts)


def substitute(text: str, host: str) -> str:
    """{{oob}} → 발급받은 host 로 치환."""
    if not text:
        return text
    return _OOB_TOKEN_RE.sub(host, text)
