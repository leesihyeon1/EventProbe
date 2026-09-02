"""순수 파이썬 TLS/전송계층 점검 — 외부 바이너리(nmap 등) 없이 in-process 로 수행.

기존 포트 스캔과 동일한 방식(표준 라이브러리 socket/ssl)으로 동작한다. 점검 항목:
  - 협상된 TLS 버전(1.0/1.1/SSLv3 = 취약)
  - 협상된 cipher(RC4/3DES/DES/NULL/EXPORT/anon/MD5 = 취약)
  - 인증서 만료/미도래/자체서명/만료임박
  - Heartbleed (CVE-2014-0160) — 원시 TLS heartbeat 로 메모리 초과 회신 여부

판정 로직(analyze_tls / cert_findings / weak_*)은 순수 함수라 네트워크 없이 테스트된다.
전송 계층 점검은 HTTP 요청보다 침습적이므로 반드시 '인가된 대상'에만 사용할 것.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

# ── 순수 판정 함수 (네트워크 없음, 테스트 대상) ────────────────────────────────
_WEAK_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-", "DES_", "NULL", "EXPORT", "EXP-",
                       "ANON", "_ANON", "MD5", "IDEA", "SEED", "CBC3")


def weak_tls_version(version: Optional[str]) -> bool:
    return (version or "") in _WEAK_VERSIONS


def weak_cipher(cipher_name: Optional[str]) -> Optional[str]:
    """취약 cipher 면 사유 토큰을, 아니면 None."""
    c = (cipher_name or "").upper()
    for tok in _WEAK_CIPHER_TOKENS:
        if tok in c:
            return tok.strip("_-")
    return None


def _parse_cert_time(s: str) -> Optional[datetime]:
    # OpenSSL 형식: 'Jun  1 12:00:00 2025 GMT'
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def _name_tuple_to_dict(seq) -> dict:
    out = {}
    for rdn in (seq or ()):
        for k, v in rdn:
            out[k] = v
    return out


def cert_findings(cert: dict, now: Optional[datetime] = None) -> list:
    """getpeercert() dict 로 인증서 문제(만료/미도래/자체서명/임박) 를 도출."""
    now = now or datetime.now(timezone.utc)
    out = []
    if not cert:
        return out
    na = _parse_cert_time(cert.get("notAfter", ""))
    nb = _parse_cert_time(cert.get("notBefore", ""))
    if na and now > na:
        out.append({"name": "인증서 만료", "risk": "high",
                    "evidence": f"notAfter={cert.get('notAfter')}"})
    elif na and (na - now).days <= 14:
        out.append({"name": "인증서 만료 임박", "risk": "medium",
                    "evidence": f"{(na - now).days}일 남음 (notAfter={cert.get('notAfter')})"})
    if nb and now < nb:
        out.append({"name": "인증서 유효기간 미도래", "risk": "medium",
                    "evidence": f"notBefore={cert.get('notBefore')}"})
    subj = _name_tuple_to_dict(cert.get("subject"))
    issuer = _name_tuple_to_dict(cert.get("issuer"))
    if subj and issuer and subj == issuer:
        out.append({"name": "자체 서명 인증서", "risk": "medium",
                    "evidence": f"issuer=subject ({subj.get('commonName', '')})"})
    return out


def analyze_tls(version: Optional[str], cipher: Optional[str],
                cert: Optional[dict], now: Optional[datetime] = None) -> list:
    """협상 결과(버전/cipher/인증서) → 취약 findings 목록(순수 함수)."""
    findings = []
    if weak_tls_version(version):
        findings.append({"name": f"취약한 TLS 버전 협상 ({version})", "risk": "high",
                         "evidence": f"{version} 은 폐기 대상 — TLS1.2+ 강제 필요"})
    wc = weak_cipher(cipher)
    if wc:
        findings.append({"name": f"취약한 cipher 협상 ({wc})", "risk": "high",
                         "evidence": f"{cipher}"})
    findings.extend(cert_findings(cert or {}, now))
    return findings


# ── 네트워크 점검 (블로킹 — asyncio.to_thread 로 감싸 호출) ─────────────────────
def _tls_info_sync(host: str, port: int, timeout: float) -> dict:
    """기본 TLS 핸드셰이크로 협상 버전/cipher/인증서 수집."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # 만료/자체서명도 '점검'해야 하므로 검증 끔
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return {"version": ss.version(),
                        "cipher": (ss.cipher() or [None])[0],
                        "cert": ss.getpeercert() or {}}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"[:200]}


# Heartbleed 원시 프로브 (TLS1.1 ClientHello + heartbeat 확장, 과대 길이 요청)
_HB_CLIENT_HELLO = bytes.fromhex(
    "16030200dc010000d80302"
    "53435b909d9b720bbc0cbc2b92a84897cfbd3904cc160a8503909f770433d4de00"
    "0066c014c00ac022c021003900380088"
    "0087c00fc00500350084c012c008c01c"
    "c01b00160013c00dc003000ac013c009"
    "c01fc01e00330032009a009900450044"
    "c00ec004002f009600410099c011c007c00cc00200050004001500120009001400"
    "1100080006000300ff01000049000b000403000102000a00340032000e000d0019"
    "000b000c00180009000a0016001700080006000700140015000400050012001300"
    "01000200030f00100011002300000000000f000101"
)
_HB_REQUEST = bytes.fromhex("1803020003014000")   # heartbeat: type1, payload_len 0x4000


def _recv_all(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _recv_tls_record(sock):
    hdr = _recv_all(sock, 5)
    if len(hdr) < 5:
        return None, None, b""
    ctype = hdr[0]
    length = (hdr[3] << 8) | hdr[4]
    payload = _recv_all(sock, length)
    return ctype, length, payload


def _heartbleed_sync(host: str, port: int, timeout: float) -> dict:
    """CVE-2014-0160 — heartbeat 응답이 요청보다 많은 바이트를 회신하면 취약."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return {"vulnerable": False, "error": f"{type(e).__name__}: {e}"[:150]}
    try:
        sock.settimeout(timeout)
        sock.sendall(_HB_CLIENT_HELLO)
        # ServerHelloDone(handshake type 14) 까지 읽어 핸드셰이크 진행
        got_hello = False
        for _ in range(8):
            ctype, _, payload = _recv_tls_record(sock)
            if ctype is None:
                break
            if ctype == 22:                      # handshake
                got_hello = True
                if 14 in payload[:1] or payload[:1] == b"\x0e":
                    break
            elif ctype == 21:                    # alert during handshake
                return {"vulnerable": False, "detail": "핸드셰이크 실패(alert)"}
        if not got_hello:
            return {"vulnerable": False, "detail": "TLS1.1 핸드셰이크 미성립(heartbeat 미지원 가능)"}
        sock.sendall(_HB_REQUEST)
        ctype, length, payload = _recv_tls_record(sock)
        if ctype == 24 and length > 3:           # heartbeat 응답 + 초과 바이트 = 메모리 누출
            return {"vulnerable": True,
                    "detail": f"heartbeat 응답 {length}B 회신(요청 payload 0B) → 메모리 누출"}
        if ctype == 21:
            return {"vulnerable": False, "detail": "heartbeat 거부(alert) — 패치됨"}
        return {"vulnerable": False, "detail": "초과 데이터 없음 — 취약하지 않음"}
    except socket.timeout:
        return {"vulnerable": False, "detail": "응답 없음(timeout) — 취약하지 않음/heartbeat 비활성"}
    except Exception as e:
        return {"vulnerable": False, "error": f"{type(e).__name__}: {e}"[:150]}
    finally:
        try:
            sock.close()
        except Exception:
            pass


async def tls_scan(host: str, port: int = 443, timeout: float = 8.0,
                   check_heartbleed: bool = True) -> dict:
    """대상의 TLS 협상 점검 + (선택) Heartbleed. 블로킹 작업은 워커 스레드에서 수행."""
    host = (host or "").strip()
    info = await asyncio.to_thread(_tls_info_sync, host, port, timeout)
    result = {"host": host, "port": port,
              "version": info.get("version"), "cipher": info.get("cipher"),
              "findings": [], "heartbleed": None}
    if info.get("error"):
        result["error"] = info["error"]
        return result
    result["findings"] = analyze_tls(info.get("version"), info.get("cipher"), info.get("cert"))
    if check_heartbleed:
        hb = await asyncio.to_thread(_heartbleed_sync, host, port, timeout)
        result["heartbleed"] = hb
        if hb.get("vulnerable"):
            result["findings"].insert(0, {
                "name": "Heartbleed (CVE-2014-0160)", "risk": "critical",
                "evidence": hb.get("detail", "메모리 누출 확인")})
    return result
