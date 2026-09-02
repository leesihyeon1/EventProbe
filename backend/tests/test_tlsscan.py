"""TLS 점검 순수 판정 함수 단위 테스트 — 네트워크 없음.

analyze_tls / cert_findings / weak_* 는 협상 결과(문자열/dict)만 받아 판정하므로
외부 대상에 접속하지 않고 검증한다. (실제 스캔은 인가된 대상에서 엔드포인트로 수행)
"""
from datetime import datetime, timedelta, timezone

from core import tlsscan


NOW = datetime(2025, 6, 1, tzinfo=timezone.utc)


def _cert(not_after="Jun  1 12:00:00 2026 GMT", not_before="Jun  1 12:00:00 2024 GMT",
          subject_cn="example.com", issuer_cn="DigiCert CA"):
    return {
        "notAfter": not_after,
        "notBefore": not_before,
        "subject": ((("commonName", subject_cn),),),
        "issuer": ((("commonName", issuer_cn),),),
    }


# ── 버전/cipher ───────────────────────────────────────────────────────────────
def test_weak_tls_versions():
    assert tlsscan.weak_tls_version("TLSv1")
    assert tlsscan.weak_tls_version("TLSv1.1")
    assert tlsscan.weak_tls_version("SSLv3")
    assert not tlsscan.weak_tls_version("TLSv1.2")
    assert not tlsscan.weak_tls_version("TLSv1.3")


def test_weak_ciphers():
    assert tlsscan.weak_cipher("ECDHE-RSA-RC4-SHA")
    assert tlsscan.weak_cipher("DES-CBC3-SHA")
    assert tlsscan.weak_cipher("NULL-MD5")
    assert tlsscan.weak_cipher("EXP-RC2-CBC-MD5")
    assert tlsscan.weak_cipher("ECDHE-RSA-AES128-GCM-SHA256") is None


# ── 인증서 ────────────────────────────────────────────────────────────────────
def test_cert_expired():
    c = _cert(not_after="Jun  1 12:00:00 2020 GMT")
    names = [f["name"] for f in tlsscan.cert_findings(c, NOW)]
    assert "인증서 만료" in names


def test_cert_expiring_soon():
    c = _cert(not_after="Jun  8 12:00:00 2025 GMT")   # 7일 후
    names = [f["name"] for f in tlsscan.cert_findings(c, NOW)]
    assert "인증서 만료 임박" in names


def test_cert_self_signed():
    c = _cert(subject_cn="self.local", issuer_cn="self.local")
    names = [f["name"] for f in tlsscan.cert_findings(c, NOW)]
    assert "자체 서명 인증서" in names


def test_cert_healthy_no_findings():
    assert tlsscan.cert_findings(_cert(), NOW) == []


# ── 통합 판정 ─────────────────────────────────────────────────────────────────
def test_analyze_tls_flags_weak_version_and_cipher():
    f = tlsscan.analyze_tls("TLSv1", "ECDHE-RSA-RC4-SHA", _cert(), NOW)
    names = " ".join(x["name"] for x in f)
    assert "취약한 TLS 버전" in names
    assert "취약한 cipher" in names


def test_analyze_tls_clean_modern():
    f = tlsscan.analyze_tls("TLSv1.3", "TLS_AES_256_GCM_SHA384", _cert(), NOW)
    assert f == []


# ── 네트워크 경로: 대상 없음이면 안전하게 실패(스캔 유발 없음) ────────────────
def test_heartbleed_refused_is_graceful():
    r = tlsscan._heartbleed_sync("127.0.0.1", 1, 0.5)   # 닫힌 포트 → 연결 거부
    assert r["vulnerable"] is False
    assert "error" in r or "detail" in r
