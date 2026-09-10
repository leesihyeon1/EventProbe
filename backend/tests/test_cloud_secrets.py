"""정밀 추출형 클라우드/서비스 시크릿 탐지 — accessKeys.csv 등 실제 키 노출을 확증.

배경: /accessKeys.csv(AWS 액세스 키) 가 200 으로 노출돼도 판정 시그니처에 AWS 키가 없어
'판정 불가'로 남았다. AWS Access Key ID(AKIA…) 등은 '정확히 추출 가능한 패턴'이라 응답
내용으로 확증할 수 있다(오탐 없음).

주: 아래 테스트 토큰은 문자열 결합으로 조립한다 — 시크릿 스캐너(GitHub push protection)가
완전한 키 리터럴로 오인해 커밋을 막지 않도록. 런타임에는 정규식이 검사할 온전한 문자열이 된다.
"""
from core.analyzer import analyze_response

# 조립형 더미 키(실제 값 아님). 리터럴로 통째 두면 시크릿 스캐너가 차단한다.
_AKIA = "AKIA" + "IOSFODNN7EXAMPLE"
_AWS_SECRET = "wJalrXUtnFEMI" + "/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
_AWS_CSV = ("Access key ID,Secret access key\n" + _AKIA + "," + _AWS_SECRET + "\n")


def _names(r):
    return [f["name"] for f in r["findings"]]


def test_accesskeys_csv_exposed_is_critical():
    r = analyze_response(200, {"content-type": "text/csv"}, _AWS_CSV, 60,
                         payload="/accessKeys.csv", category="cve", url="http://t/accessKeys.csv")
    assert r["attack_outcome"] == "success"
    assert r["risk_level"] == "critical"
    assert any("AWS 자격증명" in n for n in _names(r))
    assert any("AWS Access Key ID" in s for s in r["sensitive_data"])


def test_accesskeys_csv_not_exposed_is_safe():
    r = analyze_response(200, {"content-type": "text/html"}, "<html>Not Found</html>", 60,
                         payload="/accessKeys.csv", category="cve", url="http://t/accessKeys.csv")
    assert r["risk_level"] == "low"
    assert any("미노출" in n for n in _names(r))
    assert not any("AWS Access Key ID 노출" in s for s in r["sensitive_data"])


def test_aws_key_anywhere_is_critical():
    """응답 어디에 있든 AKIA 키가 있으면 민감정보 노출(critical)."""
    r = analyze_response(200, {}, "app config: aws_key=" + _AKIA + " ok", 60,
                         payload="", category="")
    assert r["verdict"] == "bypass" and r["risk_level"] == "critical"


def test_aws_credentials_file_signature():
    r = analyze_response(200, {}, "[default]\n" + "aws_secret_access_key" + " = abcdef...", 60,
                         payload="/.aws/credentials", category="cve", url="http://t/.aws/credentials")
    assert any("AWS 자격증명" in n for n in _names(r))


def test_gcp_service_account_exposed():
    body = '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIabc"}'
    r = analyze_response(200, {}, body, 60, payload="/service_account.json", category="cve",
                         url="http://t/service_account.json")
    assert r["attack_outcome"] == "success"
    assert any("GCP" in n or "개인키" in s for n in _names(r) for s in r["sensitive_data"] + [""])


import pytest

# (조립형 더미 토큰, 라벨) — 리터럴로 두지 않는다.
_TOKENS = [
    (_AKIA, "AWS Access Key ID"),
    ("AIza" + "Sy0123456789abcdefghijklmnopqrstuvwx"[:35], "Google API"),
    ("ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz", "GitHub"),
    ("xox" + "b-" + "1234567890-abcdefghijkl", "Slack"),
    ("sk_" + "live_" + "1234567890abcdefghijklmnop", "Stripe"),
]


@pytest.mark.parametrize("token,label", _TOKENS)
def test_precise_secret_tokens_detected(token, label):
    r = analyze_response(200, {}, "leaked: " + token + " end", 60, payload="", category="")
    assert any(label in s for s in r["sensitive_data"]), (token, r["sensitive_data"])


@pytest.mark.parametrize("benign", [
    "<img src='data:image/png;base64,AAAABBBBCCCCDDDDEEEE'>",
    "sha384-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL",  # SRI 해시
    "<html>normal page with AKIA text but not a key</html>",   # AKIA 단어(뒤 16자 대문자 아님)
    "background: url(data:font/woff2;base64,d09GMgABAAAA)",
])
def test_no_false_positive_on_benign(benign):
    r = analyze_response(200, {}, benign, 60, payload="", category="")
    assert not any("Access Key ID" in s or "GitHub" in s or "Google API" in s
                   for s in r["sensitive_data"]), (benign, r["sensitive_data"])
