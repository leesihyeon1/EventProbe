"""#2 본문 절단 — '미검출' 판정의 유효 범위를 숨기지 않는다.

회귀 방지:
    경로마다 본문 상한이 5KB/10KB/50KB 로 달라, 같은 페이로드가 단일 전송과 일괄 테스트에서
    다른 판정을 냈다. 게다가 잘린 앞부분만 보고 "시그니처 미검출 → 안전"이라고 단정해
    위음성을 '안전'으로 보고했다. 이제 상한을 하나로 통일하고, 잘렸으면 그 사실을
    '안전/미확인' 판정에 명시한다.
"""
from core.analyzer import analyze_response


def _safe_findings(r):
    return [f for f in r["findings"] if f["verdict"] in ("안전", "미확인")]


def test_not_truncated_leaves_findings_clean():
    r = analyze_response(200, {}, "<html>ok</html>", 50,
                         payload="1' OR '1'='1", category="sqli",
                         body_truncated=False, full_body_len=15)
    assert r["body_truncated"] is False
    assert not any("절단" in (f.get("why") or "") for f in r["findings"])
    assert not any("절단" in x for x in r["response_anomalies"])


def test_truncated_marks_absence_based_findings():
    """잘린 상태의 '미확인'에는 검사 범위가 붙어야 한다."""
    r = analyze_response(200, {}, "<html>ok</html>", 50,
                         payload="1' OR '1'='1", category="sqli",
                         body_truncated=True, full_body_len=120000)
    assert r["body_truncated"] is True
    assert r["body_len_seen"] == 15 and r["body_len_full"] == 120000
    marked = _safe_findings(r)
    assert marked, "미확인 신호가 있어야 하는 케이스"
    for f in marked:
        assert f.get("truncated_scope") is True
        assert "잘렸습니다" in f["why"]
        assert "본문 절단" in f["evidence"]
    assert any("본문 절단" in x for x in r["response_anomalies"])


def test_truncated_does_not_touch_success_findings():
    """실제로 찾은 증거(성공)는 절단과 무관하다 — 문구를 흐리지 않는다."""
    r = analyze_response(200, {}, "root:x:0:0:root:/root:/bin/bash\n", 50,
                         payload="../../etc/passwd", category="lfi",
                         body_truncated=True, full_body_len=99999)
    succ = [f for f in r["findings"] if f["verdict"] == "성공"]
    assert succ
    for f in succ:
        assert "잘렸습니다" not in (f.get("why") or "")
        assert not f.get("truncated_scope")


def test_truncated_flag_ignored_when_full_not_larger():
    """상한과 같은 길이 등 실제로 잘리지 않은 경우엔 경고하지 않는다."""
    r = analyze_response(200, {}, "abc", 50, payload="x", category="sqli",
                         body_truncated=True, full_body_len=3)
    assert r["body_truncated"] is False
    assert not any("절단" in x for x in r["response_anomalies"])


def test_defaults_are_backward_compatible():
    r = analyze_response(200, {}, "<html>ok</html>", 50, payload="x", category="sqli")
    assert r["body_truncated"] is False
    assert r["body_len_seen"] == 15 and r["body_len_full"] == 15


# ─────────────────────────────────────────────────────────────────────────────
# API 계층 — 상한 통일 + 읽기 헬퍼
# ─────────────────────────────────────────────────────────────────────────────
class _Resp:
    def __init__(self, text):
        self._t = text

    @property
    def text(self):
        return self._t


def test_read_body_reports_truncation():
    from routers.api import BODY_LIMIT, _read_body

    body, cut, full = _read_body(_Resp("A" * (BODY_LIMIT + 500)))
    assert len(body) == BODY_LIMIT and cut is True and full == BODY_LIMIT + 500


def test_read_body_short_response():
    from routers.api import _read_body

    assert _read_body(_Resp("hello")) == ("hello", False, 5)


def test_read_body_survives_decode_error():
    from routers.api import _read_body

    class _Bad:
        @property
        def text(self):
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "boom")

    assert _read_body(_Bad()) == ("", False, 0)


def test_all_paths_share_one_limit():
    """단일/멀티/일괄 경로가 같은 상한을 쓰는지 — 판정 불일치 회귀 방지."""
    import os
    import re

    src = open(os.path.join(os.path.dirname(__file__), "..", "routers", "api.py"),
               encoding="utf-8").read()
    # 분석에 넘기는 본문을 하드코딩 슬라이스로 자르는 곳이 남아 있으면 안 된다
    leftovers = re.findall(r"(?:resp|response)\.text\[:\d+\]", src)
    assert leftovers == [] or all("50000" in x for x in leftovers), leftovers
    assert src.count("_read_body(") >= 4       # 정의 1 + 사용 3 경로
