"""결과 기반 승격 — 근거(성공/누출 신호·성공 판정) 있을 때만 계열을 도출하는지 검증."""
from core.followup import hot_families, escalation_candidates


def test_no_escalation_without_evidence():
    # 카테고리만 시도하고 차단/판정불가 + 근거 신호 없음 → 승격 계열 없음
    assert hot_families({"category": "sqli", "attack_outcome": "blocked", "finding_names": []}) == []
    assert hot_families({"category": "xss", "attack_outcome": "inconclusive", "finding_names": []}) == []


def test_positive_finding_drives_family():
    # 실제 취약 신호(SQL 에러 노출)가 있으면 그 계열로 승격
    fams = hot_families({"category": "", "attack_outcome": "inconclusive",
                         "finding_names": ["SQL 에러 노출"]})
    assert "sqli" in fams


def test_success_outcome_escalates_tried_category():
    # 공격이 성공했다면 시도한 카테고리 자체가 근거
    fams = hot_families({"category": "ssrf", "attack_outcome": "success", "finding_names": []})
    assert "ssrf" in fams


def test_time_delay_signal_promotes_blind():
    fams = hot_families({"category": "", "attack_outcome": "inconclusive",
                         "finding_names": ["시간 지연 확인"]})
    assert "sqli" in fams and "cmdi" in fams


def test_escalation_candidates_empty_for_no_family():
    data = {"categories": [{"id": "sqli", "payloads": [{"payload": "' OR 1=1-- -"}]}]}
    assert escalation_candidates(data, [], "param", "id") == []
