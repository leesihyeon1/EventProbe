"""판정값을 변경하지 않는 영향 설명. 공격 유형은 잠재 영향에만 사용한다."""

_POTENTIAL = {
    "sqli": "SQL 주입이 확증되고 DB 권한이 허용하면 데이터 조회·변조가 가능할 수 있습니다.",
    "cmdi": "명령 실행이 확증되면 서비스 계정 권한 범위에서 파일 접근·변경이 가능할 수 있습니다.",
    "ssti": "템플릿 엔진과 실행 권한에 따라 정보 노출 또는 서버 측 코드 실행으로 이어질 수 있습니다.",
    "xss": "브라우저 실행이 확증되면 해당 출처에서 사용자 권한의 동작이나 페이지 변조가 가능할 수 있습니다.",
    "ssrf": "서버의 네트워크 접근 권한에 따라 내부 서비스나 메타데이터에 접근할 수 있습니다.",
    "lfi": "파일 읽기가 확증되면 서비스 계정이 읽을 수 있는 설정·비밀정보가 노출될 수 있습니다.",
    "file": "노출 파일에 비밀정보가 포함된 경우 해당 정보의 권한 범위로 피해가 확대될 수 있습니다.",
    "xxe": "XML 파서 설정에 따라 파일 노출이나 서버 측 외부 요청으로 이어질 수 있습니다.",
    "authbypass": "인가 우회가 확증되면 보호된 데이터나 기능에 접근할 수 있습니다.",
    "redirect": "외부 이동이 가능한 조건에서 피싱 경로로 악용될 수 있습니다.",
}


def describe_impact(analysis: dict) -> dict:
    """관측된 신호와 조건부 가능성을 분리하며 입력을 수정하지 않는다."""
    outcome = analysis.get("attack_outcome")
    observed = []
    if analysis.get("sensitive_data"):
        observed.append("민감정보 패턴이 응답에서 검출됨")
    if analysis.get("error_leaks"):
        observed.append("오류 정보가 응답에 노출됨")
    if observed:
        confirmed = " · ".join(observed)
    elif outcome == "success":
        confirmed = "공격 성공 신호 검출 — 실제 피해 범위는 추가 확인 필요"
    elif outcome == "safe":
        confirmed = "이번 검사에서 취약 신호 미검출 — 다른 요청·환경의 영향은 미확인"
    elif outcome == "blocked":
        confirmed = "요청 거부 관측 — 취약점 존재 여부와 피해 범위는 미확인"
    else:
        confirmed = "현재 증거만으로 실제 영향을 확정할 수 없음"
    limits = ["현재 요청·응답에서 관측한 범위이며, 접근 권한·데이터 범위·지속적인 상태 변화는 별도 검증이 필요합니다."]
    if analysis.get("body_truncated"):
        limits.append("응답 본문의 일부만 검사했습니다.")
    if (analysis.get("validity") or {}).get("warnings"):
        limits.append("테스트 유효성 경고가 있어 대상 도달 여부와 검사 전제조건을 확인해야 합니다.")
    return {
        "confirmed": confirmed,
        "potential": _POTENTIAL.get(analysis.get("attack_type"), "공격 유형만으로 피해 범위를 확정할 수 없습니다. 대상 기능과 권한 확인이 필요합니다."),
        "limitations": " ".join(limits),
    }
