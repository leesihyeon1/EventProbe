# ARTEX 발견 그룹 통합 분류 — 5차 이식

기준일: 2026-11-08. 대상: `C:\Users\shlee\dev\sec-api-tester`. 교차-run 발견 그룹화(`finding_group`)는 이미 있었으나, 그룹 전체를 한 번에 분류하는 수단이 없었다. ARTEX의 canonical finding 수명주기 중 **다중 worker 엔진·LLM 도구에 의존하지 않는** 부분(그룹 단위 사용자 분류)을 이식했다. ARTEX 전체 이식 완료를 뜻하지 않는다.

## 배경

발견 분류(상태/심각도/메모)는 run별 `finding_update` 이벤트로만 가능했다. 같은 구조적 취약점이 여러 run·재검증에 흩어져 있으면 각 run마다 따로 분류해야 했다. 이번 변경은 **구조적 그룹 키 `(asset_id, category, actor_id, input_shape_id)`에 한 번 분류하면 전 run에 적용되는 canonical 분류**를 추가한다. 원본 run별 판정·증거는 불변이며, 그룹의 confirmed/suspicious/inconclusive 분포도 그대로 노출된다. canonical 분류는 판정(evidence verdict)을 덮지 않는 **별도의 사람 판단 축**이다.

## 적용 기능

- **워크스페이스별 canonical 분류**: 그룹당 상태/심각도/메모 1건을 저장한다. `finding_group_triage` 헤드 테이블(현재 상태 + `revision`)과 `finding_group_triage_changes` append-only 감사 테이블을 쓰며, 둘 다 한 `BEGIN IMMEDIATE` 트랜잭션에서 revision compare-and-swap으로 갱신한다(saved_evidence 패턴).
- **낙관적 동시성**: `expected_revision`이 0이면 생성, 현재 revision과 같으면 갱신. 불일치는 `RunConflict`(→409). 변경 이력 1만 건 한도.
- **소유 범위 가드**: 쓰기 전에 해당 그룹에 호출자가 볼 수 있는 finding_index 행이 하나라도 있는지(소유 범위) 재확인한다. 볼 수 없으면 `KeyError`(→404). triage 행은 호출자 owner로 키가 분리돼, 다른 워크스페이스의 분류를 읽거나 덮어쓸 수 없다. 범위가 꺼지면(owner None) owner `''`로 단일 공유 분류가 된다.
- **심각도 시드**: 새 그룹 분류 생성 시 심각도를 그룹의 최악 멤버 심각도로 시드해, 첫 분류가 치명 그룹에서 조용히 `info`가 되지 않게 한다. 사용자가 덮어쓸 수 있다. 판정불가는 멤버 심각도 자체가 info이므로 과장되지 않는다(3상태 유지).
- **전역 그룹 목록 노출**: `finding_group_page`가 grouped 쿼리를 서브쿼리로 감싸고 `finding_group_triage`를 4개 키 + `owner` 정확 일치로 LEFT JOIN해 `canonical_status/severity/note/revision`을 그룹별로 반환한다.
- **불변성**: 그룹 분류는 `finding_update` 이벤트를 쓰지 않고, `finding_index`/`reindex_findings`/멤버 판정을 건드리지 않는다. 두 메커니즘(run별 분류 ↔ 그룹 canonical 분류)은 직교한다.
- **화면**: 전역 "보안 발견"의 그룹 행에 통합 분류 배지와, 펼침 영역에 상태/심각도/메모 + 저장 컨트롤을 추가했다(global_lookup.js). 아이콘 없이 텍스트만 사용하고 agentApi로만 호출하며, 저장은 seq 가드로 지연 응답의 오염을 막고 서버 스냅샷을 그대로 채택해 재표시한다.

## API

모든 경로는 `/api/agent/history` 기준이며 owner 범위가 켜지면 `x-eventprobe-user`/`ep_user`로 워크스페이스를 구분한다(자가 선언값이며 인증 경계가 아니다).

| 경로 | 계약 |
|---|---|
| GET /findings/groups/triage | 4개 키(asset_id·category·actor_id·input_shape_id)로 canonical 분류 + 변경 이력 조회. 없으면 `exists:false` |
| PUT /findings/groups/triage | `{키…, expected_revision, status?, severity?, note?}`. 422(값)·404(그룹 미가시)·409(revision)·400(변경 없음) |
| GET /findings/groups | 각 그룹 항목에 `canonical_*` 필드 추가 |

## 데이터와 배포

- `finding_group_triage`(헤드)·`finding_group_triage_changes`(감사) 두 테이블을 추가한다. 순수 추가형(CREATE TABLE IF NOT EXISTS)이라 backfill·마이그레이션 마커가 없다. `Store.init_finding_group_schema()`를 기존 init_* 믹스인 뒤에서 호출한다.
- 기존 run/event/finding_index/ID는 변경하지 않는다. 운영 DB·`.env`·실제 키는 변경하지 않았고 서버도 재시작하지 않았다. 다음 기동 시 테이블이 초기화된다.
- 고아 정책: run 삭제로 그룹이 비어도 triage 행은 남을 수 있다. 빈 그룹은 `finding_group_page`에 나타나지 않으므로 조회에 영향이 없고, 다음 쓰기 시 가시성 검사로 거부된다.

## 변경 파일

| 파일 | 변경 |
|---|---|
| `backend/core/finding_group_triage.py` | 신규: 스키마·읽기/쓰기(CAS)·소유 가드·심각도 시드 믹스인 |
| `backend/core/agent_store.py` | 믹스인 연결·init 호출, `finding_group_page` LEFT JOIN |
| `backend/routers/agent_history.py` | GET/PUT 그룹 triage 엔드포인트 |
| `frontend/static/js/global_lookup.js` | 통합 분류 배지 + 그룹 분류 패널 |
| `backend/tests/test_finding_group_triage.py` | 신규 7건(CAS·소유 격리·불변성·라우터 409/404/422) |
| `frontend/tests/global_lookup.test.js` | 그룹 triage PUT·배지 테스트 1건 + 기존 인덱스 갱신 |

## 검증

- 전체 백엔드 **1,362 passed**(warnings 3) — 기존 1,355 + 신규 7.
- 전체 프런트엔드 **188 passed** — 기존 187 + 신규 1.
- 합성 데이터·임시 SQLite만 사용. 실제 대상·외부 AI·운영 DB·커밋/푸시는 이 구현 단계에서 수행하지 않았다.

## 남은 범위

ARTEX의 canonical finding 수명주기 중 다중 worker 기반 "심화(deepen)" 의도·LLM 도구 연동은 이식하지 않았다(엔진/도구 의존). 다중 worker/intent lease, MCP/일반 tool 승인, source task 상속, N8/N9 운영 자동화(외부 채널·스케줄 결정 선행)는 여전히 후속 범위다.
