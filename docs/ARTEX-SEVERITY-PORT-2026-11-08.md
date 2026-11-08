# ARTEX 발견 심각도 자동 점수화 — 4차 이식

기준일: 2026-11-08. 대상: `C:\Users\shlee\dev\sec-api-tester`. 1~3차 이식(실행 큐·모델 라우팅·독립 증거 보존) 위에, 계획서가 "남은 것"으로 명시한 **심각도 자동 점수화**(`ARTEX-CONTINUATION-PLAN-2026-10-15.md`의 P1 잔여 항목)를 구현했다. ARTEX 전체 이식 완료를 뜻하지 않는다.

## 배경

기존 발견 심각도는 **판정만** 반영했다(`confirmed→high, suspicious→medium, inconclusive→info`). 취약 클래스 가중이 전혀 없어, SQL 인젝션 확증과 오픈 리다이렉트 확증이 같은 `high`로 매겨져 트리아지 정렬·보고서 우선순위가 실제 위험을 반영하지 못했다. 교차-run 발견 통합(`finding_group`)은 이미 구현돼 있었으므로, 이번 범위는 통합이 아니라 **점수화**에 한정한다.

## 적용 기능

- **클래스별 기준 심각도**를 카테고리 단일 레지스트리(`backend/core/categories.py`)에 `sev` 필드로 추가했다. "새 카테고리 = 여기 한 줄" 철학을 유지하며, `BASE_SEVERITY` 파생 뷰로 노출한다. 기준값은 확증(confirmed) 전제의 값이다.
  - critical: `sqli`, `cmdi`, `ssti`, `deserial`, `log4shell`, `shellshock`, `auth`, `authbypass`
  - high: `lfi`, `idor`/`business`, `ssrf`, `nosql`, `xxe`, `upload`, `jwt`, `ldap`, `prototype`
  - medium: `xss`, `csrf`, `cors`, `crlf`, `ssi`, `xpath`, `graphql`, `xmlrpc`, `header`, `cache`
  - low: `redirect`, `other`
  - 미등록/일반 카테고리(`verification` 등): `DEFAULT_BASE_SEVERITY='low'` — 모르는 클래스를 과대평가하지 않는다.
- **판정 가중**(`agent_findings.score_severity`)으로 실제 심각도를 산출한다. 클래스는 "진짜라면 얼마나 나쁜지"를, 판정은 "그중 얼마를 인정할지"를 정한다.
  - 확증 → 기준값
  - 의심 → 기준값 −1 단계
  - 증거 일부 누락 → 추가 −1 단계
  - 확증/의심은 `low` 미만으로 내려가지 않는다(floor).
- **3상태 가드**: 판정불가(및 알 수 없는 판정)는 클래스와 무관하게 **항상 `info`**. 취약 클래스가 미확증 발견을 끌어올리지 않으므로, '판정 불가'를 위험으로 과장하지도 '안전'으로 표기하지도 않는다(`three-state-verdict` 원칙 유지).
- **수동 분류 우선**: 사용자가 `finding_update`로 지정한 심각도는 자동 점수 위에 그대로 적용된다(기존 append-only 이력 경로 불변).
- `finding_index`의 저장 심각도는 `build_findings`가 산출한 값을 그대로 기록하므로(on-read 발견·전역 그룹·보고서가 모두 동일 경로), 점수화가 조회·정렬·보고서에 일관되게 반영된다.

## 데이터와 배포

- 새 테이블·스키마 변경은 없다. 기존 `finding_index.severity` 컬럼을 재사용한다.
- `store_migrations`에 `finding_severity_v2`를 추가했다. 서버 다음 기동 시 기존 모든 run을 `reindex_findings`로 1회 재색인해 저장 심각도를 새 점수화로 갱신한다. 수동 분류는 `finding_update` 이벤트에 있으므로 재색인이 다시 접어 넣어 **보존**한다.
- 독립 보존(saved evidence) 스냅샷은 보존 시점의 `default_severity`를 불변으로 유지한다. 과거 스냅샷은 옛 값, 새 보존은 새 점수로 기록된다(시점 증거의 불변성 유지).
- 운영 DB·`.env`·실제 키는 변경하지 않았고 서버도 재시작하지 않았다. 실제 대상·외부 AI 호출도 수행하지 않았다.

## 변경 파일

| 파일 | 변경 |
|---|---|
| `backend/core/categories.py` | 클래스별 `sev` 필드 + `BASE_SEVERITY`·`DEFAULT_BASE_SEVERITY` 파생 |
| `backend/core/agent_findings.py` | `score_severity()` 추가, 판정-only 기본값 제거·교체 |
| `backend/core/agent_store.py` | `finding_severity_v2` 재색인 마이그레이션 |
| `backend/tests/test_findings.py` | 점수화·3상태·가중·floor·기본값·통합 테스트 7건, 기존 기대값 1건 갱신 |
| `backend/tests/test_finding_groups.py` | 저장 심각도·마이그레이션 재색인 테스트 2건 |

## 검증

- 전체 백엔드 **1,355 passed**(warnings 3) — 기존 1,346 + 신규 9.
- 전체 프런트엔드 **187 passed**.
- 오프라인 계약 검사 8 passed, `git -c core.whitespace=cr-at-eol diff --check` 통과.
- 합성 데이터·임시 SQLite만 사용. 실제 대상·외부 AI·운영 DB·커밋/푸시는 수행하지 않았다.

## 남은 범위

클래스 기준값은 보수적 초기안이며, 운영 정책(예: 환경·자산 중요도 가중, CVSS 연동, 스냅샷 재점수화)과는 별개다. 다중 worker/intent lease·지식그래프, MCP/일반 tool 승인, source task 상속, N8/N9 운영 자동화(외부 채널·스케줄 결정 선행)는 여전히 후속 범위다.
