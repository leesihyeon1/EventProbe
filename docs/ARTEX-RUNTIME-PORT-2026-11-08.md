# ARTEX 실행 기반 이식 — 1차

기준일: 2026-11-08. Python/FastAPI와 기존 판정·승인·반출 정책을 유지했다.

## 반영한 기능

- 영속 FIFO 실행 대기열. 기존 정원 초과 409 대신 queued로 보관하고 슬롯이 나면 시작한다.
- 모든 생성/템플릿/사건 재검증/발견 재검증/재개는 AgentManager의 같은 admission을 사용한다.
- AGENT_MAX_CONCURRENT_RUNS: 기본 2, 허용 범위 1–16. 한 run 내부 worker는 여전히 1개다.
- 대기 취소, 대기 순번/상태 필터/통계/폴링/상세 표시, 대기 중 승인 철회와 만료 검사.
- 재기동 시 미시작·자격증명 불필요 작업만 FIFO로 자동 복원한다. 요청 이력이 있거나 credential이 필요한 작업은 paused로 전환하고 명시적 재개를 요구한다.
- HTTP 및 브라우저 요청 전 SQLite transaction으로 예산을 예약한다. 실패·취소·결과 미상 요청의 예산은 자동 환불하지 않는다.
- reservation key 중복 계상 방지, 구식 JSON 저장이 예약 카운터를 줄이지 못하도록 보호.
- Store.update의 optional expected_revision 비교 갱신. 다른 필드의 다중 worker 동시 쓰기를 지원한다는 뜻은 아니다.
- 같은 SQLite를 사용하는 두 서버가 복구를 동시에 수행하지 못하도록 OS 파일 잠금을 획득한다. 읽기 전용 접근과 테스트용 Store 생성은 잠금을 요구하지 않는다.
- 실행/대기 중 보관 및 retention 삭제 차단. 삭제 중 동일 run 재실행 차단.
- GET /api/agent/capabilities에 실제 지원 기능과 아직 미지원인 기능을 명시한다.

## 기존 데이터와 실행

Store 초기화에서 runtime_queue, request_reservations, run_revisions와 revision/삭제 정리 trigger를 추가한다. 기존 runs/events와 ID는 변경하지 않는다. store_migrations에 runtime_admission_v1을 기록한다. 운영 DB는 이식 작업 중 열거나 변경하지 않았다. 다음 서버 기동부터 적용된다.

배포 전 실행 DB를 백업하고 정상 종료한 뒤 교체한다. 여러 uvicorn worker/process가 같은 실행 DB를 공유하는 구성은 지원하지 않는다. 두 번째 프로세스는 startup에서 거절된다. 파일 잠금은 프로세스 종료 시 OS가 해제하며 lock 파일 존재 자체는 활성 실행을 뜻하지 않는다. 같은 DB 파일에 도달하는 다른 symlink 경로는 사용하지 않는다.

queued인 상태로 종료된 작업은 다음 시작에서 자동 실행될 수 있다. 이를 원하지 않으면 종료 전에 대기 취소한다. 자격증명을 파일에 저장하거나 만료된 승인 계획을 갱신해 실행하지 않는다. max_seconds는 이전처럼 실제 누적 실행시간이며 대기시간을 포함한 절대 deadline은 아직 추가하지 않았다.

## 다음 이식 범위

다중 worker/intent lease·지식 그래프, 모델 profile/chain/circuit, canonical finding·독립 evidence snapshot, 일반 tool 승인·MCP/skills, source task context, trigger/outbox는 아직 이식하지 않았다. 전체 ARTEX 이식 완료로 취급하지 않는다.

## 검증

별도 소스 복사본과 합성 데이터, 모의 HTTP/planner로 회귀 테스트를 수행했다. 운영 대상·AI 호출·서버 재시작은 수행하지 않았다. 실제 설치 DB upgrade와 브라우저 사용자 경로 확인은 별도 배포 검증 항목이다. 최종 테스트 수와 파일 변경 내역은 함께 저장된 구현 결과 문서를 참조한다.

### 최종 확인 결과

- 전체 백엔드: 1,291 passed (warnings 3).
- 전체 프론트엔드: 175 passed.
- 실제 sec-api-tester 반영 경로의 실행·큐·아카이브 테스트: 40 passed.
- 변경 파일 Git 형식 검사: 통과. 기존 혼합 줄바꿈은 유지하고 새 줄의 불필요한 차이는 정리했다.
- 실제 대상 HTTP·AI 호출, 운영 DB 변경, 서버 재시작, commit/push: 수행하지 않음.

원본 변경 전 파일은 ARTEX 작업 폴더의 docs/eventprobe-runtime-backup-2026-11-08에 보관했다. 기존 SIEM/화면/설정 변경은 이식 파일 목록에 포함하지 않았으며 그대로 보존했다.
