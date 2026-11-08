# ARTEX 모델 프로파일·작업별 장애 전환 — 2차 이식

기준일: 2026-11-08. 1차 실행 큐·예산 제어 위에 작업용 모델 설정과 안전한 AI 호출 전환을 연결했다.

## 적용 기능

- 기존 AI_*/NVIDIA_* 환경 설정을 `default` 가상 프로파일로 유지한다. 일반 요청 분석·RAG 등의 기존 단일 모델 경로는 유지하며 이번 라우팅은 검증 작업의 planner/계획 생성 및 명시적 모델을 선택한 미리보기에 적용한다.
- 모델 표시 이름, model ID, 기본 URL, 키 환경변수 이름, enabled, timeout, 최소 호출 간격, 동시 호출 수, 실패 횟수·복구 대기시간을 저장한다.
- 키 원문을 DB/브라우저 저장소/usage ledger에 저장하지 않는다. AI_API_KEY, NVIDIA_API_KEY, EVENTPROBE_MODEL_* 환경변수 이름만 참조한다. 실제 키 설정 파일을 이식 작업에서 열거나 수정하지 않았다.
- RunSpec.model_profile_ids에 최대 8개 순서를 지정한다. 빈 목록은 기존 환경 설정이다. 작업별 활성 위치와 chain revision을 영속화하고 다음 논리 AI 호출부터 변경을 적용한다. 진행 중 호출의 모델 순서를 중간에 바꾸지 않는다.
- 401 인증 오류, 402 또는 식별 가능한 403 할당량 오류, 429, 일부 일시 오류·5xx·transport 오류에 한해 다음 프로파일을 시도한다. 400/권한 거절/redirect/정상 응답의 형식 오류는 같은 payload를 다른 서버에 자동 재전송하는 이유가 아니다.
- 전환은 AI 호출 안에서만 수행한다. 대상 HTTP 요청·probe·confirm·도구 실행은 재실행하지 않는다.
- 대체 모델의 실제 호출도 max_ai_calls에 포함한다. 기존 planner가 미리 계상한 첫 호출과 추가 전환 호출을 구분하여 중복 계상·숨은 예산 초과를 방지한다.
- 프로파일별 작업/미리보기 호출이 같은 runtime limiter를 공유한다. 일반 분석·임베딩 경로 전체의 vendor 공통 rate limit으로 확장한 것은 아니다.
- health와 cooldown은 DB에 유지하며 프로파일 편집·재시작으로 초기화하지 않는다. 명시적인 상태 초기화 API/UI가 있다.
- 내부/외부 목적지를 같은 chain에 혼합하지 않는다. 매 논리 호출마다 프로파일/목적지 정책을 재검사하고 각 전송 직전 기존 ai_egress.guard를 적용한다. 반출 차단과 취소는 fallback하지 않는다. redirect도 따라가지 않는다.
- model_calls에 run/profile/revision/model/시작·종료/status/http_status/error_code/latency/실제 total_tokens만 기록한다. prompt, 응답 원문, provider header는 기록하지 않는다. 제공자가 usage를 주지 않으면 null이며 UI는 미제공으로 표시한다.
- 재시작으로 끝나지 못한 호출은 interrupted로 남기고 실제 token/처리 결과를 추정하지 않는다. 해당 run의 자동 재실행 정책은 1차 안전 규칙을 유지한다.

## 화면

새 검증 작업의 **검증 작업용 모델과 장애 전환**을 펼치면 모델 등록·편집, 상태 초기화, 모델 추가·순서 변경·제외가 가능하다. 모델을 바꾸면 이전 계획 미리보기 승인을 초기화한다. 상세 개요에는 실제 최근 모델/usage와 원문 없는 모델 호출 기록이 표시된다.

기존 index.html의 사용자 변경을 보존하기 위해 화면은 기존 JS에서 생성한다. 모델 설정 입력은 새 작업 입력 검증과 분리하며 미완성 모델 편집 내용 때문에 검증 작업 생성이 막히지 않도록 했다. 기본 모델 작업은 새 선택 필드를 생략해 서버 재시작 전의 기존 API와도 호환되도록 했다. 실제 브라우저 시각 검증은 수행하지 않았다.

## API

모든 경로는 /api/agent 기준이다.

|경로|계약|
|---|---|
|GET /model-profiles|메타데이터, key_configured 여부, health. 실키 없음|
|POST /model-profiles|ModelProfile 메타데이터만 입력; format은 현재 openai-chat 고정|
|PUT /model-profiles/{id}|{expected_revision, profile}; stale revision은 409|
|DELETE /model-profiles/{id}?expected_revision=N|참조 중인 chain 또는 진행 중 호출이 있으면 409; default 삭제 불가|
|POST /model-profiles/{id}/health/reset|모델 호출 없이 health만 초기화|
|GET /runs/{id}/model-chain|revision, profile_ids, active_position|
|PUT /runs/{id}/model-chain|{expected_revision, profile_ids}; 소유권 및 원본/진행 상태 검사|
|GET /runs/{id}/model-calls?offset=0&limit=50|작업 소유권 검사 후 메타데이터 페이지; 최대 limit 100|
|GET /capabilities|model_failover, model_profile_formats, persistent_model_call_ledger 지원 표기|

설정 변경은 EVENTPROBE_TOKEN이 있으면 실제 header/cookie의 토큰을 확인한다. 토큰이 없으면 서버 로컬 접속만 변경할 수 있다. 자가 선언 workspace 이름은 관리자 자격이 아니다. 이 변경이 기존 shared-token 제품을 다중 사용자 인증 제품으로 바꾸는 것은 아니다.

ModelProfile 필드: name, model, base_url, key_env, enabled, timeout_seconds(10–300), min_interval_seconds(0–60), max_concurrent_calls(1–16), failure_threshold(1–10), cooldown_seconds(1–3600). URL에 userinfo/query/fragment를 넣을 수 없다. /chat/completions를 붙이기 전 기본 주소를 사용한다. 반환 객체의 id/revision/health 등 읽기 전용 필드를 profile 입력에 그대로 복사하지 않는다.

## 데이터와 배포

Store 초기화 시 model_profiles/run_model_chains/model_profile_health/model_calls와 run 삭제 정리 trigger를 추가하고 store_migrations에 model_routing_v1을 기록한다. 기존 run/event/ID와 원문 증거는 변경하지 않는다. 실행 중인 서버와 운영 DB는 이식 작업에서 변경하지 않았다. 다음 서버 기동 전에 실행 DB를 백업하고 단일 runtime으로 재시작한다.

현재 profiles는 전역 설정이다. 프로파일별 사용자/agent visibility, 키 vault, 외부 공급자별 인증 형식, Anthropic/Responses/streaming, task별 context/output token 옵션은 미이식이다. 독립 evidence snapshot과 다중 worker/MCP 이식도 여전히 후속 범위다.

## 검증

- 전체 백엔드 1,322 passed, warnings 3.
- 전체 프론트엔드 182 passed.
- 신규 모델 전환·예산·권한·취소·복구 검증 31 passed는 전체 백엔드에 포함된다.
- 실제 반영된 sec-api-tester 경로에서 모델·권한·실행 큐·기존 실행 64 passed를 추가 확인했다.
- 검증은 별도 복사본/합성 키/모의 HTTP와 planner를 사용했다. 실제 대상·외부 AI·운영 자격증명을 사용하지 않았다.
- 운영 DB migration과 실제 브라우저·실제 공급자 연결은 배포 시 별도 검증해야 한다.
