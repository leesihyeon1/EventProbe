# ARTEX 기능 대비 EventProbe 반영 검토

검토일: 2026-10-14. 대상: 제공된 `D:\ARTEX-main\ARTEX-main` 소스와 EventProbe `96a489c` 및 현재 작업 중인 프런트엔드 변경. ARTEX 원격 최신 버전에 대한 평가는 아니다. 실제 사내 대상 요청, 저장된 응답 원문 열람, NVIDIA 호출은 하지 않았다.

## 결론

**ARTEX와 비슷한 외형을 만드는 작업과 ARTEX의 검증 워크플로를 구현하는 작업은 별개다. 현재 EventProbe에는 제한된 자율 HTTP 실행 및 증거 저장 기반이 있지만, 탐색 그래프, 자산 커버리지, 발견 항목 관리, 재검증 이력, 실행별 보고서 연결은 아직 빠져 있다.**

사용자가 말한 "그림으로 보여주는 기능"은 확인한 소스 기준으로 AI 이미지 생성이 아니라 구조화된 실행/자산 데이터를 그리는 인터랙티브 그래프다. 외부 AI에 내부 데이터를 보내지 않고도 구현할 수 있다.

## 주요 누락 및 위험

### F1. [P1] 탐색 그래프와 자산 커버리지 그래프가 모두 미구현

- ARTEX는 목표, 의도, 사실, 발견 등의 노드와 파생/산출/증명 관계를 탐색 그래프로 보여준다. 노드 상세, 이동/확대, 전체 맞춤, 미니맵이 있다. 단순 시간순 로그가 아니다.
- 별도로 회사, 도메인, IP, 서비스, 앱, 엔드포인트를 연결하고 범위 내 자산과 테스트된 자산을 구분하는 커버리지 그래프가 있다.
- EventProbe의 `runs/events`, `step_id`, `basis`, `evidence_ids`는 실행 그래프의 좋은 재료지만, 관계를 조회하는 API와 그래프 화면이 없다. 실행 횟수 및 발견 경로 수는 자산 커버리지를 대체하지 못한다.
- ARTEX의 자산-탐색 연결 모델에 해당하는 공통 자산 ID/검증 연결이 없으므로 CSS나 그래프 라이브러리만 추가해서 두 기능이 완성되지는 않는다.

근거: [ARTEX 탐색 그래프](D:/ARTEX-main/ARTEX-main/web/src/components/exploration-graph.tsx:48), [실제 노드/간선 조회](D:/ARTEX-main/ARTEX-main/server/server.go:2492), [커버리지 화면](D:/ARTEX-main/ARTEX-main/web/src/app/(main)/function/tasks/detail/_tabs/coverage-graph-tab.tsx:465), [커버리지 API](D:/ARTEX-main/ARTEX-main/server/server.go:1768), [EventProbe 저장 모델](C:/Users/lsh/Downloads/dev/EventProbe/backend/core/agent_store.py:22), [현재 타임라인](C:/Users/lsh/Downloads/dev/EventProbe/frontend/static/js/workspace.js:104).

### F2. [P1] 자율 검증 결과가 발견 관리, 재검증, 보고서로 이어지지 않음

- EventProbe에는 응답 분석의 findings와 자율 실행의 verification 이벤트가 있다. 따라서 "탐지 기능 자체가 없다"는 평가는 틀리다.
- 다만 발견 항목의 지속 ID, 처리 상태, 연결된 증거, 수정 후 재검증 이력을 하나의 객체로 관리하는 기능은 없다. 작업 재개는 특정 발견 항목의 수정 여부 재검증과 다르다.
- `generateReport()`는 `state.bulkResults`를 요구한다. 자율 실행이 완료돼도 그 실행의 이벤트/판정이 현재 보고서에 자동 연결되지 않는다. 자율 실행의 JSON 다운로드와 업무용 검증 보고서는 구별해야 한다.
- ARTEX에는 발견 항목에 실제 트래픽을 연결하는 API, 별도 재검증 세션/판정 기록, 작업별 보고서 화면이 있다. 원본 증거를 유지하면서 재검증 결과를 추가하는 흐름이다.

근거: [EventProbe 보고서 진입](C:/Users/lsh/Downloads/dev/EventProbe/frontend/static/js/app.js:4314), [자율 실행 JSON 내보내기](C:/Users/lsh/Downloads/dev/EventProbe/frontend/static/js/agent.js:245), [ARTEX 트래픽 연결](D:/ARTEX-main/ARTEX-main/server/finding_traffic.go:83), [ARTEX 재검증](D:/ARTEX-main/ARTEX-main/server/finding_retests.go:119), [작업별 탭](D:/ARTEX-main/ARTEX-main/web/src/app/(main)/function/tasks/detail/page.tsx:54).

### F3. [P1, 정책 확인 필요] STRICT 반복 모드와 완전한 응답-블라인드 실행은 다름

- 최신 수정은 확증 결과의 응답 원문과 자유 서술을 제거한다. 이전 리뷰의 원문 누출 재현 검사는 현재 통과한다.
- 그러나 반복 모드는 상태코드, 공격 판정, 탐지 신호, 확증 범주 등 응답 유래 요약을 다음 AI 입력에 포함한다. STRICT 배지만으로 "응답에서 나온 정보가 전혀 전달되지 않는다"고 설명하면 안 된다.
- 사용자의 금지 범위가 원문뿐 아니라 응답 유래 정보 전체라면 현재 기본값 `iterative`와 맞지 않는다. `plan`은 첫 관측 전 비식별 구조로 조건부 계획을 생성하고 이후 분기를 로컬에서 처리하도록 구현돼 있지만 기본값은 아니다.
- 그래프, 트래픽, 보고서를 향후 외부 모델의 요약 입력이나 원격 렌더러에 보내면 원래 반출 경계가 깨진다. 이 기능은 로컬 데이터와 로컬 렌더링으로 구현해야 한다.

근거: [기본 실행 모드](C:/Users/lsh/Downloads/dev/EventProbe/backend/core/agent_models.py:54), [STRICT 정제](C:/Users/lsh/Downloads/dev/EventProbe/backend/core/agent.py:223), [실제 반복 모드 입력](C:/Users/lsh/Downloads/dev/EventProbe/backend/core/agent.py:636), [응답-블라인드 계획 입력](C:/Users/lsh/Downloads/dev/EventProbe/backend/core/agent.py:281).

### F4. [P2] 실행 승인과 계획 미리보기의 UI 연결이 부족

- 현재 동일 출처 제한, 쓰기 메서드 허용, 요청/시간/AI 예산은 존재한다. 이는 중요한 실행 제한이다.
- 그러나 "이 행동을 이 대상에 실행해도 되는가"를 개별 승인/거절하고 그 결정을 저장하는 대기열은 없다. 쓰기 허용 체크박스는 개별 승인 기록과 동일하지 않다.
- `/api/agent/plan` 미리보기 API는 있으나 현재 화면은 계획 모드 선택 후 곧바로 작업을 생성한다. 계획 검토, 승인한 계획의 고정, 실행 시 동일 계획 사용까지 연결되지 않았다.
- ARTEX는 승인 요청, 상세, 이력, allowed/denied 결정과 실행 연결을 제공한다.

근거: [EventProbe 계획 미리보기 API](C:/Users/lsh/Downloads/dev/EventProbe/backend/routers/agent.py:36), [현재 시작 처리](C:/Users/lsh/Downloads/dev/EventProbe/frontend/static/js/agent.js:179), [ARTEX 승인 화면](D:/ARTEX-main/ARTEX-main/web/src/components/approval-records.tsx:741), [승인 결정 처리](D:/ARTEX-main/ARTEX-main/server/intercept.go:345).

### F5. [P2] 여러 실행 지원을 다중 에이전트 협업으로 볼 수 없음

- EventProbe는 실행별 단일 planner와 제한된 HTTP 행동을 제공한다. 최대 두 개의 독립 실행 허용은 한 작업 안의 planner/worker 협업이 아니다.
- ARTEX는 planner가 의도를 배정하고 여러 worker가 실행 결과를 기록하는 구조, 작업자별 세션, 과정 검색, 공유 계획을 제공한다.
- 이 차이는 존재하지만 사내 API 이벤트 검증에서 즉시 다중 에이전트부터 도입할 필요는 없다. 증거 추적, 재검증, 승인, 반출 경계가 먼저다. 내부 응답을 읽는 외부 worker를 그대로 추가하면 사용자의 반출 조건과 충돌한다.

근거: [EventProbe 에이전트 구조](C:/Users/lsh/Downloads/dev/EventProbe/backend/core/agent.py:1), [독립 실행 제한](C:/Users/lsh/Downloads/dev/EventProbe/backend/routers/agent.py:48), [ARTEX 실행 구조 및 공유 과정](D:/ARTEX-main/ARTEX-main/README.md:309).

## 기능 비교표

| ARTEX 기능 | EventProbe 현재 상태 | 판단 |
| --- | --- | --- |
| 좌측 전역 메뉴, 작업 목록, 검색/필터, 독립 상세 | 이번 UI 변경으로 적용 | 기본 셸 반영. 전체 ARTEX 화면 이식은 아님 |
| 탐색 그래프 | 로컬 이벤트와 증거 ID, 타임라인 | 그래프 API/관계 모델/화면 미구현 |
| 자산 그래프 및 커버리지 | 실행 중 발견 엔드포인트 | 공통 자산 목록, 범위 분모, 자산-검증 연결 미구현 |
| 목표/제약/실행 상태 관리 | 목표, 예산, 중지/재개, 제한된 범위 | 부분 반영 |
| 발견 항목 및 증거 연결 | 분석 findings, verification 이벤트, 원본 이벤트 | 독립 발견 관리와 증거 탐색 UX 부족 |
| 수정 후 재검증 이력 | 실행 재개, confirm 행동 | 발견별 재검증 세션/결론 이력 없음 |
| 트래픽 탐색 및 증거 저장 | 개별 요청/응답, Diff, 히스토리, OOB, 실행 이벤트 | 전역 트래픽 검색/발견 연결은 별도 구현 필요 |
| 개별 실행 승인/거절 | 쓰기 허용, 같은 출처, 예산 | 지속 승인 대기열/감사 이력 없음 |
| 다중 worker와 개별 세션 | 단일 planner, 제한된 HTTP 실행 | 미구현. 우선순위는 후순위 |
| 실행별 보고서 | 일괄 테스트 보고서, 자율 실행 JSON | 자율 실행 보고서 연결 없음 |
| 런타임 Agent/Tool/Skill/MCP 관리 | Python 내부 도구와 RAG | ARTEX식 런타임 레지스트리 없음 |
| 모델/도구 사용 이력 | 실행별 AI/HTTP 횟수 | ARTEX식 세션별 사용 상세와 별도 관리 화면 없음 |

개발용 Codex 스킬과 제품 내부에서 실행하는 ARTEX Skill은 서로 다르다. 개발 스킬을 적용했다고 EventProbe에 런타임 스킬 기능이 생기는 것은 아니다.

## "그림"의 정확한 의미

1. **탐색 그래프:** `@xyflow/react` 기반. 목표/의도/사실/발견 등 노드와 관계를 렌더링한다. 확대, 이동, 미니맵, 노드 상세가 있다.
2. **자산 커버리지 그래프:** `@antv/g6` 기반. 자산 관계를 배치하고 테스트됨/미테스트/범위 밖을 구별한다. 접힌 자산 그룹 확장과 상세 조회가 있다.
3. README의 Mermaid 아키텍처 다이어그램은 문서 설명이다. 이것을 제품의 AI 이미지 생성 기능으로 세면 안 된다. 확인한 그래프/보고서 구현에서 이미지 생성 모델을 요구하는 경로는 확인하지 못했다.

참조 화면: [탐색 그래프 스크린샷](D:/ARTEX-main/ARTEX-main/screenshots/graph.png), [자산 커버리지 스크린샷](D:/ARTEX-main/ARTEX-main/screenshots/assets_test.png).

## EventProbe 적용안

### 1단계: 현재 실행 데이터를 사용한 탐색 및 증거 화면

- 기존 Python/FastAPI는 유지하고 자율 검증 모듈을 별도로 확장한다. Go 재작성이나 ARTEX 전체 실행 엔진 도입은 필요하지 않다.
- 기본 관계는 `Run -> Action -> Request -> Observation -> Verification/Finding`으로 둔다. `step_id`, `basis`, `evidence_ids` 등 실제 연결 근거만 사용한다.
- 사전 조건부 계획은 별도 그래프 또는 구별된 노드 상태로 표시한다. 예정 경로와 실제 실행 경로를 혼동시키지 않는다. 시간상 인접하다는 이유로 인과관계를 만들지 않는다.
- 노드 선택 시 오른쪽 패널에 요청/응답, 판정 근거, 한계, 원본 증거 링크를 표시한다. 증거 본문은 로컬 텍스트로 렌더링하고 HTML로 실행하지 않는다.
- 기존 프런트엔드는 바닐라 JS다. ARTEX의 React 컴포넌트를 그대로 붙이지 말고 그래프 구역만 독립 컴포넌트로 도입할지, 현재 프런트에서 사용 가능한 그래프 라이브러리로 구현할지 범위를 정한다.
- 완료 기준: 모든 표시된 증거 연결이 실제 이벤트로 이동하며, 새로고침/재개 후 ID가 유지되고, 그래프 표시만으로 외부 통신이 발생하지 않는다.

### 2단계: 발견, 보고서, 커버리지

- 발견 항목에 지속 ID, 원래 판정, 증거 목록, 현재 처리 상태, 재검증 이력을 둔다. 재검증 결과로 원래 증거를 덮어쓰지 않는다.
- 자율 실행별 로컬 보고서를 만든다. 확증/의심/미확정과 검증하지 못한 범위를 구별하고 원본 증거를 연결한다. 외부 AI가 내부 증거를 읽어 보고서를 작성하는 방식은 사용하지 않는다.
- 자산 커버리지는 우선 `허용된 엔드포인트 x 검사 유형 x 계정`의 표로 시작한다. 등록 범위의 분모와 실제 실행 여부를 저장한 뒤 그래프로 확장한다.
- "요청을 전송함", "검증을 완료함", "안전하다고 입증됨"을 별도 상태로 둔다. 발견되지 않은 모든 자산까지 검증한 것처럼 백분율을 표시하지 않는다.

### 3단계: 승인 및 제한된 자율성 확장

- 응답 유래 정보까지 외부 반출 금지라면 응답-블라인드 계획을 기본으로 고정한다. 외부 NVIDIA는 비식별 구조 기반의 제한된 계획만 생성하고 로컬 엔진이 조건 판정/도구 실행/증거 기록을 담당한다.
- 계획 미리보기 후 승인한 버전/해시를 실행에 고정한다. 승인 후 다른 계획을 재생성하여 실행하지 않는다.
- 위험 행동은 실행 전 승인, 범위/예산 재검사, 감사 이력을 통과하게 한다. 외부 모델이 반환한 임의 코드나 셸 명령을 실행하지 않는다.
- 더 유연한 응답 기반 추론이 반드시 필요하면 사내 추론을 별도 옵션으로 검토한다. 외부 모델에 응답을 주지 않는 조건에서 ARTEX와 동일한 적응형 추론을 보장할 수는 없다.
- 다중 worker/MCP는 이후 승인된 로컬 도구만 제한적으로 도입한다. 그래프 렌더링, 폰트, telemetry, 오류 수집, OOB 등 AI 외 반출 경로도 함께 통제한다.

## 이번 변경과 검증

- UI: 밝은 중립색 기반 전역 메뉴, 작업 표, 검색/상태 필터, 페이지 구분, 상세 타임라인, 새 작업 다이얼로그, 로컬 Lucide 아이콘, 모바일 배치를 적용했다.
- 그래프, 자산 DB, 발견 관리, 재검증 이력, 자율 실행 보고서는 이번 변경에서 구현하지 않았다. 존재하지 않는 기능의 탭을 완료된 것처럼 추가하지 않았다.
- 기존 요청/응답 분석 내부 및 일부 레거시 모달은 유지한다. 모든 화면의 디자인 통일이 끝났다는 의미는 아니다.
- 브라우저에서 데스크톱 1440px 및 모바일 390px 배치, 목록 검색, 새 작업 다이얼로그, 메뉴 이동을 확인했다. 실제 검증 실행/삭제는 하지 않았다.
- 프런트엔드 단위 테스트 5개 통과. 관련 Python 테스트와 이전 반출 재현 검사 88개 통과. 전체 애플리케이션 테스트나 절대적 비반출 보증을 대신하지 않는다.
- UI 접근성/반응형 확인에는 [Web Interface Guidelines](https://raw.githubusercontent.com/vercel-labs/web-interface-guidelines/main/command.md)의 명명, 포커스, 긴 콘텐츠 처리, 동작 감소 항목을 참고했다.

**권장 순서: 탐색 그래프와 증거 상세 -> 자율 실행 보고서/발견 관리 -> 커버리지/재검증 -> 개별 승인 -> 필요한 경우에만 다중 에이전트. 반출 정책 확정은 이 모든 단계의 선행 조건이다.**
