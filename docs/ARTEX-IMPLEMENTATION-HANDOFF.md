# ARTEX 기능 확장: 현재 상태와 다음 작업 인계

기준일: 2026-10-14. 다음 작업은 이 문서를 먼저 읽는다. 과거 리뷰의 미구현/테스트 실패를 현재 상태로 그대로 인용하지 않는다. 이번 정리는 문서 작업이며 제품 추가 구현, pull/commit/push, 서버 재시작은 수행하지 않았다.

## 1. 사용자 목표와 필수 조건

- ARTEX의 적용 가능한 기능을 EventProbe에 단계적으로 구현한다. 외형이나 빈 탭만 추가하지 않고 실제 실행/증거/결론까지 연결한다.
- Python/FastAPI와 기존 분석/확증 코어를 유지한다. Go 재작성이나 ARTEX 서버 병행 도입은 기본안이 아니다.
- UI는 단정한 작업 표, 검색/필터, 독립 상세, 일관된 상태 표시 중심으로 구성한다. 기존 요청/분석 및 레거시 모달까지 디자인 통일은 아직 끝나지 않았다.
- 추론 제공자는 NVIDIA 외부 API다. 내부 도메인, 응답 원문/헤더, 캡처/HAR를 외부 AI로 보내지 않는다.
- URI/헤더도 자동으로 비식별 정보가 아니다. 동적 ID, 쿼리 값, 인증정보, 내부 명칭은 제거하고 승인된 구조만 전달한다.
- **응답 유래 상태코드/판정 플래그 허용 여부는 별도 확정 필요**. 허용받았다고 간주하지 않는다. 보수적인 기본안은 응답-블라인드 계획 + 로컬 분기다.
- 그래프/사이트맵/보고서는 로컬 렌더링한다. 원격 다이어그램/telemetry/외부 LLM 평가에 내부 증거를 보내지 않는다.
- 예산 자동 확대, 불명확한 대상 요청 무조건 재전송, 미확정을 안전으로 표시하는 동작을 금지한다.

## 2. 환경과 운영 주의

- 작업 경로: `C:\Users\lsh\Downloads\dev\EventProbe`
- ARTEX 참조: `D:\ARTEX-main\ARTEX-main`. 제공된 로컬 사본 기준이며 원격 최신판 전수 검토가 아니다.
- 정리 시 HEAD: `e7d21cc`. 다른 작업에서 수정/커밋할 수 있으므로 시작 시 `git status --short`, `git log -6 --oneline`을 확인한다.
- 마지막 확인 서버: `http://127.0.0.1:8000/#agent`. 자동 reload 없이 실행 중이었다. 실제 PID/상태는 다시 확인한다.
- 프런트엔드는 새로고침으로 반영된다. 조기 종료/결론/새 발견 출처 등 Python 변경은 실행 서버 재시작 여부 확인이 필요하다. 재시작 완료로 보고한 적 없다.
- 진행 중 작업과 사용자 승인 없이 기존 서버를 종료하지 않는다. 같은 운영 DB로 두 번째 앱을 띄우면 startup recovery가 기존 실행 상태를 변경할 수 있다.
- `.env`의 실제 NVIDIA 키를 읽거나 출력하지 않는다. 내부 저장 URL/응답을 모델 컨텍스트나 브라우저 스크린샷으로 가져오지 않는다.
- 실제 대상 및 NVIDIA를 사용한 검증은 하지 않았다. 모의 HTTP/planner와 합성 데이터로 검증했다.

## 3. 적용 상태

| 항목 | 구현된 부분 | 남은 부분 |
| --- | --- | --- |
| 작업 UI | 전역 메뉴, 작업 표, 검색/상태 필터, 페이지 구분, 독립 상세, 새 작업 다이얼로그, 로컬 Lucide, 반응형/테마 | 레거시 요청/분석/모달/설정 전체 통일 |
| 탐색 그래프 | Run/Action/Request/Observation/Verification, 실제 ID 기반 관계, 계획/실행 구분, 상세/확대/맞춤 | ARTEX 전체 목표/의도/자산 모델 및 모든 조작과 동일하지 않음 |
| 조기 종료 개선 | 반복/형식 오류에 기존 예산 내 최대 3회 선택 기회, 제한된 제공자 오류 복구, 실행 전 HTTP 비용 검사 | 실제 모델 품질 평가, 계획 체크포인트 재개, 승인된 예산 연장 |
| 로컬 결론 | 정상/오류/중단/예산 종료 결과, 부분 결론, 근거/한계/다음 조치, 과거 기록 집계 | 업무용 보고서/지속 발견 관리와는 다름 |
| 사이트맵 | 별도 탭, 트리/목록, 검색/메서드/상태 필터, 행위자별 HTTP/판정, 증거 이동 | 능동 크롤러/전체 도메인 커버리지/수동 이력 통합/다중 작업 자산 통합 없음 |
| 발견 출처 | source_observation_id, discovery 이벤트, 40개 수집 한도 이벤트 | 기존 기록 출처는 추정하지 않고 미기록으로 표시 |
| 제한된 자율 실행 | 예산/같은 출처/쓰기 제한, 중단/재개, 계정 세션, 증거 저장 | 다중 worker 협업/개별 행동 승인 대기열 없음 |
| 응답-블라인드 계획 | plan 모델/로컬 분기, 실제 confirm/access 실행, 미리보기 API, **승인본 고정 실행(P3): approved_plan + fingerprint, 범위 이탈 안전 정지** | 기본 mode는 iterative. 승인본 만료 TTL·체크포인트 재개는 미완성 |
| 반출 방어 기반 | ai_egress/public_shape/ai_privacy, 감사 함수/회귀 검사 존재 | 운영 전체 비반출 보증 아님. iterative는 응답 유래 요약 사용 |
| 기존 분석 도구 | 수동 요청/응답, Diff/히스토리, 분석/차등 확증, OOB, RAG, 일괄 테스트 보고서 | 자율 실행 결과와 업무 흐름 연결 필요 |

최근 커밋: `96a489c` 계획 실행 보정 → `d782cca` 작업 UI → `b53d850` 탐색 그래프 → `2a15477` 조기 종료/결론 → `e7d21cc` 그래프 회귀 보정.

**사이트맵은 구현/테스트 완료, 미커밋 상태다.** 기존 변경을 reset하거나 덮어쓰지 않는다.

## 4. ARTEX 기능 적용 대장

작업 탭, 화면 경로, README 및 기존 상세 리뷰에서 확인한 기능군이다. 보조/설정 화면은 존재 확인 수준인 항목도 있으므로 구현 전 해당 API/동작을 더 확인한다. 모든 기능을 전수 검증했다는 의미는 아니다.

| 기능군 | 현재 상태 | 적용 방향 / 조건 |
| --- | --- | --- |
| 대시보드/작업 개요 | 부분 | 상태/결론/예산/미완료 범위 로컬 집계 |
| 작업 목록/탐색 그래프 | 기반 완료 | 현재 구현 보강. 다시 만들지 않음 |
| 자산 목록/자산 그래프 | 작업별 사이트맵만 있음 | 지속 asset ID, 자산 관계, 명시적 등록 범위 |
| 자산 검사 커버리지 | **구현됨(P2):** 엔드포인트 × 검사 종류 그리드, 셀 상태(미검사~판정), 행위자별 상세, 범위 밖/예산 소진 표시 | 등록 범위 분모 기반 정량화, 다중 작업 합산 |
| 발견 관리 | **구현됨(P1):** 지속 finding ID(재시작 유지), 상태/심각도/메모 append-only 이력, 증거 연결 | 심각도 자동 점수화, 다중 작업 통합 발견 |
| 수정 후 재검증 | 전용 이력 없음 | finding별 새 retest 실행/결론. 원래 증거 불변 |
| 작업 보고서 | **구현됨(P1):** 로컬 HTML/인쇄용 보고서(무반출), 범위/판정/미완료/증거 포함 | 다중 작업 합본, PDF/서식 확장 |
| 전역 트래픽 탐색 | 개별 이력/이벤트 | 검색/필터/페이지 조회, finding 연결, 본문 지연 조회 |
| 승인/인터셉트 | 포괄적 쓰기 제한 | 행동별 승인/거절/만료, 실행 직전 범위/예산 검사 |
| 계획 미리보기/공유 할 일 | API/조건부 계획 | 승인 plan 버전/해시 고정, 예정과 실제 진행 구분 |
| 다중 worker/세션/브로드캐스트 | 단일 planner, 독립 실행 최대 2개 | 로컬 제한 worker, 공유 예산/claim/취소/증거 ID. 외부 worker 원문 제공 금지 |
| 사람 개입 채팅 | ARTEX식 작업 대화 없음 | 범위 변경/중단/추가 계획 승인 중심. 내부 증거를 읽는 외부 채팅은 그대로 도입 불가 |
| 런타임 Agent/Tool/Skill | 내부 함수/RAG | 절차 레지스트리, 스키마/버전/권한/예산/증거 조건 |
| MCP | 제품용 레지스트리 없음 | 승인된 사내 서버, 최소 권한/네트워크 격리/감사 선행 |
| 모델 관리/LLM 사용 기록 | **구현됨(P4): 반출·AI 사용 감사 뷰** — 채널·모델별 호출 수, 외부 전송·차단, 발견 분포, 최근 레코드(원문/키 없음) | 지연/토큰/오류는 제공자 응답 계측 필요(미구현) |
| Workspace/명령/산출물 | 전용 체계 없음 | 로컬 산출물/구조화 도구부터. 자율 shell/외부 코드 설치 별도 승인 |
| 기록 프록시/MITM | 기존 HTTP 기록으로 일부 대체 | 공통 전송 기록부터. 범용 프록시는 인증서/범위/세션 통제 후 검토 |
| 자산 동기화/ScopeSentry | 없음 | 사내 목록 읽기 전용 가져오기부터. 대상/자격증명 별도 확정 |
| DNS/HTTP 자산 보강 | 자동 파이프라인 없음 | 승인된 DNS/대상/예산 내 수집. 능동 요청과 수동 표시 구분 |
| 알림/로그/정책 설정 | 기능별 일부 존재 | 내부 채널, 비민감 상태 알림, 접근제어/감사/보존 통합 |
| 기억/지식 공유 | RAG 기반 | 공개 지식과 내부 증거 분리. 내부 임베딩/검색 결과 외부 전송 금지 |
| 설치/업데이트/배포 | Python 기존 방식 | Go updater 복제 대신 Python 배포/마이그레이션/롤백 정비 |

자동 스파이더는 자산 기능의 후속 확장 후보다. 이름이 Spider인 별도 ARTEX 작업 탭은 확인하지 못했다. 현재 URL 트리를 전체 도메인 크롤러라고 설명하지 않는다.

## 5. 구현 순서와 완료 조건

### P0. 반출 정책 및 현재 변경 마무리

- 미커밋 사이트맵을 검토/재검증한다. 커밋은 사용자 요청 시 수행한다.
- 응답 유래 메타데이터 허용 여부를 확인한다. 미확정이면 보수적인 plan 정책안을 제시하고 기본값 변경을 명확히 알린다.
- AI/임베딩/OOB/캡처/오류 수집 경로를 재점검한다. 합성 비밀값의 실제 전송 직전 검사와 실패 시 차단을 검증한다.
- strict-plan에서는 응답 변화가 외부 입력/추가 호출에 영향을 주지 않는지 확인한다. 단위 테스트만으로 운영 비반출을 입증했다고 하지 않는다.

### P1. 발견 관리 + 작업별 로컬 보고서 — 구현됨

구현 커밋: `a96fab1`. 핵심: `backend/core/agent_findings.py`, `backend/routers/agent.py`
(PATCH findings / GET report), `frontend/static/js/agent_findings.js`, `findings.css`.

- Finding과 append-only 증거 연결/상태 변경을 정의한다. run/step/observation/verification 참조를 유지한다.
  → finding ID = (run_id, 유형, 엔드포인트, 행위자) 순수 해시. finding_update 이벤트로 상태/심각도/메모를 append-only 기록.
- 기존 verification에서 중복 없이 생성하며 원본을 수정하지 않는다. 마이그레이션과 과거 기록 호환을 설계한다.
  → 결정적 ID 도출이라 테이블/마이그레이션 없이 과거 기록에도 그대로 적용. 출처 미기록 과거 run 은 추정하지 않는다.
- 실제 데이터가 연결된 발견 목록/상세와 로컬 보고서를 추가한다. → `발견` 탭 + GET `/runs/{id}/report` 독립 HTML.
- 완료 조건: 재시작 후 ID 유지, 유효한 증거 링크, 부분 결론/미검증 범위 포함, 보고서 생성 시 외부 AI/대상 요청 0회. → 모두 테스트로 확인(`backend/tests/test_findings.py`, `frontend/tests/agent_findings.test.js`).
- 남은 것: 심각도 자동 점수화, 다중 작업 통합. 브라우저 end-to-end 는 서버 재시작 후 실행에서 확인 필요(아직 미실행).

### P2. 재검증 + 트래픽 + 커버리지 — 커버리지 구현됨, retest/트래픽 남음

커버리지 구현 커밋: `7362237` (`frontend/static/js/agent_coverage.js`, `coverage.css`, `커버리지` 탭).
클라이언트 전용 로컬 투영이라 조회 시 대상 요청이 없다(완료 조건 충족). 셀 상태는
미검사/계획/요청/관측/판정으로 구분하고 범위 밖·예산 소진을 표시하며 허위 분모를 만들지 않는다.

- finding별 retest를 새 실행으로 연결하고 자격증명을 안전하게 재주입한다. 실행 재개와 수정 후 재검증을 구별한다. — **남음.** 실제 대상 HTTP 를 유발하므로 모의 테스트로만 검증 가능. 자격증명 재주입은 기존 resume 경로(request_headers/actor_headers) 재사용.
- 공통 traffic/asset ID를 설계한 후 수동/자율 이력을 통합한다. 등록된 범위의 커버리지 표부터 만든다. — **커버리지 표 완료.** traffic/asset ID 통합은 레거시 app.js 측과 교차하므로 별도 슬라이스.
- 완료 조건: 원래 증거 불변, 해결/실패/미확정 구분, 미실행/범위 밖/예산 소진 정확한 표시, 조회 시 대상 요청 없음. — 커버리지는 충족. retest 는 원본 증거 불변 + 새 실행 분리로 설계.

### P3. 계획 승인 + 복구 + 제한된 탐색 — 계획 승인/고정 구현됨, 복구/스파이더 남음

계획 고정 구현 커밋: `6796a18` (`RunSpec.approved_plan`, `plan.plan_fingerprint`,
`agent.pinned_plan`/`_plan_loop`, 새 작업 대화상자의 계획 미리보기·승인 UI).

- 미리보기 승인본의 버전/해시를 실행에 고정한다. 승인 후 다른 계획을 재생성하지 않는다. — **구현됨.** approved_plan 을 재생성·AI 호출 없이 실행, plan 이벤트의 fingerprint 로 승인본 동일성 대조. 범위 이탈/스키마 위반은 실행 전 안전 정지(plan_rejected). approved_plan 은 spec 에 저장돼 재시작에도 유지. (만료 TTL 은 미구현 — 생성 즉시 실행 전제.)
- 체크포인트/취소/재개를 영속화한다. 처리 여부가 불명확한 쓰기 요청은 자동 재실행하지 않는다. — **남음.** 기존 paused/interrupted + resume(자격증명 재주입)이 기반. 쓰기 요청 재실행 억제는 추가 설계 필요.
- 스파이더는 명시적 시작, origin/경로/메서드, 깊이/수/시간/동시성/리다이렉트 제한을 갖춘 별도 로컬 실행으로 구현한다. GET의 부작용도 고려한다. — **남음.** 실제 대상 HTTP 를 유발하므로 모의 테스트로만 검증 가능.
- 완료 조건: 승인 거절/만료/범위 이탈/재시작 시 안전 정지, 전체 예산 준수, 모든 종료에 결론/중단 이유. — 계획 고정은 충족(거절/범위 이탈/재시작). 만료·복구·스파이더는 위 남은 항목에서.

### P4. 운영 및 고급 기능 — 반출·AI 사용 감사 뷰 구현됨, 나머지 남음

반출 감사 뷰 커밋: `28b62e4` (`ai_egress.audit_summary`, `GET /api/egress/audit`,
정책 배너 옆 "반출 감사" 다이얼로그). 서버가 이미 기록 중인 감사를 운영 화면으로
노출한다. 원문/키 없이 채널·모델별 호출·외부 전송·차단·발견 분포 + 최근 레코드.

- 인증/작업 소유권, 비밀정보, 증거 보존/삭제/감사, 사내 네트워크 정책을 정비한다. 보존 기간 설정 기반은 이미 존재한다. — **남음**(증거 삭제 감사 로그가 다음 후보. 인증/소유권은 앱 전역·다중 사용자라 범위 큼).
- 절차 레지스트리, 모델 관리/사용 이력, 사내 자산 동기화/알림, 필요한 제한 MCP/worker를 도입한다.
- 독립 worker 필요 시 durable claim/공유 예산/취소 신호/작업 큐/DB 전환을 검토한다. Uvicorn worker 수만 늘리지 않는다.
- 외부 NVIDIA에 응답을 주지 않는 조건에서 ARTEX식 원문 기반 적응형 추론과 동등성을 보장할 수 없다. 필요 시 사내 추론을 별도 선택지로 둔다.

## 6. 코드 진입점과 미커밋 파일

- 실행/발견/복구: `backend/core/agent.py`; 결론: `agent_outcome.py`; 계약/계획: `agent_models.py`, `plan.py`.
- 저장/API: `backend/core/agent_store.py`, `backend/routers/agent.py`.
- 반출: `backend/core/ai_egress.py`, `public_shape.py`, `ai_privacy.py`, `ai_analyzer.py`, `rag.py`.
- 재사용할 판정: `backend/core/analyzer.py`, `confirm.py`, `test_validity.py`, `verification_context.py`.
- 작업 UI: `frontend/templates/index.html`, `frontend/static/js/workspace.js`, `agent.js`, `agent_graph.js`, `agent_sitemap.js`.
- 스타일: `frontend/static/css/workspace.css`, `agent.css`, `sitemap.css`; 기존 분석/보고서: `frontend/static/js/app.js`.
- ARTEX 참조: 작업 상세 `page.tsx`와 `_tabs`, `components/exploration-graph.tsx`, `server/finding_traffic.go`, `finding_retests.go`, `intercept.go`, `engine.go`, `engine_timeout.go`, `README.md`.

사이트맵 관련 미커밋 수정: `backend/core/agent.py`, `backend/tests/test_agent.py`, `backend/tests/test_plan_run.py`, `frontend/static/js/workspace.js`, `frontend/templates/index.html`, `frontend/tests/workspace.test.js`.

신규: `frontend/static/js/agent_sitemap.js`, `frontend/static/css/sitemap.css`, `frontend/tests/agent_sitemap.test.js`, `docs/reviews/2026-10-14/site-map-tab-review.md`.

기존부터 수정된 `docs/reviews/2026-10-14/autonomous-completion-fix.md`를 보존했다. 이번 정리에서 인계 문서와 과거 리뷰 안내도 추가한다. 기능/일반 UI 패턴은 독립 구현하며, ARTEX 코드를 복사하려면 루트/파일별 라이선스와 재사용 범위를 별도 확인한다.

## 7. 검증과 한계

사이트맵 구현 후 마지막 실행 결과다. 이번 문서 정리에서는 테스트를 재실행하지 않았다.

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -q
# 953 passed, 기존 deprecation warnings 3건
node --test frontend/tests/*.test.js
# 34 passed
git diff --check
# 통과
```

- 과거의 958개는 당시 백엔드 및 별도 반출 회귀 검사 묶음이다. 위 953개와 수집 범위가 같다고 간주하지 않는다.
- 합성 UI: 1440px/390px, 테마, 검색/필터/트리/목록, 증거 이동, 방향키 탭 전환, 폴링 시 선택 유지 확인. 모바일 넘침/콘솔 오류 없음. 임시 QA 화면 제거 완료.
- 기존 서버가 새 사이트맵 HTML/JS/CSS를 제공하는 것까지 확인했다. 실제 NVIDIA 계획 품질/지연/종료율과 운영 네트워크 반출은 미검증.
- 후속 개발은 `python-testing-patterns`, UI 검토는 `web-design-guidelines`, 모델 평가는 `llm-evaluation`, 명시적 보안 검토는 `security-best-practices`를 활용한다. 개발 스킬과 제품 런타임 Skill/MCP는 다르다.

## 8. 다음 작업 시작 문구

> docs/ARTEX-IMPLEMENTATION-HANDOFF.md를 먼저 읽고 현재 git 상태와 코드를 확인해줘. 기존 사이트맵/그래프/결론을 보존하고 ARTEX 기능 확장을 이어가줘. 먼저 P0의 정책 및 미반영 사항을 확인한 뒤 P1의 발견 관리와 자율 실행별 로컬 보고서를 구현해줘. Python을 유지하고 실제 내부 도메인/응답을 외부 AI로 보내지 마. 목표 시스템을 임의로 검사하거나 기존 서버를 임의로 종료하지 말고 합성 데이터 테스트와 UI 검증까지 수행해줘.

상세 이력: [최초 통합 검토](artex-integration-review.md), [기능 차이 검토](reviews/2026-10-14/artex-feature-gap-review.md), [조기 종료 개선](reviews/2026-10-14/autonomous-completion-fix.md), [사이트맵 구현](reviews/2026-10-14/site-map-tab-review.md).
