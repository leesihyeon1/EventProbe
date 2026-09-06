# 공격 검증 내역 (Attack Verification)

> 이 도구가 각 공격의 "성공"을 **어떻게 검증하는가**를 정리한 문서.
> 구현 근거: `backend/core/analyzer.py` 의 `analyze_response()` / `attack_findings()`.
> 회귀 테스트: `backend/tests/test_analyzer.py`.

---

## 1. 핵심 원칙

1. **차단 안 됨 ≠ 취약** — 방어장비(WAF/IPS)가 막지 않았다는 사실만으로 대상이 취약하다고 판정하지 않는다. 과거의 "SQLi가 200 통과 → high" 휴리스틱은 제거됨.
2. **증거 기반 판정** — 실제 성공 증거(파일 내용·명령 출력·계산 결과·타이밍 일치·실행 컨텍스트 반사·민감정보 노출)가 있을 때만 취약(`bypass`/high 이상)으로 격상한다.
3. **3-상태 명시** — 단일 응답으로 판정할 수 없는 공격 시도는 "안전"이 아니라 **"자동 판정 불가 — 수동 확인 필요(미확인)"** 로 표기해 거짓 안심을 방지한다.

각 신호(finding)는 다음 형태로 기술된다:

```
{ name, verdict(성공|안전|미확정|미확인|차단), confidence(0~100), why(판정 근거), evidence(매칭 증거) }
```

---

## 2. 검증 전략 아키타입

공격 유형마다 "성공 판정 방식"이 다르며, 아래 6개 전략 중 하나 이상으로 검증한다.

| 전략 | 성공 판정 기준 | baseline/상태 필요 | 안전 단정 가능 |
|------|----------------|:---:|:---:|
| 콘텐츠 시그니처 | 응답에 대상 내용/에러 시그니처가 나타남 | X | 가능(미노출) |
| 반사 + 실행 컨텍스트 | payload가 실행 가능한 위치에 반영됨 | X | 불가 |
| 계산 결과 | 응답에 `f(payload)` 결과가 나옴(원문 아님) | X | 불가 |
| 차분(오라클) | 정상(baseline) 대비 응답이 유의미하게 달라짐 | O | 불가 |
| 타이밍 | 응답시간 ≥ payload가 요구한 지연 | X | 불가 |
| 상태/헤더 오라클 | status code + 헤더(Location 등) 의미 | X | 부분 |

> 파일 스캔류는 "콘텐츠 시그니처"로 자기완결적으로 판정(있으면 노출, 없으면 **안전-미노출** 단정 가능).
> 인젝션류는 반사·차분·타이밍·계산에 흩어져 있어 "안전"을 증명 못 하고 "증거 없음(미확인)"까지만 간다.

---

## 3. 공격 유형별 검증 내역

| 공격 유형 | 검증 방법 | 성공 시그니처 / 증거 | verdict · confidence |
|-----------|-----------|----------------------|----------------------|
| **반사형 XSS** | payload 반사 위치의 실행 컨텍스트 분류 | 이벤트 핸들러 속성 / `javascript:` URI / `<script>` 내부 / 실행형 태그 삽입 | 성공 · 92 |
| 〃 (미인코딩) | 특수문자 원문 반사 | `<`,`>`,`"`,`'` 인코딩 없이 반영 | 성공 · 88 |
| 〃 (단순 반사) | payload가 반영되나 특수문자 없음 | 반영되나 실행 불가 | 미확정 · 40 |
| **DOM 기반 XSS** | 응답 `<script>` 내 소스→싱크 흐름(정적) | `location.hash`/`document.referrer`/`postMessage` → `innerHTML`/`document.write`/`eval` 등 | 미확정 · 55 (브라우저 확인 필요) |
| **CSTI** | 템플릿 표현식 미평가 반사 + 프레임워크 존재 | `{{7*7}}` 원문 반사 + Angular/Vue/Alpine 마커 | 미확정 · 60 |
| **파일 읽기 / LFI / XXE** | 파일 내용 시그니처 매칭 | `root:.*:0:0:`(passwd), win.ini, PHP 소스, 개인키 등 (`_FILE_READ_MARKERS`) | 성공 · 92 |
| **민감 파일 노출** | 대상 파일 실제 내용 존재 여부 | `.git/config`, `.env` 등 내용 매칭 → 노출 / 미검출 → **안전** | 성공 · 92 / 안전 · 80 |
| **명령 실행 (Cmdi)** | 명령 출력 시그니처 매칭 | `uid=..gid=..`, Windows `ver`/`dir` 출력 (`_CMD_OUTPUT_MARKERS`) | 성공 · 93 |
| **SSRF** | 내부/클라우드 메타데이터 응답 (SSRF처럼 보이는 요청일 때) | AWS/GCP/Azure 메타데이터 마커 (`_SSRF_MARKERS`) | 성공 · 85 |
| **SSTI** | 계산 결과 검증 | 요청 `7*7` + 응답에 `49`(원문 `7*7` 아님) | 성공 · 90 |
| **SQL Injection (error-based)** | DB 에러 시그니처 (SQLi처럼 보이는 요청일 때) | `ERROR_LEAK_PATTERNS` 매칭 | 성공 · 85 |
| **SQL Injection (blind, time)** | 타이밍 | payload 지연(sleep N) ≥ 응답시간의 80% | 성공 · 90 / 미지연 미확정 · 30 |
| **SQL Injection (boolean)** | 차분 | baseline 대비 상태/본문 크기 변화 | 미확정 · 55 |
| **오픈 리다이렉트 (서버)** | 상태/헤더 오라클 | 3xx + `Location`이 외부(`http(s)://`,`//`) | 성공 · 80 |
| 〃 (위험 스킴) | 헤더 오라클 | `Location`이 `javascript:`/`data:` 등 | 성공 · 85 |
| 〃 (클라이언트) | meta refresh / JS location (서버 3xx 아님) | `<meta http-equiv=refresh url=//…>`, `location.href=//…` | 성공 · 78 |
| **XML-RPC 인증 노출** | methodResponse + 인증 실패 fault | `<methodResponse>` + "Incorrect username or password" | 성공 · 85 (multicall 배열이면 88) |
| **XML-RPC 위험 메서드** | listMethods 노출 메서드 | `system.multicall` / `pingback.ping` / `wp.getUsersBlogs` 등 | 성공 · 75~88 |
| **XML-RPC 활성** | 응답 형태 | `<methodResponse>` (그 외) | 미확정 · 45 |
| **HTTP 메서드 오라클** | status 오라클 | PUT 업로드/DELETE/WebDAV/TRACE 2xx | 성공 |
| **자동 판정 불가** | 위 신호 전무 + 공격 시도 | 반사·에러·마커·시간차·baseline 변화 모두 없음 | 미확인 · 30 |

> 마커 테이블 정의: `_FILE_READ_MARKERS_STRONG/WEAK`, `_CMD_OUTPUT_MARKERS`, `_SSRF_MARKERS`, `ERROR_LEAK_PATTERNS`, `SENSITIVE_PATTERNS` (모두 `analyzer.py`).

---

## 4. 오탐 방지 장치

- **힌트 게이팅** — SSRF/SQLi 성공 신호는 "요청이 그 공격처럼 보일 때"(내부주소·SQL 구문 등)만 성공으로 격상. 정상 API/문서의 우연한 매칭 억제.
- **강/약 시그니처 구분** — 파일 노출은 매우 구체적인 강한 시그니처(passwd 등)는 모든 응답에서, 약한 시그니처는 파일 접근처럼 보일 때만 검사.
- **차단 키워드의 대형 성공 응답 예외** — 큰 200 응답에 우연히 든 차단 키워드는 차단으로 보지 않음(`_body_signals_block`).
- **SPA 셸 감지** — 서버가 껍데기만 주는 경우 서버측 반사/주입 테스트가 무의미함을 경고하고 실제 API 테스트를 유도.
- **XML-RPC** — 응답이 `<methodResponse>` 형태일 때만 동작(일반 HTML의 동일 문구는 무시).

---

## 5. 판정 → 위험도 매핑

`analyze_response()` 10번 블록. 상태코드 relabel보다 **증거 outcome을 우선**한다.

| 조건 | verdict | risk_level | score |
|------|---------|-----------|-------|
| 민감정보 노출 / `bypass` | bypass | critical | 90 |
| 에러 정보 누출 | (유지) | high | 70 |
| 공격 성공(outcome=success) | **bypass 로 격상** | high 이상 | max(score, 신뢰도) |
| 통과 + 미확정 신호 있음 | passed | medium | 40 |
| 통과 + 우려 신호 없음 | passed | low | 25 |
| 차단됨 | blocked | info | 10 |

---

## 6. AI 보강 (선택)

- **ai_verdict** — 라벨(판정/신호 이름·상태·시간)만 전송, **응답 본문 미전송(무유출)**. 판정 카드 서술에 사용.
- **ai_analyze** — 응답 body를 AI로 전송(**유출 위험**). 기본 off, `AI_RESPONSE_ANALYSIS=true` 일 때만.

AI는 결정적 룰 엔진의 판정을 **대체하지 않고 서술을 보강**하는 레이어다.

---

## 7. 새 검증 룰 추가 시 체크리스트

1. 어느 **검증 전략**(2장)에 속하는가? — 콘텐츠 시그니처면 마커/정규식만 추가, 그 외는 로직 필요.
2. **오탐 게이팅** 필요한가? — 정상 응답에 우연히 매칭될 수 있으면 힌트/응답형태로 제한.
3. **verdict/confidence** 를 3장 표의 기존 값과 일관되게 부여.
4. **안전 단정 가능**한 유형인가? — 콘텐츠 시그니처류만 "미노출=안전" 가능, 인젝션류는 "미확인".
5. `test_analyzer.py` 에 **positive + negative(오탐 방지)** 케이스 추가.
