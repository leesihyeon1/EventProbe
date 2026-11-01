# SIEM 다수 스캔 이벤트 지능형 트리아지 — 기능 제안서 (최종본)

> 대상 도구: EventProbe / SecAPITester (FastAPI + 바닐라 JS, 로컬 증거기반 보안 검증)
> 작성 근거: 현행 코드 직접 대조(약 20개 파일) + 설계 3종 종합 + 코드 대조 비평 반영.
> 모든 코드 근거는 `file:line`. 핵심 모듈 경로는 `backend/core/`(예: `classify.py` = `backend/core/classify.py`), 라우터는 `backend/routers/`(예: `api.py` = `backend/routers/api.py`), 프런트는 `frontend/static/js/`(예: `app.js`). 추측 구간은 "신규/미확정"으로 명시.
> **R4(실 SIEM 샘플) 입력이 없으므로 §3.2 벤더 매핑은 파서가 이미 토큰화하는 키에 근거한 추정치이며, 실 포맷 확정은 §8 열린 질문으로 분리한다.** status·action 값 어휘에 의존하는 결정(#1 일부·#2)은 샘플 확정을 선행조건으로 건다.

---

## 0. 배경 · 문제 정의

### 0.1 현행 "일괄 테스트" 탭이 실제로 하는 일 = URL 한 개 추출

보안 담당자가 `(index=waf OR index=ips OR index=ids) <IP·Domain>` 형태의 SIEM 덤프(수백~수천 줄)를 드롭하면, 현행 흐름은 다음과 같다.

```
드롭/선택 → readSplunkFile → fillMultiFromLog → extractUrlFromLogLine(줄별)
         → #multiUrls 텍스트영역에 "URL 문자열 목록"만 주입
         → runMultiTargetTest 가 그 텍스트영역을 다시 순수 텍스트로 재파싱
         → POST /api/multi-target-test → 들어온 URL 전부에 전수 재요청
```

- 진입: `handleSplunkDrop`/`handleSplunkPick`/`readSplunkFile` (`app.js:5346-5365`). `FileReader.readAsText` 후 `fillMultiFromLog(rd.result, file.name)` 호출(`:5360`)이 전부 — **로그는 서버로 가지 않고 전량 브라우저 로컬 파싱**.
- 파싱: `extractUrlFromLogLine` (`app.js:5391-5438`)은 모든 `key="value"`, CEF 확장부 `key=value`, IDS `layer_7_data` 내부 `NAME == VALUE ;;;` 까지 전부 `kv`/`inner`로 토큰화해 놓고(`:5394-5414`), **실제로는 host/path/query/port 4개만 읽어** URL 문자열 하나로 조립한다(`:5417-5423`). `host`나 `path`가 없으면 그 이벤트는 통째로 버린다(`if (!host || !path) return null;` `:5425`).
- 산출물: 중복제거·상한(1000) 적용한 URL 목록을 `#multiUrls`에 주입(`:5520-5525`) + 추천 파라미터명(`:5527-5536`). **그 외 이벤트 메타는 전부 소실**.
- 실행: `runMultiTargetTest`(`app.js:3861`)가 `#multiUrls`를 다시 `split('\n')`으로 읽어(`:3865`) 백엔드로 보내면, `multi_target_test`(`api.py:1968`)는 모든 `(url × payload)` 조합을 세마포어(동시 ≤30, `:1989`)로 **실제 재요청**하고, 결과를 **완전 일치 URL 문자열 기준**으로 재그룹핑한다(`by_url = {url: [] for url in urls}` `:2059-2061`, 엔드포인트 중복제거도 exact URL `:2076-2080`).

### 0.2 구조적 병목 — "텍스트영역 → URL 문자열" 경계

로그 임포트와 테스트 실행은 **오직 `#multiUrls` 텍스트영역을 통해서만** 연결된다. 이 UI 경계에서 모든 이벤트가 문자열 URL로 평탄화되므로, 설령 파서가 메타를 추출해도 흘러갈 경로 자체가 없다(`extractUrlFromLogLine`은 `:5459`·`:5513` 두 곳에서만, `fillMultiFromLog`은 `:5360` 한 곳에서만 호출 — 다른 소비자 부재).

### 0.3 "이미 파싱해 놓고 버리는" 바로 그 데이터

로그 판별 정규식이 `attack_name=`, `ruleName=`, `destination_ip=` 의 존재를 **명시적으로 참조**한다(`app.js:5510-5511`). 즉 코드가 이 필드들이 거기 있다는 걸 알면서도 추출·보존하지 않는다.

| 버려지는 정보 | 직결 결정포인트 | 근거 |
|---|---|---|
| 차단 여부 (action/blocked/deny/drop) | #1 | `kv`에 들어오나 미사용 (`:5417-5423`만 읽음) |
| 결과 코드 (http_status/status/rsp_code) | #2 | 미추출. 재요청 후에야 코드 획득(`api.py:2044`) |
| 공격명/시그니처 (attack_name/ruleName) | #3·#5·#7 | 판별 정규식에만 등장(`:5511`), 미추출 |
| 출발지 IP (src/source_ip) | #3·#7 | 미추출 |
| 목적지 호스트/IP (dst/destination_ip) | #3 | host 조립에만 쓰고 메타 미보존(`:5417-5419`) |
| 심각도 / UA / 타임스탬프 | #7·#3 | 미추출 |

### 0.4 결정포인트 대비 현행 공백 (사실 요약)

1. IPS block 구분 없음 — 차단 이벤트도 동일하게 재공격 대상.
2. 4xx/404 저우선 없음 — 대상에 쏜 뒤에야 코드를 앎(`api.py:2044`).
3. 이벤트 분류/그룹핑 없음 — 유일한 그룹 단위가 "완전 일치 URL"(`api.py:2059`,`:2076`). mass-scan 수백 경로가 전부 개별 URL.
4. 불필요 이벤트 필터 없음 — exact-URL 중복제거 + 1000 상한뿐(`app.js:5520-5522`).
5. 기존 classify 미연계 — 임포트 경로가 분류기와 연결 고리 없음.
6. 자산 대조 없음 — 존재·CDN·취약성 조회 로직이 임포트/실행 경로에 없음.
7. 스캐너 식별·캠페인 그룹핑·스코어링·오탐저감 없음 — 입력(UA·src·severity·공격명)을 버리므로 기반 자체가 없음.

**결론**: 현행은 "모르는 덤프에서 소수 선별"이 아니라 "들어온 전부에 전수 재요청"이다. 트리아지 계층이 전무하다.

---

## 1. 목표 · 범위

### 1.1 목표
- **노이즈 제거 후 "진짜 봐야 할 소수"만 남긴다.** 전수 재공격 → 필터·그룹·스코어 기반 선별검증으로 전환.
- **전량 로컬 트리아지.** 분석·판정·증거는 로컬. 외부 AI로는 내부 도메인·URL 원문·요청/응답 원문·헤더값·민감텍스트를 보내지 않는다(§6).
- **기존 인프라 최대 재사용.** `asset_shape` 조인키·`classify`·incident/verify 파이프라인·다상태 판정 가드를 **그 한계 안에서** 올라탄다(§4). (classify가 못 내는 유형, asset_shape가 못 접는 축은 §2·§4에 별도 규칙으로 보완.)
- **설명가능성.** 모든 저우선/필터/스코어 결정에 이유 태그를 붙이고 담당자 오버라이드를 허용(블랙박스 금지).

### 1.2 범위 (In)
- SIEM 로그(WAF/IPS/IDS) 구조화 파싱 → 정규화 이벤트 스키마.
- 7개 결정포인트 트리아지(필터·그룹핑·스코어링) — **읽기전용, 로컬**.
- 선별 이벤트 → 기존 사건(incident) 생성 → 능동 재검증(AI 0회) 핸드오프.
- 로그의 자산 인벤토리 적재(선택).

### 1.3 범위 밖 (Out / 비변경 경계)
- 외부 위협인텔/whois 등 도메인 반출 조회 금지(§6). → 그 귀결로 CDN/criticality는 외부조회로 못 채우고 **로컬 인벤토리 운영**으로만 해결(§2.5·§8.2).
- 트리아지 자체는 대상에 재요청하지 않음 — 재요청은 오직 명시 승인된 사건 재검증에서만(§5·§6.5).
- 내부망 대상 OOB는 자가호스팅 전제(§6.4).

---

## 2. 핵심 트리아지 설계 — 7개 결정포인트별 구체 규칙

설계 축은 **SOC 파이프라인**(수집→필터→그룹→스코어→검증→리포트)이며, 여기에 구조적 반출 차단·스코어링 공식·스캐너 UA·OOB 가드를 접목한다. 핵심 원칙: **삭제가 아니라 접힘(collapse)** — 분석가가 언제든 펼쳐 감사 가능(결정#4 "전체 정리").

> **설계 원칙 보정(비평 A3 반영): "미분류 = 저우선"이 아니다.** `classify`의 "넉넉히 분류해도 오탐이 늘지 않는다"는 성질(`classify.py:14-15`)은 **"분류가 틀려도 어차피 전부 테스트된다"**는 현행 전제에서만 성립한다. 트리아지는 반대로 classify 출력으로 이벤트를 **down-rank·접기(필터)** 하므로, classify의 **거짓음성(미분류)** 이 곧 "실제 공격을 저우선 버킷에 숨김"이 된다. 따라서 **`classify.primary`가 빈 값/카테고리 폴백인 이벤트는 저우선으로 접지 않고 REVIEW 후보(판정보류)로 올린다.**

### 2.1 의사결정 트리 (이벤트 1건 처리)

```
[로그 이벤트]
  │ host/path 없음 → DROP(파싱불가, 원문 보존)
  ▼
① ips_action ∈ {block, deny, drop, reset} ?   (1차 소스 = 로그 action 필드)
  │ 예 → [DROP버킷: "IPS 차단됨, 확인 불필요"]   (스코어 미산정)
  │ 모호(alert/빈값) → status 어휘로 보강 → 다음
  ▼
② status 코드?   (★ status 키/위치 샘플 확정 후에만 활성 — §3.2·§8.1)
  │ 404 또는 기타 4xx + 쿼리·본문 없는 GET  → [LOW버킷: "단순 미존재 스캔, 저우선"]
  │ is_direct_file_probe(url)=true 인 민감파일 직격:
  │     · 404 → [LOW버킷: "민존재 민감파일 스캔"]
  │     · 2xx → ★REVIEW 승격 ("민감파일 노출 가능")
  │ 401/403 → ★REVIEW 승격 (존재하는 보호 리소스 접근시도 = authbypass/IDOR 신호)
  │ 2xx/5xx(일반) → 다음
  ▼
⑥ asset_page(asset_id) 조회?   (asset_shape 성공 이벤트만 — host 복원 실패분은 §2.1 주)
  │ 공집합 → [LOW버킷: "인벤토리 미등록 대상"] (★'안전' 아님 — 신호로만)
  │ 로컬 인벤토리상 CDN 엣지 / criticality=low → 가중 ↓
  │ 인벤토리 존재 + criticality high → 가중 ↑
  ▼
⑤ classify(payload=path+query, headers) → {primary, subtype, header_borne, ambiguous}
  │ primary 비었거나 폴백 → ★REVIEW 후보(판정보류, 저우선 아님 — 비평 A3)
  ▼
③ 그룹핑: (dst_host, src_ip, classify.primary) 3축 클러스터 → 대표 1~3건만 승격
  ▼
⑦ 스코어링(그룹 단위, 0~100) + 스캐너 UA 교차검증 → 정렬
  ▼
[검증대상 버킷] → §5 선별 검증
```

> **host 복원 실패 주의(비평 B5):** `asset_shape`는 `map_request`가 유효 http(s) host를 넣어줄 때만 해시를 낸다(`agent_view.py:35` → host 없으면 url 미설정 → `asset_shape`가 `None` `agent_assets.py:12-13`). 즉 **host를 복원 못 한 로그 이벤트는 asset_id를 못 받아 ⑥ 자산 대조·M5 적재에서 빠진다.** 이 슬라이스는 "자산 미대조"로 명시 라벨하고 저우선으로 접지 않는다.

### 2.2 결정포인트별 구체 규칙 (표)

| # | 요구 | 구체 규칙 | 재사용/신규 근거 |
|---|---|---|---|
| **1** | IPS block 저우선 | **1차 소스 = 로그 `action` 필드.** `ips_action ∈ {block,deny,drop,reset,blocked}` → DROP버킷, 스코어 미산정. action 모호 시 status 어휘로 보강: `403/406/429/503/400`을 blocked 신호로 차용. **주의: analyzer의 차단판정 함수를 호출하지 않는다** — 그 함수들은 "도구가 보낸 요청의 응답"을 판정하며(§C2), `_body_signals_block`은 응답 바디가 필요해 로그에 적용 불가. **상태코드 상수·BLOCK 키워드 어휘만 차용.** | 어휘 차용: `_BLOCK_STATUS=(400,403,406,429,503)` `analyzer.py:174`, `_body_signals_block` `analyzer.py:177`, `4176-4185`(함수 호출 아님) |
| **2** | 4xx/404 저우선 | **`is_direct_file_probe` 의존 제거(비평 A1).** `classify.py:198` 정규식은 `.git/{config,HEAD,index}`·`.env`·`wp-config.php`·`web.config`·`.htaccess` **6종만** 매칭하고, 쿼리/본문/payload 불일치(`:194`)나 `..`·`\`(`:196`)면 False → `/phpmyadmin/`·`/wp-login.php`·`/backup.zip` 등 전형 mass-scan 경로는 전부 False. 따라서 404 저우선은 **"쿼리/본문 없는 GET + 4xx"라는 독립 규칙**으로 재정의. `is_direct_file_probe`=True는 오히려 **민감파일 직격**이므로 404→저우선, 2xx→REVIEW로 분기. **401/403은 REVIEW 승격.** ★이 규칙은 로그 `status` 키 확정(§8.1)을 선행조건으로 함. | `is_direct_file_probe` `classify.py:187-198`(6종 한정) |
| **3** | 다수 스캔 분류 | 1차=목적지 호스트(`dst_host`/`asset.origin`), 2차=소스IP 캠페인(`src_ip`), 3차=`classify.primary`. 그룹당 대표 N건만 승격, 나머지 "동일 그룹 N건" 뱃지. **수백 경로 mass-scan 접힘은 이 그룹핑 전담**(asset_shape 아님 — §2.2#4·비평 A4) | 현행 exact-URL 그룹(`api.py:2059`) → 다축 그룹으로 교체 |
| **4** | 정리·불필요 필터 | DROP/LOW/미등록 3버킷 기본 접힘, REVIEW만 펼침. **의미 dedup의 적용 범위 분리(비평 A4):** `asset_shape`는 쿼리 **값이 아닌 키**만 정렬·해시하므로(`agent_assets.py:16`) `?id=1`/`?id=UNION`은 **한 자산으로 접히지만**, `/a.php`·`/b.php`…수백 경로는 path가 달라 **전부 별개 자산**으로 남는다 → 다수경로 접힘은 §2.2#3 그룹핑이 담당. | `asset_shape` `agent_assets.py:10-22` |
| **5** | classify 재사용 | `classify()`를 그룹핑(③)·스코어(⑦)·검증유형(§5)에 재사용하되, **classify가 못 내는 유형은 별도 규칙으로 보완(비평 A2).** classify 실제 출력 primary는 `authbypass/cmdi(log4shell·shellshock·ognl 서브타입)/lfi/xss/ssti/ssrf/sqli/nosql/xmlrpc` + 카테고리 폴백뿐(`_RULES` `classify.py:142-157`). **`redirect`는 `_REDIRECT_HINT`(`classify.py:56`)가 `_RULES`에 연결 안 돼 死코드 — 현재 미출력.** `idor/access/jwt/xxe/auth`도 미출력. host 제외(비식별, `classify.py:213-217`). | `classify.py:209-247`, `_RULES:142-157`, `_REDIRECT_HINT`(死코드) `:56` |
| **6** | 자산 대조 필터 | `asset_page(asset_id)` 공집합 → "미등록 대상"(LOW, ★신호로만). CDN/criticality는 **로그만으론 산출 불가(비평 C1)** — `detect_stack`(`analyzer.py:145`)은 응답 헤더에 작동하는데 SIEM 로그엔 응답 헤더가 없음. → **사전 적재된 로컬 인벤토리 필드에서만 읽음**(신규, §2.5·§8.2). | `Store.asset_page` `agent_store.py:326-417`; 스키마 공백 `agent_store.py:66-68` |
| **7** | 스캐너·캠페인·스코어·오탐 | §2.3 스코어 공식(로그단독 산출가능 요소 우선) + 스캐너 UA 교차검증 + 분산 스캔 플래그 + ambiguous/단일신호 감점 | §2.3 참조 |

### 2.3 우선순위 스코어링 공식 (결정#7, 그룹 단위 0~100)

**입력 가용성이 요소마다 다르다(비평 H1).** MVP 스코어러는 **로그 단독 산출 가능한 요소만** 쓰고, 백엔드/인벤토리 선행이 필요한 요소는 M3+로 미룬다.

| 요소 | 방향 | 산출 | 입력 가용성 | 근거/재사용 |
|---|---|---|---|---|
| **BLOCK** | ↓ | action=block/status=blocked → ~0 | **로그 단독(M1)** | 어휘 `analyzer.py:174` |
| **CODE** | 중립/↓ | **4xx=저, 404=최저, 5xx=중.** ★**2xx는 가점하지 않고 "검증 ROI 중립"**(비평 D2): WAF 로그의 2xx는 "오리진 통과"일 뿐 공격성공이 아님 — 성공은 오라클(재검증)에서만 확정 | **로그 단독(status 키 확정 후, M1~)** | §C2·§D2 |
| **SCAN** | ↓ | 스캐너 UA면 개별 이벤트 감점(노이즈), 캠페인 레벨로 승격 | **로그 단독(M3, UA DB)** | §2.4 |
| **AMBIG** | ↓ | `classify.ambiguous`(서로 다른 유형 2+ 매칭, `classify.py:126-129`) 또는 단일신호 → 감점 | **로그 단독(M2)** | `classify.ambiguous` |
| **RATE** | ↑ | 시간윈도우 버스트/집중도 | **로그 단독(`ts` 집계, M3)** | `ts` |
| ASSET | ↑ | 인벤토리 존재=↑, 미존재=↓, CDN/비취약 스택=↓ | **인벤토리 선행(M3)** — 로그만으론 스택 불가(§C1) | `asset_page` + 로컬 인벤토리 |
| SEV | ↑ | 로그 severity 정규화(§3.2 severity 어휘 열로 벤더별 매핑) | **로그 단독이나 벤더 척도 매핑 필요(M3, §D3)** | §3.2 |
| TYPE | ↑ | classify.primary 위험도(rce/sqli/ssrf 고 > 파일스캔 저) | **로그 단독(M2)** | `classify.py:142-157` |
| CONFIRMABLE | ↑ | `confirm.is_supported(primary)`=자동확증 가능 → 검증 ROI↑. **단 authbypass/xmlrpc면 False라 가점 0**(비평 D4) | **백엔드 조회(M3)** | `confirm.py:137`, `SUPPORTED:41` |
| PRIOR | ↑ | 과거 동일 asset_id에 확정 발견 존재 → 재확인 가치↑. **★전용 조회 헬퍼 현재 없음** — `finding_index`에 asset_id·verdict 컬럼은 있으나(`agent_indexes.py:88-94`) "asset_id별 확정발견" 쿼리 신설 필요(M3) | **신규 쿼리 선행(M3)** | `agent_indexes.py:88-94` |

**버킷 컷오프·규칙 결합(비평 D1) — 수치 고정:**

- 가중합 `S = Σ(weight_i × factor_i)`, 각 factor 0~1로 정규화, 가중치는 `data/triage_weights.json`로 외부화.
- **컷오프:** `S ≥ 60` → 검증대상(REVIEW), `30 ≤ S < 60` → 저우선(LOW), `S < 30` → 확인불필요(접힘).
- **하드규칙이 가중합보다 우선(규칙 먼저 평가 후 가중합):**
  - `action=block` → DROP버킷 즉시(스코어 미산정).
  - `action=block` AND `status=404` AND 스캐너UA → **하드 저우선**("검증 불요").
  - `status=2xx` AND primary∈{rce,sqli,ssrf,cmdi} AND 인벤토리 자산존재 → **하드 REVIEW**.
  - `classify.primary` 빈값/폴백 → **하드 REVIEW 후보**(비평 A3, 저우선 금지).

```jsonc
// data/triage_weights.json  (예시 스키마 — MVP 활성 요소만)
{
  "weights": { "block": -1.0, "code": 0.15, "scan": -0.25, "ambig": -0.10, "rate": 0.15 },
  "deferred": { "asset": 0.20, "sev": 0.15, "type": 0.25, "confirmable": 0.10, "prior": 0.15 },
  "cutoffs": { "review": 60, "low": 30 }
}
// 예: status=403(code≈0.2), 스캐너UA(scan=1), 단일신호(ambig=1), rate=0.1
//   S = 100×(0.15×0.2 − 0.25×1 − 0.10×1 − (block=0) + 0.15×0.1) ≈ 음수 → 확인불필요
```

### 2.4 스캐너·봇 UA 식별 (신규 — 현재 전무)

스캐너 UA 지문 DB가 레포에 없다(`tools/import_nuclei.py`는 템플릿 임포터, UA 탐지 아님; `user-agent`는 `public_shape.py:30`에 허용 헤더 이름으로만 등장). → **신규 로컬 데이터파일 `data/scanner_ua.json`**.

- **자동 스캐너/툴**: `sqlmap, nikto, nuclei, acunetix, nessus, zgrab, masscan, python-requests, curl, Go-http-client` → 스캐너 플래그 ON.
- **정상 크롤러**: `Googlebot, bingbot` → 저우선 정찰.
- **브라우저형 UA** → 중립.
- **교차검증**: UA는 위조 가능하므로 단일 신호로 확정 금지 — `attack_name`·레이트·status와 교차(단일신호 오탐 방지).

### 2.5 "검증해도 의미없는" 자동 필터 → '검증 불필요' 버킷

**다상태 준수(메모리 three-state-verdict):** 아래는 '안전' 판정이 **아니라** '검증 불요(저가치)' 버킷이다. 각 항목에 이유 태그를 단다.

1. IPS 이미 차단(#1, 로그 action 기준) / 2. 4xx 단순 스캔(#2, status 키 확정 후) / 3. 자산 미존재(#6, `asset_page` 공집합 — 단 host 복원 성공분에 한함) / 4. **CDN 엣지 또는 비해당 스택** — ★**로그만으론 판정 불가(비평 C1)**, 사전 적재 인벤토리에 CDN/스택 필드가 있을 때만 적용(없으면 중립) / 5. 정상 크롤러 / 6. classify 결과 없음은 **저우선이 아니라 REVIEW 후보**(비평 A3) / 7. 미도달·무의미는 '안전'이 아니라 '판정불가'로 큐잉.

---

## 3. 정규화 이벤트 스키마 + 벤더 로그 파싱 확장

### 3.1 정규화 이벤트 스키마 (`LogEvent`)

`extractUrlFromLogLine`을 URL 문자열이 아닌 **구조화 레코드** 반환형으로 확장한다. 파서가 이미 `kv`/`inner`로 전 필드를 토큰화하므로(`app.js:5394-5414`) 추출부만 추가하면 된다.

```
LogEvent = {
  url, method, src_ip, dst_host, dst_ip, port,
  ips_action,        // block/allow/drop/deny/alert  ← 결정#1
  http_status,       // 404 등                        ← 결정#2
  severity, attack_name, rule_name, signature,       // ← 결정#3·5·7
  user_agent, ts,                                     // ← 결정#7·3
  raw_offset         // 원문 오프셋 — raw는 로컬에만, 서버 전송 금지
}
```

- `host`/`path` 없는 줄만 drop(`:5425` 유지), 나머지는 전부 레코드 보존.
- **생성 시 위생처리(비평 G2):** `attack_name`·`user_agent` 등 공격자 제어 문자열은 **정규식 열거만**(eval·동적실행 금지), **길이 상한(80자, `classify`가 이미 `group(0)[:80]` `classify.py:225`)** 및 **제어문자 제거**를 LogEvent 생성 시 적용.

### 3.2 파서 토크나이저 강화 (★선행작업 — 트리아지가 의존할 필드부터 깨짐, 비평 E1)

현 토크나이저는 트리아지가 신뢰할 필드를 손상시킨다. action/status/attack_name 추출 신뢰 전에 아래를 M0/M1 선행으로 강화한다.

- (a) kv 정규식 `(\w+)="([^"]*)"`(`app.js:5394`)은 **이스케이프 따옴표**를 못 다룸 → 따옴표 포함 `attack_name`/`signature` 손상.
- (b) IDS inner 파서는 `==`로 분리(`app.js:5411-5412`)하는데 **base64 패딩 `==`** 가 흔한 payload 필드를 오분할.
- (c) CEF 확장 `(\w+)=(.*?)(?=\s+\w+=|$)`(`:5402`)는 값 내부의 ` word=` 에서 잘림.

### 3.3 JSON/NDJSON SIEM export 지원 (신규 — 비평 E2)

`fillMultiFromLog`(`app.js:5440-5517`)는 CSV와 줄단위 kv/CEF만 처리하고, **JSON 라인은 "단순 URL 목록"(`:5515`)으로 새어 아무것도 못 뽑는다.** 현대 SIEM의 JSON export(한 줄 = 한 JSON 이벤트)를 LogEvent로 직접 승격하는 파서를 추가한다(§8에 포맷 확정 항목으로 유지).

### 3.4 벤더 로그 필드 매핑 (★ 실 키명·값 어휘는 §8에서 샘플로 확정 — R4 null)

파서가 이미 참조/토큰화하는 키를 근거로 한 **추정 매핑**. **각 셀은 R4 null 상태의 추정치이며, #1/#2가 의존하는 `action`/`status`의 값 어휘(block vs deny vs drop / status 위치)는 샘플 확정 전 하드코딩 금지(§8.1 선행조건).**

| 정규화 필드 | IPS CEF (TippingPoint 류) | WAF Imperva (`key="value"`) | IDS syslog (`layer_7_data`) |
|---|---|---|---|
| `ips_action` | `act`, `deviceAction`, CEF deny/drop/block | `action`, `disposition` | `action` |
| `http_status` | `cs*`(커스텀) | `http_status`, `rsp_code`, `sc` | `inner["HTTP Status"]` |
| `attack_name`/`rule` | `cs1`/`cs2`, `name`, `signature` | `attack_name`, `ruleName` (`app.js:5511` 참조) | `attack_name`, `NAME` |
| `src_ip` | `src`, `shost` | `src`, `source_ip` | `src` |
| `dst_host`/`dst_ip` | `dst`, `dhost`, `destination_ip` | `httpHost`, `dest_host` | `inner["HTTP Host"]` |
| `host` (URL) | `dhost` | `httpHost`/`host`/`hostname` (`:5417-5419`) | `inner["HTTP Host"]` |
| `path`/`query` | `request`, `requestMethod` | `url`/`uri`/`request_uri`, `webQuery` (`:5420-5422`) | `inner["HTTP URI"]` |
| `port` | `dpt` | `dport`, `destination_port` (`:5423`) | `dpt` |
| `severity` **(값 어휘)** | `severity`(0~10 숫자 흔함) | `severity`,`sev`(High/Med/Low) | `severity`(1~4 등) → **벤더별 정규화 표 필요(§D3)** |
| `user_agent` | `requestClientApplication` | `http_user_agent` | `inner["User-Agent"]` |
| `ts` | `rt` | `_time`, `timestamp` | syslog 헤더 타임스탬프 |

- CSV(Splunk `_raw`) 경로도 동일 — 줄파서 재사용(`:5457-5460`) 후 LogEvent로 승격.
- 파싱실패 줄은 **추측으로 채우지 않고** "원문 보기"로 접음(판정불가 원칙).

---

## 4. 아키텍처 · 재사용 — 트리아지→선별→사건→검증 파이프라인

### 4.1 린치핀: `asset_shape()` 단일 조인키 (한계 포함)

트리아지의 "자산/사건/트래픽 연결"은 하나의 결정적 해시로 돈다. `asset_shape(request)` = `sha256(json([origin, method, path, sorted(query_keys)]))` — **값·상태코드·헤더 미포함 비식별 구조키**(`agent_assets.py:10-22`). bulk 적재 경로 `_record_traffic_batch`(`api.py:1108`, bulk 호출부 `api.py:1961-1963`)가 이미 `{url,method,params}` dict 모양으로 이 shape를 돈다 → 서버에서 로그 레코드에 즉시 asset_id 부여 가능.

> **한계(비평 B5):** `asset_shape`는 `map_request`가 유효 http(s) host를 넣어줄 때만 작동한다(`agent_view.py:35`: scheme이 http(s) 아니거나 hostname 없으면 url 미설정 → `asset_shape`가 `None` `agent_assets.py:12-13`). **host 복원에 실패한 로그는 asset_id를 못 받아** 자산 조인·M5 적재 대상에서 빠진다. 동일 키가 다섯 테이블에 공통(assets/asset_refs/traffic_index/manual_traffic/finding_index)이나, 이 조인 이득은 **host 복원 성공 슬라이스에 한정**된다.

### 4.2 파이프라인 (기존 조각 연결)

```
[1 파싱 확장]  app.js:5391-5438 → LogEvent[] (§3)  ── #multiUrls 우회
      ▼ (구조화 레코드 직접 전송, 텍스트영역 안 거침)
[2 POST /api/triage/analyze] (신규, 로컬 전용, 모델 0회)
   이벤트당:
     asset_shape({url,method,params})          → asset_id   agent_assets.py:10 (host 없으면 None)
     classify(payload=path+query, headers)     → 유형        classify.py:209 (미출력 유형은 별도규칙 §4.3)
     asset_page(asset_id) / lookup_page(...)   → 존재·상태  agent_store.py:326,419
     경량 선필터/스코어/그룹핑(신규, §2)
   반환: {buckets:{확인불필요,저우선,REVIEW}, groups[], score}
      ▼
[3 적재(선택)] record_manual_traffic_batch([(req,status,'siem')]) → 인벤토리 편입 (asset_shape 성공분만)
      ▼ (뷰에서 "REVIEW" 선택)
[4 사건 생성] IncidentEvent 조립(category=매핑표 §4.3) → POST /api/agent/incidents
      ▼
[5 재검증] POST /api/agent/incidents/{id}/verify
   → verify_incident: max_ai_calls=0 + approved_plan 고정   agent.py:1053-1086
   → access 유형은 _verify_access_incident 분기             agent.py:1088-1125
      ▼
[6 판정 읽기] GET /api/agent/incidents/{id} → incident_trace
   → 6상태 가드: unverified/verifying/inconclusive/reproduced/suspicious/not_reproduced
                                                            agent_incidents.py:65-79
   → asset_trace 로 교차 계보                                agent_incidents.py:103-142
```

> **상태 열거 정정(비평 B4):** `agent_incidents.py:65-79`는 **6상태**다 — `unverified/verifying/inconclusive/reproduced/suspicious/not_reproduced`. "취약"에 해당하는 상태는 `reproduced`(`:72-73`)이며, **"안전" 상태는 존재하지 않는다**(`:77` `not_reproduced`도 "대상 전체의 안전/해결을 의미하지 않음"이라 명시). 트리아지 UI는 이 6상태를 그대로 노출한다.

### 4.3 classify → IncidentEvent.category 매핑표 (신규 — 간극 해소)

`IncidentEvent.category` Literal = `{sqli,auth,xss,ssti,lfi,ssrf,cmdi,redirect,nosql,access}`(`agent_models.py:64`). **classify가 내는 primary와 Literal 사이에 간극이 있어 매핑+보완이 필요하다(비평 A2).**

| 원천 | 판별 소스 | → IncidentEvent | 자동 재검증 | 근거 |
|---|---|---|---|---|
| sqli/xss/lfi/ssti/ssrf/cmdi/nosql | classify.primary | 동일 | 가능(쿼리 param 복원 시) | `_ALLOWED_PLAN_CATEGORIES` `agent.py:440` |
| log4shell/shellshock/ognl | classify subtype(cmdi) | cmdi | 가능 | cmdi 경로 |
| **redirect** | **classify 미출력(`_REDIRECT_HINT` 死코드)** | redirect | 조건부 | ★출력하려면 `_REDIRECT_HINT`를 `_RULES`에 **추가하는 작업을 M-단계에 포함**(아니면 §2.3 TYPE·이 행에서 redirect 제외) |
| authbypass(middleware) | classify.primary(헤더전용) | auth (param 有) / 없으면 사건만·수동 | 조건부 | verify는 req.url+param 필요 `agent.py:1067-1073` |
| **access/IDOR** | **classify 미출력** → **별도 로그 휴리스틱**(`status 401/403` + 경로 ID 패턴) | access | owner/intruder identity 입력 시 | `_verify_access_incident` `agent.py:1088-1125` (신규 휴리스틱) |
| **jwt/xxe** | **classify 미출력** | (해당 없음/수동) | 불가 | 별도 규칙 또는 수동 |
| xmlrpc | classify.primary | 드롭 또는 트리아지 전용 | 불가 | Literal에 없음 |

주의: `authbypass`(헤더 전용)·`xmlrpc`는 주입 param이 없어 자동 재검증 입력을 못 만듦 → "사건 생성은 하되 수동 확인" 라벨. `title`은 `min_length=1`(`agent_models.py:65`)이라 로컬 기본 제목 생성 필요.

### 4.4 재사용 vs 신규 경계 (구현 범위)

**그대로 재사용 (추가 거의 0):**
- `asset_shape`(조인/dedup키 `agent_assets.py:10`, host 없으면 None), `asset_page`/`lookup_page`(존재·상태 `agent_store.py:326,419`)
- `classify()`(유형분류, 비식별 `classify.py:209`) — **단 미출력 유형(redirect·idor·jwt·xxe)은 §4.3 별도 규칙 필요**
- `confirm.SUPPORTED`/`is_supported`(`confirm.py:41,137`)
- tier-1 detector 중 요청구조만으로 판정(JWT alg:none `detectors.py:390`, 미들웨어 authbypass `:458`, 역직렬화 매직바이트 `:946`, 위험 업로드 `:994`)
- `create_incident`/`incident_trace`/`asset_trace`/`verify_incident`(AI 0회 `agent.py:1053-1143`), 6상태 가드(`agent_incidents.py:65-79`)
- `record_manual_traffic_batch`+`_record_traffic_batch`(`agent_store.py:544`,`api.py:1108`), 소유권 스코프(`_principal`/`_incident_guard`)

**신규 필요 (전부 로컬):**
1. 파서 토크나이저 강화(이스케이프·`=`값·base64, §3.2) + JSON/NDJSON 파서(§3.3) + 구조화 반환(`app.js:5391-5525`, LogEvent §3.1)
2. `POST /api/triage/analyze` + 버킷/그룹/스코어 레이어(결정#1~4,7, 읽기전용)
3. 자산 criticality/CDN **로컬 인벤토리** — 스키마에 없음(`agent_store.py:66-68`), 로그·외부조회로 불가(§C1·§H2) → 소량 CSV 수기 관리
4. classify→IncidentEvent category 매핑표 + **미출력 유형 보완 규칙**(§4.3): redirect(`_REDIRECT_HINT`를 `_RULES`에 연결) / access(401·403+경로ID 휴리스틱)
5. 로그→IncidentEvent `request`/`location`/`param` 복원(자동 재검증 입력) — **쿼리파라미터 공격에 한정**(§I2)
6. traffic source enum에 `'siem'` 추가 — **세 곳이 서로 다른 열거라 단일소스 아님**(비평 K): write `agent_store.py:549`(`{manual,bulk,raw,multi}`), read `routers/agent_history.py:39`(`{agent,browser,manual,bulk,raw,multi}`), label `global_lookup.js:5-6`. → **한 곳 상수화 권고.**
7. 스캐너 UA DB(`data/scanner_ua.json`) + 스코어 가중(`data/triage_weights.json`)
8. PRIOR용 "asset_id별 확정 발견" 조회 신설(`finding_index`에 컬럼은 있음 `agent_indexes.py:88-94`, 쿼리 없음 §D4)
9. **드리프트 방지(인용 정정, 비평 B1·B2):**
   - `_CONFIRM_SCAN`은 `analyzer.py:25`(`_CONFIRM_SUPPORTED | {"authbypass"}`)에 정의되며 `confirm.SUPPORTED`(=`categories.CONFIRMABLE`) 파생 → **이미 단일 소스라 "categories.py 이동" 대상 아님.**
   - `_OOB_FAMILIES`/`_BROWSER_FAMILIES`/`_UNDETERMINED_NEXT`/`_undetermined_next`는 `analyzer.py:4018-4053`에 비공개. 이들의 `email`·`deserial`·`domclob`·`cssinj`·`csti`는 `categories.py` 레지스트리 `_R`에 **없는 카테고리**다 → "categories.py로 이동"은 단순 이동이 아니라 **레지스트리 신규 항목 + 필드(oob/browser) 추가**임을 로드맵에 명시(M0).
   - 이들 재사용 시 `import analyzer`가 impact/baseline/test_validity 전체 체인을 로드하므로, 블록/스택 판정은 경량 모듈로 추출 권장.

---

## 5. 통합 vs 별도 탭 — **별도 "로그 트리아지" 탭 권고** (결론)

**결론: 별도 탭.** 임포트 진입만 공유하고, 임포트 직후 "일괄 테스트에 넣기" vs "트리아지 분석"으로 분기한다. (절충안: 일괄 탭 내 하위모드 토글도 가능하나, 입력 파이프라인을 어차피 분기해야 하므로 별도 탭이 깔끔.)

**근거 (주논거를 워크플로·안전으로 재배치 — 비평 F1):**

1. **[주] 워크플로 역전.** 일괄테스트 = "아는 대상에 전수 공격"(공격-우선, 현행이 바로 전수 재요청 `api.py:1989`). 트리아지 = "모르는 덤프에서 소수 선별 후 검증"(필터-우선). 한 화면에 섞으면 트리아지 맥락에서 "전부 쏘기"를 오클릭할 위험.
2. **[주] 승인 게이트 보존.** 트리아지는 읽기전용 로컬(classify/asset_page/scorer)이고 실제 재요청은 오직 사건 "재검증" 버튼(`verify_incident`)에서만 발생. 별도 탭이 이 경계를 UI로 드러내 우발적 대량 재전송을 차단.
3. **[주] 자연스러운 종착지.** 트리아지 산출의 종착지는 이미 별도 surface인 사건(incident) 뷰다. 트리아지는 임포트↔사건 사이의 얇은 브리지로서, 별도 탭일 때 각 화면이 단일 책임 유지.
4. **[보조] 데이터 모델 차이.** 일괄/다중 입력은 URL 문자열(`app.js:3865`)이고 백엔드 모델(`BulkRequest`/`MultiTargetRequest` `api.py:129-160`)에 메타필드가 없다. 트리아지는 구조화 이벤트 레코드가 입력이다. (단 이는 새 LogEvent 모델을 스스로 신설해 생기는 차이이므로 **보조 논거**로 둔다.)
5. **[보조] 파괴적 변경 회피.** 일괄 탭의 "소수 URL 빠른 페이로드 테스트" 용도를 그대로 보존.

**필수 리팩터(비평 F2):** "임포트 진입만 공유"하려면 현재 `fillMultiFromLog`를 **무조건 호출(`app.js:5360`)** 하는 `readSplunkFile`(`:5357-5365`)을 **분기점으로 리팩터**해야 한다("일괄 넣기" vs "트리아지 분석"). 현재 분기 지점 없음 → §7 M0에 명시 변경항목으로 포함.

**엔진은 공유:** 탭은 분리하되 §4 재검증은 기존 incident/verify 파이프라인과 `_record_traffic_batch`를 공유 — 중복 구현 없음.

**연결 고리:** 트리아지에서 선별한 대표샘플만 "일괄테스트로 넘기기"(URL+param 프리필) 또는 "사건으로 승격→재검증". 전수가 아니라 선별분만.

---

## 6. 데이터 경계 · 안전 가드 준수

### 6.1 반출 경로 "구조적 부재" + 데이터 흐름 확장 명시 (비평 G1)

외부 AI로 나가는 경로는 코드상 단 2곳(`ai_analyzer._post_chat`, `rag._embed_batch`)뿐이고 그 위에 `ai_egress.guard()`가 강제 관문으로 앉아 있다(`ai_egress.py:3-7,318-339`). **트리아지 코어(`classify`/`asset_shape`/`public_shape`/`asset_page`/스코어러)는 이 두 chokepoint를 호출하지 않으므로 설계상 반출이 0.**

> **흐름 확장 명시:** 현행 로그는 100% 브라우저 로컬(`app.js:5346-5365`, 서버 미전송)이지만, §4.2[2]는 LogEvent[](내부 host/url/attack_name/UA 포함)를 `/api/triage/analyze`로 POST한다 → "브라우저 밖으로 안 나감"에서 "**localhost 백엔드로 감**"으로 데이터 흐름이 넓어진다. 따라서:
> - (a) 신규 엔드포인트는 raw 필드(dst_host/url/attack_name/UA)를 **`asset_shape`(비식별) 외로 영속화 금지**.
> - (b) LogEvent의 dst_host/url/attack_name/UA는 **ai_* 경로 부적격**으로 못박고, 혹시라도 AI 경로에 쓸 경우 **`public_shape` 변환 필수**(§6.1은 "현재 호출 안 함"만 보장하므로 장래 금지를 명문화).

### 6.2 보내야 한다면 — 3중 가드
1. **비식별 구조만**: `public_shape.build()`가 host 제거·경로 템플릿화(`/api/orders/{id}`)·쿼리/바디는 이름+타입만·페이로드는 열거 코드(`sqli-quote` 등 `_SIGNAL_RULES` `public_shape.py:53-68`)로 변환. 원문 값·도메인 미포함(`:1-14,291-313`).
2. **강제 관문**: `ai_egress.guard(payload, channel, destination_url)` — strict(기본 fail-closed `:39-43`)에서 block 등급 토큰(쿠키/authz/JWT/AWS키/등록 카나리) 있으면 `EgressBlocked`(`:329-334`). 대상 호스트는 실행 시 `register_canary(host)`로 등록(`:113-119`). 이 경계는 UI로 못 끔(`:6-7`).
3. `asset_shape`는 값·헤더·상태 미포함 구조해시(`agent_assets.py:20`), `classify`는 host 제외 로컬 정규식(`classify.py:213-217`).

### 6.3 로컬 전용 재검증
`verify_incident`는 `max_ai_calls:0` + `approved_plan` 고정(`agent.py:1084-1085`) → 사건 본문이 모델 문맥에 안 들어감(`agent_models.py:56-58`). 재검증 유형 화이트리스트 밖이면 거부(`agent.py:1064`, `_ALLOWED_PLAN_CATEGORIES` `:440`).

### 6.4 내부망 OOB — 자가호스팅 강제
blind 계열(cmdi/ssrf/log4shell)은 OOB 콜백 필요. interactsh self-host 지원이 이미 존재(`oob.py:1-15`, `.env` OOB_SERVER/OOB_DOMAIN).
- `target_is_internal(url)` RFC1918/loopback/내부TLD 판별(`oob.py:261-270`), `leak_warning`(`:250-278`), `minting_allowed`(strict에서 공개 OOB 콜백 발급 금지 `:281-293`).
- **트리아지 규칙**: 내부 자산 blind 유형은 "OOB 필요" 라벨. 사내 self-host 없으면 재전송을 막지 않고 **'판정불가'로 큐잉** + "사내 interactsh 설정 필요" 안내('안전' 아님).

### 6.5 재전송 안전가드
- 트리아지 산출물 = 검증 대기 큐(재전송 0). 실제 재전송은 사건 재검증 경로로만, **기본 OFF / 명시 승인**.
- 범위 하드리밋: `max_requests ≤ 150`, `max_steps=2`, `max_seconds=120`(`agent.py:1084`). 동시 재검증 2개 상한(`routers/agent.py:342`), `_incident_guard` 소유자 스코프(`:273-281`).
- **중복 사건 억제(설계 정정 — 비평 B3):** `incidents_for_asset`(`agent_store.py:936-947`)는 **asset_id(+owner)로만** 조회하고 **type·src/24·open 필터가 없으며**, `IncidentEvent` 모델에 **src 필드 자체가 없다**(`agent_models.py:55-69`). 따라서 "(asset,type,src/24) 열린 사건 억제"는 이 함수로 충족 불가. → **재설계**: (i) `asset_id`로 조회 후 **클라이언트측 type 필터 + `incident_trace` status로 open 판별**, 또는 (ii) src/24·type를 incident 레코드에 저장하고 **전용 쿼리 신설**(M4 범위).
- **대량 승인 방지**: "캠페인 전체 재검증"은 캠페인당 상한 + 요약 확인 화면 경유.

### 6.6 메모리 규칙 준수
- **three-state-verdict**: "자산 미존재"는 `asset_page` 공집합일 때 **신호로만**, '안전'으로 강등 금지(신규 자산은 정상적으로 미등록 가능). 저우선 버킷 ≠ 안전 판정. 어떤 트리아지 산출도 '안전'을 수립하지 않는다.
- **no-icons-on-features**: 신규 탭/버튼/헤더는 텍스트 라벨만(이모지 금지).
- **로그 신뢰경계**: `attack_name`/UA 등 로그값은 **데이터**다. 판정에 쓰되 명령으로 해석 금지(인젝션된 로그 필드 방어) — 정규식 열거만, eval 금지, 길이 상한·제어문자 제거(§3.1).

---

## 7. 단계적 구현 로드맵 (MVP → 확장)

각 단계 독립 배포 가능. **M1의 "즉각 가치"는 로그단독·키확정 요소로 재범위화(비평 I1·C3):** status 키 미확정(#2)·CDN/criticality 부재·스택 로그불가(#6)에 의존하는 부분은 뒤로 미룬다.

| 단계 | 범위 | 산출물 | 핵심 파일 |
|---|---|---|---|
| **M0 전제** | 토크나이저 강화 + `readSplunkFile` 분기 + source enum 상수화 + `_OOB/_BROWSER_FAMILIES`·`_undetermined_next` 공개(레지스트리 신규항목+필드 추가) | 이스케이프/`=`값/base64 대응, 분기점, `'siem'` 추가, 경량 모듈 추출 | `app.js:5346-5365,5394-5412`, `agent_store.py:549`, `routers/agent_history.py:39`, `global_lookup.js:5-6`, `analyzer.py:4018-4053` |
| **M1 (MVP) 파싱+필터** | LogEvent 구조화 반환 + 서버 트리아지 필터. **실산출 = #1(로그 action)+#4(의미dedup/접힘)+#6-부분(asset_page 존재여부만)**. #2(4xx)는 **status 키 샘플 확정(§8.1) 이후** 활성 | `extractUrlFromLogLine` 확장, `POST /api/triage/analyze`(필터만), 3버킷 뷰(접힘/펼침, 이유 태그) | `app.js:5391-5525` |
| **M2 그룹핑+classify** | 3축 그룹핑(결정#3, 수백경로 접힘 담당) + `classify()` 연계(결정#5) + classify **미출력 유형 보완**(redirect를 `_RULES`에 연결 / access 휴리스틱) + 민감파일 404↔2xx 분기 | 캠페인 카드, header_borne 배지, 대표샘플 선정, REVIEW-후보(미분류) 승격 | `classify.py:142-157,187,209`, `agent_assets.py:10` |
| **M3 스코어링+스캐너+인벤토리** | 스코어 공식(로그단독 요소 먼저, 지연요소 합류) + 스캐너 UA DB + CDN/criticality **로컬 CSV 인벤토리**(유지주체·주기 정의) + PRIOR 조회 신설 + SEV 벤더 정규화표 | `data/scanner_ua.json`, `data/triage_weights.json`, 스코어 기여요인 칩, CSV 임포트, finding 조회 헬퍼 | `asset_page`, `agent_indexes.py:88-94`, §2.3 |
| **M4 검증 핸드오프** | classify→IncidentEvent 매핑 + request/location/param 복원 + 사건 생성/재검증 연결 + 중복억제 재설계(§6.5). **자동검증 = 쿼리파라미터 주입 부분집합만**(sqli/xss/lfi/redirect); body/header 공격(특히 authbypass·xmlrpc)은 AgentRequest 복원 불가 → 수동 라벨(비평 I2) | `/incidents/batch`(thin), 승인 모달, run 결과 6상태 표시, 중복억제 쿼리 | `agent.py:1053-1125`, `agent_models.py:55-77` |
| **M5 리포트+적재** | `record_manual_traffic_batch(source='siem')` 적재(**asset_shape 성공분만** — host 복원 실패·파싱실패 제외, 비평 I3) + 트리아지 요약 리포트 + asset_trace 연결 | 누적 학습(성공 슬라이스 한정), **다상태 요약: 취약(reproduced)/판정불가/저우선-미검증(안전 아님)** | `agent_store.py:544`, `agent_incidents.py:103` |

> **M5 요약 라벨 정정(비평 J1):** 초안의 "3상태 요약(취약/**판정불가**/**안전**)"에서 **'안전'을 삭제**한다. 트리아지는 어떤 이벤트에도 '안전'을 수립할 근거가 없다(§2.5·§6.6, `agent_incidents.py:77` not_reproduced도 "안전 아님"). → **"취약(reproduced) / 판정불가(inconclusive·OOB대기) / 저우선-미검증"** 으로 교체.

M0+M1만으로도 "차단·의미중복·미등록 노이즈 접힘"이라는 즉각적 가치를 제공한다(4xx 저우선은 샘플 확정 후).

---

## 8. 리스크 · 열린 질문

1. **[최우선 미확정] 실 SIEM 샘플 부재(R4 null).** 레포에 SIEM 샘플 없음(`docs/raw_packets/*.txt`는 HTTP 패킷). §3.4 벤더 필드 매핑의 **실 키명과 값 어휘(block vs deny vs drop, status 위치·어휘, severity 척도)는 Imperva WAF / TippingPoint CEF / IDS syslog 샘플 1~2건으로 확정 필요** — M1의 #2(4xx) 활성 전 선행조건. 잘못 매핑하면 결정#1·#2 오탐. **추가로 JSON/NDJSON export 포맷(§3.3)도 샘플로 확정.**
2. **자산 criticality/CDN 소스 = 운영데이터 확보 프로젝트(비평 H2).** 스키마에 컬럼 없음(`agent_store.py:66-68`)이고 **외부조회 금지 경계상 whois/위협인텔 질의 불가** → 코드가 아니라 **소량 CSV 수기 관리 + 유지주체/주기 정의**로 현실화. 로그만으론 스택 판정 불가(응답 헤더 없음, §C1).
3. **classify 어휘 간극(비평 A2).** redirect는 `_RULES` 연결 전까지 미출력(死코드 `classify.py:56`); access/idor/jwt/xxe도 미출력 → 별도 로그 휴리스틱 필요. xmlrpc·authbypass(헤더전용)는 자동 재검증 입력(param) 불가 → "수동 확인" 정책 필요(§4.3).
4. **스캐너 UA 오탐.** UA 위조 가능 → 단일신호 금지, 교차검증 필수(§2.4). UA DB 유지보수 주체·주기.
5. **analyzer 체인 로드 비용.** 블록/스택 판정 재사용 시 `import analyzer`가 전체 체인 로드 → 경량 모듈 추출 vs 공개 함수만 재사용 중 택일(M0). `_CONFIRM_SCAN`은 이미 공개 파생이라 이동 불요, `_OOB/_BROWSER_FAMILIES`는 레지스트리 신규항목 추가 필요(§4.4-9).
6. **대량 사건 폭주.** mass-scan이 수백 그룹이면 사건도 폭증 → 중복 억제(§6.5, 재설계 필요) 임계값과 캠페인 단위 묶음 정책 필요.
7. **그룹핑 정확도.** `src_ip` /24 집계가 CGNAT/프록시 환경에서 과대묶음 가능 → 분석가 병합/분리 오버라이드 UI 필수.
8. **자동검증 커버리지 협소(비평 I2).** `verify_incident`는 `req.url`+주입 param 필요(`agent.py:1067-1073`) → 로그 재구성 가능 범위는 대개 **GET 쿼리파라미터 공격(sqli/xss/lfi/redirect)**. 본문/헤더 공격은 복원 불가. 자동검증 비율 기대치를 "쿼리파라미터 주입 부분집합"으로 설정.
9. **적재 이득 한정(비평 I3).** `record_manual_traffic_batch(source='siem')`는 asset_shape 성공(=host 복원 성공) 이벤트만 적재 → "누적 학습" 이득은 파싱+host복원+재검증 성공 슬라이스에만 발생.

---

## 부록 K. 코드 대조로 확인된 정확 항목 (유지 — 재작업 방지)

- `'siem'` 추가 3곳 인용 정확(단 세 열거가 서로 달라 단일소스 아님 → 상수화 권고): write `agent_store.py:549`(`'manual','bulk','raw','multi'`), read `routers/agent_history.py:39`(`'agent','browser','manual','bulk','raw','multi'`), label `global_lookup.js:5-6`.
- `IncidentEvent.source`는 자유문자열로 'siem' 허용(`agent_models.py:59`), `category` Literal에 `access` 포함(`:64`), `title` min_length=1(`:65`) — §4.3 전제 정확.
- 데이터경계 인용 정확: egress 2 chokepoint·strict fail-closed(`ai_egress.py:3-7,39-43`), canary(`:113-119`), guard/EgressBlocked(`:318-339`), public_shape 설계(`public_shape.py:1-14,27-35,53-68`), OOB self-host·내부판별·strict 발급금지(`oob.py:1-15,261-270,273-278,281-293`).
- tier-1 디텍터 인용 정확: JWT none(`detectors.py:390`), middleware authbypass(`:458`), 역직렬화(`:946`), 업로드(`:994`).
- 재검증 파이프라인 인용 정확: `verify_incident` max_ai_calls=0·approved_plan(`agent.py:1053-1086`), 화이트리스트 거부(`:1064`, `_ALLOWED_PLAN_CATEGORIES` `:440`), `_verify_access_incident`(`:1088-1125`), 소유권 가드(`routers/agent.py:273-281`), 동시 2개 상한(`:342`).
- 현행 공백 진단 정확: `extractUrlFromLogLine`이 host/path/query/port만 읽고(`app.js:5417-5423`) 나머지 버림·host/path 없으면 drop(`:5425`), 로그판별 정규식이 `attack_name=`/`ruleName=`/`destination_ip=` 참조만(`:5510-5511`), by_url exact 그룹(`api.py:2059`)·exact dedup(`:2076-2080`).
- **코드 대조로 추가 확인(이번 검증):** `is_direct_file_probe` 6종 한정·쿼리/`..` 배제(`classify.py:187-198`); `_RULES` 실제 primary 집합 + `_REDIRECT_HINT` 死코드(`classify.py:56,142-157`); classify 안전성은 "전수 테스트 전제"에서만 성립(`classify.py:14-15`); `asset_shape`는 쿼리 **키**만 해시(`agent_assets.py:16`)·host 없으면 None(`:12-13`, `agent_view.py:35`); `incidents_for_asset`는 asset_id(+owner)만 조회(`agent_store.py:936-947`); 사건 상태는 **6상태**(`agent_incidents.py:65-79`); §4.1 조인은 `_record_traffic_batch`(bulk, `api.py:1961-1963`); `_CONFIRM_SCAN`은 `analyzer.py:25`(비공개 가족들은 `:4018-4053`).