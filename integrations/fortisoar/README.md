# FortiSOAR 연동 — raw 패킷 검증 (커넥터 없이 Python 스텝)

FortiSOAR incident 화면의 **버튼 두 개**로 동작합니다. 커넥터를 만들지 않고, 각 버튼
플레이북 안의 **Execute Python Block** 스텝에서 이 폴더의 스크립트를 실행합니다.

```
[FortiSOAR incident]
  버튼① "패킷 생성"  → gen_raw_packet.py  → incident 데이터로 raw 패킷 생성 → 편집 필드에 Set
        (분석가가 raw_request 필드를 눈으로 수정)
  버튼② "검증 실행"  → verify_packet.py   → 수정된 raw 패킷을 검증도구로 전송 → 판정 결과 수신
```

검증도구(EventProbe) 쪽은 `POST /api/request/raw` 하나로 끝납니다(재전송+판정). 스크립트는
그 엔드포인트를 호출할 뿐입니다.

---

## 사전 준비

1. **검증도구 실행** (분석가/SOAR가 접근 가능한 호스트에서):
   ```
   .venv/Scripts/python.exe backend/main.py --port 8000
   ```
   SOAR 에서 도달 가능한 주소를 확인해 둡니다. 예: `http://10.0.0.5:8000` → 이 값이 `tester_url`.

2. **레코드 필드 2개** (Module Editor 에서 Alert/Incident 모듈에 추가):
   - `raw_request` (Text, 여러 줄) — 생성된 패킷을 담고 분석가가 수정하는 필드
   - `verify_result` (Text, 여러 줄) 또는 코멘트 — 판정 요약을 남길 곳(선택)

> ⚠️ 이 엔드포인트는 대상에 **실제로 재전송(replay)** 합니다. 운영망 대상이면 재공격
> 트래픽이 발생하니, 플레이북 초입에 **대상 호스트 허용 목록(allowlist) 체크**를 두는 것을
> 권장합니다(아래 6번).

---

## 버튼① "패킷 생성" 플레이북

1. **Trigger: Manual** — Trigger Type `Manual`, 대상 모듈 `Alerts`(또는 Incidents).
   → 레코드 상세에 버튼으로 뜹니다.
2. **Execute Python Block** — `gen_raw_packet.py` 전체 내용을 붙여넣고, 마지막에 진입 호출:
   ```python
   # (gen_raw_packet.py 내용 전체 위에 붙여넣은 뒤)
   params = {
       "method": "{{ vars.input.records[0].method | default('GET') }}",
       "url":    "{{ vars.input.records[0].url }}",
       # 헤더가 문자열/딕셔너리 어느 쪽이든 허용됨. 캡처 헤더가 없으면 생략 가능.
       "headers": {{ vars.input.records[0].requestHeaders | default({}) }},
       "body":    "{{ vars.input.records[0].requestBody | default('') }}",
   }
   output = main(params)     # -> {"raw_request": "..."}
   ```
   *필드명(`method`/`url`/`requestHeaders`…)은 실제 incident 스키마에 맞게 바꾸세요.*
3. **Set Field / Update Record** — `raw_request = {{ vars.steps.<PythonStep>.output.raw_request }}`

이제 분석가가 레코드의 `raw_request` 필드를 열어 필요한 부분을 수정합니다.

---

## 버튼② "검증 실행" 플레이북

1. **Trigger: Manual** — 같은 모듈에 두 번째 버튼.
2. *(권장)* **대상 allowlist 체크** — `raw_request` 의 Host 가 허용 대상인지 검사(6번 참고),
   아니면 플레이북 중단.
3. **Execute Python Block** — `verify_packet.py` 전체 내용을 붙여넣고, 마지막에 진입 호출:
   ```python
   params = {
       "tester_url":  "http://10.0.0.5:8000",     # 검증도구 주소
       "raw_request": "{{ vars.input.records[0].raw_request }}",
       "scheme":      "https",                     # 패킷 URI 가 상대경로일 때 대상 스킴
       "category":    "cve",                       # 선택
       # 우회 확증을 원하면 '정상(우회 안 한)' 응답을 baseline 으로 — 없으면 생략(의심까지만 판정)
       "baseline":    {"status_code": 302, "location": "/login"},
       "verify_tls":  False,
   }
   output = main(params)
   ```
4. **Set Field / Add Comment** — 요약을 레코드에 남깁니다:
   ```
   판정: {{ vars.steps.<PythonStep>.output.summary }}
   다음 단계: {{ vars.steps.<PythonStep>.output.next_action }}
   ```
5. *(선택)* `output.outcome` 으로 분기 — `success` 면 심각도 상향/에스컬레이션 등.

---

## verify_packet 반환값 (SOAR 에서 쓰는 필드)

| 필드 | 설명 |
|---|---|
| `ok` | 호출 성공 여부(파싱/네트워크 오류면 false, `error` 에 사유) |
| `outcome` | `success` \| `suspicious` \| `safe` \| `blocked` \| `inconclusive` |
| `risk_level` | 위험도 |
| `summary` | 분석가용 한 줄 요약(확증=성공 finding 우선) |
| `findings` | 성공·의심 finding 목록(`name`/`verdict`/`confidence`/`why`) |
| `next_action` | 판정 불가/의심일 때 다음 단계 안내 |
| `sent` | 실제 전송된 `method`/`url`/`http_version`(감사용) |
| `target_status` | 대상 응답 HTTP 상태코드 |
| `raw_response` | 검증도구 원본 응답 전체(디버그/감사) |

---

## 로컬 테스트 (SOAR 없이)

```bash
# 1) 패킷 생성
python integrations/fortisoar/gen_raw_packet.py '{"url":"https://target/admin","method":"GET"}'

# 2) 검증(검증도구가 127.0.0.1:8000 에 떠 있을 때)
python integrations/fortisoar/verify_packet.py '{"tester_url":"http://127.0.0.1:8000","raw_request":"GET /admin HTTP/1.1\r\nHost: target\r\n\r\n","scheme":"https"}'
```

---

## 6. 대상 allowlist 예시 (버튼② 2단계에 삽입)

```python
from urllib.parse import urlsplit
ALLOW = {"target.com", "staging.internal"}          # 허용 대상만
raw = "{{ vars.input.records[0].raw_request }}"
host = ""
for ln in raw.replace("\r\n", "\n").split("\n"):
    if ln.lower().startswith("host:"):
        host = ln.split(":", 1)[1].strip().split(":")[0]
        break
output = {"allowed": host in ALLOW, "host": host}    # allowed=False 면 이후 스텝 중단
```
