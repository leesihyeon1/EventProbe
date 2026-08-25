# EventProbe 🛡️

> 보안 이벤트 검증을 위한 웹 기반 API 테스트 도구  
> Web-based API tester for security event validation (WAF / IDS / IPS)

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 소개

EventProbe는 WAF/IDS/IPS 보안 장비의 이벤트 탐지 여부를 검증하는 도구입니다.  
공격 페이로드를 API 요청에 삽입하고, 응답을 자동 분석하여 차단/통과/우회 여부를 판정하며 검증 리포트를 생성합니다.

## 주요 기능

- 🗂 **치트시트 연동** — SQLi / XSS / SSRF / LFI / Command Injection / Header Injection 페이로드 내장
- 📡 **API 요청 테스터** — Method, Headers, Params, Body 설정 후 원클릭 전송
- 🔍 **응답 자동 분석** — WAF 제품 탐지, 차단 여부, 에러 누출, 민감정보 노출 판정
- ⚡ **일괄 테스트** — 카테고리별 페이로드 전체 자동 전송 및 탐지율 집계
- 📄 **검증 리포트** — 탐지율, 우회 성공 목록, 권고사항 자동 생성

## 빠른 시작

```bash
# 1. 클론
git clone https://github.com/leesihyeon1/EventProbe.git
cd EventProbe

# 2. 가상환경 생성 및 활성화 (권장 — 전역 파이썬 오염 방지)
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
# source .venv/bin/activate

# 3. 의존성 설치
pip install -r requirements.txt

# 4. 서버 실행
python backend/main.py

# 5. 브라우저 접속
# http://localhost:8000
```

> venv를 쓰지 않으면 `ModuleNotFoundError: No module named 'fastapi'` 등이 발생할 수 있습니다.
> 이 경우 의존성이 설치되지 않은 것이니 3단계를 먼저 실행하세요.

---

## 서버 실행 / 종료 가이드 (공용 PC 환경)

### ▶ 서버 실행

**Windows**
```batch
cd EventProbe
python backend/main.py
```
> 터미널에 `Uvicorn running on http://0.0.0.0:8000` 메시지가 나오면 정상 실행된 것입니다.  
> 브라우저에서 `http://localhost:8000` 접속

**포트 충돌 시 (8000번이 이미 사용 중)**
```batch
:: 사용 중인 프로세스 확인
netstat -ano | findstr :8000

:: PID 확인 후 종료 (예: PID가 1234인 경우)
taskkill /PID 1234 /F

:: 또는 다른 포트로 실행
python backend/main.py --port 8080
```

---

### ⏹ 서버 종료

| 방법 | 설명 |
|------|------|
| 터미널에서 `Ctrl + C` | 가장 권장 — 실행 중인 터미널에서 바로 종료 |
| 터미널 창 닫기 | 터미널 자체를 닫으면 서버도 같이 종료됨 |
| 작업 관리자 | `python.exe` 프로세스 찾아서 종료 |

**터미널 없이 백그라운드로 실행된 경우 강제 종료**
```batch
:: 8000번 포트 사용 중인 PID 확인
netstat -ano | findstr :8000

:: 해당 PID 강제 종료
taskkill /PID <PID번호> /F
```

---

### ⚠️ 공용 PC 사용 시 주의사항

> - 사용 후 반드시 **서버를 종료**하세요 — 종료하지 않으면 다른 사용자가 `http://localhost:8000` 으로 접근 가능합니다.
> - 테스트 대상 URL 등 **민감한 정보가 브라우저 히스토리에 남을 수 있습니다** — 사용 후 브라우저 방문 기록을 삭제하세요.
> - 실제 운영 서버 IP/도메인을 입력한 경우 **화면을 캡처하거나 자리를 비우지 마세요**.
> - 가능하면 **시크릿 모드(InPrivate)** 로 브라우저를 사용하세요.

## 지원 공격 카테고리

총 **14개 카테고리 / 178개 페이로드** 내장 (`backend/data/payloads.json`).

| 카테고리 | 페이로드 수 | 설명 |
|---------|-----------|------|
| SQL Injection | 30개 | 인증 우회, UNION, Blind, 인코딩 우회 |
| XSS | 22개 | Script, 이벤트 핸들러, SVG, 인코딩 우회 |
| SSRF | 20개 | localhost, AWS 메타데이터, 파일 프로토콜 |
| LFI / Path Traversal | 18개 | 경로 우회, 인코딩, Null 바이트 |
| Command Injection | 17개 | 세미콜론, 파이프, 서브쉘, Blind |
| Header Injection | 12개 | Host, X-Forwarded-For, User-Agent |
| Business Logic / IDOR | 10개 | 권한 우회, 객체 참조 조작 |
| SSTI | 9개 | 템플릿 인젝션 (Jinja2, Twig 등) |
| NoSQL Injection | 8개 | MongoDB 연산자 인젝션 |
| Open Redirect | 8개 | 오픈 리다이렉트 우회 |
| XXE Injection | 6개 | 외부 엔티티, 파일 읽기 |
| JWT 공격 | 6개 | alg=none, 서명 우회 |
| Prototype Pollution | 6개 | `__proto__` 오염 |
| LDAP Injection | 6개 | LDAP 필터 우회 |

## 스택

- **Backend**: Python, FastAPI, httpx
- **Frontend**: Vanilla JS, CSS (다크 테마)
- **분석 엔진**: 정규식 기반 WAF 시그니처 탐지

## 주의사항

> ⚠️ 이 도구는 **허가된 환경에서의 보안 테스트 목적**으로만 사용하세요.  
> 허가되지 않은 시스템에 대한 공격은 불법입니다.

## License

MIT
