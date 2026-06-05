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

# 2. 의존성 설치
pip install -r requirements.txt

# 3. 서버 실행
python backend/main.py

# 4. 브라우저 접속
# http://localhost:8000
```

## 지원 공격 카테고리

| 카테고리 | 페이로드 수 | 설명 |
|---------|-----------|------|
| SQL Injection | 10개 | 인증 우회, UNION, Blind, 인코딩 우회 |
| XSS | 8개 | Script, 이벤트 핸들러, SVG, 인코딩 우회 |
| SSRF | 6개 | localhost, AWS 메타데이터, 파일 프로토콜 |
| LFI / Path Traversal | 6개 | 경로 우회, 인코딩, Null 바이트 |
| Command Injection | 6개 | 세미콜론, 파이프, 서브쉘, Blind |
| Header Injection | 4개 | Host, X-Forwarded-For, User-Agent |

## 스택

- **Backend**: Python, FastAPI, httpx
- **Frontend**: Vanilla JS, CSS (다크 테마)
- **분석 엔진**: 정규식 기반 WAF 시그니처 탐지

## 주의사항

> ⚠️ 이 도구는 **허가된 환경에서의 보안 테스트 목적**으로만 사용하세요.  
> 허가되지 않은 시스템에 대한 공격은 불법입니다.

## License

MIT
