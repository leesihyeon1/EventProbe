# RAW 테스트 패킷 (실전 스타일)

GCP 로드밸런서(`Via: 1.1 google`, `X-Cloud-Trace-Context`, `CDN-Loop`) + Next.js 헤더를 동반한
실제 스캐너/공격 트래픽 형태로 재현. Host 기본값 `test.com` — 실제 대상으로 교체해 사용.

- 라인엔딩 CRLF, 요청라인에 `HTTP/1.1` 포함(소켓 전송 가능), `X-Forwarded-For` 중복 등 현실적 헤더 구성
- Log4Shell / PHP-CGI RCE / Shellshock / Next.js CVE 등 실전 페이로드 포함
- `_all_packets.txt` = 전체 번들
