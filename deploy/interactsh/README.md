# interactsh self-host — 무료 VM으로 OOB(DNS+HTTP) 콜백 서버 구축

목표: **제3자 유출 없이(내 인프라)**, **내 도메인으로**, **DNS OOB까지** 되는 OOB 콜백 서버.
서버리스(Vercel/Cloudflare Pages/Workers)로는 불가 — 포트 53(authoritative DNS)을 상시
여는 **진짜 VM**이 필요합니다.

## 왜 VM이 필요한가
DNS OOB는 대상의 DNS 질의(`<데이터>.<토큰>.내도메인`)를 **내 서버가 authoritative로 직접
받아** 캡처합니다. 이건 UDP/53 상시 바인딩 + 그 도메인의 **NS 위임**이 필수라, 서버리스에선
안 됩니다. VM은 무료로 구할 수 있습니다.

## 1) 무료 VM 확보 (택1)
- **Oracle Cloud Always Free** — ARM Ampere A1 또는 AMD micro, 공인 IPv4, 영구 무료.
  **상세: [oracle-vm-guide.md](oracle-vm-guide.md)** (가입 → 인스턴스 → 포트 개방 → SSH).
- **GCP Always Free e2-micro** — us-west1/central1/east1 리전, 영구 무료.
  **상세: [gcp-vm-guide.md](gcp-vm-guide.md)** (콘솔·gcloud 양쪽 + VPC 방화벽·정적 IP).
- **fly.io** — 컨테이너, UDP/상시 프로세스 지원, 무료 허용량.
- **사내 장비** — 내부 타깃 점검이면 이게 정답(콜백이 경계를 안 넘음).

## 2) 도메인 확보 (~$1/yr, 또는 무료 대안)
- 가장 안정적: 저가 도메인 1개(Namecheap/Porkbun/Cloudflare Registrar 등).
- 완전 무료 대안: **eu.org**(NS 위임 지원, 승인 느림 — [eu-org-domain-guide.md](eu-org-domain-guide.md))
  또는 afraid.org(FreeDNS, 불안정).
- ⚠️ `*.vercel.app`·DuckDNS 등 **NS 제어를 못 주는 무료 서브도메인은 DNS OOB 불가.**

## 3) 도메인 NS 위임 (레지스트라 DNS 설정)
VM 공인 IP를 `<IP>` 라 할 때, 도메인의 네임서버를 내 VM으로 위임:
```
ns1.<도메인>   A    <IP>      ← glue 레코드
ns2.<도메인>   A    <IP>
<도메인>       NS   ns1.<도메인>
<도메인>       NS   ns2.<도메인>
```
(레지스트라에 따라 "child nameserver/glue 등록" 메뉴가 따로 있습니다.)

## 4) 클라우드 방화벽(보안그룹) 인바운드 허용
VM 인스턴스의 보안목록/Security Group 에서:
```
UDP 53, TCP 53, TCP 80, TCP 443, (선택) TCP 25
```
Oracle 은 VCN Security List + VM 내부 iptables 둘 다 열어야 합니다(스크립트가 iptables 는 처리).

## 5) 서버 설치·기동
VM에서:
```bash
git clone <이 저장소>  # 또는 setup.sh 만 복사
sudo bash deploy/interactsh/setup.sh <도메인> <VM_공인IP> <원하는_인증토큰>
# 예: sudo bash deploy/interactsh/setup.sh oob.example.com 203.0.113.10 s3cr3t-oob
```
스크립트가 하는 일: 최신 interactsh-server 릴리스 설치 → iptables 개방 → systemd 등록·기동.

## 6) 동작 검증
아무 데서나:
```bash
dig @<VM_공인IP> anything.<도메인>
# VM: journalctl -u interactsh -f  에 질의가 찍히면 authoritative DNS 정상
```

## 7) EventProbe(툴) 연결
툴 `.env`:
```
OOB_ENABLED=true
OOB_SERVER=https://<도메인>
OOB_DOMAIN=<도메인>
OOB_TOKEN=<setup.sh 에 준 토큰>     # -auth 로 띄웠으면 필수
```
그러면 페이로드의 `{{oob}}` 가 `<랜덤>.<상관ID>.<도메인>` 으로 치환되고, 툴이 이 서버를
폴링해 응답 탭 **OOB 콜백** 탭에 시간·출처 IP·프로토콜(DNS/HTTP)을 표시합니다.

## 비용 요약
- Oracle 무료 VM + eu.org/afraid.org 무료 도메인 → **완전 $0** (도메인 NS 위임이 까다로움)
- Oracle 무료 VM + 저가 도메인 → **~$1/yr** (안정적, 권장)
- 사내 장비 + 내부 도메인 → **$0 & 완전 무유출** (내부 타깃 전용)

## 참고: 공개 서버로 먼저 테스트
self-host 전에 무료 공개 서버(oast.fun 등)로 바로 테스트 가능하나, **제3자 경유(내부 타깃
유출 주의)** 이며 공개 도메인은 WAF 차단이 잦습니다. 툴은 `OOB_SERVER` 만 바꾸면 공개↔self-host
전환됩니다.
