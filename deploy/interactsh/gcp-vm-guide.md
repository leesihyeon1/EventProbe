# GCP Free Tier VM 생성 가이드 (interactsh OOB 서버용)

GCP **Always Free e2-micro** VM 으로 DNS+HTTP OOB 콜백 서버를 무료 구축. 필요한 것:
외부 IP, Ubuntu, 포트 UDP/TCP 53·80·443 개방, root.

> ⚠️ **Always Free** ≠ $300 무료 크레딧(90일 체험). OOB 서버는 상시 떠 있어야 하므로
> **Always Free e2-micro**(영구 무료)를 써야 합니다. 아래 조건을 지켜야 무료입니다.

## Always Free e2-micro 조건 (꼭 지킬 것)
- **리전**: `us-west1`(오리건) · `us-central1`(아이오와) · `us-east1`(사우스캐롤라이나) **중 하나만**.
  (다른 리전은 과금됨.)
- **머신 타입**: `e2-micro` 1대/월 (2 vCPU 공유·1GB RAM — interactsh 는 가벼워 충분).
- **디스크**: 표준 영구 디스크 30GB 이하.
- **egress**: 북미발 월 1GB 무료(중국·호주 제외). OOB 콜백은 소량이라 문제없음.
- 가입 시 **결제 계정(카드) 필요**하지만 Always Free 한도 내면 청구 안 됨.

---

## 방법 A — 콘솔(웹 UI)

### 1) 프로젝트·결제
console.cloud.google.com → 프로젝트 생성 → 결제 계정 연결(카드 등록).

### 2) VM 생성
Compute Engine → VM instances → **Create instance**
| 항목 | 값 |
|---|---|
| Name | `oob-interactsh` |
| Region / Zone | **us-central1** / us-central1-a (Always Free 리전) |
| Machine type | Series **E2** → **e2-micro** |
| Boot disk | **Ubuntu 22.04 LTS**, Standard PD 30GB |
| Firewall | Allow HTTP·HTTPS 체크(80/443만 열림 — 53 은 아래서 별도 추가) |

**Create** → 인스턴스의 **External IP** 메모.

### 3) 정적 IP 승격(중요 — DNS 위임용)
VPC network → **IP addresses** → 방금 인스턴스의 External IP 우측 → **Reserve/Promote to static**.
(정적 IP 는 실행 중 VM 에 붙어 있으면 무료. NS glue 가 이 IP 를 가리키므로 바뀌면 안 됨.)

### 4) 방화벽 규칙 추가 (UDP/TCP 53 등)
VPC network → **Firewall** → **Create firewall rule**
| 항목 | 값 |
|---|---|
| Name | `allow-oob` |
| Direction | Ingress |
| Targets | All instances in the network |
| Source IPv4 ranges | `0.0.0.0/0` |
| Protocols/ports | **udp:53, tcp:53, tcp:80, tcp:443, tcp:25**(선택) |

> DNS OOB 는 **UDP 53** 이 핵심 — 빠뜨리지 마세요.

### 5) SSH → 설치
콘솔의 인스턴스 우측 **SSH** 버튼(브라우저 터미널) 또는:
```bash
gcloud compute ssh oob-interactsh --zone=us-central1-a
```
```bash
sudo bash deploy/interactsh/setup.sh <도메인> <정적IP> <원하는_토큰>
```

---

## 방법 B — gcloud CLI (한 번에)
```bash
# 프로젝트 지정
gcloud config set project <PROJECT_ID>

# 정적 IP 예약
gcloud compute addresses create oob-ip --region=us-central1

# VM 생성(Always Free e2-micro, Ubuntu 22.04, 위 정적 IP 부착)
gcloud compute instances create oob-interactsh \
  --zone=us-central1-a --machine-type=e2-micro \
  --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
  --boot-disk-size=30GB --address=oob-ip

# 방화벽: UDP/TCP 53·80·443·25 개방
gcloud compute firewall-rules create allow-oob \
  --direction=INGRESS --action=ALLOW --network=default \
  --rules=udp:53,tcp:53,tcp:80,tcp:443,tcp:25 --source-ranges=0.0.0.0/0

# 정적 IP 확인
gcloud compute addresses describe oob-ip --region=us-central1 --format='value(address)'

# 접속 후 설치
gcloud compute ssh oob-interactsh --zone=us-central1-a
sudo bash deploy/interactsh/setup.sh <도메인> <정적IP> <토큰>
```

---

## 6) 도메인 NS 위임 (레지스트라)
정적 IP 를 `<IP>` 라 할 때:
```
ns1.<도메인>   A    <IP>
ns2.<도메인>   A    <IP>
<도메인>       NS   ns1.<도메인>
<도메인>       NS   ns2.<도메인>
```
(무료 도메인은 eu-org-domain-guide.md, 상세는 README.md 3번.)

## 7) 검증
```bash
sudo journalctl -u interactsh -f          # VM 에서 로그
dig @<IP> test.<도메인>                    # 서버 직접 질의
dig test.<도메인>                          # NS 위임 후 — 로그에 찍히면 완성
```

## 8) EventProbe 연결
```
OOB_ENABLED=true
OOB_SERVER=https://<도메인>
OOB_DOMAIN=<도메인>
OOB_TOKEN=<setup.sh 토큰>
```

---

## GCP 함정 / 참고
- **Always Free 리전 아님** → 과금. 반드시 us-west1/us-central1/us-east1.
- **UDP 53 방화벽 누락** → DNS OOB 안 됨(가장 흔한 실수). GCP 는 기본 VPC 가 ingress 를
  막으므로 규칙을 꼭 추가.
- **정적 IP 미승격** → VM stop/start 시 IP 가 바뀌어 NS 위임이 깨짐. 정적으로 승격하세요.
  (정적 IP 는 실행 중 VM 에 붙어 있으면 무료, VM 을 stop 한 채 예약만 하면 소액 과금.)
- **OS 방화벽**: GCP Ubuntu 이미지는 보통 iptables 가 열려 있음(Oracle 과 달리). setup.sh 가
  안전하게 규칙을 한 번 더 넣습니다.
- **비용**: e2-micro 1대 + 30GB PD + 정적IP(부착 상태) → Always Free 한도 내 $0. 도메인만 별도.

## Oracle vs GCP 요약
| | Oracle Always Free | GCP Always Free |
|---|---|---|
| VM | A1(ARM 4c/24G) 또는 E2.micro | e2-micro(2vCPU공유/1G) |
| 리전 제약 | 홈 리전 | us-west1/central1/east1 |
| 방화벽 | 보안목록 + VM iptables 둘 다 | VPC 방화벽(iptables 는 대개 열림) |
| interactsh 적합성 | 충분 | 충분(가벼움) |
