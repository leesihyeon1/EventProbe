# Oracle Cloud Always Free VM 생성 가이드 (interactsh OOB 서버용)

interactsh-server 를 돌릴 **영구 무료** VM 을 만드는 절차. 필요한 것: 공인 IPv4, Ubuntu,
포트 53/80/443 개방, root.

> 요약: 무료 계정 → E2.1.Micro(또는 A1.Flex) Ubuntu 인스턴스(공인 IP 할당) → 보안목록에
> 53/80/443 인바운드 추가 → SSH 접속 → `deploy/interactsh/setup.sh` 실행.

---

## 0) 가입 (최초 1회)
1. https://www.oracle.com/cloud/free/ → **Start for free**.
2. 이메일·국가·이름 입력 → 이메일 인증.
3. **신용카드 등록**(본인확인용, Always Free 리소스는 과금 안 됨. 업그레이드 안 하면 청구 없음).
4. **홈 리전 선택** — 가입 후 변경 불가. 가까운 리전 선택(단, ARM 용량은 인기 리전일수록 품절 잦음).
5. 콘솔 로그인: https://cloud.oracle.com

---

## 1) 인스턴스 생성
콘솔 좌측 ☰ → **Compute → Instances → Create instance**

| 항목 | 값 |
|---|---|
| Name | `oob-interactsh` (아무거나) |
| Compartment | 기본(root) |
| **Image** | Edit → **Canonical Ubuntu 22.04** |
| **Shape** | Edit → Ampere(ARM) **VM.Standard.A1.Flex** (1 OCPU·6GB면 충분) — "out of capacity" 뜨면 **VM.Standard.E2.1.Micro**(AMD, 항상 가용) 선택. interactsh 는 가벼워 micro 로 충분 |
| Networking | 새 VCN 자동 생성 허용, **Assign a public IPv4 address = 예(체크)** ← 필수 |
| SSH keys | **Generate a key pair for me** → **개인키(.key) 저장**(다시 못 받음) 또는 내 공개키 업로드 |

**Create** 클릭 → 1~2분 후 Running.
생성된 인스턴스 상세에서 **Public IP address** 를 메모(예: `203.0.113.10`).

---

## 2) 방화벽 1 — 클라우드 보안목록(Security List)
콘솔 ☰ → **Networking → Virtual Cloud Networks → (내 VCN) → Security Lists →
Default Security List → Add Ingress Rules**. 아래를 각각 추가:

| Source CIDR | IP Protocol | Dest Port |
|---|---|---|
| 0.0.0.0/0 | UDP | 53 |
| 0.0.0.0/0 | TCP | 53 |
| 0.0.0.0/0 | TCP | 80 |
| 0.0.0.0/0 | TCP | 443 |
| 0.0.0.0/0 | TCP | 25 (선택, SMTP OOB) |

> DNS OOB 는 **UDP 53** 이 핵심 — 빠뜨리지 마세요.

---

## 3) SSH 접속
```bash
chmod 600 ssh-key.key
ssh -i ssh-key.key ubuntu@<공인IP>
```
(Ubuntu 이미지 기본 계정은 `ubuntu`.)

---

## 4) 방화벽 2 — VM 내부 iptables
Oracle Ubuntu 이미지는 기본 iptables 가 막고 있습니다. **setup.sh 가 자동 개방**하므로
보통 별도 작업 불필요. 수동으로 하려면:
```bash
sudo iptables -I INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -I INPUT -p tcp -m multiport --dports 53,80,443,25 -j ACCEPT
sudo netfilter-persistent save 2>/dev/null || true
```

---

## 5) interactsh 설치·기동
```bash
# 이 저장소를 받거나 setup.sh 만 복사
sudo bash deploy/interactsh/setup.sh <도메인> <공인IP> <원하는_토큰>
# 예: sudo bash deploy/interactsh/setup.sh oob.example.com 203.0.113.10 s3cr3t-oob
```
> 도메인 NS 위임(레지스트라에서 ns1/ns2 → 공인IP glue + NS 레코드)은
> `deploy/interactsh/README.md` 3번 참고. 이게 돼야 외부에서 DNS 질의가 VM 으로 옵니다.

---

## 6) 검증
```bash
# VM 에서 로그 보기
sudo journalctl -u interactsh -f
# 다른 곳에서(또는 VM 에서) 질의
dig @<공인IP> test.<도메인>          # NS 위임 전이라도 IP 직접 질의로 서버 동작 확인
dig test.<도메인>                    # NS 위임 후 — 이게 로그에 찍히면 완성
```
로그에 질의가 찍히면 authoritative DNS OOB 정상.

---

## 흔한 함정
- **ARM(A1) "out of capacity"** — 인기 리전에서 잦음. E2.1.Micro(AMD) 로 대체하거나 시간대를
  바꿔 재시도. (interactsh 는 micro 로 충분)
- **공인 IP 미할당** — 생성 시 "Assign public IPv4" 체크 안 하면 외부에서 접근 불가. 재생성 또는
  IP 추가 할당.
- **UDP 53 누락** — 보안목록에 TCP 만 넣으면 DNS OOB 안 됨. UDP 53 반드시.
- **Always Free 유휴 회수** — Oracle 은 장기 유휴 Always Free 인스턴스를 회수할 수 있음.
  interactsh 는 상시 리스닝이라 보통 유휴로 안 잡히나, 걱정되면 **Pay-As-You-Go 로 업그레이드**해도
  Always Free 한도 내면 과금 없음(회수 면제).
- **비용** — Always Free 범위(1 A1 1OCPU/6GB 또는 2 E2.micro, 부트볼륨 200GB 내)면 $0.
  도메인만 별도(~$1/yr 또는 eu.org 무료).
