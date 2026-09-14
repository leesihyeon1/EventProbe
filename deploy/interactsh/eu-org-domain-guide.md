# eu.org 무료 도메인 신청 가이드 (interactsh DNS OOB 위임용)

`<이름>.eu.org` 무료 도메인을 받아 **내 interactsh VM 으로 NS 위임**하면 DNS OOB 가 됩니다.
비용 $0. 단 **수동 승인(자원봉사자)** 이라 며칠~수주 걸리고, 신청 시 **작동하는 네임서버**를
제시해야 합니다.

> ⚠️ 대행 불가: 계정 생성·개인정보 입력·이메일 인증·약관 동의가 필요해 **본인이 직접** 신청해야
> 합니다. (급하면 ~$1 저가 도메인이 즉시·무승인이라 훨씬 빠릅니다.)

## 선행 조건
eu.org 는 위임할 **네임서버(NS)** 를 신청서에 적어야 하고, 승인 심사에서 그 NS 가 해당 존을
응답하는지 봅니다. 따라서 **interactsh VM 을 먼저 띄워** authoritative DNS 가 동작해야 합니다.
- VM 공인 IP: `<IP>` (Oracle 가이드 참고)
- 네임서버 2개를 준비: `ns1.<이름>.eu.org`, `ns2.<이름>.eu.org` → 둘 다 `<IP>` (glue)

## 절차
1. **가입** — https://nic.eu.org/ → *Create/Manage your account* → 사용자 핸들 생성
   (이름·이메일·연락처 입력, 이메일 인증). 개인/조직 contact 등록.
2. **로그인** 후 *Register a new domain* (또는 *New domain request*).
3. 도메인 이름 선택: `<이름>.eu.org` (또는 국가 서브존 아래).
4. **네임서버 지정** — 위 `ns1/ns2.<이름>.eu.org` 를 입력하고, 요구되면 **glue(호스트→IP)** 도
   등록: `ns1.<이름>.eu.org A <IP>`, `ns2.<이름>.eu.org A <IP>`.
   (즉 이 도메인의 존을 내 interactsh VM 이 응답한다고 위임하는 것.)
5. **제출** → 자원봉사 관리자 **수동 승인 대기**(며칠~수주). 상태는 계정에서 확인.
6. 승인되면 `*.<이름>.eu.org` DNS 질의가 내 VM(interactsh)으로 옴 → DNS OOB 완성.

## 승인 통과 팁 / 흔한 반려 사유
- **NS 가 실제로 응답해야** 함 — 신청 전/중에 interactsh-server 가 떠 있고 `dig @<IP>
  test.<이름>.eu.org` 가 응답하는 상태로 두세요.
- 남용/스팸/일회용처럼 보이면 반려될 수 있음 — 정상적인 contact 정보로 신청.
- glue 레코드 누락이 가장 흔한 실패 — ns 호스트의 A 레코드를 꼭 함께.

## 승인 후 툴 연결
```
OOB_ENABLED=true
OOB_SERVER=https://<이름>.eu.org
OOB_DOMAIN=<이름>.eu.org
OOB_TOKEN=<interactsh -auth 토큰>
```

## 현실적 비교
| 도메인 | 비용 | 속도 | 비고 |
|---|---|---|---|
| eu.org | $0 | 느림(수동 승인 며칠~수주) | NS 위임 가능, 반려 가능성 |
| 저가 도메인(Porkbun/Cloudflare Registrar 등) | ~$1~/yr | 즉시 | 무승인·안정, 권장 |
| 공개 oast.fun | $0 | 즉시 | 도메인 불필요, 단 제3자 경유(내부 타깃 유출 주의) |

→ **테스트/내부용이 급하면 oast.fun 로 지금 시작**하고, self-host 도메인은 eu.org(무료·느림)
또는 ~$1 도메인(즉시)으로 병행 준비하는 걸 권장합니다.
