#!/usr/bin/env bash
# interactsh-server 설치 스크립트 — 무료 VM(Oracle Always Free / fly.io / 사내 장비)의
# Ubuntu/Debian 에서 실행. DNS+HTTP+HTTPS+SMTP OOB 콜백을 자기 인프라로만 받는다(무유출).
#
# 사용:  sudo ./setup.sh <도메인> <VM_공인IP> [auth_token]
#   예:  sudo ./setup.sh oob.example.com 203.0.113.10 my-secret-token
#
# 사전 준비(레지스트라에서 도메인 NS 위임):
#   ns1.<도메인>  A  <VM_공인IP>      (glue)
#   ns2.<도메인>  A  <VM_공인IP>      (glue)
#   <도메인>      NS ns1.<도메인>
#   <도메인>      NS ns2.<도메인>
# 그리고 클라우드 보안그룹/방화벽에서 아래 인바운드 허용:
#   UDP 53, TCP 53, TCP 80, TCP 443, TCP 25(선택)
set -euo pipefail

DOMAIN="${1:-}"; IP="${2:-}"; TOKEN="${3:-}"
if [[ -z "$DOMAIN" || -z "$IP" ]]; then
  echo "usage: sudo $0 <domain> <public-ip> [auth-token]" >&2; exit 1
fi
if [[ $EUID -ne 0 ]]; then echo "root 로 실행하세요(포트 53 바인딩 필요): sudo $0 ..." >&2; exit 1; fi

echo "[*] 최신 interactsh-server 릴리스 내려받기"
ARCH="$(uname -m)"; case "$ARCH" in x86_64) A=amd64;; aarch64|arm64) A=arm64;; *) echo "미지원 arch: $ARCH"; exit 1;; esac
TMP="$(mktemp -d)"; cd "$TMP"
URL="$(curl -fsSL https://api.github.com/repos/projectdiscovery/interactsh/releases/latest \
      | grep -oE "https://[^\" ]+interactsh-server_[^\" ]+_linux_${A}\\.zip" | head -1)"
[[ -n "$URL" ]] || { echo "릴리스 URL 탐색 실패 — 수동 설치 필요"; exit 1; }
curl -fsSL "$URL" -o s.zip && (command -v unzip >/dev/null || (apt-get update -y && apt-get install -y unzip))
unzip -o s.zip >/dev/null
install -m 0755 interactsh-server /usr/local/bin/interactsh-server
echo "[*] 설치됨: $(/usr/local/bin/interactsh-server -version 2>&1 | head -1 || true)"

# 로컬 방화벽(Oracle 이미지는 기본 iptables 가 막고 있음) — 필요한 포트 개방
echo "[*] 로컬 방화벽 규칙(53/80/443/25) 추가 시도"
if command -v ufw >/dev/null; then
  ufw allow 53 >/dev/null 2>&1 || true; ufw allow 80,443/tcp >/dev/null 2>&1 || true; ufw allow 25/tcp >/dev/null 2>&1 || true
else
  iptables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
  iptables -I INPUT -p tcp -m multiport --dports 53,80,443,25 -j ACCEPT 2>/dev/null || true
  command -v netfilter-persistent >/dev/null && netfilter-persistent save 2>/dev/null || true
fi

AUTH_ARG=""; [[ -n "$TOKEN" ]] && AUTH_ARG="-auth -token ${TOKEN}"
echo "[*] systemd 유닛 작성"
cat >/etc/systemd/system/interactsh.service <<UNIT
[Unit]
Description=interactsh-server (OOB collaborator)
After=network.target

[Service]
ExecStart=/usr/local/bin/interactsh-server -domain ${DOMAIN} -ip ${IP} -wildcard ${AUTH_ARG}
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now interactsh.service
sleep 2
systemctl --no-pager --full status interactsh.service | head -12 || true
echo
echo "[✓] 완료. 검증:  dig @${IP} test.${DOMAIN}   (VM 에서 질의가 로그에 찍히면 정상)"
echo "    툴 .env 에:"
echo "        OOB_ENABLED=true"
echo "        OOB_SERVER=https://${DOMAIN}"
[[ -n "$TOKEN" ]] && echo "        OOB_TOKEN=${TOKEN}"
echo "        OOB_DOMAIN=${DOMAIN}"
