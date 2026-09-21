#!/usr/bin/env bash
# 세그먼트용 가상 네트워크 3개를 만든다. sudo 로 실행한다.
#   vmnet2 서비스망 192.168.50.0/24 (호스트 미연결)
#   vmnet3 데이터망 192.168.60.0/24 (호스트 미연결)
#   vmnet4 관리망   192.168.70.0/24 (호스트 연결 · Mac 이 작업자 단말)
# DHCP 는 모두 끈다. 주소는 노드마다 고정으로 준다.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "sudo 로 실행하세요"; exit 1; }
CFG="/Library/Preferences/VMware Fusion/networking"
LIB="/Applications/VMware Fusion.app/Contents/Library"
cp "$CFG" "$CFG.bak.$(date +%Y%m%d%H%M%S)"

add() { # $1 vnet 번호  $2 서브넷  $3 호스트 어댑터 연결 여부
  local n=$1 sub=$2 adapter=$3
  grep -q "^answer VNET_${n}_HOSTONLY_SUBNET" "$CFG" && { echo "vmnet${n} 이미 있음 · 건너뜀"; return; }
  cat >> "$CFG" <<EOT
answer VNET_${n}_DHCP no
answer VNET_${n}_HOSTONLY_NETMASK 255.255.255.0
answer VNET_${n}_HOSTONLY_SUBNET ${sub}
answer VNET_${n}_VIRTUAL_ADAPTER ${adapter}
EOT
  echo "vmnet${n} 추가 · ${sub}/24 · 호스트 어댑터 ${adapter}"
}
add 2 192.168.50.0 no
add 3 192.168.60.0 no
add 4 192.168.70.0 yes

"$LIB/vmnet-cli" --configure
"$LIB/vmnet-cli" --stop
"$LIB/vmnet-cli" --start
echo "--- 현재 상태"
"$LIB/vmnet-cli" --status
ifconfig | grep -A2 -E '^vmnet[0-9]' | grep -E '^vmnet|inet ' || true
