#!/usr/bin/env bash
# 이미 있는 내부 방화벽 VM 에 외부 역할 세그먼트(vmnet5) 랜카드를 붙이고 netplan 을 다시 넣는다 (이슈 #51).
# 새로 복제하는 방화벽은 clone.sh 가 처음부터 5장으로 만든다. 이 스크립트는 운영 중인 방화벽에 쓴다.
#
# 하는 일 (--apply 없이는 계획만 찍는다)
#   1. 방화벽을 끈다(게스트 종료). 그동안 내부망 전체의 인터넷 · 콘솔 진입점 · 세그먼트 간 통신이 멈춘다 (1분 안팎)
#   2. vmx 에 ethernet4(vmnet5 · MAC 00:50:56:20:01:04)를 더한다. 이미 있으면 건너뛴다
#   3. 켠 뒤 SSH 가 열리기를 기다려 fw.yaml.template 을 채운 netplan 을 넣고 적용한다 (ext 203.0.113.1/24)
# 방화벽 규칙(fw/nftables.conf 의 EXT · opsloop_block)은 README '내부 방화벽 차단 집행' 절의 순서로 따로 올린다.
# 사용: scripts/fw-add-ext-nic.sh            계획
#       scripts/fw-add-ext-nic.sh --apply    실행
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VMDIR="${VMDIR:-$HOME/Virtual Machines.localized}"
VMX="$VMDIR/opsloop-fw.vmwarevm/opsloop-fw.vmx"
VMRUN="/Applications/VMware Fusion.app/Contents/Library/vmrun"
SSH=(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=5)
VNET=vmnet5; MAC=00:50:56:20:01:04
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
[ -f "$VMX" ] || { echo "방화벽 VM 이 없습니다: $VMX"; exit 1; }

have_nic=0; grep -q '^ethernet4\.present' "$VMX" && have_nic=1
echo "== 계획"
echo "  vmx: $VMX (ethernet4 $([ $have_nic = 1 ] && echo 있음 · 건너뜀 || echo 없음 · 추가))"
echo "  netplan: netplan/fw.yaml.template → ext 203.0.113.1/24 (MAC $MAC)"
have_net=0; grep -q "^answer VNET_5_HOSTONLY_SUBNET " "/Library/Preferences/VMware Fusion/networking" 2>/dev/null && have_net=1
[ $have_net = 1 ] || echo "  [주의] vmnet5 가 없습니다. 먼저 sudo scripts/create-networks.sh"
[ $APPLY = 1 ] || { echo "계획만 찍었습니다. 실행은 --apply"; exit 0; }
# 없는 가상망에 랜카드를 붙이면 방화벽이 켜지지 않거나 ext 가 끊긴 채 뜬다. 방화벽을 끄기 전에 멈춘다
[ $have_net = 1 ] || { echo "vmnet5 가 없어 멈춥니다 (방화벽은 건드리지 않았다)"; exit 1; }

if [ $have_nic = 0 ]; then
  echo "== 1. 방화벽 종료 (내부망 통신이 잠시 멈춥니다)"
  "$VMRUN" list | grep -q "$VMX" && "$VMRUN" stop "$VMX" soft
  for i in $(seq 1 24); do "$VMRUN" list | grep -q "$VMX" || break; sleep 5; done
  "$VMRUN" list | grep -q "$VMX" && { echo "방화벽이 꺼지지 않습니다"; exit 1; }
  echo "== 2. vmx 에 ethernet4 추가"
  cp -p "$VMX" "$VMX.bak.$(date +%Y%m%d%H%M%S)"
  printf 'ethernet4.present = "TRUE"\nethernet4.virtualDev = "vmxnet3"\nethernet4.connectionType = "custom"\nethernet4.vnet = "%s"\nethernet4.addressType = "static"\nethernet4.address = "%s"\n' "$VNET" "$MAC" >> "$VMX"
  "$VMRUN" start "$VMX" nogui
fi
echo "== 3. SSH 대기"
ok=0; for i in $(seq 1 36); do "${SSH[@]}" fw true >/dev/null 2>&1 && { ok=1; break; }; sleep 5; done
[ $ok = 1 ] || { echo "방화벽 SSH 가 열리지 않습니다 (관리망 · VPN 확인)"; exit 1; }
echo "== 4. netplan 넣기 · 적용"
python3 - "$HERE/netplan/fw.yaml.template" <<'PY' | "${SSH[@]}" fw 'set -e
  cat > /tmp/opsloop-fw.yaml
  sudo -n install -m 600 -o root -g root /tmp/opsloop-fw.yaml /etc/netplan/50-opsloop.yaml
  sudo -n netplan apply
  sleep 2; ip -br addr show ext'
import sys
m={'__MAC_UPLINK__':'00:50:56:20:01:00','__MAC_SERVICE__':'00:50:56:20:01:01',
   '__MAC_DATA__':'00:50:56:20:01:02','__MAC_MGMT__':'00:50:56:20:01:03','__MAC_EXT__':'00:50:56:20:01:04'}
s=open(sys.argv[1]).read()
for k,v in m.items(): s=s.replace(k,v)
sys.stdout.write(s)
PY
echo "완료. 다음: README '내부 방화벽 차단 집행' 절 (규칙 올리기 → 동기화 설치)"
