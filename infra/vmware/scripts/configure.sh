#!/usr/bin/env bash
# 복제본에 호스트명과 고정 주소를 넣는다. 네트워크가 아직 없으므로
# VMware Tools 를 통해 게스트 안에서 실행한다 (SSH 아님).
# 사용: GUEST_PW='...' scripts/configure.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VMDIR="${VMDIR:-$HOME/Virtual Machines.localized}"
VMRUN="/Applications/VMware Fusion.app/Contents/Library/vmrun"
GU="${GUEST_USER:-ops}"
: "${GUEST_PW:?GUEST_PW 환경변수에 VM 콘솔 비밀번호를 넣으세요}"
KEY="${SSH_PUB:-$HOME/.ssh/opsloop_ed25519.pub}"

g() { "$VMRUN" -gu "$GU" -gp "$GUEST_PW" "$@"; }

apply() { # $1 VM 이름  $2 netplan 파일
  local name=$1 plan=$2 vmx="$VMDIR/$1.vmwarevm/$1.vmx"
  echo "== $name"
  "$VMRUN" list | grep -q "$vmx" || "$VMRUN" start "$vmx" nogui
  echo "-- VMware Tools 응답 대기"
  for i in $(seq 1 60); do g runProgramInGuest "$vmx" /bin/true >/dev/null 2>&1 && break; sleep 5; done
  g CopyFileFromHostToGuest "$vmx" "$plan" /tmp/50-opsloop.yaml
  g runScriptInGuest "$vmx" /bin/bash "
    set -e
    sudo -n hostnamectl set-hostname $name
    sudo -n sed -i 's/opsloop-base/$name/g' /etc/hosts
    sudo -n install -m 600 -o root -g root /tmp/50-opsloop.yaml /etc/netplan/50-opsloop.yaml
    sudo -n netplan apply
    sudo -n systemctl enable --now nftables || true
  "
  echo "-- 주소 확인"
  g runScriptInGuest "$vmx" /bin/bash "ip -br addr | grep -v LOOPBACK"
}

# 방화벽: MAC 으로 인터페이스를 구분한다
python3 - "$HERE/netplan/fw.yaml.template" /tmp/fw.yaml <<'PY'
import sys
src,dst=sys.argv[1:3]
m={'__MAC_UPLINK__':'00:50:56:20:01:00','__MAC_SERVICE__':'00:50:56:20:01:01',
   '__MAC_DATA__':'00:50:56:20:01:02','__MAC_MGMT__':'00:50:56:20:01:03'}
s=open(src).read()
for k,v in m.items(): s=s.replace(k,v)
open(dst,'w').write(s)
PY
apply opsloop-fw /tmp/fw.yaml
echo "-- 방화벽 규칙 적용"
FWVMX="$VMDIR/opsloop-fw.vmwarevm/opsloop-fw.vmx"
g CopyFileFromHostToGuest "$FWVMX" "$HERE/fw/nftables.conf" /tmp/nftables.conf
g runScriptInGuest "$FWVMX" /bin/bash "
  sudo -n install -m 644 /tmp/nftables.conf /etc/nftables.conf
  sudo -n sysctl -w net.ipv4.ip_forward=1
  echo 'net.ipv4.ip_forward=1' | sudo -n tee /etc/sysctl.d/99-opsloop.conf >/dev/null
  sudo -n nft -f /etc/nftables.conf
  sudo -n systemctl enable nftables
  sudo -n nft list ruleset | head -20
"

apply opsloop-console-a "$HERE/netplan/console-a.yaml"
apply opsloop-console-b "$HERE/netplan/console-b.yaml"
apply opsloop-data-01   "$HERE/netplan/data-01.yaml"

echo; echo "== SSH 확인 (관리망 경유)"
for ip in 192.168.70.254; do ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i "${KEY%.pub}" ops@$ip 'hostname; ip -br addr' || true; done
echo "콘솔과 데이터 노드는 방화벽을 통해 접근합니다: ssh -J ops@192.168.70.254 ops@192.168.50.11"
