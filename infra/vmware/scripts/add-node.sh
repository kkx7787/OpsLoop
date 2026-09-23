#!/usr/bin/env bash
# 기본 VM 을 연결 복제해 내부망에 노드 하나를 붙인다.
#
# 기본 VM 에는 네트워크 설정이 없다 (복제본마다 주소를 직접 주려고 지워 두었다).
# 그래서 첫 구성은 네트워크가 아니라 VMware Tools 로 게스트 안에서 하며, VM 콘솔 비밀번호가 필요하다.
# 비밀번호는 화면에 보이지 않게 입력받는다 (명령 이력에 남지 않는다).
#
# 하는 일
#   - 호스트명 · 고정 주소 · 시간원(방화벽) · 패키지 저장소 HTTPS
#   - 복제로 물려받은 SSH 호스트 키와 machine-id 를 새로 만든다.
#     호스트 키를 공유하면 한 노드가 뚫렸을 때 그 키로 다른 노드를 사칭할 수 있다.
#   - 새 호스트 키를 네트워크가 아닌 VMware Tools 로 가져와 Mac 의 known_hosts 에 등록한다.
#     첫 SSH 접속에서 "이 키를 믿겠습니까"를 묻지 않고, 중간자가 끼어들 틈도 없다.
#
# 사용: scripts/add-node.sh <이름> <메모리MB> <CPU> <vmnet> <MAC> <netplan 파일> <방화벽 주소> <고정 주소>
# 예:   scripts/add-node.sh opsloop-web-01 768 1 vmnet2 00:50:56:20:02:21 netplan/web-01.yaml 192.168.50.1 192.168.50.21
set -euo pipefail
NAME=${1:?이름}; MEM=${2:?메모리}; CPU=${3:?CPU}; VNET=${4:?vmnet}; MAC=${5:?MAC}
PLAN=${6:?netplan}; FW=${7:?방화벽 주소}; ADDR=${8:?고정 주소}
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VMDIR="${VMDIR:-$HOME/Virtual Machines.localized}"
BASE="${BASE:-$VMDIR/opsloop-base.vmwarevm/opsloop-base.vmx}"
VMRUN="/Applications/VMware Fusion.app/Contents/Library/vmrun"
GU="${GUEST_USER:-ops}"
TARGET="$VMDIR/$NAME.vmwarevm/$NAME.vmx"
case "$PLAN" in /*) ;; *) PLAN="$HERE/$PLAN" ;; esac
[ -f "$PLAN" ] || { echo "netplan 파일이 없습니다: $PLAN"; exit 1; }
[ -f "$TARGET" ] && { echo "$NAME 이미 있습니다"; exit 1; }
"$VMRUN" list | grep -q "$BASE" && { echo "기본 VM 이 켜져 있습니다. 끄고 다시 실행하세요"; exit 1; }
if [ -z "${GUEST_PW:-}" ]; then read -rs -p "VM 콘솔 비밀번호 (ops): " GUEST_PW; echo; fi
g() { "$VMRUN" -gu "$GU" -gp "$GUEST_PW" "$@"; }

echo "== 1. 복제 ($VNET · $MAC · ${MEM}MB · ${CPU}core)"
"$VMRUN" listSnapshots "$BASE" | grep -q '^base$' || "$VMRUN" snapshot "$BASE" base
"$VMRUN" clone "$BASE" "$TARGET" linked -snapshot=base -cloneName="$NAME"
python3 - "$TARGET" "$NAME" "$MEM" "$CPU" "$VNET" "$MAC" <<'PY'
import sys, re
vmx, name, mem, cpu, vnet, mac = sys.argv[1:7]
lines = [l for l in open(vmx) if not re.match(r'^(ethernet\d+\.|memsize|numvcpus|displayName|rtc\.startInUTC)', l)]
# 가상 RTC 를 UTC 로 받는다. 없으면 Mac 지역 시각을 줘서 게스트가 9시간 앞선 채 부팅한다 (infra/vmware/README.md 시간 동기화)
lines.append('rtc.startInUTC = "TRUE"\n')
lines += [f'displayName = "{name}"\n', f'memsize = "{mem}"\n', f'numvcpus = "{cpu}"\n',
          'ethernet0.present = "TRUE"\n', 'ethernet0.virtualDev = "vmxnet3"\n',
          'ethernet0.connectionType = "custom"\n', f'ethernet0.vnet = "{vnet}"\n',
          'ethernet0.addressType = "static"\n', f'ethernet0.address = "{mac}"\n']
open(vmx, 'w').writelines(lines)
PY
"$VMRUN" start "$TARGET" nogui

echo "== 2. VMware Tools 응답 대기"
ok=0
for i in $(seq 1 60); do g runProgramInGuest "$TARGET" /bin/true >/dev/null 2>&1 && { ok=1; break; }; sleep 5; done
[ "$ok" = 1 ] || { echo "응답이 없습니다 (비밀번호가 틀렸거나 부팅이 끝나지 않음)"; exit 1; }

echo "== 3. 게스트 구성"
g CopyFileFromHostToGuest "$TARGET" "$PLAN" /tmp/50-opsloop.yaml
g runScriptInGuest "$TARGET" /bin/bash "
set -e
sudo -n hostnamectl set-hostname $NAME
sudo -n sed -i 's/opsloop-base/$NAME/g' /etc/hosts
sudo -n sh -c 'rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null'
sudo -n sh -c 'rm -f /etc/machine-id /var/lib/dbus/machine-id && systemd-machine-id-setup >/dev/null'
sudo -n install -m 600 -o root -g root /tmp/50-opsloop.yaml /etc/netplan/50-opsloop.yaml
# 방화벽이 인터넷 80 을 막으므로 패키지 저장소는 HTTPS 로 쓴다
sudo -n sed -i 's#http://ports.ubuntu.com#https://ports.ubuntu.com#g' /etc/apt/sources.list.d/ubuntu.sources
sudo -n sed -i -E 's/^(pool .*)/#\\1/' /etc/chrony/chrony.conf
printf '# 내부 노드는 방화벽만 시간원으로 쓴다.\nserver %s iburst prefer\n# Mac 이 잠들었다 깨면 VM 시계가 크게 어긋난다. 언제든 한 번에 맞춘다.\nmakestep 1 -1\n' $FW | sudo -n tee /etc/chrony/conf.d/opsloop-fw.conf >/dev/null
sudo -n netplan apply
sudo -n systemctl restart ssh chrony
cp /etc/ssh/ssh_host_ed25519_key.pub /tmp/hostkey.pub
"

echo "== 4. 새 호스트 키를 known_hosts 에 등록 (VMware Tools 로 가져온 값)"
PUBTMP=$(mktemp)
g CopyFileFromGuestToHost "$TARGET" /tmp/hostkey.pub "$PUBTMP"
ssh-keygen -lf "$PUBTMP"
ssh-keygen -R "$ADDR" >/dev/null 2>&1 || true
printf '%s %s\n' "$ADDR" "$(cut -d' ' -f1,2 "$PUBTMP")" >> "$HOME/.ssh/known_hosts"
rm -f "$PUBTMP"
echo "완료. 방화벽을 거쳐 접속: ssh -J ops@192.168.70.254 ops@$ADDR"
