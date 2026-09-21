#!/usr/bin/env bash
# 기본 VM 을 연결 복제해 내부망 4대를 만든다.
#   opsloop-fw        1GB / 2core  NAT + 서비스망 + 데이터망 + 관리망
#   opsloop-console-a 1GB / 1core  서비스망
#   opsloop-console-b 1GB / 1core  서비스망 (평소에는 꺼 둔다)
#   opsloop-data-01   3GB / 2core  데이터망
# 연결 복제라 디스크는 바뀐 부분만 차지한다.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VMDIR="${VMDIR:-$HOME/Virtual Machines.localized}"
BASE="${BASE:-$VMDIR/opsloop-base.vmwarevm/opsloop-base.vmx}"
VMRUN="/Applications/VMware Fusion.app/Contents/Library/vmrun"
[ -f "$BASE" ] || { echo "기본 VM 을 찾을 수 없습니다: $BASE"; exit 1; }

"$VMRUN" list | grep -q "$BASE" && { echo "기본 VM 이 켜져 있습니다. 끄고 다시 실행하세요"; exit 1; }
"$VMRUN" listSnapshots "$BASE" | grep -q '^base$' || "$VMRUN" snapshot "$BASE" base

# 이름:메모리:CPU:"랜카드 정의(vmnet,MAC 공백 구분)"
NODES=(
  "opsloop-fw:1024:2:vmnet8,00:50:56:20:01:00 vmnet2,00:50:56:20:01:01 vmnet3,00:50:56:20:01:02 vmnet4,00:50:56:20:01:03"
  "opsloop-console-a:1024:1:vmnet2,00:50:56:20:02:01"
  "opsloop-console-b:1024:1:vmnet2,00:50:56:20:02:02"
  "opsloop-data-01:3072:2:vmnet3,00:50:56:20:03:01"
)

for node in "${NODES[@]}"; do
  IFS=':' read -r name mem cpu _ <<< "$node"
  nics="${node#*:*:*:}"
  target="$VMDIR/$name.vmwarevm/$name.vmx"
  if [ -f "$target" ]; then echo "$name 이미 있음 · 건너뜀"; continue; fi
  echo "== $name 복제"
  "$VMRUN" clone "$BASE" "$target" linked -snapshot=base -cloneName="$name"

  python3 - "$target" "$name" "$mem" "$cpu" "$nics" <<'PY'
import sys,re
vmx,name,mem,cpu,nics=sys.argv[1:6]
lines=[l for l in open(vmx) if not re.match(r'^(ethernet\d+\.|memsize|numvcpus|displayName)',l)]
lines.append(f'displayName = "{name}"\n')
lines.append(f'memsize = "{mem}"\n')
lines.append(f'numvcpus = "{cpu}"\n')
for i,spec in enumerate(nics.split(' ')):
    vnet,mac=spec.split(',',1)
    lines += [f'ethernet{i}.present = "TRUE"\n',
              f'ethernet{i}.virtualDev = "vmxnet3"\n',
              f'ethernet{i}.connectionType = "{"nat" if vnet=="vmnet8" else "custom"}"\n',
              f'ethernet{i}.vnet = "{vnet}"\n',
              f'ethernet{i}.addressType = "static"\n',
              f'ethernet{i}.address = "{mac}"\n']
open(vmx,'w').writelines(lines)
PY
done
echo; echo "복제 완료. 다음: scripts/configure.sh 로 주소와 이름을 넣습니다."
"$VMRUN" list
