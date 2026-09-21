#!/usr/bin/env bash
# 무인 설치용 seed 이미지를 만든다. 결과물은 저장소 밖(빌드 폴더)에 둔다.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$HOME/Virtual Machines.localized/opsloop-seed.iso}"
KEY="${SSH_PUB:-$HOME/.ssh/opsloop_ed25519.pub}"
[ -f "$KEY" ] || { echo "공개 키가 없습니다: $KEY"; exit 1; }

read -rsp "VM 콘솔 로그인 비밀번호 (ops 계정): " PW1; echo
read -rsp "다시 입력: " PW2; echo
[ "$PW1" = "$PW2" ] || { echo "입력이 일치하지 않습니다"; exit 1; }
[ ${#PW1} -ge 12 ] || { echo "12자 이상이어야 합니다"; exit 1; }
HASH="$(openssl passwd -6 "$PW1")"

BUILD="$(mktemp -d)"; trap 'rm -rf "$BUILD"' EXIT
python3 - "$HERE/seed/user-data.template" "$BUILD/user-data" "$HASH" "$(cat "$KEY")" <<'PY'
import sys
src,dst,pwhash,key=sys.argv[1:5]
open(dst,'w').write(open(src).read().replace('__PWHASH__',pwhash).replace('__SSHKEY__',key.strip()))
PY
cp "$HERE/seed/meta-data" "$BUILD/meta-data"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
# 리눅스가 읽을 수 있도록 ISO9660 로만 만든다 (HFS 를 섞으면 클라우드 설정을 못 찾는다)
hdiutil makehybrid -o "$OUT" -iso -joliet -iso-volume-name CIDATA -joliet-volume-name CIDATA "$BUILD" >/dev/null
echo "만들었습니다: $OUT"
