#!/usr/bin/env bash
# 저장소 내용을 서버에 반영한다 (서버에서 실행)
set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

sudo mkdir -p /opt/cowrie/etc
sudo cp "$REPO_DIR/scripts/cowrie.cfg" /opt/cowrie/etc/cowrie.cfg
sudo chown 999:999 /opt/cowrie/etc/cowrie.cfg

mkdir -p ~/opsloop/parser ~/opsloop/data
cp "$REPO_DIR/parser/parse_cowrie.py" ~/opsloop/parser/
[ -f ~/opsloop/parser/exclusions.txt ] || cp "$REPO_DIR/parser/exclusions.txt" ~/opsloop/parser/

echo "배포 완료."
echo "  허니팟 재기동 : $REPO_DIR/scripts/run-cowrie.sh"
echo "  로그 적재     : python3 ~/opsloop/parser/parse_cowrie.py"
