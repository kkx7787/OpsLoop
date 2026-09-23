#!/usr/bin/env bash
# 콘솔 역할(opsloop_console)의 비밀번호를 만들어 데이터 노드 DB 와 콘솔 노드의 .env 에 넣는다 (이슈 #31).
#   - 비밀번호는 이 프로세스의 환경변수와 두 노드의 파일(콘솔 ~/opsloop/.env, 데이터 노드 /etc/opsloop/triage.env)에만 있다.
#     화면 · 명령행 인자 · 원격 셸 이력 · DB 로그에 남지 않는다 (DB 에는 SCRAM 검증값만 보낸다).
#   - compose 파일(infra/vmware/compose/console.yml)도 함께 옮기고 API 컨테이너를 다시 띄운다.
#   - 역할 권한은 스키마 블록이 준다 (collector/install-collector.sh 가 적용). 이 스크립트는 비밀번호만 다룬다.
# 사용 (Mac, 저장소 루트): infra/vmware/scripts/db-console-role.sh [콘솔 별칭 …]   기본 console-a. 켜 둔 콘솔만 적는다.
#   꺼 둔 콘솔 B 는 켠 뒤 같은 명령으로 다시 돌린다 (비밀번호가 바뀌므로 A 도 함께 적는다).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SSH=(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=10)
CONSOLES=("$@"); [ ${#CONSOLES[@]} -gt 0 ] || CONSOLES=(console-a)
export OPSLOOP_PW
OPSLOOP_PW=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

echo "== 1. DB 역할 (데이터 노드. SCRAM 검증값만 보낸다)"
python3 - <<'PY' | "${SSH[@]}" data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q'
import base64, hashlib, hmac, os
pw = os.environ["OPSLOOP_PW"]
salt, it = os.urandom(16), 4096
salted = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it)
client = hmac.new(salted, b"Client Key", "sha256").digest()
server = hmac.new(salted, b"Server Key", "sha256").digest()
b64 = lambda x: base64.b64encode(x).decode()
v = f"SCRAM-SHA-256${it}:{b64(salt)}${b64(hashlib.sha256(client).digest())}:{b64(server)}"
attrs = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 20"
print(f"""DO $ol$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
    ALTER ROLE opsloop_console WITH {attrs} PASSWORD '{v}';
  ELSE
    CREATE ROLE opsloop_console WITH {attrs} PASSWORD '{v}';
  END IF;
END $ol$;""")
PY
echo "  opsloop_console 비밀번호를 바꿨다"

echo "== 2. 데이터 노드 /etc/opsloop/triage.env (root:ops 0640 · detector/triage.py 가 읽는다)"
printf '%s\n' "$OPSLOOP_PW" | "${SSH[@]}" data01 'read -r pw; printf "DATABASE_URL=postgresql://opsloop_console:%s@192.168.60.11:5432/opsloop\n" "$pw" | sudo -n install -m 640 -o root -g ops /dev/stdin /etc/opsloop/triage.env && echo "  썼다"'

for c in "${CONSOLES[@]}"; do
  echo "== 3. $c: .env · console.yml · API 컨테이너"
  printf '%s\n' "$OPSLOOP_PW" | "${SSH[@]}" "$c" 'read -r pw; f=~/opsloop/.env; umask 077; { grep -v "^OPSLOOP_CONSOLE_DB_PASSWORD=" "$f" 2>/dev/null || true; printf "OPSLOOP_CONSOLE_DB_PASSWORD=%s\n" "$pw"; } > "$f.tmp" && mv "$f.tmp" "$f" && chmod 600 "$f" && echo "  .env 갱신"'
  "${SSH[@]}" "$c" 'cat > ~/opsloop/console.yml' < "$ROOT/infra/vmware/compose/console.yml"
  "${SSH[@]}" "$c" 'cd ~/opsloop && docker compose -f console.yml up -d 2>&1 | tail -1; sleep 4; docker exec opsloop-api python3 -c "import os; print(\"  DB 역할:\", os.environ[\"DATABASE_URL\"].split(\"://\")[1].split(\":\")[0])"; curl -s -m 5 -o /dev/null -w "  /health → %{http_code}\n" http://127.0.0.1:8000/health'
done
unset OPSLOOP_PW
echo "끝. 콘솔에서 로그인 · 판정 · 차단 목록을 확인한다. 검증은 infra/vmware/scripts/verify-db-roles.sh"
