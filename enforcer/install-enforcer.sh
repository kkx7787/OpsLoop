#!/usr/bin/env bash
# 데이터 노드에 차단 집행기(opsloop-enforcer)를 설치한다 (이슈 #47 · #51 · #77). 타이머를 새로 켜지는 않는다 (관문 동기화를 깔고 확인한 뒤
# 직접 켠다). 이미 켜져 있으면 설치하는 동안 멈췄다가 끝나면(실패해도) 다시 켠다.
# 여러 번 돌려도 된다. 이미 있는 사용자 · 비밀번호 · 설정은 지키고, 무엇을 했는지 찍는다.
#
# 하는 일: 사용자 opsloop-enforcer · 상태 폴더 /var/lib/opsloop-enforcer, 코드 /opt/opsloop/enforcer (root 소유),
#   래퍼 /usr/local/bin/opsloop-enforcer, 설정 /etc/default/opsloop-enforcer (처음만), DB 역할 opsloop_enforcer 와
#   접속 파일 /etc/opsloop/enforcer.env, 마이그레이션 네 개(20260927_block_enforce.sql → 20260929_block_points.sql →
#   20260930_status_board.sql → 20261003_block_points_choice.sql, 이 순서. #47 이 집행 역할의 표 권한을 먼저 모두 거두므로 #51 · #52 가
#   뒤에 와야 enforcement 쓰기 · 생존 신호 표 쓰기 권한이 남는다. #77 은 권한을 주지 않고 요청 지점 열 · 트리거만 둔다),
#   systemd 단위 (켜지 않음),
#   OPSLOOP_FW_ID 를 주면 설정에 내부 방화벽 줄 (없을 때만).
# 순서: DB(역할 · 마이그레이션)를 코드보다 먼저 바꾼다. 옛 코드는 새 열을 모르므로 스키마가 먼저 바뀌어도 그대로 돌고,
#   마이그레이션이 실패하면 코드를 바꾸지 않고 멈춘다 ('새 코드 · 옛 스키마' 가 생기지 않는다).
# 안 하는 일: S3 쓰기 키(/etc/opsloop/s3-block.env)는 만들지 않는다. Mac 에서 aws iam create-access-key 출력을
#   파이프로 바로 넣는다 (infra/terraform/README.md '차단 목록 전달'). 관문 보고를 읽는 키는 적재기의
#   /etc/opsloop/s3-pull.env (원장 읽기 사용자, hb/* 읽기)를 그대로 쓴다.
#
# 비밀 파일 셋(enforcer.env · s3-block.env · s3-pull.env)은 서비스가 systemd LoadCredential 로 받는다. 그래서 새 파일은
# 0600 root:root 로 두고, 집행기 사용자를 opsloop-pull 그룹(적재 · 탐지 접속 파일도 읽는다)에 넣지 않는다.
# DB 역할의 비밀번호는 여기서 만들어 /etc/opsloop/enforcer.env 에만 둔다. 화면 · 셸 이력 · 명령행 인자(ps)에 남기지 않는다.
# DB 에는 표준 입력으로 SCRAM 검증값만 넘긴다. 역할을 만든 뒤 마이그레이션을 적용해야 권한 블록이 권한을 준다.
#
# 먼저 puller/install-ingest.sh · collector/install-collector.sh 가 깔려 있어야 한다 (스키마 · /etc/opsloop · DB 컨테이너).
#
# 사용 (Mac, 저장소 루트):
#   C=$(git rev-parse --short HEAD); git archive "$C" enforcer infra/migrations/20260927_block_enforce.sql infra/migrations/20260929_block_points.sql infra/migrations/20260930_status_board.sql infra/migrations/20261003_block_points_choice.sql | ssh -F ~/.ssh/config.opsloop data01 "rm -rf /tmp/ol && mkdir /tmp/ol && tar -x -C /tmp/ol && sudo bash /tmp/ol/enforcer/install-enforcer.sh $C"
#   내부 방화벽까지: 마지막을 "sudo OPSLOOP_FW_ID=fw-opsloop bash /tmp/ol/enforcer/install-enforcer.sh $C" 로
set -euo pipefail
VERSION=${1:?커밋}
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DB=opsloop-db                  # compose/data.yml 의 PostgreSQL 컨테이너
DB_HOST=192.168.60.11          # DB 는 이 주소에만 묶여 있다
CODE=/opt/opsloop/enforcer
STATE=/var/lib/opsloop-enforcer
ENV_FILE=/etc/opsloop/enforcer.env
MIGRATION=infra/migrations/20260927_block_enforce.sql
# 집행 지점 · 시험 출발지 (이슈 #51). #47 이 집행 역할의 표 권한을 먼저 모두 거두므로 반드시 그 뒤에 적용한다
MIGRATION51=infra/migrations/20260929_block_points.sql
# 관제 대상 상태판 생존 신호 표 (이슈 #52). 같은 까닭으로 #47 · #51 뒤에 적용한다(집행기가 관문 · 내부 방화벽 보고 시각을 쓴다)
MIGRATION52=infra/migrations/20260930_status_board.sql
# 차단 적용 지점 선택 (이슈 #77). 권한을 주지 않아 순서와 무관하지만 반영 순서(27 → 29 → 30 → 77)대로 마지막에 적용한다.
# 집행기는 요청 지점(blocklist.points)을 to_jsonb 로 읽어 열이 없어도 돌고(두 지점), 이 열을 고치지 않는다(읽기만)
MIGRATION77=infra/migrations/20261003_block_points_choice.sql
# 내부 방화벽 동기화의 OPSLOOP_HOST (선택 · 이슈 #51). 주면 설정 파일에 없을 때만 더한다
FW_ID=${OPSLOOP_FW_ID:-}
BUCKET=${OPSLOOP_BUCKET:-opsloop-archive-739272173045}
GATEWAY_ID=${OPSLOOP_GATEWAY_ID:-i-0ffeb29efad03546d}   # 관문 인스턴스 (terraform state show aws_instance.gateway)
PSQL=(docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -qAt)

echo "== 사전 확인"
[ "$(id -u)" = 0 ] || { echo "root 로 돌린다 (sudo bash $0 $VERSION)" >&2; exit 1; }
for f in enforcer/block_enforcer.py enforcer/opsloop-enforcer.service enforcer/opsloop-enforcer.timer "$MIGRATION" "$MIGRATION51" "$MIGRATION52" \
         "$MIGRATION77"; do
  [ -e "$SRC/$f" ] || { echo "받은 파일에 $f 가 없다. git archive 에 enforcer $MIGRATION $MIGRATION51 $MIGRATION52 $MIGRATION77 를 넣는다" >&2; exit 1; }
done
[[ "$GATEWAY_ID" =~ ^i-[0-9a-f]{8,17}$ ]] || { echo "OPSLOOP_GATEWAY_ID 가 인스턴스 ID 가 아니다: $GATEWAY_ID" >&2; exit 1; }
[ -z "$FW_ID" ] || [[ "$FW_ID" =~ ^fw-[a-z0-9-]{1,40}$ ]] || { echo "OPSLOOP_FW_ID 가 fw-<이름> 꼴이 아니다: $FW_ID" >&2; exit 1; }
[ -d /etc/opsloop ] || { echo "/etc/opsloop 이 없다. puller/install-ingest.sh 를 먼저 돌린다" >&2; exit 1; }
[ "$(docker inspect -f '{{.State.Running}}' "$DB" 2>/dev/null)" = true ] || { echo "DB 컨테이너 $DB 가 돌고 있지 않다" >&2; exit 1; }
[ "$("${PSQL[@]}" -c "SELECT to_regclass('blocklist') IS NOT NULL AND to_regclass('events') IS NOT NULL")" = t ] \
  || { echo "blocklist · events 표가 없다. collector/install-collector.sh 로 스키마를 먼저 적용한다" >&2; exit 1; }
python3 -B -c "import ast, sys; ast.parse(open(sys.argv[1], encoding='utf-8').read())" "$SRC/enforcer/block_enforcer.py" \
  || { echo "enforcer/block_enforcer.py 를 읽지 못했다" >&2; exit 1; }
echo "  확인 끝 (원본 $SRC, 커밋 $VERSION)"

echo "== 패키지"
export DEBIAN_FRONTEND=noninteractive
python3 -c 'import psycopg2' 2>/dev/null || { apt-get update -qq && apt-get install -y -qq python3-psycopg2; }
python3 -c 'import boto3' 2>/dev/null || apt-get install -y -qq python3-boto3
systemctl --version | awk 'NR==1 && $2 < 247 {print "  경고: systemd " $2 " 는 LoadCredential 을 모른다 (247 이상)"; exit}' >&2
echo "  python3-psycopg2 · python3-boto3 있음"

echo "== 사용자 · 폴더"
if id opsloop-enforcer >/dev/null 2>&1; then echo "  사용자 opsloop-enforcer 있음"; else
  useradd --system --shell /usr/sbin/nologin --home "$STATE" opsloop-enforcer; echo "  사용자 opsloop-enforcer 만들었다"; fi
install -d -o opsloop-enforcer -g opsloop-enforcer -m 750 "$STATE"
echo "  $STATE ($(stat -c '%U:%G %a' "$STATE"). 상태 · 잠금)"
# 비밀은 LoadCredential 로 받으므로 /etc/opsloop 을 지나갈 권한(ACL)을 주지 않는다
if getfacl -cp /etc/opsloop 2>/dev/null | grep -q '^user:opsloop-enforcer:'; then
  echo "  경고: /etc/opsloop 에 opsloop-enforcer ACL 이 있다. 필요 없으니 setfacl -x u:opsloop-enforcer /etc/opsloop 로 뺀다" >&2
fi

echo "== 타이머 (설치하는 동안 멈춘다)"
timer_was=$(systemctl is-active opsloop-enforcer.timer 2>/dev/null || true)
if [ "$timer_was" = active ]; then
  systemctl stop opsloop-enforcer.timer
  for _ in $(seq 1 60); do systemctl is-active -q opsloop-enforcer.service || break; sleep 1; done   # 도는 회차가 끝나기를 기다린다
  # 끝나거나 도중에 멈춰도 다시 켠다. DB 를 먼저 바꾸므로 어느 지점에서 멈춰도 돌던 코드가 그 스키마에서 돈다
  trap 'systemctl start opsloop-enforcer.timer && echo "  타이머를 다시 켰다"' EXIT
  echo "  멈췄다 (끝나면 다시 켠다)"
else
  echo "  켜져 있지 않다 (${timer_was:-없음}. 새로 켜지 않는다)"
fi

ensure_env() { # $1 파일  $2 DB 역할
  local f=$1 role=$2
  rm -f "$f.tmp"
  if [ -s "$f" ] && grep -q "^DATABASE_URL=postgresql://$role:" "$f"; then
    chown root:root "$f"; chmod 600 "$f"
    echo "  $f 있음 ($role). 비밀번호는 그대로 둔다 ($(stat -c '%U:%G %a' "$f"))"; return
  fi
  if [ -s "$f" ]; then
    mv "$f" "$f.prev" && chmod 600 "$f.prev" && chown root:root "$f.prev"
    echo "  $f 의 역할이 $role 이 아니다. $f.prev 로 옮기고 새로 만든다 (확인 뒤 지운다)"
  fi
  ( umask 077
    python3 - "$role" "$DB_HOST" > "$f.tmp" <<'PY'
import secrets, sys
# URL 안전 문자만 나오므로 인코딩이 필요 없다
print(f"DATABASE_URL=postgresql://{sys.argv[1]}:{secrets.token_urlsafe(32)}@{sys.argv[2]}:5432/opsloop")
PY
  )
  chown root:root "$f.tmp"; chmod 600 "$f.tmp"; mv "$f.tmp" "$f"
  echo "  $f 새 비밀번호로 만들었다 (0600 root:root. 화면에는 찍지 않는다)"
}

# 접속 파일로 실제 로그인이 되는지. 비밀번호는 파일에서만 읽는다
env_login() { # $1 파일
  python3 - "$1" <<'PY' >/dev/null 2>&1
import sys, psycopg2
env = dict(l.strip().split("=", 1) for l in open(sys.argv[1], encoding="utf-8") if "=" in l and not l.startswith("#"))
psycopg2.connect(env["DATABASE_URL"].strip(), connect_timeout=10).close()
PY
}

ensure_role() { # $1 DB 역할  $2 접속 파일  $3 접속 한도
  local role=$1 f=$2 limit=$3 exists
  exists=$("${PSQL[@]}" -c "SELECT 1 FROM pg_roles WHERE rolname = '$role'")
  if [ "$exists" = 1 ] && env_login "$f"; then
    # 속성(NOINHERIT · 접속 한도)은 비밀번호 없이 맞춘다. 손으로 바뀌었어도 계약대로 되돌린다
    "${PSQL[@]}" -c "ALTER ROLE $role WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT $limit" >/dev/null
    echo "  $role 있음. $f 로 로그인된다. 비밀번호는 그대로 둔다"; return
  fi
  # 역할이 없거나 비밀번호가 파일과 다르다. 파일의 비밀번호로 SCRAM 검증값을 만들어 표준 입력으로만 넘긴다
  python3 - "$role" "$f" "$limit" <<'PY' | "${PSQL[@]}" >/dev/null 2>&1 || { echo "  $role 을 만들거나 고치지 못했다 (오류 문장은 검증값을 담을 수 있어 찍지 않는다)" >&2; exit 1; }
import base64, hashlib, hmac, os, sys, urllib.parse
role, path, limit = sys.argv[1:4]
env = {}
for line in open(path, encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
u = urllib.parse.urlsplit(env.get("DATABASE_URL", ""))
pw = urllib.parse.unquote(u.password or "")
if u.username != role or not pw:
    sys.exit(1)
# PostgreSQL 이 저장하는 형식 그대로: SCRAM-SHA-256$반복:솔트$StoredKey:ServerKey (RFC 5802 · 7677)
salt, it = os.urandom(16), 4096
salted = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, it)
client = hmac.new(salted, b"Client Key", "sha256").digest()
server = hmac.new(salted, b"Server Key", "sha256").digest()
b64 = lambda x: base64.b64encode(x).decode()
verifier = f"SCRAM-SHA-256${it}:{b64(salt)}${b64(hashlib.sha256(client).digest())}:{b64(server)}"
attrs = f"LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT {int(limit)}"
print(f"""DO $ol$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
    ALTER ROLE {role} WITH {attrs} PASSWORD '{verifier}';
  ELSE
    CREATE ROLE {role} WITH {attrs} PASSWORD '{verifier}';
  END IF;
END $ol$;""")
PY
  if [ "$exists" = 1 ]; then echo "  $role 비밀번호를 $f 에 맞췄다"; else echo "  $role 만들었다 (접속 $limit 개 한도, 권한은 마이그레이션이 준다)"; fi
}

echo "== DB 접속 파일"
ensure_env "$ENV_FILE" opsloop_enforcer

echo "== DB 역할"
# 한 회차에 접속 하나. 손으로 status 를 돌리는 몫까지 2
ensure_role opsloop_enforcer "$ENV_FILE" 2

echo "== 마이그레이션 ($MIGRATION, 여러 번 돌려도 같다)"
# 역할을 만든 뒤에 적용해야 권한 블록(IF EXISTS opsloop_enforcer)이 권한을 준다. 역할 블록(schema.sql · 20260924_db_roles.sql)을
# 다시 적용하면 모든 표의 권한을 먼저 거두므로, 그 뒤에는 이 설치기(또는 이 파일)를 다시 돌린다
docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" \
  psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q < "$SRC/$MIGRATION" >/dev/null
echo "  적용했다"
echo "== 마이그레이션 ($MIGRATION51, #47 뒤. 여러 번 돌려도 같다)"
docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" \
  psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q < "$SRC/$MIGRATION51" >/dev/null
echo "  적용했다"
echo "== 마이그레이션 ($MIGRATION52, #47 · #51 뒤. 여러 번 돌려도 같다)"
docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" \
  psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q < "$SRC/$MIGRATION52" >/dev/null
echo "  적용했다"
echo "== 마이그레이션 ($MIGRATION77, #52 뒤. 여러 번 돌려도 같다. 잠금을 5초 안에 못 얻으면 실패하니 다시 돌린다)"
docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" \
  psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q < "$SRC/$MIGRATION77" >/dev/null
echo "  적용했다"
# 역할별 권한 표. 기대값과 다르면 경고만 하고 계속한다 (마이그레이션을 고친 뒤 다시 돌린다)
check_priv() { # $1 이름  $2 기대  $3 SQL(불리언 열들)
  local got; got=$("${PSQL[@]}" -F ' ' -c "$3" 2>/dev/null || echo 조회실패)
  if [ "$got" = "$2" ]; then echo "  $1: 기대대로 ($2)"; else echo "  경고: $1 권한이 예상과 다르다 (얻음 $got, 기대 $2)" >&2; fi
}
check_priv "집행 blocklist 읽기 · 집행 네 열 갱신 · 차단 금지 대역 읽기 · 만료 기록 실행" "t t t t" \
  "SELECT has_table_privilege('opsloop_enforcer','blocklist','SELECT'),
          has_column_privilege('opsloop_enforcer','blocklist','enforced_at','UPDATE')
            AND has_column_privilege('opsloop_enforcer','blocklist','method','UPDATE')
            AND has_column_privilege('opsloop_enforcer','blocklist','enforce_note','UPDATE')
            AND has_column_privilege('opsloop_enforcer','blocklist','enforcement','UPDATE'),
          has_table_privilege('opsloop_enforcer','block_exempt','SELECT'),
          has_function_privilege('opsloop_enforcer','note_block_expired(inet,timestamp with time zone)','EXECUTE')"
check_priv "집행 만료 갱신 · 해제 갱신 · 주소 갱신 · 차단 삽입 · 차단 삭제 · 금지 대역 삽입 · events 읽기 · events 삽입 · 사건 읽기" \
  "f f f f f f f f f" \
  "SELECT has_column_privilege('opsloop_enforcer','blocklist','expires_at','UPDATE'),
          has_column_privilege('opsloop_enforcer','blocklist','released_at','UPDATE'),
          has_column_privilege('opsloop_enforcer','blocklist','actor_ip','UPDATE'),
          has_table_privilege('opsloop_enforcer','blocklist','INSERT'), has_table_privilege('opsloop_enforcer','blocklist','DELETE'),
          has_table_privilege('opsloop_enforcer','block_exempt','INSERT'),
          has_table_privilege('opsloop_enforcer','events','SELECT'), has_table_privilege('opsloop_enforcer','events','INSERT'),
          has_table_privilege('opsloop_enforcer','incidents','SELECT')"
check_priv "집행 생존 신호 표 읽기 · 넣기 · 고치기 · 지우기" "t t t f" \
  "SELECT has_table_privilege('opsloop_enforcer','sensor_heartbeats','SELECT'),
          has_table_privilege('opsloop_enforcer','sensor_heartbeats','INSERT'),
          has_table_privilege('opsloop_enforcer','sensor_heartbeats','UPDATE'),
          has_table_privilege('opsloop_enforcer','sensor_heartbeats','DELETE')"
# 요청 지점 (이슈 #77). 집행기는 읽기만 하고, 지점은 콘솔 · triage 만 고친다
check_priv "집행 points 읽기 · points 갱신" "t f" \
  "SELECT has_column_privilege('opsloop_enforcer','blocklist','points','SELECT'),
          has_column_privilege('opsloop_enforcer','blocklist','points','UPDATE')"
check_priv "집행 역할 NOINHERIT · 접속 한도 2 · PUBLIC 만료 기록 실행" "f 2 f" \
  "SELECT rolinherit, rolconnlimit, has_function_privilege('public','note_block_expired(inet,timestamp with time zone)','EXECUTE')
     FROM pg_roles WHERE rolname = 'opsloop_enforcer'"

echo "== 코드 $VERSION → $CODE (root 소유. 집행기가 자기 코드를 바꿀 수 없다)"
# 적재기 앱 폴더(/opt/opsloop/app)와 따로 둔다. install-ingest.sh 가 앱 폴더를 통째로 바꿔도 사라지지 않는다
install -d -m 755 /opt/opsloop
rm -rf /opt/opsloop/.enforcer.new
install -d -m 755 /opt/opsloop/.enforcer.new
install -m 644 "$SRC/enforcer/block_enforcer.py" /opt/opsloop/.enforcer.new/block_enforcer.py
echo "$VERSION" > /opt/opsloop/.enforcer.new/VERSION
chown -R root:root /opt/opsloop/.enforcer.new
rm -rf /opt/opsloop/enforcer.old
if [ -d "$CODE" ]; then mv "$CODE" /opt/opsloop/enforcer.old; echo "  이전 판은 /opt/opsloop/enforcer.old"; fi
mv /opt/opsloop/.enforcer.new "$CODE"
# shellcheck disable=SC2012  # 깐 파일 이름을 화면에 보이기만 한다 (이름은 저장소 파일이다)
ls "$CODE" | sed 's/^/    /'
cat > /usr/local/bin/opsloop-enforcer.new <<'EOT'
#!/bin/sh
# 차단 집행기 실행 래퍼 (이슈 #47). enforcer/install-enforcer.sh 가 깐다. 코드는 root 소유 사본이다.
# 타이머: opsloop-enforcer.service (opsloop-enforcer 사용자, run). 손으로는 root 로 status · list · run --dry-run
exec /usr/bin/python3 /opt/opsloop/enforcer/block_enforcer.py "$@"
EOT
chmod 755 /usr/local/bin/opsloop-enforcer.new
mv /usr/local/bin/opsloop-enforcer.new /usr/local/bin/opsloop-enforcer
echo "  래퍼 /usr/local/bin/opsloop-enforcer → $CODE/block_enforcer.py"

echo "== 설정 (/etc/default/opsloop-enforcer, 비밀 아님)"
# 처음 설치할 때만 만든다. 이미 있으면 손으로 바꾼 값을 지키려고 덮어쓰지 않는다
if [ ! -s /etc/default/opsloop-enforcer ]; then
  cat > /etc/default/opsloop-enforcer <<EOT
OPSLOOP_BUCKET=$BUCKET
OPSLOOP_GATEWAY_ID=$GATEWAY_ID
OPSLOOP_ENFORCER_HOME=$STATE
AWS_DEFAULT_REGION=ap-northeast-2
EOT
  chmod 644 /etc/default/opsloop-enforcer
  echo "  만들었다"
fi
# 내부 방화벽 (이슈 #51). 이미 있는 설정 파일에도 줄이 없을 때만 더한다 (손으로 바꾼 값은 지킨다)
if [ -n "$FW_ID" ] && ! grep -q '^OPSLOOP_FW_ID=' /etc/default/opsloop-enforcer; then
  echo "OPSLOOP_FW_ID=$FW_ID" >> /etc/default/opsloop-enforcer
  echo "  OPSLOOP_FW_ID=$FW_ID 를 더했다"
fi
sed 's/^/    /' /etc/default/opsloop-enforcer

# ── DB 역할 · 접속 파일 ──────────────────────────────────────────────────────
# 아래 세 함수는 cti/install-cti.sh 의 것을 옮기고 접속 파일만 0600 root:root 로 바꿨다 (서비스는 LoadCredential 로 받는다).
#   enforcer.env   opsloop_enforcer   root:root 0600   집행기 (blocklist 읽기 · 집행 세 열 갱신, block_exempt 읽기, 만료 기록)
echo "== systemd 단위 (켜지 않는다)"
for u in opsloop-enforcer.service opsloop-enforcer.timer; do
  if cmp -s "$SRC/enforcer/$u" "/etc/systemd/system/$u"; then echo "  $u 그대로"; else
    install -m 644 "$SRC/enforcer/$u" "/etc/systemd/system/$u"; echo "  $u 설치했다"; fi
done
systemctl daemon-reload
echo "  opsloop-enforcer.timer: $(systemctl is-enabled opsloop-enforcer.timer 2>/dev/null || true) / $(systemctl is-active opsloop-enforcer.timer 2>/dev/null || true)"

echo "== S3 키 (서비스가 LoadCredential 로 받는다. 하나라도 없으면 서비스가 시작되지 않는다)"
keys_ok=1
if [ -s /etc/opsloop/s3-block.env ]; then
  if [ "$(stat -c '%U:%G %a' /etc/opsloop/s3-block.env)" != "root:root 600" ]; then
    chown root:root /etc/opsloop/s3-block.env; chmod 600 /etc/opsloop/s3-block.env; echo "  s3-block.env 권한을 0600 root:root 로 맞췄다"
  fi
  echo "  s3-block.env 있음 ($(stat -c '%U:%G %a' /etc/opsloop/s3-block.env))"
else
  keys_ok=0
  echo "  s3-block.env 없음. Mac 에서 목록 쓰기 사용자 키를 파이프로 넣는다 (infra/terraform/README.md '차단 목록 전달')"
fi
if [ -s /etc/opsloop/s3-pull.env ]; then
  echo "  s3-pull.env 있음 ($(stat -c '%U:%G %a' /etc/opsloop/s3-pull.env). 적재기와 같은 원장 읽기 키 · 권한은 그대로 둔다)"
else
  keys_ok=0
  echo "  s3-pull.env 없음. puller/install-ingest.sh 안내대로 원장 읽기 키를 먼저 넣는다" >&2
fi

echo "== 접속 확인"
env_login "$ENV_FILE" && echo "  집행 역할(opsloop_enforcer) 로그인 성공" || echo "  집행 역할 로그인 실패 ($DB_HOST:5432)" >&2
# 집행 역할로 목록을 만들어 본다 (DB 만 읽는다. 올리지 않는다). 마지막 줄이 행 갈래별 건수다
if out=$(/usr/local/bin/opsloop-enforcer list 2>&1); then
  printf '%s\n' "$out" | tail -n 1 | sed 's/^/  /'
else
  printf '%s\n' "$out" | tail -n 5 | sed 's/^/  /' >&2
  echo "  집행 역할로 목록을 만들지 못했다 (마이그레이션 · 권한을 본다)" >&2
fi
if [ "$keys_ok" = 1 ]; then
  # 관문 보고까지 읽고 할 일만 찍는다 (S3 · DB · 상태 파일을 고치지 않는다)
  out=$(/usr/local/bin/opsloop-enforcer run --dry-run 2>&1) || true
  printf '%s\n' "$out" | tail -n 5 | sed 's/^/  /'
fi

echo "설치 완료 ($VERSION). 타이머는 켜지 않았다."
echo "  목록 보기     sudo opsloop-enforcer list"
echo "  할 일 보기    sudo opsloop-enforcer run --dry-run"
echo "  한 번 실행    sudo systemctl start opsloop-enforcer.service; journalctl -u opsloop-enforcer -n 20"
echo "  상태          sudo opsloop-enforcer status"
echo "  켜기          sudo systemctl enable --now opsloop-enforcer.timer   (관문 동기화 opsloop-block-sync 가 돈 뒤)"
