#!/usr/bin/env bash
# 데이터 노드에 관제 대상 수집(수집 관문 · 1분 다리 · 관리 CLI)을 설치한다. 관문 · 타이머는 켜지 않는다 (확인 후 직접 켠다).
# 여러 번 돌려도 된다. 이미 있는 사용자 · 비밀번호 · 설정은 지키고, 무엇을 했는지 찍는다.
#
# 먼저 같은 커밋으로 puller/install-ingest.sh 를 돌려 parser · detector · puller 와 /etc/opsloop/collector.env 를 깔아 둔다.
# install-ingest.sh 는 /opt/opsloop/app 을 통째로 바꾸므로 collector/ 가 빠진다. 그 뒤에는 이 스크립트를 다시 돌린다.
#
# 관문 DB 역할(opsloop_gate)의 비밀번호는 여기서 만들어 /etc/opsloop/gate.env 에만 둔다.
# 화면 · 셸 이력 · 명령행 인자(ps)에 남기지 않는다. DB 에는 표준 입력으로 SCRAM 검증값만 넘긴다
# (문장이 실패해 서버 로그에 남아도 비밀번호가 아니다).
#
# 사용 (Mac, 저장소 루트):
#   C=$(git rev-parse --short HEAD)
#   git archive "$C" parser detector puller collector infra/schema.sql \
#     | ssh -F ~/.ssh/config.opsloop data01 "rm -rf /tmp/ol && mkdir /tmp/ol && tar -x -C /tmp/ol \
#         && sudo bash /tmp/ol/puller/install-ingest.sh $C && sudo bash /tmp/ol/collector/install-collector.sh $C"
set -euo pipefail
VERSION=${1:?커밋}
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DB=opsloop-db                  # compose/data.yml 의 PostgreSQL 컨테이너
LOKI=opsloop-loki
DB_HOST=192.168.60.11          # DB 는 이 주소에만 묶여 있다
APP=/opt/opsloop/app
STATE=/var/lib/opsloop
GATE_DIR=$STATE/gate
ADMIN_DIR=$STATE/admin
GATE_ENV=/etc/opsloop/gate.env
ENV_SRC=/home/ops/opsloop/.env   # compose 의 소유자 비밀번호 (admin.env 를 만들 때만 읽는다)
PSQL=(docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -qAt)

echo "== 사전 확인"
[ "$(id -u)" = 0 ] || { echo "root 로 돌린다 (sudo bash $0 $VERSION)" >&2; exit 1; }
for f in collector/pull_loki.py collector/opsloop-agents.service collector/opsloop-agents.timer infra/schema.sql; do
  [ -e "$SRC/$f" ] || { echo "받은 파일에 $f 가 없다. git archive 에 collector infra/schema.sql 을 넣는다" >&2; exit 1; }
done
missing=0
for p in "$APP" /etc/default/opsloop-ingest /etc/opsloop/collector.env; do
  [ -e "$p" ] || { echo "  없음: $p" >&2; missing=1; }
done
[ "$missing" = 0 ] || { echo "puller/install-ingest.sh 를 같은 커밋으로 먼저 돌린다" >&2; exit 1; }
[ "$(docker inspect -f '{{.State.Running}}' "$DB" 2>/dev/null)" = true ] || { echo "DB 컨테이너 $DB 가 돌고 있지 않다" >&2; exit 1; }
python3 -c 'import psycopg2' 2>/dev/null || { export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq python3-psycopg2; }
command -v setfacl >/dev/null || { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq acl; }
echo "  확인 끝 (원본 $SRC, 커밋 $VERSION)"

echo "== 사용자 · 폴더"
if id opsloop-pull >/dev/null 2>&1; then echo "  사용자 opsloop-pull 있음"; else
  useradd --system --shell /usr/sbin/nologin --home /var/lib/opsloop opsloop-pull; echo "  사용자 opsloop-pull 만들었다"; fi
if id opsloop-gate >/dev/null 2>&1; then echo "  사용자 opsloop-gate 있음"; else
  useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent --no-create-home opsloop-gate
  echo "  사용자 opsloop-gate 만들었다"; fi
# 관문은 원장 폴더까지 지나가기만 하면 된다. /var/lib/opsloop 의 다른 파일(미러 · 상태)은 읽지 못하게
# 그룹 대신 ACL 로 지나가기(x)만 준다. install-ingest.sh 가 750 으로 되돌려도 ACL 은 남는다
if getfacl -cp "$STATE" 2>/dev/null | grep -qx 'user:opsloop-gate:--x'; then
  echo "  $STATE 지나가기 권한(opsloop-gate) 있음"
else
  setfacl -m u:opsloop-gate:x "$STATE"; echo "  $STATE 에 opsloop-gate 지나가기 권한을 줬다 (ACL)"
fi
before=$(stat -c '%U:%G %a' "$GATE_DIR" 2>/dev/null || echo 없음)
# setgid: 관문 · nodes.py 가 만든 원장 파일이 opsloop-pull 그룹을 받아 다리가 읽는다
install -d -o opsloop-gate -g opsloop-pull -m 2750 "$GATE_DIR"
after=$(stat -c '%U:%G %a' "$GATE_DIR")
[ "$before" = "$after" ] && echo "  $GATE_DIR 그대로 ($after)" || echo "  $GATE_DIR $before → $after"
install -d -o root -g opsloop-pull -m 750 /etc/opsloop
# 관리 원장(nodes.py 의 발급 · 취소 · 폐기)은 관문이 쓸 수 없는 폴더에 둔다. 관문이 장악돼도 지우거나 가로채지 못한다
install -d -o root -g opsloop-pull -m 2750 "$ADMIN_DIR"
for f in "$GATE_DIR"/admin-*.jsonl; do
  [ -f "$f" ] || continue
  if [ "$(stat -c %u "$f")" = 0 ] && [ ! -L "$f" ]; then
    mv -n "$f" "$ADMIN_DIR/" && echo "  관리 원장을 옮겼다: $(basename "$f") → $ADMIN_DIR"
  else
    echo "  경고: $f 는 root 가 쓴 파일이 아니다. 옮기지 않는다 (위조 의심)" >&2
  fi
done

echo "== 코드 $VERSION → $APP/collector (root 소유. 파이프라인이 자기 코드를 바꿀 수 없다)"
rm -rf "$APP/.collector.new"
cp -r "$SRC/collector" "$APP/.collector.new"
find "$APP/.collector.new" -name '__pycache__' -prune -exec rm -rf {} +
echo "$VERSION" > "$APP/.collector.new/VERSION"
chown -R root:root "$APP/.collector.new"
chmod -R u+rwX,go+rX,go-w "$APP/.collector.new"
for f in nodes.py gate.py pull_loki.py; do
  if [ -e "$APP/.collector.new/$f" ]; then chmod 755 "$APP/.collector.new/$f"; fi
done
rm -rf "$APP/collector.old"
if [ -d "$APP/collector" ]; then mv "$APP/collector" "$APP/collector.old"; echo "  이전 판은 $APP/collector.old"; fi
mv "$APP/.collector.new" "$APP/collector"
ls "$APP/collector" | sed 's/^/    /'
app_ver=$(cat "$APP/VERSION" 2>/dev/null || echo 없음)
[ "$app_ver" = "$VERSION" ] || echo "  경고: parser · detector 는 커밋 $app_ver 이다. 같은 커밋으로 install-ingest.sh 를 돌리고 이 스크립트를 다시 돌린다"
# 다리가 돌리는 규칙 파일은 pull_loki.py RULESETS 와 같다 (s1 · w2 · a1 · i2)
for f in parser/parse_agent.py parser/exclusions.txt detector/detect.py detector/rules_self.json \
         detector/rules_w1.json detector/rules_audit.json detector/rules_infra.json; do
  [ -e "$APP/$f" ] || echo "  경고: $APP/$f 가 없다. 다리가 적재 · 탐지를 하지 못한다"
done
grep -q -- '--quiet' "$APP/detector/detect.py" 2>/dev/null || echo "  경고: detect.py 가 --quiet 를 모른다 (구판). 다리의 탐지가 실패한다"
{ grep -q '"operator_rate"' "$APP/detector/detect.py" && grep -q '"node_silence"' "$APP/detector/detect.py"; } 2>/dev/null \
  || echo "  경고: detect.py 가 operator_rate · node_silence 를 모른다 (구판). 다리의 a1 · i2 탐지가 실패한다"
# 구판은 i2 의 관문 거부 쪼개기를 모르고 넘어가 9/21 같은 공백을 i2 키로 다시 띄운다
grep -q 'split_on_gate_reject' "$APP/detector/detect.py" 2>/dev/null \
  || echo "  경고: detect.py 가 split_on_gate_reject 를 모른다 (구판). i2 R301 이 관문 거부 공백을 거르지 못한다"

# ── DB 역할 · 접속 파일 (이슈 #31) ────────────────────────────────────────────
# 역할마다 접속 파일 하나. 파일이 없으면 새 비밀번호로 만들고, 역할이 없거나 비밀번호가 파일과 다르면
# SCRAM 검증값으로 맞춘다. 비밀번호는 파일에만 있고 화면 · 셸 이력 · 명령행 인자 · DB 로그에 남지 않는다.
#   gate.env       opsloop_gate       root:opsloop-gate 0640   관문 (nodes 네 열 읽기 · enroll_node)
#   collector.env  opsloop_ingest     root:opsloop-pull 0640   다리 · 파서 (원문 · 세션 · 지표 적재)
#   detector.env   opsloop_detector   root:opsloop-pull 0640   탐지기 (규칙 실행 · 인시던트)
#   admin.env      opsloop (소유자)    root:root 0600           nodes.py (compose .env 의 비밀번호를 옮긴다)
#   콘솔 역할(opsloop_console)은 여기서 비밀번호 없이 만들고, infra/vmware/scripts/db-console-role.sh 가 넣는다.
#   백업 역할(opsloop_backup)은 컨테이너 안 로컬 접속(pg_dump)만 쓰므로 비밀번호가 없다.
ensure_env() { # $1 파일  $2 DB 역할  $3 소유 그룹
  local f=$1 role=$2 grp=$3
  rm -f "$f.tmp"
  if [ -s "$f" ] && grep -q "^DATABASE_URL=postgresql://$role:" "$f"; then
    echo "  $f 있음 ($role). 비밀번호는 그대로 둔다"; return
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
  chown "root:$grp" "$f.tmp"; chmod 640 "$f.tmp"; mv "$f.tmp" "$f"
  echo "  $f 새 비밀번호로 만들었다 (0640 root:$grp. 화면에는 찍지 않는다)"
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
    echo "  $role 있음. $f 로 로그인된다. 그대로 둔다"; return
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
  if [ "$exists" = 1 ]; then echo "  $role 비밀번호를 $f 에 맞췄다"; else echo "  $role 만들었다 (접속 $limit 개 한도, 권한은 스키마가 준다)"; fi
}

echo "== DB 접속 파일"
ensure_env "$GATE_ENV" opsloop_gate opsloop-gate
ensure_env /etc/opsloop/collector.env opsloop_ingest opsloop-pull
ensure_env /etc/opsloop/detector.env opsloop_detector opsloop-pull
if [ -s /etc/opsloop/admin.env ]; then
  echo "  /etc/opsloop/admin.env 있음 (소유자 · nodes.py)"
else
  ( umask 077
    python3 - "$ENV_SRC" "$DB_HOST" > /etc/opsloop/admin.env <<'PY'
import sys, urllib.parse
env = {}
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
pw = urllib.parse.quote(env["POSTGRES_PASSWORD"], safe="")
print(f"DATABASE_URL=postgresql://opsloop:{pw}@{sys.argv[2]}:5432/opsloop")
PY
  )
  chown root:root /etc/opsloop/admin.env; chmod 600 /etc/opsloop/admin.env
  echo "  /etc/opsloop/admin.env 만들었다 (소유자 · root 만 · nodes.py 가 읽는다)"
fi

echo "== DB 역할"
ensure_role opsloop_gate "$GATE_ENV" 10
ensure_role opsloop_ingest /etc/opsloop/collector.env 5
ensure_role opsloop_detector /etc/opsloop/detector.env 5
# 비밀번호 없는 역할. 백업은 컨테이너 안 로컬 접속(trust)만, 콘솔은 db-console-role.sh 가 비밀번호를 넣는다
"${PSQL[@]}" >/dev/null <<'SQL'
DO $ol$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_backup') THEN
    CREATE ROLE opsloop_backup WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT CONNECTION LIMIT 2;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
    CREATE ROLE opsloop_console WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 20;
  END IF;
END $ol$;
SQL
echo "  opsloop_backup · opsloop_console 있음 (콘솔 비밀번호는 db-console-role.sh)"

echo "== 스키마 ($SRC/infra/schema.sql, 여러 번 돌려도 안전)"
"${PSQL[@]}" < "$SRC/infra/schema.sql" >/dev/null
echo "  적용했다"
# 역할별 권한 표. 기대값과 다르면 경고만 하고 계속한다 (스키마를 고친 뒤 다시 돌린다)
check_priv() { # $1 이름  $2 기대  $3 SQL(불리언 열들)
  local got; got=$("${PSQL[@]}" -F ' ' -c "$3")
  if [ "$got" = "$2" ]; then echo "  $1: 기대대로 ($2)"; else echo "  경고: $1 권한이 예상과 다르다 (얻음 $got, 기대 $2)" >&2; fi
}
check_priv "관문 nodes.token_hash 읽기 · enroll 실행 · events 읽기 · PUBLIC enroll" "t t f f" \
  "SELECT has_column_privilege('opsloop_gate','nodes','token_hash','SELECT'),
          has_function_privilege('opsloop_gate','enroll_node(text,text,text,inet)','EXECUTE'),
          has_table_privilege('opsloop_gate','events','SELECT'),
          has_function_privilege('public','enroll_node(text,text,text,inet)','EXECUTE')"
check_priv "적재 events 삽입 · events 삭제 · incidents 삽입 · nodes.token_hash 읽기" "t f f f" \
  "SELECT has_table_privilege('opsloop_ingest','events','INSERT'), has_table_privilege('opsloop_ingest','events','DELETE'),
          has_table_privilege('opsloop_ingest','incidents','INSERT'), has_column_privilege('opsloop_ingest','nodes','token_hash','SELECT')"
# 탐지 갱신은 incidents 의 끝 시각 · 건수 · 근거 네 열만이다. 표 전체 · status 갱신은 없어야 한다
check_priv "탐지 incidents 삽입 · 삭제 · 네 열 갱신 · 표 갱신 · status 갱신 · verdicts 삽입 · events 삽입 · nodes.token_hash 읽기" "t t t f f f f f" \
  "SELECT has_table_privilege('opsloop_detector','incidents','INSERT'), has_table_privilege('opsloop_detector','incidents','DELETE'),
          has_column_privilege('opsloop_detector','incidents','last_ts','UPDATE')
            AND has_column_privilege('opsloop_detector','incidents','signal_count','UPDATE')
            AND has_column_privilege('opsloop_detector','incidents','session_count','UPDATE')
            AND has_column_privilege('opsloop_detector','incidents','evidence','UPDATE'),
          has_table_privilege('opsloop_detector','incidents','UPDATE'),
          has_column_privilege('opsloop_detector','incidents','status','UPDATE'),
          has_table_privilege('opsloop_detector','verdicts','INSERT'), has_table_privilege('opsloop_detector','events','INSERT'),
          has_column_privilege('opsloop_detector','nodes','token_hash','SELECT')"
# R301 i2 는 관문 거부 줄의 출발지를 노드의 등록 주소와 맞춘다
check_priv "탐지 nodes.addr 읽기 · nodes.agent_fp 읽기" "t f" \
  "SELECT has_column_privilege('opsloop_detector','nodes','addr','SELECT'),
          has_column_privilege('opsloop_detector','nodes','agent_fp','SELECT')"
check_priv "콘솔 verdicts 삽입 · events 삭제 · events 갱신 · incidents 삭제 · nodes.token_hash · enrollments.token_hash · console_users.role 갱신" "t f f f f f f" \
  "SELECT has_table_privilege('opsloop_console','verdicts','INSERT'), has_table_privilege('opsloop_console','events','DELETE'),
          has_table_privilege('opsloop_console','events','UPDATE'), has_table_privilege('opsloop_console','incidents','DELETE'),
          has_column_privilege('opsloop_console','nodes','token_hash','SELECT'),
          has_column_privilege('opsloop_console','node_enrollments','token_hash','SELECT'),
          has_column_privilege('opsloop_console','console_users','role','UPDATE')"
check_priv "백업 events 읽기 · events 삽입" "t f" \
  "SELECT has_table_privilege('opsloop_backup','events','SELECT'), has_table_privilege('opsloop_backup','events','INSERT')"

echo "== systemd 단위 (켜지 않는다)"
for u in opsloop-gate.service opsloop-agents.service opsloop-agents.timer; do
  if [ ! -e "$SRC/collector/$u" ]; then echo "  $u: 원본에 없어 건너뛴다"; continue; fi
  if cmp -s "$SRC/collector/$u" "/etc/systemd/system/$u"; then echo "  $u 그대로"; else
    install -m 644 "$SRC/collector/$u" "/etc/systemd/system/$u"; echo "  $u 설치했다"; fi
done
systemctl daemon-reload
for u in opsloop-gate.service opsloop-agents.timer; do
  echo "  $u: $(systemctl is-enabled "$u" 2>/dev/null || true) / $(systemctl is-active "$u" 2>/dev/null || true)"
done

echo "== 접속 확인"
env_login "$GATE_ENV" && echo "  관문 역할(opsloop_gate) 로그인 성공" || echo "  관문 역할 로그인 실패 ($DB_HOST:5432)" >&2
env_login /etc/opsloop/detector.env && echo "  탐지 역할(opsloop_detector) 로그인 성공" || echo "  탐지 역할 로그인 실패" >&2
sudo -u opsloop-pull python3 - <<'PY' && echo "  다리(opsloop-pull · opsloop_ingest) DB 접속 · 파서 읽기 성공" || echo "  다리 확인 실패" >&2
import sys
sys.path.insert(0, "/opt/opsloop/app/collector")
import pull_loki, psycopg2
url = pull_loki.read_env(pull_loki.DB_ENV)["DATABASE_URL"]
psycopg2.connect(url, connect_timeout=10).close()
pull_loki.load_agent()
PY
echo "  Loki 컨테이너 $LOKI: $(docker inspect -f '{{.State.Status}}' "$LOKI" 2>/dev/null || echo 없음)"
[ -d "$STATE/loki" ] || echo "  참고: Loki 데이터 폴더 $STATE/loki 는 운영자가 만든다"

echo "설치 완료 ($VERSION). 관문 · 타이머는 켜지 않았다."
echo "  관문 켜기   sudo systemctl enable --now opsloop-gate.service"
echo "  다리 한 번  sudo systemctl start opsloop-agents.service; journalctl -u opsloop-agents -n 40"
echo "  다리 켜기   sudo systemctl enable --now opsloop-agents.timer"
