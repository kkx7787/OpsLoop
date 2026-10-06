#!/usr/bin/env bash
# 데이터 노드에 AI 판정 추천 작업기(opsloop-recommend)와 AI 서버 터널을 설치한다 (이슈 #120). 타이머와 터널은 켜지 않는다
# (서버 쪽 키 등록 · 방화벽 반영 뒤 한 번 돌려 확인하고 켠다). 여러 번 돌려도 된다. 이미 있는 사용자 · 키 · 비밀번호 · 설정은 지킨다.
#
# 하는 일: 사용자 opsloop-ai · 상태 폴더 /var/lib/opsloop-ai, 코드 /opt/opsloop/recommend (root 소유), 래퍼
#   /usr/local/bin/opsloop-recommend, 설정 /etc/default/opsloop-recommend (처음만), 터널 전용 키
#   /var/lib/opsloop-ai/.ssh/id_ed25519 (처음만), AI 서버 키 /etc/opsloop/ai-known_hosts (지문을 대조한 뒤에만),
#   DB 역할 opsloop_ai 와 접속 파일 /etc/opsloop/ai.env, 마이그레이션 infra/migrations/20261006_ai_recommend.sql,
#   systemd 단위 (켜지 않음).
# 안 하는 일: AI 서버에 키를 등록하지 않는다(설치기가 찍는 한 줄을 사람이 서버의 ~/.ssh/authorized_keys 에 넣는다).
#   방화벽(데이터 노드 → AI 서버 22)은 infra/vmware/fw/nftables.conf 를 사람이 반영한다.
#
# AI 서버 키 지문: Mac 에서 이미 접속해 본 서버라면 Mac 의 known_hosts 에서 읽는다(사람이 처음 접속 때 받아들인 키다).
#   ssh-keygen -l -F 192.168.217.248 -f ~/.ssh/known_hosts | grep ED25519      → SHA256:… 를 OPSLOOP_AI_HOSTKEY 로 넘긴다
#   지문을 주지 않거나 다르면 known_hosts 를 만들지 않고 스캔한 지문만 찍는다(터널은 서버 키 확인 실패로 붙지 않는다).
#
# 먼저 puller/install-ingest.sh · collector/install-collector.sh 가 깔려 있어야 한다 (스키마 · /etc/opsloop · DB 컨테이너).
# DB 역할의 비밀번호는 여기서 만들어 /etc/opsloop/ai.env 에만 둔다. 화면 · 셸 이력 · 명령행 인자(ps)에 남기지 않는다.
#
# 사용 (Mac, 저장소 루트):
#   C=$(git rev-parse --short HEAD); FP=$(ssh-keygen -l -F 192.168.217.248 -f ~/.ssh/known_hosts | awk '/ED25519/{print $3}')
#   git archive "$C" recommend infra/migrations/20261006_ai_recommend.sql | ssh -F ~/.ssh/config.opsloop data01 \
#     "rm -rf /tmp/ol && mkdir /tmp/ol && tar -x -C /tmp/ol && sudo OPSLOOP_AI_HOSTKEY=$FP bash /tmp/ol/recommend/install-recommend.sh $C"
set -euo pipefail
VERSION=${1:?커밋}
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DB=opsloop-db                  # compose/data.yml 의 PostgreSQL 컨테이너
DB_HOST=192.168.60.11          # DB 는 이 주소에만 묶여 있다
CODE=/opt/opsloop/recommend
STATE=/var/lib/opsloop-ai
KEY=$STATE/.ssh/id_ed25519
KNOWN=/etc/opsloop/ai-known_hosts
MIGRATION=infra/migrations/20261006_ai_recommend.sql
AI_HOST=${OPSLOOP_AI_HOST:-192.168.217.248}
AI_USER=${OPSLOOP_AI_SSH_USER:-hsm}
AI_PORT=${OPSLOOP_AI_REMOTE_PORT:-21434}
HOSTKEY=${OPSLOOP_AI_HOSTKEY:-}
PSQL=(docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -qAt)

echo "== 사전 확인"
[ "$(id -u)" = 0 ] || { echo "root 로 돌린다 (sudo bash $0 $VERSION)" >&2; exit 1; }
for f in recommend/opsloop_recommend.py recommend/opsloop-recommend recommend/opsloop-recommend.service \
         recommend/opsloop-recommend.timer recommend/opsloop-ai-tunnel.service "$MIGRATION"; do
  [ -e "$SRC/$f" ] || { echo "받은 파일에 $f 가 없다. git archive 에 recommend $MIGRATION 을 넣는다" >&2; exit 1; }
done
[ -d /etc/opsloop ] || { echo "/etc/opsloop 이 없다. puller/install-ingest.sh 를 먼저 돌린다" >&2; exit 1; }
[ "$(docker inspect -f '{{.State.Running}}' "$DB" 2>/dev/null)" = true ] || { echo "DB 컨테이너 $DB 가 돌고 있지 않다" >&2; exit 1; }
[ "$("${PSQL[@]}" -c "SELECT to_regclass('verdicts') IS NOT NULL")" = t ] \
  || { echo "verdicts 표가 없다. collector/install-collector.sh 로 스키마를 먼저 적용한다" >&2; exit 1; }
[[ "$AI_HOST" =~ ^[0-9.]+$ ]] || { echo "OPSLOOP_AI_HOST 는 IPv4 주소다 (방화벽 define AI_SERVER 와 같아야 한다)" >&2; exit 1; }
[[ "$AI_PORT" =~ ^[0-9]+$ ]] || { echo "OPSLOOP_AI_REMOTE_PORT 는 숫자다" >&2; exit 1; }
[[ "$AI_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "OPSLOOP_AI_SSH_USER 가 이상하다" >&2; exit 1; }
python3 -B -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$SRC/recommend/opsloop_recommend.py" \
  || { echo "opsloop_recommend.py 를 읽지 못했다" >&2; exit 1; }
echo "  확인 끝 (원본 $SRC, 커밋 $VERSION, AI 서버 $AI_USER@$AI_HOST → 127.0.0.1:$AI_PORT)"

echo "== 패키지"
export DEBIAN_FRONTEND=noninteractive
python3 -c 'import psycopg2' 2>/dev/null || { apt-get update -qq && apt-get install -y -qq python3-psycopg2; }
command -v ssh >/dev/null || apt-get install -y -qq openssh-client
command -v setfacl >/dev/null || apt-get install -y -qq acl
echo "  python3-psycopg2 · openssh-client · acl 있음"

echo "== 사용자 · 폴더"
if id opsloop-ai >/dev/null 2>&1; then echo "  사용자 opsloop-ai 있음"; else
  useradd --system --shell /usr/sbin/nologin --home "$STATE" opsloop-ai; echo "  사용자 opsloop-ai 만들었다"; fi
install -d -o opsloop-ai -g opsloop-ai -m 750 "$STATE"
install -d -o opsloop-ai -g opsloop-ai -m 700 "$STATE/.ssh"
echo "  $STATE ($(stat -c '%U:%G %a' "$STATE"). 터널 키)"
# /etc/opsloop 은 root:opsloop-pull 750 이라 opsloop-ai 가 지나가지 못한다. 그룹 대신 ACL 로 지나가기(x)만 준다
if getfacl -cp /etc/opsloop 2>/dev/null | grep -qx 'user:opsloop-ai:--x'; then
  echo "  /etc/opsloop 지나가기 권한(opsloop-ai) 있음"
else
  setfacl -m u:opsloop-ai:x /etc/opsloop; echo "  /etc/opsloop 에 opsloop-ai 지나가기 권한을 줬다 (ACL)"
fi

echo "== 코드 $VERSION → $CODE (root 소유. 작업기가 자기 코드를 바꿀 수 없다)"
install -d -m 755 /opt/opsloop
rm -rf /opt/opsloop/.recommend.new
install -d -m 755 /opt/opsloop/.recommend.new
install -m 644 "$SRC/recommend/opsloop_recommend.py" /opt/opsloop/.recommend.new/opsloop_recommend.py
echo "$VERSION" > /opt/opsloop/.recommend.new/VERSION
chown -R root:root /opt/opsloop/.recommend.new
rm -rf /opt/opsloop/recommend.old
if [ -d "$CODE" ]; then mv "$CODE" /opt/opsloop/recommend.old; echo "  이전 판은 /opt/opsloop/recommend.old"; fi
mv /opt/opsloop/.recommend.new "$CODE"
install -m 755 "$SRC/recommend/opsloop-recommend" /usr/local/bin/opsloop-recommend
echo "  래퍼 /usr/local/bin/opsloop-recommend → $CODE/opsloop_recommend.py"

echo "== 설정 (/etc/default/opsloop-recommend, 비밀 아님)"
# 처음 설치할 때만 만든다. 이미 있으면 손으로 바꾼 값을 지키려고 덮어쓰지 않는다(서버 주소가 바뀌면 이 파일과 방화벽 define 을 고친다)
if [ ! -s /etc/default/opsloop-recommend ]; then
  cat > /etc/default/opsloop-recommend <<EOT
OPSLOOP_AI_URL=http://127.0.0.1:$AI_PORT
OPSLOOP_AI_MODEL=gpt-oss:20b
OPSLOOP_AI_MAX_PER_RUN=10
OPSLOOP_AI_HOST=$AI_HOST
OPSLOOP_AI_SSH_USER=$AI_USER
OPSLOOP_AI_SSH_PORT=22
OPSLOOP_AI_LOCAL_PORT=$AI_PORT
OPSLOOP_AI_REMOTE_PORT=$AI_PORT
EOT
  chmod 644 /etc/default/opsloop-recommend
  echo "  만들었다"
fi
sed 's/^/    /' /etc/default/opsloop-recommend

echo "== 터널 전용 키 ($KEY)"
if [ -s "$KEY" ]; then echo "  있음. 그대로 둔다"; else
  sudo -u opsloop-ai ssh-keygen -q -t ed25519 -N '' -C "opsloop-ai@$(hostname)" -f "$KEY"; echo "  만들었다"; fi
chmod 600 "$KEY"
REMOTE_PORT=$(sed -n 's/^OPSLOOP_AI_REMOTE_PORT=//p' /etc/default/opsloop-recommend)
echo "  AI 서버 $AI_USER 의 ~/.ssh/authorized_keys 에 아래 한 줄을 넣는다 (셸 · 다른 포트 불가, Ollama 포트로만 이어진다)"
echo "    restrict,port-forwarding,permitopen=\"127.0.0.1:$REMOTE_PORT\" $(cat "$KEY.pub")"

echo "== AI 서버 키 ($KNOWN)"
SCAN=$(ssh-keyscan -T 5 -t ed25519 "$AI_HOST" 2>/dev/null | grep -v '^#' || true)
if [ -z "$SCAN" ]; then
  if [ -s "$KNOWN" ]; then echo "  지금은 서버에 닿지 않는다(학교 밖?). 이미 대조해 둔 키를 그대로 쓴다"
  else echo "  서버에 닿지 않아 키를 받지 못했다(학교 밖?). 학교 안에서 다시 돌린다" >&2; fi
else
  GOT=$(printf '%s\n' "$SCAN" | ssh-keygen -l -f - | awk '{print $2}')
  if [ -n "$HOSTKEY" ] && [ "$GOT" = "$HOSTKEY" ]; then
    ( umask 022; printf '%s\n' "$SCAN" > "$KNOWN.tmp" ); chown root:opsloop-ai "$KNOWN.tmp"; chmod 644 "$KNOWN.tmp"; mv "$KNOWN.tmp" "$KNOWN"
    echo "  지문이 맞다 ($GOT). $KNOWN 에 두었다"
  else
    echo "  받은 지문 $GOT 이 넘긴 지문(${HOSTKEY:-없음})과 다르다. $KNOWN 은 바꾸지 않았다" >&2
    echo "  Mac 의 known_hosts 지문과 대조한 뒤 OPSLOOP_AI_HOSTKEY=<지문> 으로 다시 돌린다" >&2
  fi
fi

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

# 아래 두 함수와 위 env_login 은 cti/install-cti.sh 의 것을 그대로 옮겼다 (역할마다 접속 파일 하나, SCRAM 검증값만 DB 로).
#   ai.env   opsloop_ai   root:opsloop-ai 0640   AI 추천 작업기 (사건 · 이벤트 읽기, 추천 표 추가, 상태 한 행)

echo "== DB 접속 파일"
ensure_env /etc/opsloop/ai.env opsloop_ai opsloop-ai

echo "== DB 역할"
ensure_role opsloop_ai /etc/opsloop/ai.env 2

echo "== 마이그레이션 ($MIGRATION, 여러 번 돌려도 같다)"
# 역할을 만든 뒤에 적용해야 권한 블록(IF EXISTS opsloop_ai)이 권한을 준다. 역할 블록(schema.sql · 20260924_db_roles.sql)을
# 다시 적용하면 콘솔의 추천 표 읽기가 빠지므로 그 뒤에는 이 설치기(또는 이 파일)를 다시 돌린다
docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" \
  psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q < "$SRC/$MIGRATION" >/dev/null
echo "  적용했다"
check_priv() { # $1 이름  $2 기대  $3 SQL(불리언 열들)
  local got; got=$("${PSQL[@]}" -F ' ' -c "$3" 2>/dev/null || echo 조회실패)
  if [ "$got" = "$2" ]; then echo "  $1: 기대대로 ($2)"; else echo "  경고: $1 권한이 예상과 다르다 (얻음 $got, 기대 $2)" >&2; fi
}
check_priv "작업기 사건 읽기 · 이벤트 읽기 · 추천 추가 · 상태 고치기 · 추천 고치기 · 판정 값 읽기 · 판정 추가 · 차단 목록 읽기" "t t t t f f f f" \
  "SELECT has_table_privilege('opsloop_ai','incidents','SELECT'), has_table_privilege('opsloop_ai','events','SELECT'),
          has_table_privilege('opsloop_ai','ai_recommendations','INSERT'), has_table_privilege('opsloop_ai','ai_status','UPDATE'),
          has_table_privilege('opsloop_ai','ai_recommendations','UPDATE'), has_column_privilege('opsloop_ai','verdicts','verdict','SELECT'),
          has_table_privilege('opsloop_ai','verdicts','INSERT'), has_table_privilege('opsloop_ai','blocklist','SELECT')"
check_priv "콘솔 추천 읽기 · 상태 읽기 · 추천 추가 · 탐지 추천 읽기" "t t f f" \
  "SELECT has_table_privilege('opsloop_console','ai_recommendations','SELECT'), has_table_privilege('opsloop_console','ai_status','SELECT'),
          has_table_privilege('opsloop_console','ai_recommendations','INSERT'), has_table_privilege('opsloop_detector','ai_recommendations','SELECT')"

echo "== systemd 단위 (켜지 않는다)"
for u in opsloop-recommend.service opsloop-recommend.timer opsloop-ai-tunnel.service; do
  if cmp -s "$SRC/recommend/$u" "/etc/systemd/system/$u"; then echo "  $u 그대로"; else
    install -m 644 "$SRC/recommend/$u" "/etc/systemd/system/$u"; echo "  $u 설치했다"; fi
done
systemctl daemon-reload
for u in opsloop-ai-tunnel.service opsloop-recommend.timer; do
  echo "  $u: $(systemctl is-enabled "$u" 2>/dev/null || true) / $(systemctl is-active "$u" 2>/dev/null || true)"
done

echo "== 접속 확인"
env_login /etc/opsloop/ai.env && echo "  AI 추천 역할(opsloop_ai) 로그인 성공" || echo "  AI 추천 역할 로그인 실패 ($DB_HOST:5432)" >&2
# 실제 사용자로 래퍼 · 설정 · 접속 파일 · ACL 을 한 번에 본다 (DB 만 읽는다)
sudo -u opsloop-ai /usr/local/bin/opsloop-recommend status | sed 's/^/  /' \
  || echo "  opsloop-ai 사용자로 상태를 읽지 못했다 (/etc/opsloop ACL · ai.env 권한을 본다)" >&2

echo "설치 완료 ($VERSION). 터널과 타이머는 켜지 않았다."
echo "  1. AI 서버 키 등록   위 '터널 전용 키'의 한 줄을 AI 서버 ~/.ssh/authorized_keys 에 넣는다"
echo "  2. 방화벽            infra/vmware/fw/nftables.conf (define AI_SERVER · 데이터 노드 → AI 서버 22) 를 반영한다"
echo "  3. 터널              sudo systemctl enable --now opsloop-ai-tunnel.service; journalctl -u opsloop-ai-tunnel -n 20"
echo "  4. 한 번 실행        sudo systemctl start opsloop-recommend.service; journalctl -u opsloop-recommend -n 30"
echo "  5. 켜기              sudo systemctl enable --now opsloop-recommend.timer"
echo "  상태                 sudo -u opsloop-ai opsloop-recommend status"
