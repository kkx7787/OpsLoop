#!/usr/bin/env bash
# 데이터 노드에 CTI 수집기(opsloop-cti)를 설치한다 (이슈 #39). 타이머는 켜지 않는다 (한 번 돌려 확인한 뒤 직접 켠다).
# 여러 번 돌려도 된다. 이미 있는 사용자 · 비밀번호 · 설정은 지키고, 무엇을 했는지 찍는다.
#
# 하는 일: 사용자 opsloop-cti · 상태 폴더 /var/lib/opsloop-cti, 코드 /opt/opsloop/cti (root 소유, 주목 CVE 목록
#   watchlist.json 을 실행기 옆에 함께 둔다), 래퍼 /usr/local/bin/opsloop-cti, 설정 /etc/default/opsloop-cti (처음만),
#   DB 역할 opsloop_cti 와 접속 파일
#   /etc/opsloop/cti.env, 마이그레이션 infra/migrations/20260925_cti.sql (표 · 권한), systemd 단위 (켜지 않음).
# 안 하는 일: S3 쓰기 키(/etc/opsloop/s3-cti.env)는 만들지 않는다. 이 설치기로 opsloop-cti 그룹을 만든 뒤
#   Mac 에서 aws iam create-access-key 출력을 파이프로 바로 넣는다 (infra/terraform/README.md 'CTI 원본 보관').
#
# 먼저 puller/install-ingest.sh · collector/install-collector.sh 가 깔려 있어야 한다 (스키마 · /etc/opsloop · DB 컨테이너).
# DB 역할의 비밀번호는 여기서 만들어 /etc/opsloop/cti.env 에만 둔다. 화면 · 셸 이력 · 명령행 인자(ps)에 남기지 않는다.
# DB 에는 표준 입력으로 SCRAM 검증값만 넘긴다. 역할을 만든 뒤 마이그레이션을 적용해야 권한 블록이 권한을 준다.
#
# 사용 (Mac, 저장소 루트):
#   C=$(git rev-parse --short HEAD); git archive "$C" cti infra/migrations/20260925_cti.sql | ssh -F ~/.ssh/config.opsloop data01 "rm -rf /tmp/ol && mkdir /tmp/ol && tar -x -C /tmp/ol && sudo bash /tmp/ol/cti/install-cti.sh $C"
set -euo pipefail
VERSION=${1:?커밋}
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DB=opsloop-db                  # compose/data.yml 의 PostgreSQL 컨테이너
DB_HOST=192.168.60.11          # DB 는 이 주소에만 묶여 있다
CODE=/opt/opsloop/cti
STATE=/var/lib/opsloop-cti
MIGRATION=infra/migrations/20260925_cti.sql
BUCKET=${OPSLOOP_BUCKET:-opsloop-archive-739272173045}
PSQL=(docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -qAt)

echo "== 사전 확인"
[ "$(id -u)" = 0 ] || { echo "root 로 돌린다 (sudo bash $0 $VERSION)" >&2; exit 1; }
for f in cti/opsloop_cti.py cti/watchlist.json cti/opsloop-cti cti/opsloop-cti.service cti/opsloop-cti.timer "$MIGRATION"; do
  [ -e "$SRC/$f" ] || { echo "받은 파일에 $f 가 없다. git archive 에 cti $MIGRATION 을 넣는다" >&2; exit 1; }
done
[ -d /etc/opsloop ] || { echo "/etc/opsloop 이 없다. puller/install-ingest.sh 를 먼저 돌린다" >&2; exit 1; }
[ "$(docker inspect -f '{{.State.Running}}' "$DB" 2>/dev/null)" = true ] || { echo "DB 컨테이너 $DB 가 돌고 있지 않다" >&2; exit 1; }
[ "$("${PSQL[@]}" -c "SELECT to_regclass('rule_versions') IS NOT NULL")" = t ] \
  || { echo "rule_versions 표가 없다. collector/install-collector.sh 로 스키마를 먼저 적용한다" >&2; exit 1; }
# 주목 CVE 목록은 fetch 의 osv 단계가 읽는다. 틀리면 osv 가 실패로 끝나므로 실행기의 검증 함수로 설치 전에 본다
WATCH_N=$(python3 -B - "$SRC/cti" "$SRC/cti/watchlist.json" 2>&1 <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import opsloop_cti as c
try:
    print(len(c.load_watchlist(sys.argv[2])))
except c.CtiError as e:
    sys.exit(str(e))
PY
) || { echo "cti/watchlist.json 이 틀리다: $WATCH_N" >&2; exit 1; }
echo "  확인 끝 (원본 $SRC, 커밋 $VERSION)"

echo "== 패키지"
export DEBIAN_FRONTEND=noninteractive
python3 -c 'import psycopg2' 2>/dev/null || { apt-get update -qq && apt-get install -y -qq python3-psycopg2; }
python3 -c 'import boto3' 2>/dev/null || apt-get install -y -qq python3-boto3
command -v setfacl >/dev/null || apt-get install -y -qq acl
echo "  python3-psycopg2 · python3-boto3 · acl 있음"

echo "== 사용자 · 폴더"
if id opsloop-cti >/dev/null 2>&1; then echo "  사용자 opsloop-cti 있음"; else
  useradd --system --shell /usr/sbin/nologin --home "$STATE" opsloop-cti; echo "  사용자 opsloop-cti 만들었다"; fi
install -d -o opsloop-cti -g opsloop-cti -m 750 "$STATE"
echo "  $STATE ($(stat -c '%U:%G %a' "$STATE"). 잠금 · EPSS 사본)"
# /etc/opsloop 은 root:opsloop-pull 750 이라 opsloop-cti 가 지나가지 못한다. 그룹 대신 ACL 로 지나가기(x)만 준다.
# 다른 접속 파일은 0640 root:<그룹> 이라 지나가도 읽지 못한다. install-ingest.sh 가 750 으로 되돌려도 ACL 은 남는다
if getfacl -cp /etc/opsloop 2>/dev/null | grep -qx 'user:opsloop-cti:--x'; then
  echo "  /etc/opsloop 지나가기 권한(opsloop-cti) 있음"
else
  setfacl -m u:opsloop-cti:x /etc/opsloop; echo "  /etc/opsloop 에 opsloop-cti 지나가기 권한을 줬다 (ACL)"
fi

echo "== 코드 $VERSION → $CODE (root 소유. 수집기가 자기 코드를 바꿀 수 없다)"
# 적재기 앱 폴더(/opt/opsloop/app)와 따로 둔다. install-ingest.sh 가 앱 폴더를 통째로 바꿔도 사라지지 않는다
install -d -m 755 /opt/opsloop
rm -rf /opt/opsloop/.cti.new
cp -r "$SRC/cti" /opt/opsloop/.cti.new
find /opt/opsloop/.cti.new -name '__pycache__' -prune -exec rm -rf {} +
echo "$VERSION" > /opt/opsloop/.cti.new/VERSION
chown -R root:root /opt/opsloop/.cti.new
chmod -R u+rwX,go+rX,go-w /opt/opsloop/.cti.new
rm -rf /opt/opsloop/cti.old
if [ -d "$CODE" ]; then mv "$CODE" /opt/opsloop/cti.old; echo "  이전 판은 /opt/opsloop/cti.old"; fi
mv /opt/opsloop/.cti.new "$CODE"
ls "$CODE" | sed 's/^/    /'
echo "  주목 CVE 목록 $CODE/watchlist.json (${WATCH_N}개)"
install -m 755 "$SRC/cti/opsloop-cti" /usr/local/bin/opsloop-cti
echo "  래퍼 /usr/local/bin/opsloop-cti → $CODE/opsloop_cti.py"

echo "== 설정 (/etc/default/opsloop-cti, 비밀 아님)"
# 처음 설치할 때만 만든다. 이미 있으면 손으로 바꾼 값을 지키려고 덮어쓰지 않는다
if [ ! -s /etc/default/opsloop-cti ]; then
  cat > /etc/default/opsloop-cti <<EOT
OPSLOOP_BUCKET=$BUCKET
OPSLOOP_CTI_HOME=$STATE
AWS_DEFAULT_REGION=ap-northeast-2
EOT
  chmod 644 /etc/default/opsloop-cti
  echo "  만들었다"
fi
sed 's/^/    /' /etc/default/opsloop-cti

# ── DB 역할 · 접속 파일 ──────────────────────────────────────────────────────
# 아래 세 함수는 collector/install-collector.sh 의 것을 그대로 옮겼다 (역할마다 접속 파일 하나, SCRAM 검증값만 DB 로).
#   cti.env   opsloop_cti   root:opsloop-cti 0640   CTI 수집기 (원본 기록 추가 · KEV · CVE · OSV · 자산 갱신, 서명 정의 읽기)
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
ensure_env /etc/opsloop/cti.env opsloop_cti opsloop-cti

echo "== DB 역할"
ensure_role opsloop_cti /etc/opsloop/cti.env 2

echo "== 마이그레이션 ($MIGRATION, 여러 번 돌려도 같다)"
# 역할을 만든 뒤에 적용해야 권한 블록(IF EXISTS opsloop_cti)이 권한을 준다. 역할 블록(schema.sql · 20260924_db_roles.sql)을
# 다시 적용하면 모든 표의 권한을 먼저 거두므로, 그 뒤에는 이 설치기(또는 이 파일)를 다시 돌린다
docker exec -i -e "PGOPTIONS=-c client_min_messages=warning" "$DB" \
  psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q < "$SRC/$MIGRATION" >/dev/null
echo "  적용했다"
# 역할별 권한 표. 기대값과 다르면 경고만 하고 계속한다 (마이그레이션을 고친 뒤 다시 돌린다)
check_priv() { # $1 이름  $2 기대  $3 SQL(불리언 열들)
  local got; got=$("${PSQL[@]}" -F ' ' -c "$3" 2>/dev/null || echo 조회실패)
  if [ "$got" = "$2" ]; then echo "  $1: 기대대로 ($2)"; else echo "  경고: $1 권한이 예상과 다르다 (얻음 $got, 기대 $2)" >&2; fi
}
check_priv "CTI 원본 기록 삽입 · 원본 기록 갱신 · 원본 기록 삭제 · KEV 삭제 · 자산 취약점 삭제 · 자산 갱신 · 서명 정의 읽기 · 주목 CVE 삭제" "t f f t t t t t" \
  "SELECT has_table_privilege('opsloop_cti','cti_snapshots','INSERT'), has_table_privilege('opsloop_cti','cti_snapshots','UPDATE'),
          has_table_privilege('opsloop_cti','cti_snapshots','DELETE'), has_table_privilege('opsloop_cti','cti_kev','DELETE'),
          has_table_privilege('opsloop_cti','asset_vulnerabilities','DELETE'), has_table_privilege('opsloop_cti','asset_inventory','UPDATE'),
          has_table_privilege('opsloop_cti','rule_versions','SELECT'), has_table_privilege('opsloop_cti','cti_watch','DELETE')"
check_priv "CTI events 읽기 · incidents 삽입 · verdicts 삽입 · nodes.token_hash 읽기 · 규칙 정의 삽입 · 자산 삭제" "f f f f f f" \
  "SELECT has_table_privilege('opsloop_cti','events','SELECT'), has_table_privilege('opsloop_cti','incidents','INSERT'),
          has_table_privilege('opsloop_cti','verdicts','INSERT'), has_column_privilege('opsloop_cti','nodes','token_hash','SELECT'),
          has_table_privilege('opsloop_cti','rule_versions','INSERT'), has_table_privilege('opsloop_cti','asset_inventory','DELETE')"
check_priv "콘솔 KEV 읽기 · 자산 취약점 읽기 · 주목 CVE 읽기 · KEV 삽입 · 탐지 자산 읽기 · 적재 KEV 읽기 · 백업 KEV 읽기" "t t t f f f t" \
  "SELECT has_table_privilege('opsloop_console','cti_kev','SELECT'),
          has_table_privilege('opsloop_console','asset_vulnerabilities','SELECT'),
          has_table_privilege('opsloop_console','cti_watch','SELECT'),
          has_table_privilege('opsloop_console','cti_kev','INSERT'), has_table_privilege('opsloop_detector','asset_inventory','SELECT'),
          has_table_privilege('opsloop_ingest','cti_kev','SELECT'), has_table_privilege('opsloop_backup','cti_kev','SELECT')"

echo "== systemd 단위 (켜지 않는다)"
for u in opsloop-cti.service opsloop-cti.timer; do
  if cmp -s "$SRC/cti/$u" "/etc/systemd/system/$u"; then echo "  $u 그대로"; else
    install -m 644 "$SRC/cti/$u" "/etc/systemd/system/$u"; echo "  $u 설치했다"; fi
done
systemctl daemon-reload
echo "  opsloop-cti.timer: $(systemctl is-enabled opsloop-cti.timer 2>/dev/null || true) / $(systemctl is-active opsloop-cti.timer 2>/dev/null || true)"

echo "== S3 쓰기 키 (/etc/opsloop/s3-cti.env, 만들지 않는다)"
if [ -s /etc/opsloop/s3-cti.env ]; then
  echo "  있음 ($(stat -c '%U:%G %a' /etc/opsloop/s3-cti.env))"
else
  echo "  없음. Mac 에서 CTI 쓰기 사용자 키를 파이프로 넣는다 (infra/terraform/README.md 'CTI 원본 보관'). 그 전에는 fetch 가 설정 오류(2)로 끝난다"
fi

echo "== 접속 확인"
env_login /etc/opsloop/cti.env && echo "  CTI 역할(opsloop_cti) 로그인 성공" || echo "  CTI 역할 로그인 실패 ($DB_HOST:5432)" >&2
# 실제 사용자로 래퍼 · 설정 · 접속 파일 · ACL 을 한 번에 본다 (DB 만 읽는다)
sudo -u opsloop-cti /usr/local/bin/opsloop-cti status | sed 's/^/  /' \
  || echo "  opsloop-cti 사용자로 상태를 읽지 못했다 (/etc/opsloop ACL · cti.env 권한을 본다)" >&2

echo "설치 완료 ($VERSION). 타이머는 켜지 않았다."
echo "  한 번 실행  sudo systemctl start opsloop-cti.service; journalctl -u opsloop-cti -n 60   (NVD 간격 때문에 10분 안팎)"
echo "  상태        sudo -u opsloop-cti opsloop-cti status"
echo "  켜기        sudo systemctl enable --now opsloop-cti.timer"
echo "  자산 조사   Mac 에서 infra/vmware/scripts/collect-assets.sh (적재는 opsloop-cti load-assets)"
