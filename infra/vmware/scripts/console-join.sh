#!/usr/bin/env bash
# 콘솔 B 합류 · 떼기 (이슈 #43). 평소 꺼 둔 console-b 를 시험 · 시연 때 켜서 HAProxy 분배에 넣고, 끝나면 빼고 끈다.
#   infra/vmware/README.md '콘솔 B 운용' 절의 단계 가운데 Mac 에서 돌릴 수 있는 것을 단계 함수로 둔다.
#   기본은 드라이런이다. 돌릴 명령만 찍고 원격 · VM 에는 아무것도 하지 않는다(읽기도 하지 않는다). 실제로 돌리려면 --apply.
#   비밀값(SESSION_SECRET · OPSLOOP_CONSOLE_DB_PASSWORD)은 console-a → console-b ssh 파이프로만 옮긴다.
#     Mac 의 화면 · 파일 · 명령행 인자에 남지 않는다. 같은지 확인도 양쪽 해시를 변수로만 비교하고 찍지 않는다.
#     POSTGRES_PASSWORD 는 옮기지 않는다 (콘솔 컨테이너는 쓰지 않는다. 소유자 비밀번호를 둔 곳을 늘리지 않는다).
#   HAProxy 상태는 방화벽의 master 소켓(/run/haproxy-master.sock, systemd 단위의 -S)으로 바꾼다. @1 은 지금 작업 프로세스다.
#     reload 하면 maint · drain 이 풀린다(런타임 상태를 파일로 남기지 않는다). 합류 · 떼기 중에는 reload 하지 않는다.
#
# 사용 (Mac, 저장소 루트)
#   infra/vmware/scripts/console-join.sh                         합류 단계 전체를 드라이런으로
#   infra/vmware/scripts/console-join.sh --apply                 합류 단계 전체를 차례로 (실패한 단계에서 멈춘다)
#   infra/vmware/scripts/console-join.sh --step env --apply      한 단계만 (이름은 --list)
#   infra/vmware/scripts/console-join.sh --from image --apply    그 단계부터 끝까지
#   infra/vmware/scripts/console-join.sh --leave [--apply]       떼기 (끄는 절차)
#   infra/vmware/scripts/console-join.sh --list                  단계 이름 · 하는 일
#
# 합류 단계 (README '콘솔 B 운용' 켜는 절차와 같은 순서)
#   precheck  콘솔 A /health · opsloop_console 접속 한도 30 이상 · HAProxy 상태 · B VM 상태
#   maint     HAProxy console-b → maint (VM 이 켜지는 동안 요청이 가지 않게)
#   vm-start  VM 켜기 · SSH 응답 대기 (console-b 가 maint 가 아니면 멈춘다)
#   stop-old  옛 컨테이너를 restart=no 로 바꾸고 멈춘다 (옛 이미지 · 옛 .env 의 발송기가 돌지 않게)
#   chrony    방화벽만 시간원으로 (add-node.sh 와 같은 netplan/chrony-client.conf.template) · 맞춰질 때까지 대기
#   upgrade   apt full-upgrade · 재부팅 · 부팅 id 가 바뀐 뒤 SSH 응답 · 옛 컨테이너가 멈춘 채인지
#   guard     호스트 가드: ansible-playbook consoles.yml --limit console-b 두 번 (두 번째 changed=0)
#   image     콘솔 A 의 이미지를 docker save | docker load 로 옮기고 이미지 ID 가 같은지
#   env       .env 동기화 (비밀값 두 줄은 A 에서 파이프로 · OPSLOOP_WORKER=opsloop-console-b · 0600)
#   up        콘솔 A 의 console.yml 을 옮기고 compose up (빌드 없이 옮긴 이미지로) · B /health 대기
#   verify    이미지 ID · console.yml · 비밀값이 A 와 같은지 · 재시작 정책 · 발송기 이름 · DB 역할 · 방화벽에서 /health · 접속 수
#   ready     HAProxy console-b → ready · UP 이 될 때까지 대기 (rise 3 × 2초, 그 뒤 slowstart 30초)
#   assets    자산 조사: collect-assets.sh --only console-b
# 떼기 단계 (--leave)
#   drain     새 요청은 A 로만 · B 의 연결 수가 0 이 되거나 기다림이 끝날 때까지 (웹소켓은 남을 수 있다)
#   maint     HAProxy console-b → maint
#   stop      컨테이너를 restart=no 로 바꾸고 멈춘다 (다음에 VM 만 켜져도 요청을 받지 않게)
#   vm-stop   VM 끄기 (게스트 종료) · 꺼질 때까지 대기 (console-b 가 maint 가 아니면 멈춘다)
#   state     HAProxy 상태 읽기
#
# 바꿀 수 있는 값 (환경변수): VMDIR (add-node.sh 와 같다) · VMRUN · CONSOLE_JOIN_POLL (대기 간격 초, 기본 2) ·
#   COLLECT_ASSETS (자산 조사 스크립트, 기본 같은 폴더의 collect-assets.sh)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SSH=(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=10)
VMDIR="${VMDIR:-$HOME/Virtual Machines.localized}"
VMX="$VMDIR/opsloop-console-b.vmwarevm/opsloop-console-b.vmx"
VMRUN="${VMRUN:-/Applications/VMware Fusion.app/Contents/Library/vmrun}"
POLL="${CONSOLE_JOIN_POLL:-2}"
COLLECT_ASSETS="${COLLECT_ASSETS:-$HERE/collect-assets.sh}"
CHRONY_TPL="$ROOT/infra/vmware/netplan/chrony-client.conf.template"
MASTER=/run/haproxy-master.sock
BK=consoles
SRV=console-b
A_ADDR=192.168.50.11
B_ADDR=192.168.50.12
FW_SVC=192.168.50.1          # 서비스망 쪽 방화벽 주소 = B 의 시간원
IMAGE=opsloop-api:latest     # compose 프로젝트(~/opsloop) · 서비스(api) 이름에서 나온다
WORKER_B=opsloop-console-b
LIMIT_MIN=30                 # opsloop_console 접속 한도 (infra/migrations/20260926_console_connlimit.sql)
SECRET_KEYS='SESSION_SECRET|OPSLOOP_CONSOLE_DB_PASSWORD'
JOIN_STEPS="precheck maint vm-start stop-old chrony upgrade guard image env up verify ready assets"
LEAVE_STEPS="drain maint stop vm-stop state"

APPLY=0
exec 3>&1                    # 드라이런 명령 줄은 fd 3 으로 찍는다. $(…) 로 받는 읽기 결과에 섞이지 않는다
say() { printf '%s\n' "$*"; }
show() { printf '  $ %s\n' "$*" >&3; }
die() { printf '  ✘ %s\n' "$*" >&2; exit 1; }
applying() { [ "$APPLY" = 1 ]; }

# ── 실행 도우미 (드라이런이면 찍기만 한다) ───────────────────────────────
on() { # $1 별칭  $2 원격 명령. 표준 입력은 그대로 원격으로 간다
  if applying; then "${SSH[@]}" "$1" "$2"; else show "ssh $1 '$2'"; fi
}
pipe() { # $1 보내는 별칭 $2 명령  $3 받는 별칭 $4 명령. 보내는 쪽 출력은 Mac 을 거쳐 받는 쪽 표준 입력으로만 흐른다
  if applying; then "${SSH[@]}" "$1" "$2" | "${SSH[@]}" "$3" "$4"; else show "ssh $1 '$2' | ssh $3 '$4'"; fi
}
local_run() { if applying; then "$@"; else show "$*"; fi; }
check() { # $1 설명  $2… 성공하면 0 을 내는 함수
  local what=$1; shift
  if ! applying; then say "  확인: $what"; return 0; fi
  "$@" || die "$what: 기대와 다르다"
  say "  ✔ $what"
}
wait_for() { # [--soft] $1 설명  $2 시도 횟수  $3… 성공하면 0 을 내는 함수. --soft 면 끝까지 안 돼도 계속한다
  local soft=0 what tries i
  if [ "$1" = --soft ]; then soft=1; shift; fi
  what=$1; tries=$2; shift 2
  if ! applying; then say "  기다림: $what (최대 ${tries}번 · ${POLL}초 간격)"; return 0; fi
  for ((i = 1; i <= tries; i++)); do
    if "$@"; then say "  ✔ $what (${i}번째)"; return 0; fi
    sleep "$POLL"
  done
  if [ "$soft" = 1 ]; then say "  … $what: ${tries}번 기다렸다. 그대로 다음으로 간다"; return 0; fi
  die "$what: ${tries}번 기다려도 되지 않았다"
}

# ── 읽기 (apply 때만 불린다) ───────────────────────────────────────────
hap() { on fw "echo \"@1 $1\" | sudo -n nc -N -U $MASTER"; }
srv_state() { # console-b 의 '운영 관리' (show servers state 의 6 · 7번째 열)
  hap "show servers state $BK" | awk -v s="$SRV" '$4 == s { print $6, $7 }'
}
is_maint() { local st; st=$(srv_state) || return 1; set -- $st; [[ "${2:-}" =~ ^[0-9]+$ ]] && [ $(( $2 & 1 )) -ne 0 ]; }
is_up() { local st; st=$(srv_state) || return 1; [ "$st" = "2 0" ]; }
no_sessions() { # show stat 의 5번째 열 scur
  local n
  n=$(hap "show stat" | awk -F, -v s="$SRV" -v b="$BK" '$1 == b && $2 == s { print $5 }') || return 1
  say "    console-b 연결 ${n:-?}"
  [ "$n" = 0 ]
}
state_readable() { local st; st=$(srv_state) || return 1; [ -n "$st" ]; }
http_from_fw() { [ "$(on fw "curl -s -m 3 -o /dev/null -w \"%{http_code}\" http://$1:8000/health")" = 200 ]; }
health_a() { http_from_fw "$A_ADDR"; }
health_b_fw() { http_from_fw "$B_ADDR"; }
health_b() { [ "$(on console-b "curl -s -m 3 -o /dev/null -w \"%{http_code}\" http://127.0.0.1:8000/health")" = 200 ]; }
dbq() { on data01 "sudo -n docker exec opsloop-db psql -U opsloop -d opsloop -qAtc \"$1\""; }
role_limit_ok() {
  local lim
  lim=$(dbq "SELECT rolconnlimit FROM pg_roles WHERE rolname = 'opsloop_console'") || return 1
  say "    opsloop_console 접속 한도 ${lim:-없음}"
  if [[ "$lim" =~ ^[0-9]+$ ]] && [ "$lim" -ge "$LIMIT_MIN" ]; then return 0; fi
  say "    한도가 ${LIMIT_MIN} 보다 작다. infra/migrations/20260926_console_connlimit.sql 을 먼저 적용한다 (두 대 22 + triage.py)"
  return 1
}
role_conns_ok() {
  local out n lim
  out=$(dbq "SELECT (SELECT count(*) FROM pg_stat_activity WHERE usename = 'opsloop_console') || '|' || (SELECT rolconnlimit FROM pg_roles WHERE rolname = 'opsloop_console')") || return 1
  n=${out%%|*}; lim=${out##*|}
  say "    opsloop_console 접속 ${n} / 한도 ${lim}"
  [[ "$n" =~ ^[0-9]+$ ]] && [[ "$lim" =~ ^[0-9]+$ ]] && [ "$lim" -ge "$LIMIT_MIN" ] && [ "$n" -lt "$lim" ]
}
ssh_ok() { "${SSH[@]}" console-b true >/dev/null 2>&1; }
boot_id() { on console-b 'cat /proc/sys/kernel/random/boot_id'; }
rebooted() { local now; now=$(boot_id 2>/dev/null) || return 1; [ -n "$now" ] && [ "$now" != "$BOOT_BEFORE" ]; }
vm_running() { "$VMRUN" list | grep -qF "$VMX"; }
vm_stopped() { ! vm_running; }
old_stopped() { # 컨테이너가 없거나, 멈춰 있고 restart=no
  local st
  st=$(on console-b "docker inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' opsloop-api 2>/dev/null || echo 없음") || return 1
  say "    컨테이너: $st"
  [ "$st" = "false no" ] || [ "$st" = "없음" ]
}
same_image() {
  local a b
  a=$(on console-a "docker image inspect -f '{{.Id}}' $IMAGE") || return 1
  b=$(on console-b "docker image inspect -f '{{.Id}}' $IMAGE") || return 1
  say "    A ${a:0:19} · B ${b:0:19}"
  [ -n "$a" ] && [ "$a" = "$b" ]
}
same_compose() {
  local a b
  a=$(on console-a 'sha256sum < ~/opsloop/console.yml') || return 1
  b=$(on console-b 'sha256sum < ~/opsloop/console.yml') || return 1
  [ -n "$a" ] && [ "$a" = "$b" ]
}
same_secrets() { # 두 줄의 해시를 변수로만 비교한다. 해시도 찍지 않는다
  local cmd a b
  cmd="grep -E '^($SECRET_KEYS)=' ~/opsloop/.env | LC_ALL=C sort | sha256sum"
  a=$(on console-a "$cmd") || return 1
  b=$(on console-b "$cmd") || return 1
  [ -n "$a" ] && [ "$a" = "$b" ]
}
env_ok() { # 권한 · 비밀값 줄 수 · 발송기 이름 줄 수 (값은 보지 않는다)
  local out
  out=$(on console-b "f=~/opsloop/.env; echo \$(stat -c %a \"\$f\") \$(grep -cE '^($SECRET_KEYS)=.' \"\$f\") \$(grep -c '^OPSLOOP_WORKER=$WORKER_B\$' \"\$f\")") || return 1
  say "    .env 권한 · 비밀값 줄 · 발송기 이름 줄: $out"
  [ "$out" = "600 2 1" ]
}
b_container_ok() {
  local out want
  out=$(on console-b "$(b_container_script)") || return 1
  want=$(printf 'always\n%s\nopsloop_console' "$WORKER_B")
  say "    재시작 정책 · 발송기 이름 · DB 역할: $(printf '%s' "$out" | tr '\n' ' ')"
  [ "$out" = "$want" ]
}
b_container_script() {
  cat <<'EOF'
docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' opsloop-api
docker exec opsloop-api printenv OPSLOOP_WORKER
docker exec opsloop-api python3 -c "import os, urllib.parse; print(urllib.parse.urlsplit(os.environ['DATABASE_URL']).username)"
EOF
}
show_state() {
  if ! applying; then hap "show servers state $BK"; return 0; fi
  hap "show servers state $BK" | awk 'NF >= 7 && $1 !~ /^#/ { printf "    %-10s 운영 %s · 관리 %s\n", $4, $6, $7 }'
}
require_maint() {
  if ! applying; then say "  확인: console-b 가 maint 다 (아니면 멈춘다)"; return 0; fi
  is_maint || die "HAProxy 의 console-b 가 maint 가 아니다. 먼저 --step maint --apply (reload 하면 풀린다)"
}
hap_set() { # $1 maint | ready | drain
  local out
  out=$(hap "set server $BK/$SRV state $1") || die "master 소켓에 닿지 못했다"
  [ -z "$(printf '%s' "$out" | tr -d '[:space:]')" ] || die "HAProxy 가 거부했다: $out"
  if applying; then say "  HAProxy $BK/$SRV → $1"; fi
}

# ── 원격 스크립트 (비밀값은 원격에서만 다룬다) ──────────────────────────
env_write_script() { # 표준 입력으로 A 의 두 줄을 받아 B 의 .env 를 고친다. 두 줄이 아니면 파일을 건드리지 않는다
  cat <<EOF
set -e
umask 077; mkdir -p ~/opsloop; f=~/opsloop/.env
new=\$(cat)
n=\$(printf '%s\n' "\$new" | grep -cE '^($SECRET_KEYS)=.' || true)
[ "\$n" = 2 ] || { echo "  console-a 에서 두 값을 받지 못했다 (\$n/2). .env 를 바꾸지 않는다" >&2; exit 1; }
{ grep -vE '^($SECRET_KEYS|OPSLOOP_WORKER)=' "\$f" 2>/dev/null || true
  printf '%s\n' "\$new"
  echo 'OPSLOOP_WORKER=$WORKER_B'; } > "\$f.tmp"
chmod 600 "\$f.tmp"; mv "\$f.tmp" "\$f"
echo "  .env 갱신: 비밀값 두 줄은 console-a 에서 받았다 (찍지 않는다) · OPSLOOP_WORKER=$WORKER_B"
EOF
}
chrony_script() { # 표준 입력으로 시간원 설정을 받는다
  cat <<'EOF'
set -eo pipefail
cat > /tmp/opsloop-fw.conf
changed=0
if grep -qE '^pool ' /etc/chrony/chrony.conf; then sudo -n sed -i -E 's/^(pool .*)/#\1/' /etc/chrony/chrony.conf; changed=1; fi
if ! sudo -n cmp -s /tmp/opsloop-fw.conf /etc/chrony/conf.d/opsloop-fw.conf; then
  sudo -n install -m 644 -o root -g root /tmp/opsloop-fw.conf /etc/chrony/conf.d/opsloop-fw.conf; changed=1
fi
rm -f /tmp/opsloop-fw.conf
if [ "$changed" = 1 ]; then sudo -n systemctl restart chrony; echo "  시간원 설정을 바꾸고 chrony 를 다시 띄웠다"; else echo "  시간원 설정은 이미 같다"; fi
chronyc waitsync 30 1 >/dev/null
chronyc -n tracking | grep -E '^(Reference ID|System time)' | sed 's/^/    /'
EOF
}
upgrade_script() {
  cat <<'EOF'
set -eo pipefail
sudo -n apt-get -o DPkg::Lock::Timeout=300 update -q >/dev/null
sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get -o DPkg::Lock::Timeout=300 -y -q \
  -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade | tail -n 2 | sed 's/^/    /'
EOF
}
compose_file_script() { # 받은 파일이 비었으면(A 에서 읽기 실패) 지금 파일을 건드리지 않는다
  cat <<'EOF'
set -e
mkdir -p ~/opsloop/app; f=~/opsloop/console.yml
cat > "$f.tmp"
if [ ! -s "$f.tmp" ]; then rm -f "$f.tmp"; echo "  콘솔 A 에서 console.yml 을 받지 못했다. 바꾸지 않는다" >&2; exit 1; fi
if [ -f "$f" ]; then cp -p "$f" "$f.prev"; fi
mv "$f.tmp" "$f"
echo "  console.yml 을 콘솔 A 판으로 (이전 판 console.yml.prev)"
EOF
}

# ── 합류 단계 ─────────────────────────────────────────────────────────
step_precheck() {
  check "콘솔 A /health 200 (방화벽에서)" health_a
  check "opsloop_console 접속 한도 ${LIMIT_MIN} 이상" role_limit_ok
  check "HAProxy master 소켓 읽기" state_readable
  show_state
  if applying; then
    if vm_running; then say "  VM: 켜져 있다"; else say "  VM: 꺼져 있다"; fi
  else show "\"$VMRUN\" list | grep -F '$VMX'"; fi
}
step_maint() {
  hap_set maint
  wait_for "console-b 관리 상태 maint" 5 is_maint
}
step_vm_start() {
  require_maint
  if applying && [ ! -f "$VMX" ]; then die "VM 파일이 없다: $VMX"; fi
  if applying && vm_running; then say "  VM 이 이미 켜져 있다"; else local_run "$VMRUN" start "$VMX" nogui; fi
  wait_for "console-b SSH 응답" 90 ssh_ok
}
step_stop_old() {
  on console-b 'if docker inspect opsloop-api >/dev/null 2>&1; then docker update --restart=no opsloop-api >/dev/null; docker stop -t 10 opsloop-api >/dev/null; echo "  옛 컨테이너: restart=no · 멈춤"; else echo "  옛 컨테이너 없음"; fi'
  check "옛 컨테이너가 멈췄고 restart=no" old_stopped
}
step_chrony() {
  [ -f "$CHRONY_TPL" ] || die "시간원 설정 원본이 없다: $CHRONY_TPL"
  if applying; then
    sed "s/__FW__/$FW_SVC/" "$CHRONY_TPL" | on console-b "$(chrony_script)" || die "시간 맞추기 실패 (chronyc waitsync)"
  else
    show "sed 's/__FW__/$FW_SVC/' infra/vmware/netplan/chrony-client.conf.template | ssh console-b '$(chrony_script)'"
  fi
}
step_upgrade() {
  on console-b "$(upgrade_script)" || die "full-upgrade 실패"
  if applying; then BOOT_BEFORE=$(boot_id); [ -n "$BOOT_BEFORE" ] || die "부팅 id 를 읽지 못했다"; fi
  on console-b 'sudo -n systemctl reboot' || true   # 연결이 먼저 끊겨 255 로 끝날 수 있다
  wait_for "재부팅 뒤 SSH (부팅 id 가 바뀜)" 90 rebooted
  check "옛 컨테이너가 멈춘 채다" old_stopped
}
step_guard() {
  local out
  if ! applying; then
    show "(cd infra/ansible && ansible-playbook consoles.yml --limit console-b)    # 두 번. 두 번째는 changed=0"
    return 0
  fi
  (cd "$ROOT/infra/ansible" && ansible-playbook consoles.yml --limit console-b) || die "가드 플레이북 1회차 실패"
  out=$(cd "$ROOT/infra/ansible" && ansible-playbook consoles.yml --limit console-b) || { printf '%s\n' "$out"; die "가드 플레이북 2회차 실패"; }
  printf '%s\n' "$out" | grep -E '^console-b[[:space:]]+:' | sed 's/^/    /' || true
  printf '%s\n' "$out" | grep -Eq '^console-b[[:space:]]+:[[:space:]]+ok=[0-9]+[[:space:]]+changed=0[[:space:]]+unreachable=0[[:space:]]+failed=0' \
    || die "가드 플레이북 2회차가 changed=0 이 아니다"
  say "  ✔ 가드 두 번째 실행 changed=0"
}
step_image() {
  pipe console-a "set -o pipefail; docker save $IMAGE | gzip -1" console-b 'docker load -q' || die "이미지 옮기기 실패"
  check "이미지 ID 가 콘솔 A 와 같다" same_image
}
step_env() {
  pipe console-a "grep -E '^($SECRET_KEYS)=.' ~/opsloop/.env" console-b "$(env_write_script)" || die ".env 동기화 실패"
  check ".env 0600 · 비밀값 두 줄 · OPSLOOP_WORKER=$WORKER_B (값은 찍지 않는다)" env_ok
}
step_up() {
  require_maint
  pipe console-a 'cat ~/opsloop/console.yml' console-b "$(compose_file_script)" || die "console.yml 옮기기 실패"
  on console-b 'set -o pipefail; cd ~/opsloop && docker compose -f console.yml up -d --no-build --force-recreate 2>&1 | tail -n 2' || die "compose up 실패"
  wait_for "B /health 200 (B 안에서)" 30 health_b
}
step_verify() {
  check "이미지 ID 가 콘솔 A 와 같다" same_image
  check "console.yml 이 콘솔 A 와 같다" same_compose
  check "비밀값 두 줄이 콘솔 A 와 같다 (해시를 변수로만 비교한다)" same_secrets
  check "B 컨테이너: 재시작 정책 always · 발송기 이름 $WORKER_B · DB 역할 opsloop_console" b_container_ok
  check "방화벽에서 B /health 200" health_b_fw
  check "opsloop_console 접속 수가 한도 안" role_conns_ok
}
step_ready() {
  check "방화벽에서 B /health 200" health_b_fw
  hap_set ready
  wait_for "console-b UP (운영 2 · 관리 0)" 30 is_up
  show_state
}
step_assets() {
  local_run "$COLLECT_ASSETS" --only console-b || die "자산 조사 실패 (종료 코드를 본다. 1 = 일부 실패)"
}

# ── 떼기 단계 ─────────────────────────────────────────────────────────
step_drain() {
  hap_set drain
  wait_for --soft "console-b 연결 0 (웹소켓은 남을 수 있다. 컨테이너를 멈추면 끊기고 화면이 A 로 다시 붙는다)" 30 no_sessions
}
step_stop() {
  require_maint
  on console-b 'docker update --restart=no opsloop-api >/dev/null && docker stop -t 10 opsloop-api >/dev/null && echo "  컨테이너: restart=no · 멈춤"' || die "컨테이너 멈추기 실패"
  check "컨테이너가 멈췄고 restart=no" old_stopped
}
step_vm_stop() {
  # --step vm-stop 만 돌려도 분배 중인 B 를 끄지 않게 한다 (끄면 헬스체크가 빼기 전 최대 6초 요청이 실패한다)
  require_maint
  local_run "$VMRUN" stop "$VMX" soft || die "VM 끄기 실패"
  wait_for "VM 꺼짐" 60 vm_stopped
}
step_state() { show_state; }

# ── 인자 ───────────────────────────────────────────────────────────────
desc() {
  case $1 in
    precheck) echo "콘솔 A /health · 역할 접속 한도 · HAProxy 상태 · VM 상태" ;;
    maint) echo "HAProxy console-b → maint" ;;
    vm-start) echo "VM 켜기 · SSH 응답 대기" ;;
    stop-old) echo "옛 컨테이너 restart=no · 멈춤" ;;
    chrony) echo "방화벽 시간원 · 맞춰질 때까지" ;;
    upgrade) echo "full-upgrade · 재부팅" ;;
    guard) echo "consoles.yml --limit console-b 두 번" ;;
    image) echo "콘솔 A 이미지 docker save | load" ;;
    env) echo ".env 동기화 (비밀값은 파이프로만)" ;;
    up) echo "console.yml · compose up · /health" ;;
    verify) echo "A 와 같은지 · 발송기 이름 · DB 역할 · 방화벽에서 /health" ;;
    ready) echo "HAProxy console-b → ready · UP 대기" ;;
    assets) echo "자산 조사 --only console-b" ;;
    drain) echo "HAProxy console-b → drain · 연결 0 대기" ;;
    stop) echo "컨테이너 restart=no · 멈춤" ;;
    vm-stop) echo "VM 끄기" ;;
    state) echo "HAProxy 상태 읽기" ;;
    *) return 1 ;;
  esac
}
usage() { sed -n '11,17p' "$0" | sed 's/^# \{0,1\}//'; }

MODE=join; ONLY=""; FROM=""
while [ $# -gt 0 ]; do
  case $1 in
    --apply) APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    --leave) MODE=leave ;;
    --step) [ $# -ge 2 ] || { echo "--step 뒤에 단계 이름을 쓴다" >&2; exit 2; }; ONLY=$2; shift ;;
    --from) [ $# -ge 2 ] || { echo "--from 뒤에 단계 이름을 쓴다" >&2; exit 2; }; FROM=$2; shift ;;
    --list)
      echo "합류:"; for s in $JOIN_STEPS; do printf '  %-9s %s\n' "$s" "$(desc "$s")"; done
      echo "떼기 (--leave):"; for s in $LEAVE_STEPS; do printf '  %-9s %s\n' "$s" "$(desc "$s")"; done
      exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "모르는 인자: $1 (--help)" >&2; exit 2 ;;
  esac
  shift
done
if [ "$MODE" = leave ]; then STEPS=$LEAVE_STEPS; NAME=떼기; else STEPS=$JOIN_STEPS; NAME=합류; fi
in_list() { case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
if [ -n "$ONLY" ] && [ -n "$FROM" ]; then echo "--step 과 --from 은 함께 쓰지 않는다" >&2; exit 2; fi
if [ -n "$ONLY" ]; then
  in_list "$ONLY" "$STEPS" || { echo "모르는 $NAME 단계: $ONLY (--list)" >&2; exit 2; }
  STEPS=$ONLY
elif [ -n "$FROM" ]; then
  in_list "$FROM" "$STEPS" || { echo "모르는 $NAME 단계: $FROM (--list)" >&2; exit 2; }
  STEPS=" $STEPS "; STEPS="$FROM ${STEPS#* $FROM }"
fi

BOOT_BEFORE=""
if applying; then say "콘솔 B $NAME · 실제로 돌린다"
else say "콘솔 B $NAME · 드라이런 (명령만 찍는다. 원격 · VM 에 아무것도 하지 않는다)"; fi
for s in $STEPS; do
  say "== $s · $(desc "$s")"
  "step_$(printf '%s' "$s" | tr - _)"
done
if applying; then say "끝."; else say "드라이런이다. 실제로 돌리려면 --apply"; fi
