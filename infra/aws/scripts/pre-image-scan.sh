#!/usr/bin/env bash
# ============================================================
#  허니팟 이미지(AMI) 뜨기 전 비밀 검사 (이슈 #19)
#
#  목적
#    옛 허니팟(instances.tf 의 aws_instance.honeypot)에서 AMI 를 뜨면 디스크가 통째로 DMZ 허니팟
#    (honeypot_dmz.tf)에 복사된다. 옛 직접 적재 경로(scripts/install-collector.sh · scripts/deploy.sh)가
#    허니팟에 남겼을 수 있는 DB 접속 문자열(/etc/opsloop/collector.env 의 DATABASE_URL,
#    /usr/local/bin/opsloop-collect, opsloop-collect.service · .timer, ~/opsloop, 저장소 사본),
#    설치 때 셸 이력 · sudo 기록(auth.log · 저널)에 남은 접속 문자열, 운영자 키 · 자격증명,
#    옛 SQLite, 컨테이너 환경변수, cloud-init 잔여 자료, 임시 계정을 이미지를 뜨기 전에 찾아 보고한다.
#    업로더(sensor/upload.py)는 DB 주소도 비밀번호도 모르므로 이미지에 실려도 되는 것은 그쪽뿐이다.
#
#  하는 일 · 하지 않는 일
#    - 읽기만 한다. 아무것도 지우거나 고치지 않는다. 마지막에 지울 후보 목록만 낸다.
#    - 비밀값은 찍지 않는다. 파일 경로 · 줄 번호 · 패턴 이름 · 건수만 찍는다.
#    - 네트워크를 쓰지 않는다 (허니팟의 22 · 23 · 8080 에도 닿지 않는다).
#    - cowrie · 디코이 로그(/opt/cowrie/log · /opt/cowrie/lib · /opt/decoy/log)와 도커 계층(/var/lib/docker)은
#      공격자가 쓴 내용이라 패턴 검사에서 뺀다 (PGPASSWORD 같은 글자는 공격자 입력에 흔하다).
#
#  실행 (Mac, 저장소 루트. Run Command 는 root 로 돈다. README "DMZ 재구성" · puller/compare-paths.sh 처럼
#  본문을 base64 로 실어 넣는다. 본문이 25KB 라 gzip 으로 줄여 싣는다)
#    HP=i-058726c1a0671fe1d
#    cid=$(aws ssm send-command --region ap-northeast-2 --instance-ids "$HP" --document-name AWS-RunShellScript \
#      --comment pre-image-scan \
#      --parameters "commands=[\"echo $(gzip -c infra/aws/scripts/pre-image-scan.sh | base64 | tr -d '\n') | base64 -d | gunzip | bash\"]" \
#      --query Command.CommandId --output text)
#    aws ssm wait command-executed --region ap-northeast-2 --command-id "$cid" --instance-id "$HP" || true
#    aws ssm get-command-invocation --region ap-northeast-2 --command-id "$cid" --instance-id "$HP" \
#      --query '[Status,ResponseCode,StandardOutputContent,StandardErrorContent]' --output text
#    일부 항목만 볼 때는 "... | gunzip | SCAN_ONLY=history,keys bash" (항목 이름은 아래 SECTIONS).
#    SSM 세션 안에서 직접 돌릴 때는 같은 방법으로 파일을 옮겨 sudo bash pre-image-scan.sh.
#
#  결과 해석
#    종료 코드 0  [결과] 없음. 이미지를 떠도 된다 (SSM: Success · ResponseCode 0).
#    종료 코드 1  [결과] 한 건 이상. 끝의 "지울 · 정리 후보"를 손으로 정리하고 다시 돌려 0 을 본 뒤 이미지를 뜬다
#                (SSM 은 Failed · ResponseCode 1 로 보인다. 검사가 깨진 것이 아니다).
#    종료 코드 2  검사를 못 했다 (root 아님 · 리눅스 아님).
#    [결과] 이미지에 실리면 안 되는 것. 종료 코드에 들어간다.
#    [참고] 판단 재료 (cowrie 자체 DB · 업로더 설정 · cloud-init 기본 계정 · 호스트 키 등). 종료 코드에 넣지 않는다.
#    SSM 표준 출력은 24,000 자에서 잘린다. 잘리면 SCAN_ONLY 로 나눠 돌린다.
# ============================================================
set -u
export LC_ALL=C

SECTIONS="paths db logs history keys sqlite docker cloudinit accounts tmp"
ONLY=${SCAN_ONLY:-}
MAXHIT=3                       # 파일 · 패턴마다 찍는 줄 번호 수
MAXSIZE=$((8 * 1024 * 1024))   # 이보다 큰 파일은 패턴 검사를 건너뛰고 참고로 적는다

# 이름|플래그|정규식. 플래그 i 는 대소문자 무시. 값은 찍지 않으므로 패턴이 넓어도 된다.
# 172.31 은 옛 앱 노드(기본 VPC)의 주소대, 192.168 은 내부망 주소대다
PATTERNS=(
  'postgres-url||postgres(ql)?://'
  'pgpassword||PGPASSWORD'
  'database-url||DATABASE_URL'
  'addr-192-168||192\.168\.[0-9]{1,3}\.[0-9]{1,3}'
  'addr-172-31||172\.31\.[0-9]{1,3}\.[0-9]{1,3}'
  'port-5432||:5432([^0-9]|$)'
  'aws-access-key-id||AKIA[0-9A-Z]{16}'
  'aws-secret-key|i|aws_secret_access_key'
  'private-key-block||-----BEGIN [A-Z ]*PRIVATE KEY-----'
  'secret-assign|i|(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY)[A-Za-z0-9_]*[[:space:]]*[=:][[:space:]]*['"'"'"]?[^[:space:]'"'"'"]{6,}'
)
# 문서 · 예시의 자리표시자(postgresql://opsloop:PASSWORD@… 같은 것)는 postgres-url 에서 뺀다
PLACEHOLDER='postgres(ql)?://[^:/@]+:(PASSWORD|password|비밀번호|<[^>]*>|\$\{?[A-Za-z_]+\}?)@'
# 시스템 기록에는 좁은 패턴만 쓴다 (syslog 의 주소 · token 같은 글자는 잡음이다)
LOGPATTERNS=(postgres-url pgpassword database-url aws-access-key-id private-key-block)
# 패턴 검사에서 빼는 곳: 공격자 입력(허니팟 로그) · 도커 계층 · 공개 인증서 · 저장소 내부
PRUNE=(-path /opt/cowrie/log -o -path /opt/cowrie/lib -o -path /opt/decoy/log -o -path /var/lib/docker
       -o -path /etc/ssl/certs -o -path /etc/pki -o -path /etc/cloud/templates -o -name .git -o -name __pycache__ -o -name node_modules)

N_FOUND=0
N_NOTE=0
CLEAN=()
found() { N_FOUND=$((N_FOUND + 1)); printf '[결과] %s\n' "$*"; }
note()  { N_NOTE=$((N_NOTE + 1));   printf '[참고] %s\n' "$*"; }
todo()  { CLEAN+=("$1"); }
sec()   { printf '\n== %s\n' "$*"; }
want()  { [ -z "$ONLY" ] && return 0; case ",$ONLY," in *",$1,"*) return 0 ;; esac; return 1; }
desc()  { # 소유자 · 권한 · 크기(파일) 또는 파일 수(폴더)
  if [ -d "$1" ]; then printf '%s, 파일 %s개' "$(stat -c '%U:%G %a' "$1" 2>/dev/null)" "$(find "$1" -type f 2>/dev/null | wc -l | tr -d ' ')"
  else stat -c '%U:%G %a %sB' "$1" 2>/dev/null; fi
}
pat_re() { local e; for e in "${PATTERNS[@]}"; do [ "${e%%|*}" = "$1" ] && { printf '%s' "${e#*|*|}"; return 0; }; done; return 1; }

scan_file() {  # $1 파일. 패턴마다 맞는 줄 번호를 찍는다 (줄 내용은 찍지 않는다)
  local f=$1 e name flags re lines n hits
  [ -f "$f" ] && [ -r "$f" ] || return 0
  if [ "$(stat -c %s "$f" 2>/dev/null || echo 0)" -gt "$MAXSIZE" ]; then note "$f: 8MB 넘어 패턴 검사 생략. 손으로 본다"; return 0; fi
  for e in "${PATTERNS[@]}"; do
    name=${e%%|*}; flags=${e#*|}; flags=${flags%%|*}; re=${e#*|*|}
    if [ "$flags" = i ]; then lines=$(grep -nIEi -- "$re" "$f" 2>/dev/null); else lines=$(grep -nIE -- "$re" "$f" 2>/dev/null); fi
    [ -n "$lines" ] || continue
    if [ "$name" = postgres-url ]; then lines=$(printf '%s\n' "$lines" | grep -vE -- "$PLACEHOLDER"); [ -n "$lines" ] || continue; fi
    n=$(printf '%s\n' "$lines" | wc -l | tr -d ' ')
    hits=$(printf '%s\n' "$lines" | head -n "$MAXHIT" | cut -d: -f1 | paste -sd, -)
    [ "$n" -gt "$MAXHIT" ] && hits="$hits 외 $((n - MAXHIT))줄"
    found "$f 줄 $hits: $name"
    todo "$f"
  done
  return 0
}

scan_tree() {  # $1 루트 (없으면 지나간다). 일반 파일만, PRUNE 은 뺀다
  local f
  [ -e "$1" ] || return 0
  while IFS= read -r -d '' f; do scan_file "$f"; done \
    < <(find "$1" -xdev \( "${PRUNE[@]}" \) -prune -o -type f -print0 2>/dev/null)
}

count_log() {  # $1 기록 파일(.gz 포함). 패턴별 건수만 센다
  local f=$1 name re c out=""
  [ -f "$f" ] && [ -r "$f" ] || return 0
  for name in "${LOGPATTERNS[@]}"; do
    re=$(pat_re "$name")
    case "$f" in
      *.gz) c=$(zcat -- "$f" 2>/dev/null | grep -cE -- "$re") ;;
      *)    c=$(grep -cIE -- "$re" "$f" 2>/dev/null) ;;
    esac
    [ "${c:-0}" -gt 0 ] && out="$out $name ${c}줄"
  done
  [ -n "$out" ] && { found "$f:$out — 비밀이 든 줄을 지우거나 파일을 비운다"; todo "$f"; }
  return 0
}

main() {
  # 본문은 여기까지 이미 다 읽혔다. "| bash" 로 받을 때 안쪽 명령이 스크립트 본문을 표준 입력으로 먹지 않게 한다
  exec </dev/null
  [ "$(uname -s)" = Linux ] || { echo "리눅스(허니팟)에서 돌린다" >&2; exit 2; }
  [ "$(id -u)" = 0 ] || { echo "root 로 돌린다 (SSM Run Command 는 root 다. 세션에서는 sudo bash)" >&2; exit 2; }
  local iid def p h u g r e f d c n st pw su np fp name img keys frag out extra ll uid home shell re
  iid=$(cat /var/lib/cloud/data/instance-id 2>/dev/null || echo '?')
  def=$(awk '/^[[:space:]]*default_user:/{f=1} f && /^[[:space:]]*name:/{print $2; exit}' /etc/cloud/cloud.cfg 2>/dev/null)
  def=${def:-ubuntu}
  printf '== pre-image-scan  %s (%s)  %s\n' "$(hostname)" "$iid" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [ -n "$ONLY" ] && printf '   SCAN_ONLY=%s (전체 항목: %s)\n' "$ONLY" "$SECTIONS"

  # ── 1. 옛 직접 적재 경로가 놓은 파일 ──────────────────────────────
  if want paths; then
    sec "1/10 옛 직접 적재 경로 잔재 (scripts/install-collector.sh · scripts/deploy.sh 가 놓은 것)"
    for p in /etc/opsloop/collector.env /etc/opsloop /usr/local/bin/opsloop-collect \
             /etc/systemd/system/opsloop-collect.service /etc/systemd/system/opsloop-collect.timer \
             /opt/opsloop /var/lib/opsloop /tmp/opsloop-collect.lock; do
      [ -e "$p" ] || continue
      found "있음 $p ($(desc "$p"))"; todo "$p"
    done
    if [ -f /usr/local/bin/opsloop-collect ]; then
      note "옛 수집 스크립트가 가리키는 저장소: $(grep -m1 '^cd ' /usr/local/bin/opsloop-collect | cut -c4- | tr -d '"')"
    fi
    for u in opsloop-collect.timer opsloop-collect.service; do
      st=$(systemctl is-enabled "$u" 2>/dev/null || true)
      case "$st" in ""|not-found) ;; *) found "systemd $u: $st / $(systemctl is-active "$u" 2>/dev/null || true)" ;; esac
    done
    for h in /root /home/*; do
      [ -d "$h" ] || continue
      if [ -d "$h/opsloop" ]; then found "옛 배포 폴더 $h/opsloop ($(desc "$h/opsloop")) — deploy.sh 의 parser · data"; todo "$h/opsloop"; fi
      while IFS= read -r -d '' g; do
        r=${g%/.git}
        found "저장소 사본 $r ($(desc "$r")) — 이미지에 필요 없다 (업로더는 /usr/local/lib/opsloop 에 있다)"; todo "$r"
        scan_file "$g/config"
        if grep -qE '://[^/@[:space:]]+:[^/@[:space:]]+@' "$g/config" 2>/dev/null; then found "$g/config: url-credential (원격 주소에 사용자:비밀)"; fi
        while IFS= read -r -d '' e; do found "저장소 안 환경 파일 $e ($(desc "$e"))"; scan_file "$e"; done \
          < <(find "$r" -maxdepth 2 -type f \( -name '.env*' -o -name '*.env' \) -print0 2>/dev/null)
      done < <(find "$h" -maxdepth 4 -type d -name .git -print0 2>/dev/null)
    done
    if dpkg-query -W -f='${Status}' python3-psycopg2 2>/dev/null | grep -q 'ok installed'; then
      note "python3-psycopg2 설치돼 있음 — 옛 적재 경로만 썼다. 지워도 된다"
    fi
    # 새 경로(업로더)는 이미지에 실려야 하는 것. 상태만 적는다
    [ -f /etc/default/opsloop-upload ] && note "업로더 설정 /etc/default/opsloop-upload ($(desc /etc/default/opsloop-upload)) — OPSLOOP_HOST 는 새 인스턴스 첫 부팅이 바꾼다"
    [ -f /var/lib/opsloop-upload/state.json ] && note "업로더 위치 기억 /var/lib/opsloop-upload/state.json 있음 — 새 인스턴스 첫 부팅이 지운다"
    for p in /etc/systemd/system/opsloop-*; do
      [ -e "$p" ] || continue
      case "$p" in */opsloop-upload.service|*/opsloop-upload.timer|*/opsloop-collect.*) ;; *) found "알 수 없는 opsloop 유닛 $p"; todo "$p" ;; esac
    done
  fi

  # ── 2. 설정 · 환경 파일의 DB 접속 문자열 · 비밀 패턴 ──────────────
  if want db; then
    sec "2/10 DB 접속 문자열 · 비밀 패턴 (설정 · 환경 파일. 경로 줄번호: 패턴)"
    for p in /etc/opsloop /etc/default /etc/environment /etc/profile.d /etc/systemd/system /etc/cron.d \
             /var/spool/cron/crontabs /etc/docker /opt/opsloop /usr/local/lib/opsloop /usr/local/bin /usr/local/etc \
             /var/lib/opsloop /var/lib/opsloop-upload /srv; do scan_tree "$p"; done
    for h in /root /home/*; do
      [ -d "$h" ] || continue
      for d in .bashrc .profile .bash_profile .bash_login .zshrc .zprofile .zshenv .env .pgpass .pg_service.conf \
               .netrc .git-credentials .npmrc .pypirc .config/pip/pip.conf; do scan_file "$h/$d"; done
      scan_tree "$h/opsloop"
      while IFS= read -r -d '' e; do scan_file "$e"; done \
        < <(find "$h" -maxdepth 2 -type f \( -name '.env*' -o -name '*.env' -o -name '*.sql' -o -name '*.dump' \) -print0 2>/dev/null)
    done
    printf '   (패턴: %s)\n' "$(printf '%s\n' "${PATTERNS[@]}" | cut -d'|' -f1 | paste -sd' ' -)"
  fi

  # ── 3. 시스템 기록 (sudo 는 COMMAND 를 env 인자까지 통째로 auth.log · 저널에 남긴다) ──
  if want logs; then
    sec "3/10 시스템 기록 (auth.log 의 sudo COMMAND · syslog · cloud-init 로그 · 저널)"
    for f in /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* \
             /var/log/cloud-init.log /var/log/cloud-init-output.log; do count_log "$f"; done
    if command -v journalctl >/dev/null 2>&1; then
      # 한 번만 훑어 맞은 조각만 남기고 패턴별로 센다. 조각은 화면에 내지 않는다
      re=""; for name in "${LOGPATTERNS[@]}"; do re="${re:+$re|}($(pat_re "$name"))"; done
      frag=$(journalctl -q --no-pager -o cat 2>/dev/null | grep -oE -- "$re")
      out=""
      for name in "${LOGPATTERNS[@]}"; do
        c=$(printf '%s\n' "$frag" | grep -cE -- "$(pat_re "$name")")
        [ "${c:-0}" -gt 0 ] && out="$out $name ${c}줄"
      done
      if [ -n "$out" ]; then found "systemd 저널(/var/log/journal):$out — journalctl --rotate 뒤 --vacuum-time=1s 로 비운다"; todo "/var/log/journal (저널 비우기)"
      else note "systemd 저널: 패턴 없음 ($(du -sh /var/log/journal 2>/dev/null | cut -f1))"; fi
    fi
    note "wtmp · btmp · lastlog(로그인 기록)도 이미지에 실린다. 비울지 정한다"
  fi

  # ── 4. 셸 · 도구 이력 ─────────────────────────────────────────────
  if want history; then
    sec "4/10 셸 · 도구 이력 (install-collector.sh 는 DATABASE_URL 을 명령행 인자로 받았다)"
    for h in /root /home/*; do
      [ -d "$h" ] || continue
      for d in .bash_history .zsh_history .sh_history .python_history .psql_history .mysql_history .sqlite_history \
               .lesshst .viminfo .nano_history .node_repl_history .local/share/fish/fish_history; do
        f=$h/$d; [ -s "$f" ] || continue
        found "이력 $f ($(wc -l < "$f" | tr -d ' ')줄, $(desc "$f")) — 내용을 비운다"; todo "$f"
        scan_file "$f"
      done
    done
  fi

  # ── 5. 키 · 자격증명 ──────────────────────────────────────────────
  if want keys; then
    sec "5/10 키 · 자격증명 (.ssh · .aws · .docker · *.pem · *.key)"
    for h in /root /home/*; do
      [ -d "$h" ] || continue
      u=$(basename "$h"); [ "$h" = /root ] && u=root
      if [ -d "$h/.ssh" ]; then
        while IFS= read -r -d '' f; do
          if grep -qs 'PRIVATE KEY' "$f"; then found "SSH 개인키 $f ($(desc "$f"))"; todo "$f"; else note "$h/.ssh 의 기타 파일 $f ($(desc "$f"))"; fi
        done < <(find "$h/.ssh" -maxdepth 1 -type f ! -name '*.pub' ! -name 'known_hosts*' ! -name config \
                   ! -name 'authorized_keys*' ! -name environment ! -name rc -print0 2>/dev/null)
        f=$h/.ssh/authorized_keys
        if [ -s "$f" ]; then
          n=$(grep -cE '^[[:space:]]*[^#[:space:]]' "$f"); fp=$(ssh-keygen -lf "$f" 2>/dev/null | awk '{print $NF, $2}' | paste -sd';' -)
          if [ "$u" = root ] && grep -q 'Please login as the user' "$f"; then note "$f: root 로그인을 막는 기본 줄 (cloud-init disable_root)"
          elif [ "$u" = "$def" ] && [ "$n" -eq 1 ]; then note "$f: 키 1개 [$fp] — EC2 키페어(key_name)면 그대로 둔다. 새 인스턴스에도 같은 키페어가 들어간다"
          else found "$f: 키 ${n}개 [$fp] — 운영자 키가 섞였는지 본다"; todo "$f"; fi
        fi
      fi
      if [ -f "$h/.aws/credentials" ]; then found "AWS 자격증명 $h/.aws/credentials ($(desc "$h/.aws/credentials"))"; todo "$h/.aws/credentials"; fi
      [ -f "$h/.aws/config" ] && note "AWS 설정 $h/.aws/config (프로필 · 리전. 비밀은 보통 없다)"
      if [ -f "$h/.docker/config.json" ]; then
        if grep -q '"auth"' "$h/.docker/config.json"; then found "레지스트리 로그인 $h/.docker/config.json"; todo "$h/.docker/config.json"; else note "$h/.docker/config.json (로그인 정보 없음)"; fi
      fi
      for d in .git-credentials .netrc .pgpass .npmrc .pypirc; do
        if [ -f "$h/$d" ]; then found "자격증명 파일 $h/$d ($(desc "$h/$d"))"; todo "$h/$d"; fi
      done
      if [ -d "$h/.gnupg/private-keys-v1.d" ] && [ -n "$(ls -A "$h/.gnupg/private-keys-v1.d" 2>/dev/null)" ]; then found "GPG 개인키 $h/.gnupg/private-keys-v1.d"; todo "$h/.gnupg"; fi
    done
    n=$(ls /etc/ssh/ssh_host_*_key 2>/dev/null | wc -l | tr -d ' ')
    [ "$n" -gt 0 ] && note "SSH 호스트 키 ${n}개 (/etc/ssh/ssh_host_*_key) — cloud-init 이 새 인스턴스에서 다시 만든다(ssh_deletekeys 기본값). 새 인스턴스에서 지문이 바뀌었는지 확인"
    while IFS= read -r -d '' f; do
      case "$f" in
        /etc/ssl/private/ssl-cert-snakeoil.key) note "$f — ssl-cert 패키지 기본 키" ;;
        *) if grep -qs 'PRIVATE KEY' "$f"; then found "개인키 $f ($(desc "$f"))"; todo "$f"; else note "키 이름의 파일 $f ($(desc "$f")) — 개인키 아님"; fi ;;
      esac
    done < <(find /etc /root /home /opt /usr/local /var/lib/opsloop /var/lib/opsloop-upload /srv /var/backups -xdev \
               \( "${PRUNE[@]}" \) -prune -o -type f \
               \( -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' -o -name '*.jks' -o -name '*.kdbx' -o -name '*.ppk' \
                  -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -name 'id_ecdsa*' -o -name 'id_dsa*' \) \
               ! -name '*.pub' ! -name 'ssh_host_*' -print0 2>/dev/null)
  fi

  # ── 6. SQLite · DB 파일 ───────────────────────────────────────────
  if want sqlite; then
    sec "6/10 SQLite · DB 파일 (*.sqlite* · *.db. cowrie 자체 것은 경로만 적는다)"
    while IFS= read -r -d '' f; do
      case "$f" in
        /opt/cowrie/*|/opt/decoy/*) note "허니팟 자체 $f ($(desc "$f")) — 지우지 않는다" ;;
        *) found "DB 파일 $f ($(desc "$f")) — 옛 적재 · 실험 잔재면 지운다"; todo "$f" ;;
      esac
    done < <(find /root /home /opt /etc /usr/local /var/lib/opsloop /var/lib/opsloop-upload /srv /tmp /var/tmp -xdev \
               \( -path /var/lib/docker -o -name .git \) -prune -o -type f \
               \( -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.sqlitedb' -o -name '*.db' -o -name '*.db-wal' -o -name '*.db-journal' \) \
               -print0 2>/dev/null)
  fi

  # ── 7. 도커 컨테이너 환경변수 ─────────────────────────────────────
  if want docker; then
    sec "7/10 도커 컨테이너 환경변수 (이름만 본다. 값은 찍지 않는다)"
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      n=0
      for c in $(docker ps -aq 2>/dev/null); do
        n=$((n + 1))
        name=$(docker inspect -f '{{.Name}}' "$c" 2>/dev/null | sed 's#^/##'); img=$(docker inspect -f '{{.Config.Image}}' "$c" 2>/dev/null)
        keys=$(docker inspect -f '{{range .Config.Env}}{{index (split . "=") 0}}{{"\n"}}{{end}}' "$c" 2>/dev/null \
               | grep -iE 'PASS|SECRET|TOKEN|KEY|CRED|PWD' | grep -vx 'GPG_KEY' | paste -sd, -)   # GPG_KEY 는 python 이미지의 공개 서명키 지문
        if [ -n "$keys" ]; then found "컨테이너 $name ($img) 환경변수 이름: $keys — 값은 재생성 스크립트 · 이미지에서 뺀다"; todo "컨테이너 $name 의 환경변수 $keys"
        else note "컨테이너 $name ($img): 비밀 이름의 환경변수 없음"; fi
      done
      [ "$n" -eq 0 ] && note "컨테이너 없음"
    else note "docker 없음 또는 접근 불가"; fi
  fi

  # ── 8. cloud-init 잔여 자료 ───────────────────────────────────────
  if want cloudinit; then
    sec "8/10 cloud-init 잔여 자료 (/var/lib/cloud · /etc/cloud)"
    for d in /var/lib/cloud/instances/*/; do
      [ -d "$d" ] && note "cloud-init 인스턴스 기록 ${d%/} ($(desc "${d%/}")) — 옛 인스턴스 ID 폴더가 이미지에 남는다"
    done
    for f in /var/lib/cloud/instances/*/user-data.txt /var/lib/cloud/instances/*/user-data.txt.i \
             /var/lib/cloud/instances/*/vendor-data.txt /var/lib/cloud/instances/*/vendor-data.txt.i \
             /var/lib/cloud/instances/*/cloud-config.txt /var/lib/cloud/instance/scripts/* \
             /var/lib/cloud/seed/*/user-data /var/lib/cloud/seed/*/meta-data; do
      [ -f "$f" ] || continue
      scan_file "$f"
      case "$f" in *user-data.txt) [ -s "$f" ] && note "$f ($(desc "$f")) — 첫 부팅 자료. 패턴 밖의 내용도 눈으로 본다" ;; esac
    done
    scan_tree /etc/cloud
  fi

  # ── 9. 계정 · sudo ────────────────────────────────────────────────
  if want accounts; then
    sec "9/10 계정 · sudo (임시 계정. 기본 계정 $def 는 참고)"
    while IFS=: read -r u _ uid _ _ home shell; do
      [ "$uid" -ge 1000 ] 2>/dev/null && [ "$u" != nobody ] || continue
      pw=$(awk -F: -v u="$u" '$1==u {print ($2 ~ /^\$/) ? "비밀번호 있음" : "비밀번호 없음"}' /etc/shadow 2>/dev/null); pw=${pw:-?}
      if id -Gn "$u" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; then su="sudo 그룹"; else su="sudo 그룹 아님"; fi
      if [ "$u" = "$def" ] && [ "$pw" = "비밀번호 없음" ]; then note "계정 $u (uid $uid, $shell, $su, $pw) — cloud-init 기본 계정"
      elif [ "$u" = ssm-user ] && [ "$pw" = "비밀번호 없음" ]; then note "계정 $u (uid $uid, $shell, $su, $pw) — SSM 세션이 만드는 계정"
      else found "계정 $u (uid $uid, $shell, $su, $pw, $home) — 임시 · 추가 계정이면 지운다 (userdel -r)"; todo "계정 $u"; fi
    done < /etc/passwd
    for u in $(awk -F: '$2 ~ /^\$/ {print $1}' /etc/shadow 2>/dev/null); do
      uid=$(id -u "$u" 2>/dev/null || echo 0)
      if [ "$uid" -lt 1000 ]; then found "시스템 계정 $u (uid $uid) 에 비밀번호가 있다"; todo "계정 $u 의 비밀번호"; fi
    done
    for f in /etc/sudoers.d/*; do
      [ -f "$f" ] || continue
      np=$(grep -c NOPASSWD "$f" 2>/dev/null); np=${np:-0}
      case "$(basename "$f")" in
        README|90-cloud-init-users) note "sudoers $f (NOPASSWD ${np}줄) — cloud-init 기본" ;;
        ssm-agent-users) note "sudoers $f (NOPASSWD ${np}줄) — SSM 에이전트 기본" ;;
        *) found "sudoers $f (NOPASSWD ${np}줄, 대상: $(grep -vE '^[[:space:]]*(#|$)' "$f" | awk '{print $1}' | sort -u | paste -sd, -))"; todo "$f" ;;
      esac
    done
    extra=$(grep -vE '^[[:space:]]*(#|$|Defaults|root[[:space:]]|%admin|%sudo|@includedir)' /etc/sudoers 2>/dev/null | paste -sd';' -)
    if [ -n "$extra" ]; then found "/etc/sudoers 기본 밖 규칙: $extra"; todo "/etc/sudoers 의 추가 규칙"; fi
    note "홈 폴더: $(ls -ld --time-style=+%Y-%m-%d /home/* /root 2>/dev/null | awk '{print $NF" ("$3", "$6")"}' | paste -sd';' -)"
    ll=$(lastlog 2>/dev/null | awk 'NR>1 && !/Never logged in/ {print $1}' | paste -sd, -)
    [ -n "$ll" ] && note "로그인 기록 있는 계정: $ll"
  fi

  # ── 10. 임시 폴더 ─────────────────────────────────────────────────
  if want tmp; then
    sec "10/10 임시 폴더 잔재 (/tmp · /var/tmp)"
    while IFS= read -r -d '' f; do found "임시 파일 $f ($(desc "$f"))"; todo "$f"; done \
      < <(find /tmp /var/tmp -maxdepth 2 ! -path /tmp/opsloop-collect.lock \
            \( -name 'opsloop*' -o -name '*.env' -o -name '.env*' -o -name '*.sql' -o -name '*.dump' -o -name '*.pem' -o -name '*.key' \
               -o -name '*.tar' -o -name '*.tgz' -o -name '*.tar.gz' \) -print0 2>/dev/null)
  fi

  # ── 요약 ──────────────────────────────────────────────────────────
  sec "요약"
  printf '[결과] %d건 · [참고] %d건\n' "$N_FOUND" "$N_NOTE"
  if [ "$N_FOUND" -gt 0 ]; then
    printf '지울 · 정리 후보 (이 스크립트는 지우지 않는다. 정리한 뒤 다시 돌려 0 을 본다):\n'
    printf '  %s\n' ${CLEAN[@]+"${CLEAN[@]}"} | sort -u
    printf '종료 코드 1\n'
    exit 1
  fi
  printf '이미지를 떠도 된다. 종료 코드 0\n'
  exit 0
}

main "$@"
