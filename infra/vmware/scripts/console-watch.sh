#!/usr/bin/env bash
# 콘솔 진입점 감시 (이슈 #43). 알림 발송기가 콘솔 안에서 돌아 콘솔 두 대가 다 죽으면 알릴 경로가 없다.
# 그래서 Mac 에서 따로 본다. launchd(local.opsloop.console-watch)가 60초마다 부른다. install-console-watch.sh 가
# 이 파일을 ~/Library/Application Support/OpsLoop/bin 에 복사해 두고 그 사본을 부른다 (브랜치를 바꿔도 흔들리지 않는다).
# 한 회차: 진입점 /health 를 5초 간격으로 최대 3번 본다(curl -m 3). 한 번이라도 200 이면 UP, 3번 모두 실패면 DOWN.
#   HAProxy 는 콘솔 두 대가 다 빠지면 503 을 준다. 콘솔 /health 는 DB 가 닿는지도 보므로 DB 가 멈춰도 DOWN 이 된다.
# 알림: UP→DOWN 한 번 · DOWN 이 이어지면 30분마다 다시 · DOWN→UP 복구 한 번. macOS 알림과 기록 파일에 남긴다.
#   ~/.config/opsloop/console-watch.env (0600 · 본인 소유가 아니면 거부) 에 WEBHOOK_URL=https://... 이 있으면
#   {"text": ...} 를 POST 한다(curl -m 10). 주소는 기록 · 화면 · 명령줄에 남기지 않는다(curl 설정은 표준 입력으로 준다).
#   본문에는 내부 주소를 넣지 않는다.
# 점검 창: ~/.config/opsloop/console-watch.pause 에 만료 시각(epoch 초)이 있고 아직 안 지났으면 알리지 않고 상태만 적는다.
#   창 안에서 시작된 DOWN 이 창이 끝난 뒤에도 이어지면 그때 알린다. DOWN 을 알린 뒤 창 안에서 복구되면 창이 끝난 뒤 복구를 알린다.
#   복구를 알리기 전에 다시 DOWN 이 되면 처음 DOWN 이 이어진 것으로 본다(복구 알림을 잃지 않는다 · 30분 재알림도 처음 알림부터 센다).
# 사용: console-watch.sh               한 회차 (launchd 가 부르는 모양)
#       console-watch.sh --status      마지막 상태 · 점검 창 · 웹훅 설정 여부 (주소는 내지 않는다)
#       console-watch.sh --pause <분>  지금부터 <분> 동안 점검 창을 둔다 (1 ~ 10080)
#       console-watch.sh --resume      점검 창을 없앤다
#       console-watch.sh --test-alert  알림 경로를 시험한다 (macOS 알림 · 웹훅)
# 기록: ~/Library/Logs/opsloop/console-watch.log (1 MiB 를 넘으면 .1 로 한 벌 돌린다)
# 상태: ~/Library/Application Support/OpsLoop/console-watch.state
#   한 번에 한 회차만 돈다(같은 폴더의 console-watch.lock). 다른 회차가 돌고 있으면 기록만 남기고 건너뛴다
# 환경변수(시험 · 임시 변경): CONSOLE_WATCH_URL · CONSOLE_WATCH_TRIES(3) · CONSOLE_WATCH_GAP(5초) · CONSOLE_WATCH_RENOTIFY(1800초)
set -uo pipefail
umask 077
# launchd 의 PATH 는 짧다. 기본 경로는 뒤에 붙인다(시험은 가짜 curl · osascript 를 앞에 둔다)
PATH="${PATH:+$PATH:}/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

URL=${CONSOLE_WATCH_URL:-http://192.168.70.254:8443/health}
TRIES=${CONSOLE_WATCH_TRIES:-3}
GAP=${CONSOLE_WATCH_GAP:-5}
RENOTIFY=${CONSOLE_WATCH_RENOTIFY:-1800}
CONF_DIR="$HOME/.config/opsloop"
ENV_FILE="$CONF_DIR/console-watch.env"
PAUSE_FILE="$CONF_DIR/console-watch.pause"
LOG_DIR="$HOME/Library/Logs/opsloop"
LOG="$LOG_DIR/console-watch.log"
STATE_DIR="$HOME/Library/Application Support/OpsLoop"
STATE="$STATE_DIR/console-watch.state"
# 한 번에 한 회차만 돈다. launchd 회차와 손으로 돌린 회차가 겹치면 같은 전이를 두 번 알린다.
#   잠금은 pid 를 가리키는 심볼릭 링크다(ln -s 는 이미 있으면 실패하므로 만들기가 원자적이다)
LOCK="$STATE_DIR/console-watch.lock"
LOCK_STALE_MIN=5
LOG_MAX=1048576
PAUSE_MAX_MIN=10080

# 0 이상의 정수 (12자리까지. 산술 비교가 넘치지 않게)
isnum() {
  case "$1" in '' | *[!0-9]*) return 1 ;; esac
  [ "${#1}" -le 12 ]
}

usage() { sed -n '2,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

log() {
  local line size
  line="$(date '+%F %T %z') $*"
  mkdir -p "$LOG_DIR" 2>/dev/null
  if [ -f "$LOG" ]; then
    size=$(wc -c < "$LOG" | tr -d ' ')
    if isnum "$size" && [ "$size" -gt "$LOG_MAX" ]; then
      mv -f "$LOG" "$LOG.1" 2>/dev/null
    fi
  fi
  printf '%s\n' "$line" >> "$LOG"
  # 손으로 돌릴 때만 화면에도 낸다. launchd 에서는 표준 출력이 같은 기록 파일이라 두 번 적힌다
  if [ -t 1 ]; then printf '%s\n' "$line"; fi
}

fmt_time() {
  date -r "$1" '+%F %H:%M' 2>/dev/null || date -d "@$1" '+%F %H:%M' 2>/dev/null || printf '%s\n' "$1"
}

fmt_dur() {
  local s=$1
  [ "$s" -ge 0 ] 2>/dev/null || s=0
  if [ "$s" -lt 60 ]; then
    printf '%s초\n' "$s"
  elif [ "$s" -lt 3600 ]; then
    printf '%s분\n' "$((s / 60))"
  else
    printf '%s시간 %s분\n' "$((s / 3600))" "$((s % 3600 / 60))"
  fi
}

reason() {
  case "$1" in
    0) printf 'HTTP %s\n' "$2" ;;
    6) echo "주소 풀이 실패" ;;
    7) echo "연결 실패" ;;
    28) echo "시간 초과" ;;
    52) echo "빈 응답" ;;
    56) echo "수신 끊김" ;;
    *) printf 'curl 종료 %s\n' "$1" ;;
  esac
}

# 진입점을 본다. RESULT(UP|DOWN) · DETAIL(기록용) · LAST_REASON(알림용 마지막 실패 사유)을 정한다
check() {
  local i=1 code rc why fails=""
  RESULT=DOWN
  DETAIL=""
  LAST_REASON=""
  while :; do
    code=$(curl -q -s -o /dev/null --noproxy '*' -m 3 -w '%{http_code}' "$URL" 2>/dev/null)
    rc=$?
    case "$code" in [0-9][0-9][0-9]) ;; *) code=000 ;; esac
    if [ "$rc" = 0 ] && [ "$code" = 200 ]; then
      RESULT=UP
      if [ -z "$fails" ]; then DETAIL="HTTP 200"; else DETAIL="HTTP 200 · ${i}번째 (앞선 실패: $fails)"; fi
      return 0
    fi
    why=$(reason "$rc" "$code")
    LAST_REASON=$why
    fails=${fails:+$fails · }$why
    [ "$i" -ge "$TRIES" ] && break
    i=$((i + 1))
    sleep "$GAP"
  done
  DETAIL="${TRIES}번 모두 실패 ($fails)"
}

load_state() {
  S_STATE=UNKNOWN S_SINCE=0 S_DOWN_SINCE=0 S_ALERTED=0 S_LAST_ALERT=0 S_LAST_CHECK=0 S_DETAIL=""
  [ -f "$STATE" ] || return 0
  local k v
  while IFS='=' read -r k v; do
    case "$k" in
      state) case "$v" in UP | DOWN) S_STATE=$v ;; esac ;;
      since) if isnum "$v"; then S_SINCE=$v; fi ;;
      down_since) if isnum "$v"; then S_DOWN_SINCE=$v; fi ;;
      alerted) case "$v" in 0 | 1) S_ALERTED=$v ;; esac ;;
      last_alert) if isnum "$v"; then S_LAST_ALERT=$v; fi ;;
      last_check) if isnum "$v"; then S_LAST_CHECK=$v; fi ;;
      detail) S_DETAIL=$v ;;
    esac
  done < "$STATE"
  return 0
}

save_state() {
  mkdir -p "$STATE_DIR" || return 1
  local tmp="$STATE.tmp.$$"
  printf 'state=%s\nsince=%s\ndown_since=%s\nalerted=%s\nlast_alert=%s\nlast_check=%s\ndetail=%s\n' \
    "$S_STATE" "$S_SINCE" "$S_DOWN_SINCE" "$S_ALERTED" "$S_LAST_ALERT" "$S_LAST_CHECK" "$S_DETAIL" > "$tmp" \
    && mv -f "$tmp" "$STATE"
}

# 점검 창이면 PAUSE_UNTIL 을 정하고 0. 파일이 없거나 지났거나 읽지 못하면 1 (읽지 못하면 기록하고 알린다)
paused() {
  PAUSE_UNTIL=0
  [ -f "$PAUSE_FILE" ] || return 1
  local v
  v=$(head -c 64 "$PAUSE_FILE" 2>/dev/null | tr -d ' \t\r\n')
  if ! isnum "$v"; then
    log "  점검 창 파일을 읽지 못했다 (만료 시각 epoch 초가 아니다) · 무시한다"
    return 1
  fi
  [ "$v" -gt "$(date +%s)" ] || return 1
  PAUSE_UNTIL=$v
  return 0
}

# 웹훅 설정 파일을 읽어 WEBHOOK 에 주소를 둔다. 없거나 거부하면 1 (까닭은 WEBHOOK_STATE). 주소는 어디에도 내지 않는다
webhook_url() {
  WEBHOOK=""
  WEBHOOK_STATE="없음"
  [ -e "$ENV_FILE" ] || return 1
  if [ ! -f "$ENV_FILE" ]; then
    WEBHOOK_STATE="거부 (보통 파일이 아니다)"
    return 1
  fi
  local perm mode owner line val=""
  case "$(uname -s)" in
    Darwin) perm=$(stat -L -f '%Lp %u' "$ENV_FILE" 2>/dev/null) ;;
    *) perm=$(stat -L -c '%a %u' "$ENV_FILE" 2>/dev/null) ;;
  esac
  mode=${perm%% *}
  owner=${perm##* }
  if [ "$mode" != 600 ]; then
    WEBHOOK_STATE="거부 (권한 0${mode:-?} · 0600 이어야 한다. chmod 600 $ENV_FILE)"
    return 1
  fi
  if [ "$owner" != "$(id -u)" ]; then
    WEBHOOK_STATE="거부 (본인 소유가 아니다)"
    return 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in
      WEBHOOK_URL=* | "export WEBHOOK_URL="*) val=${line#*WEBHOOK_URL=} ;;
    esac
  done < "$ENV_FILE"
  case "$val" in
    \"*\") val=${val#\"} val=${val%\"} ;;
    \'*\') val=${val#\'} val=${val%\'} ;;
  esac
  if [ -z "$val" ]; then
    WEBHOOK_STATE="없음 (WEBHOOK_URL 이 비었다)"
    return 1
  fi
  case "$val" in
    *[[:space:]\"\'\\]* | *[[:cntrl:]]*)
      WEBHOOK_STATE="거부 (주소에 쓸 수 없는 문자가 있다)"
      return 1 ;;
    https://?*) ;;
    *)
      WEBHOOK_STATE="거부 (https:// 주소가 아니다)"
      return 1 ;;
  esac
  WEBHOOK=$val
  WEBHOOK_STATE="설정됨"
  return 0
}

json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '%s' "$s" | LC_ALL=C tr -d '\000-\037'
}

send_webhook() {
  if ! webhook_url; then
    case "$WEBHOOK_STATE" in 거부*) log "  웹훅 $WEBHOOK_STATE · 보내지 않는다" ;; esac
    return 0
  fi
  local body code rc
  body="{\"text\":\"$(json_escape "$1")\"}"
  # 주소는 명령줄(ps 로 보인다)에 두지 않고 curl 설정으로 표준 입력에 준다. 오류 문구도 버린다(주소가 섞인다)
  code=$(printf 'url = "%s"\n' "$WEBHOOK" | curl -q -s -o /dev/null -w '%{http_code}' -m 10 --proto '=https' \
    -H 'Content-Type: application/json' --data-binary "$body" -K - 2>/dev/null)
  rc=$?
  WEBHOOK=""
  case "$code" in [0-9][0-9][0-9]) ;; *) code=000 ;; esac
  if [ "$rc" = 0 ]; then
    case "$code" in
      2??)
        log "  웹훅 보냄 (HTTP $code)"
        return 0 ;;
    esac
  fi
  log "  웹훅 실패 (curl 종료 $rc · HTTP $code)"
  return 0
}

alert() {  # $1 제목 · $2 본문
  log "  알림: $1 · $2"
  # 문구는 AppleScript 소스에 끼우지 않고 인자로 넘긴다
  osascript -e 'on run argv' -e 'display notification (item 2 of argv) with title (item 1 of argv)' -e 'end run' \
    "$1" "$2" >/dev/null 2>&1 || log "  macOS 알림 실패"
  send_webhook "$1 · $2"
}

# 잠금을 잡으면 0. 다른 회차가 돌고 있으면 1 (LOCK_OWNER 에 pid).
#   가리키는 프로세스가 없거나 잠금이 ${LOCK_STALE_MIN}분보다 오래됐으면(한 회차는 1분 안에 끝난다 · pid 재사용) 남은 잠금으로 보고 치운다
take_lock() {
  local pid
  LOCK_OWNER=""
  mkdir -p "$STATE_DIR" 2>/dev/null || return 0
  ln -s "$$" "$LOCK" 2>/dev/null && return 0
  pid=$(readlink "$LOCK" 2>/dev/null)
  if isnum "$pid" && kill -0 "$pid" 2>/dev/null && [ -z "$(find "$LOCK" -maxdepth 0 -mmin +"$LOCK_STALE_MIN" 2>/dev/null)" ]; then
    LOCK_OWNER=$pid
    return 1
  fi
  log "  남은 잠금을 치운다 (pid ${pid:-?})"
  rm -f "$LOCK"
  ln -s "$$" "$LOCK" 2>/dev/null && return 0
  LOCK_OWNER=$(readlink "$LOCK" 2>/dev/null)
  return 1
}

drop_lock() {
  [ "$(readlink "$LOCK" 2>/dev/null)" = "$$" ] && rm -f "$LOCK"
  return 0
}

run_once() {
  local now pause=0
  if ! take_lock; then
    log "다른 회차(pid ${LOCK_OWNER:-?})가 돌고 있다 · 이번 회차는 건너뛴다"
    return 0
  fi
  trap drop_lock EXIT
  check
  now=$(date +%s)
  load_state
  if paused; then pause=1; fi

  if [ "$RESULT" = DOWN ]; then
    if [ "$S_STATE" = UP ] && [ "$S_ALERTED" = 1 ]; then
      # 점검 창 안에서 복구돼 복구 알림을 미뤄 둔 채 다시 DOWN. 알림을 받은 사람에게는 DOWN 이 이어진 것이다.
      #   알림 상태를 이어 간다. 새 DOWN 으로 시작하면 미뤄 둔 복구 알림이 사라져 DOWN 알림만 남는다
      [ "$S_DOWN_SINCE" -gt 0 ] || S_DOWN_SINCE=$now
      S_STATE=DOWN S_SINCE=$S_DOWN_SINCE
      log "DOWN · $DETAIL · 복구를 알리기 전에 다시 DOWN ($(fmt_time "$S_DOWN_SINCE") 부터 이어서 센다)"
    elif [ "$S_STATE" != DOWN ]; then
      S_STATE=DOWN S_SINCE=$now S_DOWN_SINCE=$now S_ALERTED=0 S_LAST_ALERT=0
      log "DOWN · $DETAIL"
    else
      log "DOWN 이어짐 ($(fmt_dur $((now - S_SINCE)))째) · $DETAIL"
    fi
    if [ "$pause" = 1 ]; then
      log "  점검 창 ($(fmt_time "$PAUSE_UNTIL") 까지) · 알리지 않는다"
    elif [ "$S_ALERTED" = 0 ]; then
      alert "OpsLoop 콘솔 DOWN" "진입점 /health ${TRIES}번 모두 실패 ($LAST_REASON) · $(fmt_time "$S_SINCE") 부터"
      S_ALERTED=1 S_LAST_ALERT=$now
    elif [ $((now - S_LAST_ALERT)) -ge "$RENOTIFY" ]; then
      alert "OpsLoop 콘솔 계속 DOWN" "$(fmt_dur $((now - S_SINCE)))째 ($LAST_REASON) · $(fmt_time "$S_SINCE") 부터"
      S_LAST_ALERT=$now
    fi
  else
    if [ "$S_STATE" = DOWN ]; then
      log "UP · 복구 (DOWN $(fmt_dur $((now - S_SINCE)))) · $DETAIL"
      S_STATE=UP S_SINCE=$now
    else
      [ "$S_STATE" = UP ] || S_SINCE=$now
      S_STATE=UP
      log "UP · $DETAIL"
    fi
    if [ "$S_ALERTED" = 1 ]; then
      if [ "$pause" = 1 ]; then
        log "  점검 창 ($(fmt_time "$PAUSE_UNTIL") 까지) · 복구 알림은 창이 끝난 뒤에"
      else
        alert "OpsLoop 콘솔 복구" "DOWN $(fmt_dur $((S_SINCE - S_DOWN_SINCE))) 뒤 복구 · $(fmt_time "$S_SINCE")"
        S_ALERTED=0
      fi
    fi
  fi
  S_LAST_CHECK=$now S_DETAIL=$DETAIL
  save_state || log "  상태 파일을 쓰지 못했다: $STATE"
}

status() {
  load_state
  if [ "$S_STATE" = UNKNOWN ]; then
    echo "상태: 아직 없음 (한 번도 돌지 않았다)"
  else
    echo "상태: $S_STATE ($(fmt_time "$S_SINCE") 부터 · $(fmt_dur $(($(date +%s) - S_SINCE)))째)"
    echo "마지막 확인: $(fmt_time "$S_LAST_CHECK") · $S_DETAIL"
    if [ "$S_ALERTED" = 1 ]; then echo "DOWN 알림: 보냄 ($(fmt_time "$S_LAST_ALERT")) · 복구 알림 대기"; fi
  fi
  if paused; then echo "점검 창: $(fmt_time "$PAUSE_UNTIL") 까지 (알리지 않는다)"; else echo "점검 창: 없음"; fi
  webhook_url || true
  WEBHOOK=""
  echo "웹훅: $WEBHOOK_STATE"
  echo "감시 주소: $URL · 기록: $LOG"
}

for pair in "TRIES=$TRIES" "GAP=$GAP" "RENOTIFY=$RENOTIFY"; do
  if ! isnum "${pair#*=}"; then
    echo "CONSOLE_WATCH_${pair%%=*} 는 0 이상의 정수여야 한다" >&2
    exit 2
  fi
done
if [ "$TRIES" -lt 1 ]; then
  echo "CONSOLE_WATCH_TRIES 는 1 이상이어야 한다" >&2
  exit 2
fi

case "${1:-}" in
  "")
    run_once ;;
  --status)
    status ;;
  --pause)
    m=${2:-}
    if ! isnum "$m" || [ "$m" -lt 1 ] || [ "$m" -gt "$PAUSE_MAX_MIN" ]; then
      echo "--pause <분>: 1 ~ $PAUSE_MAX_MIN 사이 정수" >&2
      exit 2
    fi
    mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
    until_at=$(($(date +%s) + m * 60))
    printf '%s\n' "$until_at" > "$PAUSE_FILE.tmp.$$" && mv -f "$PAUSE_FILE.tmp.$$" "$PAUSE_FILE" || exit 1
    log "점검 창 둠 ($(fmt_time "$until_at") 까지 · ${m}분)"
    echo "점검 창: $(fmt_time "$until_at") 까지" ;;
  --resume)
    rm -f "$PAUSE_FILE"
    log "점검 창 없앰"
    echo "점검 창을 없앴다" ;;
  --test-alert)
    alert "OpsLoop 콘솔 감시 시험" "알림 경로 시험 · $(fmt_time "$(date +%s)")" ;;
  -h | --help)
    usage ;;
  *)
    echo "모르는 옵션: $1 (--help)" >&2
    exit 2 ;;
esac
