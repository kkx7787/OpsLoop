#!/usr/bin/env bash
# launchd 가 하루 세 번(04:30 · 12:30 · 20:30) 부르는 백업 실행기. install-backup-agent.sh 가 이 파일과 backup-db.sh 를
# ~/Library/Application Support/OpsLoop/bin 에 복사해 두고 그 사본을 부른다 (브랜치를 바꿔도 흔들리지 않는다).
# 매번 임시 DB 에 실제로 복원해 건수를 대조한다(VERIFY=restore).
# 실패 재시도 (이슈 #91): 처음 1번 + 재시도 최대 2번, 재시도 사이 180초. 한 회차 전체(재시도 · 복원 시험 포함)는
#   시작 뒤 20분(백업 창) 안에 끝낸다. 창 끝 30초 전까지 끝나지 않은 시도는 멈추라고 하고(TERM. backup-db.sh 가 임시 파일 ·
#   시험 DB 를 치운다), 창 끝에도 남아 있으면 끊는다(KILL). 기다린 뒤 창 안에 다시 돌 수 없으면 더 돌지 않는다.
#   시도 중 Mac 이 잠들어 창 끝을 넘겨 깨면 멈추라고 한 뒤 30초는 정리할 틈을 주고 끊는다(그만큼 창 밖에서 끝날 수 있다).
# 알림(macOS): 첫 실패 때 바로 '재시도 예정', 재시도까지 모두 실패하면 '재시도 모두 실패', 재시도로 성공하면 '재시도 뒤 성공'
#   한 번. 다시 돌 수 없는 첫 실패는 '실패' 한 번이다.
# 기록(backup.log): '== <KST 시각> 백업 시작|성공|실패' 줄은 회차마다 한 번씩이다. 복원 훈련 도구(지금 백업 중인지)와
#   진입점 감시(마지막 성공 백업이 오래됐는지)가 읽으므로 모양을 바꾸지 않는다. 성공 · 실패 줄 뒤 괄호는 덧붙인 설명이다.
#   시도마다 '-- <KST 시각> 시도 n/3' 줄을, 실패하면 '-- … 시도 n/3 실패 (…)' 줄을 남긴다.
# 환경변수(시험 · 임시 변경): BACKUP_RETRY_WAIT(재시도 사이 대기 180초) · BACKUP_WINDOW(백업 창 1200초)
set -uo pipefail
export PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
BIN=$(cd "$(dirname "$0")" && pwd)
DEST=${OPSLOOP_BACKUP_DIR:-$HOME/opsloop-backup}
TRIES=3
WAIT=${BACKUP_RETRY_WAIT:-180}
WINDOW=${BACKUP_WINDOW:-1200}
GRACE=30

# 0 이상의 정수 (9자리까지)
isnum() {
  case "$1" in '' | *[!0-9]*) return 1 ;; esac
  [ "${#1}" -le 9 ]
}

for pair in "BACKUP_RETRY_WAIT=$WAIT" "BACKUP_WINDOW=$WINDOW"; do
  if ! isnum "${pair#*=}"; then
    echo "${pair%%=*} 는 0 이상의 정수여야 한다" >&2
    exit 2
  fi
done
if [ "$WINDOW" -lt 1 ]; then
  echo "BACKUP_WINDOW 는 1 이상이어야 한다" >&2
  exit 2
fi
# 창이 짧으면(시험) 멈춤 여유도 줄인다
[ "$WINDOW" -gt $((GRACE * 2)) ] || GRACE=$((WINDOW / 2))

# 기록 시각은 늘 KST 로 적는다 (읽는 쪽이 'KST' 를 +09:00 으로 푼다)
stamp() { TZ=Asia/Seoul date '+%F %T %Z'; }

notify() {  # $1 제목 · $2 본문. 문구는 AppleScript 소스에 끼우지 않고 인자로 넘긴다
  osascript -e 'on run argv' -e 'display notification (item 2 of argv) with title (item 1 of argv)' -e 'end run' \
    "$1" "$2" >/dev/null 2>&1 || true
}

START=$(date +%s)
STOP_AT=$((START + WINDOW - GRACE))   # 이때까지 끝나지 않은 시도는 멈추라고 한다 (TERM)
END_AT=$((START + WINDOW))            # 이때도 남아 있으면 끊는다 (KILL)
PID="" DOG="" SLP="" n=0 RC=0 CUT=0

# 시도 하나를 지킨다. $1 은 시도의 프로세스 묶음(backup-db.sh 와 그 ssh · 파이프).
#   끊는 것은 창 끝이다. 잠자기로 창 끝을 넘겨 깨어나 늦게 멈추라고 했으면 그 뒤 GRACE 초는 정리할 틈을 준다
watchdog() {
  local kill_at
  while [ "$(date +%s)" -lt "$STOP_AT" ]; do sleep 1; done
  kill -TERM -- "-$1" 2>/dev/null || return 0
  kill_at=$(($(date +%s) + GRACE))
  [ "$kill_at" -gt "$END_AT" ] || kill_at=$END_AT
  while [ "$(date +%s)" -lt "$kill_at" ]; do sleep 1; done
  kill -KILL -- "-$1" 2>/dev/null
  return 0
}

# launchctl bootout 등으로 실행기가 멈추면 돌던 시도도 함께 멈추고 실패 줄을 남긴다.
#   시도는 따로 묶여 있어 launchd 가 실행기 묶음을 멈춰도 남는다. 기록이 '백업 시작' 으로 끝나 있으면 백업 중으로 보인다
on_signal() {
  [ -z "$DOG" ] || kill -TERM -- "-$DOG" 2>/dev/null
  [ -z "$PID" ] || kill -TERM -- "-$PID" 2>/dev/null
  [ -z "$SLP" ] || kill -TERM "$SLP" 2>/dev/null
  echo "== $(stamp) 백업 실패 (실행기가 멈춤 · 시도 $n/$TRIES)"
  exit 143
}
trap on_signal TERM INT HUP

# 시도 하나. RC 에 종료 코드, 창 끝에 닿아 멈췄으면 CUT=1
attempt() {
  CUT=0
  set -m    # 시도와 감시가 각자 프로세스 묶음을 갖게 한다 (묶음째 멈춘다)
  VERIFY=restore bash "$BIN/backup-db.sh" "$DEST" < /dev/null 2>&1 &
  PID=$!
  watchdog "$PID" &
  DOG=$!
  set +m
  wait "$PID" 2>/dev/null
  RC=$?
  kill -TERM -- "-$DOG" 2>/dev/null
  wait "$DOG" 2>/dev/null
  PID="" DOG=""
  if [ "$RC" -ne 0 ] && [ "$(date +%s)" -ge "$STOP_AT" ]; then CUT=1; fi
}

# 한 회차. 성공이면 0, 모두 실패면 마지막 시도의 종료 코드
run_backup() {
  echo "== $(stamp) 백업 시작"
  while :; do
    n=$((n + 1))
    echo "-- $(stamp) 시도 $n/$TRIES"
    attempt
    if [ "$RC" -eq 0 ]; then
      if [ "$n" -eq 1 ]; then
        echo "== $(stamp) 백업 성공"
      else
        echo "== $(stamp) 백업 성공 (시도 $n/$TRIES · 재시도 뒤 성공)"
        notify "OpsLoop DB 백업 재시도 뒤 성공" "시도 $n/$TRIES 에서 성공 · $DEST/backup.log"
      fi
      return 0
    fi
    if [ "$CUT" = 1 ]; then why="백업 창 ${WINDOW}초 끝에 멈춤 · 종료 코드 $RC"; else why="종료 코드 $RC"; fi
    [ "$n" -lt "$TRIES" ] || break
    if [ $(($(date +%s) + WAIT)) -ge "$STOP_AT" ]; then
      echo "-- $(stamp) 시도 $n/$TRIES 실패 ($why) · ${WAIT}초 기다리면 백업 창(${WINDOW}초) 안에 끝낼 수 없어 다시 돌지 않는다"
      break
    fi
    echo "-- $(stamp) 시도 $n/$TRIES 실패 ($why) · ${WAIT}초 뒤 다시 돈다"
    if [ "$n" -eq 1 ]; then
      notify "OpsLoop DB 백업 실패 · 재시도 예정" "시도 1/$TRIES 실패 ($why) · ${WAIT}초 뒤 다시 돈다 · $DEST/backup.log"
    fi
    # 기다리는 동안에도 멈춤 신호를 바로 받게 뒤로 돌려 기다린다
    sleep "$WAIT" &
    SLP=$!
    wait "$SLP"
    SLP=""
    if [ "$(date +%s)" -ge "$STOP_AT" ]; then
      echo "-- $(stamp) 기다리는 사이 백업 창이 지났다 (Mac 잠자기?) · 다시 돌지 않는다"
      break
    fi
  done
  echo "== $(stamp) 백업 실패 ($why · 시도 $n/$TRIES)"
  if [ "$n" -gt 1 ]; then
    notify "OpsLoop DB 백업 실패 · 재시도 모두 실패" "시도 $n/$TRIES 모두 실패 ($why) · $DEST/backup.log 확인"
  else
    notify "OpsLoop DB 백업 실패" "시도 1/$TRIES 실패 ($why) · 백업 창 안에 다시 돌 수 없다 · $DEST/backup.log 확인"
  fi
  return "$RC"
}

run_backup
