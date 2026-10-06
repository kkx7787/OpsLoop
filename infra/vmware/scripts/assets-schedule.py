#!/usr/bin/env python3
"""자산 조사: 매일 05:10 KST, 일부 실패는 4시간, 적재 실패는 15분 뒤 재시도.

launchd가 로그인 때와 15분마다 확인한다. Mac·VM을 깨우거나 AWS 인증을 갱신하지 않는다.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))


def slot(now):
    return (datetime.fromtimestamp(now, KST) - timedelta(hours=5, minutes=10)).date().isoformat()


def valid_state(state, now):
    try:
        return (isinstance(state, dict) and state['exit_code'] in (0, 1, 2)
                and 0 < float(state['finished_at']) <= now)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def due(state, now):
    if not valid_state(state, now):
        return True
    last = float(state['finished_at'])
    return slot(last) != slot(now) or (state['exit_code'] != 0
            and now - last >= (14400 if state['exit_code'] == 1 else 900))


def stamp():
    return datetime.now(KST).strftime('%Y-%m-%d %H:%M:%S KST')


def run_bounded(command, timeout=1200):
    """매달린 하위 프로세스까지 정리해 다음 회차가 막히지 않게 한다."""
    process = subprocess.Popen(command, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        except ProcessLookupError:
            pass
        return 2


def clock_ready():
    """시계를 바꾸지 않고 S3 서명 전에 data01과 Mac 시각을 확인한다."""
    ssh = ['ssh', '-F', str(Path.home() / '.ssh/config.opsloop'), '-o', 'BatchMode=yes',
           '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2', 'data01']
    for attempt in range(2):
        before = time.time()
        try:
            result = subprocess.run(ssh + ['date +%s'], text=True, capture_output=True, timeout=30)
            after = time.time()
            remote = int(result.stdout.strip())
            if result.returncode != 0:
                return False
            if after - before <= 3 and abs(remote - (before + after) / 2) <= 2:
                return True
            print('-- 시계 차이 또는 측정 지연: chrony 동기 확인 뒤 다시 측정', flush=True)
            if attempt == 0:
                subprocess.run(ssh + ['chronyc waitsync 6 0.5 0 5'], capture_output=True, timeout=40)
        except (ValueError, OSError, subprocess.TimeoutExpired):
            return False
    return False


def notify():
    try:
        subprocess.run(['osascript', '-e', 'on run argv', '-e',
                        'display notification (item 2 of argv) with title (item 1 of argv)', '-e', 'end run',
                        'OpsLoop 자산 수집 실패', '종료 코드 2 · 15분 뒤 재시도 · ~/opsloop-assets/assets.log 확인'],
                       capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scheduled', action='store_true')
    args = parser.parse_args(argv)
    dest = Path.home() / 'opsloop-assets'
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_path = dest / 'schedule.json'
    with (dest / 'schedule.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        try:
            state = json.loads(state_path.read_text())
        except (OSError, ValueError):
            state = {}
        if not valid_state(state, time.time()):
            state = {}
        if args.scheduled and not due(state, time.time()):
            return 0
        print(f'== {stamp()} 자산 수집 시작', flush=True)

        def save(code):
            temp = dest / 'schedule.json.tmp'
            temp.write_text(json.dumps({'finished_at': time.time(), 'exit_code': code}) + '\n')
            temp.replace(state_path)

        save(2)  # 중간에 종료돼도 오래된 성공 기록으로 다음 실행을 건너뛰지 않는다
        awake = None
        code = 2
        try:
            try:
                awake = subprocess.Popen(['caffeinate', '-i', '-s', '-w', str(os.getpid())],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                pass
            if clock_ready():
                code = run_bounded(['/bin/bash', str(Path(__file__).with_name('collect-assets.sh'))])
                code = code if code in (0, 1) else 2
            else:
                print('-- data01 연결 또는 시계 확인 실패. 적재하지 않고 다음 회차에 재시도합니다.', flush=True)
        except (KeyboardInterrupt, OSError):
            code = 2
        finally:
            if awake is not None:
                awake.terminate()
                try:
                    awake.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    awake.kill()
                    awake.wait()
            save(code)
        if code == 0:
            print(f'== {stamp()} 자산 수집 성공', flush=True)
        elif code == 1:
            print(f'== {stamp()} 자산 수집 일부 실패 (적재는 됐다. 4시간 뒤 재시도)', flush=True)
        else:
            print(f'== {stamp()} 자산 수집 실패 (종료 코드 2)', flush=True)
            if state.get('exit_code') != 2 or slot(float(state['finished_at'])) != slot(time.time()):
                notify()
        return code


if __name__ == '__main__':
    def stopped(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stopped)
    raise SystemExit(main())
