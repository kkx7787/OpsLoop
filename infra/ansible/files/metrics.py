#!/usr/bin/env python3
"""노드 지표 한 줄 (WBS 3.4.2 · 관제 대상 web-01).

opsloop-metrics.timer 가 1분마다 한 번 돌린다. 상주하지 않는다 (계획 개정 4.3: exporter 대신 JSON 줄).
/proc 와 systemd 에서 값을 읽어 지표 파일 끝에 JSON 한 줄을 붙이고 끝난다.
Alloy 가 이 파일을 job=metrics 로 수집 관문에 보내고, 데이터 노드의 다리(pull_loki.py)가 node_metrics 로 옮긴다.

줄 (키 순서 고정 · 공백 없음. 줄 내용이 곧 line_hash 이므로 µs 시각과 seq 로 줄마다 다르게 한다)
  {"ts":"2026-09-21T07:00:00.123456+00:00","host":"opsloop-web-01","seq":123,"cpu_pct":1.2,"mem_used_pct":40.1,
   "mem_avail_mb":400,"swap_used_pct":0.0,"disk_root_pct":23.0,"load1":0.05,"nginx_active":true,"sshd_active":true}

  seq            재부팅 뒤에도 계속 는다 ($OPSLOOP_HOME/metrics.seq). 다리가 건너뛴 번호를 seq_gaps 로 센다.
                 번호를 먼저 저장하고 줄을 쓴다. 중간에 죽으면 번호가 하나 빌 뿐 같은 번호가 두 번 나오지 않는다.
                 번호 파일이 없거나 깨졌으면 지표 파일 끝의 마지막 번호에서 잇는다.
  cpu_pct        지난 실행 뒤로의 평균 (/proc/stat 차분). 이전 표본이 없거나 재부팅했으면 1초를 재서 쓴다.
  mem_used_pct   (MemTotal - MemAvailable) / MemTotal
  disk_root_pct  df 와 같은 셈 (예약 블록을 뺀, 일반 사용자가 쓸 수 있는 공간 기준)
  sshd_active    ssh.service 나 ssh.socket 이 켜져 있으면 참 (Ubuntu 24.04 는 소켓으로 기동한다)

값을 하나라도 읽지 못하면 줄을 쓰지 않고 종료 코드 1 로 끝난다 (숫자가 빠진 줄은 다리가 malformed 로 센다).

환경변수
  OPSLOOP_METRICS_LOG  지표 파일 (기본 /var/log/opsloop/metrics.jsonl)
  OPSLOOP_HOME         상태 폴더 (기본 /var/lib/opsloop). metrics.seq · metrics.cpu · metrics.lock
  OPSLOOP_PROC         /proc 위치 (시험용)
"""
import fcntl
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

LOG = os.environ.get("OPSLOOP_METRICS_LOG", "/var/log/opsloop/metrics.jsonl")
HOME = os.environ.get("OPSLOOP_HOME", "/var/lib/opsloop")
PROC = os.environ.get("OPSLOOP_PROC", "/proc")
NGINX_UNITS = ("nginx.service",)
SSHD_UNITS = ("ssh.service", "ssh.socket")
TAIL = 64 * 1024                  # 번호를 되살릴 때 읽는 지표 파일 끝부분

_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))


def log(msg, level=6):
    print(f"<{level}>{msg}" if _JOURNAL else msg, flush=True)


def write_atomic(path, text):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=f".{os.path.basename(path)}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --- CPU ---

def read_cpu(proc=PROC):
    """/proc/stat 첫 줄 → (전체, 쉼). guest 는 user 에 이미 들어 있으므로 앞 8칸(user..steal)만 더한다."""
    with open(os.path.join(proc, "stat"), encoding="ascii") as f:
        head = f.readline().split()
    if len(head) < 5 or head[0] != "cpu":
        raise ValueError("/proc/stat 첫 줄이 cpu 합계가 아니다")
    vals = [int(v) for v in head[1:9]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)   # idle + iowait
    return sum(vals), idle


def cpu_pct(prev, cur):
    """두 표본 사이 사용률(%). 셀 수 없으면 None (재부팅 · 카운터 감소 · 같은 표본)."""
    dt, di = cur[0] - prev[0], cur[1] - prev[1]
    if dt <= 0 or di < 0 or di > dt:
        return None
    return round(100.0 * (dt - di) / dt, 1)


def boot_id(proc=PROC):
    try:
        with open(os.path.join(proc, "sys", "kernel", "random", "boot_id"), encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return ""


def load_cpu_state(path, boot):
    """지난 실행의 표본. 부팅이 바뀌었거나 형식이 틀리면 None."""
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
        total, idle = st["total"], st["idle"]
        if st.get("boot") == boot and type(total) is int and type(idle) is int:
            return total, idle
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def measure_cpu(proc, state_path, sample=1.0):
    boot = boot_id(proc)
    cur = read_cpu(proc)
    prev = load_cpu_state(state_path, boot)
    pct = cpu_pct(prev, cur) if prev else None
    if pct is None:
        time.sleep(sample)
        nxt = read_cpu(proc)
        pct = cpu_pct(cur, nxt)
        cur = nxt
    write_atomic(state_path, json.dumps({"boot": boot, "total": cur[0], "idle": cur[1]}) + "\n")
    return 0.0 if pct is None else pct


# --- 메모리 · 디스크 · 부하 · 서비스 ---

def read_meminfo(proc=PROC):
    out = {}
    with open(os.path.join(proc, "meminfo"), encoding="ascii") as f:
        for line in f:
            k, _, rest = line.partition(":")
            parts = rest.split()
            if parts:
                out[k.strip()] = int(parts[0])      # kB
    return out


def mem_fields(mi):
    """→ (mem_used_pct, mem_avail_mb, swap_used_pct)."""
    total, avail = mi["MemTotal"], mi["MemAvailable"]
    if total <= 0 or not 0 <= avail <= total:
        raise ValueError("MemTotal · MemAvailable 값이 이상하다")
    st, sf = mi.get("SwapTotal", 0), mi.get("SwapFree", 0)
    swap = round(100.0 * (st - sf) / st, 1) if st > 0 else 0.0
    return round(100.0 * (total - avail) / total, 1), avail // 1024, swap


def disk_pct(path="/"):
    st = os.statvfs(path)
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    avail = st.f_bavail * st.f_frsize
    return round(100.0 * used / (used + avail), 1) if used + avail > 0 else 0.0


def load1(proc=PROC):
    with open(os.path.join(proc, "loadavg"), encoding="ascii") as f:
        return round(float(f.read().split()[0]), 2)


def unit_active(*units):
    """하나라도 active 면 참. systemctl 이 없거나 멈추면 거짓."""
    for u in units:
        try:
            r = subprocess.run(["systemctl", "is-active", "--quiet", u], timeout=5,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:
            return True
    return False


# --- 번호 ---

def last_seq_in_log(path):
    """지표 파일 끝부분에서 마지막으로 쓴 seq. 없으면 0."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - TAIL))
            tail = f.read()
    except OSError:
        return 0
    for raw in reversed(tail.splitlines()):
        try:
            seq = json.loads(raw).get("seq")
        except (ValueError, AttributeError):
            continue
        if type(seq) is int and seq >= 0:
            return seq
    return 0


def next_seq(seq_path, log_path):
    """저장된 번호 + 1 을 먼저 저장하고 돌려준다."""
    try:
        with open(seq_path, encoding="ascii") as f:
            last = int(f.read().strip())
        if last < 0:
            raise ValueError(last)
    except FileNotFoundError:
        last = last_seq_in_log(log_path)
    except (OSError, ValueError, UnicodeError):
        last = last_seq_in_log(log_path)
        log(f"번호 파일이 깨져 지표 파일의 마지막 번호 {last} 에서 잇는다", 4)
    seq = last + 1
    write_atomic(seq_path, f"{seq}\n")
    return seq


# --- 한 줄 ---

def collect(proc=PROC, home=HOME, root="/", active=unit_active, sample=1.0):
    cpu = measure_cpu(proc, os.path.join(home, "metrics.cpu"), sample)
    used, avail_mb, swap = mem_fields(read_meminfo(proc))
    return {
        "cpu_pct": cpu,
        "mem_used_pct": used,
        "mem_avail_mb": avail_mb,
        "swap_used_pct": swap,
        "disk_root_pct": disk_pct(root),
        "load1": load1(proc),
        "nginx_active": active(*NGINX_UNITS),
        "sshd_active": active(*SSHD_UNITS),
    }


def make_line(values, seq, host=None, now=None):
    now = now or datetime.now(timezone.utc)
    row = {"ts": now.isoformat(timespec="microseconds"), "host": host or socket.gethostname(), "seq": seq}
    row.update(values)
    return json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"


def append_line(path, line):
    """한 번의 write 로 붙인다 (Alloy 가 반쪽 줄을 보지 않게). 새 파일은 0640, 그룹은 폴더(setgid adm)를 따른다."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        data = line.encode("utf-8")
        if os.write(fd, data) != len(data):
            raise OSError("지표 줄을 다 쓰지 못했다")
    finally:
        os.close(fd)


def run(log_path=LOG, home=HOME, proc=PROC, active=unit_active, sample=1.0):
    with open(os.path.join(home, "metrics.lock"), "a") as lk:
        try:
            fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("다른 실행이 돌고 있어 건너뛴다", 4)
            return 0
        try:
            values = collect(proc, home, "/", active, sample)
        except (OSError, ValueError, KeyError, IndexError) as e:
            log(f"지표를 읽지 못했다: {e}", 3)
            return 1
        try:
            seq = next_seq(os.path.join(home, "metrics.seq"), log_path)
            append_line(log_path, make_line(values, seq))
        except OSError as e:
            log(f"지표를 쓰지 못했다: {e}", 3)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
