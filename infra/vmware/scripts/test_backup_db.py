"""backup-db.sh · backup-agent.sh · install-backup-agent.sh 시험 (이슈 #45 · #91 · #95). 가짜 ssh 로 데이터 노드 없이 돈다.

- 덤프와 같은 시각의 역할 목록(opsloop-<시각>.globals.sql)을 비밀번호 없이 0600 으로 남긴다
- 역할(지금 8개)이 빠졌거나 비밀번호가 섞인 역할 목록이면 실패하고 파일을 남기지 않는다
- 보관 개수(KEEP, 기본 21)는 덤프와 역할 목록에 똑같이 적용한다
- 덤프 전 시계 확인: 차이를 한 줄 남긴다 · 2초 넘게 다르면 chrony 동기를 기다린 뒤 다시 잰다 · 그래도 다르거나
  chronyc 가 없으면 덤프하지 않고 실패 · data01 시각을 못 읽으면 실패 · 지난 시험 DB 는 시계 확인 앞에서 치운다
- ssh 는 BatchMode · ConnectTimeout 에 ServerAliveInterval · ServerAliveCountMax 를 더한다 (원장 rsync 도)
- 실행기: 첫 시도 성공은 알리지 않음 · 재시도 뒤 성공 · 모두 실패 · 첫 실패 알림은 재시도 전에 바로 ·
  '== … 백업 시작|성공|실패' 줄은 회차마다 한 번 · 시도 줄은 '-- ' · 대기 기본 180초(창 안에 못 돌면 다시 돌지 않음) ·
  창 끝에 닿은 시도는 묶음째 멈춤(TERM) · 무시하면 끊음(KILL) · 잠자기로 창 끝을 넘겨 깨도 TERM 뒤 정리할 틈 ·
  실행기가 멈추면 시도도 멈추고 실패 줄 · 잘못된 환경변수 · 기록 시각은 Mac 시간대와 상관없이 KST
- 잠자기 방지: caffeinate -i -s -w <실행기 pid> 를 회차마다 한 번(시도 묶음 밖) · 재시도 대기 동안에도 걸림 ·
  성공 · 모두 실패 · 창 끝 · 실행기 멈춤 · 그 밖의 끝(EXIT) 뒤 남지 않음 · 잘못된 환경변수면 부르지 않음 ·
  없으면 '-- ' 줄 하나만 더하고 백업은 돈다
- 설치기: launchd 04:30 · 12:30 · 20:30 · KEEP 21 · 사본 · 내림
가짜 osascript · caffeinate · launchctl 은 bash 내보낸 함수로 덮는다(실행기가 PATH 를 새로 정하므로). 대기는 환경변수로 줄인다.

사용: python3 infra/vmware/scripts/test_backup_db.py
"""
import json
import os
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "backup-db.sh")
AGENT = os.path.join(HERE, "backup-agent.sh")
INSTALL = os.path.join(HERE, "install-backup-agent.sh")
BASH = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")
LABEL = "local.opsloop.backup-db"
WAITSYNC = "command -v chronyc >/dev/null 2>&1 || exit 127; chronyc waitsync 12 0.5 0 5"
DROP = "sudo -n docker exec opsloop-db dropdb -U opsloop --if-exists opsloop_restore_test"
MARK = re.compile(r"^== \d{4}-\d\d-\d\d \d\d:\d\d:\d\d KST 백업 (시작|성공|실패)")
OSA_HEAD = ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
            "-e", "end run"]
KST = timezone(timedelta(hours=9))

ROLES = """--
-- PostgreSQL database cluster dump
--
CREATE ROLE opsloop;
ALTER ROLE opsloop WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS;
CREATE ROLE opsloop_backup;
ALTER ROLE opsloop_backup WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;
CREATE ROLE opsloop_console;
CREATE ROLE opsloop_cti;
CREATE ROLE opsloop_detector;
CREATE ROLE opsloop_enforcer;
CREATE ROLE opsloop_gate;
CREATE ROLE opsloop_ingest;
GRANT pg_read_all_data TO opsloop_backup WITH INHERIT TRUE GRANTED BY opsloop;
"""

# 받은 원격 명령에 따라 답한다. 시각 · chrony 동기 · 덤프 · 목차 · 역할 목록만 흉내 낸다.
#   시각은 진짜 시각에 FAKE_CLOCK 파일의 초를 더한다. FAKE_CHRONY: fix(동기 뒤 시계가 맞다) · stuck(그대로) · none(chronyc 없음)
FAKE_SSH = r"""#!/bin/sh
for a; do cmd=$a; done
echo "$cmd" >> "$FAKE_LOG"
printf '%s\n' "$*" >> "$FAKE_ARGS"
case "$cmd" in
  'date +%s%N')
    if [ -n "${FAKE_DATE_OUT:-}" ]; then echo "$FAKE_DATE_OUT"; exit 0; fi
    "$FAKE_PY" -c 'import sys, time; print(time.time_ns() + int(float(open(sys.argv[1]).read()) * 1e9))' "$FAKE_CLOCK" ;;
  *chronyc\ waitsync*)
    case "${FAKE_CHRONY:-fix}" in
      none) exit 127 ;;
      stuck) echo "try: 12, refid: C0A83CFE, correction: 3.100000000, skew: 0.012"; exit 1 ;;
      *) echo 0 > "$FAKE_CLOCK"; echo "try: 2, refid: C0A83CFE, correction: 0.000012345, skew: 0.012" ;;
    esac ;;
  *pg_dumpall*) cat "$FAKE_ROLES" ;;
  *pg_restore\ --list*) cat >/dev/null; echo "123; 0 0 TABLE DATA public events opsloop" ;;
  *pg_dump\ *) printf 'PGDMP-fake' ;;
  *) : ;;
esac
"""


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def write_exec(path, body):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o755)


def jsonl(p):
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class BackupDbTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="t45-backup-")
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.bin = os.path.join(root, "bin")
        self.dest = os.path.join(root, "backup")
        self.home = os.path.join(root, "home")
        os.makedirs(self.bin)
        os.makedirs(os.path.join(self.home, ".ssh"))
        open(os.path.join(self.home, ".ssh", "config.opsloop"), "w").close()
        write_exec(os.path.join(self.bin, "ssh"), FAKE_SSH)
        self.roles = os.path.join(root, "roles.sql")
        self.log = os.path.join(root, "ssh.log")
        self.args = os.path.join(root, "ssh-args.log")
        self.clock = os.path.join(root, "clock")
        self.write_roles(ROLES)
        self.set_clock(0)

    def write_roles(self, text):
        with open(self.roles, "w") as f:
            f.write(text)

    def set_clock(self, off):
        with open(self.clock, "w") as f:
            f.write(str(off))

    def run_backup(self, keep="2", **extra):
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], HOME=self.home, LEDGER="0",
                   FAKE_ROLES=self.roles, FAKE_LOG=self.log, FAKE_ARGS=self.args, FAKE_CLOCK=self.clock,
                   FAKE_PY=sys.executable, **extra)
        env.pop("VERIFY", None)
        if keep is None:
            env.pop("KEEP", None)
        else:
            env["KEEP"] = keep
        return subprocess.run(["bash", SCRIPT, self.dest], env=env, capture_output=True, text=True, timeout=60)

    def files(self, suffix):
        return sorted(f for f in os.listdir(self.dest) if f.endswith(suffix) and not f.startswith("."))

    def cmds(self):
        return read(self.log).splitlines() if os.path.exists(self.log) else []

    def offsets(self, out, head="시계 차이"):
        return [float(v) for v in re.findall(r"^%s \(data01 − Mac\) ([+-]\d+\.\d{3})초 · 잰 왕복 \d+\.\d{3}초$" % head,
                                             out, re.M)]

    def test_역할_목록을_같은_시각으로_0600_에_남긴다(self):
        r = self.run_backup()
        self.assertEqual(r.returncode, 0, r.stderr)
        (dump,), (roles,) = self.files(".dump"), self.files(".globals.sql")
        self.assertEqual(dump[: -len(".dump")], roles[: -len(".globals.sql")])
        for name in (dump, roles):
            mode = stat.S_IMODE(os.stat(os.path.join(self.dest, name)).st_mode)
            self.assertEqual(mode, 0o600, name)
        self.assertIn("역할 8 개", r.stdout)
        cmds = read(self.log)
        # 비밀번호는 원격에서부터 빼고 받는다. 백업 전용 역할로 뜬다
        self.assertIn("pg_dumpall -U opsloop_backup --globals-only --no-role-passwords", cmds)
        self.assertIn("pg_dump -U opsloop_backup -Fc opsloop", cmds)
        self.assertEqual([f for f in os.listdir(self.dest) if f.endswith(".part")], [])

    def test_역할이_빠지면_실패하고_남기지_않는다(self):
        # 지금 역할 8개 (이슈 #91: cti · enforcer 를 더했다)
        for role in ("opsloop_console", "opsloop_cti", "opsloop_enforcer"):
            with self.subTest(role=role):
                shutil.rmtree(self.dest, ignore_errors=True)
                self.write_roles(ROLES.replace("CREATE ROLE %s;\n" % role, ""))
                r = self.run_backup()
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("역할 목록에 %s 이 없습니다" % role, r.stderr)
                self.assertEqual(os.listdir(self.dest), [])

    def test_비밀번호가_섞이면_실패한다(self):
        for leak in ("ALTER ROLE opsloop_gate WITH LOGIN PASSWORD 'x';\n",
                     "ALTER ROLE opsloop_gate WITH LOGIN PASSWORD 'SCRAM-SHA-256$4096:abc';\n"):
            with self.subTest(leak=leak[:40]):
                self.write_roles(ROLES + leak)
                r = self.run_backup()
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("비밀번호", r.stderr)
                self.assertNotIn("SCRAM", r.stdout + r.stderr)
                self.assertEqual(self.files(".globals.sql"), [])

    def old_rounds(self, n):
        os.makedirs(self.dest, exist_ok=True)
        names = []
        # 옛 회차를 먼저 둔다. 오래된 순서는 수정 시각으로 정해진다
        for i in range(n):
            ts = "202601%02d-0000" % (i + 1)
            names.append(ts)
            for suffix in (".dump", ".globals.sql"):
                path = os.path.join(self.dest, f"opsloop-{ts}{suffix}")
                with open(path, "w") as f:
                    f.write("old")
                past = time.time() - 3600 * (100 - i)
                os.utime(path, (past, past))
        return names

    def test_보관_개수는_역할_목록에도_같다(self):
        self.old_rounds(3)
        r = self.run_backup()
        self.assertEqual(r.returncode, 0, r.stderr)
        # 새 회차 하나 + 가장 최근 옛 회차 하나만 남는다
        for suffix in (".dump", ".globals.sql"):
            kept = self.files(suffix)
            self.assertEqual(len(kept), 2, kept)
            self.assertIn(f"opsloop-20260103-0000{suffix}", kept)
            self.assertNotIn(f"opsloop-20260101-0000{suffix}", kept)

    def test_보관_기본값은_21개(self):
        # 하루 세 번 · 7일
        old = self.old_rounds(22)
        r = self.run_backup(keep=None)
        self.assertEqual(r.returncode, 0, r.stderr)
        for suffix in (".dump", ".globals.sql"):
            kept = self.files(suffix)
            self.assertEqual(len(kept), 21, suffix)
            self.assertNotIn(f"opsloop-{old[1]}{suffix}", kept)
            self.assertIn(f"opsloop-{old[2]}{suffix}", kept)

    def test_시계가_맞으면_한_줄_남기고_기다리지_않는다(self):
        r = self.run_backup()
        self.assertEqual(r.returncode, 0, r.stderr)
        (off,) = self.offsets(r.stdout)
        self.assertLess(abs(off), 2)
        cmds = self.cmds()
        self.assertEqual(cmds[:2], [DROP, "date +%s%N"], "지난 시험 DB 를 치운 뒤 덤프보다 먼저 잰다")
        self.assertLess(cmds.index("date +%s%N"), min(i for i, c in enumerate(cmds) if "pg_dump" in c))
        self.assertEqual(cmds.count("date +%s%N"), 1)
        self.assertNotIn(WAITSYNC, cmds)
        self.assertNotIn("chrony", r.stdout)

    def test_시계가_어긋나면_chrony_동기를_기다린_뒤_다시_잰다(self):
        for off in (5, -5):
            with self.subTest(off=off):
                shutil.rmtree(self.dest, ignore_errors=True)
                if os.path.exists(self.log):
                    os.remove(self.log)
                self.set_clock(off)
                r = self.run_backup(FAKE_CHRONY="fix")
                self.assertEqual(r.returncode, 0, r.stderr)
                (first,) = self.offsets(r.stdout)
                self.assertLess(abs(first - off), 1, r.stdout)
                (again,) = self.offsets(r.stdout, "시계 차이 다시 잼")
                self.assertLess(abs(again), 2)
                self.assertIn("chrony 동기 기다림 (종료 0) try: 2, refid: C0A83CFE", r.stdout)
                cmds = self.cmds()
                self.assertEqual(cmds[:4], [DROP, "date +%s%N", WAITSYNC, "date +%s%N"])
                self.assertEqual(len(self.files(".dump")), 1)

    def test_동기_뒤에도_2초를_넘으면_덤프하지_않고_실패한다(self):
        self.set_clock(3)
        r = self.run_backup(FAKE_CHRONY="stuck")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("chrony 동기 기다림 (종료 1)", r.stdout)
        self.assertIn("시계 차이가 2초를 넘습니다", r.stderr)
        self.assertEqual(len(self.offsets(r.stdout, "시계 차이 다시 잼")), 1, "잰 차이는 실패해도 남긴다")
        self.assertFalse([c for c in self.cmds() if "pg_dump" in c])
        # 지난 실행이 남긴 시험 DB 는 시계가 계속 어긋나도 치운다 (시계 확인 앞에서 한 번)
        self.assertEqual(self.cmds()[0], DROP)
        self.assertEqual([c for c in self.cmds() if "dropdb" in c], [DROP])
        self.assertEqual(os.listdir(self.dest), [])

    def test_chronyc_가_없으면_기다리지_않고_차이로_판단한다(self):
        self.set_clock(-4)
        r = self.run_backup(FAKE_CHRONY="none")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("chronyc 를 쓸 수 없습니다", r.stderr)
        self.assertEqual(len(self.offsets(r.stdout)), 1)
        self.assertEqual(self.cmds(), [DROP, "date +%s%N", WAITSYNC])
        self.assertEqual(os.listdir(self.dest), [])

    def test_data01_시각을_못_읽으면_실패한다(self):
        r = self.run_backup(FAKE_DATE_OUT="Fri Oct  2 12:30:00 KST 2026")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("data01 시각을 읽지 못했습니다", r.stderr)
        self.assertFalse([c for c in self.cmds() if "pg_dump" in c])

    def test_ssh_는_끊긴_연결에_매달리지_않는다(self):
        r = self.run_backup()
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = read(self.args).splitlines()
        self.assertGreater(len(lines), 4)
        for line in lines:
            for opt in ("-o BatchMode=yes", "-o ConnectTimeout=10", "-o ServerAliveInterval=15",
                        "-o ServerAliveCountMax=4", " data01 "):
                self.assertIn(opt, line)
        # 원장 rsync 의 ssh 도 같다 (시험은 LEDGER=0 이라 글자로 본다)
        rsync = re.search(r'-e "(ssh [^"]+)"', read(SCRIPT)).group(1)
        self.assertIn("-o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=4", rsync)

    def test_셸_문법(self):
        for shell in ("/bin/bash", "bash"):
            for s in (SCRIPT, AGENT, INSTALL):
                r = subprocess.run([shell, "-n", s], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck 가 없다")
    def test_shellcheck(self):
        r = subprocess.run(["shellcheck", SCRIPT, AGENT, INSTALL], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


# 가짜 backup-db.sh. FAKE_SEQ 에서 결과를 하나씩 꺼낸다:
#   ok · fail(종료 1) · ssh(255) · hang(자식이 멈춤, TERM 이면 정리하고 끝) · stubborn(TERM 을 무시) ·
#   nap(돌던 중 Mac 이 잠들어 창 끝을 넘겨 깬 것처럼 시계가 뛴다. TERM 이면 0.5초 걸려 정리하고 끝)
FAKE_DB = r"""#!/bin/sh
r=$(head -n 1 "$FAKE_SEQ"); tail -n +2 "$FAKE_SEQ" > "$FAKE_SEQ.t"; mv "$FAKE_SEQ.t" "$FAKE_SEQ"
"$FAKE_PY" -c 'import json, sys; open(sys.argv[1], "a").write(json.dumps({"db": sys.argv[2:]}) + "\n")' \
  "$FAKE_EVENTS" "$r" "${VERIFY:-}" "$@"
case "$r" in
  ok) echo "백업 1.0M $1/opsloop-x.dump · 표 23 개 · 역할 8 개"; exit 0 ;;
  fail) echo "덤프 목차를 읽지 못했습니다" >&2; exit 1 ;;
  ssh) exit 255 ;;
  hang) trap 'echo "가짜 정리"; exit 143' TERM
        sleep 60 & echo $! > "$FAKE_CHILD"; wait ;;
  stubborn) trap '' TERM
            sleep 60 & echo $! > "$FAKE_CHILD"; wait ;;
  nap) echo 1000 > "$FAKE_JUMP"
       trap 'sleep 0.5; echo "가짜 정리"; exit 143' TERM
       sleep 60 & echo $! > "$FAKE_CHILD"; wait ;;
esac
"""

# 잠자기 흉내: FAKE_JUMP 파일이 생기면 'date +%s' 가 그 초만큼 뛴다 (기록 시각 등 다른 date 는 그대로)
FAKE_DATE = ('() {  if [ "$*" = +%s ] && [ -s "$FAKE_JUMP" ]; then echo $(($(command date +%s) + $(cat "$FAKE_JUMP"))); '
             'else command date "$@"; fi; }')

# 알릴 때 돌고 있는 가짜 caffeinate 의 pid 도 남긴다 (끈 뒤 거두기 전 좀비는 뺀다)
FAKE_OSA = r'''#!{python}
import json, os, subprocess, sys
caf = []
if os.path.exists(os.environ.get("FAKE_CAF_LOG", "")):
    for line in open(os.environ["FAKE_CAF_LOG"]):
        pid = line.split()[0]
        st = subprocess.run(["ps", "-o", "stat=", "-p", pid], capture_output=True, text=True).stdout.strip()
        if st and not st.startswith("Z"):
            caf.append(int(pid))
with open(os.environ["FAKE_EVENTS"], "a") as f:
    f.write(json.dumps({{"osa": sys.argv[1:], "caf": caf}}) + "\n")
'''

# 가짜 caffeinate. '<pid> <부모 pid> <인자…>' 한 줄을 남기고 멈추라고 할 때까지 산다. -w 의 pid 가 끝나도 스스로 끝나지
#   않는다(실행기가 끄는지 본다). FAKE_CAF=none 이면 없는 명령처럼 127 로 바로 끝난다
FAKE_CAF = r"""#!/bin/sh
echo "$$ $PPID $*" >> "$FAKE_CAF_LOG"
[ "${FAKE_CAF:-}" != none ] || exit 127
exec sleep 60
"""


class BackupAgentTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="t91-agent-")
        self.addCleanup(shutil.rmtree, self.t)
        self.bin = os.path.join(self.t, "bin")
        self.fake = os.path.join(self.t, "fakebin")
        self.home = os.path.join(self.t, "home")
        self.dest = os.path.join(self.t, "backup")
        for d in (self.bin, self.fake, self.home):
            os.makedirs(d)
        shutil.copy(AGENT, os.path.join(self.bin, "backup-agent.sh"))
        write_exec(os.path.join(self.bin, "backup-db.sh"), FAKE_DB)
        write_exec(os.path.join(self.fake, "osascript"), FAKE_OSA.format(python=sys.executable))
        write_exec(os.path.join(self.fake, "caffeinate"), FAKE_CAF)
        self.events = os.path.join(self.t, "events.jsonl")
        self.caf_log = os.path.join(self.t, "caf.log")
        self.seq = os.path.join(self.t, "seq")
        self.child = os.path.join(self.t, "child.pid")
        self.env = {"HOME": self.home, "PATH": "/usr/bin:/bin", "TMPDIR": self.t, "LANG": "en_US.UTF-8",
                    "OPSLOOP_BACKUP_DIR": self.dest, "FAKE_BIN": self.fake, "FAKE_EVENTS": self.events,
                    "FAKE_SEQ": self.seq, "FAKE_CHILD": self.child, "FAKE_PY": sys.executable,
                    "FAKE_CAF_LOG": self.caf_log,
                    # 실행기가 PATH 를 새로 정하므로 진짜 알림이 뜨지 않게 함수로 덮는다
                    "BASH_FUNC_osascript%%": '() {  "$FAKE_BIN/osascript" "$@"; }',
                    # 진짜 caffeinate 처럼 $! 이 그 프로세스가 되게 exec 한다 (실행기는 뒤로 돌려 부른다)
                    "BASH_FUNC_caffeinate%%": '() {  exec "$FAKE_BIN/caffeinate" "$@"; }'}
        self.addCleanup(self.kill_child)
        self.addCleanup(self.kill_caf)

    def kill_child(self):
        if os.path.exists(self.child):
            try:
                os.kill(int(read(self.child)), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass

    def kill_caf(self):
        for c in self.caf_calls():
            try:
                os.kill(int(c[0]), signal.SIGKILL)
            except ProcessLookupError:
                pass

    def caf_calls(self):  # 가짜 caffeinate 가 남긴 [pid, 부모 pid, 인자…]
        if not os.path.exists(self.caf_log):
            return []
        return [line.split() for line in read(self.caf_log).splitlines() if line.strip()]

    def gone(self, pid, wait=3.0):  # 끈 뒤 거둬지기까지 잠깐 기다린다
        deadline = time.time() + wait
        while alive(pid) and time.time() < deadline:
            time.sleep(0.05)
        return not alive(pid)

    def agent(self, seq, **extra):
        with open(self.seq, "w") as f:
            f.write("\n".join(seq) + "\n")
        return dict(self.env, **extra)

    def run_agent(self, seq, **extra):
        return subprocess.run([BASH, os.path.join(self.bin, "backup-agent.sh")], env=self.agent(seq, **extra),
                              capture_output=True, text=True, encoding="utf-8", stdin=subprocess.DEVNULL, timeout=60)

    def db_calls(self):
        return [e["db"] for e in jsonl(self.events) if "db" in e]

    def titles(self):
        out = []
        for e in jsonl(self.events):
            if "osa" in e:
                self.assertEqual(e["osa"][:len(OSA_HEAD)], OSA_HEAD, "문구는 osascript 인자로 넘긴다")
                self.assertEqual(len(e["osa"]), len(OSA_HEAD) + 2)
                out.append(e["osa"][len(OSA_HEAD)])
        return out

    def bodies(self):
        return [e["osa"][-1] for e in jsonl(self.events) if "osa" in e]

    def marks(self, out):
        return [m.group(1) for m in map(MARK.match, out.splitlines()) if m]

    def test_첫_시도_성공은_알리지_않는다(self):
        r = self.run_agent(["ok"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = r.stdout.splitlines()
        self.assertRegex(lines[0], r"^== \d{4}-\d\d-\d\d \d\d:\d\d:\d\d KST 백업 시작$")
        self.assertRegex(lines[1], r"^-- \d{4}-\d\d-\d\d \d\d:\d\d:\d\d KST 시도 1/3$")
        self.assertRegex(lines[-1], r"^== \d{4}-\d\d-\d\d \d\d:\d\d:\d\d KST 백업 성공$", "첫 시도 성공 줄은 옛 모양 그대로")
        self.assertIn("백업 1.0M %s/opsloop-x.dump" % self.dest, r.stdout)
        self.assertEqual(self.db_calls(), [["ok", "restore", self.dest]], "VERIFY=restore 로 보관 폴더를 넘긴다")
        self.assertEqual(self.titles(), [])
        self.assertEqual(r.stderr, "")

    def test_재시도_뒤_성공은_기록하고_알린다(self):
        r = self.run_agent(["fail", "ok"], BACKUP_RETRY_WAIT="0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.marks(r.stdout), ["시작", "성공"], "시작 · 성공 줄은 회차마다 한 번")
        self.assertRegex(r.stdout, r"(?m)^-- .* KST 시도 1/3 실패 \(종료 코드 1\) · 0초 뒤 다시 돈다$")
        self.assertRegex(r.stdout, r"(?m)^-- .* KST 시도 2/3$")
        self.assertRegex(r.stdout, r"(?m)^== .* KST 백업 성공 \(시도 2/3 · 재시도 뒤 성공\)$")
        self.assertIn("덤프 목차를 읽지 못했습니다", r.stdout, "backup-db.sh 의 오류도 기록에 들어간다")
        self.assertEqual(self.titles(), ["OpsLoop DB 백업 실패 · 재시도 예정", "OpsLoop DB 백업 재시도 뒤 성공"])
        # 첫 실패는 다시 돌기 전에 바로 알린다
        kinds = [("db" if "db" in e else "osa") for e in jsonl(self.events)]
        self.assertEqual(kinds, ["db", "osa", "db", "osa"])
        self.assertIn("시도 1/3 실패 (종료 코드 1) · 0초 뒤 다시 돈다", self.bodies()[0])

    def test_모두_실패하면_한_번_더_알리고_실패로_끝난다(self):
        r = self.run_agent(["fail", "ssh", "fail"], BACKUP_RETRY_WAIT="0")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.marks(r.stdout), ["시작", "실패"])
        self.assertRegex(r.stdout, r"(?m)^== .* KST 백업 실패 \(종료 코드 1 · 시도 3/3\)$")
        for n in (1, 2, 3):
            self.assertRegex(r.stdout, r"(?m)^-- .* KST 시도 %d/3$" % n)
        self.assertIn("시도 2/3 실패 (종료 코드 255)", r.stdout)
        self.assertEqual(len(self.db_calls()), 3, "처음 1번 + 재시도 2번")
        self.assertEqual(self.titles(), ["OpsLoop DB 백업 실패 · 재시도 예정", "OpsLoop DB 백업 실패 · 재시도 모두 실패"])
        self.assertIn("시도 3/3 모두 실패", self.bodies()[1])
        # 시도 줄은 다른 말머리라 표시 줄로 읽히지 않는다
        self.assertFalse([l for l in r.stdout.splitlines() if l.startswith("== ") and "시도 " in l and not MARK.match(l)])

    def test_대기_기본값은_180초이고_창_안에_못_돌면_다시_돌지_않는다(self):
        # 창 120초 · 멈춤 여유 30초: 180초를 기다리면 창을 넘는다
        r = self.run_agent(["fail", "ok"], BACKUP_WINDOW="120")
        self.assertEqual(r.returncode, 1)
        self.assertIn("시도 1/3 실패 (종료 코드 1) · 180초 기다리면 백업 창(120초) 안에 끝낼 수 없어 다시 돌지 않는다",
                      r.stdout)
        self.assertEqual(len(self.db_calls()), 1)
        self.assertEqual(self.marks(r.stdout), ["시작", "실패"])
        self.assertEqual(self.titles(), ["OpsLoop DB 백업 실패"], "다시 돌지 않으므로 '재시도 예정' 이 아니다")

    def test_창_끝에_닿은_시도는_묶음째_멈춘다(self):
        start = time.time()
        r = self.run_agent(["hang", "ok"], BACKUP_WINDOW="4", BACKUP_RETRY_WAIT="0")
        took = time.time() - start
        self.assertEqual(r.returncode, 143, r.stdout + r.stderr)
        self.assertLess(took, 15)
        self.assertIn("가짜 정리", r.stdout, "TERM 으로 멈추라고 해 정리할 틈을 준다")
        self.assertIn("백업 창 4초 끝에 멈춤 · 종료 코드 143", r.stdout)
        self.assertEqual(self.marks(r.stdout), ["시작", "실패"])
        self.assertEqual(len(self.db_calls()), 1, "창이 지났으니 다시 돌지 않는다")
        time.sleep(0.3)
        self.assertFalse(alive(int(read(self.child))), "시도의 자식(ssh 자리)도 함께 멈춘다")

    def test_멈추라는_신호를_무시하면_창_끝에_끊는다(self):
        start = time.time()
        r = self.run_agent(["stubborn"], BACKUP_WINDOW="4")
        took = time.time() - start
        self.assertEqual(r.returncode, 137, r.stdout + r.stderr)
        self.assertLess(took, 15)
        # START 는 정수 초로 자른 시각이라 창 끝은 실제 시작 뒤 3초 넘게 4초 이하 사이다
        self.assertGreater(took, 3.0, "끊는 것은 창 끝이다")
        self.assertIn("종료 코드 137", r.stdout)
        time.sleep(0.3)
        self.assertFalse(alive(int(read(self.child))))

    def test_잠자기로_창_끝을_넘겨_깨도_정리할_틈을_준다(self):
        # 시도 중 시계가 창 끝 너머로 뛴다. 멈추라고 한 바로 뒤 끊지 않고 정리(시험 DB · 임시 파일)를 기다린다
        r = self.run_agent(["nap", "ok"], BACKUP_WINDOW="6", BACKUP_RETRY_WAIT="0",
                           FAKE_JUMP=os.path.join(self.t, "jump"), **{"BASH_FUNC_date%%": FAKE_DATE})
        self.assertEqual(r.returncode, 143, r.stdout + r.stderr)
        self.assertIn("가짜 정리", r.stdout, "TERM 뒤 KILL 까지 정리할 틈이 있다")
        self.assertIn("백업 창 6초 끝에 멈춤 · 종료 코드 143", r.stdout)
        self.assertEqual(self.marks(r.stdout), ["시작", "실패"])
        self.assertEqual(len(self.db_calls()), 1, "창이 지났으니 다시 돌지 않는다")
        time.sleep(0.3)
        self.assertFalse(alive(int(read(self.child))))

    def test_기록_시각은_Mac_시간대와_상관없이_KST(self):
        for tz in ("UTC", "America/New_York"):
            with self.subTest(tz=tz):
                r = self.run_agent(["ok"], TZ=tz)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(self.marks(r.stdout), ["시작", "성공"])
                for line in r.stdout.splitlines():
                    if line.startswith(("== ", "-- ")):
                        at = datetime.strptime(line[3:22], "%Y-%m-%d %H:%M:%S").replace(tzinfo=KST)
                        self.assertLess(abs((at - datetime.now(KST)).total_seconds()), 60, line)

    def test_실행기가_멈추면_시도도_멈추고_실패_줄을_남긴다(self):
        p = subprocess.Popen([BASH, os.path.join(self.bin, "backup-agent.sh")], env=self.agent(["hang"]),
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             encoding="utf-8")
        deadline = time.time() + 20
        while not os.path.exists(self.child) and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(0.2)
        p.send_signal(signal.SIGTERM)
        out, _err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 143)
        self.assertEqual(self.marks(out), ["시작", "실패"])
        self.assertRegex(out, r"(?m)^== .* KST 백업 실패 \(실행기가 멈춤 · 시도 1/3\)$")
        time.sleep(0.5)
        self.assertFalse(alive(int(read(self.child))), "따로 묶인 시도도 멈춘다 (launchctl bootout)")
        calls = self.caf_calls()
        self.assertEqual([c[1:] for c in calls], [[str(p.pid), "-i", "-s", "-w", str(p.pid)]])
        self.assertTrue(self.gone(int(calls[0][0])), "실행기가 멈추면 잠자기 방지도 끈다")

    def test_잘못된_환경변수는_2_이고_아무것도_하지_않는다(self):
        pwned = os.path.join(self.t, "pwned")
        for extra in ({"BACKUP_RETRY_WAIT": "abc"}, {"BACKUP_RETRY_WAIT": "-1"}, {"BACKUP_WINDOW": "0"},
                      {"BACKUP_WINDOW": "20m"}, {"BACKUP_RETRY_WAIT": "$(touch %s)" % pwned}):
            with self.subTest(extra=extra):
                r = self.run_agent(["ok"], **extra)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("BACKUP_", r.stderr)
                self.assertEqual(r.stdout, "")
        self.assertFalse(os.path.exists(pwned))
        self.assertEqual(self.db_calls(), [])
        time.sleep(0.5)   # 뒤로 띄웠다면 실행기가 끝난 뒤에 기록될 수 있다
        self.assertEqual(self.caf_calls(), [], "검사를 통과하기 전에는 잠자기 방지를 띄우지 않는다")

    def test_잠자기_방지는_회차마다_한_번_띄우고_끝나면_끈다(self):
        for name, seq, extra, code in (
                ("성공", ["ok"], {}, 0),
                ("모두 실패", ["fail", "ssh", "fail"], {"BACKUP_RETRY_WAIT": "0"}, 1),
                ("창 끝 멈춤", ["hang", "ok"], {"BACKUP_WINDOW": "4", "BACKUP_RETRY_WAIT": "0"}, 143)):
            with self.subTest(name):
                before, ev_before = len(self.caf_calls()), len(jsonl(self.events))
                r = self.run_agent(seq, **extra)
                self.assertEqual(r.returncode, code, r.stdout + r.stderr)
                calls = self.caf_calls()[before:]
                self.assertEqual(len(calls), 1, "시도마다가 아니라 회차마다 한 번")
                pid, ppid, args = calls[0][0], calls[0][1], calls[0][2:]
                self.assertEqual(args, ["-i", "-s", "-w", ppid], "-w 는 띄운 실행기 자신의 pid")
                self.assertTrue(self.gone(int(pid)), "회차가 끝나면 끈다 (가짜는 -w 를 따르지 않는다)")
                self.assertNotIn("잠자기 방지", r.stdout)
                self.assertNotIn("caffeinate", r.stderr, "끌 때 'Terminated' 알림이 기록에 남지 않는다")
                self.assertEqual(self.marks(r.stdout)[0], "시작")
                osa = [e for e in jsonl(self.events)[ev_before:] if "osa" in e]
                if osa:
                    self.assertEqual(osa[-1]["caf"], [], "끝 알림 전에 끈다 (EXIT 까지 기다리지 않는다)")

    def test_재시도_대기_동안에도_잠자기_방지가_걸려_있다(self):
        p = subprocess.Popen([BASH, os.path.join(self.bin, "backup-agent.sh")],
                             env=self.agent(["fail", "ok"], BACKUP_RETRY_WAIT="3"), stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        self.addCleanup(lambda: p.poll() is None and p.kill())
        deadline = time.time() + 20
        while "OpsLoop DB 백업 실패 · 재시도 예정" not in self.titles() and time.time() < deadline:
            time.sleep(0.05)
        # 첫 시도가 실패해 3초 기다리는 중이다
        self.assertEqual(len(self.db_calls()), 1)
        calls = self.caf_calls()
        self.assertEqual(len(calls), 1)
        pid = int(calls[0][0])
        self.assertTrue(alive(pid), "재시도 대기 동안에도 걸려 있다")
        self.assertEqual(os.getpgid(pid), os.getpgid(p.pid), "시도 묶음이 아니라 실행기 묶음에 있다")
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 0, out + err)
        self.assertEqual(self.marks(out), ["시작", "성공"])
        self.assertEqual(len(self.db_calls()), 2)
        self.assertEqual(self.caf_calls(), calls, "재시도 때 다시 띄우지 않는다")
        self.assertEqual([e["caf"] for e in jsonl(self.events) if "osa" in e], [[pid], []],
                         "'재시도 예정' 알림 때는 걸려 있고 '재시도 뒤 성공' 알림 전에는 풀려 있다")
        self.assertEqual(calls[0][1:], [str(p.pid), "-i", "-s", "-w", str(p.pid)])
        self.assertTrue(self.gone(pid))

    def test_정해_둔_끝_밖에서_끝나도_잠자기_방지를_끈다(self):
        # 성공 · 실패 줄이나 on_signal 을 거치지 않고 셸이 끝나는 경우(셸 오류 등)를 흉내 낸다.
        #   띄운 뒤 처음 부르는 sleep(띄운 뒤 확인)에서, 가짜 caffeinate 가 기록을 남긴 뒤 셸을 끝낸다.
        #   끄는 곳은 EXIT 처리뿐이다
        quit_ = ('() {  local i=0; while [ ! -s "$FAKE_CAF_LOG" ] && [ "$i" -lt 100 ]; do command sleep 0.05; '
                 'i=$((i + 1)); done; exit 3; }')
        r = self.run_agent(["ok"], **{"BASH_FUNC_sleep%%": quit_})
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertEqual(self.marks(r.stdout), ["시작"])
        self.assertEqual(self.db_calls(), [])
        calls = self.caf_calls()
        self.assertEqual(len(calls), 1)
        self.assertTrue(self.gone(int(calls[0][0])), "EXIT 처리에서도 끈다 (가짜는 -w 를 따르지 않는다)")

    def test_caffeinate_가_없어도_백업은_돈다(self):
        stamp = re.compile(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d KST")
        base = self.run_agent(["ok"])
        self.assertEqual(base.returncode, 0, base.stdout + base.stderr)
        r = self.run_agent(["ok"], FAKE_CAF="none")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stderr, "")
        lines = r.stdout.splitlines()
        warn = [l for l in lines if "잠자기 방지" in l]
        self.assertEqual(len(warn), 1)
        self.assertRegex(warn[0], r"^-- \d{4}-\d\d-\d\d \d\d:\d\d:\d\d KST 잠자기 방지를 걸지 못했다 "
                                  r"\(caffeinate 종료 코드 127\) · 백업은 그대로 돈다$")
        self.assertEqual(lines.index(warn[0]), 1, "회차의 시작 줄 바로 뒤")
        # '-- ' 줄 하나만 더해지고 나머지(== 줄 포함)는 잠자기 방지가 걸린 회차와 같은 모양이다
        self.assertEqual([stamp.sub("T", l) for l in lines if l != warn[0]],
                         [stamp.sub("T", l) for l in base.stdout.splitlines()])
        self.assertEqual(self.marks(r.stdout), ["시작", "성공"])
        self.assertEqual(self.db_calls(), [["ok", "restore", self.dest], ["ok", "restore", self.dest]])


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="t91-install-")
        self.addCleanup(shutil.rmtree, self.t)
        self.home = os.path.join(self.t, "home")
        self.fake = os.path.join(self.t, "fakebin")
        os.makedirs(self.home)
        os.makedirs(self.fake)
        self.lc_log = os.path.join(self.t, "launchctl.log")
        open(self.lc_log, "w").close()
        write_exec(os.path.join(self.fake, "launchctl"), '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_LC_LOG"\n')
        if not shutil.which("plutil", path="/usr/bin:/bin"):
            write_exec(os.path.join(self.fake, "plutil"), "#!/bin/sh\nexit 0\n")
        self.env = {"HOME": self.home, "PATH": self.fake + ":/usr/bin:/bin", "LANG": "en_US.UTF-8",
                    "FAKE_BIN": self.fake, "FAKE_LC_LOG": self.lc_log,
                    "BASH_FUNC_launchctl%%": '() {  "$FAKE_BIN/launchctl" "$@"; }'}
        self.bin = os.path.join(self.home, "Library", "Application Support", "OpsLoop", "bin")
        self.plist = os.path.join(self.home, "Library", "LaunchAgents", LABEL + ".plist")
        self.dest = os.path.join(self.home, "opsloop-backup")

    def install(self, *args):
        return subprocess.run([BASH, INSTALL, *args], env=self.env, capture_output=True, text=True, encoding="utf-8",
                              stdin=subprocess.DEVNULL, timeout=60)

    def test_하루_세_번_8시간_간격_보관_21개(self):
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(self.plist, "rb") as f:
            p = plistlib.load(f)
        self.assertEqual(p["Label"], LABEL)
        self.assertEqual(p["StartCalendarInterval"], [{"Hour": 4, "Minute": 30}, {"Hour": 12, "Minute": 30},
                                                      {"Hour": 20, "Minute": 30}])
        self.assertEqual(p["EnvironmentVariables"], {"KEEP": "21"})
        self.assertEqual(p["ProgramArguments"], ["/bin/bash", os.path.join(self.bin, "backup-agent.sh")])
        self.assertEqual(p["StandardOutPath"], os.path.join(self.dest, "backup.log"))
        self.assertEqual(p["StandardErrorPath"], os.path.join(self.dest, "backup.log"))
        for name, src in (("backup-agent.sh", AGENT), ("backup-db.sh", SCRIPT)):
            self.assertEqual(read(os.path.join(self.bin, name)), read(src))
            self.assertEqual(os.stat(os.path.join(self.bin, name)).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.dest).st_mode & 0o777, 0o700)
        self.assertIn("매일 04:30 · 12:30 · 20:30 · 보관 21개", r.stdout)
        uid = os.getuid()
        self.assertEqual(read(self.lc_log).splitlines(),
                         ["bootout gui/%d/%s" % (uid, LABEL), "bootstrap gui/%d %s" % (uid, self.plist)])
        r = self.install("--remove")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(self.plist))
        self.assertTrue(os.path.isdir(self.dest), "보관된 덤프는 지우지 않는다")

    def test_머리_주석과_기본값이_같은_일정이다(self):
        for path in (SCRIPT, AGENT, INSTALL):
            text = read(path)
            with self.subTest(path=os.path.basename(path)):
                self.assertNotIn("16:30", text)
                self.assertIn("04:30 · 12:30 · 20:30", text)
        self.assertIn("KEEP=${KEEP:-21}", read(SCRIPT))
        self.assertIn("WAIT=${BACKUP_RETRY_WAIT:-180}", read(AGENT))
        self.assertIn("WINDOW=${BACKUP_WINDOW:-1200}", read(AGENT))


if __name__ == "__main__":
    unittest.main(verbosity=1)
