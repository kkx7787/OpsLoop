#!/usr/bin/env python3
"""복원 훈련 도구 시험 (이슈 #45).  python3 infra/vmware/restore-drill/test_restore_drill.py

운영에 닿지 않는다. HOME 은 임시 폴더이고 ssh · docker · curl · lsof · pmset · git 은 가짜로 바꾼다(PATH 앞 가짜 실행기).
가짜 ssh 는 data01 · console-a · fw 를 흉내 낸다. 원격 스크립트는 '# s:<이름>', SQL 은 '-- q:<이름>' 꼬리표로 답을 고른다.
  - 드라이런     모든 단계가 ssh · docker · curl 을 하나도 부르지 않고 회차 폴더도 만들지 않는다
  - 단계 순서    전체를 가짜로 차례로 돌린다 (주요 명령 순서 · rto:T0 … S9 표시 순서 · 증거 파일) ·
                 앞 단계 없이 --apply 하면 멈추고 아무것도 부르지 않는다 · T0 두 번 · 알림이 켜져 있으면 콘솔을 띄우지 않는다
  - 비밀값       콘솔 DSN 비밀번호 · 훈련용 SESSION_SECRET(컨테이너가 받은 실제 값)이 명령행 · 화면 · 기록 · 상태 · 증거에 없다 ·
                 Mac 비밀 파일 0600 · 폴더 0700 · 슈퍼유저 비밀번호는 파일로만(POSTGRES_PASSWORD= 없음) ·
                 역할 비밀번호는 스크립트 안에서 만들어 표준 입력으로만 · 재적재 환경 검사는 비밀번호를 찍지 않는다
  - 터널         가짜 ssh -f 는 진짜처럼 뒤로 돈 자식이 출력을 쥔다. 도구가 파이프로 받으면 멈추므로 이것을 본다
  - 재적재 환경  기본 파일에 운영 값이 있어도 훈련 값이 이긴다(실제 env 로 확인) · 환경 검사는 운영 HOME · DATABASE_URL ·
                 훈련 밖 env 파일 · 다른 대상 · 다른 cluster_name 이면 멈춘다 · 재적재 직전 메모리가 모자라면 멈춘다
  - 다시 돌리기  verify 를 다시 돌리면 알림 끄기 전에 뜬 첫 지문을 쓴다 · regen 을 console 보다 먼저 해도 RTO 순서는 맞다
  - 운영 이름    운영 컨테이너는 읽기 전용 psql(opsloop_backup · read_only) · docker inspect 에만 나온다 ·
                 운영 볼륨 · 주소는 나오지 않는다 · 지우기 · 만들기 명령은 훈련 이름만 · 운영에 보내는 SQL 은 읽기뿐
  - 확인 블록    훈련 DB 에 가는 SQL 은 모두 cluster_name 확인 블록으로 시작한다 · 원격 스크립트의 psql 은 drill_psql 뿐
  - 지표         RTO · RPO · 백업 간격 · 덤프 머리 · 역할 목록 · 목차 · 지문 차이 · 재생성 대조 · 역할 판정 · 가림
  - 문법         원격 스크립트 bash -n · 안에 든 파이썬 compile · 파이썬 3.9 문법
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import drill as D  # noqa: E402
import queries as Q  # noqa: E402

PY = sys.executable
BASH = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")
TOOL = os.path.join(HERE, "drill.py")
CANARY_PW = "c0ffee" * 8                      # 48 hex. 가짜 data01 의 console.env 비밀번호
IMAGE_ID = "sha256:2266e573a9aef90e2849527903d1cf93038d00700bceae252c867e11cdb63e18"
PG_ID = "sha256:3c5c8892d184f738f4fe282d14ddaa613a38f00f4189d2d94725ebe6f2909ddb"
UTC = timezone.utc


def pgts(dt):
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f+00")


def fake_dump(created, pad=b"DATA" * 64):
    def wint(v):
        return bytes([1 if v < 0 else 0]) + abs(v).to_bytes(4, "little")

    def wstr(s):
        b = s.encode()
        return wint(len(b)) + b
    t = created
    return (b"PGDMP" + bytes([1, 15, 0, 4, 8, 1, 1]) + wint(t.second) + wint(t.minute) + wint(t.hour) + wint(t.day)
            + wint(t.month - 1) + wint(t.year - 1900) + wint(0) + wstr("opsloop") + wstr("16.15") + wstr("16.15") + pad)


GLOBALS = """--
-- PostgreSQL database cluster dump
--

\\restrict AbCdEf123

SET default_transaction_read_only = off;

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Roles
--

CREATE ROLE opsloop;
ALTER ROLE opsloop WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS;
CREATE ROLE opsloop_backup;
ALTER ROLE opsloop_backup WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;
CREATE ROLE opsloop_console;
ALTER ROLE opsloop_console WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 30;
CREATE ROLE opsloop_cti;
ALTER ROLE opsloop_cti WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;
CREATE ROLE opsloop_detector;
ALTER ROLE opsloop_detector WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5;
CREATE ROLE opsloop_gate;
ALTER ROLE opsloop_gate WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 10;
CREATE ROLE opsloop_ingest;
ALTER ROLE opsloop_ingest WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5;

--
-- User Configurations
--

--
-- Role memberships
--

GRANT pg_read_all_data TO opsloop_backup WITH INHERIT TRUE GRANTED BY opsloop;

\\unrestrict AbCdEf123

--
-- PostgreSQL database cluster dump complete
--

"""
ROLES = {"opsloop": ("true", "true", "-1", "true"), "opsloop_backup": ("true", "true", "2", "false"),
         "opsloop_console": ("true", "false", "30", "false"), "opsloop_cti": ("true", "false", "2", "false"),
         "opsloop_detector": ("true", "false", "5", "false"), "opsloop_gate": ("true", "false", "10", "false"),
         "opsloop_ingest": ("true", "false", "5", "false")}
FUNCS = "audit_append_only,audit_blocklist,audit_event,enroll_node,incidents_keep_judged,node_first_receipt,notify_incident"
TRIGS = "trg_audit_append_only=O,trg_audit_blocklist=O,trg_incidents_keep_judged=O,trg_notify_incident=O"
CATALOG = ("c|tables|23\nc|fk|15\nc|triggers|%s\nc|functions|%s\nc|views|audit_log,rule_quality,unjudged_incidents\n"
           "c|sequences|7\nc|extensions|plpgsql\n" % (TRIGS, FUNCS))
BASE = "b|judged_not_resolved|15\nb|verdict_operator_missing|810\nb|released_blocks|0\nb|released_audit|2\n"


def toc_text(created):
    lines = [";", "; Archive created at %s UTC" % created.strftime("%Y-%m-%d %H:%M:%S"), ";     dbname: opsloop", ";"]
    n = 100
    for t in Q.TABLES:
        lines.append("%d; 1259 1 TABLE public %s opsloop" % (n, t))
        lines.append("%d; 0 1 TABLE DATA public %s opsloop" % (n + 1, t))
        n += 2
    for i in range(15):
        lines.append("%d; 2606 1 FK CONSTRAINT public t fk_%d opsloop" % (n + i, i))
    for i in range(7):
        lines.append("%d; 1259 1 SEQUENCE public s_%d opsloop" % (n + 20 + i, i))
        lines.append("%d; 0 0 SEQUENCE SET public s_%d opsloop" % (n + 30 + i, i))
    for f in FUNCS.split(","):
        n += 1
        lines.append("%d; 1255 1 FUNCTION public %s() opsloop" % (n + 40, f))
    for tr in TRIGS.split(","):
        n += 1
        lines.append("%d; 2620 1 TRIGGER public events %s opsloop" % (n + 60, tr.split("=")[0]))
    for v in ("audit_log", "rule_quality", "unjudged_incidents"):
        n += 1
        lines.append("%d; 1259 1 VIEW public %s opsloop" % (n + 80, v))
    return "\n".join(lines) + "\n"


def fingerprint_text(tb, extra_verdict=None):
    rows = ["f|verdicts|1|%s|%s" % ("a" * 32, pgts(tb - timedelta(hours=3))),
            "f|actions|1|%s|%s" % ("b" * 32, pgts(tb - timedelta(hours=3))),
            "f|blocklist|10.0.0.1|%s|%s" % ("c" * 32, pgts(tb - timedelta(hours=3))),
            "f|console_users|admin|%s|%s" % ("d" * 32, pgts(tb - timedelta(days=3))),
            "f|audit|h-audit-1|%s|%s" % ("e" * 32, pgts(tb - timedelta(hours=2)))]
    if extra_verdict:
        rows.append("f|verdicts|2|%s|%s" % ("f" * 32, pgts(extra_verdict)))
    return "\n".join(rows) + "\n"


def regen_text():
    return ("e|cowrie|120|%s\ne|gateway|900|%s\ne|web-01|30|%s\ns|12|%s\nm|web-01|60|%s\ni|4|%s\nx|fixture|0\n"
            % ("1" * 32, "2" * 32, "3" * 32, "4" * 32, "5" * 32, "6" * 32))


FAKE_HEAD = r'''#!{python}
import hashlib, json, os, re, shlex, sys, time
ROOT = os.environ["FAKE_ROOT"]
def log(tool, **kw):
    with open(os.path.join(ROOT, "events.log"), "a") as f:
        f.write(json.dumps(dict(tool=tool, **kw), ensure_ascii=False) + "\n")
def load(name, default):
    try:
        with open(os.path.join(ROOT, name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return default
def dump(name, obj):
    with open(os.path.join(ROOT, name), "w") as f:
        json.dump(obj, f)
def answer(val):
    if isinstance(val, dict):
        sys.stdout.write(val.get("out", "")); sys.stderr.write(val.get("err", "")); sys.exit(val.get("rc", 0))
    sys.stdout.write(val or ""); sys.exit(0)
'''

FAKE_SSH = FAKE_HEAD + r'''
args = sys.argv[1:]
opts, i = {}, 0
while i < len(args) and args[i].startswith("-"):
    a = args[i]
    if a in ("-F", "-o", "-S", "-O", "-L"):
        opts.setdefault(a, []).append(args[i + 1]); i += 2
    else:
        opts[a] = True; i += 1
alias = args[i] if i < len(args) else ""
cmd = " ".join(args[i + 1:])
data = sys.stdin.buffer.read() if not sys.stdin.isatty() else b""
try:
    text = data.decode("utf-8")
except UnicodeDecodeError:
    text = "<bin %d>" % len(data)
log("ssh", alias=alias, cmd=cmd, argv=args, stdin=text if len(text) < 400000 else "<long>",
    stdin_sha=hashlib.sha256(data).hexdigest())
R = load("resp.json", {})
st = load("state.json", {})
if "-O" in opts:
    op = opts["-O"][0]
    if op == "check":
        sys.exit(0 if st.get("tunnel") else 255)
    if op == "exit":
        pid = st.pop("tunnel_pid", None)
        if pid:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
        st["tunnel"] = False; dump("state.json", st); sys.exit(0)
if "-f" in opts and "-L" in opts:
    # 진짜 ssh -f 처럼 뒤로 돌며 표준 출력 · 오류를 쥐고 있는다 (부른 쪽이 파이프로 받으면 끝을 기다리며 멈춘다)
    pid = os.fork()
    if pid == 0:
        os.setsid()
        time.sleep(float(os.environ.get("FAKE_TUNNEL_HOLD", "90")))
        os._exit(0)
    st["tunnel"] = True; st["tunnel_pid"] = pid; dump("state.json", st); sys.exit(0)
if cmd == "date +%s.%N":
    print("%.9f" % time.time()); sys.exit(0)
if cmd.startswith("chronyc"):
    print("Reference ID    : C0A83C01 (192.168.60.1)\nSystem time     : 0.000061080 seconds slow of NTP time\nLeap status     : Normal"); sys.exit(0)
if alias == "console-a":
    if "docker image inspect" in cmd:
        print(R["image_id"]); sys.exit(0)
    if cmd.startswith("docker save"):
        sys.stdout.write("IMAGE-TAR"); sys.exit(0)
if alias == "data01":
    if cmd.startswith("cat ") and cmd.endswith("/console.env"):
        print(R["console_env"]); sys.exit(0)
    if "pg_restore --list" in cmd:
        answer(R["toc"])
    if cmd.startswith("bash -c "):
        script = shlex.split(cmd)[2]
        m = re.search(r"# (s:[a-z0-9_]+)", script)
        tag = m.group(1) if m else "-"
        if tag == "s:restore":
            if hashlib.sha256(data).hexdigest() != R["dump_sha"]:
                sys.stderr.write("덤프가 다르다"); sys.exit(1)
        answer(R.get(tag, {"out": "", "rc": 0}))
    if " psql " in cmd:
        target = "drill" if "opsloop-drill-db" in cmd else ("prod" if re.search(r"opsloop-db\b", cmd) else "?")
        m = re.search(r"-- (q:[a-z0-9_]+)", text)
        tag = m.group(1) if m else "-"
        if tag == "q:role_checks":
            exp = R["role_expect"]
            out = []
            for line in text.splitlines():
                mm = re.match(r"^\\echo R (\d+) :SQLSTATE$", line)
                if mm:
                    out.append("R %s %s" % (mm.group(1), "00000" if exp[mm.group(1)] == "허용" else "42501"))
                mm = re.match(r"^SELECT 'P (\d+) '", line)
                if mm:
                    out.append("P %s %s" % (mm.group(1), exp[mm.group(1)]))
            print("\n".join(out)); sys.exit(0)
        key = "%s:%s" % (target, tag)
        if key in R:
            answer(R[key])
        answer(R.get(tag, {"out": "", "rc": 0}))
sys.stderr.write("가짜 ssh: 모르는 명령 %s %s\n" % (alias, cmd[:80]))
sys.exit(97)
'''

FAKE_DOCKER = FAKE_HEAD + r'''
args = sys.argv[1:]
data = b""
if args[:1] == ["load"]:
    data = sys.stdin.buffer.read()
modes = {}
for a in args:
    if a.endswith(":/run/opsloop-drill/console.env:ro"):
        src = a.split(":", 1)[0]
        modes = {"env_mode": os.stat(src).st_mode & 0o777, "dir_mode": os.stat(os.path.dirname(src)).st_mode & 0o777}
        # 컨테이너가 읽을 값. events.log 에는 쓰지 않고 따로 둔다 (시험이 이 값이 어디에도 새지 않았는지 본다)
        with open(src) as f:
            kv = dict(x.strip().split("=", 1) for x in f if "=" in x)
        dump("console_env.json", {"secret": kv.get("SESSION_SECRET"), "target": kv.get("DATABASE_URL", "").split("@")[-1]})
log("docker", argv=args, **modes)
R = load("resp.json", {})
st = load("state.json", {})
if args[:1] == ["version"]:
    print("29.7.2 arm64"); sys.exit(0)
if args[:2] == ["image", "inspect"]:
    if "{{json .Config}}" in args:
        print(json.dumps({"Cmd": ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"], "WorkingDir": "/app"}))
        sys.exit(0)
    if st.get("loaded"):
        print(R["image_id"]); sys.exit(0)
    sys.stderr.write("Error: No such image\n"); sys.exit(1)
if args[:1] == ["load"]:
    st["loaded"] = data == b"IMAGE-TAR"; dump("state.json", st); print("Loaded image: opsloop-api:latest"); sys.exit(0)
if args[:2] == ["rm", "-f"]:
    sys.exit(0 if st.pop("console", None) else 1)
if args[:1] == ["run"]:
    st["console"] = True; dump("state.json", st); print("f00d"); sys.exit(0)
if args[:1] == ["logs"]:
    sys.exit(0)
sys.stderr.write("가짜 docker: 모르는 명령 %s\n" % args); sys.exit(97)
'''

FAKE_SIMPLE = FAKE_HEAD + r'''
name = os.path.basename(sys.argv[0])
log(name, argv=sys.argv[1:])
if name == "curl":
    sys.stdout.write("200"); sys.exit(0)
if name == "lsof":
    sys.exit(1)
if name == "pmset":
    print("Assertion status system-wide:\n   PreventUserIdleSystemSleep    1"); sys.exit(0)
if name == "git":
    if "rev-parse" in sys.argv:
        print("0123456789abcdef0123456789abcdef01234567")
    sys.exit(0)
sys.exit(97)
'''


class Env:
    """임시 HOME · 가짜 실행기 · 백업 폴더 · 가짜 답."""

    def __init__(self, tb=None):
        self.dir = tempfile.mkdtemp(prefix="drill45-")
        self.home = os.path.join(self.dir, "home")
        self.bin = os.path.join(self.dir, "bin")
        self.root = os.path.join(self.dir, "fake")
        self.run = os.path.join(self.dir, "runs", "r01")
        self.out = os.path.join(self.dir, "evidence")
        for d in (self.home, self.bin, self.root):
            os.makedirs(d)
        for name, src in (("ssh", FAKE_SSH), ("docker", FAKE_DOCKER), ("curl", FAKE_SIMPLE), ("lsof", FAKE_SIMPLE),
                          ("pmset", FAKE_SIMPLE), ("git", FAKE_SIMPLE)):
            p = os.path.join(self.bin, name)
            with open(p, "w") as f:
                f.write(src.replace("{python}", PY))
            os.chmod(p, 0o755)
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.tb = tb or (self.now - timedelta(hours=6))
        bdir = os.path.join(self.home, "opsloop-backup")
        os.makedirs(bdir)
        self.old = os.path.join(bdir, "opsloop-%s.dump" % (self.tb - timedelta(hours=12)).strftime("%Y%m%d-%H%M"))
        with open(self.old, "wb") as f:
            f.write(fake_dump(self.tb - timedelta(hours=12)))
        ts = self.tb.strftime("%Y%m%d-%H%M")
        self.dump = os.path.join(bdir, "opsloop-%s.dump" % ts)
        with open(self.dump, "wb") as f:
            f.write(fake_dump(self.tb))
        self.globals = os.path.join(bdir, "opsloop-%s.globals.sql" % ts)
        with open(self.globals, "w") as f:
            f.write(GLOBALS)
        with open(os.path.join(bdir, "backup.log"), "w") as f:
            f.write("복원 시험 (events verdicts actions blocklist): 복원 1 1 1 1 · 운영 1 1 1 1\n"
                    "백업 7.2M %s · 표 23 개 · 역할 7 개\n" % self.dump)
        self.resp = self.responses()
        self.save_resp()

    def save_resp(self):
        with open(os.path.join(self.root, "resp.json"), "w") as f:
            json.dump(self.resp, f, ensure_ascii=False)

    def responses(self):
        tb, now = self.tb, self.now
        with open(self.dump, "rb") as f:
            dump_sha = hashlib.sha256(f.read()).hexdigest()
        counts = "".join("n|%s|%d\n" % (t, 5) for t in Q.TABLES)
        prod_state = ("p|cluster_name|\np|read_only|on\np|server_version|16.15\np|now|%s\np|verdicts_max|%s\n"
                      "p|events_max|%s|1000\np|runs_max|%s\np|channels|1|1\np|channels_sig|%s\np|fixture|40\n"
                      % (pgts(now), pgts(tb - timedelta(hours=3)), pgts(now), pgts(now - timedelta(minutes=1)), "9" * 32))
        prod_after = prod_state.replace("|1000\n", "|1200\n").replace(
            pgts(now - timedelta(minutes=1)), pgts(now + timedelta(minutes=30)))
        specs = [("opsloop_backup", "backup", "self"), ("opsloop_console", "console", "self"),
                 ("opsloop_cti", "cti", "self"), ("opsloop_detector", "detector", "opsloop-pull"),
                 ("opsloop_gate", "gate", "self"), ("opsloop_ingest", "ingest", "opsloop-pull")]
        checks = D.role_checks()
        up = ("ready 1\ncluster opsloop-drill\nbind 127.0.0.1:5433\nmemory 268435456\noom_adj 1000\nimage %s\n"
              "env_password 0\ninitdb_mounts 0\n" % PG_ID)
        pre = ("chrony System time     : 0.000061080 seconds slow of NTP time\nmem_avail_mb 1337\ndisk_free_mb 12000\n"
               "port_listen 0\nimage %s\nprod_image %s\ndrill_container 0\ndrill_volume 0\ndrill_dir 0\npull_user 996\n"
               "ingest_bin 1\npull_loki 1\ndefaults_home 1\ndefaults_dburl 0\nsudo 1\ntime 1\nchoom 1\ndocker_group 1\n"
               % (PG_ID, PG_ID))
        return {
            "image_id": IMAGE_ID, "dump_sha": dump_sha, "toc": toc_text(tb),
            "console_env": "DATABASE_URL=postgresql://opsloop_console:%s@127.0.0.1:5433/opsloop" % CANARY_PW,
            "role_expect": {str(c["idx"]): c["expect"] for c in checks},
            "s:precheck": pre, "s:up": up,
            "prod:q:counts": counts + CATALOG + BASE + prod_state,
            "prod:q:t0": "p|now|%s\n" % pgts(now),
            "drill:q:roles_apply": "",
            "s:passwords": "".join("env %s %s.env %s\n" % (r, n, "ops" if o == "self" else o) for r, n, o in specs),
            "s:roles_check": "".join("ok %s.env %s opsloop-drill\nmode %s.env 600 %s\n"
                                     % (n, r, n, "ops" if o == "self" else o) for r, n, o in specs),
            "drill:q:roles_state": "".join("a|%s|%s|%s|%s|%s|true\n" % ((r,) + v) for r, v in sorted(ROLES.items()))
            + "g|pg_read_all_data|opsloop_backup|true\n",
            "s:restore": "restore_rc 0\n",
            "drill:q:counts": counts + CATALOG + "r|runs_max|%s\nr|verdicts_max|%s\nr|verdicts_max_id|1\n"
            % (pgts(tb - timedelta(minutes=2)), pgts(tb - timedelta(hours=3))),
            "drill:q:fingerprint": fingerprint_text(tb),
            "drill:q:zero": "".join("z|%s|0\n" % n for n, _d, _s in Q.ZERO) + BASE + CATALOG
            + "q|actions_id_seq|1|1\nq|verdicts_id_seq|1|1\nq|cti_snapshots_id_seq|-|-\n",
            "drill:q:notify_off": "o|0|0|1\n", "drill:q:notify_state": "o|0|0|1\n",
            "drill:q:console_base": "v|1|1\nu|k2|R002|low\n",
            "drill:q:console_after": "w|2|k2|undetermined|admin|resolved\n",
            "s:regen_check": "mem_avail_mb 1100\nhome /var/lib/opsloop-drill/home\n"
            "OPSLOOP_DB_ENV opsloop_ingest 127.0.0.1:5433 opsloop-drill\n"
            "OPSLOOP_DETECTOR_ENV opsloop_detector 127.0.0.1:5433 opsloop-drill\nok\n",
            "s:regen_full": {"out": "rc 0\n", "err": "\tMaximum resident set size (kbytes): 91234\n"
                             "\tElapsed (wall clock) time (h:mm:ss or m:ss): 1:02.50\n"},
            "s:regen_loki": {"out": "rc 0\n", "err": "\tMaximum resident set size (kbytes): 51234\n"
                             "\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:12.00\n"},
            "s:catchup": "rc_ingest 0\nrc_loki 0\nt_r %d\n" % int((now + timedelta(minutes=40)).timestamp()),
            "drill:q:regen": regen_text(), "prod:q:regen": regen_text(),
            "s:hosts": "/var/lib/opsloop-drill/home/raw/v1 sensor=cowrie/host=i-new\n"
                       "/var/lib/opsloop/raw/v1 sensor=cowrie/host=i-new\n/var/lib/opsloop/raw/v1 sensor=cowrie/host=i-old\n",
            "prod:q:fingerprint": fingerprint_text(tb, extra_verdict=tb + timedelta(hours=1)),
            "prod:q:loss": "l|console_logins|1|0\nm|verdicts_max_tf|%s\nm|runs_next|%s\n"
            % (pgts(tb + timedelta(hours=1)), pgts(tb + timedelta(minutes=3))),
            "prod:q:baseline": BASE,
            "s:cleanup": ("rm_container 0\nrm_volume 0\nrm_dir 0\nleft_container 0\nleft_volume 0\nleft_dir 0\n"
                          "prod_running true\nunit Result=success\nunit ExecMainExitTimestamp=Sun 2026-09-27 10:00:00 KST\n"
                          "unit ExecMainStatus=0\nunit Id=opsloop-ingest.service\nunit \nunit Result=success\n"
                          "unit ExecMainExitTimestamp=Sun 2026-09-27 10:00:30 KST\nunit ExecMainStatus=0\n"
                          "unit Id=opsloop-agents.service\n"),
            "prod:q:prod_state": prod_after,
        }

    def env(self):
        e = dict(os.environ)
        e.update(PATH=self.bin + os.pathsep + e.get("PATH", ""), HOME=self.home, FAKE_ROOT=self.root,
                 OPSLOOP_DRILL_POLL="0.01")
        return e

    def tool(self, *args):
        p = subprocess.run([PY, TOOL] + list(args), env=self.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=120)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")

    def events(self):
        out = []
        try:
            with open(os.path.join(self.root, "events.log")) as f:
                for line in f:
                    out.append(json.loads(line))
        except FileNotFoundError:
            pass
        return out

    def close(self):
        # 가짜 터널(뒤로 돈 자식)이 남았으면 끈다
        try:
            with open(os.path.join(self.root, "state.json")) as f:
                pid = json.load(f).get("tunnel_pid")
            if pid:
                os.kill(pid, 15)
        except (OSError, ValueError):
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


SEQUENCE = [("precheck",), ("t0",), ("up",), ("roles",), ("restore",), ("verify",), ("console",), ("console", "--confirm"),
            ("regen",), ("compare",), ("done",), ("cleanup",), ("report",)]


def script_of(ev):
    if ev.get("tool") == "ssh" and ev.get("cmd", "").startswith("bash -c "):
        return shlex.split(ev["cmd"])[2]
    return None


# ──────────────────────────────────────────────────────────────
class DryRun(unittest.TestCase):
    def test_드라이런은_아무것도_부르지_않고_폴더도_만들지_않는다(self):
        e = Env()
        try:
            for step in SEQUENCE:
                rc, out, err = e.tool(e.run, *step)
                self.assertEqual(rc, 0, (step, out[-500:], err[-500:]))
                self.assertIn("드라이런", out)
            self.assertEqual(e.events(), [])
            self.assertFalse(os.path.exists(e.run))
            self.assertFalse(os.path.exists(os.path.expanduser(os.path.join(e.home, ".config", "opsloop", "drill"))))
        finally:
            e.close()

    def test_드라이런은_대상_이름과_포트를_보인다(self):
        e = Env()
        try:
            _rc, out, _ = e.tool(e.run, "up")
            for want in ("opsloop-drill-db", "127.0.0.1", "5433", "opsloop_drill_pgdata", "cluster_name=opsloop-drill",
                         "shared_buffers=64MB", "--oom-score-adj 1000",
                         "--pull never", "--memory 256m", "POSTGRES_PASSWORD_FILE", "rto:S1", "rto:S2"):
                self.assertIn(want, out)
            self.assertNotRegex(out, r"-v \S*:/docker-entrypoint-initdb")
            self.assertNotRegex(out, r"docker[ -]compose")
            _rc, out, _ = e.tool(e.run, "regen")
            self.assertIn("OPSLOOP_HOME=/var/lib/opsloop-drill/home", out)
            self.assertLess(out.index("$(cat /etc/default/opsloop-ingest | xargs)"), out.index("OPSLOOP_HOME=/var/lib/opsloop-drill"))
            self.assertIn("OPSLOOP_DETECTOR_ENV=/var/lib/opsloop-drill/env/detector.env", out)
            self.assertIn("HOME=/var/lib/opsloop-drill/home)", out)
            # 손 실행은 유닛의 MemoryMax 밖이다. 호스트 메모리가 모자라면 운영보다 먼저 죽게 OOM 점수를 올린다
            self.assertIn('"${RUN[@]}" /usr/bin/choom -n 1000 -- /usr/bin/time -v /usr/local/bin/opsloop-ingest --full', out)
            self.assertIn('"${RUN[@]}" /usr/bin/choom -n 1000 -- /usr/bin/time -v python3 ', out)
            self.assertNotIn("systemd-run ", out.replace("systemd-run 은 쓰지 않는다", ""))
        finally:
            e.close()

    def test_목록_인자(self):
        e = Env()
        try:
            rc, out, _ = e.tool("--list")
            self.assertEqual(rc, 0)
            for s in D.STEP_NAMES:
                self.assertIn(s, out)
            rc, _o, err = e.tool(e.run, "up", "--confirm")
            self.assertEqual(rc, 2)
            rc, _o, err = e.tool(os.path.join(D.ROOT, "tmp-run"), "precheck", "--apply")
            self.assertEqual(rc, 2)
            self.assertIn("저장소 밖", err)
            self.assertEqual(e.events(), [])
        finally:
            e.close()


class FullRun(unittest.TestCase):
    """가짜 원격으로 전체를 차례로 돌린다. 한 번 돌리고 여러 시험이 결과를 본다."""

    @classmethod
    def setUpClass(cls):
        cls.e = Env()
        cls.outputs = []
        cls.rcs = []
        for step in SEQUENCE:
            args = [cls.e.run] + list(step) + ["--apply"]
            if step == ("report",):
                args += ["--out", cls.e.out]
            rc, out, err = cls.e.tool(*args)
            cls.rcs.append((step, rc))
            cls.outputs.append(out + err)
            if rc != 0:
                break
        cls.ev = cls.e.events()

    @classmethod
    def tearDownClass(cls):
        cls.e.close()

    def test_전체_단계가_성공한다(self):
        self.assertEqual([rc for _s, rc in self.rcs], [0] * len(SEQUENCE),
                         "\n".join("%s %s\n%s" % (s, rc, o[-1500:]) for (s, rc), o in zip(self.rcs, self.outputs) if rc))

    def test_주요_명령_순서(self):
        def first(pred):
            for i, ev in enumerate(self.ev):
                if pred(ev):
                    return i
            self.fail("명령이 없다")
        tag = lambda t: (lambda ev: t in (script_of(ev) or "") or ("-- " + t) in ev.get("stdin", ""))
        order = [first(tag("s:up")), first(tag("q:roles_apply")), first(tag("s:passwords")), first(tag("s:restore")),
                 first(tag("q:fingerprint")), first(tag("q:notify_off")),
                 first(lambda ev: ev["tool"] == "docker" and ev["argv"][:1] == ["run"]),
                 first(tag("q:console_after")), first(tag("s:regen_full")), first(tag("s:regen_loki")),
                 first(tag("s:catchup")), first(lambda ev: "opsloop-db " in ev.get("cmd", "") and "q:fingerprint" in ev.get("stdin", "")),
                 first(tag("s:cleanup"))]
        self.assertEqual(order, sorted(order))

    def test_터널은_뒤로_도는_ssh_가_출력을_쥐어도_멈추지_않는다(self):
        # 가짜 ssh -f 는 진짜처럼 뒤로 돈 자식이 표준 출력 · 오류를 90초 쥐고 있다. 파이프로 받으면 60초 뒤 124 로 멈춘다
        recs = [json.loads(x) for x in open(os.path.join(self.e.run, "records.jsonl"))]
        tun = [r for r in recs if r.get("name") == "tunnel"]
        self.assertEqual(len(tun), 1)
        self.assertEqual(tun[0]["rc"], 0)
        self.assertLess(tun[0]["seconds"], 10)

    def test_RTO_표시가_차례대로_있다(self):
        marks = [json.loads(x) for x in open(os.path.join(self.e.run, "marks.jsonl"))]
        codes = [re.match(r"rto:(\S+)", m["note"]).group(1) for m in marks]
        self.assertEqual(codes, ["T0"] + ["S%d" % i for i in range(1, 10)])
        self.assertTrue(all(m["host"] == "data01" and m["t_remote_ns"] for m in marks))

    def test_증거_파일(self):
        res_p = os.path.join(self.e.out, "results.json")
        with open(res_p, encoding="utf-8") as f:
            text = f.read()
        res = json.loads(text)
        with open(os.path.join(self.e.out, "sha256.json")) as f:
            self.assertEqual(json.load(f)["results.json"], hashlib.sha256(text.encode()).hexdigest())
        for k in ("date", "timezone", "scope", "provenance", "criteria", "runs", "exceptions", "summary"):
            self.assertIn(k, res)
        self.assertEqual(res["criteria"]["rto_max_s"], 7200)
        self.assertEqual(res["criteria"]["rpo_target_s"], 43200)
        run = res["runs"][0]
        for k in ("backup", "clock", "rto", "rpo", "integrity", "regen", "console", "records", "cleanup", "files"):
            self.assertIn(k, run)
        self.assertEqual(run["backup"]["sha256"], self.e.resp["dump_sha"])
        self.assertNotIn("path", run["backup"])
        s = res["summary"]
        self.assertTrue(s["rto_pass"] and s["rpo_pass"] and s["regen_match"] and s["integrity_pass"] and s["cleanup_ok"], s)
        self.assertEqual((s["rpo_backup_gap_max_s"], s["rpo_backup_gap_ok"]), (43200.0, True))
        self.assertIn("rpo_pass", res["criteria"])
        self.assertEqual(run["rpo"]["lines"]["db_only"]["lost_rows"]["verdicts"], 1)
        self.assertEqual(run["rpo"]["lines"]["db_only"]["verdict_loss_s"], 4 * 3600.0)
        self.assertEqual(run["regen"]["compare"]["mirror_hosts"]["prod_only"], ["sensor=cowrie/host=i-old"])
        self.assertEqual([r["name"] for r in run["records"]][:3], ["precheck", "t0", "up"])
        self.assertEqual(res["date"], datetime.fromisoformat(run["rto"]["t0"]).astimezone(D.KST).strftime("%Y-%m-%d"))

    def test_비밀값이_명령행_화면_기록에_없다(self):
        env_file = os.path.join(self.e.home, ".config", "opsloop", "drill", "console.env")
        # 정리 단계가 Mac 비밀 폴더를 지웠다
        self.assertFalse(os.path.exists(env_file))
        blobs = [json.dumps(ev, ensure_ascii=False) for ev in self.ev] + self.outputs
        for name in os.listdir(self.e.run):
            with open(os.path.join(self.e.run, name), encoding="utf-8", errors="replace") as f:
                blobs.append(f.read())
        for name in os.listdir(self.e.out):
            with open(os.path.join(self.e.out, name), encoding="utf-8") as f:
                blobs.append(f.read())
        # 콘솔 컨테이너가 받은 값: 새 SESSION_SECRET · 터널로 가는 DSN
        with open(os.path.join(self.e.root, "console_env.json")) as f:
            got = json.load(f)
        self.assertRegex(got["secret"] or "", r"^[0-9a-f]{64}$")
        self.assertEqual(got["target"], "host.docker.internal:15433/opsloop")
        for b in blobs:
            self.assertNotIn(CANARY_PW, b)
            self.assertNotIn(got["secret"], b)
            self.assertNotRegex(b, r"SESSION_SECRET=[0-9a-f]{16}")
        # 콘솔 컨테이너 · 훈련 DB 컨테이너에는 파일로만 준다
        runs = [ev["argv"] for ev in self.ev if ev["tool"] == "docker" and ev["argv"][:1] == ["run"]]
        self.assertEqual(len(runs), 1)
        joined = " ".join(runs[0])
        # 콘솔을 띄울 때 Mac 비밀 파일은 0600 · 폴더는 0700 이었다
        run_ev = [ev for ev in self.ev if ev["tool"] == "docker" and ev["argv"][:1] == ["run"]][0]
        self.assertEqual((run_ev.get("env_mode"), run_ev.get("dir_mode")), (0o600, 0o700))
        self.assertNotIn("DATABASE_URL", joined)
        self.assertNotIn("SESSION_SECRET", joined)
        self.assertIn("127.0.0.1:18000:8000", joined)
        self.assertIn("OPSLOOP_WORKER=opsloop-drill", joined)
        up = [script_of(ev) for ev in self.ev if "s:up" in (script_of(ev) or "")][0]
        self.assertNotRegex(up, r"-e POSTGRES_PASSWORD=|--env-file")
        self.assertIn("POSTGRES_PASSWORD_FILE=", up)
        # 역할 비밀번호는 원격에서 만들어 표준 입력으로만 (스크립트에 값이 없다)
        pw = [script_of(ev) for ev in self.ev if "s:passwords" in (script_of(ev) or "")][0]
        self.assertIn("openssl rand -hex 24", pw)
        self.assertRegex(pw, r"printf \"ALTER ROLE %s PASSWORD '%s';\\n\" \"\$role\" \"\$pw\" \| drill_psql")
        self.assertNotRegex(pw, r"PASSWORD '[0-9a-f]")
        self.assertIn("install -m 600 -o \"$2\" -g \"$2\" /dev/stdin", pw)

    def test_운영_이름은_읽기에만(self):
        prod_re = re.compile(r"opsloop-db\b")
        for ev in self.ev:
            if ev["tool"] != "ssh":
                continue
            cmd, stdin = ev["cmd"], ev.get("stdin", "")
            self.assertNotIn("opsloop_pgdata", cmd + stdin)
            self.assertNotIn("192.168.60.11", cmd + stdin)
            if cmd == D.PROD_PSQL:
                self.assertTrue(stdin.startswith(Q.PROD_HEAD))
                Q.assert_read_only(stdin[len(Q.PROD_HEAD):])
                self.assertIn("-U opsloop_backup", cmd)
                self.assertIn("default_transaction_read_only=on", cmd)
                continue
            script = script_of(ev)
            for line in (script or cmd).splitlines():
                if prod_re.search(line):
                    self.assertRegex(line, r"docker inspect -f '\{\{\.(Image|State\.Running)\}\}' opsloop-db ", line)
                if re.search(r"/var/lib/opsloop(?![-\w])", line):
                    self.assertTrue(line.startswith("for root in") or line.startswith("#"), line)
            # 운영 DB 를 대상으로 역할 · 비밀번호를 바꾸는 설치 스크립트는 쓰지 않는다
            self.assertNotRegex(cmd + (script or ""), r"install-collector|db-console-role|install-cti")
            if script and "s:hosts" in script:
                self.assertNotRegex(script.replace("2>/dev/null", ""), r"\b(rm|mv|cp|tee|install|chmod|chown)\b|>")

    def test_지우기_만들기는_훈련_이름만(self):
        write = re.compile(r"\bdocker (rm|run|volume rm|stop|kill)\b|\brm -rf\b|\binstall -[dm]\b|\bchmod\b|\bchown\b|"
                           r"pg_restore -U|\bUPDATE\b|\bALTER ROLE\b|\bCREATE ROLE\b")
        for ev in self.ev:
            if ev["tool"] != "ssh" or ev["alias"] != "data01":
                continue
            for line in ((script_of(ev) or ev["cmd"]) + "\n" + ev.get("stdin", "")).splitlines():
                if write.search(line) and not line.lstrip().startswith(("#", "--")):
                    self.assertNotRegex(line, r"opsloop-db\b|opsloop_pgdata|/var/lib/opsloop(?![-\w])", line)
        # 훈련 이름은 운영 이름과 겹치지 않는다
        for n in (D.DRILL_DB, D.DRILL_VOLUME, D.DRILL_DIR, D.DRILL_CLUSTER, D.CONSOLE_NAME, D.WORKER):
            self.assertIn("drill", n)
            self.assertNotIn(n, (D.PROD_DB, "opsloop_pgdata", D.PROD_HOME))
        self.assertNotEqual(D.DRILL_PORT, 5432)
        self.assertEqual(D.DRILL_BIND, "127.0.0.1")

    def test_훈련_SQL_은_모두_확인_블록으로_시작한다(self):
        n = 0
        for ev in self.ev:
            if ev["tool"] != "ssh":
                continue
            if "opsloop-drill-db psql" in ev["cmd"]:
                self.assertTrue(ev["stdin"].startswith(Q.DRILL_HEAD), ev["stdin"][:120])
                n += 1
            script = script_of(ev)
            if script:
                for line in script.splitlines():
                    if "psql" in line:
                        self.assertTrue("drill_psql()" in line or "SHOW cluster_name" in line
                                        or re.match(r"^\s*printf .*\| drill_psql\s*$", line), line)
                if "drill_psql" in script:
                    self.assertIn(Q.DRILL_HEAD, script)
        self.assertGreaterEqual(n, 15)
        self.assertIn("current_setting('cluster_name') IS DISTINCT FROM 'opsloop-drill'", Q.GUARD)
        self.assertIn("RAISE EXCEPTION", Q.GUARD)


class Order(unittest.TestCase):
    def test_앞_단계_없이_apply_하면_아무것도_하지_않는다(self):
        e = Env()
        try:
            for step in ("t0", "up", "restore", "console", "regen", "done"):
                rc, _o, err = e.tool(e.run, step, "--apply")
                self.assertEqual(rc, 2, step)
                self.assertIn("앞 단계", err)
            self.assertEqual(e.events(), [])
        finally:
            e.close()

    def test_T0_두번과_알림이_켜진_콘솔(self):
        e = Env()
        try:
            for step in ("precheck", "t0"):
                self.assertEqual(e.tool(e.run, step, "--apply")[0], 0)
            rc, _o, err = e.tool(e.run, "t0", "--apply")
            self.assertEqual(rc, 2)
            self.assertIn("이미", err)
            # T0 뒤에 새 덤프가 생겨도 precheck 를 다시 돌려 백업 선택(T_b)을 바꾸지 못한다
            before = json.load(open(os.path.join(e.run, "state.json")))["precheck"]["backup"]["file"]
            newer = e.tb + timedelta(hours=7)
            bdir = os.path.join(e.home, "opsloop-backup")
            name = "opsloop-%s" % newer.strftime("%Y%m%d-%H%M")
            with open(os.path.join(bdir, name + ".dump"), "wb") as f:
                f.write(fake_dump(newer))
            shutil.copy(e.globals, os.path.join(bdir, name + ".globals.sql"))
            n = len(e.events())
            rc, _o, err = e.tool(e.run, "precheck", "--apply")
            self.assertEqual(rc, 2)
            self.assertIn("T0 를 표시한 뒤", err)
            self.assertEqual(len(e.events()), n)
            self.assertEqual(json.load(open(os.path.join(e.run, "state.json")))["precheck"]["backup"]["file"], before)
            # verify 가 끝났다고 치고 알림 채널이 켜진 채로 콘솔을 띄우려 한다
            st = json.load(open(os.path.join(e.run, "state.json")))
            st["steps"]["verify"] = {"ok": True}
            D.write_private(os.path.join(e.run, "state.json"), json.dumps(st))
            e.resp["drill:q:notify_state"] = "o|1|1|1\n"
            e.save_resp()
            rc, out, _ = e.tool(e.run, "console", "--apply")
            self.assertEqual(rc, 1)
            self.assertIn("알림 채널이 켜져", out)
            self.assertFalse(any(ev["tool"] == "docker" and ev["argv"][:1] == ["run"] for ev in e.events()))
        finally:
            e.close()

    def test_역할_목록에_비밀번호가_있으면_멈춘다(self):
        e = Env()
        try:
            with open(e.globals, "a") as f:
                f.write("ALTER ROLE opsloop_gate WITH LOGIN PASSWORD 'x';\n")
            rc, out, _ = e.tool(e.run, "precheck", "--apply")
            self.assertEqual(rc, 1)
            self.assertIn("비밀번호", out)
            self.assertEqual([ev for ev in e.events() if ev["tool"] == "ssh"], [])
        finally:
            e.close()

    def test_복원_대상이_훈련_DB_가_아니면_멈춘다(self):
        e = Env()
        try:
            for step in ("precheck", "t0", "up", "roles"):
                self.assertEqual(e.tool(e.run, step, "--apply")[0], 0, step)
            e.resp["s:restore"] = {"out": "", "err": "훈련 DB 가 아니다 (cluster_name). 복원하지 않는다\n", "rc": 3}
            e.save_resp()
            rc, out, _ = e.tool(e.run, "restore", "--apply")
            self.assertEqual(rc, 1)
            self.assertFalse(any("pg_restore --list" in ev.get("cmd", "") for ev in e.events()))
        finally:
            e.close()

    def test_verify_를_다시_돌리면_첫_지문을_쓴다(self):
        e = Env()
        try:
            for step in ("precheck", "t0", "up", "roles", "restore"):
                self.assertEqual(e.tool(e.run, step, "--apply")[0], 0, step)
            good = e.resp["drill:q:zero"]
            e.resp["drill:q:zero"] = good.replace("z|verdict_orphan|0", "z|verdict_orphan|1")
            e.save_resp()
            self.assertEqual(e.tool(e.run, "verify", "--apply")[0], 1)
            # 점검은 실패했어도 알림 끄기까지 갔다 (훈련 DB 의 notify_channels 가 이미 바뀌었다)
            self.assertTrue(any("-- q:notify_off" in ev.get("stdin", "") for ev in e.events()))
            # 지금 다시 뜨면 복원 직후와 다른 지문이 나온다
            e.resp["drill:q:zero"] = good
            e.resp["drill:q:fingerprint"] = fingerprint_text(e.tb).replace("c" * 32, "0" * 32)
            e.save_resp()
            rc, out, _ = e.tool(e.run, "verify", "--apply")
            self.assertEqual(rc, 0, out[-800:])
            self.assertIn("처음 뜬 것", out)
            self.assertEqual(len([ev for ev in e.events() if "-- q:fingerprint" in ev.get("stdin", "")]), 1)
            with open(os.path.join(e.run, "state.json"), encoding="utf-8") as f:
                st = json.load(f)
            self.assertEqual(st["verify"]["fingerprint"]["blocklist"]["10.0.0.1"][0], "c" * 32)
            # 새로 복원했으면(restore 시각이 다르면) 다시 뜬다
            st["steps"]["restore"]["at"] = "2099-01-01T00:00:00+00:00"
            D.write_private(os.path.join(e.run, "state.json"), json.dumps(st))
            rc, out, _ = e.tool(e.run, "verify", "--apply")
            self.assertEqual(rc, 0, out[-800:])
            self.assertEqual(len([ev for ev in e.events() if "-- q:fingerprint" in ev.get("stdin", "")]), 2)
        finally:
            e.close()

    def test_재적재_직전_메모리가_모자라면_멈춘다(self):
        e = Env()
        try:
            for step in ("precheck", "t0", "up", "roles", "restore", "verify"):
                self.assertEqual(e.tool(e.run, step, "--apply")[0], 0, step)
            e.resp["s:regen_check"] = e.resp["s:regen_check"].replace("mem_avail_mb 1100", "mem_avail_mb 450")
            e.save_resp()
            rc, out, _ = e.tool(e.run, "regen", "--apply")
            self.assertEqual(rc, 1)
            self.assertIn("가용 메모리", out)
            self.assertFalse(any("s:regen_full" in (script_of(ev) or "") for ev in e.events()))
        finally:
            e.close()

    def test_대조_창이_T_b_뒤를_덮지_않으면_멈춘다(self):
        # 백업 뒤 곧바로 훈련해 따라잡기가 T_b + 20분에 끝났다: 창 끝(T_r − 30분)이 T_b 앞이라 덤프 행만 견주게 된다
        e = Env()
        try:
            e.resp["s:catchup"] = "rc_ingest 0\nrc_loki 0\nt_r %d\n" % int((e.tb + timedelta(minutes=20)).timestamp())
            e.save_resp()
            for step in ("precheck", "t0", "up", "roles", "restore", "verify", "regen"):
                self.assertEqual(e.tool(e.run, step, "--apply")[0], 0, step)
            rc, out, _ = e.tool(e.run, "compare", "--apply")
            self.assertEqual(rc, 1)
            self.assertIn("T_b 뒤를", out)
            self.assertFalse(any("-- q:regen" in ev.get("stdin", "") for ev in e.events()))
            # T_b + 50분에 다시 돌리면 창이 T_b 뒤 20분을 덮어 대조한다
            e.resp["s:catchup"] = "rc_ingest 0\nrc_loki 0\nt_r %d\n" % int((e.tb + timedelta(minutes=50)).timestamp())
            e.save_resp()
            rc, out, _ = e.tool(e.run, "compare", "--apply")
            self.assertEqual(rc, 0, out[-600:])
            with open(os.path.join(e.run, "state.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f)["compare"]["window_after_tb_s"], 1200.0)
        finally:
            e.close()

    def test_재적재를_콘솔보다_먼저_해도_RTO_순서는_맞다(self):
        # 선행 규칙은 regen 을 verify 뒤에 허용한다. 그 순서로 끝까지 가도 RTO 가 순서 때문에 불합격이 되지 않는다
        e = Env()
        try:
            seq = [("precheck",), ("t0",), ("up",), ("roles",), ("restore",), ("verify",), ("regen",), ("compare",),
                   ("console",), ("console", "--confirm"), ("done",), ("report", "--out", e.out)]
            for step in seq:
                rc, out, err = e.tool(e.run, *(list(step) + ["--apply"]))
                self.assertEqual(rc, 0, (step, out[-800:], err[-400:]))
            with open(os.path.join(e.out, "results.json"), encoding="utf-8") as f:
                res = json.load(f)
            self.assertEqual((res["runs"][0]["rto"]["order_ok"], res["summary"]["rto_pass"]), (True, True))
        finally:
            e.close()


class Metrics(unittest.TestCase):
    T0 = 1_790_000_000 * 10 ** 9

    def marks(self, seconds):
        out = [{"note": "rto:T0 장애 선언", "t_local_ns": self.T0, "t_remote_ns": self.T0 + 5_000_000, "offset_ms": 5.0}]
        for i, s in enumerate(seconds, 1):
            out.append({"note": "rto:S%d x" % i, "t_local_ns": self.T0 + int(s * 1e9), "t_remote_ns": None})
        return out

    def test_RTO(self):
        r = D.compute_rto(self.marks([60, 120, 300, 400, 900, 1000, 1500, 3000, 7200]))
        self.assertEqual((r["service_s"], r["complete_s"], r["pass"], r["order_ok"]), (1500.0, 7200.0, True, True))
        r = D.compute_rto(self.marks([60, 120, 300, 400, 900, 1000, 1500, 3000, 7200.5]))
        self.assertFalse(r["pass"])
        # console(S6 · S7)과 regen(S8)은 verify(S5) 뒤 어느 쪽이 먼저여도 된다 (단계 선행 규칙과 같다)
        r = D.compute_rto(self.marks([60, 120, 300, 400, 900, 2000, 2500, 1500, 3000]))
        self.assertEqual((r["order_ok"], r["pass"], r["service_s"]), (True, True, 2500.0))
        # S8 이 S5 보다 이르거나, S9 가 S7 보다 이르면 순서 불합격
        self.assertFalse(D.compute_rto(self.marks([60, 120, 300, 400, 900, 1000, 1500, 800, 3000]))["order_ok"])
        self.assertFalse(D.compute_rto(self.marks([60, 120, 300, 400, 900, 1000, 3500, 1500, 3000]))["order_ok"])
        self.assertEqual(set(D.RTO_PRED), {"S%d" % i for i in range(1, 10)})
        r = D.compute_rto(self.marks([60, 120, 300]))
        self.assertEqual((r["complete_s"], r["pass"]), (None, False))
        self.assertEqual(r["missing"], ["S4", "S5", "S6", "S7", "S8", "S9"])
        # T0 는 첫 표시, 나머지는 마지막 표시 · 시각이 거꾸로면 순서 불합격
        m = self.marks([60, 120, 300, 400, 900, 1000, 1500, 3000, 3600])
        m.append({"note": "rto:T0 다시", "t_local_ns": self.T0 + 10 ** 12})
        m.append({"note": "rto:S2 다시", "t_local_ns": self.T0 + int(4000e9)})
        r = D.compute_rto(m)
        self.assertEqual(r["t0"], D.iso(D.ns_dt(self.T0)))
        self.assertFalse(r["order_ok"])
        self.assertFalse(r["pass"])
        self.assertIsNone(D.compute_rto([])["t0"])

    def test_RPO(self):
        tb = datetime(2026, 9, 26, 19, 30, 6, tzinfo=UTC)
        tf = tb + timedelta(hours=7)
        regen = {"sensors": {"cowrie": {"same": True, "drill": {"count": 5}, "prod": {"count": 5}},
                             "web-01": {"same": True, "drill": {"count": 2}, "prod": {"count": 2}}},
                 "node_metrics": {"same": True}}
        loss = {"verdicts": {"until_tf": 2, "after_tf": 1}}
        r = D.compute_rpo(tb, tf, loss, tb - timedelta(hours=2), tb + timedelta(hours=1), regen, {"max_gap_s": 43395.0})
        self.assertEqual(r["design_s"], 7 * 3600.0)
        self.assertEqual(r["lines"]["db_only"]["verdict_loss_s"], 3 * 3600.0)
        self.assertEqual(r["lines"]["db_only"]["lost_rows"], {"verdicts": 2})
        self.assertEqual(r["lines"]["s3_sensor"], {"match": True, "loss_rows": 0, "sensors": ["cowrie"]})
        self.assertEqual(r["lines"]["monitored_logs"]["sensors"], ["web-01"])
        # 합격은 설계 RPO(7시간) · 재생성으로 본다. 실측 백업 간격 12h03m15s 는 12시간을 넘으므로 따로 적는다
        self.assertEqual((r["pass"], r["backup_gap_ok"], r["backup_gap_max_s"]), (True, False, 43395.0))
        # 04:30 · 16:30 백업이 3초 밀린 것만으로 설계 RPO 6시간이 불합격이 되지 않는다
        g = D.backup_gaps([tb - timedelta(hours=12, seconds=3), tb])
        r = D.compute_rpo(tb, tb + timedelta(hours=6), {}, None, None, regen, g)
        self.assertEqual((r["pass"], r["backup_gap_ok"]), (True, False))
        r = D.compute_rpo(tb, tf, loss, None, None, regen, {"max_gap_s": 43200})
        self.assertEqual((r["pass"], r["backup_gap_ok"]), (True, True))
        self.assertEqual(r["lines"]["db_only"]["verdict_loss_s"], 0.0)
        regen["sensors"]["cowrie"] = {"same": False, "drill": {"count": 3}, "prod": {"count": 5}}
        r = D.compute_rpo(tb, tf, loss, None, None, regen, None)
        self.assertEqual(r["lines"]["s3_sensor"], {"match": False, "loss_rows": 2, "sensors": ["cowrie"]})
        self.assertEqual((r["pass"], r["backup_gap_ok"]), (False, None))
        r = D.compute_rpo(tb, tb + timedelta(hours=13), {}, None, None, None, None)
        self.assertEqual((r["design_s"], r["pass"]), (13 * 3600.0, False))
        # T_b 가 T_f 보다 늦으면(장애 선언 뒤의 덤프) 설계 RPO 가 음수다. 합격이 아니다
        r = D.compute_rpo(tb, tb - timedelta(hours=1), {}, None, None, None, None)
        self.assertEqual((r["design_s"], r["pass"]), (-3600.0, False))

    def test_백업_간격(self):
        base = datetime(2026, 9, 21, 19, 26, 51, tzinfo=UTC)
        g = D.backup_gaps([base, base + timedelta(hours=12, minutes=3, seconds=15), base + timedelta(hours=24), None])
        self.assertEqual(g["max_gap_s"], 43395.0)
        self.assertEqual(g["count"], 3)
        self.assertIsNone(D.backup_gaps([base])["max_gap_s"])

    def test_덤프_머리(self):
        t = datetime(2026, 9, 26, 7, 27, 40, tzinfo=UTC)
        h = D.parse_archive_header(fake_dump(t))
        self.assertEqual((h["created"], h["version"], h["pg_dump_version"], h["dbname"]), (t, "1.15.0", "16.15", "opsloop"))
        with self.assertRaises(ValueError):
            D.parse_archive_header(b"NOTADUMP" + b"\0" * 100)

    def test_백업_고르기(self):
        e = Env()
        try:
            bdir = os.path.join(e.home, "opsloop-backup")
            self.assertEqual(D.pick_backup(bdir), (e.dump, e.globals))
            with self.assertRaises(D.ToolError):
                D.pick_backup(bdir, e.old)          # 역할 목록 짝이 없다
            os.remove(e.globals)
            with self.assertRaises(D.ToolError):
                D.pick_backup(bdir)
        finally:
            e.close()

    def test_역할_목록(self):
        g = D.parse_globals(GLOBALS)
        self.assertNotIn("CREATE ROLE opsloop;", g["sql"])
        self.assertIn("ALTER ROLE opsloop WITH SUPERUSER", g["sql"])
        self.assertIn("GRANT pg_read_all_data TO opsloop_backup WITH INHERIT TRUE GRANTED BY opsloop;", g["sql"])
        self.assertEqual(g["roles"]["opsloop_console"], {"login": True, "inherit": False, "superuser": False, "connlimit": 30})
        self.assertEqual(g["roles"]["opsloop_backup"]["inherit"], True)
        specs = D.login_specs(g["roles"])
        self.assertEqual([s[0] for s in specs], ["opsloop_backup", "opsloop_console", "opsloop_cti", "opsloop_detector",
                                                 "opsloop_gate", "opsloop_ingest"])
        self.assertEqual(dict((s[0], s[2]) for s in specs)["opsloop_ingest"], "opsloop-pull")
        self.assertEqual(dict((s[0], s[2]) for s in specs)["opsloop_console"], "self")
        for bad in ("ALTER ROLE opsloop_gate WITH LOGIN PASSWORD 'SCRAM-SHA-256$4096:x';",
                    "CREATE TABLESPACE t LOCATION '/x';", "CREATE ROLE postgres;",
                    "GRANT pg_read_all_data TO nobody;"):
            with self.assertRaises(ValueError):
                D.parse_globals(GLOBALS + bad + "\n")
        with self.assertRaises(ValueError):
            D.parse_globals(GLOBALS.replace("CREATE ROLE opsloop_ingest;\n", "").replace(
                "ALTER ROLE opsloop_ingest WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS"
                " CONNECTION LIMIT 5;\n", ""))

    def test_목차(self):
        t = datetime(2026, 9, 26, 7, 27, 40, tzinfo=UTC)
        toc = D.parse_toc(toc_text(t))
        self.assertEqual(sorted(toc["tables"]), sorted(Q.TABLES))
        self.assertEqual((toc["counts"]["TABLE"], toc["counts"]["TABLE DATA"], toc["counts"]["FK CONSTRAINT"],
                          toc["counts"]["SEQUENCE"], toc["counts"]["SEQUENCE SET"], toc["counts"]["FUNCTION"],
                          toc["counts"]["TRIGGER"], toc["counts"]["VIEW"]), (23, 23, 15, 7, 7, 7, 4, 3))
        self.assertEqual(toc["archive_created"], {"at": "2026-09-26 07:27:40", "tz": "UTC"})

    def test_지문_차이(self):
        tb = datetime(2026, 9, 26, 19, 30, 6, tzinfo=UTC)
        tf = tb + timedelta(hours=7)
        drill = D.parse_fingerprints("f|verdicts|1|aa|%s\nf|verdicts|2|bb|%s\nf|blocklist|10.0.0.1|cc|%s\n"
                                     "f|audit|h1|dd|%s\n" % (pgts(tb), pgts(tb), pgts(tb), pgts(tb)))
        prod = D.parse_fingerprints("f|verdicts|1|aa|%s\nf|verdicts|2|bb|%s\nf|verdicts|3|ee|%s\nf|verdicts|4|ff|%s\n"
                                    "f|blocklist|10.0.0.1|c2|%s\nf|audit|h1|dd|%s\nf|audit|a/b|dx|%s\n"
                                    % (pgts(tb), pgts(tb), pgts(tb + timedelta(hours=1)), pgts(tf + timedelta(minutes=5)),
                                       pgts(tb + timedelta(hours=2)), pgts(tb), pgts(tb + timedelta(minutes=1))))
        self.assertIn("a/b", prod["audit"])
        d = D.diff_fingerprints(drill, prod, tf)
        self.assertEqual((d["verdicts"]["prod_only"], d["verdicts"]["until_tf"], d["verdicts"]["after_tf"], d["verdicts"]["ok"]),
                         (2, 1, 1, True))
        self.assertEqual((d["blocklist"]["changed"], d["blocklist"]["until_tf"], d["blocklist"]["ok"]), (1, 1, True))
        self.assertEqual((d["audit"]["prod_only"], d["audit"]["ok"]), (1, True))
        # 추가만 되는 기록이 바뀌거나 사라지면 불합격
        prod["verdicts"]["1"] = ["zz", pgts(tb)]
        del prod["audit"]["h1"]
        d = D.diff_fingerprints(drill, prod, tf)
        self.assertEqual((d["verdicts"]["changed"], d["verdicts"]["ok"]), (1, False))
        self.assertEqual((d["audit"]["drill_only"], d["audit"]["ok"]), (1, False))

    def test_재생성_대조(self):
        r = D.regen_compare(regen_text(), regen_text())
        self.assertTrue(r["match"])
        other = regen_text().replace("e|gateway|900|", "e|gateway|899|")
        r = D.regen_compare(regen_text(), other)
        self.assertFalse(r["match"])
        self.assertFalse(r["sensors"]["gateway"]["same"])
        self.assertTrue(r["sensors"]["cowrie"]["same"])
        r = D.regen_compare(regen_text(), regen_text().replace("i|4|", "i|5|"))
        self.assertTrue(r["match"])                      # 사건 키는 참고로만
        self.assertFalse(r["incidents_ref"]["same"])

    def test_역할_판정(self):
        checks = D.role_checks()
        self.assertGreater(len(checks), 50)
        self.assertTrue(any(c["kind"] == "p" for c in checks))
        out = []
        for c in checks:
            if c["kind"] == "p":
                out.append("P %d %s" % (c["idx"], c["expect"]))
            else:
                out.append("R %d %s" % (c["idx"], "00000" if c["expect"] == "허용" else "42501"))
        rows = D.judge_role_output(checks, ["\n".join(out)])
        self.assertTrue(all(r["ok"] for r in rows))
        first = checks[0]
        out[0] = "R %d 42P01" % first["idx"]
        rows = D.judge_role_output(checks, ["\n".join(out)])
        self.assertEqual(rows[0]["got"], "오류(42P01)")
        self.assertFalse(rows[0]["ok"])
        sql = Q.q_role_checks("opsloop_console", [c for c in checks if c["role"] == "opsloop_console" and c["kind"] == "q"])
        self.assertTrue(sql.startswith("\\set ON_ERROR_STOP off"))
        self.assertEqual(sql.count("BEGIN;"), sql.count("ROLLBACK;"))

    def test_운영_SQL_은_읽기만(self):
        for body in (Q.q_counts(Q.TABLES), Q.Q_CATALOG, Q.Q_BASELINE, Q.Q_PROD_STATE, Q.Q_T0, Q.q_fingerprint(),
                     Q.q_loss("a", "b", "c"), Q.q_regen("a", "b"), Q.q_hashes("web-01", "a", "b")):
            Q.assert_read_only(body)
        for bad in ("UPDATE notify_channels SET enabled = false", "SELECT 1; DELETE FROM events",
                    "SELECT * FROM verdicts FOR UPDATE", "SELECT setval('x', 1)", "SELECT 1 INTO t",
                    "SET default_transaction_read_only = off", "SELECT 1 \\gexec", Q.Q_SEQUENCES, Q.Q_NOTIFY_OFF):
            with self.assertRaises(Q.SqlError):
                Q.assert_read_only(bad)
        self.assertTrue(Q.prod_sql(Q.Q_T0).startswith(Q.PROD_HEAD))
        self.assertTrue(Q.drill_sql("SELECT 1;").startswith(Q.DRILL_HEAD))
        with self.assertRaises(Q.SqlError):
            Q.q_counts(["events; DROP TABLE x"])
        with self.assertRaises(Q.SqlError):
            Q.q_hashes("web-01' OR '1", "a", "b")

    def test_가림(self):
        text = ("DATABASE_URL=postgresql://opsloop_console:%s@host:5433/opsloop ALTER ROLE x PASSWORD 'abc'; "
                "SESSION_SECRET=%s https://example.webhook.office.com/abc postgresql://u:p@h/db" % (CANARY_PW, "ab" * 32))
        m = D.mask(text, ["zzz"])
        self.assertNotIn(CANARY_PW, m)
        self.assertNotIn("'abc'", m)
        self.assertNotIn("ab" * 32, m)
        self.assertNotIn("webhook.office.com", m)
        self.assertNotIn(":p@", m)
        self.assertEqual(D.find_secrets(m), [])
        self.assertEqual(sorted(set(D.find_secrets(text))), ["dsn", "env", "password", "webhook"])
        self.assertEqual(D.find_secrets("https://notify.invalid/"), [])

    def test_systemctl_show_읽기(self):
        # 실제 data01 출력 차례: Result · ExecMainExitTimestamp · ExecMainStatus · Id, 단위 사이 빈 줄
        text = ("unit Result=success\nunit ExecMainExitTimestamp=Sun 2026-09-27 00:48:32 KST\nunit ExecMainStatus=0\n"
                "unit Id=opsloop-ingest.service\nunit \nunit Result=exit-code\nunit ExecMainStatus=10\n"
                "unit Id=opsloop-agents.service\n")
        u = D.parse_units(text)
        self.assertEqual(u["opsloop-ingest.service"]["Result"], "success")
        self.assertEqual(u["opsloop-agents.service"], {"Result": "exit-code", "ExecMainStatus": "10"})

    def test_운영_작업_창(self):
        k = lambda h, m: datetime(2026, 9, 27, h, m, tzinfo=D.KST)
        self.assertIsNone(D.busy_window(k(10, 0)))
        self.assertIn("04:30", D.busy_window(k(4, 30)))
        self.assertIn("CTI", D.busy_window(k(0, 11)))
        self.assertIn("16:30", D.busy_window(datetime(2026, 9, 27, 7, 35, tzinfo=UTC)))
        self.assertIsNone(D.busy_window(k(4, 41)))

    def test_콘솔_컨테이너_인자(self):
        argv = D.console_run_argv("/x/console.env", ["uvicorn", "main:app"])
        self.assertEqual(argv[-2:], ["uvicorn", "main:app"])
        self.assertIn("127.0.0.1:18000:8000", argv)
        self.assertIn("/x/console.env:/run/opsloop-drill/console.env:ro", argv)
        self.assertNotIn("--env-file", argv)
        self.assertFalse([a for a in argv if a.startswith(("DATABASE_URL", "SESSION_SECRET"))])
        self.assertEqual(D.tunnel_argv()[-3:], ["-L", "127.0.0.1:15433:127.0.0.1:5433", "data01"])

    def test_시각_읽기(self):
        self.assertEqual(D.parse_pg_ts("2026-09-26 07:27:40.5+00"), datetime(2026, 9, 26, 7, 27, 40, 500000, tzinfo=UTC))
        self.assertEqual(D.parse_pg_ts("2026-09-26T16:27:40+09:00"), datetime(2026, 9, 26, 7, 27, 40, tzinfo=UTC))
        self.assertEqual(D.parse_pg_ts("2026-09-26 07:27:40"), datetime(2026, 9, 26, 7, 27, 40, tzinfo=UTC))
        self.assertIsNone(D.parse_pg_ts("-"))
        self.assertEqual(D.chrony_offset("System time     : 0.000061080 seconds slow of NTP time"), -0.00006108)
        self.assertEqual(D.time_v("Maximum resident set size (kbytes): 12\nElapsed (wall clock) time (h:mm:ss or m:ss): 1:02:03.5"),
                         {"max_rss_kb": 12, "elapsed_s": 3723.5})


class Syntax(unittest.TestCase):
    SPECS = [("opsloop_ingest", "ingest", "opsloop-pull"), ("opsloop_console", "console", "self")]

    def scripts(self):
        return [D.script_precheck(), D.script_up(), D.script_passwords(self.SPECS), D.script_roles_check(self.SPECS),
                D.script_restore(), D.script_regen_check(), D.script_regen_full(),
                D.script_regen_loki("2026-09-26T18:30:06Z"), D.script_catchup(), D.script_hosts(), D.script_cleanup()]

    def test_원격_스크립트_bash_n(self):
        for s in self.scripts():
            p = subprocess.run([BASH, "-n"], input=s.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(p.returncode, 0, (s[:60], p.stderr.decode()))
            self.assertNotIn("@@", s)

    def test_안에_든_파이썬(self):
        compile(D.fill(D.PY_DSN_CHECK, PORT=5433), "dsn", "exec")
        compile(D.fill(D.PY_ENV_CHECK, BIND="127.0.0.1", PORT=5433, CLUSTER="opsloop-drill"), "env", "exec")

    def test_재적재_시각_인자(self):
        with self.assertRaises(D.ToolError):
            D.script_regen_loki("2026-09-26T18:30:06Z'; rm -rf /")

    def test_재적재_환경은_기본_파일_뒤에_훈련_값이_이긴다(self):
        # 기본 파일에 운영 값(OPSLOOP_HOME · OPSLOOP_DB_ENV · OPSLOOP_DETECTOR_ENV · HOME)이 있어도 훈련 값이 이긴다.
        # 문자열 순서가 아니라 실제 env 가 받는 값을 본다 (가짜 sudo 는 -n -u 사용자를 떼고 그대로 돌린다)
        tmp = tempfile.mkdtemp(prefix="drill45env-")
        try:
            defaults = os.path.join(tmp, "defaults")
            with open(defaults, "w") as f:
                f.write("OPSLOOP_BUCKET=b\nOPSLOOP_HOSTS=h1,h2\nOPSLOOP_HOME=/var/lib/opsloop\nAWS_DEFAULT_REGION=ap-northeast-2\n"
                        "OPSLOOP_DB_ENV=/etc/opsloop/collector.env\nOPSLOOP_DETECTOR_ENV=/etc/opsloop/detector.env\n"
                        "HOME=/var/lib/opsloop\n")
            b = os.path.join(tmp, "bin")
            os.makedirs(b)
            with open(os.path.join(b, "sudo"), "w") as f:
                f.write('#!/bin/sh\n[ "$1" = -n ] && shift\n[ "$1" = -u ] && shift 2\nexec "$@"\n')
            os.chmod(os.path.join(b, "sudo"), 0o755)
            script = (D.fill(D.SH_PULL_ENV, PULL="nobody", DEFAULTS=defaults, HOME=D.DRILL_HOME, ENV=D.DRILL_ENV)
                      + '"${RUN[@]}" /usr/bin/env\n')
            p = subprocess.run([BASH, "-c", script], env={"PATH": b + os.pathsep + "/usr/bin:/bin"},
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(p.returncode, 0, p.stderr.decode())
            got = dict(x.split("=", 1) for x in p.stdout.decode().splitlines() if "=" in x)
            self.assertEqual((got["OPSLOOP_HOME"], got["HOME"]), (D.DRILL_HOME, D.DRILL_HOME))
            self.assertEqual(got["OPSLOOP_DB_ENV"], D.DRILL_ENV + "/ingest.env")
            self.assertEqual(got["OPSLOOP_DETECTOR_ENV"], D.DRILL_ENV + "/detector.env")
            self.assertEqual((got["OPSLOOP_BUCKET"], got["OPSLOOP_HOSTS"]), ("b", "h1,h2"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_재적재_환경_검사는_운영을_가리키면_멈춘다(self):
        # regen 이 적재 · 탐지를 돌리기 전에 opsloop-pull 로 같은 환경에서 도는 검사(PY_ENV_CHECK). 가짜 psycopg2 로 돌린다
        tmp = tempfile.mkdtemp(prefix="drill45chk-")
        try:
            with open(os.path.join(tmp, "psycopg2.py"), "w") as f:
                f.write("import os\n"
                        "class _C:\n"
                        "    def __init__(self, url): self.url = url\n"
                        "    def cursor(self): return self\n"
                        "    def execute(self, q): pass\n"
                        "    def fetchone(self): return (self.url.split('://')[1].split(':')[0],"
                        " os.environ.get('FAKE_CLUSTER', 'opsloop-drill'))\n"
                        "    def close(self): pass\n"
                        "def connect(url, connect_timeout=None): return _C(url)\n")
            envd, home = os.path.join(tmp, "env"), os.path.join(tmp, "home")
            os.makedirs(envd)
            pw = "ab" * 24

            def put(name, host):
                with open(os.path.join(envd, name), "w") as f:
                    f.write("DATABASE_URL=postgresql://opsloop_x:%s@%s/opsloop\n" % (pw, host))
            put("ingest.env", "127.0.0.1:5433")
            put("detector.env", "127.0.0.1:5433")
            code = D.fill(D.PY_ENV_CHECK, BIND="127.0.0.1", PORT=5433, CLUSTER="opsloop-drill")
            base = {"PATH": "/usr/bin:/bin", "PYTHONPATH": tmp, "OPSLOOP_HOME": home, "HOME": home,
                    "OPSLOOP_DB_ENV": envd + "/ingest.env", "OPSLOOP_DETECTOR_ENV": envd + "/detector.env"}

            def check(**over):
                env = dict(base)
                for k, v in over.items():
                    if v is None:
                        env.pop(k, None)
                    else:
                        env[k] = v
                p = subprocess.run([PY, "-c", code, home, envd], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out = p.stdout.decode() + p.stderr.decode()
                self.assertNotIn(pw, out)
                return p.returncode, out
            rc, out = check()
            self.assertEqual((rc, out.strip().splitlines()[-1]), (0, "ok"), out)
            for over in ({"OPSLOOP_HOME": "/var/lib/opsloop"}, {"HOME": "/var/lib/opsloop"},
                         {"DATABASE_URL": "postgresql://opsloop_ingest:x@192.168.60.11:5432/opsloop"},
                         {"OPSLOOP_DETECTOR_ENV": "/etc/opsloop/detector.env"}, {"OPSLOOP_DB_ENV": None},
                         {"FAKE_CLUSTER": ""}):
                rc, out = check(**over)
                self.assertEqual(rc, 1, (over, out))
                self.assertIn("bad ", out)
            put("detector.env", "192.168.60.11:5432")
            rc, out = check()
            self.assertEqual(rc, 1, out)
            self.assertIn("OPSLOOP_DETECTOR_ENV 대상", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_파이썬_39_문법(self):
        py39 = "/usr/bin/python3"
        if not os.path.exists(py39):
            self.skipTest("/usr/bin/python3 없음")
        v = subprocess.run([py39, "-c", "import sys; print(sys.version_info[:2] >= (3, 9))"], stdout=subprocess.PIPE)
        if v.stdout.strip() != b"True":
            self.skipTest("3.9 아님")
        for f in ("drill.py", "queries.py", "test_restore_drill.py"):
            src = open(os.path.join(HERE, f), encoding="utf-8").read()
            p = subprocess.run([py39, "-c", "import ast, sys; ast.parse(sys.stdin.read())"], input=src.encode(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(p.returncode, 0, (f, p.stderr.decode()[-300:]))

    def test_표준_라이브러리만(self):
        import ast
        allowed = {"argparse", "hashlib", "json", "os", "re", "secrets", "shlex", "shutil", "subprocess", "sys", "tempfile",
                   "time", "datetime", "common", "mark", "queries"}
        for f in ("drill.py", "queries.py"):
            tree = ast.parse(open(os.path.join(HERE, f), encoding="utf-8").read())
            mods = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    mods.add((node.module or "").split(".")[0])
            self.assertLessEqual(mods, allowed, f)



class ConsoleAfterParseTest(unittest.TestCase):
    """판정 반영 확인: 사건 키 안의 '|' 때문에 상태 칸을 잘못 읽지 않는다 (2026-09-27 첫 훈련에서 드러남)."""

    def test_키에_세로줄이_있어도_상태를_읽는다(self):
        text = "w|895|R003|v3|4.4.66.84|2026-09-04T16:50:24.170898+00:00|undetermined|restore-drill|resolved\n"
        (row,) = D.parse_console_after(text)
        self.assertEqual(row["key"], "R003|v3|4.4.66.84|2026-09-04T16:50:24.170898+00:00")
        self.assertEqual((row["id"], row["verdict"], row["operator"], row["status"]),
                         ("895", "undetermined", "restore-drill", "resolved"))

    def test_세로줄_없는_키와_모자란_줄(self):
        rows = D.parse_console_after("w|1|k1|threat|han|open\nw|2|x\n")
        self.assertEqual([(r["key"], r["status"]) for r in rows], [("k1", "open")])

if __name__ == "__main__":
    unittest.main(verbosity=2)
