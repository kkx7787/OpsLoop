"""backup-db.sh 시험 (이슈 #45). 가짜 ssh 로 데이터 노드 없이 돈다.

- 덤프와 같은 시각의 역할 목록(opsloop-<시각>.globals.sql)을 비밀번호 없이 0600 으로 남긴다
- 역할이 빠졌거나 비밀번호가 섞인 역할 목록이면 실패하고 파일을 남기지 않는다
- 보관 개수(KEEP)는 덤프와 역할 목록에 똑같이 적용한다

사용: python3 infra/vmware/scripts/test_backup_db.py
"""
import os
import stat
import subprocess
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "backup-db.sh")

ROLES = """--
-- PostgreSQL database cluster dump
--
CREATE ROLE opsloop;
ALTER ROLE opsloop WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS;
CREATE ROLE opsloop_backup;
ALTER ROLE opsloop_backup WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;
CREATE ROLE opsloop_console;
CREATE ROLE opsloop_detector;
CREATE ROLE opsloop_gate;
CREATE ROLE opsloop_ingest;
GRANT pg_read_all_data TO opsloop_backup WITH INHERIT TRUE GRANTED BY opsloop;
"""

# 받은 원격 명령에 따라 답한다. 덤프 · 목차 · 역할 목록만 흉내 낸다
FAKE_SSH = r"""#!/bin/sh
for a; do cmd=$a; done
echo "$cmd" >> "$FAKE_LOG"
case "$cmd" in
  *pg_dumpall*) cat "$FAKE_ROLES" ;;
  *pg_restore\ --list*) cat >/dev/null; echo "123; 0 0 TABLE DATA public events opsloop" ;;
  *pg_dump\ *) printf 'PGDMP-fake' ;;
  *) : ;;
esac
"""


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
        ssh = os.path.join(self.bin, "ssh")
        with open(ssh, "w") as f:
            f.write(FAKE_SSH)
        os.chmod(ssh, 0o755)
        self.roles = os.path.join(root, "roles.sql")
        self.log = os.path.join(root, "ssh.log")
        self.write_roles(ROLES)

    def write_roles(self, text):
        with open(self.roles, "w") as f:
            f.write(text)

    def run_backup(self):
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], HOME=self.home, LEDGER="0",
                   FAKE_ROLES=self.roles, FAKE_LOG=self.log, KEEP="2")
        env.pop("VERIFY", None)
        return subprocess.run(["bash", SCRIPT, self.dest], env=env, capture_output=True, text=True, timeout=60)

    def files(self, suffix):
        return sorted(f for f in os.listdir(self.dest) if f.endswith(suffix) and not f.startswith("."))

    def test_역할_목록을_같은_시각으로_0600_에_남긴다(self):
        r = self.run_backup()
        self.assertEqual(r.returncode, 0, r.stderr)
        (dump,), (roles,) = self.files(".dump"), self.files(".globals.sql")
        self.assertEqual(dump[: -len(".dump")], roles[: -len(".globals.sql")])
        for name in (dump, roles):
            mode = stat.S_IMODE(os.stat(os.path.join(self.dest, name)).st_mode)
            self.assertEqual(mode, 0o600, name)
        self.assertIn("역할 6 개", r.stdout)
        with open(self.log) as f:
            cmds = f.read()
        # 비밀번호는 원격에서부터 빼고 받는다. 백업 전용 역할로 뜬다
        self.assertIn("pg_dumpall -U opsloop_backup --globals-only --no-role-passwords", cmds)
        self.assertIn("pg_dump -U opsloop_backup -Fc opsloop", cmds)
        self.assertEqual([f for f in os.listdir(self.dest) if f.endswith(".part")], [])

    def test_역할이_빠지면_실패하고_남기지_않는다(self):
        self.write_roles(ROLES.replace("CREATE ROLE opsloop_console;\n", ""))
        r = self.run_backup()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("opsloop_console", r.stderr)
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

    def test_보관_개수는_역할_목록에도_같다(self):
        os.makedirs(self.dest, exist_ok=True)
        # 옛 회차 셋을 먼저 둔다. 오래된 순서는 수정 시각으로 정해진다
        for i, ts in enumerate(("20260101-0000", "20260102-0000", "20260103-0000")):
            for suffix in (".dump", ".globals.sql"):
                path = os.path.join(self.dest, f"opsloop-{ts}{suffix}")
                with open(path, "w") as f:
                    f.write("old")
                past = time.time() - 3600 * (10 - i)
                os.utime(path, (past, past))
        r = self.run_backup()
        self.assertEqual(r.returncode, 0, r.stderr)
        # 새 회차 하나 + 가장 최근 옛 회차 하나만 남는다
        for suffix in (".dump", ".globals.sql"):
            kept = self.files(suffix)
            self.assertEqual(len(kept), 2, kept)
            self.assertIn(f"opsloop-20260103-0000{suffix}", kept)
            self.assertNotIn(f"opsloop-20260101-0000{suffix}", kept)

    def test_셸_문법(self):
        for shell in ("/bin/bash", "bash"):
            r = subprocess.run([shell, "-n", SCRIPT], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=1)
