#!/usr/bin/env python3
"""노드 관리 CLI(nodes.py) 단위 시험. DB 없이 가짜 커서로 본다.  python3 collector/test_nodes.py

인자가 틀리면 DB 에 닿기 전에 64 로 끝나는지, 토큰이 표준 출력 한 줄로만 나오고 DB · 원장에는
원문이 가지 않는지, 관리 원장 줄 모양, check 의 종료 코드(처음 실패한 단계)와 --kick 을 본다.
SQL 자체(enroll_node · node_first_receipt)는 PostgreSQL 에서 따로 확인한다.
"""
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

# psycopg2 가 없는 곳에서도 돌게 가짜를 넣는다 (접속은 시험마다 가짜 연결로 바꾼다)
if "psycopg2" not in sys.modules:
    fake = types.ModuleType("psycopg2")

    class Error(Exception):
        pass

    def _no_connect(*a, **k):
        raise Error("가짜 psycopg2 는 접속하지 않는다")

    fake.Error, fake.connect = Error, _no_connect
    sys.modules["psycopg2"] = fake

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nodes  # noqa: E402

PGError = sys.modules["psycopg2"].Error
TOKEN_RE = re.compile(r"olE_[A-Za-z0-9_-]{43}")
EXP = datetime(2026, 9, 21, 8, 0, tzinfo=timezone.utc)


class FakeDB:
    """SQL 을 받아 적고, 정해 둔 응답(행 목록 · rowcount)을 돌려준다.

    answers: [(SQL 에 든 문자열, 행 목록 또는 예외, rowcount)]. 앞에서부터 처음 맞는 것을 쓰고,
    같은 문자열에 응답이 여럿이면 차례로 소비한다 (마지막 것은 남겨 계속 쓴다).
    """

    def __init__(self, answers=()):
        self.answers = [list(a) for a in answers]
        self.log, self.commits, self.rollbacks, self.closed, self.conns = [], 0, 0, 0, []

    def answer(self, sql):
        for i, (key, rows, rc) in enumerate(self.answers):
            if key in sql:
                if len([a for a in self.answers if a[0] == key]) > 1:
                    self.answers.pop(i)
                return rows, rc
        return [], 0


class FakeCursor:
    def __init__(self, db):
        self.db, self.rows, self.rowcount = db, [], -1

    def execute(self, sql, params=None):
        sql = " ".join(sql.split())
        self.db.log.append((sql, params))
        rows, self.rowcount = self.db.answer(sql)
        if isinstance(rows, BaseException):
            raise rows
        self.rows = list(rows)

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        rows, self.rows = self.rows, []
        return rows


class FakeConn:
    def __init__(self, db, autocommit):
        self.db, self.autocommit = db, autocommit
        db.conns.append(self)

    def cursor(self):
        return FakeCursor(self.db)

    def commit(self):
        self.db.commits += 1

    def rollback(self):
        self.db.rollbacks += 1

    def close(self):
        self.db.closed += 1


class Base(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t, True)
        env = {"OPSLOOP_ADMIN_DIR": self.t, "SUDO_USER": "tester", "USER": "root"}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("DATABASE_URL", None)
        os.environ.pop("JOURNAL_STREAM", None)
        self.db = FakeDB()
        self.connects = 0
        self.systemctl_calls = []
        self.systemctl_ok = True

        def fake_connect(autocommit=False):
            self.connects += 1
            if isinstance(self.connect_error, BaseException):
                err, self.connect_error = self.connect_error, None
                raise err
            return FakeConn(self.db, autocommit)

        def fake_systemctl(args):
            self.systemctl_calls.append(list(args))
            return self.systemctl_ok

        self.connect_error = None
        for name, val in (("connect", fake_connect), ("systemctl", fake_systemctl)):
            p = mock.patch.object(nodes, name, val)
            p.start()
            self.addCleanup(p.stop)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = nodes.main(list(argv))
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def ledger_lines(self):
        path = os.path.join(self.t, f"admin-{datetime.now(timezone.utc):%Y-%m-%d}.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def sql(self, key):
        return [(s, p) for s, p in self.db.log if key in s]


ISSUE = ("issue", "web-01", "--host", "opsloop-web-01", "--addr", "192.168.50.21", "--logs", "nginx,auth,metrics")


class IssueTest(Base):
    def setUp(self):
        super().setUp()
        self.db = FakeDB([("INSERT INTO nodes", [("pending",)], 1),
                          ("UPDATE node_enrollments", [], 0),
                          ("INSERT INTO node_enrollments", [(EXP,)], 1)])

    def test_토큰은_표준_출력에_한_줄만(self):
        rc, out, _ = self.run_cli(*ISSUE)
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], TOKEN_RE)
        self.assertTrue(out.endswith("\n"))

    def test_표준_출력이_터미널이면_발급하지_않는다(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        out, err = Tty(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = nodes.main(list(ISSUE))
        self.assertEqual(rc, nodes.EXIT_USAGE)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(self.connects, 0)                  # DB 도 바꾸지 않는다
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = nodes.main(list(ISSUE) + ["--allow-tty"])
        self.assertEqual(rc, 0)
        self.assertRegex(out.getvalue().strip(), TOKEN_RE)

    def test_원장에_못_쓰면_3_토큰은_나온다(self):
        os.environ["OPSLOOP_ADMIN_DIR"] = os.path.join(self.t, "없음")
        rc, out, _ = self.run_cli(*ISSUE)
        self.assertEqual(rc, nodes.EXIT_LEDGER)
        self.assertRegex(out.strip(), TOKEN_RE)

    def test_DB_에는_해시만_간다(self):
        _, out, err = self.run_cli(*ISSUE)
        token = out.strip()
        [(_, prm)] = self.sql("INSERT INTO node_enrollments")
        self.assertEqual(prm, ("web-01", hashlib.sha256(token.encode()).hexdigest(), "tester", 3600))
        for _sql, p in self.db.log:
            self.assertNotIn(token, repr(p))
        self.assertNotIn(token, err)
        self.assertEqual(self.db.commits, 1)

    def test_새_행은_pending_이고_선언한_로그가_들어간다(self):
        self.run_cli(*ISSUE)
        [(sql, prm)] = self.sql("INSERT INTO nodes")
        self.assertIn("'pending'", sql)
        self.assertIn("ON CONFLICT (node_id) DO NOTHING", sql)
        self.assertEqual(prm, ("web-01", "opsloop-web-01", "web-01", "192.168.50.21", ["nginx", "auth", "metrics"]))
        self.assertEqual(self.sql("UPDATE nodes SET"), [])

    def test_이전_미사용_토큰은_새_토큰보다_먼저_취소(self):
        self.run_cli(*ISSUE)
        order = [s.split(" (")[0].split(" SET")[0] for s, _ in self.db.log]
        self.assertEqual(order, ["INSERT INTO nodes", "UPDATE node_enrollments", "INSERT INTO node_enrollments"])
        [(sql, prm)] = self.sql("UPDATE node_enrollments")
        self.assertIn("used_at IS NULL AND canceled_at IS NULL", sql)
        self.assertEqual(prm, ("web-01",))

    def test_기존_노드는_상태를_두고_호스트_주소_로그만_고친다(self):
        self.db = FakeDB([("INSERT INTO nodes", [], 0),
                          ("SELECT status, host(addr)", [("active", "192.168.50.20")], 1),
                          ("UPDATE node_enrollments", [], 1),
                          ("INSERT INTO node_enrollments", [(EXP,)], 1)])
        rc, out, err = self.run_cli(*ISSUE)
        self.assertEqual(rc, 0)
        self.assertRegex(out.strip(), TOKEN_RE)
        [(sql, prm)] = self.sql("UPDATE nodes SET")
        self.assertNotIn("status", sql)
        self.assertEqual(prm, ("opsloop-web-01", "192.168.50.21", ["nginx", "auth", "metrics"], "web-01"))
        self.assertIn("FOR UPDATE", self.sql("SELECT status, host(addr)")[0][0])
        self.assertIn("192.168.50.20 → 192.168.50.21", err)
        self.assertIn("1개를 취소", err)

    def test_관리_원장에는_토큰도_해시도_없다(self):
        _, out, _ = self.run_cli(*ISSUE)
        token = out.strip()
        [rec] = self.ledger_lines()
        self.assertEqual(set(rec), {"ts", "eventid", "node_id", "issued_by", "expires_at", "host", "addr", "logs"})
        self.assertEqual((rec["host"], rec["addr"], rec["logs"]),
                         ("opsloop-web-01", "192.168.50.21", ["nginx", "auth", "metrics"]))
        self.assertEqual(rec["eventid"], "collector.admin.issue")
        self.assertEqual((rec["node_id"], rec["issued_by"]), ("web-01", "tester"))
        self.assertEqual(rec["expires_at"], EXP.isoformat())
        self.assertRegex(rec["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}\+00:00$")
        with open(os.path.join(self.t, os.listdir(self.t)[0]), encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn(token, raw)
        self.assertNotIn(hashlib.sha256(token.encode()).hexdigest(), raw)
        mode = os.stat(os.path.join(self.t, os.listdir(self.t)[0])).st_mode & 0o777
        self.assertEqual(mode, 0o640)

    def test_SUDO_USER_가_없으면_USER(self):
        os.environ.pop("SUDO_USER")
        self.run_cli(*ISSUE)
        self.assertEqual(self.ledger_lines()[0]["issued_by"], "root")

    def test_관문_HUP_이_실패해도_토큰은_나온다(self):
        self.systemctl_ok = False
        rc, out, err = self.run_cli(*ISSUE)
        self.assertEqual(rc, 0)
        self.assertRegex(out.strip(), TOKEN_RE)
        self.assertEqual(self.systemctl_calls, [["kill", "-s", "HUP", "opsloop-gate"]])
        self.assertIn("HUP", err)

    def test_기간을_주면_그대로_넘긴다(self):
        self.run_cli(*ISSUE, "--ttl", "600")
        self.assertEqual(self.sql("INSERT INTO node_enrollments")[0][1][3], 600)

    def test_토큰은_매번_다르다(self):
        a = self.run_cli(*ISSUE)[1]
        self.db.answers.append(["INSERT INTO node_enrollments", [(EXP,)], 1])
        b = self.run_cli(*ISSUE)[1]
        self.assertNotEqual(a, b)

    def test_DB_오류면_토큰도_원장도_없고_1(self):
        self.db = FakeDB([("INSERT INTO nodes", [("pending",)], 1),
                          ("INSERT INTO node_enrollments", PGError("unique"), 0)])
        rc, out, err = self.run_cli(*ISSUE)
        self.assertEqual((rc, out), (1, ""))
        self.assertEqual((self.db.commits, self.db.rollbacks, self.db.closed), (0, 1, 1))
        self.assertEqual(self.ledger_lines(), [])
        self.assertEqual(self.systemctl_calls, [])
        self.assertIn("DB 오류", err)

    def test_접속_실패도_1(self):
        self.connect_error = PGError("could not connect")
        rc, out, _ = self.run_cli(*ISSUE)
        self.assertEqual((rc, out), (1, ""))


class ArgsTest(Base):
    def assertUsage(self, *argv):
        rc, out, err = self.run_cli(*argv)
        self.assertEqual(rc, 64, argv)
        self.assertEqual(out, "")
        self.assertIn("인자 오류", err)
        self.assertEqual(self.connects, 0)

    def issue(self, **kw):
        a = {"node": "web-01", "--host": "opsloop-web-01", "--addr": "192.168.50.21", "--logs": "nginx"}
        a.update(kw)
        argv = ["issue", a.pop("node")]
        for k, v in a.items():
            argv += [k, v]
        return argv

    def test_노드_이름(self):
        for bad in ("Web-01", "web_01", "-web", "", "a" * 64, "web 01", "web-01\n",
                    "cowrie", "decoy", "gateway", "console", "collector", "puller"):
            self.assertUsage(*self.issue(node=bad))
        self.assertUsage("revoke", "cowrie")
        self.assertUsage("check", "collector", "--nonce", "x")

    def test_주소는_주소_하나(self):
        for bad in ("192.168.50.0/24", "web01", "192.168.50.256", "0.0.0.0", "::", "224.0.0.1", ""):
            self.assertUsage(*self.issue(**{"--addr": bad}))

    def test_호스트_이름(self):
        for bad in ("", "-web", "web_01", "web 01", "a/b", "web.", "x" * 254):
            self.assertUsage(*self.issue(**{"--host": bad}))

    def test_로그는_세_가지_중에서(self):
        for bad in ("", ",", "nginx,syslog", "NGINX", "nginx,,auth"):
            self.assertUsage(*self.issue(**{"--logs": bad}))

    def test_로그_중복은_한_번만_순서는_그대로(self):
        self.db = FakeDB([("INSERT INTO nodes", [("pending",)], 1), ("INSERT INTO node_enrollments", [(EXP,)], 1)])
        rc, _, _ = self.run_cli(*self.issue(**{"--logs": "auth, nginx,auth"}))
        self.assertEqual(rc, 0)
        self.assertEqual(self.sql("INSERT INTO nodes")[0][1][4], ["auth", "nginx"])

    def test_기간_범위(self):
        for bad in ("59", "86401", "abc", "-1", "1e3"):
            self.assertUsage(*self.issue(**{"--ttl": bad}))

    def test_필수_인자와_명령(self):
        self.assertUsage()
        self.assertUsage("issue", "web-01", "--host", "h", "--addr", "192.168.50.21")
        self.assertUsage("check", "web-01")
        self.assertUsage("nope")

    def test_nonce_와_기다림(self):
        for bad in ("", "a b", "../x", "a%b", "x" * 129):
            self.assertUsage("check", "web-01", "--nonce", bad)
        for bad in ("-1", "3601", "x"):
            self.assertUsage("check", "web-01", "--nonce", "n1", "--wait", bad)

    def test_IPv6_주소는_정규형으로(self):
        self.assertEqual(nodes.arg_addr("FD00:0:0::1"), "fd00::1")


def rows(*oks, details=None):
    names = ("등록", "첫 로그", "형식 변환", "규칙 적용")
    details = details or {}
    return [(i + 1, names[i], ok, details.get(i + 1, "대기" if ok is None else "d")) for i, ok in enumerate(oks)]


class Clock:
    def __init__(self):
        self.t, self.sleeps = 1000.0, []

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


class CheckTest(Base):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        for name in ("monotonic", "sleep"):
            p = mock.patch.object(nodes.time, name, getattr(self.clock, name))
            p.start()
            self.addCleanup(p.stop)

    def check(self, *extra):
        return self.run_cli("check", "web-01", "--nonce", "n-1", *extra)

    def answer(self, *results):
        self.db = FakeDB([("node_first_receipt", r, len(r) if isinstance(r, list) else 0) for r in results])

    def test_모두_통과면_0_이고_네_줄(self):
        self.answer(rows(True, True, True, True))
        rc, out, _ = self.check()
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.splitlines()), 4)
        [(sql, prm)] = self.sql("node_first_receipt")
        self.assertEqual(prm, ("web-01", "n-1"))
        self.assertTrue(self.db.conns[0].autocommit)

    def test_종료_코드는_처음_실패한_단계(self):
        for oks, code in (((False, None, None, None), 1), ((True, False, None, None), 2),
                          ((True, True, False, None), 3), ((True, True, True, False), 4)):
            self.answer(rows(*oks))
            self.assertEqual(self.check()[0], code, oks)
        self.assertEqual(self.systemctl_calls, [])

    def test_결과가_없으면_1(self):
        self.answer([])
        self.assertEqual(self.check()[0], 1)

    def test_기다리며_5초마다_보고_kick_은_3단계_통과_뒤_한_번(self):
        self.answer(rows(True, True, False, None), rows(True, True, True, False),
                    rows(True, True, True, False), rows(True, True, True, True))
        rc, out, err = self.check("--wait", "600", "--kick")
        self.assertEqual(rc, 0)
        self.assertEqual(self.clock.sleeps, [5, 5, 5])
        self.assertEqual(self.systemctl_calls, [["start", "--no-block", "opsloop-agents.service"]])
        self.assertIn("통과", out)
        self.assertEqual(err.count("[ "), 3)       # 바뀐 때만 알린다 (3단계 실패 · 4단계 실패 · 통과)

    def test_기다림이_끝나면_마지막_실패_단계(self):
        self.answer(rows(True, False, None, None, details={2: "아직 줄이 없는 로그: metrics"}))
        rc, out, err = self.check("--wait", "12", "--kick")
        self.assertEqual(rc, 2)
        self.assertEqual(self.clock.sleeps, [5, 5, 2])
        self.assertEqual(self.systemctl_calls, [])
        self.assertIn("metrics", err)
        self.assertEqual(len(out.splitlines()), 4)

    def test_kick_없이는_당기지_않는다(self):
        self.answer(rows(True, True, True, False))
        self.assertEqual(self.check("--wait", "10")[0], 4)
        self.assertEqual(self.systemctl_calls, [])

    def test_DB_접속_실패면_5(self):
        self.connect_error = PGError("could not connect")
        rc, out, err = self.check()
        self.assertEqual((rc, out), (5, ""))
        self.assertIn("could not connect", err)

    def test_잠깐_끊긴_DB_는_다시_붙는다(self):
        self.connect_error = PGError("could not connect")
        self.answer(rows(True, True, True, True))
        rc, _, _ = self.check("--wait", "30")
        self.assertEqual(rc, 0)
        self.assertEqual(self.connects, 2)

    def test_조회_중_오류도_5(self):
        self.answer(PGError("function node_first_receipt does not exist"))
        rc, _, err = self.check()
        self.assertEqual(rc, 5)
        self.assertIn("does not exist", err)


class RevokeCancelTest(Base):
    def test_폐기는_상태만_바꾸고_해시는_남긴다(self):
        self.db = FakeDB([("UPDATE nodes SET status = 'revoked'", [("3f9a1c0e",)], 1),
                          ("UPDATE node_enrollments", [], 2)])
        rc, out, err = self.run_cli("revoke", "web-01")
        self.assertEqual((rc, out), (0, ""))
        order = [s for s, _ in self.db.log]
        self.assertTrue(order[0].startswith("UPDATE nodes SET status = 'revoked'"))   # nodes 먼저 잠근다
        self.assertTrue(order[1].startswith("UPDATE node_enrollments"))
        self.assertNotIn("token_hash", " ".join(order))
        self.assertEqual(self.systemctl_calls, [["kill", "-s", "HUP", "opsloop-gate"]])
        [rec] = self.ledger_lines()
        self.assertEqual((rec["eventid"], rec["node_id"], rec["issued_by"], rec["status"], rec["agent_fp"],
                          rec["canceled"]), ("collector.admin.revoke", "web-01", "tester", "revoked", "3f9a1c0e", 2))

    def test_없는_노드_폐기는_1(self):
        self.db = FakeDB([("UPDATE nodes", [], 0)])
        rc, _, err = self.run_cli("revoke", "web-09")
        self.assertEqual(rc, 1)
        self.assertEqual((self.db.commits, self.db.rollbacks), (0, 1))
        self.assertEqual((self.systemctl_calls, self.ledger_lines()), ([], []))
        self.assertIn("노드 없음", err)

    def test_취소(self):
        self.db = FakeDB([("SELECT 1 FROM nodes", [(1,)], 1), ("UPDATE node_enrollments", [], 1)])
        rc, _, err = self.run_cli("cancel", "web-01")
        self.assertEqual(rc, 0)
        self.assertIn("FOR UPDATE", self.db.log[0][0])
        self.assertEqual(self.systemctl_calls, [])
        [rec] = self.ledger_lines()
        self.assertEqual((rec["eventid"], rec["issued_by"], rec["canceled"]), ("collector.admin.cancel", "tester", 1))
        self.assertIn("1개를 취소", err)

    def test_없는_노드_취소는_1(self):
        self.db = FakeDB([("SELECT 1 FROM nodes", [], 0)])
        self.assertEqual(self.run_cli("cancel", "web-09")[0], 1)
        self.assertEqual(len(self.db.log), 1)


class ListTest(Base):
    def test_목록에는_지문만(self):
        self.db = FakeDB([("FROM nodes n", [("web-01", "active", "opsloop-web-01", "192.168.50.21",
                                             "nginx,auth,metrics", "3f9a1c0e", EXP, None, 0)], 1)])
        rc, out, _ = self.run_cli("list")
        self.assertEqual(rc, 0)
        self.assertNotIn("token_hash", self.db.log[0][0])
        self.assertIn("3f9a1c0e", out)
        self.assertIn("2026-09-21 08:00:00Z", out)
        self.assertEqual(len(out.splitlines()), 2)

    def test_제어_문자는_로그에_그대로_쓰지_않는다(self):
        self.db = FakeDB([("FROM nodes n", [("web-01", "active", "evil\nhost", None, "", None, None, None, 0)], 1)])
        _, out, _ = self.run_cli("list")
        self.assertIn("evil\\x0ahost", out)


class LedgerTest(Base):
    def test_줄을_이어_쓴다(self):
        now = datetime(2026, 9, 21, 23, 59, 59, 123456, tzinfo=timezone.utc)
        self.assertTrue(nodes.ledger("issue", {"node_id": "a"}, now=now))
        self.assertTrue(nodes.ledger("revoke", {"node_id": "a"}, now=now + timedelta(microseconds=1)))
        with open(os.path.join(self.t, "admin-2026-09-21.jsonl"), encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual([json.loads(x)["eventid"] for x in lines], ["collector.admin.issue", "collector.admin.revoke"])
        self.assertEqual(json.loads(lines[0])["ts"], "2026-09-21T23:59:59.123456+00:00")

    def test_날짜는_UTC(self):
        kst = timezone(timedelta(hours=9))
        now = datetime(2026, 9, 22, 1, 0, tzinfo=kst).astimezone(timezone.utc)
        nodes.ledger("issue", {}, now=now)
        self.assertEqual(os.listdir(self.t), ["admin-2026-09-21.jsonl"])

    def test_링크는_따라가지_않는다(self):
        victim = os.path.join(self.t, "victim")
        with open(victim, "w") as f:
            f.write("원본\n")
        now = datetime(2026, 9, 21, tzinfo=timezone.utc)
        os.symlink(victim, os.path.join(self.t, "admin-2026-09-21.jsonl"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertFalse(nodes.ledger("issue", {}, now=now))
        with open(victim, encoding="utf-8") as f:
            self.assertEqual(f.read(), "원본\n")
        self.assertIn("관리 원장", err.getvalue())

    def test_하드_링크된_파일에도_쓰지_않는다(self):
        other = os.path.join(self.t, "other")
        open(other, "w").close()
        os.link(other, os.path.join(self.t, "admin-2026-09-21.jsonl"))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(nodes.ledger("issue", {}, now=datetime(2026, 9, 21, tzinfo=timezone.utc)))
        self.assertEqual(os.path.getsize(other), 0)

    def test_폴더가_없으면_경고만(self):
        os.environ["OPSLOOP_ADMIN_DIR"] = os.path.join(self.t, "없음")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(nodes.ledger("issue", {}))


class EnvTest(unittest.TestCase):
    def test_env_파일은_셸로_읽지_않는다(self):
        fd, path = tempfile.mkstemp()
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as f:
            f.write("# 주석\nDATABASE_URL=postgresql://opsloop:p$(id)@192.168.60.11/opsloop\n\nX = 'q'\n")
        self.assertEqual(nodes.read_env(path),
                         {"DATABASE_URL": "postgresql://opsloop:p$(id)@192.168.60.11/opsloop", "X": "'q'"})
        with mock.patch.dict(os.environ, {"OPSLOOP_DB_ENV": path}):
            os.environ.pop("DATABASE_URL", None)
            self.assertEqual(nodes.database_url(), "postgresql://opsloop:p$(id)@192.168.60.11/opsloop")
            os.environ["DATABASE_URL"] = "postgresql://env"
            self.assertEqual(nodes.database_url(), "postgresql://env")

    def test_env_파일이_없으면_DB_오류(self):
        with mock.patch.dict(os.environ, {"OPSLOOP_DB_ENV": "/없는/파일"}):
            os.environ.pop("DATABASE_URL", None)
            with self.assertRaises(nodes.DBError):
                nodes.database_url()

    def test_토큰_형식(self):
        toks = {nodes.new_token() for _ in range(50)}
        self.assertEqual(len(toks), 50)
        for t in toks:
            self.assertRegex(t, TOKEN_RE)
        self.assertEqual(nodes.sha256_hex("olE_x"), hashlib.sha256(b"olE_x").hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=1)
