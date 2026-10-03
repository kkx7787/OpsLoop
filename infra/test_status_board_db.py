#!/usr/bin/env python3
"""관제 대상 상태판(이슈 #52) DB 시험.  python3 infra/test_status_board_db.py

DB 없이 도는 글자 시험: 마이그레이션(infra/migrations/20260930_status_board.sql)이 schema.sql 의 '관제 대상 상태판 (이슈 #52)'
블록을 글자 그대로 담는지, 블록이 #51 블록 뒤에 있는지(그 뒤에는 #59 블록만), 표 정의가 계약(갈래 B 시험의 임시 표)과
같은지, 트리거 · 권한 줄이 계약과 같은지, verify-db-roles.sh 에 #52 줄이 있는지, 적재기 · 집행기의 기록 문장이 쓰기 규칙(못 읽은
회차는 seen_at 을 둔다)을 지키는지, 복원 훈련의 표 목록 · 구조 기대값에 새 표 · 트리거 · 함수가 들어 있는지 본다.

OPSLOOP_TEST_DATABASE_URL 이 슈퍼유저 연결이면 infra/test_block_enforce_db.py 와 같은 방식(무작위 데이터베이스 · 역할)으로
schema.sql 과 마이그레이션을 두 번씩 적용하고, 트리거가 역할별로 행 종류를 막는지, 콘솔이 읽기만 되는지, 역할 블록 · #47 을 다시
적용하면 권한이 빠지고 이 마이그레이션으로 되살아나는지, 역할 검증 스크립트의 #52 줄이 같은 답을 내는지 본다. 콘솔 DB 연결(이슈 #76 ·
#84)은 schema.sql 의 콘솔 역할로 실제 로그인해 상태판(app/targets.py targets_view)을 부른다(같은 역할의 콘솔 이름표 연결만 센다).
역할은 시험 안에서 만들고 지운다. 운영 DB · 운영 역할은 건드리지 않는다.
"""
import asyncio
import importlib.util
import os
import re
import secrets
import sys
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20260930_status_board.sql")
ROLES_SQL = os.path.join(ROOT, "infra", "migrations", "20260924_db_roles.sql")
M47 = os.path.join(ROOT, "infra", "migrations", "20260927_block_enforce.sql")
VERIFY = os.path.join(ROOT, "infra", "vmware", "scripts", "verify-db-roles.sh")
BLOCK47 = os.path.join(ROOT, "infra", "test_block_enforce_db.py")
APP = os.path.join(ROOT, "app")
A_ONLY = "DB 연결 확인: 콘솔 A 있음 · 콘솔 B 없음(평소 꺼 두는 예비)"

HEADER = "-- 관제 대상 상태판 (이슈 #52)"
HEADER51 = "-- 차단 집행 지점 · 시험 출발지 (이슈 #51)"
NEXT_HEADER = "-- 콘솔 계정 관리 (이슈 #59)"      # 이 블록 뒤에 오는 다음 블록(infra/test_console_accounts_db.py)
VERIFY_SECTION = 'echo "== 관제 대상 상태판 (이슈 #52'
# 계약서 1장의 표 정의. 갈래 B(app/test_targets_db.py)는 이 글자를 그대로 임시 표로 쓴다
DDL = """CREATE TABLE IF NOT EXISTS sensor_heartbeats (
    source     text        PRIMARY KEY,           -- 'uploader:<인스턴스 ID>' · 'block:gateway' · 'block:fw'
    kind       text        NOT NULL CHECK (kind IN ('uploader', 'block_report')),
    role       text        NOT NULL CHECK (role IN ('sensor', 'gateway', 'fw')),
    host       text        NOT NULL,              -- 인스턴스 ID(i-…) 또는 fw-<이름>
    seen_at    timestamptz,                       -- 신호 자체의 시각: 업로더 hb 의 S3 LastModified · 차단 보고의 at(검증한 값)
    checked_at timestamptz NOT NULL,              -- 기록한 쪽(적재기 · 집행기)이 마지막으로 읽어 본 시각
    problem    text                               -- 읽기 문제(없음 · 형식이 틀림 · 일시 오류 …). 정상이면 NULL
);"""
GRANTS = ["GRANT SELECT, INSERT, UPDATE ON sensor_heartbeats TO opsloop_ingest;",
          "GRANT SELECT, INSERT, UPDATE ON sensor_heartbeats TO opsloop_enforcer;",
          "GRANT SELECT ON sensor_heartbeats, node_metrics TO opsloop_console;"]
VERIFY_LINES = [
    ("q", "opsloop_ingest", "INSERT INTO sensor_heartbeats SELECT * FROM sensor_heartbeats WHERE false"
                            " ON CONFLICT (source) DO UPDATE SET seen_at = EXCLUDED.seen_at", "허용"),
    ("q", "opsloop_ingest", "DELETE FROM sensor_heartbeats WHERE false", "거부"),
    ("p", "opsloop_ingest", "has_table_privilege('opsloop_ingest', 'sensor_heartbeats', 'TRUNCATE')", "f"),
    ("q", "opsloop_enforcer", "INSERT INTO sensor_heartbeats SELECT * FROM sensor_heartbeats WHERE false"
                              " ON CONFLICT (source) DO UPDATE SET seen_at = EXCLUDED.seen_at", "허용"),
    ("q", "opsloop_enforcer", "DELETE FROM sensor_heartbeats WHERE false", "거부"),
    ("q", "opsloop_enforcer", "SELECT count(*) FROM node_metrics", "거부"),
    ("q", "opsloop_console", "SELECT source, kind, role, host, seen_at, checked_at, problem FROM sensor_heartbeats LIMIT 0", "허용"),
    ("q", "opsloop_console", "SELECT node_id, ts, cpu_pct, mem_used_pct, disk_root_pct, load1 FROM node_metrics LIMIT 0", "허용"),
    ("q", "opsloop_console", "INSERT INTO sensor_heartbeats SELECT * FROM sensor_heartbeats WHERE false", "거부"),
    ("q", "opsloop_console", "UPDATE sensor_heartbeats SET problem = problem WHERE false", "거부"),
    ("q", "opsloop_console", "INSERT INTO node_metrics SELECT * FROM node_metrics WHERE false", "거부"),
    ("q", "opsloop_detector", "SELECT count(*) FROM sensor_heartbeats", "거부"),
    ("p", "opsloop_ingest", "(SELECT tgenabled = 'O' FROM pg_trigger WHERE tgname = 'sensor_heartbeats_guard')", "t"),
]
HOST = "i-058726c1a0671fe1d"
GW = "i-0ffeb29efad03546d"
T0 = datetime(2026, 9, 21, 6, 0, tzinfo=timezone.utc)      # 과거 시각 (미래면 DB now() 로 줄어든다)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RH = load("record_heartbeats_52", os.path.join(ROOT, "puller", "record_heartbeats.py"))
BE = load("block_enforcer_52", os.path.join(ROOT, "enforcer", "block_enforcer.py"))
QUERIES = load("drill_queries_52", os.path.join(ROOT, "infra", "vmware", "restore-drill", "queries.py"))
MOD = load("block47_for_52", BLOCK47)


def block52(text):
    """'관제 대상 상태판 (이슈 #52)' 블록(머리 주석 · 표 · 트리거 · 권한). 뒤에 #59 블록이 있으면 그 앞까지다."""
    start = text.index(HEADER + "\n")
    stop = text.find("\n" + NEXT_HEADER, start)
    region = text if stop < 0 else text[:stop]
    end = region.rindex("END\n$$;") + len("END\n$$;")
    return text[start:end]


def verify_lines52():
    """verify-db-roles.sh 의 #52 절(echo 머리부터 다음 echo 앞까지) q · p 줄."""
    text = read(VERIFY)
    sec = text[text.index(VERIFY_SECTION):]
    sec = sec[sec.index("\n"):].split("\necho", 1)[0]
    pat = re.compile(r'^([qp]) (opsloop_[a-z]+) +"(.+)" (허용|거부|t|f)$')
    return [m.groups() for m in map(pat.match, sec.splitlines()) if m]


def flat(sql):
    return " ".join(sql.split())


def app_targets():
    """콘솔 상태판(app/targets.py). 같은 폴더 모듈(cti · absorbed · …)을 이름으로 부르므로 app 을 경로에 넣는다. asyncpg 가 없으면 None."""
    try:
        import asyncpg  # noqa: F401
    except ImportError:
        return None
    if APP not in sys.path:
        sys.path.insert(0, APP)
    import targets
    return targets


class StatusBoardTextTest(unittest.TestCase):
    def test_마이그레이션은_스키마_블록_그대로다(self):
        schema, mig = read(SCHEMA), read(MIGRATION)
        head, body = mig.split("\nBEGIN;\n", 1)
        self.assertTrue(all(ln.startswith("--") for ln in head.splitlines()))
        self.assertEqual(body.rstrip("\n"), block52(schema) + "\nCOMMIT;")

    def test_블록은_51_블록_뒤에_있고_그_뒤에는_59_블록만_온다(self):
        schema = read(SCHEMA)
        at = schema.index(HEADER + "\n")
        self.assertGreater(at, schema.index(HEADER51 + "\n"))
        rest = schema[at + len(block52(schema)):].strip("\n")
        self.assertTrue(rest.startswith(NEXT_HEADER), rest[:80])
        self.assertEqual(schema.count(HEADER + "\n"), 1)
        self.assertEqual(schema.count("CREATE TABLE IF NOT EXISTS sensor_heartbeats"), 1)

    def test_표_정의는_계약과_같다(self):
        self.assertIn(DDL, block52(read(SCHEMA)))

    def test_트리거는_역할별로_행_종류를_가르고_호출자_권한으로_돈다(self):
        blk = block52(read(SCHEMA))
        fn = blk[blk.index("CREATE OR REPLACE FUNCTION sensor_heartbeats_guard()"):blk.index("REVOKE ALL ON FUNCTION")]
        self.assertIn("\nLANGUAGE plpgsql\nSECURITY INVOKER\nSET search_path = public, pg_temp\n", fn)
        self.assertNotIn("SECURITY DEFINER", blk)
        self.assertIn("CASE session_user::text WHEN 'opsloop_ingest' THEN 'uploader'", fn)
        self.assertIn("WHEN 'opsloop_enforcer' THEN 'block_report' END;", fn)
        self.assertIn("EXISTS (SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper)", fn)
        self.assertIn("IF NEW.kind IS DISTINCT FROM v_kind THEN", fn)
        self.assertIn("IF TG_OP = 'UPDATE' THEN\n        IF OLD.kind IS DISTINCT FROM v_kind THEN", fn)
        self.assertEqual(fn.count("ERRCODE = 'insufficient_privilege'"), 2)
        self.assertIn("CONSTRAINT = 'sensor_heartbeats_source'", fn)
        self.assertIn("REVOKE ALL ON FUNCTION sensor_heartbeats_guard() FROM PUBLIC;", blk)
        self.assertIn("CREATE OR REPLACE TRIGGER sensor_heartbeats_guard\n    BEFORE INSERT OR UPDATE ON sensor_heartbeats\n"
                      "    FOR EACH ROW EXECUTE FUNCTION sensor_heartbeats_guard();", blk)

    def test_권한_줄은_계약과_같다(self):
        blk = block52(read(SCHEMA))
        grants = [" ".join(ln.split()) for ln in blk[blk.rindex("DO $$"):].splitlines() if ln.strip().startswith("GRANT")]
        self.assertEqual(grants, GRANTS)
        self.assertEqual(re.findall(r"rolname = '(\w+)'", blk[blk.rindex("DO $$"):]),
                         ["opsloop_ingest", "opsloop_enforcer", "opsloop_console"])
        self.assertNotIn("REVOKE ALL ON ALL", blk)            # 역할의 다른 표 권한은 건드리지 않는다
        self.assertNotIn("CREATE ROLE", blk)
        for role in ("opsloop_gate", "opsloop_backup", "opsloop_cti", "opsloop_detector"):
            self.assertNotIn(role, blk)
        # 콘솔 역할 블록에는 node_metrics 가 없다. 이 블록이 준다
        roles = read(ROLES_SQL)
        console = roles[roles.index("rolname = 'opsloop_console'"):]
        self.assertNotIn("node_metrics", console[:console.index("END IF;")])

    def test_역할_검증_스크립트에_52_줄이_있다(self):
        self.assertEqual(verify_lines52(), VERIFY_LINES)
        self.assertIn("infra/migrations/20260930_status_board.sql", read(VERIFY))

    def test_기록_문장은_못_읽은_회차의_seen_at_을_두고_자기_종류만_쓴다(self):
        for name, sql, kind in (("적재기", RH.UPSERT_SQL, "uploader"), ("집행기", BE.HEARTBEAT_SQL, "block_report")):
            with self.subTest(name):
                s = flat(sql)
                self.assertIn("INSERT INTO sensor_heartbeats AS h (source, kind, role, host, seen_at, checked_at, problem)", s)
                self.assertIn(f"VALUES (%(source)s, '{kind}', %(role)s, %(host)s,", s)
                self.assertIn("ON CONFLICT (source) DO UPDATE SET", s)
                self.assertIn("seen_at = CASE WHEN h.host = EXCLUDED.host THEN coalesce(EXCLUDED.seen_at, h.seen_at)"
                              " ELSE EXCLUDED.seen_at END", s)
                self.assertIn("checked_at = EXCLUDED.checked_at, problem = EXCLUDED.problem", s)
        self.assertIn("least(%(checked_at)s::timestamptz, now())", flat(RH.UPSERT_SQL))
        self.assertIn(", now(), %(problem)s)", flat(BE.HEARTBEAT_SQL))          # 집행기의 checked_at 은 DB now()

    def test_복원_훈련은_새_표를_백업_대상으로_세고_구조_기대값이_늘었다(self):
        self.assertIn("sensor_heartbeats", QUERIES.TABLES)
        self.assertEqual(len(QUERIES.TABLES), len(set(QUERIES.TABLES)))
        # #59 가 트리거 +2 · 함수 +3, #63 이 함수 +3, #77 이 트리거 +1 · 함수 +1 을 더했다(infra/test_console_accounts_manage_db.py ·
        # infra/test_block_points_choice_db.py 가 시험 DB 카탈로그와 대조한다)
        self.assertEqual(QUERIES.EXPECT, {"tables": 27, "fk": 16, "triggers": 10, "functions": 20, "views": 3})


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class StatusBoardDatabaseTest(MOD.DbCase):
    @classmethod
    def setUpClass(cls):
        cls.create()
        for text in (read(SCHEMA), read(SCHEMA), read(MIGRATION), read(MIGRATION)):   # 두 번 적용해도 같다
            cls.scur.execute(cls.sub(text))
        cls.connect()

    def privs(self, key, table):
        return {p for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
                if self.one("SELECT has_table_privilege(%s, %s, %s)", (self.roles[key], table, p))[0]}

    def upsert(self, key, sql, row):
        with self.as_role(key):
            self.cur.execute(sql, row)

    def rows(self):
        return self.q("SELECT source, kind, role, host, seen_at, problem FROM sensor_heartbeats ORDER BY source")

    def uploader(self, seen=T0, problem=None, host=HOST):
        return {"source": f"uploader:{host}", "role": "sensor", "host": host, "seen_at": seen,
                "checked_at": T0 + timedelta(minutes=1), "problem": problem}

    def report(self, point="gateway", host=GW, seen=T0, problem=None):
        return {"source": f"block:{point}", "role": point, "host": host, "seen_at": seen, "problem": problem}

    def test_표_트리거_권한은_두_번_적용해도_계약과_같다(self):
        cols = self.q("SELECT attname, format_type(atttypid, atttypmod), attnotnull FROM pg_attribute"
                      " WHERE attrelid = 'sensor_heartbeats'::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum")
        self.assertEqual(cols, [("source", "text", True), ("kind", "text", True), ("role", "text", True),
                                ("host", "text", True), ("seen_at", "timestamp with time zone", False),
                                ("checked_at", "timestamp with time zone", True), ("problem", "text", False)])
        trg = self.q("SELECT tgname, pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid = 'sensor_heartbeats'::regclass"
                     " AND NOT tgisinternal")
        self.assertEqual([t for t, _ in trg], ["sensor_heartbeats_guard"])
        self.assertIn("BEFORE INSERT OR UPDATE ON public.sensor_heartbeats FOR EACH ROW", trg[0][1])
        self.assertEqual(self.one("SELECT prosecdef, proconfig FROM pg_proc WHERE proname = 'sensor_heartbeats_guard'"),
                         (False, ["search_path=public, pg_temp"]))
        self.assertFalse(self.one("SELECT has_function_privilege('public', 'sensor_heartbeats_guard()', 'EXECUTE')")[0])
        want = {"ingest": {"SELECT", "INSERT", "UPDATE"}, "enforcer": {"SELECT", "INSERT", "UPDATE"}, "console": {"SELECT"},
                "detector": set(), "gate": set(), "cti": set(), "backup": {"SELECT"}}     # 백업은 pg_read_all_data
        for key, privs in want.items():
            with self.subTest(role=key):
                self.assertEqual(self.privs(key, "sensor_heartbeats"), privs)
        self.assertEqual(self.privs("console", "node_metrics"), {"SELECT"})
        self.assertEqual(self.privs("enforcer", "node_metrics"), set())

    def test_적재_역할은_업로더_행만_집행_역할은_차단_보고_행만_쓴다(self):
        self.upsert("ingest", RH.UPSERT_SQL, self.uploader())
        self.upsert("enforcer", BE.HEARTBEAT_SQL, self.report())
        self.upsert("enforcer", BE.HEARTBEAT_SQL, self.report("fw", "fw-opsloop"))
        self.assertEqual(self.rows(), [("block:fw", "block_report", "fw", "fw-opsloop", T0, None),
                                       ("block:gateway", "block_report", "gateway", GW, T0, None),
                                       (f"uploader:{HOST}", "uploader", "sensor", HOST, T0, None)])
        with self.as_role("ingest"):
            # 장악된 적재기: 방화벽 보고를 새로 넣거나, 업로더 행 모양으로 덮어쓰거나, 행을 지우지 못한다
            self.denied("INSERT INTO sensor_heartbeats (source, kind, role, host, seen_at, checked_at)"
                        " VALUES ('block:gateway', 'block_report', 'gateway', %s, now(), now())"
                        " ON CONFLICT (source) DO UPDATE SET seen_at = EXCLUDED.seen_at", (GW,))
            self.denied("UPDATE sensor_heartbeats SET seen_at = now() WHERE source = 'block:gateway'")
            self.denied("UPDATE sensor_heartbeats SET kind = 'uploader', role = 'sensor', host = %s, source = 'uploader:' || %s"
                        " WHERE source = 'block:fw'", (HOST, HOST))
            e = self.fails(RH.UPSERT_SQL, dict(self.uploader(), source="block:gateway"))
            self.assertEqual(e.pgcode, "23514")                                 # 키 모양이 틀린 업로더 행
            self.denied("DELETE FROM sensor_heartbeats")
        with self.as_role("enforcer"):
            # 장악된 집행기: 업로더 신호를 꾸미지 못한다
            self.denied(RH.UPSERT_SQL, self.uploader(seen=T0 + timedelta(minutes=5)))
            self.denied("UPDATE sensor_heartbeats SET seen_at = now() WHERE source = %s", (f"uploader:{HOST}",))
            e = self.fails(BE.HEARTBEAT_SQL, self.report(point="fw", host="i-058726c1a0671fe1d; DROP"))
            self.assertEqual(e.pgcode, "23514")
            self.denied("TRUNCATE sensor_heartbeats")
        self.assertEqual(self.rows()[2], (f"uploader:{HOST}", "uploader", "sensor", HOST, T0, None))

    def test_못_읽은_회차는_seen_at_을_두고_관문이_바뀌면_옛_시각을_잇지_않는다(self):
        self.upsert("enforcer", BE.HEARTBEAT_SQL, self.report())
        self.upsert("enforcer", BE.HEARTBEAT_SQL, self.report(seen=None, problem="없음 (관문 동기화가 아직 쓰지 않았다)"))
        self.assertEqual(self.rows(), [("block:gateway", "block_report", "gateway", GW, T0, "없음 (관문 동기화가 아직 쓰지 않았다)")])
        self.assertEqual(self.one("SELECT checked_at = now() FROM sensor_heartbeats")[0], True)
        self.upsert("enforcer", BE.HEARTBEAT_SQL, self.report(host="i-0123456789abcdef0", seen=None, problem="SlowDown"))
        self.assertEqual(self.rows()[0][3:], ("i-0123456789abcdef0", None, "SlowDown"))

    def test_콘솔은_읽기만_하고_탐지는_보지_못한다(self):
        self.upsert("ingest", RH.UPSERT_SQL, self.uploader())
        with self.as_role("console"):
            self.assertEqual(self.one("SELECT count(*) FROM sensor_heartbeats")[0], 1)
            self.q("SELECT node_id, ts, cpu_pct, mem_used_pct, disk_root_pct, load1 FROM node_metrics LIMIT 1")
            for sql in ("UPDATE sensor_heartbeats SET problem = 'x'", "DELETE FROM sensor_heartbeats",
                        "TRUNCATE sensor_heartbeats", "INSERT INTO node_metrics (line_hash, node_id, ts) VALUES ('x', 'n', now())"):
                with self.subTest(sql=sql):
                    self.denied(sql)
            self.denied(RH.UPSERT_SQL, self.uploader(host="i-0000000000000001"))
        with self.as_role("detector"):
            self.denied("SELECT count(*) FROM sensor_heartbeats")

    def test_슈퍼유저는_막지_않는다(self):
        self.cur.execute("INSERT INTO sensor_heartbeats (source, kind, role, host, checked_at)"
                         " VALUES ('복원된 옛 줄', 'uploader', 'fw', 'x', now())")
        self.assertEqual(self.one("SELECT count(*) FROM sensor_heartbeats")[0], 1)

    def apply(self, path):
        self.cur.execute(self.sub(read(path).replace("BEGIN;", "").replace("COMMIT;", "")))

    def test_역할_블록이나_47_을_다시_적용하면_권한이_빠지고_이_마이그레이션으로_되살아난다(self):
        self.apply(ROLES_SQL)
        self.assertEqual((self.privs("ingest", "sensor_heartbeats"), self.privs("console", "sensor_heartbeats"),
                          self.privs("console", "node_metrics")), (set(), set(), set()))
        self.assertEqual(self.privs("enforcer", "sensor_heartbeats"), {"SELECT", "INSERT", "UPDATE"})
        self.apply(M47)
        self.assertEqual(self.privs("enforcer", "sensor_heartbeats"), set())
        with self.as_role("ingest"):
            self.denied(RH.UPSERT_SQL, self.uploader())                       # 적재기는 알리고 0 으로 끝난다(record_heartbeats)
        self.apply(MIGRATION)
        self.assertEqual((self.privs("ingest", "sensor_heartbeats"), self.privs("enforcer", "sensor_heartbeats"),
                          self.privs("console", "sensor_heartbeats"), self.privs("console", "node_metrics")),
                         ({"SELECT", "INSERT", "UPDATE"}, {"SELECT", "INSERT", "UPDATE"}, {"SELECT"}, {"SELECT"}))

    def test_역할_검증_스크립트_줄이_시험_DB_에서_같은_답을_낸다(self):
        lines = verify_lines52()
        self.assertEqual(len(lines), len(VERIFY_LINES))
        for kind, role, stmt, want in lines:
            key = role.removeprefix("opsloop_")
            with self.subTest(role=role, stmt=stmt):
                if kind == "p":
                    got = "t" if self.one("SELECT " + self.sub(stmt))[0] else "f"
                else:
                    self.cur.execute("SAVEPOINT v")
                    self.cur.execute(f"SET SESSION AUTHORIZATION {self.roles[key]}")
                    try:
                        self.cur.execute(self.sub(stmt))
                        got = "허용"
                    except MOD.psycopg2.Error as e:
                        got = "거부" if e.pgcode == "42501" else f"오류({e.pgcode} {e})"
                    self.cur.execute("ROLLBACK TO SAVEPOINT v")
                    self.cur.execute("RESET SESSION AUTHORIZATION")
                self.assertEqual(got, want)


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class ConsoleLinksLoginTest(MOD.DbCase):
    """콘솔 DB 연결(이슈 #76 · #84). app/test_targets_db 는 시험 연결(슈퍼유저)을 같은 역할로 쓰므로, 여기서는 schema.sql 의 콘솔 역할로
    실제 로그인한다(usename = current_user 는 SET ROLE 로 흉내 낼 수 없다). 콘솔 A 처럼 이름표를 단 콘솔 역할 연결에서 상태판을 부른다.
    역할에는 시험 비밀번호를 주고, 끝나면 데이터베이스와 함께 지운다."""

    @classmethod
    def setUpClass(cls):
        cls.targets = app_targets()
        if cls.targets is None:
            raise unittest.SkipTest("asyncpg 없음(콘솔 의존)")
        cls.create()
        cls.scur.execute(cls.sub(read(SCHEMA)))
        cls.pw = {key: secrets.token_urlsafe(18) for key in ("console", "ingest")}
        for key, pw in cls.pw.items():
            cls.admin.cursor().execute(f"ALTER ROLE {cls.roles[key]} LOGIN PASSWORD %s", (pw,))
        cls.connect()

    def test_콘솔_역할로_로그인하면_같은_역할의_콘솔_이름표_연결만_센다(self):
        asyncio.run(self.links())

    async def links(self):
        import asyncpg
        url = MOD.psycopg2.extensions.parse_dsn(MOD.URL)
        opened = []

        async def link(key, name=None):
            try:
                conn = await asyncpg.connect(host=url.get("host"), port=int(url.get("port") or 5432), user=self.roles[key],
                                             password=self.pw[key], database=self.dbname,
                                             server_settings={"application_name": name} if name else None)
            except (asyncpg.InvalidAuthorizationSpecificationError, asyncpg.InvalidPasswordError, OSError) as e:
                self.skipTest(f"시험 역할로 붙을 수 없다(pg_hba): {e}")
            opened.append(conn)
            return conn

        async def console(conn):
            async with conn.transaction(isolation="repeatable_read", readonly=True):
                body = await self.targets.targets_view(conn, await conn.fetchval("SELECT now()"))
            return next(x for x in body["targets"] if x["id"] == "console")["collection"]
        try:
            a = await link("console", "opsloop-console-a")                 # 콘솔 A(풀 · LISTEN 과 같은 이름표)
            self.assertTrue(await a.fetchval("SELECT session_user = current_user AND current_user = $1", self.roles["console"]))
            self.assertTrue(await a.fetchval(self.targets.CONSOLE_LINKS_READABLE_SQL))
            got = await console(a)
            self.assertEqual((got["state"], got["reason"]), ("responding", A_ONLY))
            await link("ingest", "opsloop-console-b")                       # 다른 역할이 콘솔 B 이름표를 쓴 연결
            await link("console")                                           # 같은 역할 · 이름표 없음(triage.py · 옛 이미지 콘솔)
            self.assertEqual((await console(a))["reason"], A_ONLY)
            await link("console", "opsloop-console-b")                      # 같은 역할 · 콘솔 B 이름표(B 를 켬)
            self.assertEqual((await console(a))["reason"], "DB 연결 확인: 콘솔 A 있음 · 콘솔 B 있음")
        finally:
            for conn in opened:
                await conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
