#!/usr/bin/env python3
"""업로더 생존 신호 기록(record_heartbeats.py, 이슈 #52) 시험.  python3 puller/test_record_heartbeats.py

DB 없이: 상태 파일의 heartbeats 를 행으로 바꾸고 거르는지(호스트 · 역할 · 시각 · 문제 글), 풀러가 쓴 값을 그대로 읽는지,
표 없음(42P01) · 권한 없음(42501)은 0 이고 그 밖의 DB 오류 · 상태 파일 오류는 1 인지 본다(가짜 접속).

OPSLOOP_TEST_DATABASE_URL 이 슈퍼유저 연결이면 infra/test_block_enforce_db.py 의 무작위 데이터베이스 · 역할로 schema.sql 과
마이그레이션을 적용하고, 적재 역할(SET SESSION AUTHORIZATION)로 upsert 가 되는지 · 못 읽은 회차가 옛 seen_at 을 두는지 ·
미래 시각이 now() 로 줄어드는지 · 트리거가 차단 보고 행과 모양이 틀린 행을 막는지 본다. main() 은 슈퍼유저 접속에 role ·
search_path 를 바꿔 권한 없음 · 표 없음 경로를 실제로 낸다.
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import pull  # noqa: E402
import record_heartbeats as rh  # noqa: E402

HOST = "i-058726c1a0671fe1d"
GW = "i-0a1b2c3d4e5f60718"
T0 = datetime(2026, 9, 21, 6, 0, tzinfo=timezone.utc)
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20260930_status_board.sql")


def beat(role="sensor", seen=T0, checked=T0 + timedelta(minutes=1), problem=None):
    return {"role": role, "seen_at": seen.isoformat() if isinstance(seen, datetime) else seen,
            "checked_at": checked.isoformat() if isinstance(checked, datetime) else checked, "problem": problem}


class PgError(Exception):
    def __init__(self, code):
        super().__init__(f"가짜 DB 오류 {code}")
        self.pgcode = code


class FakeConn:
    """psycopg2 접속 흉내. with 블록 · 커서 · 문장 기록 · 오류 내기."""

    def __init__(self, fail=None):
        self.fail, self.sql, self.closed, self.committed = fail, [], False, False

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        self.committed = et is None

    def cursor(self):
        conn = self

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, args=None):
                if conn.fail and "INSERT" in sql:
                    raise PgError(conn.fail)
                conn.sql.append((sql, args))
        return Cur()

    def close(self):
        self.closed = True


class ParseTest(unittest.TestCase):
    def test_풀러가_쓴_값을_그대로_읽는다(self):
        entry = pull.heartbeat_entry(HOST, T0, None, T0 + timedelta(minutes=1), frozenset())
        [row], skipped = rh.rows_from_state({"heartbeats": {HOST: json.loads(json.dumps(entry))}})
        self.assertEqual(skipped, [])
        self.assertEqual(row, {"source": f"uploader:{HOST}", "role": "sensor", "host": HOST, "seen_at": T0,
                               "checked_at": T0 + timedelta(minutes=1), "problem": None})
        miss = pull.heartbeat_entry(GW, None, "읽기 일시 오류 (SlowDown)", T0, frozenset({GW}))
        [row], _ = rh.rows_from_state({"heartbeats": {GW: miss}})
        self.assertEqual((row["role"], row["seen_at"], row["problem"]), ("gateway", None, "읽기 일시 오류 (SlowDown)"))

    def test_모양이_틀린_항목은_건너뛴다(self):
        beats = {
            HOST: beat(),
            "i-0123": beat(),                                   # 짧다
            "i-058726C1A0671FE1D": beat(),                      # 대문자
            "i-058726c1a0671fe1d\n": beat(),                    # 끝 줄바꿈
            "fw-opsloop": beat(role="fw"),
            "i-0000000000000001": beat(role="fw"),              # 역할이 두 값 밖
            "i-0000000000000002": beat(checked="2026-09-21T06:00:00"),        # 시간대 없음
            "i-0000000000000003": beat(checked=None),
            "i-0000000000000004": beat(seen="어제"),
            "i-0000000000000005": beat(problem=12),
            "i-0000000000000006": "hb",
            "i-0000000000000007": beat(seen=None, problem="없음 (NoSuchKey)"),
            "i-0000000000000008": beat(checked="2026-09-21T06:00:00Z", problem="줄\n바꿈" + "가" * 300),
        }
        rows, skipped = rh.rows_from_state({"heartbeats": beats})
        self.assertEqual([r["host"] for r in rows], ["i-0000000000000007", "i-0000000000000008", HOST])
        self.assertEqual(len(skipped), len(beats) - 3)
        self.assertEqual(rows[1]["checked_at"], T0)
        self.assertEqual(rows[1]["problem"], ("줄?바꿈" + "가" * 300)[:rh.PROBLEM_MAX])
        self.assertTrue(all("\n" not in s for s in skipped))

    def test_항목이_없거나_틀려도_빈_목록이다(self):
        for state in ({}, {"heartbeats": []}, {"heartbeats": None}, [], "x"):
            self.assertEqual(rh.rows_from_state(state), ([], []))

    def test_상한을_넘는_항목은_자른다(self):
        beats = {f"i-{n:016x}": beat() for n in range(rh.MAX_ITEMS + 5)}
        rows, skipped = rh.rows_from_state({"heartbeats": beats})
        self.assertEqual(len(rows), rh.MAX_ITEMS)
        self.assertIn("5개", skipped[-1])

    def test_문장은_못_읽은_회차의_seen_at_을_지우지_않고_미래_시각을_줄인다(self):
        sql = " ".join(rh.UPSERT_SQL.split())
        self.assertIn("seen_at = CASE WHEN h.host = EXCLUDED.host THEN coalesce(EXCLUDED.seen_at, h.seen_at)", sql)
        self.assertIn("least(%(checked_at)s::timestamptz, now())", sql)
        self.assertIn("CASE WHEN %(seen_at)s::timestamptz IS NOT NULL THEN least(%(seen_at)s::timestamptz, now()) END", sql)
        self.assertIn("'uploader'", sql)


class MainTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.logs = []
        p = mock.patch.object(rh, "log", lambda m, level=6: self.logs.append((level, m)))
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.dict(os.environ, {"OPSLOOP_HOME": self.home, "DATABASE_URL": "postgresql://opsloop_ingest@db/x"})
        p.start()
        self.addCleanup(p.stop)

    def write(self, state):
        with open(os.path.join(self.home, "pull-state.json"), "w", encoding="utf-8") as f:
            json.dump(state, f)

    def main(self, conn):
        with mock.patch.object(rh, "connect", lambda url: conn):
            return rh.main()

    def test_기록하고_0(self):
        self.write({"objects": {}, "heartbeats": {HOST: beat()}})
        conn = FakeConn()
        self.assertEqual(self.main(conn), 0)
        ups = [a for s, a in conn.sql if "INSERT" in s]
        self.assertEqual([a["source"] for a in ups], [f"uploader:{HOST}"])
        self.assertTrue(conn.committed and conn.closed)
        self.assertIn("SET LOCAL statement_timeout = '30s'", [s for s, _ in conn.sql])

    def test_표_없음_권한_없음은_알리고_0_그_밖은_1(self):
        self.write({"heartbeats": {HOST: beat()}})
        for code, rc, level in (("42P01", 0, 5), ("42501", 0, 5), ("23514", 1, 3), ("57014", 1, 3)):
            with self.subTest(code=code):
                self.logs.clear()
                conn = FakeConn(fail=code)
                self.assertEqual(self.main(conn), rc)
                self.assertTrue(conn.closed)
                self.assertEqual(self.logs[-1][0], level)

    def test_접속_실패는_1이고_접속_문자열을_찍지_않는다(self):
        self.write({"heartbeats": {HOST: beat()}})

        def refuse(url):
            raise RuntimeError(f"could not connect {url}")
        with mock.patch.object(rh, "connect", refuse):
            self.assertEqual(rh.main(), 1)
        self.assertNotIn("postgresql://", " ".join(m for _, m in self.logs))

    def test_상태_파일이_없거나_항목이_없으면_0_깨졌으면_1(self):
        self.assertEqual(self.main(FakeConn(fail="XX000")), 0)                # 풀러가 아직 돌지 않았다
        self.write({"objects": {}})                                           # 옛 풀러 (heartbeats 없음)
        self.assertEqual(self.main(FakeConn(fail="XX000")), 0)
        with open(os.path.join(self.home, "pull-state.json"), "w") as f:
            f.write("{깨짐")
        self.assertEqual(self.main(FakeConn()), 1)
        with mock.patch.dict(os.environ, {"DATABASE_URL": ""}):
            self.assertEqual(rh.main(), 1)
        self.write({"heartbeats": {HOST: beat()}})
        with mock.patch.object(rh, "STATE_MAX", 10):                        # 너무 큰 상태 파일은 읽지 않는다
            self.assertEqual(self.main(FakeConn()), 1)

    def test_건너뛴_항목은_한_줄로_알린다(self):
        self.write({"heartbeats": {HOST: beat(), "i-bad": beat()}})
        self.assertEqual(self.main(FakeConn()), 0)
        warn = [m for level, m in self.logs if level == 4]
        self.assertEqual(len(warn), 1)
        self.assertIn("i-bad: 호스트 모양", warn[0])


# ── 실제 PostgreSQL (infra/test_block_enforce_db.py 의 무작위 데이터베이스 · 역할) ────────────────

def db_module():
    spec = importlib.util.spec_from_file_location("block47_for_heartbeats", os.path.join(ROOT, "infra", "test_block_enforce_db.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = db_module()


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class RecordDatabaseTest(MOD.DbCase):
    @classmethod
    def setUpClass(cls):
        cls.create()
        with open(SCHEMA, encoding="utf-8") as f:
            cls.scur.execute(cls.sub(f.read()))
        with open(MIGRATION, encoding="utf-8") as f:
            cls.scur.execute(cls.sub(f.read()))
        cls.connect()

    def rows(self, beats):
        rows, skipped = rh.rows_from_state({"heartbeats": beats})
        self.assertEqual(skipped, [])
        return rows

    def record(self, beats, role="ingest"):
        with self.as_role(role):
            return rh.record(self.cur, self.rows(beats))

    def table(self):
        return self.q("SELECT source, kind, role, host, seen_at, checked_at, problem FROM sensor_heartbeats ORDER BY source")

    def test_적재_역할로_넣고_못_읽은_회차는_옛_seen_at_을_둔다(self):
        self.assertEqual(self.record({HOST: beat(), GW: beat(role="gateway")}), 2)
        self.assertEqual(self.table(), [
            (f"uploader:{HOST}", "uploader", "sensor", HOST, T0, T0 + timedelta(minutes=1), None),
            (f"uploader:{GW}", "uploader", "gateway", GW, T0, T0 + timedelta(minutes=1), None)])
        self.record({HOST: beat(seen=None, checked=T0 + timedelta(minutes=6), problem="읽기 일시 오류 (SlowDown)")})
        self.assertEqual(self.table()[0][4:], (T0, T0 + timedelta(minutes=6), "읽기 일시 오류 (SlowDown)"))
        self.assertEqual(self.table()[1][4:], (T0, T0 + timedelta(minutes=1), None))          # 이번 회차에 없던 호스트는 그대로
        self.record({HOST: beat(seen=T0 + timedelta(minutes=10), checked=T0 + timedelta(minutes=11))})
        self.assertEqual(self.table()[0][4:], (T0 + timedelta(minutes=10), T0 + timedelta(minutes=11), None))

    def test_미래_시각은_지금으로_줄인다(self):
        future = datetime.now(timezone.utc) + timedelta(days=3)
        self.record({HOST: beat(seen=future, checked=future)})
        now = self.one("SELECT now()")[0]
        self.assertEqual(self.table()[0][4:6], (now, now))

    def test_트리거는_적재_역할에_업로더_행만_허락한다(self):
        ins = ("INSERT INTO sensor_heartbeats (source, kind, role, host, seen_at, checked_at)"
               " VALUES (%s, %s, %s, %s, now(), now())")
        with self.as_role("ingest"):
            self.denied(ins, ("block:gateway", "block_report", "gateway", GW))              # 방화벽 보고를 꾸미지 못한다
            for bad in (("block:gateway", "uploader", "gateway", GW), (f"uploader:{GW}", "uploader", "sensor", HOST),
                        ("uploader:fw-x", "uploader", "sensor", "fw-x"), (f"uploader:{HOST}", "uploader", "fw", HOST)):
                with self.subTest(bad=bad):
                    e = self.fails(ins, bad)
                    self.assertEqual((e.pgcode, e.diag.constraint_name), ("23514", "sensor_heartbeats_source"))
            self.denied("DELETE FROM sensor_heartbeats")
        with self.as_role("enforcer"):
            self.cur.execute(ins, ("block:gateway", "block_report", "gateway", GW))
            self.denied(ins, (f"uploader:{HOST}", "uploader", "sensor", HOST))            # 업로더 신호를 꾸미지 못한다
        with self.as_role("ingest"):
            # 이미 있는 차단 보고 행을 업로더 행으로 덮어쓰지 못한다 (UPDATE 는 바뀌기 전 행의 kind 도 본다)
            self.denied("UPDATE sensor_heartbeats SET kind = 'uploader', role = 'sensor', host = %s,"
                        " source = 'uploader:' || %s WHERE source = 'block:gateway'", (HOST, HOST))
        for key in ("console", "detector"):
            with self.subTest(role=key), self.as_role(key):
                self.denied(ins, (f"uploader:{HOST}", "uploader", "sensor", HOST))
        with self.as_role("console"):
            self.assertEqual(self.one("SELECT count(*) FROM sensor_heartbeats")[0], 1)

    def dsn(self, **options):
        return MOD.psycopg2.extensions.make_dsn(MOD.URL, dbname=self.dbname,
                                                options=" ".join(f"-c {k}={v}" for k, v in options.items()))

    def run_main(self, url, beats):
        home = tempfile.mkdtemp()
        with open(os.path.join(home, "pull-state.json"), "w", encoding="utf-8") as f:
            json.dump({"heartbeats": beats}, f)
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"OPSLOOP_HOME": home, "DATABASE_URL": url}), mock.patch.object(sys, "stdout", out):
            return rh.main(), out.getvalue()

    def test_main_은_권한_없음과_표_없음을_0으로_끝낸다(self):
        rc, out = self.run_main(self.dsn(role=self.roles["detector"]), {HOST: beat()})
        self.assertEqual(rc, 0)
        self.assertIn("권한이 없다", out)
        rc, out = self.run_main(self.dsn(search_path="pg_catalog"), {HOST: beat()})
        self.assertEqual(rc, 0)
        self.assertIn("표가 없다", out)
        # 슈퍼유저 접속은 트리거를 지나 실제로 쓴다 (스키마 적용 · 복원 몫)
        rc, out = self.run_main(self.dsn(), {"i-00000000000000ff": beat()})
        self.assertEqual((rc, out.strip()), (0, "생존 신호 1건을 기록했다"))
        with MOD.psycopg2.connect(self.dsn()) as c, c.cursor() as cur:
            cur.execute("DELETE FROM sensor_heartbeats WHERE host = 'i-00000000000000ff' RETURNING seen_at")
            self.assertEqual(cur.fetchall(), [(T0,)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
