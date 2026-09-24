#!/usr/bin/env python3
"""판정 검토 도구(triage.py)의 중복 제안 시험.  python3 detector/test_triage.py

중복(대표 인시던트) 계산은 같은 규칙 버전의 인시던트 안에서만 해야 한다. 버전이 다른 인시던트가
심각도가 더 높다고 대표가 되면, 새 버전 인시던트가 까닭 없이 '무시 가능(중복)'으로 제안된다.
같은 페이로드 흡수(규칙 v3): 첫 사건의 흡수 기록을 보이고, 차단할 때 흡수 출발지를 함께 올리는 선택을 본다.
R006(키 심기)은 순환 규칙이다.

  - 가짜 커서: DB 없이 조회 문장과 인자에 규칙 버전이 들어가는지 본다
  - 임시 테이블: OPSLOOP_TEST_DATABASE_URL 이 있으면 연결 전용 임시 테이블(search_path=pg_temp)에서
    실제 조회 결과를 본다. 운영 테이블은 건드리지 않는다
"""
import io
import os
import re
import sys
import types
from unittest import mock
import unittest
from datetime import datetime, timedelta, timezone

try:
    import psycopg2  # noqa: F401
    REAL_PG = True
except ImportError:
    # psycopg2 가 없는 곳에서도 가짜 커서 시험은 돌게 한다 (DB 에는 붙지 않는다)
    sys.modules["psycopg2"] = types.ModuleType("psycopg2")
    REAL_PG = False

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import triage  # noqa: E402

ACTOR = "192.0.2.8"
T0 = datetime(2026, 9, 20, 3, tzinfo=timezone.utc)


class FakeCursor:
    """조회 문장과 인자를 기록한다. 결과는 모두 비어 있다."""

    def __init__(self):
        self.calls = []

    def execute(self, sql, args=None):
        self.calls.append((" ".join(sql.split()), args))

    def fetchall(self):
        return []

    def fetchone(self):
        return None


class CircularTests(unittest.TestCase):
    def test_key_plant_is_circular_and_matches_console(self):
        # 콘솔(app/proposals.py)과 같은 목록이어야 판정자가 같은 기준으로 본다
        sys.path.insert(0, os.path.join(HERE, "..", "app"))
        try:
            import proposals
        finally:
            sys.path.pop(0)
        self.assertEqual(set(triage.CIRCULAR), proposals.CIRCULAR_RULES)
        ev = {"counts": {"cowrie.command.input": 2}, "covered_by": None}
        suggestion, basis = triage.propose("R006", ev)
        self.assertEqual(suggestion, "threat")
        self.assertIn("authorized_keys", " ".join(basis))


class AbsorbedSqlSameAsConsoleTests(unittest.TestCase):
    """triage 의 흡수 차단 문장은 콘솔(app/absorbed.py)과 자리표시자만 다르다. 한쪽만 고치면 여기서 걸린다."""

    def test_same_statements_and_nets(self):
        sys.path.insert(0, os.path.join(HERE, "..", "app"))
        try:
            import absorbed
        finally:
            sys.path.pop(0)
        self.assertEqual(triage.NO_BLOCK_NETS, absorbed.NO_BLOCK_NETS)
        self.assertEqual(triage.absorbed_reason_tag("k"), absorbed.absorbed_reason_tag("k"))
        for name, names in (("BLOCK_ABSORBED_SQL", ("key", "reason", "ip", "who", "expires", "nets")),
                            ("ABSORBED_STATE_SQL", ("key", "reason", "ip", "nets", "n")),
                            ("FOLLOW_UPSERT_SQL", ("key", "hours", "who"))):
            with self.subTest(sql=name):
                console = re.sub(r"\$(\d)", lambda m: f"%({names[int(m.group(1)) - 1]})s", getattr(absorbed, name))
                self.assertEqual(getattr(triage, name), console)


class OverlapQueryTests(unittest.TestCase):
    def test_overlap_query_is_limited_to_rule_version(self):
        cur = FakeCursor()
        triage.gather(cur, "R003|v2", ACTOR, T0, T0, [], "v2")
        sql, args = next((s, a) for s, a in cur.calls if "interval '15 minutes'" in s)
        self.assertIn("rule_version = %s", sql)
        self.assertEqual(args[:2], (ACTOR, "v2"))

    def test_absorbed_query_is_by_first_key(self):
        cur = FakeCursor()
        ev = triage.gather(cur, "R006|v3", ACTOR, T0, T0, [], "v3")
        sql, args = next((s, a) for s, a in cur.calls if "FROM incident_absorbed" in s)
        self.assertIn("first_key = %s", sql)
        self.assertEqual(args, (ACTOR, "R006|v3"))
        self.assertEqual(ev["absorbed"], {"total": 0, "sources": 0, "sample": []})

    def test_covered_by_drives_duplicate_proposal_only_when_set(self):
        ev = {"counts": {"cowrie.login.success": 1}, "covered_by": None}
        self.assertNotIn("이미 떴다", " ".join(triage.propose("R003", ev)[1]))
        ev["covered_by"] = "R002"
        suggestion, basis = triage.propose("R003", ev)
        self.assertEqual(suggestion, "non_actionable")
        self.assertIn("R002", basis[1])


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class OverlapDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute("""
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_name text,
                rule_version text NOT NULL, severity text, actor_ip inet, first_ts timestamptz,
                last_ts timestamptz);
            CREATE TEMP TABLE events (ts timestamptz, src_ip inet, session text, eventid text,
                username text, password text, input text, shasum text, url text);
            CREATE TEMP TABLE blocklist (actor_ip inet PRIMARY KEY, released_at timestamptz);
            CREATE TEMP TABLE incident_absorbed (first_key text, member_key text, kind text, via_key text,
                rule_id text, rule_version text, actor_ip inet, first_ts timestamptz, last_ts timestamptz,
                signal_count integer, sessions text[] DEFAULT '{}', payloads text[] DEFAULT '{}');
        """)

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def incident(self, key, rule, version, severity, minutes=0):
        first = T0 + timedelta(minutes=minutes)
        self.cur.execute(
            "INSERT INTO incidents VALUES (%s, %s, '시험 규칙', %s, %s, %s, %s, %s)",
            (key, rule, version, severity, ACTOR, first, first + timedelta(minutes=1)))
        return first

    def gather(self, key, version, first):
        return triage.gather(self.cur, key, ACTOR, first, first + timedelta(minutes=1), [], version)

    def test_higher_severity_of_other_version_is_not_representative(self):
        # 버전을 가리지 않으면 더 높은 심각도의 v1 인시던트가 대표가 된다
        self.incident("R002|v1", "R002", "v1", "critical")
        first = self.incident("R003|v2", "R003", "v2", "high", minutes=2)
        self.assertIsNone(self.gather("R003|v2", "v2", first)["covered_by"])

    def test_newer_version_is_not_representative_of_older(self):
        self.incident("R002|v2", "R002", "v2", "critical")
        first = self.incident("R003|v1", "R003", "v1", "high", minutes=2)
        self.assertIsNone(self.gather("R003|v1", "v1", first)["covered_by"])

    def test_same_version_representative_is_still_found(self):
        self.incident("R002|v1", "R002", "v1", "critical")
        self.incident("R004|v2", "R004", "v2", "critical", minutes=1)
        first = self.incident("R003|v2", "R003", "v2", "high", minutes=2)
        ev = self.gather("R003|v2", "v2", first)
        self.assertEqual(ev["covered_by"], "R004")
        self.assertEqual(triage.propose("R003", ev)[0], "non_actionable")


FIRST = "R006|v3|192.0.2.1|2026-09-20T00:00:00+00:00"
OWN = "192.0.2.1"


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class AbsorbedDatabaseTests(unittest.TestCase):
    """흡수 기록 표시와 흡수 출발지 함께 차단(record absorbed=True). 이 출발지의 차단은 만료가 없고(triage 차단),
    흡수 출발지는 만료(기본 24시간)가 있으며 후속 차단 약속을 남긴다."""

    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute("""
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_name text,
                rule_version text NOT NULL, severity text, actor_ip inet, first_ts timestamptz,
                last_ts timestamptz, status text DEFAULT 'open');
            CREATE TEMP TABLE events (ts timestamptz, src_ip inet, session text, eventid text,
                username text, password text, input text, shasum text, url text);
            CREATE TEMP TABLE verdicts (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, verdict text,
                reason text, observed_value double precision, operator text, proposed text, decision_seconds integer);
            CREATE TEMP TABLE actions (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, action text,
                operator text, note text);
            CREATE TEMP TABLE blocklist (actor_ip inet PRIMARY KEY, reason text, incident_key text,
                created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz, released_at timestamptz,
                method text, requested_by text, enforced_at timestamptz, enforce_note text, released_by text);
            CREATE TEMP TABLE incident_absorbed (first_key text, member_key text, kind text, via_key text,
                rule_id text, rule_version text, actor_ip inet, first_ts timestamptz, last_ts timestamptz,
                signal_count integer, sessions text[] DEFAULT '{}', payloads text[] DEFAULT '{}');
            CREATE TEMP TABLE absorbed_blocks (first_key text PRIMARY KEY, expires_at timestamptz NOT NULL,
                requested_by text, created_at timestamptz NOT NULL DEFAULT now(), released_at timestamptz,
                released_by text);
            CREATE TEMP TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL);
            INSERT INTO rule_versions VALUES ('v3', '{"rules": [{"id": "R002", "params": {}},
                {"id": "R006", "params": {"absorb_same_payload": {"window_hours": 24, "max_sources": 100}}}]}');
        """)
        self.cur.execute("INSERT INTO incidents VALUES (%s, 'R006', 'SSH 키 심기', 'v3', 'critical', %s, %s, %s)",
                         (FIRST, OWN, T0, T0))
        for i, (ip, kind) in enumerate([("198.51.100.2", "absorbed"), ("198.51.100.2", "absorbed"),
                                        ("198.51.100.3", "absorbed"), ("198.51.100.4", "absorbed"),
                                        (OWN, "absorbed"), ("198.51.100.2", "suppressed")]):
            self.cur.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, via_key, rule_id,
                rule_version, actor_ip, first_ts, last_ts, signal_count, sessions)
                VALUES (%s, %s, %s, %s, 'R006', 'v3', %s, %s, %s, 1, ARRAY['s1'])""",
                (FIRST, f"m{i}", kind, "m0" if kind == "suppressed" else None, ip,
                 T0 + timedelta(minutes=i), T0 + timedelta(minutes=i)))
        # 198.51.100.4 는 다른 사건 차단으로 살아 있다(콘솔 24시간)
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, method)
            VALUES ('198.51.100.4', 'console', 'R002|v3|other', now() + interval '1 hour', 'nft')""")

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def rows(self):
        self.cur.execute("SELECT host(actor_ip), reason, incident_key, expires_at, requested_by, method FROM blocklist")
        return {r[0]: r[1:] for r in self.cur.fetchall()}

    def test_gather_counts_absorbed_sources(self):
        ev = triage.gather(self.cur, FIRST, OWN, T0, T0, [], "v3")
        self.assertEqual((ev["absorbed"]["total"], ev["absorbed"]["sources"]), (6, 3))
        self.assertEqual([r[3] for r in ev["absorbed"]["sample"]], ["absorbed"] * 5 + ["suppressed"])
        self.assertEqual(ev["absorbed"]["state"], {"blocked": 0, "kept": 1, "skipped_total": 0, "skipped": [],
                                                   "unblockable": 0, "open": 2})
        self.assertTrue(triage.rule_absorbs(self.cur, "v3", "R006"))
        self.assertFalse(triage.rule_absorbs(self.cur, "v3", "R002"))

    def test_record_blocks_absorbed_sources_with_expiry(self):
        # record 는 커밋한다. 임시 테이블이라 연결을 닫으면 사라진다
        before = self.rows()["198.51.100.4"]
        done = triage.record(self.conn, FIRST, OWN, "threat", "키 심기 캠페인", 1.0, "han", None, True,
                             absorbed=True)
        rows = self.rows()
        tag = triage.absorbed_reason_tag(FIRST)
        self.assertEqual(set(rows), {OWN, "198.51.100.2", "198.51.100.3", "198.51.100.4"})
        self.assertIsNone(rows[OWN][2])                               # 이 출발지의 triage 차단은 만료가 없다
        now = datetime.now(timezone.utc)
        for ip in ("198.51.100.2", "198.51.100.3"):
            self.assertEqual((rows[ip][0], rows[ip][1], rows[ip][3], rows[ip][4]), (tag, FIRST, "han", None))
            self.assertTrue(now + timedelta(hours=23) < rows[ip][2] < now + timedelta(hours=25))
        # 다른 사건으로 살아 있는 차단은 그 사건 것으로 두고 만료도 건드리지 않는다
        self.assertEqual(rows["198.51.100.4"], before)
        self.assertEqual({k: done[k] for k in ("blocked", "kept", "skipped_total", "unblockable")},
                         {"blocked": 2, "kept": 1, "skipped_total": 0, "unblockable": 0})
        self.assertEqual(done["follow_expires_at"], rows["198.51.100.2"][2])
        self.cur.execute("SELECT expires_at, requested_by FROM absorbed_blocks WHERE first_key = %s", (FIRST,))
        self.assertEqual(self.cur.fetchone(), (rows["198.51.100.2"][2], "han"))
        self.cur.execute("SELECT note FROM actions WHERE action = 'block_ip'")
        self.assertEqual(self.cur.fetchone()[0], "키 심기 캠페인 [흡수 출발지 2곳 함께 차단 · "
                                                 "1곳은 다른 사건으로 차단 중 · 만료 전 새 흡수도 차단]")

    def test_record_skips_human_released_source(self):
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, released_at, released_by)
            VALUES ('198.51.100.3', 'console', 'R002|v3|x', now() + interval '1 hour', now(), 'admin')""")
        done = triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, absorbed=True,
                             absorbed_hours=48)
        rows = self.rows()
        self.assertEqual(rows["198.51.100.3"][1], "R002|v3|x")      # 사람이 푼 행은 그대로
        self.assertEqual((done["blocked"], done["skipped"]), (1, ["198.51.100.3"]))
        with self.assertRaises(ValueError):
            triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, absorbed=True,
                          absorbed_hours=0)

    def test_triage_flow_asks_absorbed_block_with_expiry(self):
        # 판정 화면 흐름: 위협 → 근거(엔터) → 차단 y → 흡수 함께 차단 y. 흡수 차단은 --absorbed-hours 만료로 오른다
        self.cur.execute("""ALTER TABLE incidents ADD COLUMN signal_count integer DEFAULT 1,
            ADD COLUMN session_count integer DEFAULT 1, ADD COLUMN evidence jsonb, ADD COLUMN target text""")
        prompts = []
        answers = iter(["t", "", "y", "y"])

        def fake_input(prompt=""):
            prompts.append(prompt)
            return next(answers)
        with mock.patch("builtins.input", fake_input), mock.patch("sys.stdout", io.StringIO()) as out:
            triage.triage(self.conn, "R006", 5, "han", absorbed_hours=12)
        self.assertIn("흡수된 출발지 3곳도 함께 차단할까요? (만료 12시간", prompts[-1])
        rows = self.rows()
        now = datetime.now(timezone.utc)
        self.assertTrue(now + timedelta(hours=11) < rows["198.51.100.2"][2] < now + timedelta(hours=13))
        self.assertIn("흡수 2곳 함께(다른 사건 차단 1곳 유지)", out.getvalue())
        self.assertIn("다른 사건 차단 중 1곳", out.getvalue())

    def test_record_without_option_blocks_own_source_only(self):
        done = triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True)
        self.assertIsNone(done)
        self.assertEqual(set(self.rows()), {OWN, "198.51.100.4"})


if __name__ == "__main__":
    unittest.main()
