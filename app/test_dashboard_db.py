"""PostgreSQL 경계 시험. OPSLOOP_TEST_DATABASE_URL이 있을 때만 실행한다.

모든 데이터는 연결 전용 임시 테이블에 둔다. search_path=pg_temp로 운영 테이블 접근을 막는다.
환경이 없으면 건너뛰며, 실제 DB 검증 여부를 완료 기록에 구분해 남긴다.
"""
import os
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from dashboard import dashboard_metrics


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class DashboardDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncpg
        self.conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        await self.conn.execute("SET search_path TO pg_temp")
        await self.conn.execute("""
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_name text,
                rule_version text, severity text, actor_ip inet, target text, first_ts timestamptz,
                status text, created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE verdicts (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text,
                verdict text, created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE events (ts timestamptz, src_ip inet, provenance text);
            CREATE TEMP TABLE actions (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text,
                action text, operator text, note text, created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE blocklist (actor_ip inet PRIMARY KEY, reason text, incident_key text,
                created_at timestamptz DEFAULT now(), expires_at timestamptz, released_at timestamptz,
                requested_by text, method text, enforced_at timestamptz, enforce_note text, released_by text);
        """)
        self.now = datetime(2026, 9, 23, 8, tzinfo=timezone.utc)
        self.pool = SimpleNamespace(acquire=self.acquire)

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def asyncTearDown(self):
        await self.conn.close()

    async def incident(self, key, seconds, rule="R001", severity="high", status="open"):
        await self.conn.execute("""INSERT INTO incidents
            (incident_key, rule_id, rule_name, rule_version, severity, actor_ip, first_ts, status)
            VALUES ($1,$2,'시험 규칙','v2',$3,'192.0.2.8',$4,$5)""",
            key, rule, severity, self.now - timedelta(seconds=seconds), status)

    async def test_pending_buckets_boundaries_and_console_target(self):
        for i, seconds in enumerate([0, 3600, 14400, 43200, 86400]):
            await self.incident(str(i), seconds, status="acknowledged")
        await self.incident("audit", 3600, rule="R201", severity="low")
        await self.incident("judged", 100000)
        await self.conn.execute("INSERT INTO verdicts (incident_key,verdict) VALUES ('judged','undetermined')")
        data = await dashboard_metrics(self.conn, self.now)
        self.assertEqual(data["pending"]["total"], 6)
        self.assertEqual(data["pending"]["age_distribution"], [1, 2, 1, 1, 1])
        self.assertEqual(data["pending"]["overdue"], 4)
        self.assertEqual(data["oldest_pending"][0]["incident_key"], "4")
        self.assertTrue(next(row for row in data["oldest_pending"] if row["incident_key"] == "audit")["overdue"])

    async def test_latest_verdict_wins_and_undetermined_is_excluded(self):
        for key in ("a", "b", "c", "d"):
            await self.incident(key, 100)
        await self.conn.execute("""INSERT INTO verdicts (incident_key,verdict,created_at) VALUES
            ('a','false_positive','2026-09-23'), ('a','threat','2026-09-23'),
            ('b','non_actionable','2026-09-23'), ('c','benign_positive','2026-09-23'),
            ('d','undetermined','2026-09-23')""")
        data = await dashboard_metrics(self.conn, self.now)
        row = data["rule_quality"][0]
        self.assertEqual((row["incidents"], row["judged_effective"], row["non_action"]), (4, 3, 2))
        self.assertEqual(float(row["non_action_rate"]), 66.7)
        self.assertEqual(data["pending"]["total"], 0)

    async def test_zero_cases_preserve_null_rate(self):
        empty = await dashboard_metrics(self.conn, self.now)
        self.assertEqual(empty["pending"]["total"], 0)
        self.assertEqual(empty["pending"]["oldest_seconds"], 0)
        await self.incident("a", 0)
        data = await dashboard_metrics(self.conn, self.now)
        self.assertIsNone(data["rule_quality"][0]["non_action_rate"])

    async def test_active_filter_and_summary_exclude_expired_released(self):
        import main
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, released_at) VALUES
            ('192.0.2.1', now() + interval '1 hour', NULL),
            ('192.0.2.2', now() - interval '1 second', NULL),
            ('192.0.2.3', now() + interval '1 hour', now()),
            ('192.0.2.4', NULL, NULL)""")
        with patch.object(main.app.state, "pool", self.pool, create=True):
            rows = await main.blocklist(True)
            self.assertEqual({row["actor_ip"] for row in rows}, {"192.0.2.1", "192.0.2.4"})
            self.assertEqual(len(await main.blocklist(False)), 4)
            self.assertEqual((await main.summary())["blocked_ips"], 2)

    async def test_summary_splits_active_blocks_by_enforcement(self):
        # 활성 차단 요청을 집행 상태로 나눈다(이슈 #47). 요청 수가 실제로 막은 수로 읽히지 않게 한다.
        # 순서: 만료 없음 · 집행 제외 → 관문 불일치 → 집행 확인 → 집행 대기. 풀리거나 만료된 것은 세지 않는다
        import main
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, released_at, enforced_at, enforce_note)
            VALUES
            ('192.0.2.1', now() + interval '1 hour', NULL, now(), '관문 반영 · abcd1234 · x'),
            ('192.0.2.2', now() + interval '1 hour', NULL, now(), '관문 반영 · abcd1234 · x'),
            ('192.0.2.3', now() + interval '1 hour', NULL, NULL, NULL),
            ('192.0.2.4', NULL, NULL, NULL, '집행 제외 · 만료 없음'),
            ('192.0.2.5', NULL, NULL, NULL, NULL),
            ('192.0.2.6', now() + interval '1 hour', NULL, NULL, '집행 제외 · 금지 대역'),
            ('192.0.2.7', now() + interval '1 hour', NULL, now(), '관문 불일치 · 관문 상태가 7분 전'),
            ('192.0.2.8', now() + interval '1 hour', now(), now(), '관문 반영 · abcd1234 · x'),
            ('192.0.2.9', now() - interval '1 second', NULL, now(), '관문 반영 · abcd1234 · x')""")
        with patch.object(main.app.state, "pool", self.pool, create=True):
            data = await main.summary()
        self.assertEqual(data["blocked_ips"], 7)
        self.assertEqual(data["blocks"], {"enforced": 2, "pending": 1, "excluded": 3, "mismatch": 1})

    async def test_release_once_and_reject_expired_changed_incident(self):
        import main
        await self.incident("a", 0)
        await self.conn.execute("INSERT INTO blocklist (actor_ip,incident_key,expires_at) VALUES ('192.0.2.8','a',now()+interval '1 hour')")
        request = SimpleNamespace(state=SimpleNamespace(user={"u": "test-admin", "r": "admin"}))
        body = main.ActionIn(action="unblock_ip", note="시험")
        with patch.object(main.app.state, "pool", self.pool, create=True), patch.object(main.hub, "broadcast", AsyncMock()):
            await main.add_action("a", body, request)
            first = dict(await self.conn.fetchrow("SELECT released_at, released_by FROM blocklist"))
            with self.assertRaises(main.HTTPException) as error:
                await main.add_action("a", body, request)
            self.assertEqual(error.exception.status_code, 409)
            self.assertEqual(dict(await self.conn.fetchrow("SELECT released_at, released_by FROM blocklist")), first)
            for expiry, key in (("now()-interval '1 second'", "a"), ("now()+interval '1 hour'", "other")):
                await self.conn.execute(f"UPDATE blocklist SET released_at=NULL, expires_at={expiry}, incident_key=$1", key)
                with self.assertRaises(main.HTTPException) as error:
                    await main.add_action("a", body, request)
                self.assertEqual(error.exception.status_code, 409)
            self.assertEqual(await self.conn.fetchval("SELECT count(*) FROM actions"), 1)

    async def test_operator_cannot_release(self):
        import main
        request = SimpleNamespace(state=SimpleNamespace(user={"u": "test-operator", "r": "operator"}))
        with self.assertRaises(main.HTTPException) as error:
            await main.add_action("a", main.ActionIn(action="unblock_ip"), request)
        self.assertEqual(error.exception.status_code, 403)
