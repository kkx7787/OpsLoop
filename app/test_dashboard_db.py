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


async def with_test_source(conn):
    """시험 출발지 판단 함수(is_test_source · 이슈 #51)를 이 연결에만 둔다. PostgreSQL 은 임시 스키마(pg_temp)에서 함수를
    찾지 않으므로 무작위 스키마에 두고 search_path 맨 앞에 넣는다. 표는 그대로 임시 표다(스키마가 비어 pg_temp 에서 찾는다).
    시험 대역은 203.0.113.0/24 만 둔다. 기존 시험의 192.0.2.x 사건은 그대로 집계된다. 지울 스키마 이름을 돌려준다"""
    import secrets
    schema = f"t51_{secrets.token_hex(4)}"
    await conn.execute(f"""
        CREATE TEMP TABLE test_ranges (cidr inet PRIMARY KEY, note text NOT NULL);
        INSERT INTO test_ranges VALUES ('203.0.113.0/24', '시험');
        CREATE SCHEMA {schema};
        CREATE FUNCTION {schema}.is_test_source(ip inet) RETURNS boolean LANGUAGE sql STABLE
            AS $$ SELECT EXISTS (SELECT 1 FROM pg_temp.test_ranges t WHERE ip <<= t.cidr) $$;
        SET search_path TO {schema}, pg_temp;""")
    return schema


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
                requested_by text, method text, enforced_at timestamptz, enforce_note text, released_by text,
                enforcement jsonb);
        """)
        self.schema = await with_test_source(self.conn)
        self.now = datetime(2026, 9, 23, 8, tzinfo=timezone.utc)
        self.pool = SimpleNamespace(acquire=self.acquire)

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def asyncTearDown(self):
        await self.conn.execute(f"DROP SCHEMA IF EXISTS {self.schema} CASCADE")
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

    async def test_rule_rates_exclude_test_sources(self):
        # 시험 출발지(이슈 #51)의 사건은 규칙별 집계에서 빠지고, 판정 대기에는 그대로 남는다
        await self.incident("real", 100)
        await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_name, rule_version, severity,
            actor_ip, first_ts, status) VALUES ('lab', 'R001', '시험 규칙', 'v2', 'high', '203.0.113.10', $1, 'open')""",
            self.now - timedelta(seconds=100))
        data = await dashboard_metrics(self.conn, self.now)
        self.assertEqual(data["rule_quality"][0]["incidents"], 1)
        self.assertEqual(data["pending"]["total"], 2)

    async def test_blocklist_enforcement_is_an_object(self):
        # asyncpg 는 jsonb 를 글자로 준다. API 는 객체로 풀어 준다 (이슈 #51)
        import main
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, enforcement) VALUES
            ('203.0.113.10', now() + interval '1 hour', '{"fw": {"state": "confirmed", "since": "2026-09-29T01:00:00Z",
              "mode": "nft", "note": null}}'),
            ('203.0.113.11', now() + interval '1 hour', NULL)""")
        with patch.object(main.app.state, "pool", self.pool, create=True):
            rows = {row["actor_ip"]: row for row in await main.blocklist(True)}
        self.assertEqual(rows["203.0.113.10"]["enforcement"]["fw"]["state"], "confirmed")
        self.assertIsNone(rows["203.0.113.11"]["enforcement"])

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

    async def test_summary_counts_active_blocks_by_point(self):
        # 지점별 적용 확인 · 실패 · 미확인(이슈 #72). 상태판 카드 대응과 같은 정의(targets.point_counts)다.
        # 해제 · 만료 · 만료 없음 · 집행 제외는 어느 지점에도 세지 않는다. 지점별 합 = blocked_ips − blocks.excluded
        import main
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, released_at, enforce_note, enforcement) VALUES
            ('192.0.2.1', now() + interval '1 hour', NULL, NULL, '{"gateway": {"state": "confirmed"}, "fw": {"state": "confirmed"}}'),
            ('192.0.2.2', now() + interval '1 hour', NULL, NULL, '{"gateway": {"state": "confirmed"}, "fw": {"state": "failed"}}'),
            ('192.0.2.3', now() + interval '1 hour', NULL, NULL, '{"gateway": {"state": "pending"}}'),
            ('192.0.2.4', now() + interval '1 hour', NULL, NULL, NULL),
            ('192.0.2.5', now() + interval '1 hour', NULL, '관문 불일치 · 관문이 거부함',
             '{"gateway": {"state": "failed"}, "fw": {"state": "stale"}}'),
            ('192.0.2.6', now() + interval '1 hour', now(), NULL, '{"gateway": {"state": "confirmed"}}'),
            ('192.0.2.7', now() - interval '1 second', NULL, NULL, '{"gateway": {"state": "confirmed"}}'),
            ('192.0.2.8', NULL, NULL, NULL, '{"gateway": {"state": "confirmed"}}'),
            ('192.0.2.9', now() + interval '1 hour', NULL, '집행 제외 · 금지 대역', '{"fw": {"state": "failed"}}')""")
        with patch.object(main.app.state, "pool", self.pool, create=True):
            data = await main.summary()
        self.assertEqual(data["blocks_by_point"], [
            {"point": "gateway", "label": "AWS 관문", "applied": 2, "failed": 1, "unverified": 2, "stalled": None},
            {"point": "fw", "label": "내부 방화벽", "applied": 1, "failed": 1, "unverified": 3, "stalled": None}])
        self.assertEqual((data["blocked_ips"], data["blocks"]["excluded"], data["blocks"]["mismatch"]), (7, 2, 1))
        for point in data["blocks_by_point"]:
            self.assertEqual(point["applied"] + point["failed"] + point["unverified"],
                             data["blocked_ips"] - data["blocks"]["excluded"])

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


if __name__ == "__main__":
    unittest.main()
