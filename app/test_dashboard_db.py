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
                verdict text, operator text, created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE events (ts timestamptz, src_ip inet, provenance text);
            CREATE TEMP TABLE actions (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text,
                action text, operator text, note text, created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE blocklist (actor_ip inet PRIMARY KEY, reason text, incident_key text,
                created_at timestamptz DEFAULT now(), expires_at timestamptz, released_at timestamptz,
                requested_by text, method text, enforced_at timestamptz, enforce_note text, released_by text,
                enforcement jsonb, points text[] NOT NULL DEFAULT '{gateway,fw}'
                CHECK (points IN ('{gateway,fw}'::text[], '{fw}'::text[])));
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

    async def test_미결은_사람이_남긴_최신_판정만_사건_단위로_센다(self):
        # 대시보드 미결(이슈 #83) = 최신 판정이 사람이 남긴 undetermined 인 사건 수. 시스템 전환 기록(operator 'system:…')은 빼고
        #   기록은 지우지 않는다. 보고서의 판단 유보(reports.UNDETERMINED_SQL)는 시스템 기록을 포함한 수로 그대로다
        import reports
        for key in ("twice", "rejudged", "system", "no-operator", "human-after-system", "system-after-human", "none"):
            await self.incident(key, 100)
        await self.conn.execute("""INSERT INTO verdicts (incident_key, verdict, operator, created_at) VALUES
            ('twice', 'undetermined', 'han', '2026-09-23 01:00Z'), ('twice', 'undetermined', 'kim', '2026-09-23 02:00Z'),
            ('rejudged', 'undetermined', 'han', '2026-09-23 01:00Z'), ('rejudged', 'threat', 'han', '2026-09-23 02:00Z'),
            ('system', 'undetermined', 'system:v3-cutover', '2026-09-23 01:00Z'),
            ('no-operator', 'undetermined', NULL, '2026-09-23 01:00Z'),
            ('human-after-system', 'undetermined', 'system:v3-cutover', '2026-09-23 01:00Z'),
            ('human-after-system', 'undetermined', 'han', '2026-09-23 02:00Z'),
            ('system-after-human', 'undetermined', 'han', '2026-09-23 01:00Z'),
            ('system-after-human', 'undetermined', 'system:v3-cutover', '2026-09-23 02:00Z')""")
        data = await dashboard_metrics(self.conn, self.now)
        self.assertEqual(data["pending"]["undetermined"], 3)        # twice · no-operator · human-after-system
        self.assertEqual(data["pending"]["total"], 1)               # 미판정(none)과 따로 센다
        self.assertEqual(await self.conn.fetchval("SELECT count(*) FROM verdicts WHERE operator LIKE 'system:%'"), 3)
        self.assertEqual(await self.conn.fetchval(reports.UNDETERMINED_SQL), 5)
        # 미결이 없으면 0 이다(화면은 0 이면 보이지 않는다)
        await self.conn.execute("DELETE FROM verdicts WHERE operator IS DISTINCT FROM 'system:v3-cutover'")
        self.assertEqual((await dashboard_metrics(self.conn, self.now))["pending"]["undetermined"], 0)

    async def test_요약의_최근_원문_수집은_앞선_시각_줄을_뺀다(self):
        # 장비 로그 목록(node_logs)과 같은 기준: 요약 기준 시각 + 5분 넘게 앞선 줄은 최근 원문 수집이 아니다. 수는 그대로 센다
        import main
        await self.conn.execute("""INSERT INTO events (ts, src_ip, provenance) VALUES
            (now() - interval '1 hour', '192.0.2.1', 'real'), (now() + interval '4 minutes', '192.0.2.2', 'real'),
            (now() + interval '10 minutes', '192.0.2.3', 'real'), (now() - interval '1 minute', '192.0.2.4', 'simulated')""")
        near = await self.conn.fetchval("SELECT ts FROM events WHERE src_ip = '192.0.2.2'")
        with patch.object(main.app.state, "pool", self.pool, create=True):
            data = await main.summary()
            self.assertEqual((data["latest_event"], data["events"], data["actors"]), (near.isoformat(), 3, 3))
            # 앞선 줄뿐이면 최근 원문 수집이 없다
            await self.conn.execute("DELETE FROM events WHERE src_ip IN ('192.0.2.1', '192.0.2.2')")
            data = await main.summary()
        self.assertEqual((data["latest_event"], data["events"]), (None, 1))

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
        await self.conn.execute("UPDATE blocklist SET points = '{fw}' WHERE actor_ip = '203.0.113.11'")
        with patch.object(main.app.state, "pool", self.pool, create=True):
            rows = {row["actor_ip"]: row for row in await main.blocklist(True)}
        self.assertEqual(rows["203.0.113.10"]["enforcement"]["fw"]["state"], "confirmed")
        self.assertIsNone(rows["203.0.113.11"]["enforcement"])
        # 요청 지점(이슈 #77)은 정규 순서 목록이다
        self.assertEqual((rows["203.0.113.10"]["points"], rows["203.0.113.11"]["points"]), (["gateway", "fw"], ["fw"]))

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
        # 활성 차단 요청을 종합 상태로 나눈다(이슈 #47 · #77). 요청 수가 실제로 막은 수로 읽히지 않게 한다. 요청한 지점이 모두
        # 확인이어야 적용이고 순서는 제외 > 실패 > 불일치 > 대기 > 적용이다(경우 표는 test_block_points). 풀리거나 만료된 것은 세지 않는다
        import main
        ok = '{"gateway": {"state": "confirmed"}, "fw": {"state": "confirmed"}}'
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, released_at, enforced_at, enforce_note,
            enforcement, points) VALUES
            ('192.0.2.1', now() + interval '1 hour', NULL, now(), '관문 반영 · abcd1234 · x', $1, '{gateway,fw}'),
            ('192.0.2.2', now() + interval '1 hour', NULL, now(), '관문 반영 · abcd1234 · x', NULL, '{gateway,fw}'),
            ('192.0.2.3', now() + interval '1 hour', NULL, NULL, NULL, NULL, '{gateway,fw}'),
            ('192.0.2.4', NULL, NULL, NULL, '집행 제외 · 만료 없음', NULL, '{gateway,fw}'),
            ('192.0.2.5', NULL, NULL, NULL, NULL, NULL, '{fw}'),
            ('192.0.2.6', now() + interval '1 hour', NULL, NULL, '집행 제외 · 금지 대역', $1, '{gateway,fw}'),
            ('192.0.2.7', now() + interval '1 hour', NULL, now(), '관문 불일치 · 관문 상태가 7분 전', $1, '{gateway,fw}'),
            ('192.0.2.8', now() + interval '1 hour', now(), now(), '관문 반영 · abcd1234 · x', $1, '{gateway,fw}'),
            ('192.0.2.9', now() - interval '1 second', NULL, now(), '관문 반영 · abcd1234 · x', $1, '{gateway,fw}'),
            ('192.0.2.10', now() + interval '1 hour', NULL, NULL, NULL, '{"fw": {"state": "confirmed"}}', '{fw}'),
            ('192.0.2.11', now() + interval '1 hour', NULL, NULL, NULL, '{"fw": {"state": "failed"}}', '{fw}')""", ok)
        with patch.object(main.app.state, "pool", self.pool, create=True):
            data = await main.summary()
        self.assertEqual(data["blocked_ips"], 9)
        # 192.0.2.2 는 관문 확인이 있어도 내부 방화벽 확인 전이라 대기다(기존 두 지점 행도 같은 규칙)
        self.assertEqual(data["blocks"], {"enforced": 2, "pending": 2, "excluded": 3, "mismatch": 1, "failed": 1})

    async def test_summary_counts_active_blocks_by_point(self):
        # 지점별 적용 확인 · 실패 · 미확인(이슈 #72). 상태판 카드 대응과 같은 정의(targets.point_counts)다.
        # 해제 · 만료 · 만료 없음 · 집행 제외는 어느 지점에도 세지 않는다. 지점은 요청한 행만 세고 미요청은 따로다(이슈 #77).
        # 지점별 합 = blocked_ips − blocks.excluded − 그 지점 미요청
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
            ('192.0.2.9', now() + interval '1 hour', NULL, '집행 제외 · 금지 대역', '{"fw": {"state": "failed"}}'),
            ('192.0.2.10', now() + interval '1 hour', NULL, NULL,
             '{"gateway": {"state": "failed"}, "fw": {"state": "confirmed"}}')""")
        # 내부 방화벽만 요청한 행. 남은 관문 결과(관문 빼기 뒤 관문이 뺐다고 확인하기 전)는 관문 수 · 미요청에 들지 않고 빠짐 확인 전이다
        await self.conn.execute("UPDATE blocklist SET points = '{fw}' WHERE actor_ip = '192.0.2.10'")
        from test_targets_db import HEARTBEATS_TABLE
        with patch.object(main.app.state, "pool", self.pool, create=True):
            unread = await main.summary()
            # 집행 보고(생존 신호 표)가 새로우면 지점이 확인한 수다. 지점 불일치(stale)는 미확인 가운데 따로 센 수다(#82)
            await self.conn.execute(HEARTBEATS_TABLE)
            await self.conn.execute("""INSERT INTO sensor_heartbeats VALUES
                ('block:gateway', 'block_report', 'gateway', 'i-0fedcba9876543210', now(), now(), NULL),
                ('block:fw', 'block_report', 'fw', 'fw-opsloop', now(), now(), NULL)""")
            data = await main.summary()
        self.assertEqual(data["blocks_by_point"], [
            {"point": "gateway", "label": "AWS 관문", "applied": 2, "failed": 1, "unverified": 2, "stale": 0,
             "unrequested": 0, "removing": 1, "stalled": None, "unreadable": False},
            {"point": "fw", "label": "내부 방화벽", "applied": 2, "failed": 1, "unverified": 3, "stale": 1,
             "unrequested": 0, "removing": 0, "stalled": None, "unreadable": False}])
        # 생존 신호 표를 읽을 수 없으면 집행 보고를 모르니 옛 '적용 확인' 을 믿지 않고 모두 미확인이다(#82).
        #   집행기가 멈춘 것이 아니라 모르는 것이라 unreadable 로 가른다. 미요청은 합치지 않는다
        self.assertEqual([(p["applied"], p["failed"], p["unverified"], p["stale"], p["unrequested"], p["removing"],
                           p["stalled"], p["unreadable"]) for p in unread["blocks_by_point"]],
                         [(0, 0, 5, 0, 0, 1, "집행 보고를 읽을 수 없음 · 적용 여부 확인 불가", True),
                          (0, 0, 6, 0, 0, 0, "집행 보고를 읽을 수 없음 · 적용 여부 확인 불가", True)])
        # 192.0.2.5 는 관문 불일치 쪽지가 있어도 관문 실패가 먼저라 실패다. 192.0.2.1 은 관문 열(enforced_at)이 비어 대기다
        self.assertEqual((data["blocked_ips"], data["blocks"]), (8, {"enforced": 1, "pending": 3, "excluded": 2,
                                                                     "mismatch": 0, "failed": 2}))
        for point in [*data["blocks_by_point"], *unread["blocks_by_point"]]:
            self.assertEqual(point["applied"] + point["failed"] + point["unverified"],
                             data["blocked_ips"] - data["blocks"]["excluded"] - point["unrequested"] - point["removing"])

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
