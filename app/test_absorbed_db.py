"""같은 페이로드 흡수(규칙 v3 · incident_absorbed)의 상세 · 차단 · 해제 시험.  python3 -m unittest discover -s app

DB 시험은 OPSLOOP_TEST_DATABASE_URL 이 있을 때만 돈다. 연결 전용 임시 테이블만 쓰고 search_path=pg_temp 로
운영 테이블을 가린다(감사 트리거는 두지 않는다. 트리거는 행마다 돌므로 함께 푼 행 수가 곧 감사 해제 건수다).

  - 상세: 흡수 기록 목록(흡수 먼저 · 첫 시각 순, 200행) · 총수 · 함께 차단할 곳 수(이 출발지 제외 · 중복 제거) ·
    함께 풀 흡수 차단 수 · 흡수 사유
  - 차단: include_absorbed 가 없으면 이 출발지만. 있으면 흡수 출발지도 '흡수: <첫 사건 키>' 로 올린다.
    다른 사건으로 살아 있는 차단은 가져오지도 만료를 늘리지도 않는다. 누가 풀었는지 없는 풀린 차단 · 만료된 차단은
    새로 건다. 사람이 푼 차단(released_by)과 차단 금지 대역은 넣지 않는다. 억제 행은 넣지 않는다.
    흡수를 쓰는 규칙이면 후속 차단 약속(absorbed_blocks)을 남긴다
  - 후속 차단: 약속이 살아 있으면 뒤에 흡수된 출발지를 약속의 만료로 올리고 첫 사건에 메모 조치를 남긴다
  - 해제: include_absorbed 가 있으면 이 사건의 흡수 차단만 함께 풀고 약속을 거둔다. 다른 사건 차단은 두고, 풀 것이
    없으면 409. actor_ip 를 주면 이 사건의 흡수 차단 한 행만 푼다(차단 목록 화면). 첫 사건 출발지의 차단은 그대로다
"""
import os
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import absorbed as absorbed_mod
import main

FIRST = "R006|v3|192.0.2.1|2026-09-20T00:00:00+00:00"
OWN = "192.0.2.1"
T0 = datetime(2026, 9, 20, tzinfo=timezone.utc)
ADMIN = SimpleNamespace(state=SimpleNamespace(user={"u": "test-admin", "r": "admin"}))
OPERATOR = SimpleNamespace(state=SimpleNamespace(user={"u": "test-operator", "r": "operator"}))


class AbsorbedUnitTests(unittest.TestCase):
    def test_default_is_own_source_only(self):
        self.assertFalse(main.ActionIn(action="block_ip").include_absorbed)

    def test_reason_tag_and_row_reason(self):
        self.assertEqual(main.absorbed_reason_tag(FIRST), f"흡수: {FIRST}")
        row = {"kind": "absorbed", "rule_id": "R006", "via_key": None}
        self.assertIn("같은 SSH 키", main.absorbed_reason(row))
        row = {"kind": "absorbed", "rule_id": "R003", "via_key": None}
        self.assertIn("같은 파일", main.absorbed_reason(row))
        row = {"kind": "suppressed", "rule_id": "R002", "via_key": "R006|v3|198.51.100.9|x"}
        self.assertIn("R006", main.absorbed_reason(row))
        self.assertIn("억제", main.absorbed_reason(row))


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class AbsorbedDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncpg
        self.conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        await self.conn.execute("SET search_path TO pg_temp")
        await self.conn.execute("""
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_version text NOT NULL,
                rule_name text, severity text, actor_ip inet, target text, first_ts timestamptz,
                last_ts timestamptz, signal_count integer, session_count integer, evidence jsonb,
                status text DEFAULT 'open', created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE verdicts (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, verdict text,
                reason text, observed_value double precision, operator text, proposed text,
                decision_seconds integer, created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE actions (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, action text,
                operator text, note text, created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE events (ts timestamptz, sensor text, eventid text, session text, username text,
                password text, input text, url text, shasum text, http_method text, http_status integer,
                user_agent text, message text, src_ip inet, provenance text);
            CREATE TEMP TABLE blocklist (actor_ip inet PRIMARY KEY, reason text, incident_key text,
                created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz, released_at timestamptz,
                method text, requested_by text, enforced_at timestamptz, enforce_note text, released_by text);
            CREATE TEMP TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL);
            CREATE TEMP TABLE absorbed_blocks (first_key text PRIMARY KEY, expires_at timestamptz NOT NULL,
                requested_by text, created_at timestamptz NOT NULL DEFAULT now(), released_at timestamptz,
                released_by text);
            CREATE TEMP TABLE incident_absorbed (first_key text NOT NULL, member_key text NOT NULL,
                kind text NOT NULL CHECK (kind IN ('absorbed', 'suppressed')), via_key text,
                rule_id text NOT NULL, rule_version text NOT NULL, actor_ip inet,
                first_ts timestamptz NOT NULL, last_ts timestamptz NOT NULL, signal_count integer NOT NULL,
                sessions text[] NOT NULL DEFAULT '{}', payloads text[] NOT NULL DEFAULT '{}',
                recorded_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (first_key, member_key),
                CHECK ((kind = 'suppressed') = (via_key IS NOT NULL)));
        """)
        await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
            actor_ip, first_ts, last_ts, signal_count, session_count)
            VALUES ($1, 'R006', 'v3', 'SSH 키 심기', 'critical', $2, $3, $3, 1, 1)""", FIRST, OWN, T0)
        # 규칙 정의: R006 은 흡수를 쓰고 R002 는 쓰지 않는다(rules_v3.json 과 같은 꼴)
        await self.conn.execute("""INSERT INTO rule_versions VALUES ('v3', '{"rules": [
            {"id": "R002", "params": {"expr": "x"}},
            {"id": "R006", "params": {"absorb_same_payload": {"window_hours": 24, "max_sources": 100}}}]}')""")
        self.pool = SimpleNamespace(acquire=self.acquire)

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def asyncTearDown(self):
        await self.conn.close()

    async def absorb(self, ip, minutes, kind="absorbed", via=None, rule="R006", sessions=("s1",), first=FIRST):
        member = f"{rule}|v3|{ip}|{minutes}"
        await self.conn.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, via_key, rule_id,
            rule_version, actor_ip, first_ts, last_ts, signal_count, sessions, payloads)
            VALUES ($1, $2, $3, $4, $5, 'v3', $6, $7, $7, 1, $8, ARRAY['SHA256:MkYY9qiVsFGBC5Wk'])""",
            first, member, kind, via, rule, ip, T0 + timedelta(minutes=minutes), list(sessions))
        return member

    async def act(self, body, request=OPERATOR, key=FIRST):
        with patch.object(main.app.state, "pool", self.pool, create=True), \
                patch.object(main.hub, "broadcast", AsyncMock()):
            return await main.add_action(key, body, request)

    async def block_rows(self):
        return {r["ip"]: dict(r) for r in await self.conn.fetch(
            "SELECT host(actor_ip) ip, reason, incident_key, requested_by, expires_at, released_at, released_by, "
            "method FROM blocklist")}

    # ------------------------------------------------------------ 상세

    async def test_detail_lists_absorbed_with_counts(self):
        via = await self.absorb("198.51.100.2", 5)
        await self.absorb("198.51.100.2", 90)                      # 같은 출발지를 두 번 흡수 → 곳 수는 1
        await self.absorb("198.51.100.3", 1)
        await self.absorb(OWN, 30)                                  # 이 사건 출발지는 함께 차단할 곳에서 뺀다
        await self.absorb("198.51.100.2", 6, kind="suppressed", via=via, rule="R002", sessions=("s1", "s2"))
        await self.absorb("203.0.113.9", 2, first="R006|v3|other")  # 다른 첫 사건의 흡수
        await self.conn.execute(
            "INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at) VALUES "
            "('198.51.100.3', $1, $2, now() + interval '1 hour'), "
            "('198.51.100.2', $1, $2, now() - interval '1 second')",   # 만료된 흡수 차단은 풀 것에서 뺀다
            main.absorbed_reason_tag(FIRST), FIRST)
        with patch.object(main.app.state, "pool", self.pool, create=True):
            d = await main.get_incident(FIRST)
        ab = d["absorbed"]
        self.assertEqual((ab["total"], ab["sources"], ab["blocked"]), (5, 2, 1))
        kinds = [r["kind"] for r in ab["items"]]
        self.assertEqual(kinds, ["absorbed"] * 4 + ["suppressed"])   # 흡수 먼저, 그 안은 첫 시각 순
        self.assertEqual([r["actor_ip"] for r in ab["items"][:2]], ["198.51.100.3", "198.51.100.2"])
        self.assertEqual(ab["items"][-1]["sessions"], 2)
        self.assertIn("R006", ab["items"][-1]["reason"])
        self.assertIn("같은 SSH 키", ab["items"][0]["reason"])
        self.assertEqual(ab["items"][0]["payload"], "SHA256:MkYY9qiVsFGBC5Wk")
        self.assertEqual(d["circular"], main.CIRCULAR["R006"])

    async def test_detail_caps_rows_but_counts_all(self):
        await self.conn.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, rule_id,
            rule_version, actor_ip, first_ts, last_ts, signal_count)
            SELECT $1, 'm' || g, 'absorbed', 'R006', 'v3', ('10.1.' || (g / 250) || '.' || (g % 250 + 1))::inet,
                   $2::timestamptz + make_interval(secs => g), $2::timestamptz, 1
            FROM generate_series(1, 230) g""", FIRST, T0)
        with patch.object(main.app.state, "pool", self.pool, create=True):
            ab = (await main.get_incident(FIRST))["absorbed"]
        self.assertEqual(len(ab["items"]), main.ABSORBED_SHOWN)
        self.assertEqual((ab["total"], ab["sources"]), (230, 230))

    async def test_detail_without_absorption_is_empty(self):
        with patch.object(main.app.state, "pool", self.pool, create=True):
            ab = (await main.get_incident(FIRST))["absorbed"]
        # 흡수 기록이 아직 없어도 흡수를 쓰는 규칙이면(absorbs) 함께 차단을 고를 수 있다
        self.assertEqual(ab, {"items": [], "total": 0, "sources": 0, "blocked": 0, "kept": 0, "skipped": [],
                              "skipped_total": 0, "unblockable": 0, "absorbs": True, "follow": None})

    async def test_detail_shows_what_block_would_leave_out(self):
        await self.absorb("198.51.100.2", 5)
        await self.absorb("198.51.100.6", 6)
        await self.absorb("10.20.0.7", 7)                                # 차단 금지 대역
        await self.absorb("198.51.100.8", 8)
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, released_at,
            released_by) VALUES ('198.51.100.6', 'console', 'R002|v3|x', now() + interval '1 hour', now(), 'admin'),
                                ('198.51.100.8', 'console', 'R002|v3|y', now() + interval '1 hour', NULL, NULL)""")
        with patch.object(main.app.state, "pool", self.pool, create=True):
            ab = (await main.get_incident(FIRST))["absorbed"]
        self.assertEqual((ab["sources"], ab["blocked"], ab["kept"], ab["skipped"], ab["skipped_total"],
                          ab["unblockable"]), (4, 0, 1, ["198.51.100.6"], 1, 1))

    # ------------------------------------------------------------ 차단

    async def test_block_without_option_is_own_source_only(self):
        await self.absorb("198.51.100.2", 5)
        out = await self.act(main.ActionIn(action="block_ip"))
        self.assertEqual(set(await self.block_rows()), {OWN})
        self.assertNotIn("absorbed", out)

    async def test_block_with_absorbed_sources(self):
        via = await self.absorb("198.51.100.2", 5)
        await self.absorb("198.51.100.2", 90)
        await self.absorb("198.51.100.3", 1)
        await self.absorb("198.51.100.4", 2)
        await self.absorb("198.51.100.5", 3)
        await self.absorb(OWN, 30)
        await self.absorb("203.0.113.7", 6, kind="suppressed", via=via, rule="R002")  # 억제 행은 넣지 않는다
        await self.conn.execute("""INSERT INTO blocklist
            (actor_ip, reason, incident_key, expires_at, released_at, method) VALUES
            ('198.51.100.3', 'console', 'R002|v3|other', now() + interval '1 hour', NULL, 'nft'),
            ('198.51.100.4', 'triage', 'R003|v3|other', NULL, NULL, 'nft'),
            ('198.51.100.5', 'old', 'R001|v3|old', now() + interval '1 hour', now(), 'nft')""")
        out = await self.act(main.ActionIn(action="block_ip", note="캠페인", expires_hours=72, include_absorbed=True))
        rows = await self.block_rows()
        tag = main.absorbed_reason_tag(FIRST)
        self.assertEqual(set(rows), {OWN, "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5"})
        self.assertEqual(rows[OWN]["reason"], "캠페인")
        # 빈 자리 · 누가 풀었는지 없는 풀린 차단은 이 사건의 흡수 차단이 된다(집행 정보는 비운다). 만료는 72시간
        for ip in ("198.51.100.2", "198.51.100.5"):
            self.assertEqual((rows[ip]["reason"], rows[ip]["incident_key"], rows[ip]["requested_by"]),
                             (tag, FIRST, "test-operator"))
            self.assertIsNone(rows[ip]["released_at"])
            self.assertIsNone(rows[ip]["method"])
            self.assertGreater(rows[ip]["expires_at"], datetime.now(timezone.utc) + timedelta(hours=71))
        # 다른 사건으로 살아 있는 차단은 그 사건 것으로 두고 만료도 건드리지 않는다. 만료 없는 차단은 그대로 없다
        self.assertEqual((rows["198.51.100.3"]["reason"], rows["198.51.100.3"]["incident_key"],
                          rows["198.51.100.3"]["method"]), ("console", "R002|v3|other", "nft"))
        self.assertLess(rows["198.51.100.3"]["expires_at"], datetime.now(timezone.utc) + timedelta(hours=2))
        self.assertIsNone(rows["198.51.100.4"]["expires_at"])
        self.assertEqual(rows["198.51.100.4"]["incident_key"], "R003|v3|other")
        ab = out["absorbed"]
        self.assertEqual({k: ab[k] for k in ("blocked", "kept", "skipped", "skipped_total", "unblockable")},
                         {"blocked": 2, "kept": 2, "skipped": [], "skipped_total": 0, "unblockable": 0})
        self.assertIsNotNone(ab["follow_expires_at"])
        self.assertEqual(out["note"], "캠페인 [흡수 출발지 2곳 함께 차단 · 2곳은 다른 사건으로 차단 중 · 만료 전 새 흡수도 차단]")

    async def test_block_skips_human_released_and_no_block_nets(self):
        await self.absorb("198.51.100.6", 5)
        await self.absorb("10.20.0.7", 6)
        await self.absorb("192.168.50.1", 7)
        await self.absorb("198.51.100.9", 8)
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, released_at,
            released_by) VALUES ('198.51.100.6', 'console', 'R002|v3|x', now() + interval '1 hour', now(), 'admin')""")
        out = await self.act(main.ActionIn(action="block_ip", include_absorbed=True))
        rows = await self.block_rows()
        # 사람이 푼 곳은 다시 걸지 않고(해제 기록 그대로), 차단 금지 대역은 넣지 않는다
        self.assertEqual(set(rows), {OWN, "198.51.100.6", "198.51.100.9"})
        self.assertEqual((rows["198.51.100.6"]["released_by"], rows["198.51.100.6"]["incident_key"]),
                         ("admin", "R002|v3|x"))
        self.assertEqual((out["absorbed"]["blocked"], out["absorbed"]["skipped"], out["absorbed"]["unblockable"]),
                         (1, ["198.51.100.6"], 2))
        self.assertIn("사람이 푼 1곳 제외 · 차단 금지 대역 2곳 제외", out["note"])

    async def test_block_never_shortens_live_absorbed_block(self):
        await self.absorb("198.51.100.2", 5)
        await self.act(main.ActionIn(action="block_ip", expires_hours=168, include_absorbed=True))
        before = (await self.block_rows())["198.51.100.2"]["expires_at"]
        follow = await self.conn.fetchval("SELECT expires_at FROM absorbed_blocks WHERE first_key = $1", FIRST)
        out = await self.act(main.ActionIn(action="block_ip", expires_hours=1, include_absorbed=True))
        self.assertEqual((await self.block_rows())["198.51.100.2"]["expires_at"], before)
        self.assertEqual(await self.conn.fetchval("SELECT expires_at FROM absorbed_blocks"), follow)
        self.assertEqual(out["absorbed"]["blocked"], 1)
        # 약속이 더 길어지면 이 사건의 흡수 차단도 그 만료로 늦춘다
        await self.act(main.ActionIn(action="block_ip", expires_hours=300, include_absorbed=True))
        self.assertGreater((await self.block_rows())["198.51.100.2"]["expires_at"], before)

    async def test_block_option_on_rule_without_absorption_adds_nothing(self):
        other = "R002|v3|192.0.2.5|2026-09-20T00:00:00+00:00"
        await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
            actor_ip, first_ts, last_ts, signal_count, session_count)
            VALUES ($1, 'R002', 'v3', '침해 후 행위', 'high', '192.0.2.5', $2, $2, 1, 1)""", other, T0)
        out = await self.act(main.ActionIn(action="block_ip", note="메모", include_absorbed=True), key=other)
        self.assertEqual(set(await self.block_rows()), {"192.0.2.5"})
        self.assertEqual((out["absorbed"]["blocked"], out["absorbed"]["follow_expires_at"]), (0, None))
        self.assertEqual(out["note"], "메모")
        self.assertEqual(await self.conn.fetchval("SELECT count(*) FROM absorbed_blocks"), 0)

    # ------------------------------------------------------------ 후속 차단

    async def test_follow_blocks_sources_absorbed_after_block(self):
        # 판정 · 차단이 흡수보다 먼저 온다. 약속이 있으면 뒤에 흡수된 출발지를 약속의 만료로 올린다
        out = await self.act(main.ActionIn(action="block_ip", expires_hours=48, include_absorbed=True))
        self.assertEqual(out["absorbed"]["blocked"], 0)
        self.assertIn("만료 전 새 흡수도 차단", out["note"])
        follow = await self.conn.fetchval("SELECT expires_at FROM absorbed_blocks WHERE first_key = $1", FIRST)
        await self.absorb("198.51.100.2", 90)
        await self.absorb("198.51.100.3", 95)
        await self.absorb("10.20.0.7", 96)                                  # 차단 금지 대역은 넣지 않는다
        follower = absorbed_mod.AbsorbedFollower(self.pool)
        self.assertEqual(await follower.step(self.conn), [(FIRST, 2)])
        rows = await self.block_rows()
        self.assertEqual(set(rows), {OWN, "198.51.100.2", "198.51.100.3"})
        for ip in ("198.51.100.2", "198.51.100.3"):
            self.assertEqual((rows[ip]["reason"], rows[ip]["incident_key"], rows[ip]["expires_at"],
                              rows[ip]["requested_by"]), (main.absorbed_reason_tag(FIRST), FIRST, follow,
                                                          "test-operator"))
        note = await self.conn.fetchrow("SELECT action, operator, note FROM actions WHERE action = 'note'")
        self.assertEqual((note["action"], note["operator"]), ("note", absorbed_mod.FOLLOW_ACTOR))
        self.assertTrue(note["note"].startswith("[흡수 후속 차단 2곳"))
        self.assertEqual(await self.conn.fetchval("SELECT status FROM incidents WHERE incident_key = $1", FIRST),
                         "in_progress")                                    # 상태는 바꾸지 않는다(차단이 바꾼 그대로)
        # 할 것이 없으면 아무것도 쓰지 않는다
        self.assertEqual(await follower.step(self.conn), [])
        self.assertEqual(await self.conn.fetchval("SELECT count(*) FROM actions WHERE action = 'note'"), 1)

    async def test_follow_skips_released_rows_and_stops_after_release_all(self):
        await self.absorb("198.51.100.2", 5)
        await self.act(main.ActionIn(action="block_ip", include_absorbed=True))
        # 잘못 묶인 한 곳을 풀면 후속 차단이 다시 걸지 않는다
        await self.act(main.ActionIn(action="unblock_ip", actor_ip="198.51.100.2"), ADMIN)
        await self.absorb("198.51.100.2", 60)
        follower = absorbed_mod.AbsorbedFollower(self.pool)
        self.assertEqual(await follower.step(self.conn), [])
        self.assertIsNotNone((await self.block_rows())["198.51.100.2"]["released_at"])
        # 함께 풀면 약속을 거두고, 그 뒤의 흡수는 올리지 않는다
        out = await self.act(main.ActionIn(action="unblock_ip", include_absorbed=True), ADMIN)
        self.assertEqual(out["absorbed"], {"released": 0, "follow_stopped": True})
        self.assertEqual(out["note"], "[흡수 차단 0곳 함께 해제 · 후속 차단 중지]")
        await self.absorb("198.51.100.3", 70)
        self.assertEqual(await follower.step(self.conn), [])
        self.assertNotIn("198.51.100.3", await self.block_rows())

    async def test_unblocked_after_verdict_counts_threat_first_incidents_only(self):
        await self.conn.execute("INSERT INTO verdicts (incident_key, verdict, created_at) VALUES ($1, 'threat', now())",
                                FIRST)
        await self.absorb("198.51.100.2", 5)          # 판정 전에 흡수 → 세지 않는다
        await self.conn.execute("UPDATE incident_absorbed SET recorded_at = now() - interval '1 hour'")
        await self.absorb("198.51.100.3", 90)
        await self.absorb("198.51.100.4", 91)
        await self.absorb("10.20.0.7", 92)            # 차단 금지 대역
        await self.conn.execute("INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at) "
                                "VALUES ('198.51.100.4', 'console', 'x', now() + interval '1 hour')")
        # recorded_at 기본값 now() 는 트랜잭션 시작 시각이라 판정과 같을 수 있다. 판정을 앞으로 당긴다
        await self.conn.execute("UPDATE verdicts SET created_at = now() - interval '30 minutes'")
        row = await self.conn.fetchrow(absorbed_mod.UNBLOCKED_AFTER_VERDICT_SQL, absorbed_mod.NO_BLOCK_NETS)
        self.assertEqual((row["sources"], row["incidents"], row["first_key"]), (1, 1, FIRST))
        await self.conn.execute("INSERT INTO verdicts (incident_key, verdict) VALUES ($1, 'non_actionable')", FIRST)
        row = await self.conn.fetchrow(absorbed_mod.UNBLOCKED_AFTER_VERDICT_SQL, absorbed_mod.NO_BLOCK_NETS)
        self.assertEqual(row["sources"], 0)          # 마지막 판정이 위협이 아니면 차단을 기대하지 않는다

    # ------------------------------------------------------------ 해제

    async def test_release_with_absorbed_keeps_other_incident_blocks(self):
        await self.absorb("198.51.100.2", 5)
        await self.absorb("198.51.100.3", 1)
        await self.absorb("198.51.100.4", 2)
        await self.act(main.ActionIn(action="block_ip", include_absorbed=True))
        # 흡수 차단 하나를 다른 사건이 다시 걸면 그 사건 것이다
        await self.conn.execute("UPDATE blocklist SET incident_key = 'R002|v3|x', reason = 'console' "
                                "WHERE actor_ip = '198.51.100.4'")
        out = await self.act(main.ActionIn(action="unblock_ip", include_absorbed=True), ADMIN)
        rows = await self.block_rows()
        for ip in (OWN, "198.51.100.2", "198.51.100.3"):
            self.assertIsNotNone(rows[ip]["released_at"])
            self.assertEqual(rows[ip]["released_by"], "test-admin")
        self.assertIsNone(rows["198.51.100.4"]["released_at"])
        self.assertEqual(out["absorbed"], {"released": 2, "follow_stopped": True})
        self.assertEqual(out["note"], "[흡수 차단 2곳 함께 해제 · 후속 차단 중지]")
        self.assertIsNotNone(await self.conn.fetchval("SELECT released_at FROM absorbed_blocks"))

    async def test_release_without_option_keeps_absorbed_blocks(self):
        await self.absorb("198.51.100.2", 5)
        await self.act(main.ActionIn(action="block_ip", include_absorbed=True))
        await self.act(main.ActionIn(action="unblock_ip"), ADMIN)
        rows = await self.block_rows()
        self.assertIsNotNone(rows[OWN]["released_at"])
        self.assertIsNone(rows["198.51.100.2"]["released_at"])
        # 이 출발지가 풀린 뒤에도 흡수 차단만 따로 풀 수 있다. 그 뒤에는 풀 것이 없어 409
        out = await self.act(main.ActionIn(action="unblock_ip", include_absorbed=True), ADMIN)
        self.assertEqual(out["absorbed"], {"released": 1, "follow_stopped": True})
        with self.assertRaises(main.HTTPException) as error:
            await self.act(main.ActionIn(action="unblock_ip", include_absorbed=True), ADMIN)
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(await self.conn.fetchval("SELECT count(*) FROM actions WHERE action = 'unblock_ip'"), 2)

    async def test_release_one_absorbed_row_keeps_first_incident_block(self):
        # 차단 목록 화면의 흡수 차단 행 해제. 행의 incident_key 는 첫 사건이지만 행의 출발지는 흡수 출발지다.
        # 그 행만 풀고 첫 사건 출발지의 차단은 그대로 둔다
        await self.absorb("198.51.100.2", 5)
        await self.absorb("198.51.100.3", 6)
        await self.act(main.ActionIn(action="block_ip", include_absorbed=True))
        out = await self.act(main.ActionIn(action="unblock_ip", actor_ip="198.51.100.2", note="오탐 출발지"), ADMIN)
        rows = await self.block_rows()
        self.assertEqual(rows["198.51.100.2"]["released_by"], "test-admin")
        self.assertIsNone(rows[OWN]["released_at"])
        self.assertIsNone(rows["198.51.100.3"]["released_at"])
        self.assertEqual(out["absorbed"], {"released": 1, "actor_ip": "198.51.100.2"})
        self.assertEqual(out["note"], "오탐 출발지 [흡수 차단 198.51.100.2 한 곳 해제]")
        # 이미 풀린 행 · 이 사건의 흡수 차단이 아닌 행은 409 다. 첫 사건 출발지의 차단은 그대로다
        await self.conn.execute("INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at) "
                                "VALUES ('198.51.100.9', 'console', $1, now() + interval '1 hour')", FIRST)
        for ip in ("198.51.100.2", "198.51.100.9", "203.0.113.1"):
            with self.subTest(ip=ip), self.assertRaises(main.HTTPException) as error:
                await self.act(main.ActionIn(action="unblock_ip", actor_ip=ip), ADMIN)
            self.assertEqual(error.exception.status_code, 409)
        self.assertIsNone((await self.block_rows())[OWN]["released_at"])
        # 이 사건 출발지를 actor_ip 로 주면 전처럼 이 출발지의 차단을 푼다
        await self.act(main.ActionIn(action="unblock_ip", actor_ip=OWN), ADMIN)
        self.assertIsNotNone((await self.block_rows())[OWN]["released_at"])

    async def test_release_one_row_rejects_mixed_options(self):
        with self.assertRaises(main.HTTPException) as error:
            await self.act(main.ActionIn(action="unblock_ip", actor_ip="198.51.100.2", include_absorbed=True), ADMIN)
        self.assertEqual(error.exception.status_code, 400)
        with self.assertRaises(main.HTTPException) as error:
            await self.act(main.ActionIn(action="block_ip", actor_ip="198.51.100.2"))
        self.assertEqual(error.exception.status_code, 400)
        with self.assertRaises(main.HTTPException) as error:
            await self.act(main.ActionIn(action="unblock_ip", actor_ip="198.51.100.2"), OPERATOR)
        self.assertEqual(error.exception.status_code, 403)
        with self.assertRaises(ValueError):
            main.ActionIn(action="unblock_ip", actor_ip="not-an-ip")

    async def test_release_with_absorbed_still_needs_admin(self):
        with self.assertRaises(main.HTTPException) as error:
            await self.act(main.ActionIn(action="unblock_ip", include_absorbed=True), OPERATOR)
        self.assertEqual(error.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
