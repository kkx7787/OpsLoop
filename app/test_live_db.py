"""실시간 통보 · 사건 행 잠금 PostgreSQL 시험 (이슈 #43). OPSLOOP_TEST_DATABASE_URL 이 있을 때만 돈다.

연결 여럿이 같은 표를 봐야 하므로 이름이 무작위인 스키마를 만들고 끝나면 지운다(외래 키는 schema.sql 과 같다).
NOTIFY 채널은 DB 전체에 하나라 시험은 사건 키로 제 통보만 골라 본다.

  - 두 연결: 한 연결이 판정 · 조치를 기록하면 다른 연결의 Listener 둘(콘솔 A · B)이 모두 verdict.created ·
    action.created 를 받는다. 되돌려진 기록(404 · 409)은 알리지 않는다. hub.broadcast 를 직접 부르지 않는다
  - 커밋 때만: 통보 문장을 돌린 뒤 커밋 전에는 어느 화면에도 가지 않고, 통보 뒤에 되돌려지면 나가지 않는다.
    404 · 409 는 통보 문장 전에 끝나므로 이것을 보이지 못한다. 통보를 트랜잭션 밖 연결로 보내게 바뀌면 여기서 드러난다
  - 연결 끊기: pg_terminate_backend 로 LISTEN 연결을 끊으면 다시 붙고 resync 를 보낸 뒤 통보를 다시 받는다
  - 잠금: 판정 · 조치는 사건 행을 먼저 잠근다. 앞 트랜잭션이 사건 행을 쥐고 있으면 뒤 판정 · 조치는 아무것도 쓰지
    않고 기다렸다가 앞의 결과 위에 쓴다(상태가 커밋 순서를 따른다)
  - 교착 없음: 흡수 후속 차단(AbsorbedFollower)이 차단 목록 행을 쥔 사이 같은 첫 사건의 함께 차단이 와도 둘 다 끝난다
  - 페이로드 한도: 사건 키를 뺀 페이로드는 pg_notify 가 받고, 넘친 원래 모양은 거부된다
"""
import asyncio
import json
import os
import secrets
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import absorbed as absorbed_mod
import live
import main

DSN = os.environ.get("OPSLOOP_TEST_DATABASE_URL")
KEY = "R006|v3|192.0.2.1|2026-09-26T00:00:00+00:00"
OWN = "192.0.2.1"
T0 = datetime(2026, 9, 26, tzinfo=timezone.utc)
OPERATOR = SimpleNamespace(state=SimpleNamespace(user={"u": "test-operator", "r": "operator"}))
ADMIN = SimpleNamespace(state=SimpleNamespace(user={"u": "test-admin", "r": "admin"}))

TABLES = """
    CREATE TABLE incidents (incident_key text PRIMARY KEY, rule_id text NOT NULL, rule_version text NOT NULL,
        rule_name text, severity text NOT NULL, actor_ip inet, target text, first_ts timestamptz NOT NULL,
        last_ts timestamptz NOT NULL, signal_count integer NOT NULL, session_count integer, evidence jsonb,
        status text NOT NULL DEFAULT 'open', created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE actions (id bigserial PRIMARY KEY,
        incident_key text NOT NULL REFERENCES incidents (incident_key) ON DELETE CASCADE,
        action text NOT NULL, operator text, note text, created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE verdicts (id bigserial PRIMARY KEY,
        incident_key text NOT NULL REFERENCES incidents (incident_key) ON DELETE CASCADE,
        verdict text NOT NULL, reason text, observed_value double precision, operator text, proposed text,
        decision_seconds integer, created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE blocklist (actor_ip inet PRIMARY KEY, reason text, incident_key text,
        created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz, released_at timestamptz,
        method text, requested_by text, enforced_at timestamptz, enforce_note text, released_by text);
    CREATE TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL);
    CREATE TABLE absorbed_blocks (first_key text PRIMARY KEY, expires_at timestamptz NOT NULL, requested_by text,
        created_at timestamptz NOT NULL DEFAULT now(), released_at timestamptz, released_by text);
    CREATE TABLE incident_absorbed (first_key text NOT NULL, member_key text NOT NULL, kind text NOT NULL,
        via_key text, rule_id text NOT NULL, rule_version text NOT NULL, actor_ip inet,
        first_ts timestamptz NOT NULL, last_ts timestamptz NOT NULL, signal_count integer NOT NULL,
        sessions text[] NOT NULL DEFAULT '{}', payloads text[] NOT NULL DEFAULT '{}',
        recorded_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (first_key, member_key));
"""


class RecordingHub:
    def __init__(self):
        self.messages = []

    async def broadcast(self, payload):
        self.messages.append(payload)

    def about(self, key):
        return [m for m in self.messages if (m.get("data") or {}).get("incident_key") == key]


class Pool:
    """정해 둔 연결을 차례로 빌려준다. 먼저 빌린 쪽이 앞 연결을 받는다."""

    def __init__(self, *conns):
        self.free = asyncio.Queue()
        for conn in conns:
            self.free.put_nowait(conn)

    @asynccontextmanager
    async def acquire(self):
        conn = await self.free.get()
        try:
            yield conn
        finally:
            self.free.put_nowait(conn)


class GatedConn:
    """처음으로 match 에 맞는 문장을 돌린 직후 멈춘다(reached 를 켜고 gate 를 기다린다). 나머지는 진짜 연결로 넘긴다.
    트랜잭션 한가운데서 멈춰, 그 사이 다른 연결이 무엇을 기다리는지 본다."""

    def __init__(self, conn, match):
        self._conn = conn
        self._match = match
        self._done = False
        self.reached = asyncio.Event()
        self.gate = asyncio.Event()

    def __getattr__(self, name):
        return getattr(self._conn, name)

    async def _run(self, method, sql, *args, **kw):
        result = await getattr(self._conn, method)(sql, *args, **kw)
        if not self._done and self._match(sql):
            self._done = True
            self.reached.set()
            await self.gate.wait()
        return result

    async def execute(self, sql, *args, **kw):
        return await self._run("execute", sql, *args, **kw)

    async def fetch(self, sql, *args, **kw):
        return await self._run("fetch", sql, *args, **kw)

    async def fetchrow(self, sql, *args, **kw):
        return await self._run("fetchrow", sql, *args, **kw)

    async def fetchval(self, sql, *args, **kw):
        return await self._run("fetchval", sql, *args, **kw)


class FailingConn(GatedConn):
    """match 에 맞는 문장을 돌린 직후 예외를 던진다. 그 문장까지 쓴 트랜잭션이 되돌려지는 길을 만든다."""

    async def _run(self, method, sql, *args, **kw):
        result = await getattr(self._conn, method)(sql, *args, **kw)
        if self._match(sql):
            raise RuntimeError("시험: 통보 뒤 실패")
        return result


async def until(predicate, timeout=10.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not predicate():
        if loop.time() > end:
            raise AssertionError("기다린 상태가 오지 않았다")
        await asyncio.sleep(0.02)


@unittest.skipUnless(DSN, "PostgreSQL 시험 연결 미지정")
class LiveDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncpg
        self.asyncpg = asyncpg
        self.schema = "t43_" + secrets.token_hex(4)
        self.admin = await asyncpg.connect(DSN)
        await self.admin.execute(f"CREATE SCHEMA {self.schema}")
        self.conns = []
        self.a = await self.connect()
        self.b = await self.connect()
        await self.a.execute(TABLES)
        await self.incident(KEY)
        self.state_patch = patch.object(main.app.state, "pool", Pool(self.a, self.b), create=True)
        self.state_patch.start()

    async def asyncTearDown(self):
        self.state_patch.stop()
        for conn in self.conns:
            if not conn.is_closed():
                conn.terminate()
        await self.admin.execute(f"DROP SCHEMA {self.schema} CASCADE")
        await self.admin.close()

    async def connect(self):
        conn = await self.asyncpg.connect(DSN, server_settings={"search_path": self.schema})
        self.conns.append(conn)
        return conn

    async def incident(self, key, ip=OWN, rule="R006"):
        await self.a.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
            actor_ip, first_ts, last_ts, signal_count, session_count)
            VALUES ($1, $2, 'v3', '시험 규칙', 'critical', $3, $4, $4, 1, 1)""", key, rule, ip, T0)

    async def listener(self, hub):
        listener = live.Listener(DSN, hub)
        await listener.start()
        self.addAsyncCleanup(listener.stop)
        return listener

    # ------------------------------------------------------------ 두 연결

    async def test_verdict_and_action_reach_both_consoles(self):
        hub_a, hub_b = RecordingHub(), RecordingHub()
        await self.listener(hub_a)
        await self.listener(hub_b)
        with patch.object(main.hub, "broadcast", AsyncMock()) as direct:
            verdict = await main.add_verdict(KEY, main.VerdictIn(verdict="threat", reason="시험"), OPERATOR)
            action = await main.add_action(KEY, main.ActionIn(action="acknowledge"), OPERATOR)
            # 되돌려진 기록은 알리지 않는다: 없는 사건(404) · 풀 차단 없음(409)
            with self.assertRaises(main.HTTPException) as missing:
                await main.add_verdict("R001|v2|none", main.VerdictIn(verdict="threat"), OPERATOR)
            self.assertEqual(missing.exception.status_code, 404)
            with self.assertRaises(main.HTTPException) as conflict:
                await main.add_action(KEY, main.ActionIn(action="unblock_ip"), ADMIN)
            self.assertEqual(conflict.exception.status_code, 409)
        direct.assert_not_awaited()
        # 응답 본문은 그대로다
        self.assertEqual((verdict["incident_key"], verdict["verdict"], verdict["operator"]), (KEY, "threat", "test-operator"))
        self.assertEqual((action["incident_key"], action["action"]), (KEY, "acknowledge"))
        want = [{"type": "verdict.created", "data": {"incident_key": KEY, "id": verdict["id"]}},
                {"type": "action.created", "data": {"incident_key": KEY, "id": action["id"]}}]
        for hub in (hub_a, hub_b):
            await until(lambda: len(hub.about(KEY)) >= 2)
        await asyncio.sleep(0.2)
        for hub in (hub_a, hub_b):
            self.assertEqual(hub.about(KEY), want)
            self.assertEqual([m for m in hub.messages if m["type"] in live.EVENT_TYPES and m not in want], [])

    async def test_event_leaves_only_on_commit(self):
        """통보는 판정 · 조치와 같은 트랜잭션에서 나간다. 커밋 전에는 가지 않고, 통보 뒤에 되돌려지면 가지 않는다.
        NOTIFY 는 커밋 순서대로 온다. 그래서 뒤에 보낸 표지가 도착했을 때 앞선 통보가 없으면 나가지 않은 것이다."""
        hub = RecordingHub()
        await self.listener(hub)

        async def marker(name):
            await self.admin.execute("SELECT pg_notify($1, $2)", live.INCIDENT_CHANNEL,
                                     json.dumps({"incident_key": name}))
            await until(lambda: hub.about(name))

        # 통보 문장을 돌린 직후 멈춘다. 커밋 전이다
        gated = GatedConn(self.a, lambda sql: "pg_notify" in sql)
        main.app.state.pool = Pool(gated)
        task = asyncio.create_task(main.add_verdict(KEY, main.VerdictIn(verdict="threat"), OPERATOR))
        await asyncio.wait_for(gated.reached.wait(), 5)
        await marker("t43-before-commit")
        self.assertEqual(hub.about(KEY), [], "커밋 전에는 나가지 않는다")
        gated.gate.set()
        verdict = await asyncio.wait_for(task, 10)
        await until(lambda: hub.about(KEY))
        self.assertEqual(hub.about(KEY), [{"type": "verdict.created", "data": {"incident_key": KEY, "id": verdict["id"]}}])

        # 통보 문장 뒤에 실패하면 트랜잭션이 되돌려지고 통보도 나가지 않는다
        hub.messages.clear()
        main.app.state.pool = Pool(FailingConn(self.a, lambda sql: "pg_notify" in sql))
        with self.assertRaises(RuntimeError):
            await main.add_action(KEY, main.ActionIn(action="note", note="되돌림"), OPERATOR)
        await marker("t43-after-rollback")
        self.assertEqual(hub.about(KEY), [], "되돌려진 조치는 알리지 않는다")
        self.assertEqual(await self.a.fetchval("SELECT count(*) FROM actions WHERE incident_key = $1", KEY), 0)

    async def test_payload_limit_is_real(self):
        big = "k" * 8000
        with self.assertRaises(self.asyncpg.exceptions.InvalidParameterValueError):
            await self.admin.execute("SELECT pg_notify($1, $2)", live.EVENT_CHANNEL,
                                     json.dumps({"type": "verdict.created", "data": {"incident_key": big, "id": 1}}))
        hub = RecordingHub()
        await self.listener(hub)
        await self.admin.execute("SELECT pg_notify($1, $2)", live.EVENT_CHANNEL,
                                 live.event_payload("verdict.created", big, 424242))
        await until(lambda: {"type": "verdict.created", "data": {"id": 424242}} in hub.messages)

    # ------------------------------------------------------------ 연결 끊기

    async def test_terminated_listener_reconnects_and_resyncs(self):
        hub = RecordingHub()
        listener = await self.listener(hub)
        pid = listener.conn.get_server_pid()
        with self.assertLogs("opsloop.live", "WARNING") as logs:
            self.assertTrue(await self.admin.fetchval("SELECT pg_terminate_backend($1)", pid))
            await until(lambda: {"type": "resync"} in hub.messages)
        self.assertEqual(listener.reconnects, 1)
        self.assertNotEqual(listener.conn.get_server_pid(), pid)
        self.assertIn("끊김(종료 알림)", logs.output[0])
        self.assertIn("다시 붙음(1회째 시도", logs.output[-1])
        # 다시 붙은 연결로 두 채널을 모두 받는다
        verdict = await main.add_verdict(KEY, main.VerdictIn(verdict="threat"), OPERATOR)
        await self.admin.execute("SELECT pg_notify('opsloop_incident', $1)", json.dumps({"incident_key": "t43-new"}))
        await until(lambda: hub.about(KEY) and hub.about("t43-new"))
        self.assertEqual(hub.about(KEY), [{"type": "verdict.created", "data": {"incident_key": KEY, "id": verdict["id"]}}])
        self.assertEqual(hub.about("t43-new")[0]["type"], "incident.created")

    # ------------------------------------------------------------ 잠금

    async def hold_then_race(self, first, second):
        """first 가 사건 행을 처음 건드린 직후 멈춘 사이 second 를 띄운다. second 가 기다리는지 보고 풀어 준다.
        돌려주는 값: (first 결과, second 결과, 멈춘 사이 second 가 끝났는가, second 의 대기 종류)."""
        gated = GatedConn(self.a, lambda sql: "FROM incidents" in sql)
        main.app.state.pool = Pool(gated, self.b)
        task_a = asyncio.create_task(first())
        await asyncio.wait_for(gated.reached.wait(), 5)
        task_b = asyncio.create_task(second())
        await asyncio.sleep(0.5)
        finished_early = task_b.done()
        waiting = await self.admin.fetchval("SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1",
                                            self.b.get_server_pid())
        gated.gate.set()
        return await asyncio.wait_for(task_a, 10), await asyncio.wait_for(task_b, 10), finished_early, waiting

    async def test_concurrent_verdicts_run_in_turn(self):
        first, second, finished_early, waiting = await self.hold_then_race(
            lambda: main.add_verdict(KEY, main.VerdictIn(verdict="threat"), OPERATOR),
            lambda: main.add_verdict(KEY, main.VerdictIn(verdict="false_positive"), OPERATOR))
        self.assertFalse(finished_early, "앞 판정이 사건 행을 쥔 동안 뒤 판정은 끝나지 않는다")
        self.assertEqual(waiting, "Lock")
        self.assertLess(first["id"], second["id"])
        rows = await self.a.fetch("SELECT verdict FROM verdicts WHERE incident_key = $1 ORDER BY id", KEY)
        self.assertEqual([r["verdict"] for r in rows], ["threat", "false_positive"])
        self.assertEqual(await self.a.fetchval("SELECT status FROM incidents WHERE incident_key = $1", KEY), "resolved")

    async def test_action_waits_for_verdict_and_status_follows_commit_order(self):
        _, action, finished_early, waiting = await self.hold_then_race(
            lambda: main.add_verdict(KEY, main.VerdictIn(verdict="threat"), OPERATOR),
            lambda: main.add_action(KEY, main.ActionIn(action="acknowledge"), OPERATOR))
        self.assertFalse(finished_early, "판정이 사건 행을 쥔 동안 조치는 아무것도 쓰지 않고 기다린다")
        self.assertEqual(waiting, "Lock")
        self.assertEqual(action["action"], "acknowledge")
        # 조치가 판정 뒤에 커밋됐다. 상태도 조치의 것이다(판정이 늦게 커밋돼 조치 상태를 덮지 않는다)
        self.assertEqual(await self.a.fetchval("SELECT status FROM incidents WHERE incident_key = $1", KEY),
                         "acknowledged")

    async def test_follower_and_absorbed_block_do_not_deadlock(self):
        """후속 차단이 흡수 출발지의 차단 목록 행을 쥔 사이 같은 첫 사건의 함께 차단이 온다. 잠금 순서가 같으면
        함께 차단이 사건 행에서 기다렸다가 끝나고, 어긋나면 교착으로 한쪽이 실패한다."""
        await self.a.execute("""INSERT INTO rule_versions VALUES ('v3', '{"rules": [
            {"id": "R006", "params": {"absorb_same_payload": {"window_hours": 24, "max_sources": 100}}}]}')""")
        await self.a.execute("INSERT INTO absorbed_blocks (first_key, expires_at, requested_by) "
                             "VALUES ($1, now() + interval '24 hours', 'test-operator')", KEY)
        for n, ip in enumerate(("198.51.100.2", "198.51.100.3")):
            await self.a.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, rule_id, rule_version,
                actor_ip, first_ts, last_ts, signal_count) VALUES ($1, $2, 'absorbed', 'R006', 'v3', $3, $4, $4, 1)""",
                KEY, f"R006|v3|{ip}|{n}", ip, T0 + timedelta(minutes=n))
        follower = absorbed_mod.AbsorbedFollower(pool=None)
        gated = GatedConn(self.a, lambda sql: sql == absorbed_mod.BLOCK_ABSORBED_SQL)
        main.app.state.pool = Pool(self.b)
        follow = asyncio.create_task(follower.step(gated))
        await asyncio.wait_for(gated.reached.wait(), 5)
        block = asyncio.create_task(main.add_action(
            KEY, main.ActionIn(action="block_ip", include_absorbed=True, expires_hours=48), OPERATOR))
        await asyncio.sleep(0.5)
        self.assertFalse(block.done())
        gated.gate.set()
        done = await asyncio.wait_for(follow, 10)
        result = await asyncio.wait_for(block, 10)
        self.assertEqual(done, [(KEY, 2)])
        self.assertEqual(result["absorbed"]["blocked"], 2)
        rows = await self.a.fetch("SELECT host(actor_ip) ip, incident_key FROM blocklist ORDER BY actor_ip")
        self.assertEqual([(r["ip"], r["incident_key"]) for r in rows],
                         [(OWN, KEY), ("198.51.100.2", KEY), ("198.51.100.3", KEY)])
        self.assertEqual(await self.a.fetchval("SELECT status FROM incidents WHERE incident_key = $1", KEY),
                         "in_progress")


if __name__ == "__main__":
    unittest.main(verbosity=1)
