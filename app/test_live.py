"""실시간 통보(live.py) 시험 (이슈 #43).  python3 -m unittest discover -s app -p 'test_live.py'

DB 없이 가짜 연결로 본다. 실제 PostgreSQL 로 보는 두 연결 · 연결 끊기 · 잠금 시험은 test_live_db.py 에 있다.

  - 페이로드: opsloop_event 는 {"type", "data": {"incident_key", "id"}} 뿐이다. 8000 바이트를 넘으면 사건 키를 뺀다
  - 받은 통보: 사건 채널은 incident.created 로, 판정 · 조치 채널은 종류와 두 필드만 넘긴다. 모르는 것은 버린다
  - 콘솔 이름: OPSLOOP_WORKER, 없으면 hostname. 64자. 알림 발송기의 기본 이름과 같다
  - 감시: 종료 알림 · SELECT 1 실패 · 시간 초과로 끊김을 안다. 1초 → 2배 → 최대 30초로 다시 붙고 resync 를 보낸다.
    옛 연결의 늦은 종료 알림은 무시한다. 끊김 · 실패 · 재연결을 로그 한 줄씩 남긴다(주소 · 비밀번호는 없다)
  - 기동: 첫 연결이 안 되면 예외로 기동을 실패시키고 풀을 닫는다. 붙으면 두 채널을 듣고 종료 때 닫는다
"""
import asyncio
import json
import os
import socket
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import live  # noqa: E402

DSN = "postgresql://opsloop_console:secret-password@db.example:5432/opsloop"


class RecordingHub:
    def __init__(self):
        self.messages = []

    async def broadcast(self, payload):
        self.messages.append(payload)


class FakeConn:
    """asyncpg 연결 대역. 종료 알림은 close · terminate · die 에서 모두 울린다(asyncpg 와 같다)."""

    def __init__(self, name, ping=None):
        self.name = name
        self.ping = ping
        self.pings = []
        self.listeners = {}
        self.term = []
        self.closed = False
        self.terminated = False

    def add_termination_listener(self, callback):
        self.term.append(callback)

    async def add_listener(self, channel, callback):
        self.listeners[channel] = callback

    async def fetchval(self, sql, *args, timeout=None):
        self.pings.append((sql, timeout))
        if self.ping is not None:
            raise self.ping
        return 1

    def is_closed(self):
        return self.closed

    def _end(self):
        if not self.closed:
            self.closed = True
            for callback in list(self.term):
                callback(self)

    def terminate(self):
        self.terminated = True
        self._end()

    async def close(self):
        self._end()

    def die(self):
        """서버가 연결을 끊었다(pg_terminate_backend · DB 재시작)."""
        self._end()

    def notify(self, channel, payload):
        self.listeners[channel](self, 4242, channel, payload)


class Connector:
    """차례로 연결 또는 예외를 돌려준다. 받은 주소를 기록한다."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    async def __call__(self, dsn):
        self.calls.append(dsn)
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


async def until(predicate, timeout=2.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not predicate():
        if loop.time() > end:
            raise AssertionError("기다린 상태가 오지 않았다")
        await asyncio.sleep(0.005)


class PayloadTest(unittest.TestCase):
    def test_event_payload_shape(self):
        text = live.event_payload("verdict.created", "R001|v2|192.0.2.8|k", 17)
        self.assertEqual(json.loads(text), {"type": "verdict.created",
                                            "data": {"incident_key": "R001|v2|192.0.2.8|k", "id": 17}})
        self.assertEqual(json.loads(live.event_payload("action.created", "k", 3))["type"], "action.created")
        with self.assertRaises(ValueError):
            live.event_payload("incident.created", "k", 1)

    def test_oversized_key_is_dropped_under_limit(self):
        # 한글 키는 UTF-8 로 3바이트다. 글자 수가 아니라 바이트로 잰다
        for key in ("가" * 2700, "k" * 7990, "k" * 20000):
            text = live.event_payload("action.created", key, 9)
            self.assertLess(len(text.encode("utf-8")), live.NOTIFY_MAX)
            self.assertEqual(json.loads(text), {"type": "action.created", "data": {"id": 9}})
        near = "k" * 7900
        self.assertEqual(json.loads(live.event_payload("action.created", near, 9))["data"]["incident_key"], near)

    def test_parse_incident_channel(self):
        self.assertEqual(live.parse_notification("opsloop_incident", '{"incident_key": "k", "severity": "high"}'),
                         {"type": "incident.created", "data": {"incident_key": "k", "severity": "high"}})
        self.assertIsNone(live.parse_notification("opsloop_incident", "{broken"))
        # 한도 안의 깊은 중첩이 콜백 예외로 새지 않는다
        with mock.patch.object(live.json, "loads", side_effect=RecursionError):
            self.assertIsNone(live.parse_notification("opsloop_event", "[" * 3990 + "]" * 3990))

    def test_parse_event_channel_keeps_type_key_and_id_only(self):
        payload = json.dumps({"type": "verdict.created", "data": {"incident_key": "k", "id": 5,
                                                                  "note": "<img src=//x>", "operator": "x"},
                              "extra": 1})
        self.assertEqual(live.parse_notification("opsloop_event", payload),
                         {"type": "verdict.created", "data": {"incident_key": "k", "id": 5}})
        # 사건 키가 빠진 통보(8000 바이트 초과)는 id 만
        self.assertEqual(live.parse_notification("opsloop_event", '{"type": "action.created", "data": {"id": 2}}'),
                         {"type": "action.created", "data": {"id": 2}})
        # 형이 틀린 값은 넘기지 않는다
        self.assertEqual(live.parse_notification(
            "opsloop_event", '{"type": "action.created", "data": {"incident_key": 3, "id": true}}'),
            {"type": "action.created", "data": {}})
        for bad in ('{"type": "incident.created", "data": {}}', '{"type": "resync"}', '["verdict.created"]',
                    '"verdict.created"', "{broken", '{"type": "hello", "data": {"console": "x"}}'):
            self.assertIsNone(live.parse_notification("opsloop_event", bad), bad)
        self.assertIsNone(live.parse_notification("other_channel", '{"type": "verdict.created", "data": {}}'))


class ConsoleNameTest(unittest.TestCase):
    def test_worker_env_or_hostname_clipped(self):
        with mock.patch.dict(os.environ, {"OPSLOOP_WORKER": "opsloop-console-b"}):
            self.assertEqual(live.console_name(), "opsloop-console-b")
        with mock.patch.dict(os.environ, {"OPSLOOP_WORKER": "x" * 100}):
            self.assertEqual(live.console_name(), "x" * 64)
        with mock.patch.dict(os.environ, {"OPSLOOP_WORKER": ""}):
            self.assertEqual(live.console_name(), socket.gethostname()[:64])

    def test_notifier_default_name_is_the_console_name(self):
        import notifier
        for env in ({"OPSLOOP_WORKER": "opsloop-console-a"}, {"OPSLOOP_WORKER": ""}):
            with mock.patch.dict(os.environ, env):
                self.assertEqual(notifier.Notifier(pool=None).worker, live.console_name())
        self.assertEqual(notifier.Notifier(pool=None, worker="test-a").worker, "test-a")


class ListenerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.hub = RecordingHub()
        self.delays = []

    async def record_sleep(self, delay):
        self.delays.append(delay)
        await asyncio.sleep(0)

    def listener(self, connector, **kw):
        listener = live.Listener(DSN, self.hub, connect=connector, **kw)
        listener._sleep = self.record_sleep
        self.addAsyncCleanup(listener.stop)
        return listener

    async def test_listens_on_both_channels_and_forwards(self):
        conn = FakeConn("a")
        connector = Connector(conn)
        listener = self.listener(connector, ping_interval=60)
        await listener.start()
        self.assertEqual(connector.calls, [DSN])
        self.assertEqual(set(conn.listeners), {"opsloop_incident", "opsloop_event"})
        conn.notify("opsloop_incident", '{"incident_key": "k1"}')
        conn.notify("opsloop_event", live.event_payload("verdict.created", "k1", 7))
        conn.notify("opsloop_event", live.event_payload("action.created", "k1", 8))
        conn.notify("opsloop_event", "{broken")
        await until(lambda: len(self.hub.messages) >= 3)
        await asyncio.sleep(0.01)
        self.assertEqual(self.hub.messages, [
            {"type": "incident.created", "data": {"incident_key": "k1"}},
            {"type": "verdict.created", "data": {"incident_key": "k1", "id": 7}},
            {"type": "action.created", "data": {"incident_key": "k1", "id": 8}}])

    async def test_termination_reconnects_with_backoff_and_resyncs(self):
        first, second = FakeConn("a"), FakeConn("b")
        failures = [OSError("password=secret-password")] * 6
        connector = Connector(first, *failures, second)
        listener = self.listener(connector, ping_interval=60)
        await listener.start()
        with self.assertLogs("opsloop.live", "WARNING") as logs:
            first.die()
            await until(lambda: listener.reconnects == 1)
            await until(lambda: self.hub.messages)
        self.assertEqual(self.delays, [1, 2, 4, 8, 16, 30, 30])
        self.assertIs(listener.conn, second)
        self.assertEqual(connector.calls, [DSN] * 8)
        self.assertEqual(self.hub.messages, [{"type": "resync"}])
        self.assertEqual(set(second.listeners), {"opsloop_incident", "opsloop_event"})
        # 끊김 한 줄 · 실패 여섯 줄(회차 · 다음 간격) · 다시 붙음 한 줄. 주소 · 비밀번호 · 예외 문구는 남기지 않는다
        self.assertEqual(len(logs.output), 8)
        self.assertIn("끊김(종료 알림)", logs.output[0])
        self.assertIn("1회째 실패(OSError). 2초 뒤 다시", logs.output[1])
        self.assertIn("6회째 실패(OSError). 30초 뒤 다시", logs.output[6])
        self.assertIn("다시 붙음(7회째 시도", logs.output[7])
        self.assertIn("resync", logs.output[7])
        for line in logs.output:
            self.assertNotIn("secret-password", line)
            self.assertNotIn("db.example", line)
        # 새 연결의 통보가 그대로 온다
        second.notify("opsloop_incident", '{"incident_key": "k2"}')
        await until(lambda: len(self.hub.messages) == 2)
        self.assertEqual(self.hub.messages[1]["type"], "incident.created")

    async def test_late_termination_of_old_connection_is_ignored(self):
        first, second = FakeConn("a"), FakeConn("b")
        listener = self.listener(Connector(first, second), ping_interval=60)
        await listener.start()
        with self.assertLogs("opsloop.live", "WARNING"):
            first.die()
            await until(lambda: listener.reconnects == 1)
        for callback in first.term:
            callback(first)
        await asyncio.sleep(0.02)
        self.assertEqual(listener.reconnects, 1)
        self.assertIs(listener.conn, second)
        self.assertFalse(listener._lost.is_set())

    async def test_ping_failure_and_timeout_count_as_lost(self):
        for error, reason in ((ConnectionResetError(), "SELECT 1 실패 ConnectionResetError"),
                              (TimeoutError(), "SELECT 1 5초 초과")):
            with self.subTest(reason=reason):
                self.hub.messages.clear()
                first, second = FakeConn("a", ping=error), FakeConn("b")
                listener = self.listener(Connector(first, second), ping_interval=0.01)
                await listener.start()
                with self.assertLogs("opsloop.live", "WARNING") as logs:
                    await until(lambda: listener.reconnects == 1)
                    await until(lambda: self.hub.messages)
                self.assertIn(f"끊김({reason})", logs.output[0])
                self.assertEqual(first.pings[0], ("SELECT 1", 5))
                # 조용히 끊긴 연결은 인사 없이 버린다
                self.assertTrue(first.terminated)
                self.assertEqual(self.hub.messages, [{"type": "resync"}])
                await listener.stop()

    async def test_healthy_ping_keeps_connection(self):
        conn = FakeConn("a")
        listener = self.listener(Connector(conn), ping_interval=0.01)
        await listener.start()
        await until(lambda: len(conn.pings) >= 3)
        self.assertEqual(listener.reconnects, 0)
        self.assertIs(listener.conn, conn)
        self.assertEqual(self.hub.messages, [])

    async def test_first_connect_failure_raises(self):
        listener = self.listener(Connector(OSError("refused")))
        with self.assertRaises(OSError):
            await listener.start()
        self.assertIsNone(listener.task)
        self.assertIsNone(listener.conn)

    async def test_stop_closes_without_reconnect(self):
        conn = FakeConn("a")
        connector = Connector(conn)
        listener = self.listener(connector, ping_interval=60)
        await listener.start()
        await listener.stop()
        self.assertTrue(conn.closed)
        self.assertFalse(conn.terminated)
        self.assertIsNone(listener.task)
        self.assertIsNone(listener.conn)
        await asyncio.sleep(0.01)
        self.assertEqual(connector.calls, [DSN])


class HubTest(unittest.IsolatedAsyncioTestCase):
    async def test_broadcast_drops_dead_clients(self):
        hub = live.Hub()
        good = mock.Mock(accept=mock.AsyncMock(), send_json=mock.AsyncMock())
        dead = mock.Mock(accept=mock.AsyncMock(), send_json=mock.AsyncMock(side_effect=RuntimeError()))
        await hub.join(good)
        await hub.join(dead)
        await hub.broadcast({"type": "resync"})
        good.send_json.assert_awaited_once_with({"type": "resync"})
        self.assertEqual(hub.clients, {good})


class LifespanTest(unittest.IsolatedAsyncioTestCase):
    """main.lifespan: 첫 LISTEN 연결이 안 되면 기동 실패 · 풀 닫기. 붙으면 main.hub 로 넘기고 종료 때 닫는다."""

    async def asyncSetUp(self):
        import main
        self.main = main
        saved = dict(main.app.state._state)
        self.addCleanup(lambda: (main.app.state._state.clear(), main.app.state._state.update(saved)))
        self.pool = SimpleNamespace(closed=False)

        async def close():
            self.pool.closed = True
        self.pool.close = close

        async def create_pool(*_a, **_k):
            return self.pool
        self.side = SimpleNamespace(start=mock.AsyncMock(), stop=mock.AsyncMock())
        for patcher in (mock.patch.object(main, "DATABASE_URL", DSN),
                        mock.patch.object(main.asyncpg, "create_pool", create_pool),
                        mock.patch.object(main, "Notifier", mock.Mock(return_value=self.side)),
                        mock.patch.object(main, "AbsorbedFollower", mock.Mock(return_value=self.side))):
            patcher.start()
            self.addCleanup(patcher.stop)

    async def test_first_listen_failure_fails_startup(self):
        with mock.patch.object(live, "_asyncpg_connect", Connector(OSError("refused"))):
            with self.assertRaises(OSError):
                async with self.main.lifespan(self.main.app):
                    self.fail("기동하면 안 된다")
        self.assertTrue(self.pool.closed)
        self.side.start.assert_not_awaited()

    async def test_listener_runs_for_app_lifetime(self):
        conn = FakeConn("a")
        with mock.patch.object(live, "_asyncpg_connect", Connector(conn)):
            async with self.main.lifespan(self.main.app):
                listener = self.main.app.state.listener
                self.assertIs(listener.hub, self.main.hub)
                self.assertIs(self.main.hub, live.hub)
                self.assertIs(listener.conn, conn)
                self.assertIsNotNone(listener.task)
        self.assertTrue(conn.closed)
        self.assertIsNone(listener.task)
        self.assertTrue(self.pool.closed)


if __name__ == "__main__":
    unittest.main(verbosity=1)
