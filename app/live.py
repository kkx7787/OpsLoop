"""실시간 통보 (이슈 #43). 접속한 화면에 사건 · 판정 · 조치를 밀어 준다.

  Hub       이 콘솔에 붙은 웹소켓들. 받은 통보를 모두에게 보낸다. 다른 콘솔의 화면은 그 콘솔의 Hub 가 맡는다.
  Listener  PostgreSQL LISTEN 전용 연결 하나. 두 채널을 듣고 Hub 로 넘긴다. 끊기면 다시 붙는다.

채널
  opsloop_incident  탐지가 인시던트를 넣으면 트리거가 보낸다(infra/notify.sql) → incident.created
  opsloop_event     콘솔이 판정 · 조치를 기록한 트랜잭션에서 보낸다(main.add_verdict · add_action) →
                    verdict.created · action.created. 커밋 때 나가므로 되돌려진 기록은 알리지 않는다.
                    요청을 받은 콘솔만이 아니라 두 콘솔이 모두 받는다. 콘솔 B 화면도 A 에서 한 판정을 본다.
                    페이로드는 {"type": …, "data": {"incident_key": …, "id": …}} 뿐이다. 화면은 내용을 그리지 않고
                    그 사건의 쿼리를 무효화해 REST 로 다시 받는다.

끊김
  DB 재시작 · 망 끊김 뒤 LISTEN 연결이 다시 붙지 않으면 incident.created 가 조용히 멈춘다(2026-09-25 약 2시간).
  종료 알림(add_termination_listener)과 15초마다 SELECT 1(5초 한도)로 끊김을 알고, 1초 → 2배 → 최대 30초 간격으로
  다시 붙는다. 다시 붙으면 모든 화면에 {"type": "resync"} 를 보낸다. 끊긴 동안 놓친 통보는 화면이 전부 다시 받아 메운다.
  /health 에는 넣지 않는다. DB 가 잠깐 흔들려도 두 콘솔이 함께 빠지지 않게 한다. 상태는 로그 한 줄로 남긴다.
  기동 때 첫 연결이 안 되면 예외로 기동을 실패시킨다(풀 만들기와 같다). 헬스체크가 빠져 다른 콘솔이 받는다.
"""
import asyncio
import json
import logging
import os
import socket
import time

log = logging.getLogger("opsloop.live")

INCIDENT_CHANNEL = "opsloop_incident"
EVENT_CHANNEL = "opsloop_event"
EVENT_TYPES = frozenset({"verdict.created", "action.created"})
# NOTIFY 페이로드는 이 바이트 수보다 짧아야 한다(PostgreSQL 기본 설정).
NOTIFY_MAX = 8000

PING_INTERVAL = 15      # 살아 있는지 보는 간격(초)
PING_TIMEOUT = 5        # SELECT 1 한도(초)
BACKOFF_FIRST = 1       # 끊긴 뒤 첫 시도까지(초). 시도마다 2배
BACKOFF_MAX = 30
# 연결 한 번의 한도(초). asyncpg 기본(60초)이면 망이 조용히 끊긴 동안 한 시도에 1분씩 묶인다.
CONNECT_TIMEOUT = 10


def console_name() -> str:
    """이 콘솔의 이름. 알림 발송기(notifier.Notifier)의 기본 이름과 같다.

    OPSLOOP_WORKER(compose 가 opsloop-console-a · opsloop-console-b 로 준다)가 없으면 hostname 이다. 64자에서 자른다.
    화면의 연결 표시(hello) · /api/me 에 싣는다. 세션 뒤에서만 나가고 응답 헤더로는 내지 않는다(이슈 #41).
    """
    return (os.environ.get("OPSLOOP_WORKER") or socket.gethostname())[:64]


CONSOLE_NAME = console_name()


def event_payload(kind: str, incident_key: str, row_id) -> str:
    """opsloop_event 로 보낼 페이로드(JSON 글). NOTIFY_MAX 를 넘으면 사건 키를 뺀다. 화면은 목록만 무효화한다."""
    if kind not in EVENT_TYPES:
        raise ValueError(f"모르는 통보 종류: {kind}")
    text = json.dumps({"type": kind, "data": {"incident_key": incident_key, "id": row_id}},
                      ensure_ascii=False, separators=(",", ":"))
    if len(text.encode("utf-8")) >= NOTIFY_MAX:
        text = json.dumps({"type": kind, "data": {"id": row_id}}, separators=(",", ":"))
    return text


def parse_notification(channel: str, payload: str):
    """받은 NOTIFY 하나를 화면에 보낼 통보로 바꾼다. 모르는 채널 · 모양이면 None.

    같은 DB 에 붙는 역할은 누구나 NOTIFY 를 보낼 수 있다. opsloop_event 는 종류와 두 필드(사건 키 · 행 id)만
    넘긴다. 화면에 그 밖의 값이 흘러가지 않게 한다.
    """
    try:
        data = json.loads(payload)
    except (TypeError, ValueError, RecursionError):   # 8000 바이트 안의 깊은 중첩도 버린다
        return None
    if channel == INCIDENT_CHANNEL:
        return {"type": "incident.created", "data": data}
    if channel != EVENT_CHANNEL or not isinstance(data, dict) or data.get("type") not in EVENT_TYPES:
        return None
    body = data.get("data") if isinstance(data.get("data"), dict) else {}
    out = {}
    if isinstance(body.get("incident_key"), str):
        out["incident_key"] = body["incident_key"]
    if isinstance(body.get("id"), int) and not isinstance(body.get("id"), bool):
        out["id"] = body["id"]
    return {"type": data["type"], "data": out}


class Hub:
    """접속한 화면들에게 통보를 밀어 준다."""

    def __init__(self):
        self.clients: set = set()
        self.lock = asyncio.Lock()

    async def join(self, ws):
        await ws.accept()
        async with self.lock:
            self.clients.add(ws)

    async def leave(self, ws):
        async with self.lock:
            self.clients.discard(ws)

    async def broadcast(self, payload: dict):
        async with self.lock:
            targets = list(self.clients)
        dead = []
        for ws in targets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        if dead:
            async with self.lock:
                for ws in dead:
                    self.clients.discard(ws)


hub = Hub()


async def _asyncpg_connect(dsn):
    import asyncpg
    return await asyncpg.connect(dsn, timeout=CONNECT_TIMEOUT)


class Listener:
    """LISTEN 전용 연결 하나를 들고 두 채널의 통보를 Hub 로 넘긴다. 풀에서 빌린 연결로 LISTEN 하면 반납될 때 끊긴다.

    역할 연결 수: 콘솔 한 대 = 풀 최대 10 + 이 연결 1. 다시 붙을 때는 옛 연결을 버린 뒤 연다(겹치지 않는다).
    """

    def __init__(self, dsn, hub: Hub, *, connect=None, ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT,
                 backoff_first=BACKOFF_FIRST, backoff_max=BACKOFF_MAX):
        self.dsn = dsn
        self.hub = hub
        self.connect = connect or _asyncpg_connect
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.backoff_first = backoff_first
        self.backoff_max = backoff_max
        self.conn = None
        self.task: asyncio.Task | None = None
        self.reconnects = 0          # 다시 붙은 횟수(시험 · 점검용)
        self._lost: asyncio.Event | None = None
        self._sending: set[asyncio.Task] = set()
        self._sleep = asyncio.sleep  # 시험이 기다림 간격을 기록하려고 바꿔 끼운다

    async def start(self):
        """첫 연결. 실패하면 예외를 그대로 올려 기동을 실패시킨다. 붙으면 감시 루프를 띄운다."""
        self._lost = asyncio.Event()
        await self._open()
        self.task = asyncio.create_task(self._watch(), name="live-listen")

    async def stop(self):
        task, self.task = self.task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        conn, self.conn = self.conn, None
        if conn is not None and not conn.is_closed():
            try:
                await asyncio.wait_for(conn.close(), self.ping_timeout)
            except Exception:
                conn.terminate()
        for sending in list(self._sending):
            sending.cancel()

    # ------------------------------------------------------------ 연결

    async def _open(self):
        conn = await self.connect(self.dsn)
        # 종료 알림이 붙이는 중에 와도 놓치지 않게 먼저 지금 연결로 둔다. 옛 연결의 늦은 알림은 _on_terminate 가 거른다.
        self.conn = conn
        self._lost.clear()
        try:
            conn.add_termination_listener(self._on_terminate)
            await conn.add_listener(INCIDENT_CHANNEL, self._on_notify)
            await conn.add_listener(EVENT_CHANNEL, self._on_notify)
        except BaseException:
            self.conn = None
            conn.terminate()
            raise

    def _drop(self):
        """끊긴 연결을 버린다. 끊긴 연결에 close() 는 인사를 기다리다 멈출 수 있어 terminate() 로 닫는다."""
        conn, self.conn = self.conn, None
        if conn is not None and not conn.is_closed():
            conn.terminate()

    def _on_terminate(self, conn):
        if conn is self.conn:
            self._lost.set()

    def _on_notify(self, _conn, _pid, channel, payload):
        message = parse_notification(channel, payload)
        if message is not None:
            self._send(message)

    def _send(self, message: dict):
        # 화면 하나가 느려도 감시 루프 · 다음 통보가 막히지 않게 따로 돌린다. 끝나기 전에 사라지지 않게 쥐고 있는다.
        sending = asyncio.create_task(self.hub.broadcast(message))
        self._sending.add(sending)
        sending.add_done_callback(self._sending.discard)

    # ------------------------------------------------------------ 감시

    async def _wait_lost(self) -> str:
        """연결이 끊길 때까지 기다리고 까닭을 돌려준다. 종료 알림이 오거나 SELECT 1 이 실패 · 시간 초과하면 끊긴 것이다.
        종료 알림은 서버가 연결을 닫았을 때 온다. 망이 조용히 끊기면 오지 않으므로 SELECT 1 로 본다."""
        while True:
            try:
                await asyncio.wait_for(self._lost.wait(), self.ping_interval)
                return "종료 알림"
            except TimeoutError:
                pass
            try:
                await self.conn.fetchval("SELECT 1", timeout=self.ping_timeout)
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                return f"SELECT 1 {self.ping_timeout}초 초과"
            except Exception as error:
                return f"SELECT 1 실패 {type(error).__name__}"

    async def _reopen(self) -> int:
        """다시 붙을 때까지 1초 → 2배 → 최대 30초 간격으로 시도한다. 붙은 시도 번호를 돌려준다."""
        attempt = 0
        delay = self.backoff_first
        while True:
            await self._sleep(delay)
            attempt += 1
            try:
                await self._open()
                return attempt
            except asyncio.CancelledError:
                raise
            except Exception as error:
                delay = min(delay * 2, self.backoff_max)
                log.warning("실시간 통보: LISTEN 다시 붙기 %d회째 실패(%s). %s초 뒤 다시", attempt,
                            type(error).__name__, delay)

    async def _watch(self):
        while True:
            reason = await self._wait_lost()
            since = time.monotonic()
            log.warning("실시간 통보: LISTEN 연결 끊김(%s). 다시 붙는다", reason)
            self._drop()
            attempt = await self._reopen()
            self.reconnects += 1
            log.warning("실시간 통보: LISTEN 다시 붙음(%d회째 시도 · 끊긴 지 %.0f초). 화면에 resync 를 보낸다",
                        attempt, time.monotonic() - since)
            self._send({"type": "resync"})
