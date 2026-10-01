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
  종료 알림(add_termination_listener)과 15초마다 SELECT 1(5초 한도)로 끊김을 알고, 시도 시작 사이를 1초 → 2배 → 최대 5초로
  다시 붙는다(이슈 #56. 최대 30초였을 때 DB 가 돌아와도 통보가 최대 30초 늦게 붙었다). 대기는 실패한 시도에 쓴 시간을 뺀 나머지다.
  그래서 DB 가 돌아온 뒤 늦는 시간은 연결 거부형(DB 재시작)이면 최대 5초, 응답 없는 끊김(패킷 버림 · 망 단절)이면 시도 하나가
  연결 한도 10초를 다 써도 곧바로 다음 시도를 하므로 최대 약 3초(마지막 SYN 재전송 7초 ~ 한도 10초 사이)다.
  다시 붙으면 on_reconnect(콘솔은 풀 연결 새 세대로 바꾸기)를 부른다. 30초 넘게 끊겼으면 DB 가 keepalive 로 이 콘솔의 풀 연결도
  닫았을 수 있어서다(DB_KEEPALIVE). 옛 연결은 다음에 빌릴 때 닫히고 새로 붙는다. 다시 붙으면 모든 화면에 {"type": "resync"} 를 보낸다. 끊긴 동안 놓친 통보는 화면이 전부 다시 받아 메운다.
  /health 에는 넣지 않는다. DB 가 잠깐 흔들려도 두 콘솔이 함께 빠지지 않게 한다. 상태는 로그 한 줄로 남긴다.
  기동 때 첫 연결이 안 되면 예외로 기동을 실패시킨다(풀 만들기와 같다). 헬스체크가 빠져 다른 콘솔이 받는다.

이름표
  콘솔의 DB 연결(풀 · 이 LISTEN 연결)은 application_name 을 콘솔 이름(CONSOLE_NAME)으로 단다(db_settings, 이슈 #76). 상태판이
  pg_stat_activity 에서 콘솔 역할의 그 이름 연결이 있는지 본다(targets.CONSOLE_LINKS_SQL).
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
BACKOFF_MAX = 5         # 다시 붙기 시도 시작 사이의 상한(초). 늦는 시간의 상한은 위 머리말 (이슈 #56)
# 연결 한 번의 한도(초). asyncpg 기본(60초)이면 망이 조용히 끊긴 동안 한 시도에 1분씩 묶인다.
CONNECT_TIMEOUT = 10
# 콘솔의 DB 연결(풀 · 이 LISTEN 연결)에 거는 서버 쪽 TCP 설정 (이슈 #56). 연결 시작 때 보내면 DB 가 그 연결의 소켓에 건다.
#   운영 DB 는 이 값이 0(운영체제 기본: 유휴 2시간 뒤 확인)이라, 콘솔 VM 이 전원째 꺼지거나 망이 끊기면 그 콘솔의 연결이 2시간 넘게
#   남았다(장애 주입 시험에서 VM 끔마다 3개). 두세 번 겹치면 콘솔 역할 한도(30)가 차 두 콘솔이 함께 빠질 수 있다.
#   keepalive: 30초 조용하면 10초 간격으로 3번 확인 → 약 60초 안에 끊긴 연결을 닫는다.
#   tcp_user_timeout: 보낸 자료가 60초 넘게 확인되지 않으면 닫는다. 통보를 보내는 중(확인 안 된 자료가 있는 동안)에는 keepalive 가
#   돌지 않아 운영체제 재전송 한도(약 15분)까지 남으므로 따로 건다. DB 설정 · 역할 설정은 바꾸지 않는다(콘솔 연결에만 적용)
DB_KEEPALIVE = {"tcp_keepalives_idle": "30", "tcp_keepalives_interval": "10", "tcp_keepalives_count": "3",
                "tcp_user_timeout": "60000"}


def console_name() -> str:
    """이 콘솔의 이름. 알림 발송기(notifier.Notifier)의 기본 이름과 같다.

    OPSLOOP_WORKER(compose 가 opsloop-console-a · opsloop-console-b 로 준다)가 없으면 hostname 이다. 64자에서 자른다.
    화면의 연결 표시(hello) · /api/me 에 싣는다. 세션 뒤에서만 나가고 응답 헤더로는 내지 않는다(이슈 #41).
    """
    return (os.environ.get("OPSLOOP_WORKER") or socket.gethostname())[:64]


CONSOLE_NAME = console_name()


def db_settings() -> dict:
    """콘솔 DB 연결(풀 · LISTEN)의 서버 설정: keepalive(DB_KEEPALIVE) + 이름표 application_name = 콘솔 이름(이슈 #76).
    DB 가 63바이트에서 자르지만 판정에 쓰는 이름(opsloop-console-a · b)은 짧은 ASCII 다. 시험이 CONSOLE_NAME 을 바꿔 끼울 수
    있게 부를 때마다 만든다. DB_KEEPALIVE 는 그대로 둔다."""
    return {**DB_KEEPALIVE, "application_name": CONSOLE_NAME}


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
    return await asyncpg.connect(dsn, timeout=CONNECT_TIMEOUT, server_settings=db_settings())


class Listener:
    """LISTEN 전용 연결 하나를 들고 두 채널의 통보를 Hub 로 넘긴다. 풀에서 빌린 연결로 LISTEN 하면 반납될 때 끊긴다.

    역할 연결 수: 콘솔 한 대 = 풀 최대 10 + 이 연결 1. 다시 붙을 때는 옛 연결을 버린 뒤 연다(겹치지 않는다).
    """

    def __init__(self, dsn, hub: Hub, *, connect=None, ping_interval=PING_INTERVAL, ping_timeout=PING_TIMEOUT,
                 backoff_first=BACKOFF_FIRST, backoff_max=BACKOFF_MAX, on_reconnect=None):
        self.dsn = dsn
        self.hub = hub
        self.connect = connect or _asyncpg_connect
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.backoff_first = backoff_first
        self.backoff_max = backoff_max
        self.on_reconnect = on_reconnect     # 다시 붙은 뒤 부를 코루틴 함수(콘솔: 풀 연결 새 세대로). 실패해도 통보는 이어 간다
        self.conn = None
        self.task: asyncio.Task | None = None
        self.reconnects = 0          # 다시 붙은 횟수(시험 · 점검용)
        self._lost: asyncio.Event | None = None
        self._sending: set[asyncio.Task] = set()
        self._sleep = asyncio.sleep  # 시험이 기다림 간격을 기록하려고 바꿔 끼운다
        self._clock = time.monotonic # 시도에 쓴 시간을 재는 시계. 시험이 바꿔 끼운다

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
        """다시 붙을 때까지 시도 시작 사이를 1초 → 2배 → 최대 5초로 둔다. 붙은 시도 번호를 돌려준다.

        실패한 뒤에는 그 시도에 쓴 시간을 뺀 만큼만 기다린다. 응답 없는 끊김에서는 시도 하나가 연결 한도(10초)를 다 쓰는데,
        그 뒤에 또 5초를 온전히 기다리면 주기가 15초가 되고 복구 뒤 최대 약 8초 늦는다(이슈 #56 검토)."""
        attempt = 0
        delay = wait = self.backoff_first
        while True:
            await self._sleep(wait)
            attempt += 1
            started = self._clock()
            try:
                await self._open()
                return attempt
            except asyncio.CancelledError:
                raise
            except Exception as error:
                delay = min(delay * 2, self.backoff_max)
                wait = max(0.0, delay - (self._clock() - started))
                log.warning("실시간 통보: LISTEN 다시 붙기 %d회째 실패(%s). %s초 뒤 다시", attempt,
                            type(error).__name__, f"{wait:.1f}".rstrip("0").rstrip("."))

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
            if self.on_reconnect is not None:
                try:
                    await self.on_reconnect()
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    log.warning("실시간 통보: 다시 붙은 뒤 정리 실패(%s)", type(error).__name__)
            self._send({"type": "resync"})
