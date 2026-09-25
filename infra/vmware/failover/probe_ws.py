#!/usr/bin/env python3
"""콘솔 웹소켓 프로브 (이슈 #43 장애 주입 시험). Mac 에서 돈다. 표준 라이브러리만 쓴다.

표준 라이브러리로 만든 최소 웹소켓 클라이언트다(핸드셰이크 · 텍스트 · 핑 · 퐁 · 클로즈 프레임, 조각난 텍스트).
프로브 쿠키와 Origin 을 실어 /ws 에 붙는다(서버 OriginCheck 는 Origin 과 Host 가 같아야 받는다).

두 모드
  browser  화면(console/src/api/live.ts)과 같게 군다. 핑을 보내지 않는다(서버 핑에는 퐁으로 답한다. 브라우저도 그렇다).
           끊기면 1초 × 2^n, 최대 30초 백오프로 다시 붙고, 붙으면 n 을 0 으로 되돌린다.
           서버가 1008 로 닫으면 다시 붙지 않는다(stopped. 화면은 이때 /api/me 로 로그인에 간다).
           앞단(HAProxy)이 죽은 콘솔과의 터널을 닫지 않으면 끊김을 모른 채 남는다(좀비). 그 시간을 재려는 모드다.
  net      1초마다 핑을 보내고 2초 안에 퐁이 없으면 끊긴 것으로 보고 닫은 뒤 같은 백오프로 다시 붙는다(망 수준 감지).

기록: <회차 폴더>/ws.jsonl 에 사건마다 한 줄 (덧붙인다)
  {run, stream: ws-browser|ws-net, conn, event, t_ns, ...}
  open                            핸드셰이크 101
  hello      console              서버 hello 의 data.console (콘솔 이름. 없으면 null)
  message    msg_type             통보(내용은 적지 않는다)
  close      code · by · reason · was_open
             by: server(클로즈 프레임) · net(EOF · 끊김 · 연결 실패 · 핸드셰이크 거부, code 1006) · local(퐁 없음 1006 · 프로토콜 오류 1002)
  reconnect  attempt · delay_ms   백오프를 기다린 뒤 다시 붙기 시작한 시각
  stopped                         1008 뒤 다시 붙지 않음 (browser)
  end        was_open             시험 끝(--duration · Ctrl-C). 좀비 집계에서 close 로 치지 않는다

사용 (저장소 루트. 쿠키는 probe_http.py 와 같은 파일을 쓴다. --mint-cookie · --drop-cookie 도 같다)
  python3 infra/vmware/failover/probe_ws.py --run-dir ~/opsloop-failover/r01-stop-a --mode browser --conns 4 --duration 300
  python3 infra/vmware/failover/probe_ws.py --run-dir <폴더> --mode net --conns 4
  연결 하나가 어느 콘솔에 붙을지는 HAProxy roundrobin 이 정한다. 대상 콘솔에 붙은 연결이 있게 --conns 를 2 이상으로 준다.
  --url · --duration(기본 600, 0 이면 Ctrl-C 까지) · --base-delay 1 · --max-delay 30 · --ping-interval 1 · --pong-timeout 2
  Ctrl-C · kill(SIGTERM)로 멈추면 연결마다 클로즈 프레임(1000)을 보내고 end 를 남긴다.
종료 코드: 0 · 2 설정 오류 · 130 중단
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import common  # noqa: E402

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
CONTROL = (OP_CLOSE, OP_PING, OP_PONG)
MAX_PAYLOAD = 1024 * 1024       # 통보는 작다(서버 NOTIFY 한도 8000 바이트). 넘으면 프로토콜 오류로 본다
MAX_HEADER = 16 * 1024
CLOSE_UNAUTHORIZED = 1008       # live.ts CLOSE_UNAUTHORIZED
CLOSE_ABNORMAL = 1006           # 클로즈 프레임 없이 끊김 (브라우저가 보이는 값)
USER_AGENT = "opsloop-failover-probe/1"


class ProtocolError(Exception):
    pass


class Frame:
    __slots__ = ("fin", "opcode", "payload", "masked")

    def __init__(self, fin, opcode, payload, masked):
        self.fin, self.opcode, self.payload, self.masked = fin, opcode, payload, masked

    def __repr__(self):
        return "Frame(fin=%r, opcode=%r, len=%d, masked=%r)" % (self.fin, self.opcode, len(self.payload), self.masked)


def accept_key(key: str) -> str:
    """RFC 6455 4.2.2 Sec-WebSocket-Accept."""
    return base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")


def _xor(data: bytes, key: bytes) -> bytes:
    if not data:
        return b""
    n = len(data)
    k = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(k, "big")).to_bytes(n, "big")


def encode_frame(opcode: int, payload: bytes = b"", mask: bool = True, fin: bool = True, mask_key=None) -> bytes:
    """프레임 하나. 클라이언트가 보내는 프레임은 반드시 가린다(mask=True)."""
    if opcode in CONTROL and (len(payload) > 125 or not fin):
        raise ProtocolError("제어 프레임은 125 바이트 이하 · 조각 없음")
    head = bytearray([(0x80 if fin else 0) | (opcode & 0x0F)])
    n = len(payload)
    bit = 0x80 if mask else 0
    if n < 126:
        head.append(bit | n)
    elif n < 65536:
        head.append(bit | 126)
        head += struct.pack("!H", n)
    else:
        head.append(bit | 127)
        head += struct.pack("!Q", n)
    if mask:
        key = mask_key if mask_key is not None else os.urandom(4)
        return bytes(head) + key + _xor(payload, key)
    return bytes(head) + payload


def decode_frame(buf, max_payload: int = MAX_PAYLOAD):
    """버퍼 앞의 프레임 하나를 푼다. 모자라면 (None, 0). 규칙 위반이면 ProtocolError."""
    if len(buf) < 2:
        return None, 0
    b0, b1 = buf[0], buf[1]
    if b0 & 0x70:
        raise ProtocolError("RSV 비트(확장은 협상하지 않았다)")
    fin, opcode = bool(b0 & 0x80), b0 & 0x0F
    if opcode not in (OP_CONT, OP_TEXT, OP_BINARY) + CONTROL:
        raise ProtocolError("모르는 opcode %d" % opcode)
    masked, n, i = bool(b1 & 0x80), b1 & 0x7F, 2
    if n == 126:
        if len(buf) < 4:
            return None, 0
        n, i = struct.unpack("!H", bytes(buf[2:4]))[0], 4
    elif n == 127:
        if len(buf) < 10:
            return None, 0
        n, i = struct.unpack("!Q", bytes(buf[2:10]))[0], 10
    if opcode in CONTROL and (n > 125 or not fin):
        raise ProtocolError("제어 프레임은 125 바이트 이하 · 조각 없음")
    if n > max_payload:
        raise ProtocolError("프레임이 너무 크다 (%d 바이트)" % n)
    key = b""
    if masked:
        if len(buf) < i + 4:
            return None, 0
        key, i = bytes(buf[i:i + 4]), i + 4
    if len(buf) < i + n:
        return None, 0
    payload = bytes(buf[i:i + n])
    if masked:
        payload = _xor(payload, key)
    return Frame(fin, opcode, payload, masked), i + n


def close_payload(code=None, reason: str = "") -> bytes:
    if code is None:
        return b""
    return struct.pack("!H", code) + reason.encode("utf-8")[:123]


def parse_close(payload: bytes):
    """클로즈 프레임 본문 → (code, reason). 본문이 없으면 1005(코드 없음)."""
    if len(payload) < 2:
        return 1005, ""
    return struct.unpack("!H", payload[:2])[0], payload[2:].decode("utf-8", "replace")


class Assembler:
    """조각난 텍스트 · 바이너리 메시지를 잇는다."""

    def __init__(self, max_payload=MAX_PAYLOAD):
        self.opcode = None
        self.parts = bytearray()
        self.max_payload = max_payload

    def feed(self, frame):
        """데이터 프레임을 넣는다. 메시지가 끝나면 (opcode, bytes), 아니면 None."""
        if frame.opcode == OP_CONT:
            if self.opcode is None:
                raise ProtocolError("시작 없는 이어짐 프레임")
        else:
            if self.opcode is not None:
                raise ProtocolError("앞 메시지가 끝나기 전에 새 메시지")
            self.opcode = frame.opcode
            self.parts = bytearray()
        self.parts += frame.payload
        if len(self.parts) > self.max_payload:
            raise ProtocolError("메시지가 너무 크다")
        if not frame.fin:
            return None
        done = (self.opcode, bytes(self.parts))
        self.opcode, self.parts = None, bytearray()
        return done


def handshake_request(host_header, path, key, origin=None, cookie=None) -> bytes:
    lines = ["GET %s HTTP/1.1" % path, "Host: %s" % host_header, "Upgrade: websocket",
             "Connection: Upgrade", "Sec-WebSocket-Key: %s" % key, "Sec-WebSocket-Version: 13",
             "User-Agent: %s" % USER_AGENT]
    if origin:
        lines.append("Origin: %s" % origin)
    if cookie:
        lines.append("Cookie: %s=%s" % (common.COOKIE_NAME, cookie))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def read_response_head(sock):
    """응답 머리를 읽는다 → (status, {이름: 값}, 남은 바이트)."""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionResetError("핸드셰이크 중 끊김")
        buf += chunk
        if len(buf) > MAX_HEADER:
            raise ProtocolError("응답 머리가 너무 크다")
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise ProtocolError("응답 첫 줄이 HTTP 가 아니다")
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return int(parts[1]), headers, rest


def backoff(attempt, base=1.0, cap=30.0):
    """live.ts backoffMs 와 같다: base · 2^n, 최대 cap (초)."""
    return min(cap, base * (2 ** max(0, attempt)))


def _err_name(exc):
    if isinstance(exc, ConnectionRefusedError):
        return "connect_refused"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "reset"
    return type(exc).__name__


class Session:
    """연결 하나(끊기면 다시 붙는다). 스레드 하나에서 돈다."""

    def __init__(self, url, run, mode, conn, cookie, writer, stop, base_delay=1.0, max_delay=30.0,
                 ping_interval=1.0, pong_timeout=2.0, connect_timeout=10.0):
        self.scheme, self.host, self.port, self.origin = common.split_url(url)
        self.host_header = self.origin.split("://", 1)[1]
        self.run_name, self.mode, self.conn = run, mode, conn
        self.stream = "ws-%s" % mode
        self.cookie, self.writer, self.stop = cookie, writer, stop
        self.base_delay, self.max_delay = base_delay, max_delay
        self.ping_interval, self.pong_timeout = ping_interval, pong_timeout
        self.connect_timeout = connect_timeout
        self.sock = None

    def log(self, event, **kw):
        rec = {"run": self.run_name, "stream": self.stream, "conn": self.conn, "event": event, "t_ns": common.now_ns()}
        rec.update(kw)
        self.writer.write(rec)

    # 한 번 붙어서 끊길 때까지 ────────────────────────────────
    def _open(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
        if self.scheme == "https":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)
        self.sock = raw
        raw.settimeout(self.connect_timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        raw.sendall(handshake_request(self.host_header, "/ws", key, self.origin, self.cookie))
        status, headers, rest = read_response_head(raw)
        ok = (status == 101 and headers.get("upgrade", "").lower() == "websocket"
              and headers.get("sec-websocket-accept") == accept_key(key))
        return ok, status, rest

    def _send(self, opcode, payload=b""):
        self.sock.sendall(encode_frame(opcode, payload))

    def _drop(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def once(self):
        """→ (opened, 결과). 결과: 'closed' · 'stopped'(1008) · 'end'(시험 끝)."""
        try:
            ok, status, rest = self._open()
        except ProtocolError as e:
            self._drop()
            self.log("close", code=CLOSE_ABNORMAL, by="net", reason=common.clean(str(e), 80), was_open=False)
            return False, "closed"
        except OSError as e:
            self._drop()
            self.log("close", code=CLOSE_ABNORMAL, by="net", reason=_err_name(e), was_open=False)
            return False, "closed"
        if not ok:
            # 수락 전에 닫히면(옛 서버의 인증 실패 · 출처 거부 403) 브라우저는 1006 을 본다
            self._drop()
            self.log("close", code=CLOSE_ABNORMAL, by="net", reason="핸드셰이크 거부", status=status, was_open=False)
            return False, "closed"
        self.log("open")
        return True, self._loop(bytearray(rest))

    def _loop(self, buf):
        sock = self.sock
        sock.settimeout(0.2)
        assembler = Assembler()
        pings = {}                     # 본문 → 보낸 시각(단조)
        counter = 0
        next_ping = time.monotonic() + self.ping_interval
        while True:
            if self.stop.is_set():
                try:
                    self._send(OP_CLOSE, close_payload(1000, "test end"))
                except OSError:
                    pass
                self._drop()
                self.log("end", was_open=True)
                return "end"
            try:
                while True:
                    frame, used = decode_frame(buf)
                    if frame is None:
                        break
                    del buf[:used]
                    result = self._handle(frame, assembler, pings)
                    if result:
                        return result
            except ProtocolError as e:
                try:
                    self._send(OP_CLOSE, close_payload(1002))
                except OSError:
                    pass
                self._drop()
                self.log("close", code=1002, by="local", reason=common.clean(str(e), 80), was_open=True)
                return "closed"
            if self.mode == "net":
                now = time.monotonic()
                if pings and now - min(pings.values()) > self.pong_timeout:
                    self._drop()
                    self.log("close", code=CLOSE_ABNORMAL, by="local", reason="퐁 없음", was_open=True)
                    return "closed"
                if now >= next_ping:
                    counter += 1
                    payload = str(counter).encode("ascii")
                    try:
                        self._send(OP_PING, payload)
                    except OSError as e:
                        self._drop()
                        self.log("close", code=CLOSE_ABNORMAL, by="net", reason=_err_name(e), was_open=True)
                        return "closed"
                    pings[payload] = now
                    next_ping = max(next_ping + self.ping_interval, now)
            try:
                data = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                continue
            except OSError as e:
                self._drop()
                self.log("close", code=CLOSE_ABNORMAL, by="net", reason=_err_name(e), was_open=True)
                return "closed"
            if not data:
                self._drop()
                self.log("close", code=CLOSE_ABNORMAL, by="net", reason="eof", was_open=True)
                return "closed"
            buf += data

    def _handle(self, frame, assembler, pings):
        op = frame.opcode
        if op == OP_PING:
            try:
                self._send(OP_PONG, frame.payload)
            except OSError:
                pass
            return None
        if op == OP_PONG:
            pings.pop(frame.payload, None)
            return None
        if op == OP_CLOSE:
            code, reason = parse_close(frame.payload)
            try:
                self._send(OP_CLOSE, close_payload(code if code not in (1005, 1006) else None))
            except OSError:
                pass
            self._drop()
            self.log("close", code=code, by="server", reason=common.clean(reason, 80), was_open=True)
            if code == CLOSE_UNAUTHORIZED and self.mode == "browser":
                return "stopped"
            return "closed"
        done = assembler.feed(frame)
        if done is None:
            return None
        opcode, data = done
        if opcode != OP_TEXT:
            self.log("message", msg_type="binary")
            return None
        try:
            msg = json.loads(data.decode("utf-8", "replace"))
        except ValueError:
            msg = None
        kind = common.clean(msg.get("type"), 40) if isinstance(msg, dict) else None
        if kind == "hello":
            body = msg.get("data") if isinstance(msg.get("data"), dict) else {}
            self.log("hello", console=common.clean(body.get("console"), 64))
        else:
            self.log("message", msg_type=kind)
        return None

    # 다시 붙기 ─────────────────────────────────────────────
    def run(self):
        retries = 0
        first = True
        try:
            while not self.stop.is_set():
                if not first:
                    delay = backoff(retries, self.base_delay, self.max_delay)
                    retries += 1
                    if self.stop.wait(delay):
                        break
                    self.log("reconnect", attempt=retries, delay_ms=round(delay * 1000))
                first = False
                opened, result = self.once()
                if opened:
                    retries = 0          # live.ts 는 open 때 되돌린다. 다음 대기는 다시 1초부터
                if result == "end":
                    return
                if result == "stopped":
                    self.log("stopped")
                    return
            self.log("end", was_open=False)
        finally:
            self._drop()


def parse_args(argv):
    p = argparse.ArgumentParser(description="콘솔 웹소켓 프로브 (이슈 #43). 사용법은 파일 머리 주석")
    p.add_argument("--run-dir", help="회차 폴더. ws.jsonl 을 여기에 덧붙인다")
    p.add_argument("--run", help="회차 이름 (기본: 폴더 이름)")
    p.add_argument("--url", default=common.DEFAULT_URL, help="콘솔 진입점 (기본 %(default)s). /ws 로 붙는다")
    p.add_argument("--mode", choices=("browser", "net"), default="browser")
    p.add_argument("--conns", type=int, default=1, help="동시에 여는 연결 수 (기본 1)")
    p.add_argument("--duration", type=float, default=600, help="돌 시간 초. 0 이면 Ctrl-C 까지 (기본 600)")
    p.add_argument("--base-delay", type=float, default=1.0, help="백오프 시작 초 (기본 1, live.ts 와 같다)")
    p.add_argument("--max-delay", type=float, default=30.0, help="백오프 상한 초 (기본 30)")
    p.add_argument("--ping-interval", type=float, default=1.0, help="net: 핑 간격 초 (기본 1)")
    p.add_argument("--pong-timeout", type=float, default=2.0, help="net: 퐁 기다림 초 (기본 2)")
    p.add_argument("--connect-timeout", type=float, default=10.0, help="연결 · 핸드셰이크 한도 초 (기본 10)")
    common.add_cookie_args(p)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if common.cookie_command(args):
        return 0
    common.stop_signals()
    if not args.run_dir:
        raise common.ToolError("--run-dir 가 필요하다")
    if not 1 <= args.conns <= 64:
        raise common.ToolError("--conns 는 1 ~ 64")
    if min(args.base_delay, args.max_delay, args.ping_interval, args.pong_timeout, args.connect_timeout) <= 0 \
            or args.duration < 0:
        raise common.ToolError("시간 옵션은 0 보다 커야 한다 (--duration 은 0 이상)")
    cookie = common.load_cookie(args.cookie_file)
    run = common.run_name(args.run_dir, args.run)
    out = os.path.join(args.run_dir, "ws.jsonl")
    writer = common.JsonlWriter(out)
    stop = threading.Event()
    sessions = [Session(args.url, run, args.mode, i, cookie, writer, stop, args.base_delay, args.max_delay,
                        args.ping_interval, args.pong_timeout, args.connect_timeout) for i in range(args.conns)]
    print("웹소켓 프로브: %s/ws · %s · 연결 %d · 회차 %s → %s" % (
        sessions[0].origin, args.mode, args.conns, run, out), file=sys.stderr)
    threads = []
    interrupted = False
    try:
        for s in sessions:
            th = threading.Thread(target=s.run, daemon=True)
            th.start()
            threads.append(th)
            time.sleep(0.05)
        deadline = time.monotonic() + args.duration if args.duration else None
        while any(t.is_alive() for t in threads):
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        interrupted = True
    stop.set()
    for th in threads:
        th.join(5)
    writer.close()
    print("웹소켓 프로브를 멈췄다", file=sys.stderr)
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(common.main_guard(main))
