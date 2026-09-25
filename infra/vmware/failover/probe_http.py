#!/usr/bin/env python3
"""콘솔 HTTP 프로브 (이슈 #43 장애 주입 시험). Mac 에서 돈다. 표준 라이브러리만 쓴다.

열린 루프로 요청을 쏜다. 간격(기본 100ms)마다 줄기마다 요청 하나를 새 스레드 · 새 연결로 보낸다.
앞 요청이 끝나기를 기다리지 않으므로 장애 동안 걸려 있는 요청도 그대로 보이고 발사 간격은 흔들리지 않는다.
요청 한도는 70초다(HAProxy timeout server 60초보다 길어 504 를 받는다).
걸린 요청마다 소켓 하나를 쥐므로 시작할 때 파일 기술자 한도(soft)를 --max-inflight 만큼 올린다
(macOS 터미널 기본 256 이면 걸린 요청 250개쯤에서 새 요청이 EMFILE 로 실패해 실패 구간이 늘어난다).
hard 한도가 모자라면 동시 요청 한도를 낮추고 알린다. 넘친 회차는 보내지 않고 detail 'in-flight 한도' 로 남긴다.

  health  GET /health?p=<회차>-<번호>  인증 없음. p 로 HAProxy 로그(fw-haproxy.log)에서 어느 콘솔이 받았는지 찾는다
  me      GET /api/me                 프로브 쿠키 · Origin. 응답의 console(콘솔 이름)을 기록한다

기록: <회차 폴더>/http.jsonl 에 요청마다 한 줄 (덧붙인다. 같은 폴더에 다시 띄우면 번호를 이어 가 p 가 겹치지 않는다)
  {run, stream, seq, t_send_ns, t_recv_ns, status, latency_ms, error, console}
  error: null · connect_refused · timeout · reset · http_5xx · http_401 · other (other 는 detail 에 까닭)
  시각은 Mac 벽시계 epoch ns, latency_ms 는 단조 시계로 잰 값이다. t_recv_ns = t_send_ns + 지연

쿠키 (me 줄기에만 쓴다)
  python3 infra/vmware/failover/probe_http.py --mint-cookie console-a
    ssh 로 콘솔 A 컨테이너 안에서 auth.issue("failover-probe", "viewer") 를 불러 ~/.config/opsloop/probe-cookie(0600)에만 둔다.
    비밀번호 없이 서버 비밀로 발급한 viewer 12시간 쿠키다. 화면 · 로그 · 기록에 찍지 않는다.
  python3 infra/vmware/failover/probe_http.py --drop-cookie      시험 뒤 파일 삭제

사용 (저장소 루트)
  python3 infra/vmware/failover/probe_http.py --run-dir ~/opsloop-failover/r01-stop-a --duration 300
  python3 infra/vmware/failover/probe_http.py --run-dir <폴더> --streams health        쿠키 없이 health 만
  --url http://192.168.70.254:8443 (기본) · --interval 0.1 · --timeout 70 · --duration 초(0 이면 Ctrl-C 까지)
  Ctrl-C · kill(SIGTERM)로 멈추면 걸려 있는 요청이 끝나기를 기다렸다 끝낸다(한 번 더 누르면 바로 끝낸다).
종료 코드: 0 · 2 설정 오류(쿠키 파일 권한 · 꼴 · 만료 포함) · 130 중단
"""

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import threading
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import common  # noqa: E402

USER_AGENT = "opsloop-failover-probe/1"
STREAMS = ("health", "me")
BODY_LIMIT = 64 * 1024
FD_RESERVE = 64      # 걸린 요청 소켓 말고 프로세스가 쓰는 기술자 몫(표준 입출력 · 기록 파일 · 모듈)


def fit_inflight(max_inflight):
    """걸린 요청 수만큼 소켓을 열 수 있게 파일 기술자 soft 한도를 hard 안에서 올린다.
    → (쓸 동시 요청 한도, soft 한도 또는 None). hard 가 모자라면 동시 요청 한도를 그만큼 낮춘다."""
    try:
        import resource
    except ImportError:          # 한도를 모르는 체제는 그대로
        return max_inflight, None
    inf = resource.RLIM_INFINITY
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = max_inflight + FD_RESERVE
    if soft != inf and soft < need:
        want = need if hard == inf else min(need, hard)
        if want > soft:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
                soft = want
            except (ValueError, OSError):
                pass
    if soft != inf and soft - FD_RESERVE < max_inflight:
        return max(1, soft - FD_RESERVE), soft
    return max_inflight, soft


def next_seq(path, run):
    """같은 회차 폴더에 다시 띄우면 앞 실행의 마지막 번호 다음부터 센다.
    health 의 p(<회차>-<번호>)로 HAProxy 로그에서 서버를 찾으므로 번호가 겹치면 콘솔을 잘못 안다."""
    last = -1
    for r in common.read_jsonl(path):
        if r.get("run") == run and isinstance(r.get("seq"), int):
            last = max(last, r["seq"])
    return last + 1


def classify_exception(exc):
    """예외 → (error, detail). 순서가 중요하다(모두 OSError 의 하위다)."""
    if isinstance(exc, ConnectionRefusedError):
        return "connect_refused", None
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout", None
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
                        http.client.RemoteDisconnected, http.client.IncompleteRead)):
        return "reset", None
    if isinstance(exc, http.client.HTTPException):
        return "other", type(exc).__name__
    if isinstance(exc, OSError):
        name = type(exc).__name__
        if exc.errno:
            import errno as _errno
            name = "%s:%s" % (name, _errno.errorcode.get(exc.errno, exc.errno))
        return "other", name
    return "other", type(exc).__name__


def classify_status(status):
    if status is None:
        return None
    if status >= 500:
        return "http_5xx"
    if status == 401:
        return "http_401"
    if 200 <= status < 300:
        return None
    return "other"


class Prober:
    def __init__(self, url, run, streams, cookie, timeout, writer, max_inflight=2000, seq0=0):
        self.scheme, self.host, self.port, self.origin = common.split_url(url)
        self.run = run
        self.seq0 = seq0
        self.streams = streams
        self.cookie = cookie
        self.timeout = timeout
        self.writer = writer
        self.max_inflight = max_inflight
        self.inflight = 0
        self.lock = threading.Lock()
        self.counts = Counter()
        self.threads = []

    def _connection(self):
        if self.scheme == "https":
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout,
                                               context=ssl.create_default_context())
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def request(self, stream, seq):
        """요청 하나. 결과를 한 줄로 쓴다. 예외를 밖으로 내지 않는다."""
        t_send = common.now_ns()
        t0 = time.perf_counter()
        status = error = detail = console = None
        headers = {"User-Agent": USER_AGENT, "Connection": "close", "Accept": "application/json"}
        if stream == "health":
            path = "/health?p=%s-%d" % (self.run, seq)
        else:
            path = "/api/me"
            headers["Cookie"] = "%s=%s" % (common.COOKIE_NAME, self.cookie)
            headers["Origin"] = self.origin
        conn = None
        try:
            conn = self._connection()
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            body = resp.read(BODY_LIMIT)
            error = classify_status(status)
            if error == "other":
                detail = "http_%d" % status
            if stream == "me" and status == 200:
                try:
                    data = json.loads(body.decode("utf-8", "replace"))
                except ValueError:
                    data = None
                if isinstance(data, dict):
                    console = common.clean(data.get("console"), 64)
        except Exception as exc:  # noqa: BLE001  무엇이든 한 줄로 남긴다
            error, detail = classify_exception(exc)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
        latency_ms = (time.perf_counter() - t0) * 1000.0
        rec = {"run": self.run, "stream": stream, "seq": seq, "t_send_ns": t_send,
               "t_recv_ns": t_send + int(latency_ms * 1e6), "status": status,
               "latency_ms": round(latency_ms, 3), "error": error, "console": console}
        if detail:
            rec["detail"] = common.clean(detail, 80)
        self.writer.write(rec)
        with self.lock:
            self.counts[(stream, error or "ok")] += 1
            self.inflight -= 1

    def fire(self, k):
        seq = self.seq0 + k
        for stream in self.streams:
            with self.lock:
                full = self.inflight >= self.max_inflight
                if not full:
                    self.inflight += 1
            if full:
                # 걸린 요청이 너무 많다. 보내지 않고 그 사실을 남긴다(열린 루프의 발사 시각은 지킨다)
                t = common.now_ns()
                self.writer.write({"run": self.run, "stream": stream, "seq": seq, "t_send_ns": t,
                                   "t_recv_ns": t, "status": None, "latency_ms": 0.0,
                                   "error": "other", "console": None, "detail": "in-flight 한도"})
                with self.lock:
                    self.counts[(stream, "other")] += 1
                continue
            th = threading.Thread(target=self.request, args=(stream, seq), daemon=True)
            th.start()
            self.threads.append(th)
        # 끝난 스레드는 목록에서 뺀다 (오래 돌 때 목록이 자라지 않게)
        if len(self.threads) > 4096:
            self.threads = [t for t in self.threads if t.is_alive()]

    def wait(self, limit):
        deadline = time.monotonic() + limit
        for th in self.threads:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            th.join(left)


def run_loop(prober, interval, duration, stop):
    """열린 루프. 밀렸으면(잠자기 등) 놓친 회차는 건너뛴다(몰아서 쏘지 않는다). 쏜 회차 수를 돌려준다."""
    start = time.monotonic()
    k = fired = 0
    while not stop.is_set():
        due = start + k * interval
        now = time.monotonic()
        if duration and now - start >= duration:
            break
        if due > now:
            if stop.wait(due - now):
                break
            continue
        if now - due > interval:
            k = int((now - start) / interval)
            continue
        prober.fire(k)
        fired += 1
        k += 1
    return fired


def parse_args(argv):
    p = argparse.ArgumentParser(description="콘솔 HTTP 프로브 (이슈 #43). 사용법은 파일 머리 주석")
    p.add_argument("--run-dir", help="회차 폴더. http.jsonl 을 여기에 덧붙인다")
    p.add_argument("--run", help="회차 이름 (기본: 폴더 이름)")
    p.add_argument("--url", default=common.DEFAULT_URL, help="콘솔 진입점 (기본 %(default)s)")
    p.add_argument("--interval", type=float, default=0.1, help="발사 간격 초 (기본 0.1)")
    p.add_argument("--duration", type=float, default=600, help="돌 시간 초. 0 이면 Ctrl-C 까지 (기본 600)")
    p.add_argument("--timeout", type=float, default=70, help="요청 한도 초 (기본 70)")
    p.add_argument("--streams", default="health,me", help="health · me 중 쉼표로 (기본 health,me)")
    p.add_argument("--max-inflight", type=int, default=2000, help="동시에 걸려 있을 수 있는 요청 수 (기본 2000)")
    common.add_cookie_args(p)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if common.cookie_command(args):
        return 0
    common.stop_signals()
    if not args.run_dir:
        raise common.ToolError("--run-dir 가 필요하다")
    streams = [s.strip() for s in args.streams.split(",") if s.strip()]
    bad = [s for s in streams if s not in STREAMS]
    if bad or not streams:
        raise common.ToolError("모르는 줄기: %s (health · me)" % ",".join(common.clean(s, 20) for s in bad))
    if args.interval <= 0 or args.timeout <= 0 or args.duration < 0 or args.max_inflight < 1:
        raise common.ToolError("--interval · --timeout 은 0 보다, --duration 은 0 이상, --max-inflight 는 1 이상이어야 한다")
    cookie = common.load_cookie(args.cookie_file) if "me" in streams else None
    run = common.run_name(args.run_dir, args.run)
    out = os.path.join(args.run_dir, "http.jsonl")
    max_inflight, nofile = fit_inflight(args.max_inflight)
    if max_inflight < args.max_inflight:
        print("경고: 파일 기술자 한도 %d 에 맞춰 동시 요청 한도를 %d → %d 로 낮춘다 (ulimit -Hn 을 올리면 늘어난다)" % (
            nofile, args.max_inflight, max_inflight), file=sys.stderr)
    seq0 = next_seq(out, run)
    writer = common.JsonlWriter(out)
    prober = Prober(args.url, run, streams, cookie, args.timeout, writer, max_inflight, seq0)
    print("HTTP 프로브: %s · 줄기 %s · %dms 간격 · 한도 %gs · 동시 %d · 회차 %s%s → %s" % (
        prober.origin, ",".join(streams), round(args.interval * 1000), args.timeout, max_inflight, run,
        " (번호 %d 부터 이어 감)" % seq0 if seq0 else "", out), file=sys.stderr)
    stop = threading.Event()
    interrupted = False
    try:
        fired = run_loop(prober, args.interval, args.duration, stop)
    except KeyboardInterrupt:
        interrupted, fired = True, None
    print("발사를 멈췄다. 걸린 요청을 최대 %gs 기다린다 (Ctrl-C 로 바로 끝낸다)" % (args.timeout + 2), file=sys.stderr)
    try:
        prober.wait(args.timeout + 2)
    except KeyboardInterrupt:
        interrupted = True
    with prober.lock:
        counts = dict(prober.counts)
    for stream in streams:
        parts = ["%s %d" % (k[1], v) for k, v in sorted(counts.items()) if k[0] == stream]
        print("  %s: %s" % (stream, " · ".join(parts) or "없음"), file=sys.stderr)
    if fired is not None:
        print("  회차 %d번 발사" % fired, file=sys.stderr)
    writer.close()
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(common.main_guard(main))
