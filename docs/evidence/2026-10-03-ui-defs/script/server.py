"""#94 폭별 실측용 목 백엔드(저장소 밖, 84/mock/server.py 를 옮겨 넓힘). 응답은 모두 가짜 자료(시험 픽스처)다.
#94 에서 더한 것: 차단 목록(/api/blocklist) · 사건 상세(/api/incidents/<키>, 모드 incident=judged|open) · 출발지 상세(/api/sources/detail).
#94 에서는 targets=1|2 · band=0 · nodes=4 픽스처만 뽑았다(fixtures.dump.test.ts). 다른 모드는 픽스처가 없다. 아래는 #84 설명 그대로다.
#84 배치 확인용 목 백엔드(저장소 밖, 83/mock/server.py 를 넓힘). vite 개발 서버의 프록시(OPSLOOP_BACKEND)가 여기로 넘긴다.
로그인 없이 대시보드 · 수집 · 관제 상태(/nodes)를 띄운다: /api/me · 요약 · 상태판 · 관제 이상 · CVE 배지 · 장비 로그 · 노드 · 웹소켓(hello 만 보내고 열어 둔다).
응답은 fixtures/*.json(시험 픽스처를 fixtures.dump.test.ts 로 뽑은 것). 응답마다 as_of 를 지금으로 두고 같은 차이만큼 다른 시각도 옮긴다(상대 시각이 픽스처와 같게).
모드는 GET /__mode?... 로 바꾼다:
  targets=1|2|busy   상태판(보호 대상 1장 · 2장 · 390 배지 최대)
  band=0|1|2|s       관제 이상(없음 · 한 줄 · 두 항목 · 가장 긴 센서 까닭 하나)
  ws=1|0             0 이면 웹소켓을 받지 않는다(화면은 실시간 끊김 · 다시 연결 중)
  unmapped=auto|N    상태판 unmapped.pending. auto 는 대기열의 장비 미확인 수
  tfail=1 · nfail=1  상태판 · 노드 조회를 400 으로 실패시킨다(받은 뒤 갱신 실패. 숨은 탭은 5xx 재시도가 멈춰 400 을 쓴다)
  nodes=4|25         등록 노드 표
  role=operator|admin
실행: python3 server.py 8794
"""
import base64, hashlib, json, os, re, sys
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
MODE = {"targets": "2", "band": "0", "ws": "1", "unmapped": "auto", "tfail": "0", "nfail": "0", "nodes": "4", "role": "admin", "incident": "judged"}
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ISO = re.compile(r'"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d))"')


def parse(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def fixture(name):
    with open(os.path.join(HERE, "fixtures", f"{name}.json"), encoding="utf-8") as f:
        return json.load(f)


def now_shift(body):
    """as_of 를 지금으로 두고 같은 차이만큼 다른 시각(문자열 전체가 시각인 값)을 옮긴다."""
    text = json.dumps(body, ensure_ascii=False)
    base = body.get("as_of") if isinstance(body, dict) else None
    if not base:
        return text
    delta = datetime.now(timezone.utc) - parse(base)
    return ISO.sub(lambda m: '"' + (parse(m.group(1)) + delta).isoformat().replace("+00:00", "Z") + '"', text)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, body):
        data = now_shift(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def ws(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        hello = json.dumps({"type": "hello", "data": {"channel": "mock", "console": "opsloop-console-a"}}).encode()
        self.wfile.write(bytes([0x81, len(hello)]) + hello)
        self.wfile.flush()
        try:
            while self.rfile.read(1):   # 닫힐 때까지 붙잡아 둔다(받은 프레임은 버린다)
                pass
        except OSError:
            pass
        self.close_connection = True

    def script(self, name):
        data = open(os.path.join(HERE, name), encoding="utf-8").read().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/javascript; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            if MODE["ws"] == "0":   # 실시간 끊김: 연결을 받지 않는다(화면은 다시 연결 중)
                return self.send(503, {"detail": "실시간 끊김(목)"})
            return self.ws()
        if u.path == "/__mode":
            for k in MODE:
                if k in q:
                    MODE[k] = q[k][0]
            return self.send(200, MODE)
        if u.path == "/api/__measure84":
            return self.script("measure84.js")
        if u.path == "/api/me":
            return self.send(200, {"username": "han", "role": MODE["role"], "console": "opsloop-console-a"})
        if u.path == "/api/stats/summary":
            return self.send(200, fixture("summary"))
        if u.path == "/api/dashboard/targets":
            if MODE["tfail"] == "1":
                return self.send(400, {"detail": "상태판 실패(목)"})
            body = fixture(f"targets-{MODE['targets']}")
            queue = body.get("queue") or {}
            body["unmapped"]["pending"] = int(queue.get("unconfirmed", 0)) if MODE["unmapped"] == "auto" else int(MODE["unmapped"])
            return self.send(200, body)
        if u.path == "/api/dashboard/monitor":
            return self.send(200, fixture({"1": "health-band1", "2": "health-band", "s": "health-sensor"}.get(MODE["band"], "health-ok")))
        if u.path == "/api/nodes":
            if MODE["nfail"] == "1":
                return self.send(400, {"detail": "노드 조회 실패(목)"})
            return self.send(200, fixture(f"nodes-{MODE['nodes']}"))
        if u.path == "/api/cti/badges":
            return self.send(200, {"badges": {}})
        if u.path == "/api/blocklist":
            return self.send(200, fixture("blocklist"))
        if u.path == "/api/sources/detail":
            return self.send(200, fixture("source-detail"))
        if u.path.startswith("/api/incidents/") and u.path.endswith("/cti"):
            return self.send(200, {"applicable": False})
        if u.path.startswith("/api/incidents/") and u.path.count("/") == 3:
            return self.send(200, fixture(f"incident-{MODE['incident']}"))
        if u.path.startswith("/api/devices/") and u.path.endswith("/logs"):
            body = fixture("logs")
            limit = int(q.get("limit", ["100"])[0])
            body["limit"] = limit
            body["items"] = body["items"][:limit]
            return self.send(200, body)
        return self.send(404, {"detail": "없는 경로"})


class S(ThreadingHTTPServer):
    daemon_threads = True


S(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8794), H).serve_forever()
