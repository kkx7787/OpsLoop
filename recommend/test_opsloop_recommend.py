#!/usr/bin/env python3
"""AI 판정 추천 작업기 단위 시험 (DB 없이). 가짜 Ollama 를 실제 HTTP 서버로 띄워 연결 실패를 흉내 낸다.
  python3 recommend/test_opsloop_recommend.py
"""
import ast
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import opsloop_recommend as r  # noqa: E402

PILOT = os.path.join(os.path.dirname(HERE), "docs", "evidence", "2026-10-06-ai-pilot", "tools", "run-pilot.py")
GOOD = {"recommendation": "threat", "needs_human": False, "confidence": "high", "block_hours": 24,
        "reason_ko": ["출발지가 로그인 뒤 명령을 실행했다.", "로그인 성공 뒤 명령 실행은 위협 조건이다.", "출발지 차단을 검토한다."]}
SSH_CASE = {"rule_id": "R002", "source_ip": "198.51.100.7"}


class Fake(http.server.BaseHTTPRequestHandler):
    """경로마다 서버 동작을 고른다. server.mode: ok · broken · loop · http500 · slow · notollama"""
    def log_message(self, *a):
        pass

    def reply(self, code, body):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        mode = self.server.mode
        if mode == "slow":
            time.sleep(1.5)
        if mode == "notollama":
            return self.reply(200, b"<html>login</html>")
        self.reply(200, {"version": "0.35.1"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append(body)
        mode = self.server.mode
        if mode == "http500":
            return self.reply(500, {"error": "model not found"})
        content = {"ok": json.dumps(GOOD, ensure_ascii=False),
                   "broken": "{\"recommendation\": \"threat\", ",
                   "loop": json.dumps(GOOD | {"reason_ko": ["가", "block_hours\":24}}}}}}}", "다"]}, ensure_ascii=False)}
        if mode == "loop_then_ok":
            mode = "loop" if len(self.server.seen) == 1 else "ok"
        self.reply(200, {"message": {"role": "assistant", "content": content[mode]}})


class FakeServer:
    def __enter__(self):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        self.httpd.mode, self.httpd.seen = "ok", []
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ValidGuardTests(unittest.TestCase):
    def test_정상_응답은_통과한다(self):
        self.assertTrue(r.valid(GOOD))

    def test_망가진_응답은_거른다(self):
        for bad in (GOOD | {"recommendation": "false_positive"},          # 오탐은 사람만 판정한다
                    GOOD | {"recommendation": "benign_positive"},
                    GOOD | {"reason_ko": GOOD["reason_ko"][:2]},
                    GOOD | {"reason_ko": ["가", "block_hours\":24}}}}", "다"]},  # 반복 생성
                    GOOD | {"reason_ko": ["가" * 201, "나", "다"]},
                    GOOD | {"reason_ko": ["", "나", "다"]},
                    GOOD | {"needs_human": "false"},
                    GOOD | {"block_hours": True},                          # bool 은 int 의 하위형이라 따로 막는다
                    GOOD | {"block_hours": "24"},
                    {k: v for k, v in GOOD.items() if k != "reason_ko"}, [], None, "threat"):
            self.assertFalse(r.valid(bad), bad)

    def test_SSH_규칙_공인_출발지_위협은_24시간_제안(self):
        g = r.guard(SSH_CASE, GOOD)
        self.assertEqual((g["recommendation"], g["needs_human"], g["guard"], g["block_hours"]), ("threat", False, [], 24))

    def test_차단_금지_대역은_위협이라도_차단_제안이_없고_사람이_본다(self):
        g = r.guard({"rule_id": "R202", "source_ip": "192.168.60.1"}, GOOD)
        self.assertEqual((g["needs_human"], g["block_hours"]), (True, 0))
        self.assertEqual(g["guard"], ["SSH 규칙 밖 사건", "차단 금지 대역 출발지"])
        for ip in ("10.0.21.10", "172.17.0.2", "127.0.0.1", "fe80::1"):
            self.assertEqual(r.guard({"rule_id": "R002", "source_ip": ip}, GOOD)["block_hours"], 0, ip)

    def test_시험_공격_VM_은_문서용_대역이라도_차단_제안(self):
        # is_private 는 203.0.113.0/24 를 사설로 본다. 시연의 공격 VM 사건에 차단 제안이 빠지면 안 된다
        g = r.guard({"rule_id": "R002", "source_ip": "203.0.113.10"}, GOOD)
        self.assertEqual((g["guard"], g["block_hours"]), ([], 24))

    def test_차단_금지_대역은_콘솔과_triage_와_같다(self):
        import re
        root = os.path.dirname(HERE)
        for path in ("app/absorbed.py", "detector/triage.py"):
            src = open(os.path.join(root, path), encoding="utf-8").read()
            got = re.search(r"NO_BLOCK_NETS = (\[.*?\])", src, re.S).group(1)
            self.assertEqual(ast.literal_eval(got), r.NO_BLOCK_NETS, path)

    def test_SSH_규칙_밖_사건과_미결은_사람이_본다(self):
        g = r.guard({"rule_id": "R105", "source_ip": "203.0.113.9"}, GOOD | {"recommendation": "non_actionable", "block_hours": 24})
        self.assertEqual((g["needs_human"], g["guard"], g["block_hours"]), (True, ["SSH 규칙 밖 사건"], 0))
        g = r.guard(SSH_CASE, GOOD | {"recommendation": "undetermined"})
        self.assertEqual((g["needs_human"], g["guard"], g["block_hours"]), (True, ["미결 추천"], 0))

    def test_모델이_주는_차단_시간은_쓰지_않는다(self):
        self.assertEqual(r.guard(SSH_CASE, GOOD | {"block_hours": 9999})["block_hours"], 24)
        self.assertEqual(r.guard(SSH_CASE, GOOD | {"recommendation": "non_actionable"})["block_hours"], 0)

    def test_출발지가_없거나_이상해도_멈추지_않는다(self):
        for ip in (None, "", "not-an-ip"):
            self.assertEqual(r.guard({"rule_id": "R001", "source_ip": ip}, GOOD)["block_hours"], 24)

    def test_근거_줄의_공백을_한_칸으로(self):
        g = r.guard(SSH_CASE, GOOD | {"reason_ko": ["가\n  나", "다", "라"]})
        self.assertEqual(g["reasons"][0], "가 나")


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".env")
        self.addCleanup(os.unlink, self.tmp.name)

    def conf(self, text, **env):
        self.tmp.write(text)
        self.tmp.flush()
        env = {"OPSLOOP_AI_DEFAULTS": self.tmp.name} | env
        with mock.patch.dict(os.environ, env, clear=True):
            return r.settings()

    def test_기본값과_설정_파일(self):
        self.assertEqual(self.conf(""), {"url": "http://127.0.0.1:21434", "model": "gpt-oss:20b", "limit": 10})
        self.assertEqual(self.conf("OPSLOOP_AI_MAX_PER_RUN=3\nOPSLOOP_AI_URL=http://127.0.0.1:9/\n")["limit"], 3)

    def test_환경변수가_먼저(self):
        self.assertEqual(self.conf("OPSLOOP_AI_MODEL=a\n", OPSLOOP_AI_MODEL="b")["model"], "b")

    def test_터널_끝이_아닌_주소와_이상한_상한은_거부(self):
        for text in ("OPSLOOP_AI_URL=http://192.168.217.248:21434\n", "OPSLOOP_AI_URL=https://example.com\n",
                     "OPSLOOP_AI_MAX_PER_RUN=0\n", "OPSLOOP_AI_MAX_PER_RUN=500\n", "OPSLOOP_AI_MAX_PER_RUN=열\n"):
            self.tmp.seek(0)
            self.tmp.truncate()
            with self.subTest(text=text), self.assertRaises(r.ConfigError):
                self.conf(text)

    def test_설정_파일이_없어도_기본값(self):
        with mock.patch.dict(os.environ, {"OPSLOOP_AI_DEFAULTS": "/없는/파일"}, clear=True):
            self.assertEqual(r.settings()["limit"], 10)


class OllamaTests(unittest.TestCase):
    def test_정상(self):
        with FakeServer() as s:
            c = r.Ollama(s.url, "gpt-oss:20b")
            self.assertEqual(c.healthy(), "0.35.1")
            rec, err, sec = r.recommend(c, SSH_CASE, "0")
            self.assertIsNone(err)
            self.assertEqual(rec["recommendation"], "threat")
            body = s.httpd.seen[0]
            # 평가 때와 같은 설정으로 묻는다
            self.assertEqual((body["think"], body["keep_alive"], body["stream"]), ("low", "0", False))
            self.assertEqual(body["options"], {"temperature": 0, "seed": 7, "num_ctx": 8192, "num_predict": 700})
            self.assertEqual(body["format"], r.SCHEMA)
            self.assertTrue(body["messages"][1]["content"].startswith("<자료>\n"))

    def test_서버가_꺼져_있으면_닿지_않음(self):
        c = r.Ollama(f"http://127.0.0.1:{closed_port()}", "m")
        t0 = time.monotonic()
        with self.assertRaises(r.Unreachable):
            c.healthy()
        with self.assertRaises(r.Unreachable):
            r.recommend(c, SSH_CASE, "0")
        self.assertLess(time.monotonic() - t0, 5)

    def test_느린_서버는_시간_초과로_닿지_않음(self):
        with FakeServer() as s, mock.patch.object(r, "HEALTH_TIMEOUT", 0.3):
            s.httpd.mode = "slow"
            with self.assertRaises(r.Unreachable):
                r.Ollama(s.url, "m").healthy()

    def test_Ollama_가_아닌_응답은_닿지_않음으로(self):
        with FakeServer() as s:
            s.httpd.mode = "notollama"
            with self.assertRaises(r.Unreachable):
                r.Ollama(s.url, "m").healthy()

    def test_깨진_응답은_한_번_다시_묻고_실패로_남긴다(self):
        for mode, why in (("broken", "약속한 JSON"), ("loop", "망가짐"), ("http500", "응답 500")):
            with self.subTest(mode=mode), FakeServer() as s:
                s.httpd.mode = mode
                rec, err, _ = r.recommend(r.Ollama(s.url, "m"), SSH_CASE, "0")
                self.assertIsNone(rec)
                self.assertIn(why, err)
                self.assertEqual([b["options"]["seed"] for b in s.httpd.seen], [7, 8])

    def test_반복_생성_뒤_다시_물어_정상이면_저장한다(self):
        with FakeServer() as s:
            s.httpd.mode = "loop_then_ok"
            rec, err, _ = r.recommend(r.Ollama(s.url, "m"), SSH_CASE, "0")
            self.assertEqual((rec["recommendation"], err), ("threat", None))

    def test_오류_문장은_한_줄_300자_안(self):
        self.assertEqual(r.short("가\n나  다"), "가 나 다")
        self.assertEqual(len(r.short("x" * 1000)), 300)


class PromptTests(unittest.TestCase):
    """작업기의 지시문 · 출력 양식은 평가한 것(docs/evidence/2026-10-06-ai-pilot, p3-1006)과 같아야 한다.
    바꾸면 PROMPT_VERSION 을 올리고 다시 평가한다."""
    def test_평가한_지시문과_같다(self):
        if not os.path.exists(PILOT):
            self.skipTest("평가 도구가 없다")
        tree = ast.parse(open(PILOT, encoding="utf-8").read())
        got = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
               for t in n.targets if isinstance(t, ast.Name) and t.id in ("SYSTEM", "SCHEMA", "PROMPT_VERSION")}
        self.assertEqual(got["PROMPT_VERSION"], r.PROMPT_VERSION)
        self.assertEqual(got["SYSTEM"], r.SYSTEM)
        self.assertEqual(got["SCHEMA"], r.SCHEMA)

    def test_근거에_비밀번호_열을_넣지_않는다(self):
        # 모델이 근거 문장에 옮겨 적으면 콘솔 AI 칸으로 새어 나간다(평가 p2 에서 140건 중 51건)
        import re
        self.assertIsNone(re.search(r"\bpassword\b", r.EVIDENCE_SQL))

    def test_SSH_규칙은_콘솔_제안과_같다(self):
        sys.path.insert(0, os.path.join(os.path.dirname(HERE), "app"))
        import proposals
        self.assertEqual(r.SSH_RULES, proposals.SSH_RULES)


class ContractTests(unittest.TestCase):
    """단위 파일 · 설치기 · 마이그레이션 사이의 약속."""
    root = os.path.dirname(HERE)

    def read(self, rel):
        return open(os.path.join(self.root, rel), encoding="utf-8").read()

    def test_터널은_키로만_서버_키를_확인하고_127_0_0_1_에만_연다(self):
        unit = self.read("recommend/opsloop-ai-tunnel.service")
        for need in ("-o BatchMode=yes", "-o StrictHostKeyChecking=yes", "-o UserKnownHostsFile=/etc/opsloop/ai-known_hosts",
                     "-o ExitOnForwardFailure=yes", "-L 127.0.0.1:${OPSLOOP_AI_LOCAL_PORT}:127.0.0.1:${OPSLOOP_AI_REMOTE_PORT}",
                     "User=opsloop-ai", "Restart=always", "StartLimitIntervalSec=0", "NoNewPrivileges=yes"):
            self.assertIn(need, unit)
        self.assertNotIn("-R ", unit)                       # 서버가 안으로 들어오는 역방향 터널은 없다
        # 실패가 이어지면 간격을 늘린다(공용 서버에 1분마다 로그인 실패를 남기지 않는다, 이슈 #122)
        for need in ("RestartSec=60", "RestartSteps=4", "RestartMaxDelaySec=15min"):
            self.assertIn(need, unit)
        self.assertNotIn("StrictHostKeyChecking=no", unit)

    def test_작업기는_opsloop_ai_로_돌고_타이머는_5분(self):
        svc, timer = self.read("recommend/opsloop-recommend.service"), self.read("recommend/opsloop-recommend.timer")
        self.assertIn("User=opsloop-ai", svc)
        self.assertIn("ExecStart=/usr/local/bin/opsloop-recommend run", svc)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertFalse([ln for ln in timer.splitlines() if ln.startswith("OnCalendar")])   # 주석에만 나온다

    def test_설치기의_기본값은_작업기_기본값과_같고_서버_키는_Ollama_포트로만(self):
        inst = self.read("recommend/install-recommend.sh")
        self.assertIn('OPSLOOP_AI_URL=http://127.0.0.1:$AI_PORT', inst)
        self.assertIn('AI_PORT=${OPSLOOP_AI_REMOTE_PORT:-21434}', inst)
        self.assertEqual(r.DEFAULTS["OPSLOOP_AI_URL"], "http://127.0.0.1:21434")
        self.assertIn('OPSLOOP_AI_MODEL=gpt-oss:20b', inst)
        self.assertEqual(r.DEFAULTS["OPSLOOP_AI_MODEL"], "gpt-oss:20b")
        self.assertIn('restrict,port-forwarding,permitopen=\\"127.0.0.1:$REMOTE_PORT\\"', inst)
        self.assertIn('AI_HOST=${OPSLOOP_AI_HOST:-192.168.217.248}', inst)
        self.assertIn("define AI_SERVER = 192.168.217.248", self.read("infra/vmware/fw/nftables.conf"))
        self.assertIn("ensure_role opsloop_ai /etc/opsloop/ai.env 2", inst)

    def test_마이그레이션과_schema_블록이_같다(self):
        mig = self.read("infra/migrations/20261006_ai_recommend.sql")
        block = mig[mig.index("-- AI 판정 추천 (이슈 #120)\n--   판정 대기"):mig.index("COMMIT;")].rstrip()
        self.assertIn(block, self.read("infra/schema.sql"))


if __name__ == "__main__":
    unittest.main()
