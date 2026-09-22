#!/usr/bin/env python3
"""적재 실행기(opsloop-ingest) 단위 시험.  python3 puller/test_ingest.py

가짜 풀러 · 파서 · 탐지기를 둔 임시 APP 로 돌린다. 가짜 파서는 파일 안에 POISON 이 있으면 실패한다.
"""
import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

FAKE_PULL = """import os, sys
sys.exit(int(open(os.environ["FAKE_PULL_RC_FILE"]).read()))
"""
FAKE_PARSER = """import os, sys
files = [l.strip() for l in sys.stdin if l.strip()]
if any(b"POISON" in open(p, "rb").read() for p in files):
    sys.exit(1)
with open(os.environ["FAKE_LOG"], "a") as f:
    for p in files:
        f.write(os.path.basename(p) + "\\n")
"""
FAKE_DETECT = """import os
open(os.environ["FAKE_DETECT"], "a").write("run\\n")
"""


def load_ingest():
    loader = importlib.machinery.SourceFileLoader("ingest", os.path.join(HERE, "opsloop-ingest"))
    spec = importlib.util.spec_from_loader("ingest", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.app = os.path.join(self.t, "app")
        self.home = os.path.join(self.t, "home")
        for d, name, body in (("puller", "pull.py", FAKE_PULL), ("parser", "parse_cowrie.py", FAKE_PARSER),
                              ("parser", "parse_decoy.py", FAKE_PARSER), ("parser", "parse_gateway.py", FAKE_PARSER),
                              ("detector", "detect.py", FAKE_DETECT)):
            os.makedirs(os.path.join(self.app, d), exist_ok=True)
            with open(os.path.join(self.app, d, name), "w") as f:
                f.write(body)
        for sensor in ("cowrie", "decoy", "gateway"):
            os.makedirs(os.path.join(self.home, "inbox", sensor))
        self.rc_file = os.path.join(self.t, "rc")
        self.set_pull(0)
        self.log = os.path.join(self.t, "loaded")
        self.detect = os.path.join(self.t, "detect")
        for p in (self.log, self.detect):
            open(p, "w").close()
        s3env, dbenv = os.path.join(self.t, "s3.env"), os.path.join(self.t, "db.env")
        open(s3env, "w").write("AWS_ACCESS_KEY_ID=x\n")
        open(dbenv, "w").write("DATABASE_URL=postgresql://x\n")
        os.environ.update({"FAKE_PULL_RC_FILE": self.rc_file, "FAKE_LOG": self.log, "FAKE_DETECT": self.detect})
        self.m = load_ingest()
        self.m.APP, self.m.HOME, self.m.S3_ENV, self.m.DB_ENV = self.app, self.home, s3env, dbenv
        self.m.base_env = lambda: {k: v for k, v in os.environ.items()
                                   if k.startswith("FAKE_") or k in ("PATH", "LANG")}
        self.m.db_ok = lambda env: True
        self.m.log = lambda msg, level=6: None

    def set_pull(self, rc):
        open(self.rc_file, "w").write(str(rc))

    def put(self, sensor, name, body=b'{"x":1}\n'):
        with open(os.path.join(self.home, "inbox", sensor, name), "wb") as f:
            f.write(body)

    def loaded(self):
        return open(self.log).read().split()

    def detected(self):
        return open(self.detect).read().count("run")

    def run_main(self, *args):
        old = sys.argv
        sys.argv = ["opsloop-ingest", *args]
        try:
            return self.m.main()
        finally:
            sys.argv = old

    def inbox(self, sensor, sub=""):
        d = os.path.join(self.home, "inbox", sensor, sub)
        return sorted(n for n in os.listdir(d) if n.endswith(".jsonl")) if os.path.isdir(d) else []

    def test_정상_회차(self):
        self.put("cowrie", "a.jsonl")
        self.put("decoy", "b.jsonl")
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(sorted(self.loaded()), ["a.jsonl", "b.jsonl"])
        self.assertEqual((self.inbox("cowrie"), self.inbox("decoy")), ([], []))
        self.assertEqual(self.detected(), 1)

    def test_관문_기록은_gateway_파서로(self):
        self.put("gateway", "g.jsonl", b"2026-09-22T01:02:03+00:00 gw kernel: gw-forward-drop SRC=203.0.113.7\n")
        self.put("cowrie", "a.jsonl")
        calls = []
        real = self.m.parse
        self.m.parse = lambda sensor, files, env: calls.append((sensor, [os.path.basename(p) for p in files])) or real(sensor, files, env)
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(sorted(calls), [("cowrie", ["a.jsonl"]), ("gateway", ["g.jsonl"])])   # 발생원별 파서(parse_gateway.py)
        self.assertEqual(sorted(self.loaded()), ["a.jsonl", "g.jsonl"])
        self.assertEqual(self.inbox("gateway"), [])
        self.assertEqual(self.m.SENSORS, ("cowrie", "decoy", "gateway"))
        # gateway 파서가 없으면 그 조각만 격리되고 나머지는 간다
        os.unlink(os.path.join(self.app, "parser", "parse_gateway.py"))
        self.put("gateway", "h.jsonl")
        self.put("decoy", "b.jsonl")
        self.assertEqual(self.run_main(), 12)
        self.assertEqual(self.inbox("gateway", "quarantine"), ["h.jsonl"])
        self.assertIn("b.jsonl", self.loaded())

    def test_독_파일만_격리하고_나머지는_적재_탐지(self):
        self.put("decoy", "a.jsonl")
        self.put("decoy", "b.jsonl", b"POISON\n")
        self.put("decoy", "c.jsonl")
        self.put("cowrie", "d.jsonl")
        self.assertEqual(self.run_main(), 12)
        self.assertEqual(sorted(self.loaded()), ["a.jsonl", "c.jsonl", "d.jsonl"])
        self.assertEqual(self.inbox("decoy", "quarantine"), ["b.jsonl"])
        self.assertEqual(self.detected(), 1)
        # 다음 회차: 격리 파일이 고쳐졌으면 돌아온다
        with open(os.path.join(self.home, "inbox", "decoy", "quarantine", "b.jsonl"), "wb") as f:
            f.write(b'{"ok":1}\n')
        self.assertEqual(self.run_main(), 12)                 # 아직 다시 시도할 시각이 아니다
        import types, time as _t
        self.m.time = types.SimpleNamespace(time=lambda: _t.time() + 400)
        self.m._just_quarantined.clear()
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.inbox("decoy", "quarantine"), [])

    def test_격리_재시도는_예산_안에서_탐지_뒤에(self):
        import types, time as _t
        q = os.path.join(self.home, "inbox", "cowrie", "quarantine")
        os.makedirs(q)
        for i in range(30):
            with open(os.path.join(q, f"{i:03d}.jsonl"), "wb") as f:
                f.write(b"POISON\n")
        self.put("cowrie", "new.jsonl")
        calls = []
        real = self.m.parse
        self.m.parse = lambda sensor, files, env: calls.append(len(files)) or real(sensor, files, env)
        self.assertEqual(self.run_main(), 12)
        self.assertEqual(self.loaded(), ["new.jsonl"])        # 새 파일 적재와 탐지가 먼저다
        self.assertEqual(self.detected(), 1)
        self.assertEqual(len(calls), 1 + self.m.RETRY_PER_RUN)
        calls.clear()
        self.run_main()
        self.assertEqual(len(calls), 10)                      # 실패한 20개는 간격이 남아 나머지 10개만
        calls.clear()
        self.m.time = types.SimpleNamespace(time=lambda: _t.time() + 100000)
        self.run_main()
        self.assertEqual(len(calls), self.m.RETRY_PER_RUN)

    def test_디스크_부족이면_탐지_보류(self):
        self.set_pull(13)
        self.put("cowrie", "a.jsonl")
        self.assertEqual(self.run_main(), 13)
        self.assertEqual(self.loaded(), ["a.jsonl"])
        self.assertEqual(self.detected(), 0)

    def test_구멍이면_적재는_하고_탐지는_보류(self):
        self.set_pull(10)
        self.put("cowrie", "a.jsonl")
        self.assertEqual(self.run_main(), 10)
        self.assertEqual(self.loaded(), ["a.jsonl"])
        self.assertEqual(self.detected(), 0)

    def test_생존신호_이상은_적재_탐지_후_11(self):
        self.set_pull(11)
        self.put("cowrie", "a.jsonl")
        self.assertEqual(self.run_main(), 11)
        self.assertEqual(self.detected(), 1)

    def test_가져오기_실패면_받아둔_것만_적재하고_탐지_보류(self):
        self.set_pull(2)
        self.put("cowrie", "a.jsonl")
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.loaded(), ["a.jsonl"])
        self.assertEqual(self.detected(), 0)
        self.set_pull(1)                                          # 일시 오류도 같다
        self.put("cowrie", "b.jsonl")
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.detected(), 0)

    def test_DB_가_없으면_편지함을_건드리지_않음(self):
        self.m.db_ok = lambda env: False
        self.put("cowrie", "a.jsonl")
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.inbox("cowrie"), ["a.jsonl"])
        self.assertEqual(self.inbox("cowrie", "quarantine"), [])

    def test_많은_파일은_묶음으로(self):
        self.m.BATCH_FILES = 7
        for i in range(30):
            self.put("cowrie", f"{i:03d}.jsonl")
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(self.loaded()), 30)
        self.assertEqual(self.inbox("cowrie"), [])

    def test_전체_재적재(self):
        mirror = os.path.join(self.home, "raw", "v1", "sensor=cowrie", "host=i-0123456789abcdef0", "ino=11.g0")
        os.makedirs(mirror)
        with open(os.path.join(mirror, "000000000000-000000000008.jsonl"), "wb") as f:
            f.write(b'{"x":1}\n')
        self.assertEqual(self.run_main("--full"), 0)
        self.assertEqual(self.loaded(), ["i-0123456789abcdef0.11.g0.000000000000-000000000008.jsonl"])
        self.assertTrue(os.path.exists(os.path.join(mirror, "000000000000-000000000008.jsonl")))  # 미러는 남는다

    def test_파서는_S3_키를_보지_못함(self):
        seen = os.path.join(self.t, "env")
        with open(os.path.join(self.app, "parser", "parse_cowrie.py"), "a") as f:
            f.write(f"\nopen({seen!r}, 'w').write(os.environ.get('AWS_ACCESS_KEY_ID', 'none'))\n")
        self.put("cowrie", "a.jsonl")
        self.run_main()
        self.assertEqual(open(seen).read(), "none")


if __name__ == "__main__":
    unittest.main(verbosity=2)
