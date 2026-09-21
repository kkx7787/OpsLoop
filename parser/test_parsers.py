#!/usr/bin/env python3
"""파서 단위 시험. DB 없이 parse_lines 만 본다.  python3 parser/test_parsers.py

독이 되는 줄(NUL · 긴 세션 · 객체가 아닌 JSON · 범위 밖 정수 · 주소가 아닌 src_ip)이 와도
행을 만들 수 있어야 하고, 정상 줄은 예전과 같은 값이어야 한다.
"""
import hashlib
import json
import os
import sys
import tempfile
import types
import unittest

# psycopg2 가 없는 곳에서도 돌게 가짜를 넣는다 (parse_lines 는 DB 를 쓰지 않는다)
if "psycopg2" not in sys.modules:
    fake = types.ModuleType("psycopg2")
    extras = types.ModuleType("psycopg2.extras")
    extras.execute_batch = lambda *a, **k: None
    fake.extras = extras
    sys.modules["psycopg2"], sys.modules["psycopg2.extras"] = fake, extras

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parse_cowrie  # noqa: E402
import parse_decoy   # noqa: E402


def lines_file(lines):
    fd, p = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write((ln if isinstance(ln, str) else json.dumps(ln)) + "\n")
    return p


def decoy_line(**kw):
    ev = {"ts": "2026-09-21T05:00:00+00:00", "eventid": "decoy.request", "session": "abc",
          "src_ip": "1.2.3.4", "src_port": 5555, "dst_port": 8080, "protocol": "http",
          "sensor": "decoy", "user_agent": "curl/8", "url": "/", "http_method": "GET"}
    ev.update(kw)
    return ev


def cowrie_line(**kw):
    ev = {"timestamp": "2026-09-21T05:00:00.123456Z", "eventid": "cowrie.login.failed",
          "session": "0123456789ab", "src_ip": "1.2.3.4", "src_port": 5555, "dst_port": 22,
          "protocol": "ssh", "username": "root", "password": "123456", "message": "login attempt"}
    ev.update(kw)
    return ev


def parse(mod, lines):
    stats = {}
    rows = list(mod.parse_lines([lines_file(lines)], set(), stats))
    return rows, stats["malformed"]


class DecoyTest(unittest.TestCase):
    def test_정상_줄은_그대로(self):
        ev = decoy_line()
        [row], bad = parse(parse_decoy, [ev])
        self.assertEqual(bad, 0)
        self.assertEqual(row[0], hashlib.sha1(json.dumps(ev).encode()).hexdigest())
        self.assertEqual(row[2:5], ("decoy.request", "abc", "1.2.3.4"))
        self.assertEqual(row[-1], "decoy")

    def test_NUL_은_지우고_해시는_원문대로(self):
        ev = decoy_line(url="/\x00x", username="admin\x00")
        [row], _ = parse(parse_decoy, [ev])
        self.assertEqual(row[11], "/x")
        self.assertEqual(row[8], "admin")
        self.assertEqual(row[0], hashlib.sha1(json.dumps(ev).encode()).hexdigest())

    def test_긴_세션은_색인_한도_안으로(self):
        [row], _ = parse(parse_decoy, [decoy_line(session="s" * 5000)])
        self.assertEqual(len(row[3]), 128)

    def test_다른_출처를_흉내_낸_줄은_받지_않음(self):
        rows, bad = parse(parse_decoy, [decoy_line(eventid="console.login.success", sensor="console")])
        self.assertEqual((rows, bad), ([], 1))
        [row], _ = parse(parse_decoy, [decoy_line(sensor="console")])
        self.assertEqual(row[-1], "decoy")               # 줄 안의 sensor 값은 믿지 않는다

    def test_이상한_값은_비우거나_글자로(self):
        [row], _ = parse(parse_decoy, ['{"ts":"2026-09-21T05:00:00+00:00","eventid":"decoy.request","src_port":1e400,'
                                       '"http_status":99999999999,"src_ip":"not-an-ip","message":["a",1]}'])
        self.assertIsNone(row[5])
        self.assertIsNone(row[16])
        self.assertIsNone(row[4])
        self.assertEqual(row[14], '["a", 1]')

    def test_객체가_아닌_JSON_과_깨진_줄(self):
        rows, bad = parse(parse_decoy, ["[1,2]", '"x"', "{bad", "[" * 100000, decoy_line()])
        self.assertEqual((len(rows), bad), (1, 4))


    def test_남은_독_줄_세_가지와_긴_줄(self):
        rows, bad = parse(parse_decoy, [
            decoy_line(src_ip="fe80::1%eth0"),
            '{"ts":"2026-09-21T05:00:00+00:00","eventid":"decoy.request","src_port":' + "9" * 5000 + '}',
            '{"ts":"2026-09-21T05:00:00+00:00","eventid":"decoy.request","url":"/\\ud800x"}',
            decoy_line(url="/" + "a" * (parse_decoy.MAX_LINE + 10)),
        ])
        self.assertEqual((len(rows), bad), (2, 2))
        self.assertIsNone(rows[0][4])
        rows[1][11].encode("utf-8")                       # 서로게이트가 남지 않아 UTF-8 로 바뀐다
        self.assertEqual(rows[1][11], "/?x")


class CowrieTest(unittest.TestCase):
    def test_정상_줄은_그대로(self):
        ev = cowrie_line()
        [row], bad = parse(parse_cowrie, [ev])
        self.assertEqual(bad, 0)
        self.assertEqual(row[0], hashlib.sha1(json.dumps(ev).encode()).hexdigest())
        self.assertEqual(row[2:10], ("cowrie.login.failed", "0123456789ab", "1.2.3.4", 5555, 22, "ssh", "root", "123456"))

    def test_NUL_비밀번호와_명령(self):
        [row], _ = parse(parse_cowrie, [cowrie_line(password="pa\x00ss", input="ls\x00")])
        self.assertEqual((row[9], row[10]), ("pass", "ls"))

    def test_긴_비밀번호는_자르지_않음(self):
        [row], _ = parse(parse_cowrie, [cowrie_line(password="p" * 10000)])
        self.assertEqual(len(row[9]), 10000)             # 색인이 없는 열은 원문 길이 그대로 (AWS 경로와 같은 값)

    def test_서로게이트_비밀번호와_영역_ID(self):
        [row], _ = parse(parse_cowrie, ['{"timestamp":"2026-09-21T05:00:00Z","eventid":"cowrie.login.failed",'
                                        '"password":"\\udc80pw","src_ip":"fe80::1%eth0"}'])
        row[9].encode("utf-8")
        self.assertIsNone(row[4])

    def test_cowrie_가_아닌_이벤트는_받지_않음(self):
        rows, bad = parse(parse_cowrie, [cowrie_line(eventid="console.login.success")])
        self.assertEqual((rows, bad), ([], 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
