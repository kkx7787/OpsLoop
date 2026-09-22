#!/usr/bin/env python3
"""관문 방화벽 기록 파서 단위 시험. DB 없이 parse_line · parse_lines 만 본다.  python3 parser/test_parse_gateway.py

방화벽이 실제로 남기는 줄(rsyslog RFC3339 · 커널 nft 기록 · 가동 시각 대괄호)은 설계대로 바뀌어야 하고,
독이 되는 줄(NUL · 잘린 줄 · 주소가 아닌 SRC · 4MiB 넘는 줄)과 설계 밖의 줄(연도 없는 옛 syslog 형식 ·
모르는 접두 · gw- 가 아닌 커널 줄)이 와도 예외 없이 건너뛰거나, 적재가 실패하지 않는 행을 만들어야 한다.
"""
import hashlib
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone

# psycopg2 가 없는 곳에서도 돌게 가짜를 넣는다 (parse_lines 는 DB 를 쓰지 않는다)
if "psycopg2" not in sys.modules:
    fake = types.ModuleType("psycopg2")
    extras = types.ModuleType("psycopg2.extras")
    extras.execute_batch = lambda *a, **k: None
    fake.extras = extras
    sys.modules["psycopg2"], sys.modules["psycopg2.extras"] = fake, extras

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parse_gateway as pg  # noqa: E402

TS = "2026-09-22T01:02:03.123456+00:00"
HOST = "ip-10-0-1-10"
FIELDS = ("IN=ens5 OUT=ens5 MAC=02:ab:cd:ef:01:23:02:00:00:00:00:01:08:00 SRC=203.0.113.7 DST=10.0.21.10 "
          "LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=54321 DF PROTO=TCP SPT=51234 DPT=445 WINDOW=65535 RES=0x00 SYN URGP=0")
EX = {"112.76.112.180", "127.0.0.1"}

# 행의 열 순서 (INSERT_EVENT 와 같다)
LINE_HASH, TS_, EVENTID, SESSION, SRC_IP, SRC_PORT, DST_PORT, PROTO, USER, PASS, INPUT, URL, SHASUM, PROV, MSG, HM, HS, UA, SENSOR = range(19)


def gw(prefix="gw-forward-drop", fields=FIELDS, ts=TS, host=HOST, tag="kernel:"):
    return f"{ts} {host} {tag} {prefix} {fields}".rstrip()


def sha1(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def parse(lines, exclusions=EX):
    fd, p = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")
    stats = {}
    rows = list(pg.parse_lines([p], exclusions, stats))
    os.unlink(p)
    return rows, stats["unmatched"]


class GatewayLineTest(unittest.TestCase):
    def test_전달_거부_줄은_설계대로(self):
        line = gw()
        row = pg.parse_line(line, EX)
        self.assertEqual(row[LINE_HASH], sha1(line))
        self.assertEqual(row[TS_], datetime(2026, 9, 22, 1, 2, 3, 123456, tzinfo=timezone.utc))
        self.assertEqual(row[EVENTID], "gateway.forward.drop")
        self.assertIsNone(row[SESSION])
        self.assertEqual((row[SRC_IP], row[SRC_PORT], row[DST_PORT], row[PROTO]), ("203.0.113.7", 51234, 445, "tcp"))
        self.assertEqual(row[INPUT], "in=ens5 out=ens5 dst=10.0.21.10")
        self.assertEqual((row[PROV], row[MSG], row[SENSOR]), ("real", line, "gateway"))
        for i in (USER, PASS, URL, SHASUM, HM, HS, UA):
            self.assertIsNone(row[i])
        self.assertEqual(len(row), pg.INSERT_EVENT.count("%s"))        # 열 수와 자리표시자 수가 같다

    def test_세_접두가_각각의_eventid_로(self):
        for prefix, eventid in (("gw-forward-drop", "gateway.forward.drop"), ("gw-input-drop", "gateway.input.drop"),
                                ("gw-egress", "gateway.egress")):
            self.assertEqual(pg.parse_line(gw(prefix), EX)[EVENTID], eventid, prefix)
        self.assertTrue(all(v.startswith("gateway.") for v in pg.EVENTIDS.values()))   # 허니팟 규칙(cowrie.*)에 걸리지 않는다

    def test_시간대와_커널_가동_시각(self):
        row = pg.parse_line(gw(ts="2026-09-22T10:02:03+09:00"), EX)
        self.assertEqual(row[TS_], datetime(2026, 9, 22, 1, 2, 3, tzinfo=timezone.utc))
        self.assertEqual(pg.parse_line(gw(ts="2026-09-22T01:02:03Z"), EX)[TS_],
                         datetime(2026, 9, 22, 1, 2, 3, tzinfo=timezone.utc))
        # rsyslog imklog 기본값은 커널 가동 시각을 본문에 남긴다
        row = pg.parse_line(f"{TS} {HOST} kernel: [   12.345678] gw-input-drop {FIELDS}", EX)
        self.assertEqual((row[EVENTID], row[SRC_IP]), ("gateway.input.drop", "203.0.113.7"))

    def test_제외_목록의_출발지는_fixture(self):
        row = pg.parse_line(gw(fields=FIELDS.replace("SRC=203.0.113.7", "SRC=112.76.112.180")), EX)
        self.assertEqual((row[SRC_IP], row[PROV]), ("112.76.112.180", "fixture"))
        self.assertEqual(pg.parse_line(gw(), set())[PROV], "real")

    def test_접두_뒤가_잘린_줄은_있는_필드만으로(self):
        row = pg.parse_line(gw(fields="IN=ens5 OUT=ens5 SRC=203.0.113.7 DS"), EX)
        self.assertEqual((row[SRC_IP], row[DST_PORT], row[PROTO]), ("203.0.113.7", None, None))
        self.assertEqual(row[INPUT], "in=ens5 out=ens5 dst=")
        row = pg.parse_line(f"{TS} {HOST} kernel: gw-input-drop", EX)               # 접두만 남은 줄
        self.assertEqual((row[EVENTID], row[SRC_IP], row[INPUT]), ("gateway.input.drop", None, "in= out= dst="))

    def test_접두가_잘리거나_모르는_접두는_unmatched(self):
        rows, bad = parse([f"{TS} {HOST} kernel: gw-forw", f"{TS} {HOST} kernel: gw-", f"{TS} {HOST} kernel: gw-other {FIELDS}",
                           f"{TS} {HOST} kernel: audit: type=1400 apparmor", f"{TS} {HOST} sshd[1]: gw-egress {FIELDS}",
                           f"{TS} {HOST}", "", "   "])
        self.assertEqual((rows, bad), ([], 6))

    def test_연도_없는_옛_syslog_형식은_unmatched(self):
        rows, bad = parse([f"Sep 22 01:02:03 {HOST} kernel: gw-forward-drop {FIELDS}",
                           gw(ts="2026-09-22T01:02:03"),                       # 시간대 없음
                           gw(ts="2026-13-22T01:02:03+00:00"),                 # 13월
                           gw()])
        self.assertEqual((len(rows), bad), (1, 3))

    def test_NUL_은_지우고_해시는_원문대로(self):
        line = gw(fields=FIELDS + " URGP=0\x00x")
        row = pg.parse_line(line, EX)
        self.assertNotIn("\x00", row[MSG])
        self.assertEqual(row[LINE_HASH], sha1(line))
        self.assertEqual(row[SRC_IP], "203.0.113.7")
        row = pg.parse_line(gw(fields=FIELDS.replace("SRC=203.0.113.7", "SRC=203.0.113.7\x00")), EX)
        self.assertIsNone(row[SRC_IP])                                       # NUL 이 낀 주소는 비운다
        row = pg.parse_line(gw(host="ip\x00host"), EX)
        self.assertEqual(row[EVENTID], "gateway.forward.drop")

    def test_주소가_아닌_SRC_는_비운다(self):
        for bad in ("999.1.1.1", "fe80::1%eth0", "not-an-ip", "", "1.2.3.4;rm"):
            row = pg.parse_line(gw(fields=FIELDS.replace("SRC=203.0.113.7", f"SRC={bad}")), EX)
            self.assertIsNone(row[SRC_IP], bad)
            self.assertEqual(row[PROV], "real")
        row = pg.parse_line(gw(fields=FIELDS.replace("SRC=203.0.113.7", "SRC=2001:db8::1")), EX)
        self.assertEqual(row[SRC_IP], "2001:db8::1")

    def test_이상한_포트와_프로토콜(self):
        row = pg.parse_line(gw(fields="SRC=203.0.113.7 PROTO=ICMP TYPE=8 CODE=0"), EX)
        self.assertEqual((row[SRC_PORT], row[DST_PORT], row[PROTO]), (None, None, "icmp"))
        row = pg.parse_line(gw(fields="PROTO=UDP SPT=99999999999 DPT=0x35 SRC=203.0.113.7"), EX)
        self.assertEqual((row[SRC_PORT], row[DST_PORT], row[PROTO]), (None, None, "udp"))
        row = pg.parse_line(gw(fields="PROTO=" + "X" * 100 + " SPT=53 SPT=54"), EX)
        self.assertEqual((len(row[PROTO]), row[SRC_PORT]), (32, 53))           # 같은 키가 두 번이면 앞 것

    def test_긴_줄과_긴_메시지(self):
        rows, bad = parse([gw(fields="X=" + "x" * (pg.MAX_LINE + 10)), gw(fields=FIELDS + " Y=" + "y" * 2000)])
        self.assertEqual((len(rows), bad), (1, 1))
        self.assertEqual(len(rows[0][MSG]), 512)
        self.assertEqual(rows[0][LINE_HASH], sha1(gw(fields=FIELDS + " Y=" + "y" * 2000)))

    def test_서로게이트가_와도_죽지_않는다(self):
        row = pg.parse_line(gw(fields=FIELDS + " Z=\udc80"), EX)
        row[MSG].encode("utf-8")
        self.assertEqual(len(row[LINE_HASH]), 40)

    def test_파일_단위_읽기와_없는_파일(self):
        rows, bad = parse([gw(), gw("gw-egress", ts="2026-09-22T01:02:04+00:00"), "garbage"])
        self.assertEqual(([r[EVENTID] for r in rows], bad), (["gateway.forward.drop", "gateway.egress"], 1))
        stats = {}
        old, sys.stderr = sys.stderr, open(os.devnull, "w")
        try:
            self.assertEqual(list(pg.parse_lines(["/nonexistent/gateway.log"], EX, stats)), [])
        finally:
            sys.stderr.close(); sys.stderr = old
        self.assertEqual(stats["unmatched"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
