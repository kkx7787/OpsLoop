#!/usr/bin/env python3
"""관문 차단 목록 동기화 시험 (이슈 #47).  python3 infra/aws/gateway/test_block_sync.py

가짜 nft(집합 · 원자적 묶음 · 원소 만료) · 가짜 fail2ban-client(banip 이 actionban 으로 nft 에 넣는다) · 가짜 S3 로
두 모드의 반영 · 대조 · 되살림 · 금지 대역 재검사 · digest 불일치 거부 · 상한 · until 지남 · 자가 시험 판정을 본다.
설정 파일(nftables.conf · fail2ban · systemd)은 글자로 읽어 계약과 맞는지 본다. nft 가 있고 root 면 문법도 본다.
"""
import configparser
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("block_sync", os.path.join(HERE, "block-sync.py"))
bs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bs)

HOST = "i-0ffeb29efad03546d"
ELEM_RE = re.compile(r"(add|delete) element inet filter opsloop_block \{ (\S+)(?: timeout (\d+)s)? \}")


class Clock:
    def __init__(self, now):
        self.now = now

    @property
    def t(self):
        return self.now.timestamp()

    def advance(self, sec):
        self.now += timedelta(seconds=sec)


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self):
        self.objects, self.puts = {}, []
        self.fail_get = self.fail_put = None

    def get_object(self, Bucket, Key):
        if self.fail_get:
            raise ClientError(self.fail_get)
        if Key not in self.objects:
            raise ClientError("NoSuchKey")
        return {"Body": io.BytesIO(self.objects[Key])}

    def put_object(self, Bucket, Key, Body, ContentType=None):
        if self.fail_put:
            raise ClientError(self.fail_put)
        self.objects[Key] = Body
        self.puts.append((Key, ContentType))


class Fake:
    """nft 와 fail2ban-client 를 흉내 낸다. 커널 집합 상태는 elems {ip: (timeout 초|None, 넣은 시각)} 이다."""

    def __init__(self, clock):
        self.clock = clock
        self.elems = {}
        self.set_exists = True
        self.rule = True
        self.fail_add, self.fail_del = set(), set()
        self.vanish_after_list = set()       # 집합을 읽은 직후 만료로 빠지는 원소(읽기와 반영 사이의 경주)
        self.size = 4096
        self.f2b_up = True
        self.banned = {}
        self.bantime = 86400
        self.action_ok = True
        self.banned_form = "repr"
        self.calls = []

    # 커널
    def live(self):
        return {ip: v for ip, v in self.elems.items() if v[0] is None or v[1] + v[0] > self.clock.t}

    def expires(self, ip):
        timeout, t0 = self.live()[ip]
        return None if timeout is None else int(t0 + timeout - self.clock.t)

    def __call__(self, argv, stdin=None, timeout=None):
        self.calls.append((tuple(argv), stdin))
        if argv[0] == "nft":
            return self.nft(list(argv[1:]), stdin)
        if argv[0] == "fail2ban-client":
            return self.f2b(list(argv[1:]))
        return 127, "", f"{argv[0]} 없음"

    def nft(self, args, stdin):
        missing = (1, "", "Error: No such file or directory\nlist set inet filter opsloop_block\n")
        if args == ["-j", "list", "set", "inet", "filter", "opsloop_block"]:
            if not self.set_exists:
                return missing
            elem = []
            for ip in sorted(self.live(), key=ipaddress.ip_address):
                timeout, _ = self.elems[ip]
                elem.append(ip if timeout is None else {"elem": {"val": ip, "timeout": timeout, "expires": self.expires(ip)}})
            s = {"family": "inet", "name": "opsloop_block", "table": "filter", "type": "ipv4_addr", "handle": 3,
                 "size": 4096, "flags": ["timeout"]}
            if elem:
                s["elem"] = elem
            for ip in self.vanish_after_list:
                self.elems.pop(ip, None)
            self.vanish_after_list = set()
            return 0, json.dumps({"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
                                               {"set": s}]}), ""
        if args == ["list", "chain", "inet", "filter", "forward"]:
            rule = ('\t\tip saddr @opsloop_block limit rate 10/second burst 5 packets log prefix "gw-block-drop "\n'
                    "\t\tip saddr @opsloop_block drop\n") if self.rule else ""
            return 0, ("table inet filter {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n"
                       "\t\tct state established,related accept\n" + rule +
                       "\t\tip daddr 10.0.21.10 ct status dnat tcp dport { 22, 23, 8080 } accept\n\t}\n}\n"), ""
        if args == ["-f", "/dev/stdin"]:
            if not self.set_exists:
                return missing
            work = self.live()
            for line in (stdin or "").splitlines():
                m = ELEM_RE.fullmatch(line.strip())
                if not m:
                    return 1, "", f"Error: syntax error\n{line}\n"
                kind, ip, timeout = m.groups()
                ipaddress.IPv4Address(ip)
                if kind == "add":
                    if ip in self.fail_add:
                        return 1, "", "Error: Could not process rule: Operation not permitted\n"
                    if ip not in work:                      # 있는 원소에 add 는 아무 일도 없다 (timeout 도 그대로)
                        if len(work) >= self.size:
                            return 1, "", "Error: Could not process rule: No space left on device\n"
                        work[ip] = (int(timeout) if timeout else None, self.clock.t)
                else:
                    if ip not in work or ip in self.fail_del:
                        return 1, "", "Error: Could not process rule: No such file or directory\n"
                    del work[ip]
            self.elems = work                               # 묶음이 다 되어야 반영한다
            return 0, "", ""
        return 1, "", "Error: 알 수 없는 명령\n"

    def f2b(self, args):
        if not self.f2b_up:
            return 255, "", ("ERROR   Failed to access socket path: /var/run/fail2ban/fail2ban.sock. "
                             "Is fail2ban running?\n")
        if args == ["ping"]:
            return 0, "Server replied: pong\n", ""
        if len(args) >= 2 and args[1] != "opsloop-block":
            return 255, "", f"ERROR  NOK: ('{args[1]}',)\n"
        if args == ["get", "opsloop-block", "banned"]:
            if self.banned_form == "bare":                  # 따옴표 없이 찍히는 판을 흉내 낸다
                return 0, "[" + ", ".join(sorted(self.banned)) + "]\n", ""
            return 0, repr(sorted(self.banned)) + "\n", ""
        if args == ["get", "opsloop-block", "banip"]:
            return 0, " ".join(sorted(self.banned)) + "\n", ""
        if args[:3] == ["set", "opsloop-block", "banip"]:
            n = 0
            for ip in args[3:]:
                if ip in self.banned:                        # 이미 걸린 주소는 다시 걸지 않는다
                    continue
                self.banned[ip] = self.clock.t
                n += 1
                if self.action_ok:                           # actionban 이 실패해도 fail2ban 은 걸린 것으로 안다
                    self.nft(["-f", "/dev/stdin"], f"add element inet filter opsloop_block {{ {ip} timeout {self.bantime}s }}\n")
            return 0, f"{n}\n", ""
        if args[:3] == ["set", "opsloop-block", "unbanip"]:
            n = 0
            for ip in args[3:]:
                if self.banned.pop(ip, None) is not None:
                    n += 1
                    self.nft(["-f", "/dev/stdin"], f"delete element inet filter opsloop_block {{ {ip} }}\n")
            return 0, f"{n}\n", ""
        return 255, "", "ERROR 알 수 없는 명령\n"

    def count(self, *prefix):
        return sum(1 for argv, _ in self.calls if argv[:len(prefix)] == prefix)


def list_doc(entries, generated_at, digest=None, v=1):
    canon = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    d = hashlib.sha256(canon.encode()).hexdigest() if digest is None else digest
    return json.dumps({"v": v, "generated_at": generated_at, "entries": entries, "digest": d}).encode()


class Base(unittest.TestCase):
    MODE = "fail2ban"

    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.clock = Clock(self.now)
        self.fake = Fake(self.clock)
        self.s3 = FakeS3()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def iso(self, sec=0):
        return (self.clock.now + timedelta(seconds=sec)).isoformat()

    def put_list(self, entries, generated_at=None, **kw):
        self.s3.objects[bs.LIST_KEY] = list_doc(entries, generated_at or self.iso(), **kw)

    def digest(self):
        return json.loads(self.s3.objects[bs.LIST_KEY])["digest"]

    def round(self, mode=None, dry_run=False):
        cfg = {"mode": mode or self.MODE, "bucket": "opsloop-archive-test", "host": HOST, "state": self.tmp}
        st, self.plan = bs.sync(cfg, self.s3, bs.Nft(self.fake), bs.Fail2ban(self.fake), now=self.clock.now,
                                dry_run=dry_run)
        return st

    def main(self, *argv, mode=None, host=HOST):
        env = {"MODE": mode or self.MODE, "OPSLOOP_BUCKET": "opsloop-archive-test", "OPSLOOP_HOST": host,
               "OPSLOOP_BLOCK_STATE": self.tmp}
        if host.startswith("fw-"):
            env.update(AWS_ACCESS_KEY_ID="AKIATEST", AWS_SECRET_ACCESS_KEY="secret-test")
        out = io.StringIO()
        old = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = out
        try:
            rc = bs.main(list(argv), env=env, s3=self.s3, nft=bs.Nft(self.fake), f2b=bs.Fail2ban(self.fake))
        finally:
            sys.stdout, sys.stderr = old
        return rc, out.getvalue()

    def whys(self, st):
        return {r["ip"]: r["why"] for r in st["rejected"]}


class ListTest(Base):
    def test_digest_는_계약대로_계산한다(self):
        entries = [{"ip": "198.51.100.7", "until": "2026-09-28T00:00:00+00:00"}]
        canon = '[{"ip":"198.51.100.7","until":"2026-09-28T00:00:00+00:00"}]'
        self.assertEqual(bs.canonical_digest(entries), hashlib.sha256(canon.encode()).hexdigest())
        # 파일 안의 키 순서는 상관없다. 항목 순서는 다시 정렬하지 않고 적힌 그대로 쓴다
        self.assertEqual(bs.canonical_digest([{"until": "2026-09-28T00:00:00+00:00", "ip": "198.51.100.7"}]),
                         bs.canonical_digest(entries))
        two = [{"ip": "9.9.9.9", "until": "x"}, {"ip": "10.0.0.1", "until": "y"}]
        self.assertNotEqual(bs.canonical_digest(two), bs.canonical_digest(two[::-1]))

    def test_목록을_못_읽으면_집합을_건드리지_않는다(self):
        self.fake.elems["198.51.100.7"] = (86400, self.clock.t)
        self.fake.banned["198.51.100.7"] = self.clock.t
        for fail in (None, "AccessDenied"):
            self.s3.fail_get = fail
            st = self.round()
            self.assertIsNone(st["list_digest"])
            self.assertEqual(st["errors"], [f"목록을 읽지 못함 ({fail or 'NoSuchKey'})"])
            self.assertEqual(st["set_count"], 1)
        self.assertEqual(set(self.fake.live()), {"198.51.100.7"})
        self.assertEqual(set(self.fake.banned), {"198.51.100.7"})
        self.assertEqual(self.fake.count("nft", "-f") + self.fake.count("fail2ban-client", "set"), 0)

    def test_digest_불일치는_거부하고_집합을_건드리지_않는다(self):
        self.fake.elems["198.51.100.7"] = (3600, self.clock.t)
        entries = [{"ip": "203.0.113.9", "until": self.iso(3600)}]
        self.s3.objects[bs.LIST_KEY] = list_doc(entries, self.iso(), digest="0" * 64)
        st = self.round()
        self.assertEqual((st["list_digest"], st["errors"]), (None, ["목록 digest 불일치"]))
        self.assertEqual(set(self.fake.live()), {"198.51.100.7"})
        # 목록을 바꿔치기해도(항목은 그대로 두고 digest 만 옛 값) 거부한다
        self.put_list(entries)
        doc = json.loads(self.s3.objects[bs.LIST_KEY])
        doc["entries"].append({"ip": "8.8.8.8", "until": self.iso(3600)})
        self.s3.objects[bs.LIST_KEY] = json.dumps(doc).encode()
        self.assertEqual(self.round()["errors"], ["목록 digest 불일치"])
        self.assertEqual(self.fake.count("nft", "-f") + self.fake.count("fail2ban-client", "set"), 0)

    def test_형식이_틀린_목록은_거부한다(self):
        e = [{"ip": "203.0.113.9", "until": self.iso(3600)}]
        cases = {
            "목록 판 번호가 1 이 아니다": [list_doc(e, self.iso(), v=2), list_doc(e, self.iso(), v=True),
                                   json.dumps([1]).encode()],
            "목록 형식이 틀리다": [json.dumps({"v": 1, "generated_at": self.iso(), "entries": {}, "digest": "x"}).encode(),
                            json.dumps({"v": 1, "generated_at": self.iso(), "entries": []}).encode()],
            "목록 generated_at 형식이 틀리다": [list_doc(e, "2026-09-27T12:00:00"), list_doc(e, "어제")],
            "목록이 JSON 이 아니다": [b"{", b'{"v": NaN}', b"\xff\xfe"],
            "목록 크기 초과": [b" " * (bs.MAX_LIST_BYTES + 1)],
        }
        for why, bodies in cases.items():
            for body in bodies:
                self.s3.objects[bs.LIST_KEY] = body
                st = self.round()
                self.assertEqual((st["list_digest"], st["errors"]), (None, [why]), body[:60])
        self.assertEqual(self.fake.count("nft", "-f") + self.fake.count("fail2ban-client", "set"), 0)

    def test_오래된_목록으로는_다시_걸지_않아_bantime_에_풀린다(self):
        # 집행기가 멈추면 목록이 그대로 남는다. 그사이의 해제가 목록에 오지 않으므로 관문은 차단을 늘리지 않는다
        a, b = "203.0.113.9", "198.51.100.7"
        self.put_list([{"ip": a, "until": self.iso(3 * 86400)}, {"ip": b, "until": self.iso(3600)}])
        self.assertEqual(self.round()["errors"], [])
        self.clock.advance(40 * 60)
        st = self.round()
        self.assertEqual(st["errors"], ["목록이 오래됨 (40분) · 넣거나 늘리지 않음"])
        # 목록을 적용한 것이 아니다. 집행기는 '관문이 목록을 적용하지 못함 · 목록이 오래됨 …' 으로 읽는다
        self.assertEqual((st["list_digest"], st["list_generated_at"], st["applied"], st["rejected"]), (None, None, 2, []))
        self.clock.advance(30 * 60)                    # b 의 until 이 지났다. 오래된 목록이어도 빼기는 한다
        st = self.round()
        self.assertEqual((set(self.fake.banned), set(self.fake.live()), self.whys(st)), ({a}, {a}, {b: "만료 지남"}))
        self.clock.advance(86400 - 70 * 60 - 300)      # a 의 원소가 5분 남았다. 신선한 목록이면 다시 걸 때다
        sets = self.fake.count("fail2ban-client", "set")
        self.round()
        self.assertEqual(self.fake.count("fail2ban-client", "set"), sets)
        self.assertLessEqual(self.fake.expires(a), 300)
        self.clock.advance(301)                        # 원소가 만료로 빠지면 fail2ban 에서도 푼다
        st = self.round()
        self.assertEqual((self.fake.live(), self.fake.banned, st["applied"]), ({}, {}, 0))

    def test_오래된_목록으로는_새로_넣거나_flush_뒤_되살리지_않는다(self):
        a, c = "203.0.113.9", "198.51.100.7"
        self.put_list([{"ip": a, "until": self.iso(3 * 86400)}])
        self.round()
        # 관문이 못 받은 새 항목(c)이 든 목록이 40분 전 것이다
        self.put_list([{"ip": a, "until": self.iso(3 * 86400)}, {"ip": c, "until": self.iso(3600)}],
                      generated_at=self.iso(-40 * 60))
        st = self.round()
        self.assertEqual((set(self.fake.banned), set(self.fake.live()), st["applied"]), ({a}, {a}, 1))
        self.fake.elems.clear()                        # nft -f (flush ruleset)
        st = self.round()
        self.assertEqual((self.fake.live(), self.fake.banned), ({}, {}))
        self.assertEqual(st["errors"], ["목록이 오래됨 (40분) · 넣거나 늘리지 않음"])
        # 목록이 다시 신선해지면(집행기가 돌아옴) 넣는다
        self.put_list([{"ip": a, "until": self.iso(3 * 86400)}, {"ip": c, "until": self.iso(3600)}])
        st = self.round()
        self.assertEqual((set(self.fake.live()), st["list_digest"], st["errors"]), ({a, c}, self.digest(), []))


class RecheckTest(Base):
    MODE = "nft"

    def test_금지_대역과_형식을_다시_거른다(self):
        until = self.iso(3600)
        bad = {
            "10.1.2.3": "금지 대역 10.0.0.0/8", "15.164.37.49": "금지 대역 15.164.37.49/32",
            "100.64.0.1": "금지 대역 100.64.0.0/10", "172.18.0.1": "금지 대역 172.16.0.0/12",
            "192.168.50.1": "금지 대역 192.168.0.0/16", "127.0.0.1": "금지 대역 127.0.0.0/8",
            "169.254.169.254": "금지 대역 169.254.0.0/16", "224.0.0.1": "금지 대역 224.0.0.0/4",
            "255.255.255.255": "금지 대역 240.0.0.0/4", "0.0.0.0": "금지 대역 0.0.0.0/8",
            "192.0.0.9": "금지 대역 192.0.0.0/24", "198.18.0.1": "금지 대역 198.18.0.0/15",
            "198.51.100.0/24": "대역 주소", "0.0.0.0/0": "대역 주소", "198.51.100.7/32": "대역 주소",
            "2001:db8::1": "IPv4 아님", "::1": "금지 대역 ::1/128", "fe80::1": "금지 대역 fe80::/10",
            "fd00::1": "금지 대역 fc00::/7", "01.2.3.4": "주소 형식", "1.2.3": "주소 형식",
            "not-an-ip": "주소 형식", "": "주소 형식", " 8.8.8.8": "주소 형식",
        }
        entries = [{"ip": ip, "until": until} for ip in bad]
        entries += [{"ip": 134744072, "until": until}, {"until": until}, "8.8.4.4",
                    {"ip": "8.8.8.8"}, {"ip": "9.9.9.9", "until": "2026-09-28T00:00:00"},
                    {"ip": "203.0.113.9", "until": until}]
        self.put_list(entries)
        st = self.round()
        got = [(r["ip"], r["why"]) for r in st["rejected"]]
        self.assertEqual(got, list(bad.items()) + [("", "주소 형식"), ("", "주소 형식"), ("", "주소 형식"),
                                                   ("8.8.8.8", "만료 형식"), ("9.9.9.9", "만료 형식")])
        self.assertTrue(all(isinstance(r["ip"], str) for r in st["rejected"]))
        self.assertEqual((st["applied"], set(self.fake.live())), (1, {"203.0.113.9"}))
        self.assertEqual(st["list_digest"], self.digest())      # 거른 항목이 있어도 목록 자체는 반영한 것이다

    def test_문서용_대역은_막을_수_있다(self):
        for ip in ("192.0.2.5", "198.51.100.5", "203.0.113.5", bs.SELFTEST_IP):
            self.assertEqual(bs.check_ip(ip), (ip, None))

    def test_금지_대역은_계약_목록과_같다(self):
        self.assertEqual([str(n) for n in bs.EXEMPT], [
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
            "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "15.164.37.49/32",
            "::1/128", "fc00::/7", "fe80::/10"])

    @unittest.skipUnless(os.path.exists(os.path.join(HERE, "..", "..", "migrations", "20260927_block_enforce.sql")),
                         "마이그레이션이 아직 없다")
    def test_금지_대역은_DB_초기값에_모두_있다(self):
        with open(os.path.join(HERE, "..", "..", "migrations", "20260927_block_enforce.sql"), encoding="utf-8") as f:
            text = f.read()
        found = set()
        for tok in re.findall(r"[0-9a-fA-F:.]+/\d{1,3}", text):
            try:
                found.add(ipaddress.ip_network(tok))
            except ValueError:
                pass
        self.assertEqual([str(n) for n in bs.EXEMPT if n not in found], [])

    def test_만료가_지난_항목은_rejected(self):
        self.put_list([{"ip": "203.0.113.9", "until": self.iso(-1)}, {"ip": "203.0.113.10", "until": self.iso()},
                       {"ip": "203.0.113.11", "until": self.iso(3600)}])
        st = self.round()
        self.assertEqual(self.whys(st), {"203.0.113.9": "만료 지남", "203.0.113.10": "만료 지남"})
        self.assertEqual(set(self.fake.live()), {"203.0.113.11"})

    def test_상한은_4096(self):
        until = self.iso(3600)
        base = int(ipaddress.IPv4Address("11.0.0.0"))
        self.put_list([{"ip": str(ipaddress.IPv4Address(base + i)), "until": until} for i in range(bs.MAX_ENTRIES + 1)])
        st = self.round()
        self.assertEqual((st["applied"], st["set_count"], len(self.fake.live())), (4096, 4096, 4096))
        self.assertEqual(st["rejected"], [{"ip": str(ipaddress.IPv4Address(base + 4096)), "why": "상한 초과"}])
        self.assertEqual(st["errors"], [])

    def test_중복_항목은_한_번만_넣고_알린다(self):
        self.put_list([{"ip": "203.0.113.9", "until": self.iso(3600)}, {"ip": "203.0.113.9", "until": self.iso(7200)}])
        st = self.round()
        self.assertEqual((st["applied"], st["rejected"], st["errors"]), (1, [], ["목록에 중복 항목 1개"]))

    def test_rejected_는_상한까지만_싣는다(self):
        self.put_list([{"ip": f"10.0.{i // 250}.{i % 250}", "until": self.iso(3600)} for i in range(300)])
        st = self.round()
        self.assertEqual(len(st["rejected"]), bs.MAX_REJECTED)
        self.assertIn(f"rejected 300건 중 {bs.MAX_REJECTED}건만 싣는다", st["errors"])


class Fail2banModeTest(Base):
    MODE = "fail2ban"

    def test_banip_으로_걸고_상태를_채운다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "203.0.113.9", "until": self.iso(7200)}])
        st = self.round()
        self.assertEqual(self.fake.count("fail2ban-client", "set", "opsloop-block", "banip"), 1)   # 한 번에 넘긴다
        self.assertEqual(set(self.fake.banned), {"198.51.100.7", "203.0.113.9"})
        self.assertEqual({ip: v[0] for ip, v in self.fake.live().items()},
                         {"198.51.100.7": 86400, "203.0.113.9": 86400})    # 원소 timeout 은 jail bantime
        self.assertEqual(st, {"v": 1, "at": self.clock.now.isoformat(), "mode": "fail2ban",
                              "list_digest": self.digest(), "list_generated_at": self.iso(), "applied": 2,
                              "set_count": 2, "rejected": [], "errors": [], "selftest": None})

    def test_until_이_지나거나_목록에서_빠지면_unbanip(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "203.0.113.9", "until": self.iso(7200)}])
        self.round()
        # 한 시간 뒤: 첫 항목은 만료(bantime 24시간이 남아 있어도 until 에 푼다). 집행기가 아직 목록을 안 고쳤어도 같다
        self.clock.advance(3601)
        st = self.round()
        self.assertEqual(self.whys(st), {"198.51.100.7": "만료 지남"})
        self.assertEqual((set(self.fake.banned), set(self.fake.live())), ({"203.0.113.9"}, {"203.0.113.9"}))
        # 해제로 목록에서 빠지면 푼다
        self.put_list([])
        st = self.round()
        self.assertEqual((self.fake.banned, self.fake.live(), st["applied"], st["set_count"]), ({}, {}, 0, 0))
        self.assertEqual(st["list_digest"], self.digest())

    def test_flush_ruleset_뒤_nft_로_되살린다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "203.0.113.9", "until": self.iso(3 * 86400)}])
        self.round()
        self.fake.elems.clear()                    # nft -f /etc/nftables.conf (flush ruleset)
        self.clock.advance(60)
        bans = self.fake.count("fail2ban-client", "set")
        st = self.round()
        self.assertEqual(self.fake.count("fail2ban-client", "set"), bans)   # fail2ban 은 걸었다고 알고 있다
        self.assertEqual({ip: v[0] for ip, v in self.fake.live().items()},
                         {"198.51.100.7": 3540, "203.0.113.9": 86400})     # 남은 초와 bantime 중 짧은 쪽
        self.assertEqual((st["applied"], st["rejected"], st["list_digest"]), (2, [], self.digest()))
        self.assertEqual(st["errors"], ["집합에서 빠진 원소 2개를 nft 로 되살림"])

    def test_bantime_보다_먼_차단은_만료_전에_다시_건다(self):
        entries = [{"ip": "203.0.113.9", "until": self.iso(3 * 86400)}]
        self.put_list(entries)
        self.round()
        self.clock.advance(86400 - 300)            # 원소가 5분 남았다. 집행기는 그사이 같은 목록을 다시 올렸다
        self.put_list(entries)
        st = self.round()
        self.assertEqual(self.fake.count("fail2ban-client", "set", "opsloop-block", "unbanip"), 1)
        self.assertEqual(self.fake.expires("203.0.113.9"), 86400)
        self.assertEqual((st["applied"], st["errors"]), (1, []))

    def test_같은_목록이면_아무것도_바꾸지_않는다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        first = self.round()
        self.fake.calls.clear()
        self.clock.advance(60)
        st = self.round()
        self.assertEqual(self.fake.count("fail2ban-client", "set") + self.fake.count("nft", "-f"), 0)
        self.assertEqual((st["list_digest"], st["applied"], st["errors"]), (first["list_digest"], 1, []))
        # 읽기만: 집합 두 번(처음 · 대조) · banned 한 번 · forward 체인 한 번
        self.assertEqual((self.fake.count("nft", "-j"), self.fake.count("fail2ban-client", "get"),
                          self.fake.count("nft", "list")), (2, 1, 1))

    def test_fail2ban_이_응답하지_않으면_새_차단은_rejected(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        self.round()
        self.fake.f2b_up = False
        self.fake.elems["203.0.113.50"] = (600, self.clock.t)      # 목록 밖 원소
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "203.0.113.9", "until": self.iso(3600)}])
        st = self.round()
        self.assertEqual(self.whys(st), {"203.0.113.9": "fail2ban 응답 없음"})
        self.assertTrue(any(e.startswith("fail2ban 응답 없음: ERROR   Failed to access socket") for e in st["errors"]))
        self.assertEqual(set(self.fake.live()), {"198.51.100.7"})   # 있던 것은 두고 목록 밖 원소는 뺀다
        self.assertEqual((st["applied"], st["list_digest"]), (1, self.digest()))

    def test_actionban_이_실패하면_nft_로_메우고_알린다(self):
        self.fake.action_ok = False
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        st = self.round()
        self.assertEqual((set(self.fake.live()), st["applied"]), ({"198.51.100.7"}, 1))
        self.assertEqual(st["errors"], ["집합에서 빠진 원소 1개를 nft 로 되살림"])

    def test_dry_run_은_계획만_세운다(self):
        self.fake.banned["203.0.113.50"] = self.clock.t
        self.fake.elems["203.0.113.50"] = (86400, self.clock.t)
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "10.0.0.1", "until": self.iso(3600)}])
        st = self.round(dry_run=True)
        self.assertEqual(self.plan, ["fail2ban unbanip 1 · banip 1 · 다시 걸기 0", "nft add 0 · replace 0 · del 0"])
        self.assertEqual((st["applied"], self.whys(st)), (1, {"10.0.0.1": "금지 대역 10.0.0.0/8"}))
        self.assertEqual(self.fake.count("fail2ban-client", "set") + self.fake.count("nft", "-f"), 0)
        self.assertEqual(set(self.fake.banned), {"203.0.113.50"})


class NftModeTest(Base):
    MODE = "nft"

    def test_남은_초로_넣고_fail2ban_은_부르지_않는다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "203.0.113.9", "until": self.iso(30 * 86400)}])
        st = self.round()
        self.assertEqual({ip: v[0] for ip, v in self.fake.live().items()},
                         {"198.51.100.7": 3600, "203.0.113.9": 30 * 86400})
        self.assertEqual(self.fake.count("fail2ban-client"), 0)
        self.assertEqual(self.fake.count("nft", "-f"), 1)                     # 한 묶음
        self.assertEqual((st["mode"], st["applied"], st["list_digest"], st["errors"]), ("nft", 2, self.digest(), []))

    def test_until_이_바뀌면_바꿔_넣는다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "203.0.113.9", "until": self.iso(3600)}])
        self.round()
        self.clock.advance(60)
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(7200)}, {"ip": "203.0.113.9", "until": self.iso(600)}])
        st = self.round()
        self.assertEqual({ip: self.fake.expires(ip) for ip in self.fake.live()}, {"198.51.100.7": 7200, "203.0.113.9": 600})
        self.assertEqual((st["applied"], st["errors"]), (2, []))
        self.fake.calls.clear()
        self.clock.advance(60)                    # 바뀐 것이 없으면 다시 넣지 않는다
        self.round()
        self.assertEqual(self.fake.count("nft", "-f"), 0)

    def test_목록에서_빠지거나_flush_되면_맞춘다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "203.0.113.9", "until": self.iso(3600)}])
        self.round()
        self.fake.elems.clear()
        self.clock.advance(60)
        st = self.round()
        self.assertEqual({ip: self.fake.expires(ip) for ip in self.fake.live()}, {"198.51.100.7": 3540, "203.0.113.9": 3540})
        self.assertEqual(st["errors"], [])
        self.put_list([{"ip": "203.0.113.9", "until": self.iso(3540)}])
        st = self.round()
        self.assertEqual((set(self.fake.live()), st["set_count"]), ({"203.0.113.9"}, 1))

    def test_만료_없는_원소는_두지_않는다(self):
        self.fake.elems["198.51.100.7"] = (None, self.clock.t)         # 손으로 timeout 없이 넣은 원소
        self.fake.elems["203.0.113.50"] = (None, self.clock.t)
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        self.round()
        self.assertEqual({ip: v[0] for ip, v in self.fake.live().items()}, {"198.51.100.7": 3600})

    def test_오래된_목록으로는_넣거나_늘리지_않고_줄이기만_한다(self):
        a, c = "203.0.113.9", "198.51.100.7"
        self.fake.elems[a] = (600, self.clock.t)                         # until 보다 일찍 끝나는 원소
        self.fake.elems["203.0.113.50"] = (600, self.clock.t)            # 목록 밖
        self.put_list([{"ip": a, "until": self.iso(7200)}, {"ip": c, "until": self.iso(7200)}],
                      generated_at=self.iso(-40 * 60))
        st = self.round()
        self.assertEqual({ip: self.fake.expires(ip) for ip in self.fake.live()}, {a: 600})
        self.assertEqual((st["list_digest"], st["applied"], st["errors"]),
                         (None, 1, ["목록이 오래됨 (40분) · 넣거나 늘리지 않음"]))
        # until 보다 늦게 끝나는 원소 · 만료 없는 원소는 줄인다 (늘리는 쪽이 아니다)
        self.fake.elems[a] = (86400, self.clock.t)
        self.round()
        self.assertEqual(self.fake.expires(a), 7200)
        self.fake.elems[a] = (None, self.clock.t)
        self.round()
        self.assertEqual(self.fake.expires(a), 7200)

    def test_가득_찬_집합에서도_한_묶음으로_빼고_넣는다(self):
        # 커널은 묶음 안에서 뺀 원소 수만큼만 상한을 늘려 준다. 넣기가 빼기보다 앞이면 묶음이 실패한다
        self.fake.size = 3
        until = self.iso(3600)
        self.put_list([{"ip": f"203.0.113.{i}", "until": until} for i in (1, 2, 3)])
        self.round()
        self.put_list([{"ip": f"203.0.113.{i}", "until": until} for i in (1, 2, 4)])
        self.fake.calls.clear()
        st = self.round()
        self.assertEqual(sorted(self.fake.live()), ["203.0.113.1", "203.0.113.2", "203.0.113.4"])
        self.assertEqual((st["rejected"], st["errors"], self.fake.count("nft", "-f")), ([], [], 1))

    def test_묶음이_실패하면_하나씩_넣는다(self):
        self.fake.fail_add = {"203.0.113.9"}
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "203.0.113.9", "until": self.iso(3600)},
                       {"ip": "203.0.113.10", "until": self.iso(3600)}])
        st = self.round()
        self.assertEqual(set(self.fake.live()), {"198.51.100.7", "203.0.113.10"})
        self.assertEqual((self.whys(st), st["applied"]), ({"203.0.113.9": "nft 반영 실패"}, 2))
        self.assertEqual(st["errors"], ["nft 반영 실패 1건: Error: Could not process rule: Operation not permitted"])
        self.assertEqual(st["list_digest"], self.digest())

    def test_막_만료된_원소를_빼다_실패해도_나머지는_된다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        self.fake.elems["203.0.113.50"] = (600, self.clock.t)
        self.fake.vanish_after_list = {"203.0.113.50"}                 # 읽은 뒤 빼려는 순간 만료로 빠졌다
        st = self.round()
        self.assertIn("198.51.100.7", self.fake.live())
        self.assertNotIn("203.0.113.50", self.fake.live())
        # 묶음은 없는 원소 빼기로 취소되고 하나씩 다시 넣는다. 끝 상태가 맞으므로 오류 · 거부가 아니다
        self.assertEqual((st["applied"], st["rejected"], st["errors"], st["list_digest"]), (1, [], [], self.digest()))
        self.assertEqual(self.round()["errors"], [])

    def test_빼기가_정말_실패하면_알린다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        self.fake.elems["203.0.113.50"] = (600, self.clock.t)
        self.fake.fail_del = {"203.0.113.50"}                          # 원소는 있는데 빼기가 안 된다
        st = self.round()
        self.assertEqual(st["errors"], ["nft 반영 실패 1건: Error: Could not process rule: No such file or directory",
                                        "목록 밖 원소 1개가 집합에 남음"])
        self.assertEqual((st["applied"], st["rejected"]), (1, []))

    def test_바꿔_넣을_원소가_읽은_뒤_만료돼도_넣는다(self):
        # until 이 늘어난 원소(바꿔 넣기 = 빼고 넣기)가 집합을 읽은 뒤 만료로 빠졌다. 묶음은 빼기에서 취소되지만
        # 하나씩 넣을 때 빼기 실패에 넣기까지 건너뛰면 그 주소가 한 회차 rejected 로 돌아가 집행기가 바로 불일치로 쓴다
        self.fake.elems["198.51.100.7"] = (5, self.clock.t)
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(7200)}, {"ip": "203.0.113.9", "until": self.iso(3600)}])
        self.fake.vanish_after_list = {"198.51.100.7"}
        st = self.round()
        self.assertEqual({ip: self.fake.expires(ip) for ip in self.fake.live()}, {"198.51.100.7": 7200, "203.0.113.9": 3600})
        self.assertEqual((st["applied"], st["rejected"], st["errors"]), (2, [], []))


class StateTest(Base):
    MODE = "nft"

    def test_forward_규칙이_없으면_digest_를_비운다(self):
        self.fake.rule = False
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        st = self.round()
        self.assertEqual((st["list_digest"], st["list_generated_at"]), (None, None))
        self.assertIn("forward 체인에 차단 규칙이 없다", st["errors"])
        self.assertEqual(set(self.fake.live()), {"198.51.100.7"})    # 넣기는 한다. 막는 규칙이 없을 뿐이다

    def test_집합이_없으면_아무것도_하지_않는다(self):
        self.fake.set_exists = False
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        for mode in ("nft", "fail2ban"):
            st = self.round(mode)
            self.assertEqual((st["list_digest"], st["set_count"], st["applied"]), (None, None, 0))
            self.assertEqual(st["errors"], ["nft 집합을 읽지 못함: Error: No such file or directory"])
        self.assertEqual(self.fake.count("fail2ban-client") + self.fake.count("nft", "-f"), 0)

    def test_상태는_계약_형식으로_관문_경로에_올린다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}, {"ip": "10.0.0.1", "until": self.iso(3600)}])
        rc, out = self.main()
        self.assertEqual(rc, 0, out)
        key = "hb/v1/host=i-0ffeb29efad03546d-block/latest.json"
        self.assertEqual(self.s3.puts, [(key, "application/json")])
        st = json.loads(self.s3.objects[key].decode("utf-8"))
        self.assertEqual(list(st), ["v", "at", "mode", "list_digest", "list_generated_at", "applied", "set_count",
                                    "rejected", "errors", "selftest"])
        self.assertEqual((st["v"], st["mode"], st["list_digest"], st["applied"], st["set_count"], st["selftest"]),
                         (1, "nft", self.digest(), 1, 1, None))
        self.assertEqual(st["rejected"], [{"ip": "10.0.0.1", "why": "금지 대역 10.0.0.0/8"}])
        self.assertIsNotNone(bs.parse_time(st["at"]))
        with open(os.path.join(self.tmp, "status.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f), st)

    def test_상태를_못_올리면_종료_코드_1_오류가_있으면_2(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        self.s3.fail_put = "AccessDenied"
        rc, out = self.main()
        self.assertEqual(rc, 1)
        self.assertIn("상태를 올리지 못함 (AccessDenied)", out)
        self.s3.fail_put = None
        self.fake.rule = False
        self.assertEqual(self.main()[0], 2)

    def test_dry_run_은_아무것도_바꾸거나_올리지_않는다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        rc, out = self.main("--dry-run")
        self.assertEqual(rc, 0)
        self.assertIn("nft add 1 · replace 0 · del 0", out)
        self.assertEqual((self.s3.puts, self.fake.count("nft", "-f")), ([], 0))

    def test_설정이_틀리면_멈춘다(self):
        for env in ({"MODE": "iptables", "OPSLOOP_BUCKET": "b", "OPSLOOP_HOST": HOST},
                    {"MODE": "nft", "OPSLOOP_BUCKET": "", "OPSLOOP_HOST": HOST},
                    {"MODE": "nft", "OPSLOOP_BUCKET": "b", "OPSLOOP_HOST": "i-0ffeb29efad03546d-block"},
                    {"MODE": "nft", "OPSLOOP_BUCKET": "b", "OPSLOOP_HOST": "../x"}):
            with self.assertRaises(SystemExit):
                bs.config(env)
        self.assertEqual(bs.config({"OPSLOOP_BUCKET": "b", "OPSLOOP_HOST": HOST})["mode"], "fail2ban")
        self.assertEqual(bs.config({"OPSLOOP_BUCKET": "b", "OPSLOOP_HOST": HOST})["point"], "gateway")
        # 내부 방화벽 (이슈 #51): fw-<이름> · nft 모드만 · 키가 있어야 한다
        fw = {"MODE": "nft", "OPSLOOP_BUCKET": "b", "OPSLOOP_HOST": "fw-opsloop",
              "AWS_ACCESS_KEY_ID": "AKIATEST", "AWS_SECRET_ACCESS_KEY": "s"}
        self.assertEqual((bs.config(fw)["point"], bs.config(fw)["host"]), ("fw", "fw-opsloop"))
        for bad in (dict(fw, MODE="fail2ban"), {k: v for k, v in fw.items() if k != "AWS_SECRET_ACCESS_KEY"},
                    dict(fw, AWS_ACCESS_KEY_ID=""), dict(fw, OPSLOOP_HOST="fw-"), dict(fw, OPSLOOP_HOST="fw-Opsloop"),
                    dict(fw, OPSLOOP_HOST="fw-" + "a" * 41), dict(fw, OPSLOOP_HOST="fw-op sloop")):
            with self.assertRaises(SystemExit):
                bs.config(bad)

    def test_내부_방화벽은_키로만_S3_에_닿고_메타데이터를_끈다(self):
        env = {"MODE": "nft", "OPSLOOP_BUCKET": "b", "OPSLOOP_HOST": "fw-opsloop",
               "AWS_ACCESS_KEY_ID": "AKIATEST ", "AWS_SECRET_ACCESS_KEY": " s"}
        fw = bs.config(env)
        self.assertEqual(bs.client_kwargs(fw, env), {"region_name": "ap-northeast-2", "aws_access_key_id": "AKIATEST",
                                                     "aws_secret_access_key": "s"})
        gw_env = {"OPSLOOP_BUCKET": "b", "OPSLOOP_HOST": HOST, "AWS_DEFAULT_REGION": "us-east-1"}
        gw = bs.config(gw_env)
        self.assertEqual(bs.client_kwargs(gw, gw_env), {"region_name": "us-east-1"})   # 관문은 인스턴스 역할(기본 자격 체인)
        environ = {}
        bs.isolate_credentials(fw, environ)
        self.assertEqual(environ, {"AWS_CONFIG_FILE": os.devnull, "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
                                   "AWS_EC2_METADATA_DISABLED": "true"})
        environ = {"AWS_EC2_METADATA_DISABLED": "false"}
        bs.isolate_credentials(fw, environ)
        self.assertEqual(environ["AWS_EC2_METADATA_DISABLED"], "false")               # 이미 정한 값은 두지 않고 덮지 않는다
        environ = {}
        bs.isolate_credentials(gw, environ)
        self.assertEqual(environ, {})

    def test_내부_방화벽_상태는_fw_경로에_올린다(self):
        self.put_list([{"ip": "203.0.113.10", "until": self.iso(3600)}])
        rc, out = self.main(mode="nft", host="fw-opsloop")
        self.assertEqual(rc, 0, out)
        key = "hb/v1/host=fw-opsloop-block/latest.json"
        self.assertEqual(self.s3.puts, [(key, "application/json")])
        st = json.loads(self.s3.objects[key].decode("utf-8"))
        self.assertEqual((st["mode"], st["applied"], st["list_digest"]), ("nft", 1, self.digest()))
        self.assertEqual(self.fake.count("fail2ban-client"), 0)

    def test_nft_출력의_원소는_IPv4_표준형만_받는다(self):
        got = bs.parse_elems(["198.51.100.7", {"elem": {"val": "203.0.113.9", "timeout": 60, "expires": 59}},
                              {"elem": {"val": "203.0.113.10", "counter": {"packets": 0, "bytes": 0}}},
                              "1.2.3.4; flush ruleset", {"elem": {"val": {"prefix": {}}}}, 7, None])
        self.assertEqual(got, {"198.51.100.7": {"timeout": None, "expires": None},
                               "203.0.113.9": {"timeout": 60, "expires": 59},
                               "203.0.113.10": {"timeout": None, "expires": None}})

    def test_banned_출력은_두_형식을_받는다(self):
        self.assertEqual(bs.parse_banned("['198.51.100.7', '203.0.113.9']\n"), {"198.51.100.7", "203.0.113.9"})
        self.assertEqual(bs.parse_banned("[]\n"), set())
        self.assertEqual(bs.parse_banned("198.51.100.7 203.0.113.9\n"), {"198.51.100.7", "203.0.113.9"})
        self.assertEqual(bs.parse_banned(""), set())
        for bad in ("['x; rm']", "{'a': 1}", "[1.5]", "Server replied: pong", "[198.51.100.7, 203.0.113.9]"):
            with self.assertRaises(bs.F2bOutputError):
                bs.parse_banned(bad)
        # banned 표기를 못 읽으면 banip 으로 다시 본다
        self.fake.banned = {"198.51.100.7": 0, "203.0.113.9": 0}
        self.fake.banned_form = "bare"
        self.assertEqual(bs.Fail2ban(self.fake).banned(), {"198.51.100.7", "203.0.113.9"})
        self.assertEqual(self.fake.count("fail2ban-client", "get", "opsloop-block", "banip"), 1)


class SelftestTest(Base):
    def assertNoResidue(self):
        self.assertNotIn(bs.SELFTEST_IP, self.fake.live())
        self.assertNotIn(bs.SELFTEST_IP, self.fake.banned)

    def test_nft_모드(self):
        self.assertEqual(bs.selftest("nft", bs.Nft(self.fake), bs.Fail2ban(self.fake)), "ok")
        self.assertIn("add element inet filter opsloop_block { 192.0.2.123 timeout 60s }\n",
                      [s for a, s in self.fake.calls if a[:2] == ("nft", "-f")])
        self.assertEqual(self.fake.count("fail2ban-client"), 0)
        self.assertNoResidue()

    def test_fail2ban_모드(self):
        self.assertEqual(bs.selftest("fail2ban", bs.Nft(self.fake), bs.Fail2ban(self.fake)), "ok")
        self.assertEqual(self.fake.count("fail2ban-client", "set", "opsloop-block", "banip"), 1)
        self.assertNoResidue()

    def test_fail2ban_경로가_안_되면_fail(self):
        cases = [("action_ok", False, "fail:fail2ban banip 뒤 집합에 없다"),
                 ("bantime", 600, "fail:fail2ban 원소 timeout 600 (기대 86400)"),
                 ("f2b_up", False, "fail:ERROR   Failed to access socket path: /var/run/fail2ban/fail2ban.sock. "
                                   "Is fail2ban running?")]
        for attr, value, want in cases:
            self.fake = Fake(self.clock)
            setattr(self.fake, attr, value)
            self.assertEqual(bs.selftest("fail2ban", bs.Nft(self.fake), bs.Fail2ban(self.fake)), want, attr)
            self.assertNoResidue()
            # 같은 상태에서도 nft 경로는 된다: MODE=nft 로 바꾸면 된다
            self.assertEqual(bs.selftest("nft", bs.Nft(self.fake), bs.Fail2ban(self.fake)), "ok")

    def test_규칙이나_집합이_없으면_fail(self):
        self.fake.rule = False
        self.assertEqual(bs.selftest("nft", bs.Nft(self.fake), bs.Fail2ban(self.fake)), "fail:forward 체인에 차단 규칙이 없다")
        self.fake.rule, self.fake.set_exists = True, False
        self.assertEqual(bs.selftest("nft", bs.Nft(self.fake), bs.Fail2ban(self.fake)),
                         "fail:Error: No such file or directory")

    def test_지난_시험이_남긴_주소는_치우고_시작한다(self):
        self.fake.elems[bs.SELFTEST_IP] = (60, self.clock.t)
        self.assertEqual(bs.selftest("nft", bs.Nft(self.fake), bs.Fail2ban(self.fake)), "ok")
        self.assertNoResidue()

    def test_결과는_상태에_실리고_모드가_바뀌면_비운다(self):
        self.put_list([{"ip": "198.51.100.7", "until": self.iso(3600)}])
        rc, out = self.main("--selftest")
        self.assertEqual(rc, 0, out)
        self.assertIn("자가 시험 (fail2ban): ok", out)
        key = bs.status_key(HOST)
        self.assertEqual(json.loads(self.s3.objects[key])["selftest"], "ok")
        self.assertEqual(json.loads(self.s3.objects[key])["applied"], 1)
        self.main()
        self.assertEqual(json.loads(self.s3.objects[key])["selftest"], "ok")      # 이후 회차에도 싣는다
        self.main(mode="nft")
        self.assertIsNone(json.loads(self.s3.objects[key])["selftest"])


ENFORCER = os.path.join(HERE, "..", "..", "..", "enforcer", "block_enforcer.py")


@unittest.skipUnless(os.path.exists(ENFORCER), "집행기가 아직 없다")
class EnforcerCompatTest(Base):
    """데이터 노드 집행기와 주고받는 두 객체를 서로의 코드로 읽어 본다 (목록 digest · 관문 상태 형식)."""
    MODE = "fail2ban"

    def setUp(self):
        super().setUp()
        spec = importlib.util.spec_from_file_location("block_enforcer_compat", ENFORCER)
        self.en = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.en)

    def test_집행기가_만든_목록을_받아들인다(self):
        self.assertEqual((self.en.LIST_KEY, self.en.STATUS_KEY.format(gw=HOST)), (bs.LIST_KEY, bs.status_key(HOST)))
        entries = [{"ip": ip, "until": self.iso(3600 + i)} for i, ip in
                   enumerate(["203.0.113.9", "198.51.100.7", "8.8.8.8", "11.0.0.10", "11.0.0.9"])]
        doc = self.en.list_doc(entries, self.clock.now)
        self.s3.objects[bs.LIST_KEY] = json.dumps(doc, ensure_ascii=True).encode("utf-8")
        got, why = bs.load_list(self.s3, "b")
        self.assertIsNone(why)
        self.assertEqual(got["digest"], doc["digest"])
        st = self.round()
        self.assertEqual((st["applied"], st["errors"], st["list_digest"]), (5, [], doc["digest"]))

    def test_관문_상태를_집행기가_읽는다(self):
        entries = [{"ip": "203.0.113.9", "until": self.iso(3600)}, {"ip": "10.0.0.1", "until": self.iso(3600)}]
        self.s3.objects[bs.LIST_KEY] = json.dumps(self.en.list_doc(entries, self.clock.now)).encode()
        st = self.round()
        wire = json.loads(json.dumps(st, ensure_ascii=False).encode("utf-8"))
        got, why = self.en.validate_status(wire, self.clock.now)
        self.assertIsNone(why)
        self.assertEqual((got["mode"], got["digest"], got["applied"], got["set_count"]),
                         ("fail2ban", st["list_digest"], 1, 1))
        self.assertEqual(got["rejected"], {"10.0.0.1": "금지 대역 10.0.0.0/8"})
        # 집합을 못 읽은 회차(set_count null · list_digest null)와 형식이 틀린 항목도 보고 전체가 버려지지 않는다
        self.fake.set_exists = False
        self.put_list([{"ip": 1, "until": self.iso(3600)}])
        bad = self.round()
        self.assertIsNone(self.en.validate_status(json.loads(json.dumps(bad)), self.clock.now)[1])
        self.fake.set_exists = True
        bad = self.round()
        self.assertEqual(bad["rejected"], [{"ip": "", "why": "주소 형식"}])
        self.assertIsNone(self.en.validate_status(json.loads(json.dumps(bad)), self.clock.now)[1])


class ConfigFilesTest(unittest.TestCase):
    def read(self, *path):
        with open(os.path.join(HERE, *path), encoding="utf-8") as f:
            return f.read()

    def test_계약의_이름과_경로(self):
        self.assertEqual((bs.LIST_KEY, bs.status_key(HOST), bs.FAMILY, bs.TABLE, bs.SET, bs.JAIL),
                         ("block/v1/latest.json", "hb/v1/host=i-0ffeb29efad03546d-block/latest.json",
                          "inet", "filter", "opsloop_block", "opsloop-block"))
        # 내부 방화벽 (이슈 #51). s3.tf 의 fw_sync_host · fw_sync_status_key 와 같아야 한다
        self.assertEqual(bs.status_key("fw-opsloop"), "hb/v1/host=fw-opsloop-block/latest.json")
        tf = self.read("..", "..", "terraform", "s3.tf")
        self.assertIn('fw_sync_host       = "fw-opsloop"', tf)
        self.assertIn('fw_sync_status_key = "hb/v1/host=${local.fw_sync_host}-block/latest.json"', tf)
        for sid in ("OnlyFwSyncWritesFwHb", "aws_iam_user.fw_sync.arn]", "local.fw_sync_status_key}\",\n      ])"):
            self.assertIn(sid, tf, sid)

    def test_내부_방화벽_nftables_도_같은_집합과_규칙_꼴이다(self):
        text = self.read("..", "..", "vmware", "fw", "nftables.conf")
        body = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        i = body.index("set opsloop_block {")
        self.assertEqual(body[i:i + 5], ["set opsloop_block {", "type ipv4_addr", "flags timeout",
                                         f"size {bs.MAX_ENTRIES}", "}"])
        start = body.index("chain forward {")
        fwd = body[start:body.index("}", start)]
        j = fwd.index("ip saddr @opsloop_block drop")
        self.assertTrue(bs.DROP_RULE_RE.search(fwd[j]))
        self.assertEqual(fwd[j - 1], 'ip saddr @opsloop_block limit rate 10/second log prefix "fw-block-drop "')

    def test_nftables_집합과_forward_규칙(self):
        text = self.read("nftables.conf")
        body = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        i = body.index("set opsloop_block {")
        self.assertEqual(body[i:i + 5], ["set opsloop_block {", "type ipv4_addr", "flags timeout",
                                         f"size {bs.MAX_ENTRIES}", "}"])
        chains = {}
        for name in ("input", "forward", "output"):
            start = body.index(f"chain {name} {{")
            chains[name] = body[start:body.index("}", start)]
        fwd = chains["forward"]
        j = fwd.index("ip daddr $HONEYPOT ct status dnat tcp dport $FORWARDED accept")
        self.assertEqual(fwd[j - 2:j], ['ip saddr @opsloop_block limit rate 10/second log prefix "gw-block-drop "',
                                        "ip saddr @opsloop_block drop"])
        self.assertTrue(bs.DROP_RULE_RE.search(fwd[j - 1]))
        self.assertLess(fwd.index("ct state established,related accept"), j - 2)
        self.assertFalse(any("opsloop_block" in ln for ln in chains["input"] + chains["output"]))   # 관리 경로는 그대로

    @unittest.skipUnless(shutil.which("nft") and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "nft 가 없거나 root 가 아니다")
    def test_nftables_문법(self):
        p = subprocess.run(["nft", "-c", "-f", os.path.join(HERE, "nftables.conf")], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def cfg(self, *path):
        c = configparser.RawConfigParser(strict=False)      # systemd 단위는 EnvironmentFile 을 두 번 쓴다
        c.read_string(self.read(*path))
        return c

    def test_jail(self):
        c = self.cfg("fail2ban", "jail.d", "opsloop-block.conf")
        self.assertEqual(c.get("sshd", "enabled"), "false")
        j = dict(c.items("opsloop-block"))
        self.assertEqual(j, {"enabled": "true", "filter": "", "backend": "polling",
                             "logpath": "/var/lib/opsloop-block-sync/fail2ban-empty.log",
                             "action": "opsloop-nft", "bantime": str(bs.BANTIME)})
        self.assertTrue(j["logpath"].startswith(bs.DEFAULT_STATE + "/"))
        # 읽는 순서상 패키지의 defaults-debian.conf(sshd 를 켠다)보다 뒤여야 덮는다
        self.assertGreater("opsloop-block.conf", "defaults-debian.conf")

    def test_action_은_집합에만_넣고_뺀다(self):
        c = self.cfg("fail2ban", "action.d", "opsloop-nft.conf")
        d = dict(c.items("Definition"))
        self.assertEqual((d["actionstart"], d["actionstop"], d["actioncheck"]), ("", "", ""))
        self.assertEqual(d["actionflush"], "nft flush set inet filter opsloop_block")

        def fill(cmd):
            # fail2ban 이 태그를 채운 뒤 셸이 \{ \} 를 { } 로 바꾼 모습
            return cmd.replace("<ip>", bs.SELFTEST_IP).replace("<bantime>", str(bs.BANTIME)).replace("\\{", "{").replace("\\}", "}")
        ban, unban = fill(d["actionban"]), fill(d["actionunban"])
        self.assertTrue(ban.startswith("nft ") and unban.startswith("nft "))
        # 동기화가 nft -f 로 넣는 줄과 같은 문법이어야 한다
        self.assertEqual(ban[4:], bs.nft_lines(("add", bs.SELFTEST_IP, bs.BANTIME))[0])
        self.assertEqual(unban[4:], bs.nft_lines(("del", bs.SELFTEST_IP))[0])

    def test_fail2ban_자체_DB_끔(self):
        self.assertEqual(self.cfg("fail2ban", "fail2ban.d", "opsloop.conf").get("Definition", "dbfile"), "None")

    def test_systemd_단위(self):
        svc = self.cfg("opsloop-block-sync.service")
        s = dict(svc.items("Service"))
        self.assertEqual(s["execstart"], "/usr/bin/python3 /usr/local/lib/opsloop/block-sync.py")
        raw = self.read("opsloop-block-sync.service").splitlines()
        # 관문 설정 + 내부 방화벽 키 파일(없으면 건너뛴다 · 이슈 #51)
        self.assertEqual([ln for ln in raw if ln.startswith("EnvironmentFile=")],
                         ["EnvironmentFile=/etc/default/opsloop-block-sync", "EnvironmentFile=-/etc/opsloop/block-sync.env"])
        self.assertEqual("/var/lib/" + s["statedirectory"], bs.DEFAULT_STATE)
        self.assertEqual(s["capabilityboundingset"], "CAP_NET_ADMIN")
        self.assertIn("AF_NETLINK", s["restrictaddressfamilies"].split())
        self.assertEqual(s["type"], "oneshot")
        t = dict(self.cfg("opsloop-block-sync.timer").items("Timer"))
        self.assertEqual(t["onunitactivesec"], "1min")


if __name__ == "__main__":
    unittest.main(verbosity=2)
