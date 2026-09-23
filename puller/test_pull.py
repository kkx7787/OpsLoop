#!/usr/bin/env python3
"""풀러 단위 시험. 가짜 S3 로 돌린다.  python3 puller/test_pull.py"""
import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pull  # noqa: E402

HOST = "i-058726c1a0671fe1d"
GW = "i-0a1b2c3d4e5f60718"          # 관문 방화벽 (OPSLOOP_GATEWAY_HOSTS)
T0 = datetime(2026, 9, 21, 6, 0, tzinfo=timezone.utc)


class Err(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self):
        self.objs = {}      # key → dict(body, lm, etag, sha, sc)
        self.gets = []
        self.fail = {}      # key → 받을 때 낼 오류 코드
        self.read_fail = {}  # key → 본문을 읽다가 한 번 낼 예외
        self.prefixes = []

    def put(self, key, body, lm, sha=None, etag=None, sc="STANDARD"):
        self.objs[key] = {
            "body": body, "lm": lm, "sc": sc,
            "etag": etag or '"' + hashlib.md5(body).hexdigest() + '"',
            "sha": base64.b64encode(hashlib.sha256(body).digest()).decode() if sha is None else sha,
        }

    def chunk(self, sensor, ino, gen, start, body, lm, host=HOST):
        key = (f"raw/v1/sensor={sensor}/host={host}/ino={ino}.g{gen}/"
               f"{start:012d}-{start + len(body):012d}.jsonl")
        self.put(key, body, lm)
        return key

    def hb(self, files, lm, host=HOST):
        self.put(f"hb/v1/host={host}/latest.json",
                 json.dumps({"ts": lm.isoformat(), "host": host, "files": files}).encode(), lm)

    def get_object(self, Bucket, Key, **kw):
        if Key not in self.objs:
            raise Err("NoSuchKey")
        o = self.objs[Key]
        self.gets.append(Key)
        if Key in self.fail:
            raise Err(self.fail[Key])
        body = io.BytesIO(o["body"])
        if Key in self.read_fail:
            exc = self.read_fail.pop(Key)

            class Broken:
                def read(self, n=-1):
                    raise exc
            body = Broken()
        r = {"Body": body, "LastModified": o["lm"], "ETag": o["etag"]}
        if o["sha"]:
            r["ChecksumSHA256"] = o["sha"]
        return r

    def get_paginator(self, name):
        s3 = self

        class P:
            def paginate(self, Bucket, Prefix):
                s3.prefixes.append(Prefix)
                keys = sorted(k for k in s3.objs if k.startswith(Prefix))
                for i in range(0, len(keys), 2):          # 쪽 나눔도 지나가게 작게 자른다
                    yield {"Contents": [{"Key": k, "Size": len(s3.objs[k]["body"]),
                                         "ETag": s3.objs[k]["etag"], "StorageClass": s3.objs[k]["sc"],
                                         "LastModified": s3.objs[k]["lm"]} for k in keys[i:i + 2]]}
        return P()


def hbfile(sensor, ino, gen, offset):
    return {"sensor": sensor, "ino": str(ino), "gen": gen, "size": offset, "offset": offset}


L1 = b'{"eventid":"cowrie.session.connect","timestamp":"2026-09-21T05:00:00Z"}\n'
L2 = b'{"eventid":"cowrie.login.failed","timestamp":"2026-09-21T05:00:01Z"}\n'
L3 = b'{"eventid":"cowrie.session.closed","timestamp":"2026-09-21T05:00:02Z"}\n'
G1 = b'2026-09-22T01:02:03.123456+00:00 ip-10-0-1-10 kernel: gw-forward-drop IN=ens5 SRC=203.0.113.7 DPT=445\n'


class PullTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.s3 = FakeS3()
        pull._JOURNAL = False

    def run_pull(self, now=None):
        return pull.run(self.s3, "b", {HOST}, self.dir, now=now or T0 + timedelta(minutes=1))

    def inbox(self, sensor="cowrie"):
        d = os.path.join(self.dir, "inbox", sensor)
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    def test_받고_원문_그대로(self):
        k = self.s3.chunk("cowrie", 11, 0, 0, L1 + L2, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1 + L2))}, T0)
        self.assertEqual(self.run_pull(), 0)
        with open(os.path.join(self.dir, k), "rb") as f:
            self.assertEqual(f.read(), L1 + L2)
        self.assertEqual(len(self.inbox()), 1)

    def test_두번_돌려도_다시_받지_않음(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        self.run_pull()
        n = len(self.s3.gets)
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(len(self.s3.gets) - n, 1)    # hb 만 다시 읽는다

    def test_hb_이후_조각은_대기(self):
        # 업로더 회차 도중: 회전된 파일 꼬리는 아직 없고 새 파일 조각만 올라와 있다
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        self.s3.chunk("cowrie", 12, 0, 0, L3, T0 + timedelta(minutes=5))
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(len(self.inbox()), 1)
        # 회차가 끝나 hb 가 갱신되면 받는다
        self.s3.chunk("cowrie", 11, 0, len(L1), L2, T0 + timedelta(minutes=5))
        self.s3.hb({"cowrie.json.2026-09-21": hbfile("cowrie", 11, 0, len(L1 + L2)),
                    "cowrie.json": hbfile("cowrie", 12, 0, len(L3))}, T0 + timedelta(minutes=5, seconds=2))
        self.assertEqual(self.run_pull(T0 + timedelta(minutes=6)), 0)
        self.assertEqual(len(self.inbox()), 3)

    def test_hb_없으면_받지_않고_11(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.assertEqual(self.run_pull(), pull.EXIT_STALE)
        self.assertEqual(self.inbox(), [])

    def test_체크섬_불일치_거부(self):
        k = self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.objs[k]["sha"] = base64.b64encode(b"x" * 32).decode()
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        self.assertEqual(self.run_pull(), pull.EXIT_GAP)     # 받지 못했으니 구멍
        self.assertFalse(os.path.exists(os.path.join(self.dir, k)))
        self.assertEqual(self.inbox(), [])
        self.assertEqual([f for f in os.listdir(os.path.dirname(os.path.join(self.dir, k)))], [])

    def test_체크섬_없는_객체_거부(self):
        k = self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.objs[k]["sha"] = ""
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        self.assertEqual(self.run_pull(), pull.EXIT_GAP)
        self.assertEqual(self.inbox(), [])

    def test_줄바꿈으로_끝나지_않으면_거부(self):
        body = L1[:-1] + b"x"
        k = self.s3.chunk("cowrie", 11, 0, 0, body, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(body))}, T0)
        self.assertEqual(self.run_pull(), pull.EXIT_GAP)
        self.assertFalse(os.path.exists(os.path.join(self.dir, k)))

    def test_크기와_구간_불일치_거부(self):
        key = f"raw/v1/sensor=cowrie/host={HOST}/ino=11.g0/000000000000-000000000005.jsonl"
        self.s3.put(key, L1, T0)
        self.s3.hb({}, T0)
        self.run_pull()
        self.assertEqual(self.inbox(), [])

    def test_키_규칙과_허용목록(self):
        self.s3.put("raw/v1/sensor=cowrie/host=i-0000000000000000a/ino=1.g0/"
                    f"000000000000-{len(L1):012d}.jsonl", L1, T0)
        self.s3.put("raw/v1/sensor=cowrie/host=../../etc/ino=1.g0/x.jsonl", L1, T0)
        self.s3.put("raw/v1/sensor=evil/host=" + HOST + "/ino=1.g0/"
                    f"000000000000-{len(L1):012d}.jsonl", L1, T0)
        self.s3.hb({}, T0)
        self.s3.hb({}, T0, host="i-0000000000000000a")
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.inbox(), [])
        self.assertFalse(os.path.exists(os.path.join(self.dir, "etc")))

    def test_구멍이면_10(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.chunk("cowrie", 11, 0, len(L1 + L2), L3, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1 + L2 + L3))}, T0)
        self.assertEqual(self.run_pull(), pull.EXIT_GAP)

    def test_hb_위치까지_못받으면_10(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1 + L2))}, T0)
        self.assertEqual(self.run_pull(), pull.EXIT_GAP)

    def test_겹치는_조각은_구멍_아님(self):
        # 업로더가 올린 뒤 상태 저장 전에 죽으면 같은 시작점에서 더 긴 조각이 다시 올라온다
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.chunk("cowrie", 11, 0, 0, L1 + L2, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1 + L2))}, T0)
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(len(self.inbox()), 2)

    def test_새_세대는_따로_이어짐(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1 + L2, T0)
        self.s3.chunk("cowrie", 11, 1, 0, L3, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 1, len(L3))}, T0)
        self.assertEqual(self.run_pull(), 0)

    def test_변조_경보는_한번만_로컬은_유지(self):
        k = self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        self.run_pull()
        self.s3.objs[k]["etag"] = '"deadbeef"'
        self.s3.objs[k]["body"] = L2[: len(L1)]
        out = io.StringIO()
        old, sys.stdout = sys.stdout, out
        try:
            self.run_pull()
            self.run_pull()
        finally:
            sys.stdout = old
        self.assertEqual(out.getvalue().count("원장 변조 의심"), 1)
        with open(os.path.join(self.dir, k), "rb") as f:
            self.assertEqual(f.read(), L1)

    def test_생존신호_오래되면_받되_11(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        out = io.StringIO()
        old, sys.stdout = sys.stdout, out
        try:
            rc = self.run_pull(T0 + timedelta(hours=1))
        finally:
            sys.stdout = old
        self.assertEqual(rc, pull.EXIT_STALE)
        self.assertEqual(len(self.inbox()), 1)
        self.assertIn("생존 신호가 60분 전", out.getvalue())

    def test_상태_저장_전_사망해도_다시_받으면_그만(self):
        k = self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        self.run_pull()
        os.unlink(os.path.join(self.dir, "pull-state.json"))
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(len(self.inbox()), 1)
        with open(os.path.join(self.dir, k), "rb") as f:
            self.assertEqual(f.read(), L1)

    def run_gw(self):
        return pull.run(self.s3, "b", {HOST, GW}, self.dir, now=T0 + timedelta(minutes=1), gateway_hosts={GW})

    def test_관문_기록_조각은_gateway_편지함으로(self):
        k = self.s3.chunk("gateway", 31, 0, 0, G1, T0, host=GW)
        self.s3.hb({"gateway.log": hbfile("gateway", 31, 0, len(G1))}, T0, host=GW)   # hb 의 sensor 도 gateway 를 받는다
        self.s3.hb({}, T0)
        self.assertEqual(self.run_gw(), 0)
        [name] = self.inbox("gateway")
        with open(os.path.join(self.dir, "inbox", "gateway", name), "rb") as f:
            self.assertEqual(f.read(), G1)                                    # JSON 이 아니어도 줄 그대로
        self.assertTrue(os.path.exists(os.path.join(self.dir, k)))
        self.assertEqual((self.inbox("cowrie"), self.inbox("decoy")), ([], []))
        self.assertIn(f"raw/v1/sensor=gateway/host={GW}/", self.s3.prefixes)

    def test_허니팟이_올린_관문_기록은_받지_않고_구멍도_아니다(self):
        # 역할 · 버킷 정책이 먼저 막지만 풀러도 확인한다. 장악된 허니팟이 gateway 조각과 hb 항목을 흉내 낸다
        self.s3.chunk("gateway", 41, 0, 0, G1, T0)
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1)),
                    "gateway.log": hbfile("gateway", 41, 0, len(G1) + 100)}, T0)   # 받지 않을 항목. 두면 구멍이 된다
        self.s3.hb({}, T0, host=GW)
        rc, out = self.quiet(self.run_gw)
        self.assertEqual(rc, 0)
        self.assertEqual(self.inbox("gateway"), [])
        self.assertEqual(len(self.inbox("cowrie")), 1)
        self.assertIn("발생원 · 호스트 불일치", json.dumps(self.state()["ignored"], ensure_ascii=False))
        self.assertIn("올릴 수 없는 발생원 항목 1개", out)

    def test_관문이_올린_허니팟_기록도_받지_않는다(self):
        self.s3.chunk("cowrie", 51, 0, 0, L1, T0, host=GW)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 51, 0, len(L1))}, T0, host=GW)
        self.s3.hb({}, T0)
        rc, _ = self.quiet(self.run_gw)
        self.assertEqual(rc, 0)
        self.assertEqual(self.inbox("cowrie"), [])

    def test_관문_목록이_없으면_gateway_조각을_받지_않는다(self):
        # 설정을 빠뜨리면 조용히 섞이는 대신 받지 않는다 (README 2단계)
        self.s3.chunk("gateway", 61, 0, 0, G1, T0)
        self.s3.hb({}, T0)
        rc, _ = self.quiet(self.run_pull)
        self.assertEqual(rc, 0)
        self.assertEqual(self.inbox("gateway"), [])

    def test_다른_발생원_이름은_받지_않는다(self):
        ok = f"raw/v1/sensor=gateway/host={HOST}/ino=1.g0/000000000000-000000000010.jsonl"
        self.assertIsNotNone(pull.KEY_RE.fullmatch(ok))
        for s in ("fw", "gate", "gateway2", "gateways", "Gateway", "gateway/x", "nginx"):
            self.assertIsNone(pull.KEY_RE.fullmatch(ok.replace("sensor=gateway", f"sensor={s}")), s)
            self.assertIsNone(pull.valid_hb({"files": {"a": {"sensor": s, "ino": 1, "gen": 0, "offset": 1}}}), s)
        self.assertEqual(pull.SENSORS, ("cowrie", "decoy", "gateway"))
        # 목록 조회도 허용 발생원의 접두사만 본다
        self.s3.put(f"raw/v1/sensor=fw/host={HOST}/ino=1.g0/000000000000-{len(G1):012d}.jsonl", G1, T0)
        self.s3.hb({}, T0)
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.inbox("fw"), [])
        self.assertFalse(any("sensor=fw" in p for p in self.s3.prefixes))
        # 거부가 넘친 세대 목록(bad_groups)도 gateway 세대를 알아본다
        gaps = pull.coverage({}, {}, bad_groups=[f"gateway/{HOST}/ino=5.g0", f"fw/{HOST}/ino=5.g0"])
        self.assertEqual(gaps, [(("gateway", HOST, "5", 0), -1, -1)])

    def test_편지함은_미러와_같은_파일(self):
        k = self.s3.chunk("decoy", 21, 0, 0, L1, T0)
        self.s3.hb({"decoy.json.2026-09-21": hbfile("decoy", 21, 0, len(L1))}, T0)
        self.run_pull()
        [name] = self.inbox("decoy")
        a = os.stat(os.path.join(self.dir, k))
        b = os.stat(os.path.join(self.dir, "inbox", "decoy", name))
        self.assertEqual((a.st_ino, a.st_dev), (b.st_ino, b.st_dev))


    def state(self):
        with open(os.path.join(self.dir, "pull-state.json"), encoding="utf-8") as f:
            return json.load(f)

    def quiet(self, fn):
        out = io.StringIO()
        old, sys.stdout = sys.stdout, out
        try:
            rc = fn()
        finally:
            sys.stdout = old
        return rc, out.getvalue()

    def test_끝_줄바꿈_키로_바꿔치기_못함(self):
        k = self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.put(k + "\n", L2[: len(L1)], T0)          # 같은 크기의 조작본
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        rc, out = self.quiet(self.run_pull)
        self.assertEqual(rc, 0)
        [name] = self.inbox()
        with open(os.path.join(self.dir, "inbox", "cowrie", name), "rb") as f:
            self.assertEqual(f.read(), L1)
        self.assertIn("\\x0a", out)                        # 로그에는 줄바꿈이 이스케이프되어 한 줄로 남는다

    def test_저장_등급이_다르면_받지_않고_계속(self):
        bad = f"raw/v1/sensor=cowrie/host={HOST}/ino=1.g0/000000000000-{len(L1):012d}.jsonl"
        self.s3.put(bad, L1, T0, sc="GLACIER")
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        rc, _ = self.quiet(self.run_pull)
        self.assertEqual(rc, pull.EXIT_GAP)                  # 받지 못한 세대는 구멍으로 드러난다
        self.assertEqual(len(self.inbox()), 1)               # 뒤의 정상 조각은 받는다
        self.assertNotIn(bad, self.s3.gets)

    def test_받기_오류는_격리하고_같은_ETag_는_다시_받지_않음(self):
        bad = self.s3.chunk("cowrie", 1, 0, 0, L1, T0)
        self.s3.fail[bad] = "InvalidObjectState"
        self.s3.chunk("cowrie", 11, 0, 0, L2, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L2))}, T0)
        rc, _ = self.quiet(self.run_pull)
        self.assertEqual(rc, pull.EXIT_GAP)
        self.assertEqual(len(self.inbox()), 1)
        n = self.s3.gets.count(bad)
        self.quiet(self.run_pull)
        self.assertEqual(self.s3.gets.count(bad), n)          # 같은 ETag 면 다시 받지 않는다
        self.s3.objs[bad]["etag"] = '"new"'
        del self.s3.fail[bad]
        self.quiet(self.run_pull)
        self.assertEqual(len(self.inbox()), 2)                # ETag 가 바뀌면 다시 시도한다

    def test_구멍_인정_목록(self):
        self.s3.chunk("cowrie", 7, 0, 100, L1, T0)            # 0 부터 시작하지 않는 가짜 세대
        self.s3.hb({}, T0)
        rc, _ = self.quiet(self.run_pull)
        self.assertEqual(rc, pull.EXIT_GAP)
        rc, _ = self.quiet(lambda: pull.run(self.s3, "b", {HOST}, self.dir, now=T0 + timedelta(minutes=1),
                                            ack={f"cowrie/{HOST}/ino=7.g0"}))
        self.assertEqual(rc, 0)

    def test_가짜_생존신호로_죽지_않음(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        for body in (b'{"files": []}', b'{"files": {"a": null}}', b'{"files": {"a": {"sensor": "cowrie", "ino": 1, "gen": "x", "offset": 1}}}',
                     b'{"files": {"a": {"sensor": "cowrie", "ino": 1, "gen": 0, "offset": 1000000000000000}}}',
                     b"{not json", b"[" * 100000, b"x" * (pull.HB_MAX + 10)):
            self.s3.put(f"hb/v1/host={HOST}/latest.json", body, T0)
            rc, out = self.quiet(self.run_pull)
            self.assertEqual(rc, pull.EXIT_STALE, body[:40])
            self.assertIn("생존 신호", out)
        self.assertEqual(self.inbox(), [])

    def test_회차_한도를_넘으면_다음_회차로(self):
        old = pull.RUN_BYTES
        pull.RUN_BYTES = len(L1) + 1
        try:
            self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
            self.s3.chunk("cowrie", 11, 0, len(L1), L2, T0)
            self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1 + L2))}, T0)
            rc, out = self.quiet(self.run_pull)
            self.assertEqual(rc, pull.EXIT_GAP)               # 아직 hb 위치까지 못 받았다
            self.assertIn("한도로 미룸 있음", out)
            self.assertIn("구멍(일시)", out)
            rc, _ = self.quiet(self.run_pull)
            self.assertEqual(rc, 0)
            self.assertEqual(len(self.inbox()), 2)
        finally:
            pull.RUN_BYTES = old

    def test_너무_큰_조각은_받지_않음(self):
        old = pull.MAX_OBJ
        pull.MAX_OBJ = len(L1) - 1
        try:
            k = self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
            self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
            rc, _ = self.quiet(self.run_pull)
            self.assertEqual(rc, pull.EXIT_GAP)
            self.assertNotIn(k, self.s3.gets)
        finally:
            pull.MAX_OBJ = old

    def test_상태_목록은_상한을_넘지_않음(self):
        old = pull.CAP
        pull.CAP = 3
        try:
            for i in range(10):
                self.s3.put(f"raw/v1/sensor=cowrie/host={HOST}/junk{i}", b"x", T0)
            self.s3.hb({}, T0)
            self.quiet(self.run_pull)
            with open(os.path.join(self.dir, "pull-state.json"), encoding="utf-8") as f:
                st = json.load(f)
            self.assertEqual(len(st["ignored"]), 3)
            self.assertEqual(st["overflow"], 7)
        finally:
            pull.CAP = old

    def test_허용_호스트_접두사만_조회(self):
        self.s3.hb({}, T0)
        self.quiet(self.run_pull)
        self.assertTrue(all(p.startswith(f"raw/v1/sensor=") and f"/host={HOST}/" in p for p in self.s3.prefixes))

    def test_남은_임시_파일_정리(self):
        d = os.path.join(self.dir, "raw", "v1", "x")
        os.makedirs(d)
        for n in (".part.abc", ".pull-state.xyz"):
            open(os.path.join(d if n.startswith(".part") else self.dir, n), "w").close()
        self.s3.hb({}, T0)
        self.quiet(self.run_pull)
        self.assertEqual(os.listdir(d), [])
        self.assertFalse(any(n.startswith(".pull-state.") for n in os.listdir(self.dir)))

    def test_디스크_여유가_없으면_13(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        old = pull.disk_ok
        pull.disk_ok = lambda home: (False, 0)
        try:
            rc, out = self.quiet(self.run_pull)
        finally:
            pull.disk_ok = old
        self.assertEqual(rc, pull.EXIT_DISK)
        self.assertEqual(self.inbox(), [])
        self.assertIn("디스크 여유", out)
        self.assertNotIn("인정 목록", out)                  # 멀쩡한 세대를 인정하라고 안내하지 않는다


    def test_일시_오류는_다음_회차에_다시_받는다(self):
        class ReadTimeoutError(Exception):
            pass
        k1 = self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        k2 = self.s3.chunk("cowrie", 11, 0, len(L1), L2, T0)
        k3 = self.s3.chunk("cowrie", 11, 0, len(L1 + L2), L3, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1 + L2 + L3))}, T0)
        for fail in ("get", "read"):
            with self.subTest(fail=fail):
                self.setUp()
                self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
                self.s3.chunk("cowrie", 11, 0, len(L1), L2, T0)
                self.s3.chunk("cowrie", 11, 0, len(L1 + L2), L3, T0)
                self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1 + L2 + L3))}, T0)
                if fail == "get":
                    self.s3.fail[k2] = "SlowDown"
                else:
                    self.s3.read_fail[k2] = ReadTimeoutError("끊김")
                rc, out = self.quiet(self.run_pull)
                self.assertEqual(rc, 1)                       # 일시 오류: 실패로 드러내고 탐지는 보류
                self.assertNotIn("인정 목록", out)
                self.s3.fail.pop(k2, None)
                rc, _ = self.quiet(self.run_pull)
                self.assertEqual(rc, 0)                       # 다음 회차에 받아 회복
                self.assertEqual(len(self.inbox()), 3)

    def test_무한대_생존신호로_죽지_않음(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        for bad in ('"ino": Infinity', '"offset": 1e999', '"gen": -Infinity', '"offset": 1.5', '"ino": true'):
            body = ('{"files": {"a": {"sensor": "cowrie", "ino": 11, "gen": 0, "offset": 72, ' + bad + '}}}').encode()
            self.s3.put(f"hb/v1/host={HOST}/latest.json", body, T0)
            rc, _ = self.quiet(self.run_pull)
            self.assertEqual(rc, pull.EXIT_STALE, bad)

    def test_유니코드_숫자_키로_바꿔치기_못함(self):
        k = self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        fake = k.replace("/000000000000-", "/" + "\u0660" * 12 + "-")
        self.s3.put(fake, L2[: len(L1)], T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        rc, out = self.quiet(self.run_pull)
        self.assertEqual(rc, 0)
        [name] = self.inbox()
        with open(os.path.join(self.dir, "inbox", "cowrie", name), "rb") as f:
            self.assertEqual(f.read(), L1)
        self.assertIn("키 규칙 위반", out)
        self.assertNotIn(fake, self.s3.gets)

    def test_거부가_넘치면_세대를_멈추고_다시_받지_않는다(self):
        old = pull.CAP
        pull.CAP = 2
        try:
            keys = []
            for i in range(6):
                body = b"x" * 9 + b"y"                        # 줄바꿈으로 끝나지 않는 10 B
                keys.append(self.s3.chunk("cowrie", 5, 0, i * 10, body, T0))
            self.s3.hb({}, T0)
            rc, out = self.quiet(self.run_pull)
            self.assertEqual(rc, pull.EXIT_GAP)
            self.assertIn("세대 전체를 멈춘다", out)
            n = len(self.s3.gets)
            rc, _ = self.quiet(self.run_pull)
            self.assertEqual(rc, pull.EXIT_GAP)
            self.assertEqual(len(self.s3.gets) - n, 1)       # hb 만 다시 읽는다
            rc, _ = self.quiet(lambda: pull.run(self.s3, "b", {HOST}, self.dir, now=T0 + timedelta(minutes=1),
                                                ack={f"cowrie/{HOST}/ino=5.g0"}))
            self.assertEqual(rc, 0)
        finally:
            pull.CAP = old

    def test_실패한_받기도_회차_한도에_든다(self):
        old = pull.RUN_BYTES
        pull.RUN_BYTES = 15
        try:
            for i in range(4):
                self.s3.chunk("cowrie", 5, 0, i * 10, b"x" * 9 + b"y", T0)
            self.s3.hb({}, T0)
            n = len(self.s3.gets)
            self.quiet(self.run_pull)
            self.assertEqual(len(self.s3.gets) - n, 1 + 1)   # hb + 조각 1개 뒤 한도
        finally:
            pull.RUN_BYTES = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
