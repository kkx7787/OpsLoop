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
T0 = datetime(2026, 9, 21, 6, 0, tzinfo=timezone.utc)


class Err(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self):
        self.objs = {}      # key → dict(body, lm, etag, sha)
        self.gets = []

    def put(self, key, body, lm, sha=None, etag=None):
        self.objs[key] = {
            "body": body, "lm": lm,
            "etag": etag or '"' + hashlib.md5(body).hexdigest() + '"',
            "sha": base64.b64encode(hashlib.sha256(body).digest()).decode() if sha is None else sha,
        }

    def chunk(self, sensor, ino, gen, start, body, lm):
        key = (f"raw/v1/sensor={sensor}/host={HOST}/ino={ino}.g{gen}/"
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
        r = {"Body": io.BytesIO(o["body"]), "LastModified": o["lm"], "ETag": o["etag"]}
        if o["sha"]:
            r["ChecksumSHA256"] = o["sha"]
        return r

    def get_paginator(self, name):
        s3 = self

        class P:
            def paginate(self, Bucket, Prefix):
                keys = sorted(k for k in s3.objs if k.startswith(Prefix))
                for i in range(0, len(keys), 2):          # 쪽 나눔도 지나가게 작게 자른다
                    yield {"Contents": [{"Key": k, "Size": len(s3.objs[k]["body"]),
                                         "ETag": s3.objs[k]["etag"],
                                         "LastModified": s3.objs[k]["lm"]} for k in keys[i:i + 2]]}
        return P()


def hbfile(sensor, ino, gen, offset):
    return {"sensor": sensor, "ino": str(ino), "gen": gen, "size": offset, "offset": offset}


L1 = b'{"eventid":"cowrie.session.connect","timestamp":"2026-09-21T05:00:00Z"}\n'
L2 = b'{"eventid":"cowrie.login.failed","timestamp":"2026-09-21T05:00:01Z"}\n'
L3 = b'{"eventid":"cowrie.session.closed","timestamp":"2026-09-21T05:00:02Z"}\n'


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

    def test_hb_없으면_받지_않음(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.assertEqual(self.run_pull(), 0)
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

    def test_생존신호_오래되면_경고만(self):
        self.s3.chunk("cowrie", 11, 0, 0, L1, T0)
        self.s3.hb({"cowrie.json": hbfile("cowrie", 11, 0, len(L1))}, T0)
        out = io.StringIO()
        old, sys.stdout = sys.stdout, out
        try:
            rc = self.run_pull(T0 + timedelta(hours=1))
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
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

    def test_편지함은_미러와_같은_파일(self):
        k = self.s3.chunk("decoy", 21, 0, 0, L1, T0)
        self.s3.hb({"decoy.json.2026-09-21": hbfile("decoy", 21, 0, len(L1))}, T0)
        self.run_pull()
        [name] = self.inbox("decoy")
        a = os.stat(os.path.join(self.dir, k))
        b = os.stat(os.path.join(self.dir, "inbox", "decoy", name))
        self.assertEqual((a.st_ino, a.st_dev), (b.st_ino, b.st_dev))


if __name__ == "__main__":
    unittest.main(verbosity=2)
