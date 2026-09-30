#!/usr/bin/env python3
"""차단 집행기 시험 (이슈 #47 · #51 · #77). 가짜 DB · 가짜 S3 · 관문 흉내로 목록 · digest · 확인 · 불일치 · 만료 · 제외 · 멱등을 본다.

  python3 enforcer/test_block_enforcer.py
  OPSLOOP_TEST_DATABASE_URL=postgresql://… python3 enforcer/test_block_enforcer.py   # 실제 PostgreSQL 시험도

실제 PostgreSQL 시험은 시험마다 새 DB 를 만들어 infra/schema.sql 과 infra/migrations/20260927_block_enforce.sql 을
그대로 적용하고, opsloop_enforcer 역할로 붙어 한 회차를 돌린다(권한 · 트리거 · 감사 · 만료 기록). 끝나면 DB 를 지운다.
다시 걸기(RearmPgTest, 관문 없이 · 관문 포함)는 콘솔 · triage · 흡수 후속 차단의 실제 문장으로 다시 걸고 집행기를 돌린다(관문 포함은
보고서 ENFORCE_SQL 의 기존 차단 유지 분류까지 본다).
역할 opsloop_enforcer 는 클러스터 전체라 시험 전용 PostgreSQL 에서만 돌린다.
"""
import ast
import asyncio
import copy
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import block_enforcer as be  # noqa: E402

T0 = datetime(2026, 9, 27, 8, 0, 0, tzinfo=timezone.utc)
GW = "i-0ffeb29efad03546d"
STATUS = f"hb/v1/host={GW}-block/latest.json"
MIN = timedelta(minutes=1)
DAY = timedelta(days=1)
FW = "fw-opsloop"


def contract_digest(entries):
    """계약의 digest 를 따로 계산한다 (ip 문자열 순 · sort_keys · 빈칸 없는 구분자 · UTF-8 sha256)."""
    canon = json.dumps(sorted(entries, key=lambda e: e["ip"]), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


class S3Err(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self):
        self.objects, self.puts, self.fail_put = {}, [], None

    def put_object(self, Bucket, Key, Body, **kw):
        if self.fail_put:
            raise S3Err(self.fail_put)
        self.objects[Key] = Body
        self.puts.append((Bucket, Key, kw))

    def get_object(self, Bucket, Key):
        if Key not in self.objects:
            raise S3Err("NoSuchKey")
        return {"Body": io.BytesIO(self.objects[Key])}

    def listed(self):
        return json.loads(self.objects[be.LIST_KEY])


class FakeStore:
    """blocklist 흉내. 읽기 조건 · 읽은 값 대조 쓰기 · 집행 감사(enforced · unenforced) · 만료 기록(멱등)을 따른다."""

    def __init__(self, now=T0):
        self.now, self.rows = now, {}
        self.writes, self.audit, self.expired_calls = 0, [], []
        self.fail_fetch = self.fail_apply = False
        self.before_apply = None
        self.beats = []                  # heartbeat 호출마다 받은 행 목록 (차단 보고 생존 신호, 이슈 #52)
        self.fail_heartbeat = None       # 오류를 낼 때의 pgcode ('' 이면 pgcode 없는 오류)

    def add(self, ip, expires=DAY, created=None, released=None, enforced=None, method=None, note=None, exempt_net=None,
            enforcement=None, points=("gateway", "fw")):
        net = ipaddress.ip_network(ip, strict=False)
        host = net.prefixlen == net.max_prefixlen
        key = str(net.network_address) if host else str(net)
        self.rows[key] = {"key": key, "ip": str(net.network_address), "fam": net.version, "mask": net.prefixlen,
                          "created_at": created or self.now,
                          "expires_at": (self.now + expires) if isinstance(expires, timedelta) else expires,
                          "released_at": released, "enforced_at": enforced, "method": method, "note": note,
                          "enforcement": enforcement, "exempt_net": exempt_net,
                          "points": None if points is None else list(points)}   # DB 는 jsonb 배열로 읽는다 (이슈 #77)
        return self.rows[key]

    def fetch(self):
        if self.fail_fetch:
            raise RuntimeError("연결이 끊겼다")
        out = []
        for r in sorted(self.rows.values(), key=lambda r: r["key"]):
            live = r["released_at"] is None and (r["expires_at"] is None or r["expires_at"] > self.now - 2 * DAY)
            if live or r["enforced_at"] is not None or r["enforcement"] is not None:
                out.append({k: r[k] for k in be.FIELDS})
        return {"now": self.now, "rows": out}

    def apply(self, updates):
        if self.before_apply:
            self.before_apply()
        if self.fail_apply:
            raise RuntimeError("권한이 없다")
        n = 0
        for u in updates:
            r = self.rows.get(u["key"])
            if r is None:
                continue
            cur = {"released_at": r["released_at"], "expires_at": r["expires_at"], "enforced_at": r["enforced_at"],
                   "method": r["method"], "enforce_note": r["note"], "enforcement": r["enforcement"], "points": r["points"]}
            if any(cur[k] != u["guard"][k] for k in be.GUARD + tuple(be.GUARD_EXPR)):
                continue
            for c, v in u["set"].items():
                if c == "enforced_at":
                    old = r["enforced_at"]
                    if v is not None and old != v:
                        self.audit.append(("enforced", r["ip"]))
                    elif v is None and old is not None:
                        self.audit.append(("unenforced", r["ip"]))
                r["note" if c == "enforce_note" else c] = v
            self.writes += 1
            n += 1
        return n

    def note_expired(self, key, expires):
        if (key, expires) not in self.expired_calls:
            self.audit.append(("expired", key))
        self.expired_calls.append((key, expires))

    def heartbeat(self, rows):
        if self.fail_heartbeat is not None:
            e = RuntimeError("생존 신호 표를 쓰지 못했다")
            e.pgcode = self.fail_heartbeat or None
            raise e
        self.beats.append(copy.deepcopy(rows))


class Gateway:
    """관문(또는 내부 방화벽) block-sync.py 흉내. S3 목록을 읽어 digest 를 따로 확인하고 보고를 hb 경로에 쓴다.
    point 가 None 이면 #77 전 판(entries 만 적용 · 보고에 list 없음), 'gateway' · 'fw' 면 #77 판(내부 방화벽은 points.fw 를
    적용하고 list 를 싣는다. infra/aws/gateway/block-sync.py load_list 와 같다). 적용한 주소 집합을 돌려준다."""

    def __init__(self, s3, mode="nft", key=STATUS, point=None):
        self.s3, self.mode, self.key, self.point = s3, mode, key, point

    def sync(self, at, rejected=(), errors=(), digest=None, applied=None, set_count=None):
        doc = self.s3.listed()
        assert contract_digest(doc["entries"]) == doc["digest"], "관문이 digest 를 거부할 목록이다"
        lst, dg, kind = doc["entries"], doc["digest"], "legacy"
        if self.point and "points" in doc:
            kind = self.point
            if self.point == "fw":
                lst, dg = doc["points"]["fw"]["entries"], doc["points"]["fw"]["digest"]
                assert contract_digest(lst) == dg, "내부 방화벽이 거부할 갈래다"
        live = [e for e in lst if be.parse_ts(e["until"]) > at and e["ip"] not in dict(rejected)]
        n = len(live) if applied is None else applied
        status = {"v": 1, "at": be.iso(at), "mode": self.mode, "list_digest": digest or dg,
                  "list_generated_at": doc["generated_at"], "applied": n, "set_count": n if set_count is None else set_count,
                  "rejected": [{"ip": ip, "why": w} for ip, w in rejected], "errors": list(errors), "selftest": None}
        if self.point:
            status["list"] = kind
        self.put(status)
        return {e["ip"] for e in live}

    def put(self, status):
        self.s3.objects[self.key] = json.dumps(status).encode("utf-8")


FW_STATUS = be.STATUS_KEY.format(gw=FW)


class Base(unittest.TestCase):
    def setUp(self):
        self.store, self.s3 = FakeStore(), FakeS3()
        self.gw = Gateway(self.s3)
        self.st = be.new_state()
        self.cfg = {"bucket": "opsloop-archive-test", "gateway": GW, "home": "/nonexistent", "region": "ap-northeast-2"}
        self.logs = []
        p = mock.patch.object(be, "log", lambda m, level=6: self.logs.append((level, m)))
        p.start()
        self.addCleanup(p.stop)

    def run_once(self, dry_run=False):
        return be.cycle(self.cfg, self.store, self.s3, self.s3, self.st, dry_run=dry_run)

    def tick(self, d=MIN):
        self.store.now += d

    def row(self, ip):
        return self.store.rows[ip]

    def confirmed(self, ip, at, mode="nft", kept=False):
        """관문 확인 세 열. kept 는 앞 확인을 비운 적 없이 다시 확인한 것(쪽지 끝 ' · 기존 차단 유지', 이슈 #77 결정 2)이다."""
        r = self.row(ip)
        self.assertEqual(r["enforced_at"], at.replace(microsecond=0))
        self.assertEqual(r["method"], mode)
        self.assertRegex(r["note"], r"^관문 반영 · [0-9a-f]{8} · " + be.iso(at) + (be.NOTE_KEPT if kept else "") + "$")

    def settle(self, ip="198.51.100.7"):
        """행 하나를 올리고 관문이 적용한 뒤 확인까지 (T0 + 1분)."""
        self.store.add(ip)
        self.run_once()
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.assertEqual(self.run_once(), 0)
        self.confirmed(ip, T0 + timedelta(seconds=30))


class ListTest(Base):
    def test_목록은_살아있는_IPv4_한_주소만_주소_문자열_순이다(self):
        s = self.store
        s.add("203.0.113.9")
        s.add("198.51.100.20", expires=timedelta(hours=1))
        s.add("9.9.9.9", expires=timedelta(hours=2))
        s.add("203.0.113.10", released=T0 - MIN)                   # 해제
        s.add("203.0.113.11", expires=-MIN)                        # 만료
        s.add("203.0.113.12", expires=None)                        # 만료 없음
        s.add("198.51.100.0/24")                                   # 대역
        s.add("10.1.2.3")                                          # 금지 대역 (상수)
        s.add("198.51.100.99", exempt_net="198.51.100.99/32")      # 금지 대역 (표)
        s.add("15.164.37.49")                                      # 관문 EIP
        s.add("2001:db8::7")                                       # IPv6 한 주소
        self.run_once()
        doc = self.s3.listed()
        self.assertEqual(list(doc), ["v", "generated_at", "entries", "digest", "points"])     # points 는 늘 싣는다 (이슈 #77)
        self.assertEqual(doc["points"], {"fw": {"entries": doc["entries"], "digest": doc["digest"]}})   # 모두 두 지점
        self.assertEqual(doc["v"], 1)
        self.assertEqual(doc["generated_at"], "2026-09-27T08:00:00Z")
        self.assertEqual([e["ip"] for e in doc["entries"]], ["198.51.100.20", "203.0.113.9", "9.9.9.9"])
        self.assertEqual(doc["entries"][0], {"ip": "198.51.100.20", "until": "2026-09-27T09:00:00Z"})
        self.assertEqual(doc["digest"], contract_digest(doc["entries"]))
        _, key, kw = self.s3.puts[0]
        self.assertEqual((key, kw["ContentType"]), ("block/v1/latest.json", "application/json"))
        self.assertNotIn("ServerSideEncryption", kw)      # 버킷 기본 암호화 · 기본 저장 등급만 (버킷 정책)
        self.assertNotIn("StorageClass", kw)

    def test_digest_는_항목_순서와_무관하고_until_이_바뀌면_바뀐다(self):
        a = [{"ip": "9.9.9.9", "until": "2026-09-28T08:00:00Z"}, {"ip": "10.0.0.1", "until": "2026-09-28T08:00:00Z"}]
        self.assertEqual(be.digest_of(a), be.digest_of(list(reversed(a))))
        self.assertEqual(be.digest_of(a), contract_digest(a))
        self.assertEqual(be.canonical(a), '[{"ip":"10.0.0.1","until":"2026-09-28T08:00:00Z"},'
                                          '{"ip":"9.9.9.9","until":"2026-09-28T08:00:00Z"}]')
        b = copy.deepcopy(a)
        b[0]["until"] = "2026-09-28T08:00:01Z"
        self.assertNotEqual(be.digest_of(a), be.digest_of(b))
        self.assertEqual(be.digest_of([]), hashlib.sha256(b"[]").hexdigest())

    def test_until_은_초_단위로_내린다(self):
        self.store.add("198.51.100.7", expires=T0 + timedelta(hours=1, microseconds=900000))
        self.run_once()
        self.assertEqual(self.s3.listed()["entries"][0]["until"], "2026-09-27T09:00:00Z")

    def test_바뀔_때와_10분마다만_올린다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        for _ in range(8):
            self.tick()
            self.run_once()
        self.assertEqual(len(self.s3.puts), 1)
        self.tick()                                   # 9분 뒤 (9분 30초가 문턱)
        self.run_once()
        self.tick()                                   # 10분 뒤: 생존 표시
        self.run_once()
        self.assertEqual(len(self.s3.puts), 2)
        self.assertEqual(self.s3.listed()["generated_at"], "2026-09-27T08:10:00Z")
        self.tick()
        self.store.add("198.51.100.8")                # 바뀌면 바로
        self.run_once()
        self.assertEqual(len(self.s3.puts), 3)

    def test_상한을_넘으면_요청이_늦은_것부터_넣고_나머지는_불일치로_둔다(self):
        with mock.patch.object(be, "LIST_MAX", 2):
            self.store.add("198.51.100.1", created=T0 - 3 * MIN)
            self.store.add("198.51.100.2", created=T0 - 2 * MIN)
            self.store.add("198.51.100.3", created=T0 - MIN)
            self.run_once()
            self.assertEqual([e["ip"] for e in self.s3.listed()["entries"]], ["198.51.100.2", "198.51.100.3"])
            self.assertEqual(self.row("198.51.100.1")["note"], "관문 불일치 · 목록 상한 2 초과")

    def test_빈_목록도_올린다(self):
        self.run_once()
        self.assertEqual(self.s3.listed()["entries"], [])


class ConfirmTest(Base):
    def test_관문이_적용한_목록의_행을_확인한다(self):
        self.store.add("198.51.100.7")
        self.assertEqual(self.run_once(), 1)          # 관문 보고가 아직 없다
        self.assertIsNone(self.row("198.51.100.7")["note"])
        at = T0 + timedelta(seconds=30, microseconds=250000)
        self.gw.sync(at)
        self.tick()
        self.assertEqual(self.run_once(), 0)
        self.confirmed("198.51.100.7", at)
        self.assertEqual(self.store.audit, [("enforced", "198.51.100.7")])

    def test_같은_값은_다시_쓰지_않는다(self):
        self.settle()
        writes, audit = self.store.writes, list(self.store.audit)
        for i in range(5):                             # 관문 보고 시각이 매 분 바뀌어도
            self.gw.sync(self.store.now + timedelta(seconds=30))
            self.tick()
            self.assertEqual(self.run_once(), 0)
        self.assertEqual((self.store.writes, self.store.audit), (writes, audit))
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))

    def test_목록이_매분_바뀌어도_한_회차_늦은_반영을_확인한다(self):
        ips = [f"198.51.100.{i}" for i in range(1, 6)]
        for n, ip in enumerate(ips):
            self.store.add(ip)                         # 흡수 후속 차단처럼 매 분 하나씩
            self.run_once()
            self.gw.sync(self.store.now + timedelta(seconds=30))
            self.tick()
        self.run_once()
        for ip in ips[:-1]:
            self.assertRegex(self.row(ip)["note"] or "", "^관문 반영")
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.assertRegex(self.row(ips[-1])["note"], "^관문 반영")
        self.assertEqual(sum(1 for a in self.store.audit if a[0] == "enforced"), 5)

    def test_연장된_행은_새_만료로_다시_확인한다(self):
        self.settle()
        r = self.row("198.51.100.7")
        r["expires_at"] = r["expires_at"] + DAY      # 흡수 후속 차단이 집행 열을 둔 채 만료만 늦췄다
        self.run_once()
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))   # 관문이 새 목록을 적용하기 전에는 그대로
        at = self.store.now + timedelta(seconds=20)
        self.gw.sync(at)
        self.tick()
        self.run_once()
        self.confirmed("198.51.100.7", at, kept=True)             # 앞 확인을 비운 적 없이 새 만료를 확인했다

    def test_방식이_바뀌면_새_방식으로_다시_확인한다(self):
        self.gw.mode = "fail2ban"
        self.store.add("198.51.100.7")
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30), mode="fail2ban")
        self.gw.mode = "nft"
        at = self.store.now + timedelta(seconds=30)
        self.gw.sync(at)
        self.tick()
        self.run_once()
        self.confirmed("198.51.100.7", at, mode="nft", kept=True)

    def test_상태_파일을_잃어도_DB_의_확인을_이어받는다(self):
        self.settle()
        writes, audit = self.store.writes, list(self.store.audit)
        self.st = be.new_state()
        self.run_once()                                # 목록을 다시 올린다 (같은 digest)
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.assertEqual((self.store.writes, self.store.audit), (writes, audit))
        self.assertEqual(len(self.s3.puts), 2)

    def test_그_사이_콘솔이_고친_행은_쓰지_않는다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30))
        self.tick()

        def console_rearms():                          # 읽은 뒤 콘솔이 다시 걸어 집행 열을 비웠다
            self.row("198.51.100.7")["expires_at"] += DAY
        self.store.before_apply = console_rearms
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])
        self.assertTrue(any("다음 회차" in m for _, m in self.logs))

    def test_dry_run_은_아무것도_고치지_않는다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30))
        self.tick()
        self.store.add("198.51.100.8")
        before = self.store.writes                     # 첫 회차가 7번 행의 지점별 결과(대기)를 한 번 썼다
        self.run_once(dry_run=True)
        self.assertEqual(len(self.s3.puts), 1)
        self.assertEqual(self.store.writes, before)
        self.assertTrue(any("(dry-run)" in m and "confirm" in m for _, m in self.logs))


class MismatchTest(Base):
    def test_보고가_멈추면_불일치로_두고_enforced_at_은_그대로다(self):
        self.settle()
        for _ in range(4):                             # 08:05 까지는 마지막 보고(08:00:30)가 5분 안
            self.tick()
            self.run_once()
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))
        self.tick()
        self.run_once()
        r = self.row("198.51.100.7")
        self.assertEqual(r["note"], "관문 불일치 · 관문 보고가 5분 넘게 멈춤 (마지막 2026-09-27T08:00:30Z)")
        self.assertEqual(r["enforced_at"], T0 + timedelta(seconds=30))
        writes = self.store.writes
        self.tick()
        self.run_once()
        self.assertEqual(self.store.writes, writes)    # 같은 쪽지는 다시 쓰지 않는다
        at = self.store.now + timedelta(seconds=10)
        self.gw.sync(at)                                # 되살아나면 새 시각으로 다시 확인한다
        self.tick()
        self.run_once()
        self.confirmed("198.51.100.7", at)
        self.assertEqual(sum(1 for a in self.store.audit if a[0] == "enforced"), 2)

    def test_보고를_5분_넘게_못_읽으면_불일치다(self):
        self.store.add("198.51.100.7")
        for _ in range(5):
            self.assertEqual(self.run_once(), 1)
            self.tick()
        self.assertIsNone(self.row("198.51.100.7")["note"])
        self.run_once()
        self.assertEqual(self.row("198.51.100.7")["note"],
                         "관문 불일치 · 관문 상태를 읽지 못함 (없음 (관문 동기화가 아직 쓰지 않았다))")

    def test_올린_지_5분이_지나도_반영되지_않으면_그_행만_불일치다(self):
        self.settle("198.51.100.7")
        old = self.s3.listed()["digest"]
        self.store.add("198.51.100.8")
        for _ in range(6):
            self.run_once()
            self.gw.sync(self.store.now + timedelta(seconds=30), digest=old)   # 관문이 새 목록을 못 받는다
            self.tick()
        self.run_once()
        self.assertEqual(self.row("198.51.100.8")["note"], "관문 불일치 · 5분 넘게 반영되지 않음")
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))

    def test_확인된_행은_한_회차_관문_오류로_뒤집히지_않는다(self):
        self.settle()
        for _ in range(6):                             # 올린 지 5분이 넘도록 멀쩡한 보고
            self.gw.sync(self.store.now + timedelta(seconds=30))
            self.tick()
            self.run_once()
        writes = self.store.writes
        self.gw.sync(self.store.now + timedelta(seconds=30), errors=["집합에서 빠진 원소 1개를 nft 로 되살림"])
        self.tick()
        self.run_once()                                # nft -f 뒤 관문이 되살린 회차
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))
        self.assertEqual(self.store.writes, writes)
        self.assertEqual(self.store.audit, [("enforced", "198.51.100.7")])

    def test_관문이_거부한_주소는_사유를_바로_적는다(self):
        self.store.add("198.51.100.7")
        self.store.add("198.51.100.8")
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30), rejected=[("198.51.100.8", "금지 대역\u202e(관문 목록)\n")])
        self.tick()
        self.run_once()
        self.assertEqual(self.row("198.51.100.8")["note"], "관문 불일치 · 관문 거부 · 금지 대역?(관문 목록)?")
        self.assertIsNone(self.row("198.51.100.8")["enforced_at"])
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))

    def test_곧_만료될_행의_거부는_불일치로_보지_않는다(self):
        self.store.add("198.51.100.7", expires=timedelta(minutes=2))
        self.run_once()
        self.gw.put({"v": 1, "at": be.iso(T0 + timedelta(seconds=90)), "mode": "nft", "list_digest": self.s3.listed()["digest"],
                     "list_generated_at": "2026-09-27T08:00:00Z", "applied": 0, "set_count": 0,
                     "rejected": [{"ip": "198.51.100.7", "why": "만료 지남"}], "errors": [], "selftest": None})
        self.tick(timedelta(seconds=100))
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["note"])

    def test_부분_반영_관문이_적용한_행은_확인하고_실패한_행만_거부다(self):
        for ip in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
            self.store.add(ip)
        self.run_once()
        at = T0 + timedelta(seconds=30)
        for _ in range(7):                             # 5분이 넘도록 3번 행만 관문에서 계속 실패한다
            self.gw.sync(self.store.now + timedelta(seconds=30), rejected=[("198.51.100.3", "nft 반영 실패")],
                         errors=["nft 반영 실패 1건: Error: Could not process rule"])
            self.tick()
            self.run_once()
        self.confirmed("198.51.100.1", at)             # 집합에 있는 행은 첫 보고의 at 으로 확인된 채다
        self.confirmed("198.51.100.2", at)
        r = self.row("198.51.100.3")
        self.assertEqual((r["note"], r["enforced_at"]), ("관문 불일치 · 관문 거부 · nft 반영 실패", None))
        self.assertEqual(self.store.audit, [("enforced", "198.51.100.1"), ("enforced", "198.51.100.2")])
        # 첫 회차의 지점별 결과(대기) 3 + 확인 2 · 거부 1. 거부가 이어져도 다시 쓰지 않는다
        self.assertEqual(self.store.writes, 6)
        self.assertEqual(self.row("198.51.100.3")["enforcement"]["gateway"]["state"], "failed")
        self.assertTrue(any("관문 오류 (행 확인은 보고대로)" in m for _, m in self.logs))

    def test_셈이_맞지_않는_보고가_5분_이어지면_불일치다(self):
        self.store.add("198.51.100.7")
        self.store.add("198.51.100.8")
        self.run_once()
        for _ in range(6):
            self.gw.sync(self.store.now + timedelta(seconds=30), applied=1)   # 거부는 없는데 하나만 적용했다고 한다
            self.tick()
            self.run_once()
        for ip in ("198.51.100.7", "198.51.100.8"):
            self.assertIsNone(self.row(ip)["enforced_at"])
            self.assertEqual(self.row(ip)["note"], "관문 불일치 · 관문 오류 · 적용 수 부족 (1/2)")

    def test_거부_목록이_관문_상한에_닿으면_확인하지_않는다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        capped = [(f"203.0.113.{i}", "집합에 없음") for i in range(be.GW_REJECTED_CAP)]   # 잘렸을 수 있는 거부 목록
        for _ in range(6):
            self.gw.sync(self.store.now + timedelta(seconds=30), rejected=capped)
            self.tick()
            self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])
        self.assertEqual(self.row("198.51.100.7")["note"], "관문 불일치 · 관문 오류 · 거부 목록이 관문 상한에 닿음 (200)")

    def test_숫자만_바뀌는_불일치_쪽지는_다시_쓰지_않는다(self):
        self.store.add("198.51.100.7")
        real, n = be.judge, [20]

        def judge(*a, **k):
            j = real(*a, **k)
            n[0] += 1
            j["mismatch"] = f"관문 오류 · 목록이 오래됨 ({n[0]}분)"      # 관문 문구의 수가 회차마다 바뀐다
            return j
        with mock.patch.object(be, "judge", judge):
            for _ in range(6):
                self.run_once()
                self.tick()
        self.assertEqual(self.row("198.51.100.7")["note"], "관문 불일치 · 관문 오류 · 목록이 오래됨 (21분)")
        self.assertEqual(self.store.writes, 1)

    def test_옛_목록의_거부는_연장된_행에_붙지_않는다(self):
        self.store.add("198.51.100.7", expires=timedelta(minutes=3))
        self.run_once()                                # 08:00 목록 (until 08:03)
        old = self.s3.listed()
        self.gw.sync(T0 + timedelta(seconds=30))
        self.tick()
        self.run_once()                                # 08:01 확인
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))
        self.tick()
        self.row("198.51.100.7")["expires_at"] = self.store.now + DAY    # 08:02 관리자가 연장했다
        # 관문이 08:02:59 에 옛 목록(until 08:03)을 읽어 '만료 지남'으로 거부했다. 집행기는 08:03 에 새 목록을 올린다
        self.gw.put({"v": 1, "at": be.iso(self.store.now + timedelta(seconds=59)), "mode": "nft",
                     "list_digest": old["digest"], "list_generated_at": old["generated_at"], "applied": 0, "set_count": 0,
                     "rejected": [{"ip": "198.51.100.7", "why": "만료 지남"}], "errors": [], "selftest": None})
        self.tick()
        self.run_once()                                # 08:03
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))       # 옛 목록의 거부는 이 행의 것이 아니다
        at = self.store.now + timedelta(seconds=30)
        self.gw.sync(at)
        self.tick()
        self.run_once()
        self.confirmed("198.51.100.7", at, kept=True)
        # 관문 열 2(확인 · 재확인) + 지점별 결과 2(첫 대기 · 연장 뒤 새 만료의 대기). 확인은 관문 열과 같은 쓰기에 실린다
        self.assertEqual(self.store.writes, 4)
        self.assertEqual(self.store.audit, [("enforced", "198.51.100.7")] * 2)

    def test_모르는_목록의_거부는_붙지_않는다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30), rejected=[("198.51.100.7", "집합에 없음")])
        self.tick()
        self.st = be.new_state()                       # 상태 파일을 잃었고
        self.store.add("198.51.100.8")                 # DB 도 바뀌어 지금 목록의 digest 가 다르다
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["note"])
        at = self.store.now + timedelta(seconds=30)
        self.gw.sync(at)
        self.tick()
        self.run_once()
        self.confirmed("198.51.100.7", at)
        self.confirmed("198.51.100.8", at)

    def test_적용_수가_모자라면_확인하지_않는다(self):
        self.store.add("198.51.100.7")
        self.store.add("198.51.100.8")
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30), applied=1)
        self.tick()
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])
        self.assertTrue(any("적용 수 부족 (1/2)" in m for _, m in self.logs))
        self.gw.sync(self.store.now, applied=2, set_count=0)       # 집합이 비었다 (flush ruleset)
        self.tick()
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])
        self.assertTrue(any("집합 원소 수 부족 (0/2)" in m for _, m in self.logs))

    def test_관문이_목록을_못_읽으면_그_까닭으로_불일치다(self):
        self.store.add("198.51.100.7")
        for _ in range(6):
            self.run_once()
            self.gw.put({"v": 1, "at": be.iso(self.store.now), "mode": "nft", "list_digest": None,
                         "list_generated_at": None, "applied": 0, "set_count": 3, "rejected": [],
                         "errors": ["목록 digest 불일치"], "selftest": None})
            self.tick()
        self.run_once()
        self.assertEqual(self.row("198.51.100.7")["note"], "관문 불일치 · 관문이 목록을 적용하지 못함 · 목록 digest 불일치")

    def test_모르는_목록을_5분_적용하면_불일치다(self):
        self.store.add("198.51.100.7")
        for _ in range(6):
            self.run_once()
            self.gw.sync(self.store.now, digest="f" * 64)
            self.tick()
        self.run_once()
        self.assertEqual(self.row("198.51.100.7")["note"], "관문 불일치 · 관문이 모르는 목록을 적용함 (ffffffff)")


class ReleaseExpireTest(Base):
    def test_만료되면_만료_기록을_한_번_남기고_관문이_뺀_뒤_집행을_푼다(self):
        self.store.add("198.51.100.7", expires=timedelta(minutes=3))
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))
        note = self.row("198.51.100.7")["note"]
        self.tick(3 * MIN)                             # 만료
        self.run_once()
        self.assertEqual(self.s3.listed()["entries"], [])
        self.assertEqual(self.store.expired_calls, [("198.51.100.7", T0 + 3 * MIN)])
        self.assertIsNotNone(self.row("198.51.100.7")["enforced_at"])   # 관문이 아직 옛 목록
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])
        self.assertEqual(self.row("198.51.100.7")["note"], note)
        self.tick()
        self.run_once()
        self.assertEqual(len(self.store.expired_calls), 1)              # 회차마다 부르지 않는다
        self.assertEqual([a[0] for a in self.store.audit], ["enforced", "expired", "unenforced"])

    def test_관문이_멈춰도_만료_24시간_뒤에는_집행을_푼다(self):
        self.store.add("198.51.100.7", expires=timedelta(minutes=3))
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.tick(DAY)                                 # 관문 보고가 멈췄다 (만료 뒤 23시간 57분)
        self.run_once()
        self.assertIsNotNone(self.row("198.51.100.7")["enforced_at"])
        self.tick(3 * MIN)
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])

    def test_해제된_행도_관문_보고가_끊기면_만료_24시간_뒤에_집행을_푼다(self):
        self.store.add("198.51.100.7", expires=timedelta(hours=1))
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.row("198.51.100.7")["released_at"] = self.store.now      # 여기서 관문 보고가 멈춘다
        self.tick(DAY)                                 # 만료(08:00+1시간) 뒤 23시간 1분
        self.run_once()
        self.assertIsNotNone(self.row("198.51.100.7")["enforced_at"])
        self.tick(timedelta(hours=1))
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])
        self.assertEqual(self.store.audit, [("enforced", "198.51.100.7"), ("unenforced", "198.51.100.7")])
        self.assertEqual(self.store.expired_calls, [])                  # 해제는 만료 기록이 아니다

    def test_해제된_행은_관문이_뺀_목록을_적용한_뒤에_푼다(self):
        self.settle()
        self.row("198.51.100.7")["released_at"] = self.store.now
        self.run_once()
        self.assertIsNotNone(self.row("198.51.100.7")["enforced_at"])
        self.assertEqual(self.store.expired_calls, [])
        self.tick(10 * MIN)                            # 관문 보고가 멈춰 있으면 계속 기다린다
        self.run_once()
        self.assertIsNotNone(self.row("198.51.100.7")["enforced_at"])
        self.gw.sync(self.store.now)
        self.tick()
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])
        self.assertEqual(self.store.audit[-1], ("unenforced", "198.51.100.7"))

    def test_집행기가_멈춘_동안의_만료도_줍는다(self):
        self.store.add("198.51.100.7", expires=-DAY)
        self.store.add("198.51.100.8", expires=-3 * DAY)           # 2일보다 오래됐다
        self.run_once()
        self.assertEqual([k for k, _ in self.store.expired_calls], ["198.51.100.7"])

    def test_만료_기록이_실패하면_다음_회차에_다시_부른다(self):
        self.store.add("198.51.100.7", expires=-MIN)
        with mock.patch.object(self.store, "note_expired", side_effect=RuntimeError("권한이 없다")):
            self.assertEqual(self.run_once(), 1)
        self.tick()
        self.run_once()
        self.assertEqual(len(self.store.expired_calls), 1)


class ExcludeTest(Base):
    def test_제외_쪽지는_한_번만_쓴다(self):
        s = self.store
        s.add("203.0.113.12", expires=None)
        s.add("198.51.100.0/24")
        s.add("10.1.2.3")
        s.add("198.51.100.99", exempt_net="198.51.100.99/32")
        s.add("15.164.37.49")
        s.add("2001:db8::7")
        s.add("fe80::1")
        self.run_once()
        self.assertEqual(self.row("203.0.113.12")["note"], "집행 제외 · 만료 없음")
        self.assertEqual(self.row("198.51.100.0/24")["note"], "집행 제외 · 대역 주소")
        for ip in ("10.1.2.3", "198.51.100.99", "15.164.37.49", "fe80::1"):
            self.assertEqual(self.row(ip)["note"], "집행 제외 · 금지 대역", ip)
        self.assertIsNone(self.row("2001:db8::7")["note"])
        self.assertEqual(self.store.writes, 6)
        self.assertEqual(self.store.audit, [])         # 쪽지만 바뀌어 집행 감사가 없다
        self.tick()
        self.run_once()
        self.assertEqual(self.store.writes, 6)

    def test_만료가_생긴_옛_행은_대기로_돌렸다가_확인한다(self):
        self.store.add("203.0.113.12", expires=None)
        self.run_once()
        self.assertEqual(self.row("203.0.113.12")["note"], "집행 제외 · 만료 없음")
        self.row("203.0.113.12")["expires_at"] = self.store.now + DAY      # 관리자가 만료를 줬다
        self.tick()
        self.run_once()
        self.assertIsNone(self.row("203.0.113.12")["note"])
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.assertRegex(self.row("203.0.113.12")["note"], "^관문 반영")

    def test_운영의_만료_없는_13건은_제외만_하고_목록에_넣지_않는다(self):
        for i in range(13):
            self.store.add(f"203.0.113.{100 + i}", expires=None, created=T0 - 19 * DAY)
        self.run_once()
        self.assertEqual(self.s3.listed()["entries"], [])
        self.assertTrue(all(r["note"] == "집행 제외 · 만료 없음" for r in self.store.rows.values()))
        self.assertEqual(self.store.audit, [])

    def test_집행된_행이_금지_대역이_되면_관문이_뺀_뒤_푼다(self):
        self.settle()
        self.row("198.51.100.7")["exempt_net"] = "198.51.100.0/24"
        self.run_once()
        r = self.row("198.51.100.7")
        self.assertEqual(r["note"], "집행 제외 · 금지 대역")
        self.assertIsNotNone(r["enforced_at"])
        self.gw.sync(self.store.now)
        self.tick()
        self.run_once()
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])


class FailureTest(Base):
    def test_DB_를_못_읽으면_올리지_않는다(self):
        self.store.fail_fetch = True
        self.assertEqual(self.run_once(), 1)
        self.assertEqual(self.s3.puts, [])

    def test_목록을_못_올리면_확인하지_않고_다음에_다시_올린다(self):
        self.settle()
        self.store.add("198.51.100.8")
        self.s3.fail_put = "AccessDenied"
        self.assertEqual(self.run_once(), 1)
        self.gw.sync(self.store.now)
        self.tick()
        self.run_once()
        self.assertIsNone(self.row("198.51.100.8")["note"])            # 올리지 못한 행은 대기
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))
        self.s3.fail_put = None
        self.tick()
        self.run_once()
        self.assertEqual(len(self.s3.listed()["entries"]), 2)

    def test_목록을_5분_넘게_못_올리면_S3_에_없는_행은_불일치다(self):
        self.settle()
        self.store.add("198.51.100.8")
        self.s3.fail_put = "AccessDenied"              # 쓰기 키가 꺼졌다. 관문은 옛 목록을 계속 적용한다
        for _ in range(5):                             # 08:01 ~ 08:05 (처음 실패부터 4분)
            self.assertEqual(self.run_once(), 1)
            self.gw.sync(self.store.now + timedelta(seconds=30))
            self.tick()
        self.assertIsNone(self.row("198.51.100.8")["note"])
        self.run_once()                                # 처음 실패부터 5분
        self.assertEqual(self.row("198.51.100.8")["note"], "관문 불일치 · 목록을 5분 넘게 올리지 못함")
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))     # S3 목록에 있는 행은 그대로 확인
        writes = self.store.writes
        for _ in range(3):                             # 같은 쪽지를 다시 쓰지 않는다
            self.tick()
            self.run_once()
        self.assertEqual(self.store.writes, writes)
        self.s3.fail_put = None
        self.tick()
        self.assertEqual(self.run_once(), 0)
        self.assertIsNone(self.st["upload_fail_since"])
        at = self.store.now + timedelta(seconds=30)
        self.gw.sync(at)
        self.tick()
        self.run_once()
        self.confirmed("198.51.100.8", at)
        self.assertEqual(self.store.audit, [("enforced", "198.51.100.7"), ("enforced", "198.51.100.8")])

    def test_올릴_것이_없어지면_올리기_실패_시계를_지운다(self):
        self.settle()
        self.store.add("198.51.100.8")
        self.s3.fail_put = "SlowDown"
        self.run_once()
        self.assertIsNotNone(self.st["upload_fail_since"])
        del self.store.rows["198.51.100.8"]           # S3 에 있는 목록과 다시 같아졌다
        self.tick()
        self.assertEqual(self.run_once(), 0)
        self.assertIsNone(self.st["upload_fail_since"])

    def test_DB_쓰기가_실패하면_다음_회차에_같은_값을_쓴다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        self.gw.sync(T0 + timedelta(seconds=30))
        self.tick()
        self.store.fail_apply = True
        self.assertEqual(self.run_once(), 1)
        self.store.fail_apply = False
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.assertEqual(self.run_once(), 0)
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))


class StatusTest(unittest.TestCase):
    def base(self, **kw):
        d = {"v": 1, "at": "2026-09-27T08:00:30Z", "mode": "nft", "list_digest": "a" * 64,
             "list_generated_at": "2026-09-27T08:00:00Z", "applied": 1, "set_count": 1, "rejected": [], "errors": [],
             "selftest": "ok"}
        d.update(kw)
        return d

    def check(self, body):
        s3 = FakeS3()
        s3.objects["k"] = body if isinstance(body, bytes) else json.dumps(body).encode()
        return be.read_status(s3, "b", "k", T0 + MIN)

    def test_맞는_보고(self):
        gw, why = self.check(self.base(rejected=[{"ip": "198.51.100.8", "why": "x"}, {"ip": "없음", "why": "y"},
                                                 {"ip": 1, "why": "z"}, "1.2.3.4"]))
        self.assertIsNone(why)
        self.assertEqual(gw["at"], T0 + timedelta(seconds=30))
        self.assertEqual(gw["rejected"], {"198.51.100.8": "x"})
        self.assertEqual(gw["selftest"], "ok")

    def test_틀린_보고는_못_읽은_것으로_본다(self):
        cases = [(b"{", "JSON 이 아니다"), (b'{"v": NaN}', "JSON 이 아니다"), (self.base(v=2), "형식 틀림 (v)"),
                 (self.base(at="2026-09-27 08:00:30"), "형식 틀림 (at)"),
                 (self.base(at="2026-09-27T08:05:00Z"), "관문 시각이 앞섬"),
                 (self.base(mode="iptables"), "형식 틀림 (mode)"), (self.base(list_digest="A" * 64), "형식 틀림 (list_digest)"),
                 (self.base(errors="x"), "형식 틀림 (rejected · errors)"),
                 (self.base(applied=None), "형식 틀림 (applied)"), (self.base(applied="1"), "형식 틀림 (applied)"),
                 (b" " * (be.STATUS_MAX + 1), "크기 초과")]
        for body, want in cases:
            self.assertEqual(self.check(body), (None, want), want)
        self.assertEqual(be.read_status(FakeS3(), "b", "없는 키", T0)[1], "없음 (관문 동기화가 아직 쓰지 않았다)")

    def test_문구는_제어_문자를_지우고_자른다(self):
        gw, _ = self.check(self.base(errors=["a\x1b[31m\u200bb" + "x" * 500] * 150))
        self.assertEqual(gw["errors"][0], "a?[31m?b" + "x" * 112)
        self.assertEqual(len(gw["errors"]), 101)


class ConfigTest(unittest.TestCase):
    def test_비밀_파일은_systemd_사본이_먼저고_셸로_읽지_않는다(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s3-block.env")
            with open(p, "w") as f:
                f.write("# 주석\nAWS_ACCESS_KEY_ID=AKIA$(touch /tmp/x)\nAWS_SECRET_ACCESS_KEY = s=e`c`\n")
            with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": d}, clear=False):
                os.environ.pop("OPSLOOP_ENFORCER_S3_BLOCK_ENV", None)
                self.assertEqual(be.secret_path("s3-block.env"), p)
                self.assertEqual(be.secret_path("s3-pull.env"), "/etc/opsloop/s3-pull.env")
            self.assertEqual(be.read_env(p), {"AWS_ACCESS_KEY_ID": "AKIA$(touch /tmp/x)", "AWS_SECRET_ACCESS_KEY": "s=e`c`"})

    def test_관문_ID_가_틀리면_설정_오류다(self):
        with mock.patch.dict(os.environ, {"OPSLOOP_ENFORCER_DEFAULTS": "/nonexistent", "OPSLOOP_GATEWAY_ID": "i-x; rm"}):
            with self.assertRaises(be.ConfigError):
                be.settings()
        with mock.patch.dict(os.environ, {"OPSLOOP_ENFORCER_DEFAULTS": "/nonexistent"}):
            os.environ.pop("OPSLOOP_GATEWAY_ID", None)
            self.assertEqual(be.settings()["gateway"], GW)

    def test_금지_대역_상수는_계약_목록과_같다(self):
        want = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "15.164.37.49/32",
                "::1/128", "fc00::/7", "fe80::/10"]
        self.assertEqual([str(n) for n in be.EXEMPT_NETS], want)
        for ip in ("192.0.2.123", "198.51.100.1", "203.0.113.254"):        # 시험 출발지는 막히지 않는다
            self.assertFalse(be.in_exempt(ip), ip)

    def test_금지_대역과_digest_는_관문_코드와_같다(self):
        path = os.path.join(ROOT, "infra", "aws", "gateway", "block-sync.py")
        spec = importlib.util.spec_from_file_location("block_sync_for_enforcer_test", path)
        bs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bs)
        self.assertEqual(be.EXEMPT_NETS, bs.EXEMPT)
        self.assertEqual(be.GW_REJECTED_CAP, bs.MAX_REJECTED)
        entries = [{"ip": ip, "until": "2026-09-28T08:00:00Z"} for ip in ("9.9.9.9", "11.0.0.10", "11.0.0.9", "203.0.113.9")]
        doc = be.list_doc(entries[:2], entries, T0)                                # 관문 목록 · 내부 방화벽 목록 (이슈 #77)
        wire = json.loads(json.dumps(doc, ensure_ascii=True).encode("utf-8"))    # 올린 바이트를 관문이 읽은 모양
        self.assertEqual(bs.canonical_digest(wire["entries"]), doc["digest"])
        self.assertEqual(bs.canonical_digest(wire["points"]["fw"]["entries"]), doc["points"]["fw"]["digest"])
        for ip in ("192.0.2.123", "198.51.100.1", "10.0.0.1", "15.164.37.49", "fe80::1", "8.8.8.8"):
            self.assertEqual(be.in_exempt(ip), bs.check_ip(ip)[1] is not None and bs.check_ip(ip)[1].startswith("금지"), ip)

    def test_list_는_JSON_을_먼저_내보내고_갈래_수가_마지막_줄이다(self):
        # 설치기는 `opsloop-enforcer list 2>&1 | tail -n 1` 로 갈래 수를 보인다. 표준 출력이 버퍼에 남으면 '}' 가 찍힌다
        code = ("import sys\nsys.path.insert(0, %r)\nimport block_enforcer as be, test_block_enforcer as te\n"
                "s = te.FakeStore()\nfor i in range(13):\n    s.add('203.0.113.%%d' %% (100 + i), expires=None)\n"
                "class C:\n    def close(self): pass\n"
                "be.db_connect = lambda: C()\nbe.PgStore = lambda c: s\nsys.exit(be.main(['list']))\n") % HERE
        env = {k: v for k, v in os.environ.items() if k != "JOURNAL_STREAM"}
        p = subprocess.run([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                           timeout=60, env=env)
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(p.stdout.splitlines()[-1], "# 행 13: exclude 13")
        self.assertEqual(json.loads(p.stdout[:p.stdout.rindex("}") + 1])["entries"], [])

    def test_상태_파일은_원자적으로_쓰고_깨지면_새로_시작한다(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "state.json")
            st = be.new_state()
            st["seq"] = 7
            be.save_state(p, st)
            self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o600")
            self.assertEqual(be.load_state(p)["seq"], 7)
            with open(p, "w") as f:
                f.write("{")
            with mock.patch.object(be, "log"):
                self.assertEqual(be.load_state(p), be.new_state())

    def test_잠금은_한_실행만_잡고_읽기로_연다(self):
        with tempfile.TemporaryDirectory() as d:
            a = be.take_lock(d)
            with self.assertRaises(be.ConfigError):
                be.take_lock(d, wait=2, sleep=lambda s: None)
            a.close()
            os.chmod(os.path.join(d, "enforcer.lock"), 0o444)      # root 가 만든 파일처럼 쓰기 권한이 없어도
            be.take_lock(d).close()

    def test_root_는_dry_run_만_한다(self):
        with mock.patch.object(be.os, "geteuid", return_value=0), mock.patch.object(be, "log") as lg:
            self.assertEqual(be.main(["run"]), 2)
        self.assertIn("root 로는", lg.call_args[0][0])

    def test_인자가_틀리면_2(self):
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as c:
                be.main(["없는-명령"])
        self.assertEqual(c.exception.code, 2)


class HeartbeatTest(Base):
    """차단 보고 생존 신호 (이슈 #52). 회차마다 지점별 한 줄을 넘기고, 못 읽은 회차는 seen_at 없이 까닭을 넘긴다."""

    def test_관문_보고를_읽으면_그_at_을_못_읽으면_까닭을_넘긴다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        self.assertEqual(self.store.beats, [[{"source": "block:gateway", "role": "gateway", "host": GW, "seen_at": None,
                                              "problem": "없음 (관문 동기화가 아직 쓰지 않았다)"}]])
        at = self.store.now + timedelta(seconds=30)
        self.gw.sync(at)
        self.tick()
        self.run_once()
        self.assertEqual(self.store.beats[-1], [{"source": "block:gateway", "role": "gateway", "host": GW,
                                                 "seen_at": at.replace(microsecond=0), "problem": None}])

    def test_멈춘_보고도_읽었으면_문제가_아니고_시각으로_드러난다(self):
        at = self.store.now
        self.store.add("198.51.100.7")
        self.run_once()
        self.gw.sync(at)
        self.tick(10 * MIN)
        self.run_once()
        self.assertEqual((self.store.beats[-1][0]["seen_at"], self.store.beats[-1][0]["problem"]), (at, None))
        self.assertTrue(any("5분 넘게 멈춤" in m for _, m in self.logs))

    def test_내부_방화벽을_설정하면_두_줄이다(self):
        self.cfg["fw"] = FW
        fw = Gateway(self.s3, key=FW_STATUS)
        self.store.add("203.0.113.10")
        self.run_once()
        at = self.store.now + timedelta(seconds=40)
        fw.sync(at)
        self.tick()
        self.run_once()
        self.assertEqual(self.store.beats[-1], [
            {"source": "block:gateway", "role": "gateway", "host": GW, "seen_at": None,
             "problem": "없음 (관문 동기화가 아직 쓰지 않았다)"},
            {"source": "block:fw", "role": "fw", "host": FW, "seen_at": at.replace(microsecond=0), "problem": None}])

    def test_형식이_틀린_보고는_못_읽은_것이다(self):
        self.gw.put({"v": 1, "at": be.iso(self.store.now + timedelta(minutes=10)), "mode": "nft", "applied": 0})
        self.run_once()
        self.assertEqual(self.store.beats[-1][0]["problem"], "관문 시각이 앞섬")
        self.assertIsNone(self.store.beats[-1][0]["seen_at"])

    def test_dry_run_은_기록하지_않는다(self):
        self.gw.put({"v": 1, "at": be.iso(self.store.now), "mode": "nft", "applied": 0})
        self.run_once(dry_run=True)
        self.assertEqual(self.store.beats, [])

    def test_기록이_실패해도_종료_코드와_집행은_그대로다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        self.gw.sync(self.store.now + timedelta(seconds=30))
        for code, level in (("42P01", 5), ("42501", 5), ("", 4), ("57014", 4)):
            with self.subTest(code=code):
                self.store.fail_heartbeat = code
                self.logs.clear()
                self.tick()
                self.assertEqual(self.run_once(), 0)
                [(got, msg)] = [(lv, m) for lv, m in self.logs if m.startswith("차단 보고 생존 신호를 기록하지 못했다")]
                self.assertEqual(got, level)
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=30))       # 집행 기록은 그대로 됐다
        self.assertEqual(self.store.beats, [[{"source": "block:gateway", "role": "gateway", "host": GW, "seen_at": None,
                                              "problem": "없음 (관문 동기화가 아직 쓰지 않았다)"}]])


# ── 실제 PostgreSQL ────────────────────────────────────────────────────────────

try:
    import psycopg2
    REAL_PG = True
except ImportError:
    REAL_PG = False

URL = os.environ.get("OPSLOOP_TEST_DATABASE_URL")
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20260927_block_enforce.sql")
MIGRATION51 = os.path.join(ROOT, "infra", "migrations", "20260929_block_points.sql")   # #47 뒤에 적용해야 enforcement 권한이 남는다
MIGRATION52 = os.path.join(ROOT, "infra", "migrations", "20260930_status_board.sql")   # #47 뒤에 적용해야 생존 신호 권한이 남는다
MIGRATION77 = os.path.join(ROOT, "infra", "migrations", "20261003_block_points_choice.sql")   # 요청 지점 (설치기 순서 그대로)


def with_db(url, db, user=None, password=None):
    u = urllib.parse.urlsplit(url)
    netloc = u.netloc if user is None else f"{user}:{urllib.parse.quote(password)}@{u.hostname}:{u.port or 5432}"
    return urllib.parse.urlunsplit((u.scheme, netloc, "/" + db, u.query, ""))


APP_DIR = os.path.join(ROOT, "app")
TRIAGE_PY = os.path.join(ROOT, "detector", "triage.py")


def load_file(name, path, near=None):
    """저장소의 다른 모듈을 파일에서 부른다. near 는 그 모듈이 부르는 이웃 모듈의 폴더다."""
    if near:
        sys.path.insert(0, near)
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if near:
            sys.path.remove(near)


def console_block_sql():
    """콘솔 add_action 의 차단 문장 그대로(app/main.py BLOCK_SQL, $n 자리표시자). 앱(FastAPI)을 불러오지 않고 글자에서 떼어
    f-문자열의 이름(_LIVE · block_points)을 채운다(infra/test_block_enforce_db.py 와 같은 방식)."""
    with open(os.path.join(APP_DIR, "main.py"), encoding="utf-8") as f:
        text = f.read()
    ns = {"_LIVE": re.search(r'^_LIVE = "(.+)"$', text, re.M).group(1),
          "block_points": load_file("block_points_for_enforcer_test", os.path.join(APP_DIR, "block_points.py"))}
    [node] = [n.value for n in ast.parse(text).body
              if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", None) == "BLOCK_SQL"]
    return "".join(v.value if isinstance(v, ast.Constant) else str(eval(ast.unparse(v.value), {}, ns))   # noqa: S307
                   for v in node.values)


def main_sql(name):
    """app/main.py 의 글자 상수 문장(f-문자열이 아닌 것) 그대로."""
    with open(os.path.join(APP_DIR, "main.py"), encoding="utf-8") as f:
        text = f.read()
    [node] = [n.value for n in ast.parse(text).body
              if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", None) == name]
    return ast.literal_eval(node)


def positional(sql, *args):
    """asyncpg 자리표시자($n) 문장을 psycopg2 로 돌린다. $n 을 %s 로 바꾸고 나오는 차례대로 인자를 늘어놓는다."""
    order = [int(n) for n in re.findall(r"\$(\d+)", sql)]
    return re.sub(r"\$\d+", "%s", sql.replace("%", "%%")), [args[n - 1] for n in order]


@unittest.skipUnless(REAL_PG and URL and os.path.exists(MIGRATION), "PostgreSQL 시험 연결 · 마이그레이션 없음")
class PgBase(unittest.TestCase):
    """스키마 · 마이그레이션을 그대로 적용한 새 DB 에서 opsloop_enforcer 역할로 회차를 돌린다."""

    def setUp(self):
        self.db = f"opsloop_enforcer_test_{os.getpid()}_{secrets.token_hex(4)}"
        self.pw = secrets.token_urlsafe(24)
        admin = psycopg2.connect(URL)
        admin.autocommit = True
        with admin.cursor() as c:
            c.execute(f"CREATE DATABASE {self.db}")
            c.execute("SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_enforcer'")
            verb = "ALTER" if c.fetchone() else "CREATE"
            c.execute(f"{verb} ROLE opsloop_enforcer WITH LOGIN NOINHERIT CONNECTION LIMIT 2 PASSWORD %s", (self.pw,))
        admin.close()
        self.owner = psycopg2.connect(with_db(URL, self.db))
        self.owner.autocommit = True
        with self.owner.cursor() as c:
            c.execute("SET client_min_messages = warning")
            for path in (SCHEMA, MIGRATION, MIGRATION51, MIGRATION52, MIGRATION77):
                with open(path, encoding="utf-8") as f:
                    c.execute(f.read())
        self.conn = psycopg2.connect(with_db(URL, self.db, "opsloop_enforcer", self.pw))
        self.store = be.PgStore(self.conn)
        self.s3 = FakeS3()
        self.gw = Gateway(self.s3)
        self.st = be.new_state()
        self.cfg = {"bucket": "b", "gateway": GW, "home": "/nonexistent", "region": "x"}
        p = mock.patch.object(be, "log", lambda m, level=6: None)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.conn.close()
        self.owner.close()
        admin = psycopg2.connect(URL)
        admin.autocommit = True
        with admin.cursor() as c:
            c.execute(f"DROP DATABASE IF EXISTS {self.db} WITH (FORCE)")
        admin.close()

    def sql(self, q, args=()):
        with self.owner.cursor() as c:
            c.execute(q, args)
            return c.fetchall() if c.description else None

    def audit(self):
        return [r[0] for r in self.sql("SELECT eventid FROM events WHERE sensor = 'audit' ORDER BY ts, line_hash")]

    def cycle(self):
        return be.cycle(self.cfg, self.store, self.s3, self.s3, self.st)


class PgTest(PgBase):
    """한 회차 · 권한 · 트리거 · 감사 · 만료 기록 · 요청 지점(이슈 #77)."""

    def test_한_회차를_집행_역할로_돌린다(self):
        self.sql("INSERT INTO blocklist (actor_ip, reason, expires_at) VALUES "
                 "('198.51.100.7', '시험', now() + interval '1 day'), ('198.51.100.8', '시험', now() - interval '1 minute'),"
                 "('203.0.113.12', '시험', NULL)")
        base = len(self.audit())
        self.cycle()
        self.assertEqual([e["ip"] for e in self.s3.listed()["entries"]], ["198.51.100.7"])
        at = datetime.now(timezone.utc).replace(microsecond=0)
        self.gw.sync(at)
        self.cycle()
        row = self.sql("SELECT enforced_at, method, enforce_note FROM blocklist WHERE actor_ip = '198.51.100.7'")[0]
        self.assertEqual(row[0], at)
        self.assertEqual(row[1], "nft")
        self.assertRegex(row[2], "^관문 반영 · ")
        self.assertEqual(self.sql("SELECT enforce_note FROM blocklist WHERE actor_ip = '203.0.113.12'")[0][0],
                         "집행 제외 · 만료 없음")
        events = self.audit()[base:]
        self.assertEqual(events.count("console.block.enforced"), 1)
        self.assertEqual(events.count("console.block.expired"), 1)
        self.cycle()                                              # 멱등: 감사가 늘지 않는다
        self.assertEqual(len(self.audit()) - base, len(events))
        self.sql("UPDATE blocklist SET released_at = now(), released_by = 'admin' WHERE actor_ip = '198.51.100.7'")
        self.cycle()
        self.gw.sync(datetime.now(timezone.utc))
        self.cycle()
        self.assertIsNone(self.sql("SELECT enforced_at FROM blocklist WHERE actor_ip = '198.51.100.7'")[0][0])
        self.assertIn("console.block.unenforced", self.audit()[base:])
        actors = self.sql("SELECT DISTINCT username FROM events WHERE eventid IN "
                          "('console.block.enforced', 'console.block.expired', 'console.block.unenforced')")
        self.assertEqual(actors, [("db:opsloop_enforcer",)])

    def test_금지_대역_표와_옛_대역_행은_집행_제외다(self):
        # 트리거가 생기기 전에 들어간 행을 흉내 낸다 (설정만 소유자로 트리거를 잠깐 끈다)
        self.sql("ALTER TABLE blocklist DISABLE TRIGGER blocklist_guard")
        self.sql("INSERT INTO blocklist (actor_ip, reason, expires_at) VALUES "
                 "('198.51.100.0/24', '옛 행', now() + interval '1 day'), ('10.9.9.9', '옛 행', now() + interval '1 day')")
        self.sql("ALTER TABLE blocklist ENABLE TRIGGER blocklist_guard")
        self.sql("INSERT INTO blocklist (actor_ip, reason, expires_at) VALUES ('198.51.100.7', '시험', now() + interval '1 day')")
        self.sql("INSERT INTO block_exempt (cidr, note) VALUES ('198.51.100.7/32', '시험 뒤 금지')")
        self.cycle()
        self.assertEqual(self.s3.listed()["entries"], [])
        self.assertEqual(dict(self.sql("SELECT abbrev(actor_ip), enforce_note FROM blocklist")),
                         {"198.51.100.0/24": "집행 제외 · 대역 주소", "10.9.9.9": "집행 제외 · 금지 대역",
                          "198.51.100.7": "집행 제외 · 금지 대역"})

    def test_차단_보고_생존_신호를_집행_역할로_쓰고_못_읽은_회차는_시각을_둔다(self):
        self.cycle()
        self.assertEqual(self.sql("SELECT source, kind, role, host, seen_at, problem, checked_at > now() - interval '1 minute'"
                                  " FROM sensor_heartbeats"),
                         [("block:gateway", "block_report", "gateway", GW, None, "없음 (관문 동기화가 아직 쓰지 않았다)", True)])
        at = datetime.now(timezone.utc).replace(microsecond=0)
        self.gw.sync(at)
        self.cycle()
        self.assertEqual(self.sql("SELECT seen_at, problem FROM sensor_heartbeats"), [(at, None)])
        del self.s3.objects[STATUS]
        self.cycle()
        self.assertEqual(self.sql("SELECT seen_at, problem FROM sensor_heartbeats"),
                         [(at, "없음 (관문 동기화가 아직 쓰지 않았다)")])
        # 트리거: 집행 역할은 업로더 신호를 꾸미지 못한다 (표 권한은 있다)
        with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
            with self.conn, self.conn.cursor() as c:
                c.execute("INSERT INTO sensor_heartbeats (source, kind, role, host, checked_at)"
                          " VALUES ('uploader:i-058726c1a0671fe1d', 'uploader', 'sensor', 'i-058726c1a0671fe1d', now())")

    def test_집행_역할은_집행_세_열만_고친다(self):
        self.sql("INSERT INTO blocklist (actor_ip, reason, expires_at) VALUES ('198.51.100.7', '시험', now() + interval '1 day')")
        for q in ("UPDATE blocklist SET expires_at = now()", "UPDATE blocklist SET released_at = now()",
                  "INSERT INTO blocklist (actor_ip) VALUES ('198.51.100.9')", "DELETE FROM blocklist",
                  "SELECT count(*) FROM events", "INSERT INTO block_exempt (cidr, note) VALUES ('198.51.100.0/24', 'x')",
                  "UPDATE blocklist SET points = '{fw}'"):                   # 요청 지점은 콘솔만 고친다 (이슈 #77)
            with self.subTest(q=q), self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                with self.conn, self.conn.cursor() as c:
                    c.execute(q)

    # ── 차단 적용 지점 선택 (이슈 #77) ──

    def enf(self):
        """주소 → (points, enforced_at 있음, 지점 → state)."""
        return {ip: (p, e, s) for ip, p, e, s in self.sql(
            "SELECT host(actor_ip), points, enforced_at IS NOT NULL,"
            " (SELECT jsonb_object_agg(k, v->>'state') FROM jsonb_each(enforcement) AS x(k, v)) FROM blocklist")}

    def test_지점별_모드의_내부_방화벽_전용_행을_집행_역할로_돌린다(self):
        # 요청 지점은 to_jsonb 로 읽고, 읽은 값 대조에 points 가 든 UPDATE 가 실제 DB 에서 맞는다
        self.sql("INSERT INTO blocklist (actor_ip, reason, expires_at) VALUES ('198.51.100.7', '시험', now() + interval '1 day')")
        self.sql("INSERT INTO blocklist (actor_ip, reason, expires_at, points)"
                 " VALUES ('203.0.113.10', '시험', now() + interval '1 day', '{fw}')")
        self.cfg["fw"] = FW
        fw = Gateway(self.s3, key=FW_STATUS, point="fw")
        base = len(self.audit())
        self.cycle()
        self.assertEqual([e["ip"] for e in self.s3.listed()["entries"]], ["198.51.100.7", "203.0.113.10"])   # 보고 전이라 전체
        for _ in range(2):
            at = datetime.now(timezone.utc).replace(microsecond=0)
            self.gw.sync(at)
            fw.sync(at)
            self.cycle()
        doc = self.s3.listed()
        self.assertEqual([e["ip"] for e in doc["entries"]], ["198.51.100.7"])
        self.assertEqual([e["ip"] for e in doc["points"]["fw"]["entries"]], ["198.51.100.7", "203.0.113.10"])
        self.assertEqual(self.enf(), {"198.51.100.7": (["gateway", "fw"], True, {"gateway": "confirmed", "fw": "confirmed"}),
                                      "203.0.113.10": (["fw"], False, {"fw": "confirmed"})})
        self.assertEqual(self.audit()[base:], ["console.block.enforced"])
        # 해제: 요청 지점마다 removing 을 거쳐 NULL
        self.sql("UPDATE blocklist SET released_at = now(), released_by = 'admin' WHERE actor_ip = '203.0.113.10'")
        self.cycle()
        self.assertEqual(self.enf()["203.0.113.10"], (["fw"], False, {"fw": "removing"}))
        fw.sync(datetime.now(timezone.utc).replace(microsecond=0))
        self.cycle()
        self.assertEqual(self.enf()["203.0.113.10"], (["fw"], False, None))
        self.assertNotIn("console.block.unenforced", self.audit()[base:])

    def test_points_열이_없는_DB_에서도_두_지점으로_돈다(self):
        self.sql("ALTER TABLE blocklist DROP COLUMN points CASCADE")        # 20261003 을 적용하기 전 DB
        self.sql("INSERT INTO blocklist (actor_ip, reason, expires_at) VALUES ('198.51.100.7', '시험', now() + interval '1 day')")
        self.cycle()
        self.assertEqual([e["ip"] for e in self.s3.listed()["entries"]], ["198.51.100.7"])
        self.gw.sync(datetime.now(timezone.utc).replace(microsecond=0))
        self.cycle()
        row = self.sql("SELECT enforced_at IS NOT NULL, enforcement ? 'gateway', enforcement ? 'fw' FROM blocklist")[0]
        self.assertEqual(row, (True, True, True))

    def test_읽은_뒤_콘솔이_넓힌_행은_쓰지_않는다(self):
        self.sql("INSERT INTO blocklist (actor_ip, reason, expires_at, points)"
                 " VALUES ('203.0.113.10', '시험', now() + interval '1 day', '{fw}')")
        real = self.store.apply

        def widen_then_apply(updates):                              # 집행기가 읽은 뒤 콘솔이 관문을 더했다
            self.sql("UPDATE blocklist SET points = '{gateway,fw}' WHERE actor_ip = '203.0.113.10'")
            return real(updates)
        self.store.apply = widen_then_apply
        self.cycle()
        self.assertEqual(self.enf()["203.0.113.10"], (["gateway", "fw"], False, None))
        self.store.apply = real
        self.cycle()
        self.assertEqual(self.enf()["203.0.113.10"][2], {"gateway": "pending", "fw": "stale"})


class PointsTest(Base):
    """집행 지점별 결과 (이슈 #51). 관문의 세 열 · 감사는 그대로고 enforcement 에 지점마다 state · since · mode · note 가 붙는다."""

    def points(self, ip):
        return self.row(ip)["enforcement"]

    def test_관문만_설정하면_내부_방화벽은_설정_없음이다(self):
        # 내부 방화벽은 늘 요청된다(이슈 #77). OPSLOOP_FW_ID 가 없으면 확인할 곳이 없어 stale '설정 없음'이다 (G7)
        self.settle()
        pts = self.points("198.51.100.7")
        self.assertEqual(list(pts), ["gateway", "fw"])
        self.assertEqual(pts["gateway"], {"state": "confirmed", "since": be.iso(T0 + timedelta(seconds=30)),
                                          "mode": "nft", "note": None})
        self.assertEqual(pts["fw"], {"state": "stale", "since": be.iso(T0), "mode": None, "note": "내부 방화벽 설정 없음"})
        # 확인이 이어져도 다시 쓰지 않는다
        w = self.store.writes
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.assertEqual(self.store.writes, w)

    def test_첫_회차는_대기로_적고_since_는_그때다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        self.assertEqual(self.points("198.51.100.7"), {
            "gateway": {"state": "pending", "since": be.iso(T0), "mode": None, "note": None},
            "fw": {"state": "stale", "since": be.iso(T0), "mode": None, "note": "내부 방화벽 설정 없음"}})
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])       # 관문 열은 아직 비어 있다

    def test_내부_방화벽까지_확인되면_두_지점이_confirmed(self):
        self.cfg["fw"] = FW
        fw = Gateway(self.s3, key=FW_STATUS)
        self.store.add("203.0.113.10")
        self.run_once()
        self.gw.sync(self.store.now + timedelta(seconds=20))
        fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        self.assertEqual(self.run_once(), 0)
        self.confirmed("203.0.113.10", T0 + timedelta(seconds=20))       # 관문 열은 관문 보고로만
        pts = self.points("203.0.113.10")
        self.assertEqual(pts["gateway"]["state"], "confirmed")
        self.assertEqual(pts["fw"], {"state": "confirmed", "since": be.iso(T0 + timedelta(seconds=40)), "mode": "nft",
                                     "note": None})
        self.assertEqual(self.store.audit, [("enforced", "203.0.113.10")])     # 내부 방화벽 확인은 감사를 만들지 않는다
        w = self.store.writes
        self.gw.sync(self.store.now + timedelta(seconds=20))
        fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        self.run_once()
        self.assertEqual(self.store.writes, w)
        self.assertTrue(any("내부 방화벽 nft" in m for _, m in self.logs))

    def test_내부_방화벽_보고가_없으면_대기_뒤_5분에_stale(self):
        self.cfg["fw"] = FW
        self.store.add("203.0.113.10")
        self.run_once()
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.assertEqual(self.run_once(), 1)                             # 못 한 일(내부 방화벽 보고 읽기)이 있다
        self.confirmed("203.0.113.10", T0 + timedelta(seconds=30))
        self.assertEqual(self.points("203.0.113.10")["fw"]["state"], "pending")
        for _ in range(5):
            self.gw.sync(self.store.now + timedelta(seconds=30))
            self.tick()
            self.run_once()
        fwp = self.points("203.0.113.10")["fw"]
        self.assertEqual(fwp["state"], "stale")
        self.assertEqual(fwp["note"], "내부 방화벽 상태를 읽지 못함 (없음 (내부 방화벽 동기화가 아직 쓰지 않았다))")
        self.confirmed("203.0.113.10", T0 + timedelta(seconds=30))       # 관문 확인은 그대로
        self.assertTrue(any("내부 방화벽 불일치" in m for _, m in self.logs))
        # stale 이 이어져도 since · 쓰기는 그대로
        w, since = self.store.writes, fwp["since"]
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.assertEqual((self.store.writes, self.points("203.0.113.10")["fw"]["since"]), (w, since))

    def test_내부_방화벽이_거부하면_failed_에_까닭이_붙는다(self):
        self.cfg["fw"] = FW
        fw = Gateway(self.s3, key=FW_STATUS)
        self.store.add("203.0.113.10")
        self.run_once()
        self.gw.sync(self.store.now + timedelta(seconds=20))
        fw.sync(self.store.now + timedelta(seconds=40), rejected=[("203.0.113.10", "nft 반영 실패")],
                errors=["nft 반영 실패 1건"])
        self.tick()
        self.run_once()
        self.confirmed("203.0.113.10", T0 + timedelta(seconds=20))
        self.assertEqual(self.points("203.0.113.10")["fw"], {"state": "failed", "since": be.iso(T0 + MIN), "mode": "nft",
                                                              "note": "nft 반영 실패"})
        self.assertEqual(self.row("203.0.113.10")["note"], "관문 반영 · " + self.s3.listed()["digest"][:8] + " · "
                         + be.iso(T0 + timedelta(seconds=20)))

    def test_해제되면_지점별_결과를_비운다(self):
        self.cfg["fw"] = FW
        fw = Gateway(self.s3, key=FW_STATUS)
        self.store.add("203.0.113.10")
        self.run_once()
        self.gw.sync(self.store.now + timedelta(seconds=20))
        fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        self.run_once()
        self.row("203.0.113.10")["released_at"] = self.store.now
        self.tick()
        self.run_once()
        # 요청 지점마다 빠짐 확인 전(removing)을 거친다 (이슈 #77)
        self.assertEqual({p: v["state"] for p, v in self.points("203.0.113.10").items()},
                         {"gateway": "removing", "fw": "removing"})
        self.assertNotIn("203.0.113.10", self.st["points"]["fw"])
        self.gw.sync(self.store.now + timedelta(seconds=20))
        fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        self.run_once()
        self.assertIsNone(self.points("203.0.113.10"))

    def test_보고를_한_회차_못_읽어도_지점별_결과는_그대로다(self):
        self.settle()
        before, w = dict(self.points("198.51.100.7")), self.store.writes
        del self.s3.objects[STATUS]                      # 관문 보고를 한 회차 못 읽는다
        self.tick()
        self.run_once()
        self.assertEqual((self.points("198.51.100.7"), self.store.writes), (before, w))
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.assertEqual((self.points("198.51.100.7"), self.store.writes), (before, w))

    def test_목록을_못_읽은_보고_한_회차도_보류다(self):
        self.settle()
        before, w = dict(self.points("198.51.100.7")), self.store.writes
        self.gw.put({"v": 1, "at": be.iso(self.store.now + timedelta(seconds=30)), "mode": "nft", "list_digest": None,
                     "list_generated_at": None, "applied": 0, "set_count": 1, "rejected": [],
                     "errors": ["목록을 읽지 못함 (SlowDown)"], "selftest": None})
        self.tick()
        self.run_once()
        self.assertEqual((self.points("198.51.100.7"), self.store.writes), (before, w))

    def test_상태_파일을_잃어도_지점별_확인_시각을_이어받는다(self):
        self.cfg["fw"] = FW
        fw = Gateway(self.s3, key=FW_STATUS)
        self.store.add("203.0.113.10")
        self.run_once()
        for _ in range(3):
            self.gw.sync(self.store.now + timedelta(seconds=20))
            fw.sync(self.store.now + timedelta(seconds=40))
            self.tick()
            self.run_once()
        before, w = dict(self.points("203.0.113.10")), self.store.writes
        self.assertEqual(before["gateway"]["since"], be.iso(self.row("203.0.113.10")["enforced_at"]))
        self.st = be.new_state()                         # 상태 파일을 잃었다
        self.gw.sync(self.store.now + timedelta(seconds=20))
        fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        self.run_once()
        self.assertEqual((self.points("203.0.113.10"), self.store.writes), (before, w))

    def test_처음_배포하면_관문_확인_시각은_enforced_at_과_같다(self):
        self.settle()
        for _ in range(2):
            self.gw.sync(self.store.now + timedelta(seconds=30))
            self.tick()
            self.run_once()
        self.st["points"] = {}                           # #47 판 상태 파일 (points 없음)
        self.row("198.51.100.7")["enforcement"] = None   # 옛 DB (열 비어 있음)
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.assertEqual(self.points("198.51.100.7")["gateway"]["since"], be.iso(T0 + timedelta(seconds=30)))

    def test_관문_확인_전에_해제된_행의_지점별_결과도_비운다(self):
        self.cfg["fw"] = FW
        fw = Gateway(self.s3, key=FW_STATUS)
        self.store.add("203.0.113.10")
        self.run_once()
        fw.sync(self.store.now + timedelta(seconds=20))  # 내부 방화벽만 확인, 관문 보고는 없다
        self.tick()
        self.run_once()
        self.assertIsNone(self.row("203.0.113.10")["enforced_at"])
        self.assertEqual(self.points("203.0.113.10")["fw"]["state"], "confirmed")
        self.row("203.0.113.10")["released_at"] = self.store.now
        self.tick()
        self.run_once()
        # 요청 지점마다 removing 을 거쳐, 그 지점이 뺀 목록을 적용했다고 보고한 뒤 비운다 (이슈 #77)
        fw.sync(self.store.now + timedelta(seconds=20))
        self.tick()
        self.run_once()
        self.assertEqual(self.points("203.0.113.10"), {"gateway": {"state": "removing", "since": be.iso(T0 + 2 * MIN),
                                                                    "mode": None, "note": None}})
        self.gw.sync(self.store.now + timedelta(seconds=20))
        self.tick()
        self.run_once()
        self.assertIsNone(self.points("203.0.113.10"))

    def test_내부_방화벽을_뺐다_다시_넣으면_새로_센다(self):
        self.cfg["fw"] = FW
        fw = Gateway(self.s3, key=FW_STATUS)
        self.store.add("203.0.113.10")
        self.run_once()
        self.gw.sync(self.store.now + timedelta(seconds=20))
        fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        self.run_once()
        old_since = self.points("203.0.113.10")["fw"]["since"]
        self.cfg["fw"] = None
        for _ in range(10):                              # 10분 동안 관문만 본다 (내부 방화벽 보고는 그대로 멈춰 있다)
            self.gw.sync(self.store.now + timedelta(seconds=20))
            self.tick()
            self.run_once()
        self.assertEqual(self.points("203.0.113.10")["fw"]["note"], "내부 방화벽 설정 없음")     # 이슈 #77 (G7)
        self.assertIsNone(self.st["fw_status_fail_since"])
        self.cfg["fw"] = FW
        self.gw.sync(self.store.now + timedelta(seconds=20))
        self.tick()
        self.run_once()
        fwp = self.points("203.0.113.10")["fw"]
        self.assertEqual(fwp["state"], "stale")          # 멈춘 옛 보고를 확인으로 이어 쓰지 않는다
        self.assertNotEqual(fwp["since"], old_since)

    def test_내부_방화벽_문구는_관문이라_적지_않는다(self):
        got, why = be.validate_status({"v": 1, "at": be.iso(self.store.now + timedelta(minutes=10)), "mode": "nft",
                                       "applied": 0}, self.store.now, "내부 방화벽")
        self.assertEqual((got, why), (None, "내부 방화벽 시각이 앞섬"))

    def test_설정의_내부_방화벽_ID(self):
        with mock.patch.dict(os.environ, {"OPSLOOP_ENFORCER_DEFAULTS": "/nonexistent", "OPSLOOP_BUCKET": "b",
                                          "OPSLOOP_FW_ID": " fw-opsloop "}):
            self.assertEqual(be.settings()["fw"], "fw-opsloop")
        with mock.patch.dict(os.environ, {"OPSLOOP_ENFORCER_DEFAULTS": "/nonexistent", "OPSLOOP_BUCKET": "b",
                                          "OPSLOOP_FW_ID": ""}):
            self.assertIsNone(be.settings()["fw"])
        for bad in ("i-0ffeb29efad03546d", "fw-", "fw-Opsloop", "fw-" + "a" * 41):
            with mock.patch.dict(os.environ, {"OPSLOOP_ENFORCER_DEFAULTS": "/nonexistent", "OPSLOOP_BUCKET": "b",
                                              "OPSLOOP_FW_ID": bad}):
                with self.assertRaises(be.ConfigError):
                    be.settings()
        self.assertEqual(be.STATUS_KEY.format(gw="fw-opsloop"), "hb/v1/host=fw-opsloop-block/latest.json")


# ── 차단 적용 지점 선택 (이슈 #77) ─────────────────────────────────────────────

# P 판(#77 직전 main) 집행기의 validate_status · list_doc 사본. 되돌린 옛 집행기와 주고받는 두 객체를 대조한다
_pspec = importlib.util.spec_from_file_location("block_enforcer_p", os.path.join(HERE, "testdata", "block_enforcer_p.py"))
be_p = importlib.util.module_from_spec(_pspec)
_pspec.loader.exec_module(be_p)

FW_ONLY = ("fw",)
BOTH = ["198.51.100.7", "203.0.113.10"]


class ChoiceBase(Base):
    """내부 방화벽을 설정하고 #77 판 내부 방화벽 동기화(points.fw 적용 · list 보고)를 둔다. 관문은 반영하지 않으므로 옛 판(entries)이다."""

    def setUp(self):
        super().setUp()
        self.cfg["fw"] = FW
        self.fw = Gateway(self.s3, key=FW_STATUS, point="fw")

    def gw_ips(self):
        return [e["ip"] for e in self.s3.listed()["entries"]]

    def fw_ips(self):
        return [e["ip"] for e in self.s3.listed()["points"]["fw"]["entries"]]

    def step(self, gw=True, fw=True):
        """두 동기화가 지금 S3 목록을 적용하고(관문 +20초 · 내부 방화벽 +40초) 1분 뒤 한 회차."""
        if gw:
            self.gw.sync(self.store.now + timedelta(seconds=20))
        if fw:
            self.fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        return self.run_once()

    def per_point(self):
        """첫 회차는 내부 방화벽 보고 전이라 전체다. 내부 방화벽이 list fw 로 보고한 뒤 회차부터 지점별이다."""
        self.run_once()
        self.assertFalse(self.st["fw_list_ok"])
        self.step()
        self.assertTrue(self.st["fw_list_ok"])

    def pts(self, ip):
        return self.row(ip)["enforcement"]

    def states(self, ip):
        e = self.pts(ip)
        return None if e is None else {p: v["state"] for p, v in e.items()}

    def fw_report(self, **kw):
        d = {"v": 1, "at": be.iso(self.store.now + timedelta(seconds=40)), "mode": "nft", "list": None, "list_digest": None,
             "list_generated_at": None, "applied": 0, "set_count": 2, "rejected": [], "errors": ["목록을 읽지 못함 (SlowDown)"],
             "selftest": None}
        d.update(kw)
        self.fw.put(d)


class NoChangeTest(ChoiceBase):
    """반영 단계의 무변화 (계약 5장 ② · ③). 모든 행이 두 지점이면 entries · digest 가 #77 전과 같고, 옛 상태 파일의 첫 회차에 고칠 행이 없다."""

    def test_모든_행이_두_지점이면_목록이_77_전과_같다(self):
        self.store.add("198.51.100.7")
        self.store.add("203.0.113.9", expires=timedelta(hours=2))
        self.store.add("9.9.9.9", points=None)                     # 열이 없는 DB (NULL) 도 두 지점
        self.run_once()
        doc = self.s3.listed()
        old = be_p.list_doc(doc["entries"], T0)                    # P 판 list_doc
        self.assertEqual({k: doc[k] for k in old}, old)
        self.assertEqual(doc["digest"], doc["points"]["fw"]["digest"])
        self.assertEqual(doc["points"]["fw"]["entries"], doc["entries"])

    def test_옛_상태_파일_첫_회차는_고칠_행이_없고_points_가_든_목록을_바로_올린다(self):
        old_fw = Gateway(self.s3, key=FW_STATUS)                   # 옛 판 내부 방화벽 동기화 (entries 적용 · list 없음)
        for ip in ("198.51.100.7", "203.0.113.10", "203.0.113.11"):
            self.store.add(ip)
        self.run_once()
        for _ in range(3):
            self.gw.sync(self.store.now + timedelta(seconds=20))
            old_fw.sync(self.store.now + timedelta(seconds=40))
            self.tick()
            self.run_once()
        # 옛 집행기(#51 판)의 상태 파일 · S3 목록으로 바꾼다: #77 키가 없고 published 에 fw_digest 가 없다
        for k in ("fw_book", "fw_list_ok", "fw_list_seq"):
            del self.st[k]
        for k in ("fw_digest", "fw_count"):
            del self.st["published"][k]
        old = be_p.list_doc(self.s3.listed()["entries"], be.parse_ts(self.st["published"]["generated_at"]))
        self.s3.objects[be.LIST_KEY] = json.dumps(old).encode("utf-8")
        with tempfile.TemporaryDirectory() as d:
            be.save_state(os.path.join(d, "state.json"), self.st)
            self.st = be.load_state(os.path.join(d, "state.json"))
        self.gw.sync(self.store.now + timedelta(seconds=20))
        old_fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        writes, audit, puts = self.store.writes, list(self.store.audit), len(self.s3.puts)
        kept = copy.deepcopy(self.st)
        self.run_once(dry_run=True)                                # 반영 ② 의 dry-run
        self.assertTrue(any("고칠 행 0 · 만료 기록 0" in m for _, m in self.logs))
        self.st = kept
        self.assertEqual(self.run_once(), 0)
        self.assertEqual((self.store.writes, self.store.audit), (writes, audit))
        self.assertEqual(len(self.s3.puts), puts + 1)             # points 가 든 문서를 바로 올린다 (10분을 기다리지 않는다)
        doc = self.s3.listed()
        self.assertEqual((doc["digest"], doc["points"]["fw"]["digest"]), (old["digest"], old["digest"]))
        self.assertFalse(self.st["fw_list_ok"])                    # 옛 판 내부 방화벽 보고라 전체
        # ③ 내부 방화벽 동기화를 #77 판으로: 지점별 모드가 돼도 entries 는 그대로다 (제한 행이 없다)
        for _ in range(3):
            self.step()
        self.assertTrue(self.st["fw_list_ok"])
        self.assertEqual(self.s3.listed()["digest"], old["digest"])
        self.assertEqual((self.store.writes, self.store.audit), (writes, audit))


class ListModeTest(ChoiceBase):
    """관문 목록 모드 (계약 2.1). 내부 방화벽 보고를 목록보다 먼저 읽어 같은 회차 목록에 반영한다.
    list fw 면 지점별, list 가 없거나 legacy 면 그 회차부터 전체, 못 읽었거나 null 이면 직전 회차(fw_list_seq)의 모드만 잇는다."""

    def setUp(self):
        super().setUp()
        self.store.add("198.51.100.7")                             # 두 지점
        self.store.add("203.0.113.10", points=FW_ONLY)             # 내부 방화벽 전용

    def test_list_mode_표(self):
        # (OPSLOOP_FW_ID, 직전 모드, 모드를 정한 회차가 직전 회차인가, 이번 보고의 list('못 읽음' 은 보고 없음), 기대)
        cases = [(None, True, True, "fw", False), (FW, False, True, "fw", True), (FW, False, False, "fw", True),
                 (FW, True, True, "legacy", False), (FW, True, True, "gateway", False),
                 (FW, True, True, None, True), (FW, True, True, "못 읽음", True), (FW, False, True, None, False),
                 (FW, True, False, None, False), (FW, True, False, "못 읽음", False)]
        for fw_id, before, fresh, lst, want in cases:
            st = be.new_state()
            st.update(seq=10, fw_list_ok=before, fw_list_seq=9 if fresh else 7)
            got = be.list_mode(st, {"fw": fw_id}, None if lst == "못 읽음" else {"list": lst})
            self.assertEqual((got, st["fw_list_ok"], st["fw_list_seq"]), (want, want, 10), (fw_id, before, fresh, lst))

    def test_OPSLOOP_FW_ID_가_없으면_전체고_관문이_적용해도_관문_열은_쓰지_않는다(self):
        self.cfg["fw"] = None
        self.run_once()
        for _ in range(3):
            self.step(fw=False)
        self.assertEqual((self.gw_ips(), self.fw_ips()), (BOTH, BOTH))
        self.assertFalse(self.st["fw_list_ok"])
        r = self.row("203.0.113.10")
        self.assertEqual((r["enforced_at"], r["method"], r["note"]), (None, None, None))
        self.assertEqual(self.pts("203.0.113.10"), {"fw": {"state": "stale", "since": be.iso(T0), "mode": None,
                                                           "note": "내부 방화벽 설정 없음"}})
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=20))

    def test_내부_방화벽_보고가_없으면_전체다(self):
        self.run_once()
        for _ in range(3):
            self.step(fw=False)
        self.assertEqual(self.gw_ips(), BOTH)
        self.assertFalse(self.st["fw_list_ok"])

    def test_list_fw_보고를_읽은_회차에_올리는_목록부터_지점별이다(self):
        self.run_once()
        self.assertEqual(self.gw_ips(), BOTH)
        self.fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        puts = len(self.s3.puts)
        self.run_once()
        self.assertEqual(len(self.s3.puts), puts + 1)             # 다음 회차로 미루지 않는다
        self.assertEqual((self.gw_ips(), self.fw_ips()), (["198.51.100.7"], BOTH))
        self.assertEqual((self.st["fw_list_ok"], self.st["fw_list_seq"]), (True, self.st["seq"]))
        self.assertIn((4, "관문 목록 모드: 전체 · 내부 방화벽 확인 전 → 지점별 (내부 방화벽 보고 list fw)"), self.logs)

    def test_list_없는_옛_보고를_읽은_회차의_목록이_곧_전체다(self):
        self.per_point()
        self.assertEqual(self.gw_ips(), ["198.51.100.7"])
        self.fw = Gateway(self.s3, key=FW_STATUS)                  # 옛 판 내부 방화벽 동기화로 되돌렸다
        self.assertNotIn("203.0.113.10", self.fw.sync(self.store.now + timedelta(seconds=40)))   # 옛 판 첫 회차에 빠진다
        self.tick()
        self.run_once()
        self.assertEqual(self.gw_ips(), BOTH)                      # 그 보고를 읽은 회차에 바로 전체
        self.assertEqual((self.st["fw_list_ok"], self.st["fw_list_seq"]), (False, self.st["seq"]))
        self.assertIn((4, "관문 목록 모드: 지점별 → 전체 · 내부 방화벽 확인 전 (내부 방화벽 보고 list legacy)"), self.logs)
        self.assertIn("203.0.113.10", self.fw.sync(self.store.now + timedelta(seconds=40)))      # 옛 판 다음 회차에 다시 든다

    def test_list_legacy_보고도_전체다(self):
        self.per_point()
        self.fw_report(list="legacy", list_digest=self.s3.listed()["digest"], applied=1, set_count=1, errors=[])
        self.tick()
        self.run_once()
        self.assertEqual(self.gw_ips(), BOTH)
        self.assertFalse(self.st["fw_list_ok"])

    def test_모르는_list_보고도_전체다(self):
        # 보고를 버리면 직전 모드(지점별)가 이어져 그 동기화가 entries 를 적용할 때 내부 방화벽 전용 행이 빠진다 (계약 12장 2번)
        self.per_point()
        self.fw_report(list="fw2", list_digest=self.s3.listed()["digest"], applied=1, set_count=1, errors=[])
        self.tick()
        self.run_once()
        self.assertEqual((self.gw_ips(), self.st["fw_list_ok"]), (BOTH, False))
        self.assertIn((4, "관문 목록 모드: 지점별 → 전체 · 내부 방화벽 확인 전 (내부 방화벽 보고 list legacy)"), self.logs)

    def test_list_null_이나_못_읽은_보고는_직전_회차의_모드를_잇는다(self):
        self.per_point()
        self.fw_report()                                           # 목록을 못 읽은 회차 (list null)
        self.tick()
        self.run_once()
        self.assertEqual((self.gw_ips(), self.st["fw_list_ok"], self.st["fw_list_seq"]),
                         (["198.51.100.7"], True, self.st["seq"]))
        del self.s3.objects[FW_STATUS]                             # 보고를 못 읽는다
        for _ in range(2):
            self.tick()
            self.assertEqual(self.run_once(), 1)
            self.assertEqual((self.gw_ips(), self.st["fw_list_ok"], self.st["fw_list_seq"]),
                             (["198.51.100.7"], True, self.st["seq"]))

    def cut(self):
        """fw_list_ok=True 인데 fw_list_seq 가 직전 회차가 아닌 상태 (옛 집행기가 세 회차 돈 뒤 다시 올렸다)."""
        self.per_point()
        self.st["seq"] += 3
        with tempfile.TemporaryDirectory() as d:
            be.save_state(os.path.join(d, "state.json"), self.st)
            st = be.load_state(os.path.join(d, "state.json"))
        self.assertEqual((st["fw_list_ok"], st["fw_list_seq"]), (False, self.st["seq"]))
        self.assertTrue(self.st["fw_list_ok"])

    def test_끊긴_상태_파일에서_보고를_못_읽으면_첫_회차는_전체다(self):
        self.cut()
        del self.s3.objects[FW_STATUS]
        self.tick()
        self.run_once()                                            # 상태 파일을 거치지 않아도 cycle 이 맞춘다
        self.assertEqual(self.gw_ips(), BOTH)
        self.assertFalse(self.st["fw_list_ok"])
        self.assertTrue(any(lv == 4 and "끊긴 상태 파일" in m for lv, m in self.logs))

    def test_끊긴_상태_파일에서_list_null_이면_첫_회차는_전체다(self):
        self.cut()
        self.fw_report()
        self.tick()
        self.run_once()
        self.assertEqual(self.gw_ips(), BOTH)
        self.assertFalse(self.st["fw_list_ok"])

    def test_상태_파일이_없으면_보고가_null_일_때_전체다(self):
        self.fw_report()
        self.run_once()
        self.assertEqual(self.gw_ips(), BOTH)
        self.fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        self.run_once()
        self.assertEqual(self.gw_ips(), ["198.51.100.7"])


class FwOnlyTest(ChoiceBase):
    """내부 방화벽 전용 행 ('{fw}')."""

    def setUp(self):
        super().setUp()
        self.store.add("198.51.100.7")
        self.store.add("203.0.113.10", points=FW_ONLY)

    def test_지점별_모드의_전용_행은_관문_목록에_없고_관문_열_쪽지_갈래가_없다(self):
        self.per_point()
        self.assertEqual((self.gw_ips(), self.fw_ips()), (["198.51.100.7"], BOTH))
        for _ in range(10):                                        # 관문 보고 10분
            self.step()
        r = self.row("203.0.113.10")
        self.assertEqual((r["enforced_at"], r["method"], r["note"]), (None, None, None))
        self.assertEqual(self.pts("203.0.113.10"), {"fw": {"state": "confirmed", "since": be.iso(T0 + timedelta(seconds=40)),
                                                           "mode": "nft", "note": None}})
        self.confirmed("198.51.100.7", T0 + timedelta(seconds=20))
        self.assertEqual(self.states("198.51.100.7"), {"gateway": "confirmed", "fw": "confirmed"})
        self.assertEqual(self.store.audit, [("enforced", "198.51.100.7")])
        self.assertFalse(any("불일치" in m for _, m in self.logs))

    def test_옛_판_내부_방화벽_보고면_5분_지난_전용_행은_옛_판_stale_이고_그_회차에_전체로_돌린다(self):
        self.per_point()
        for _ in range(3):
            self.step()
        self.store.add("203.0.113.11", points=FW_ONLY)             # 옛 판으로 가기 2분 전에 든 전용 행
        for _ in range(2):
            self.step()
        self.assertEqual(self.states("203.0.113.11"), {"fw": "confirmed"})
        self.fw = Gateway(self.s3, key=FW_STATUS)                  # 옛 판 내부 방화벽 동기화 (지점별 entries 를 적용)
        self.step(gw=False)
        self.assertEqual(self.gw_ips(), ["198.51.100.7", "203.0.113.10", "203.0.113.11"])   # 같은 회차에 전체
        self.assertEqual(self.pts("203.0.113.10")["fw"]["state"], "stale")
        self.assertEqual(self.pts("203.0.113.10")["fw"]["note"], "내부 방화벽 동기화 옛 판")
        self.assertEqual(self.pts("203.0.113.11")["fw"]["state"], "pending")      # 든 지 5분이 안 됐다
        self.assertTrue(any(lv == 4 and "내부 방화벽이 관문 목록을 적용했다" in m for lv, m in self.logs))
        self.step(gw=False)                                        # 옛 판이 전체 entries 를 적용했다
        self.assertEqual(self.states("203.0.113.10"), {"fw": "confirmed"})
        self.assertEqual(self.states("203.0.113.11"), {"fw": "confirmed"})
        self.assertIsNone(self.row("203.0.113.10")["enforced_at"])

    def test_셈_대조는_보고를_찾은_장부의_목록_수다(self):
        self.store.add("198.51.100.8")
        self.per_point()                                           # 관문 목록 2개 · 내부 방화벽 목록 3개
        self.logs.clear()
        self.gw.sync(self.store.now + timedelta(seconds=20))       # 관문은 2개를 적용 (관문 목록 수와 대조)
        self.fw.sync(self.store.now + timedelta(seconds=40), applied=2)     # 3개 목록인데 2개만 적용했다고 한다
        self.tick()
        self.run_once()
        self.assertIn((5, "내부 방화벽 확인 보류: 적용 수 부족 (2/3)"), self.logs)
        self.assertFalse(any(m.startswith("관문 ") and "적용 수 부족" in m for _, m in self.logs))
        self.logs.clear()
        # 관문 목록(entries 2개)을 적용한 보고는 기존 장부에서 찾고 그 목록 수(2)와 댄다 (list null 이라 모드는 그대로)
        self.fw_report(list_digest=self.s3.listed()["digest"], applied=1, set_count=1, errors=[])
        self.tick()
        self.run_once()
        self.assertIn((5, "내부 방화벽 확인 보류: 적용 수 부족 (1/2)"), self.logs)
        self.assertTrue(any("내부 방화벽이 관문 목록을 적용했다" in m for _, m in self.logs))

    def test_관문을_더해_넓히면_관문은_대기에서_확인으로_가고_내부_방화벽_확인은_그대로다(self):
        self.per_point()
        self.step()
        fw_before = self.pts("203.0.113.10")["fw"]
        self.assertEqual(fw_before["state"], "confirmed")
        self.row("203.0.113.10")["points"] = ["gateway", "fw"]    # 콘솔이 관문을 더했다
        self.tick()
        self.run_once()
        self.assertIn("203.0.113.10", self.gw_ips())
        self.assertEqual(self.pts("203.0.113.10"), {"gateway": {"state": "pending", "since": be.iso(self.store.now),
                                                                "mode": "nft", "note": None}, "fw": fw_before})
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.confirmed("203.0.113.10", at)
        self.assertEqual(self.pts("203.0.113.10"), {"gateway": {"state": "confirmed", "since": be.iso(at), "mode": "nft",
                                                                "note": None}, "fw": fw_before})

    def test_points_가_없거나_틀리면_두_지점이다(self):
        for p in (None, [], ["gateway"], ["fw", "fw"], ["gateway", "fw", "x"], ["x"], "fw", [1], {"fw": 1}):
            self.assertEqual(be.requested({"points": p}), ("gateway", "fw"), p)
        self.assertEqual(be.requested({}), ("gateway", "fw"))
        self.assertEqual(be.requested({"points": ["fw"]}), ("fw",))
        self.assertEqual(be.requested({"points": ["fw", "gateway"]}), ("gateway", "fw"))
        self.store.add("198.51.100.9", points=None)
        self.per_point()
        self.assertEqual(self.gw_ips(), ["198.51.100.7", "198.51.100.9"])
        self.assertEqual(set(self.pts("198.51.100.9")), {"gateway", "fw"})

    def test_옛_집행기가_채운_관문_세_열은_관문_목록_밖이_되고_관문이_뺀_뒤_비운다(self):
        self.row("203.0.113.10").update(enforced_at=T0 - MIN, method="nft", note="관문 반영 · 0123abcd · 2026-09-27T07:59:00Z")
        self.run_once()                                            # 전체 모드: 관문 목록에 있어 그대로 둔다
        self.gw.sync(self.store.now + timedelta(seconds=20))
        self.fw.sync(self.store.now + timedelta(seconds=40))
        self.tick()
        self.run_once()                                            # 지점별: 관문 목록에서 빠진다. 관문은 아직 옛 목록
        r = self.row("203.0.113.10")
        self.assertEqual((r["enforced_at"], r["method"]), (T0 - MIN, "nft"))
        self.step()                                                # 관문이 빠진 목록을 오류 없이 적용했다
        r = self.row("203.0.113.10")
        self.assertEqual((r["enforced_at"], r["method"], r["note"]), (None, None, None))
        self.assertEqual(self.store.audit.count(("unenforced", "203.0.113.10")), 1)
        self.assertEqual(self.states("203.0.113.10"), {"fw": "confirmed"})


class RemovingTest(ChoiceBase):
    """해제 · 만료 · 제외로 목록에서 빠진 행의 지점별 removing (이슈 #77)."""

    def setUp(self):
        super().setUp()
        self.store.add("198.51.100.7")
        self.store.add("203.0.113.10", points=FW_ONLY)
        self.per_point()
        self.step()

    def test_요청_지점마다_removing_이고_지점마다_따로_지운다(self):
        for ip in BOTH:
            self.row(ip)["released_at"] = self.store.now
        self.tick()
        self.run_once()
        gone = {"state": "removing", "since": be.iso(self.store.now), "mode": "nft", "note": None}
        self.assertEqual(self.pts("198.51.100.7"), {"gateway": gone, "fw": gone})
        self.assertEqual(self.pts("203.0.113.10"), {"fw": gone})
        self.step(fw=False)                                        # 관문이 먼저 뺐다
        self.assertEqual(self.pts("198.51.100.7"), {"fw": gone})
        self.assertEqual(self.pts("203.0.113.10"), {"fw": gone})
        self.assertIsNone(self.row("198.51.100.7")["enforced_at"])
        self.fw.sync(self.store.now + timedelta(seconds=40), errors=["목록 밖 원소 1개를 빼지 못함"])
        self.tick()
        self.run_once()                                            # 오류가 있는 보고로는 지우지 않는다
        self.assertEqual(self.pts("203.0.113.10"), {"fw": gone})
        self.step(gw=False)
        self.assertIsNone(self.pts("198.51.100.7"))
        self.assertIsNone(self.pts("203.0.113.10"))
        self.assertEqual(self.store.audit, [("enforced", "198.51.100.7"), ("unenforced", "198.51.100.7")])

    def test_만료되면_보고가_없어도_만료_24시간_뒤에_지운다(self):
        self.row("203.0.113.10")["expires_at"] = self.store.now + MIN
        self.tick(2 * MIN)
        self.run_once()
        self.assertEqual(self.states("203.0.113.10"), {"fw": "removing"})
        self.assertEqual(self.store.expired_calls, [("203.0.113.10", self.row("203.0.113.10")["expires_at"])])
        self.tick(DAY - 2 * MIN)                                   # 보고가 멈췄다. 만료 뒤 23시간 59분
        self.run_once()
        self.assertEqual(self.states("203.0.113.10"), {"fw": "removing"})
        self.tick(2 * MIN)
        self.run_once()
        self.assertIsNone(self.pts("203.0.113.10"))
        self.assertEqual([k for k, _ in self.store.expired_calls].count("203.0.113.10"), 1)

    def test_빠짐_확인_전에_다시_건_행은_removing_을_잇지_않는다(self):
        self.row("203.0.113.10")["released_at"] = self.store.now
        self.tick()
        self.run_once()
        self.assertEqual(self.states("203.0.113.10"), {"fw": "removing"})
        self.row("203.0.113.10").update(released_at=None, expires_at=self.store.now + DAY)    # 콘솔이 다시 걸었다
        self.tick()
        self.run_once()
        self.assertEqual(self.states("203.0.113.10"), {"fw": "pending"})
        self.step()
        self.assertEqual(self.states("203.0.113.10"), {"fw": "confirmed"})

    def test_OPSLOOP_FW_ID_를_빼면_내부_방화벽_갈래는_확인할_곳이_없어_바로_지운다(self):
        self.row("198.51.100.7")["released_at"] = self.store.now
        self.cfg["fw"] = None
        self.tick()
        self.run_once()
        self.assertEqual(self.states("198.51.100.7"), {"gateway": "removing"})


class NarrowTest(ChoiceBase):
    """관리자 관문 빼기 (이슈 #77 결정 14). 콘솔은 한 트랜잭션에서 풀고 '{fw}' 로 다시 건다. 관문 세 열 · enforcement 는 그대로 둔다
    (BLOCK_SQL 의 충돌 갱신에 그 열이 없다). 관문 칸은 관문이 실제로 뺐다고 확인될 때까지 빠짐 확인 전이고, unenforced 감사는 그 뒤에 남는다."""

    IP = "203.0.113.10"

    def setUp(self):
        super().setUp()
        self.store.add("198.51.100.7")
        self.store.add(self.IP)
        self.per_point()
        self.step()
        self.at = self.row(self.IP)["enforced_at"]
        self.fw_before = self.pts(self.IP)["fw"]
        self.assertEqual(self.states(self.IP), {"gateway": "confirmed", "fw": "confirmed"})

    def narrow(self):
        self.row(self.IP)["points"] = ["fw"]

    def cols(self):
        r = self.row(self.IP)
        return r["enforced_at"], r["method"]

    def test_관문이_뺀_회차_전에는_빠짐_확인_전이고_깨끗한_보고_뒤에_지우고_unenforced_를_남긴다(self):
        self.narrow()
        self.tick()
        self.run_once()                                            # 지점별: 이 회차 목록부터 관문 목록에서 빠진다
        self.assertNotIn(self.IP, self.gw_ips())
        since = be.iso(self.store.now)
        self.assertEqual(self.pts(self.IP), {"gateway": {"state": "removing", "since": since, "mode": "nft", "note": None},
                                             "fw": self.fw_before})
        self.assertEqual(self.cols(), (self.at, "nft"))
        rows = self.store.fetch()["rows"]
        be.classify_rows(rows, self.store.now, True)
        self.assertEqual(be.point_counts(rows), {"gateway": (1, 1, 0, 1), "fw": (2, 2, 0, 0)})
        self.step(gw=False)                                        # 관문은 아직 옛 목록 (빠지기 전)
        self.assertEqual(self.pts(self.IP)["gateway"], {"state": "removing", "since": since, "mode": "nft", "note": None})
        self.gw.sync(self.store.now + timedelta(seconds=20), errors=["목록 밖 원소 1개를 빼지 못함"])
        self.tick()
        self.run_once()                                            # 오류가 있는 보고로는 지우지 않는다
        self.assertEqual(self.states(self.IP), {"gateway": "removing", "fw": "confirmed"})
        self.assertEqual(self.cols(), (self.at, "nft"))
        self.assertNotIn(("unenforced", self.IP), self.store.audit)
        self.step()                                                # 관문이 이 행이 빠진 목록을 오류 없이 적용했다
        self.assertEqual(self.pts(self.IP), {"fw": self.fw_before})
        r = self.row(self.IP)
        self.assertEqual((r["enforced_at"], r["method"], r["note"]), (None, None, None))
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)
        self.step()
        self.assertEqual(self.pts(self.IP), {"fw": self.fw_before})
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)

    def test_전체_모드면_관문_목록에_남아_계속_빠짐_확인_전이다(self):
        self.fw = Gateway(self.s3, key=FW_STATUS)                  # 옛 판 내부 방화벽 동기화 (list 없음 → 전체 모드)
        self.step()
        self.assertFalse(self.st["fw_list_ok"])
        self.narrow()
        for _ in range(3):
            self.step()
        self.assertIn(self.IP, self.gw_ips())
        self.assertEqual(self.states(self.IP), {"gateway": "removing", "fw": "confirmed"})
        self.assertEqual(self.cols(), (self.at, "nft"))
        self.assertNotIn(("unenforced", self.IP), self.store.audit)
        self.fw = Gateway(self.s3, key=FW_STATUS, point="fw")      # 새 판으로 돌아오면 지점별 → 관문 목록에서 빠진다
        self.step()
        self.assertNotIn(self.IP, self.gw_ips())
        self.assertEqual(self.states(self.IP), {"gateway": "removing", "fw": "confirmed"})
        self.step()
        self.assertEqual(self.states(self.IP), {"fw": "confirmed"})
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)

    def test_관문_보고가_끊겨도_만료_24시간_뒤에_지운다(self):
        self.narrow()
        self.tick()
        self.run_once()
        self.row(self.IP)["expires_at"] = self.store.now + MIN
        self.tick(2 * MIN)
        self.run_once()                                            # 만료: 두 지점 모두 빠짐 확인 전 (보고가 멈췄다)
        self.assertEqual(self.states(self.IP), {"gateway": "removing", "fw": "removing"})
        self.tick(DAY - 2 * MIN)
        self.run_once()
        self.assertEqual(self.states(self.IP), {"gateway": "removing", "fw": "removing"})
        self.assertEqual(self.cols(), (self.at, "nft"))
        self.tick(2 * MIN)
        self.run_once()
        self.assertIsNone(self.pts(self.IP))
        self.assertIsNone(self.row(self.IP)["enforced_at"])
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)

    def test_관문이_뺀_뒤_확인_전에_다시_요청하면_removing_을_잇지_않고_남은_세_열을_비운다(self):
        self.narrow()
        self.tick()
        self.run_once()
        self.assertEqual(self.states(self.IP)["gateway"], "removing")
        self.gw.sync(self.store.now + timedelta(seconds=20))       # 관문이 뺐다 (집행기는 그 보고를 아직 보지 않았다)
        self.row(self.IP)["points"] = ["gateway", "fw"]           # 콘솔이 관문을 다시 더했다 (넓히기)
        self.tick()
        self.run_once()
        self.assertIn(self.IP, self.gw_ips())
        self.assertEqual(self.pts(self.IP), {"gateway": {"state": "pending", "since": be.iso(self.store.now), "mode": "nft",
                                                         "note": None}, "fw": self.fw_before})
        r = self.row(self.IP)
        self.assertEqual((r["enforced_at"], r["method"], r["note"]), (None, None, None))
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)
        at = self.store.now + timedelta(seconds=20)
        self.step()                                                # 관문이 다시 적용했다 → 새 시각으로 확인
        self.confirmed(self.IP, at)
        self.assertEqual(self.states(self.IP), {"gateway": "confirmed", "fw": "confirmed"})
        self.assertEqual(self.store.audit.count(("enforced", self.IP)), 2)

    def test_관문이_빼기_전에_다시_요청하면_removing_을_잇지_않고_관문_확인을_잇는다(self):
        self.narrow()
        self.tick()
        self.run_once()
        self.assertEqual(self.states(self.IP)["gateway"], "removing")
        self.row(self.IP)["points"] = ["gateway", "fw"]           # 관문은 아직 이 주소가 든 목록(같은 digest)을 적용 중이다
        self.tick()
        self.run_once()
        self.assertEqual(self.states(self.IP), {"gateway": "confirmed", "fw": "confirmed"})
        self.assertEqual(self.cols(), (self.at, "nft"))
        self.assertEqual(self.pts(self.IP)["gateway"]["since"], be.iso(self.at))
        self.assertEqual(self.store.audit.count(("enforced", self.IP)), 1)
        self.assertNotIn(("unenforced", self.IP), self.store.audit)

    def test_목록이_바뀐_채_관문이_빼기_전에_다시_요청하면_세_열을_두고_확인을_잇는다(self):
        self.narrow()
        self.tick()
        self.run_once()                                            # 관문 목록에서 빠진다. 관문은 아직 빠지기 전 목록이다
        self.assertEqual(self.states(self.IP)["gateway"], "removing")
        self.store.add("198.51.100.8")                             # 다른 행이 바뀌어 다시 든 목록의 digest 가 처음과 다르다
        self.row(self.IP)["points"] = ["gateway", "fw"]
        self.tick()
        self.run_once()
        self.assertIn(self.IP, self.gw_ips())
        self.assertEqual(self.states(self.IP), {"gateway": "pending", "fw": "confirmed"})
        self.assertEqual(self.cols(), (self.at, "nft"))            # 관문은 이 주소가 든 목록을 적용 중이라 세 열을 둔다
        self.assertNotIn(("unenforced", self.IP), self.store.audit)
        self.step()                                                # 관문이 다시 든 목록을 적용했다 → 옛 확인을 잇는다
        self.assertEqual(self.states(self.IP), {"gateway": "confirmed", "fw": "confirmed"})
        self.assertEqual(self.cols(), (self.at, "nft"))
        self.assertEqual(self.pts(self.IP)["gateway"]["since"], be.iso(self.at))
        self.assertEqual(self.store.audit.count(("enforced", self.IP)), 1)
        self.assertNotIn(("unenforced", self.IP), self.store.audit)

    def test_다시_요청한_뒤에야_관문이_빠진_목록을_오류_없이_적용했다고_보고하면_그때_세_열을_비운다(self):
        self.narrow()
        self.tick()
        self.run_once()
        d1 = self.s3.listed()["digest"]                            # 이 주소가 빠진 관문 목록
        self.store.add("198.51.100.8")
        self.row(self.IP)["points"] = ["gateway", "fw"]
        self.tick()
        self.run_once()                                            # 관문은 아직 빠지기 전 목록 → 세 열을 둔다
        self.assertEqual(self.cols(), (self.at, "nft"))
        self.gw.sync(self.store.now + timedelta(seconds=20), digest=d1, errors=["목록 밖 원소 1개를 빼지 못함"])
        self.tick()
        self.run_once()                                            # 빠진 목록이지만 오류가 있는 보고로는 비우지 않는다
        self.assertEqual(self.cols(), (self.at, "nft"))
        self.assertNotIn(("unenforced", self.IP), self.store.audit)
        self.gw.sync(self.store.now + timedelta(seconds=20), digest=d1)
        self.tick()
        self.run_once()                                            # 관문이 뺐다 → 옛 확인을 비운다
        r = self.row(self.IP)
        self.assertEqual((r["enforced_at"], r["method"], r["note"]), (None, None, None))
        self.assertEqual(self.states(self.IP), {"gateway": "pending", "fw": "confirmed"})
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)
        at = self.store.now + timedelta(seconds=20)
        self.step()                                                # 관문이 다시 적용했다 → 새 시각으로 확인
        self.confirmed(self.IP, at)
        self.assertEqual(self.store.audit.count(("enforced", self.IP)), 2)
        self.step()
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)

    def test_전체_모드에서_다시_요청하면_남은_확인을_잇는다(self):
        self.fw = Gateway(self.s3, key=FW_STATUS)
        self.step()
        self.narrow()
        self.step()
        self.assertEqual(self.states(self.IP)["gateway"], "removing")
        self.row(self.IP)["points"] = ["gateway", "fw"]           # 관문 목록에서 빠진 적이 없다
        self.step()
        self.assertEqual(self.states(self.IP), {"gateway": "confirmed", "fw": "confirmed"})
        self.assertEqual(self.cols(), (self.at, "nft"))
        self.assertEqual(self.store.audit.count(("enforced", self.IP)), 1)
        self.assertNotIn(("unenforced", self.IP), self.store.audit)

    def test_남은_기록은_state_가_글자인_결과_기록이나_관문_확인_시각이다(self):
        # 콘솔 block_points.held_sql · 화면 heldPoint 와 같은 정의다 (state 가 글자가 아니면 기록으로 보지 않는다)
        for enforcement, enforced_at, want in [
                ({"gateway": {"state": "removing"}}, None, True), ({"gateway": {"state": ""}}, None, True),
                ({"gateway": {"state": 1}}, None, False), ({"gateway": {"state": None}}, None, False),
                ({"gateway": "removing"}, None, False), ({"gateway": ["removing"]}, None, False), (None, None, False),
                (None, T0, True), ({"gateway": {"state": 1}}, T0, True)]:
            with self.subTest(enforcement=enforcement, enforced_at=enforced_at):
                self.assertIs(be.held_at({"enforcement": enforcement, "enforced_at": enforced_at}, "gateway"), want)
        self.assertIs(be.held_at({"enforcement": {"fw": {"state": 1}}, "enforced_at": T0}, "fw"), False)


class RearmTest(ChoiceBase):
    """해제 · 만료된 두 지점 행을 관문 없이({fw}) 다시 걸기 (이슈 #77, 2026-10-01 결정). 콘솔 · triage · 흡수 후속 차단은 관문 세 열 ·
    지점 결과를 두고(충돌 갱신에 그 열이 없다), 집행기가 관문이 이 주소가 빠진 목록을 오류 없이 적용했다고 확인한 뒤에만 세 열을
    비우고 unenforced 를 한 번 남긴다. 세 경로의 실제 문장 · DB 는 RearmPgTest 가 본다."""

    IP = "203.0.113.10"

    def setUp(self):
        super().setUp()
        self.store.add("198.51.100.7")
        self.store.add(self.IP)
        self.per_point()
        self.step()
        self.old = self.s3.objects[STATUS]                         # 이 주소가 든 목록의 관문 보고 (다시 걸기 전 회차)
        self.row(self.IP)["released_at"] = self.store.now          # 해제
        self.tick()
        self.run_once()                                            # 목록에서 빠진다. 관문은 아직 옛 목록이다
        self.assertEqual(self.states(self.IP), {"gateway": "removing", "fw": "removing"})
        self.kept = self.cols()
        self.assertEqual(self.kept[1], "nft")

    def rearm(self, expires=DAY):
        """콘솔 · triage · 흡수 후속 차단의 다시 걸기(관문 없이). 세 열 · 지점 결과는 그대로다."""
        self.row(self.IP).update(released_at=None, expires_at=self.store.now + expires, points=["fw"])

    def cols(self):
        r = self.row(self.IP)
        return r["enforced_at"], r["method"], r["note"]

    def held(self, why):
        with self.subTest(why=why):
            self.assertEqual((self.cols(), self.states(self.IP)["gateway"]), (self.kept, "removing"))
            self.assertNotIn(("unenforced", self.IP), self.store.audit)

    def test_관문이_뺐다고_확인한_뒤에만_세_열을_비우고_unenforced_는_한_번이다(self):
        self.rearm()
        self.s3.objects[STATUS] = self.old
        self.tick()
        self.run_once()
        self.held("① 다시 걸기 전 회차의 보고")
        self.gw.sync(self.store.now + timedelta(seconds=20), errors=["목록 밖 원소 1개를 빼지 못함"])
        self.tick()
        self.run_once()
        self.held("③ 오류가 있는 보고")
        del self.s3.objects[STATUS]
        self.tick()
        self.run_once()
        self.held("③ 보고 없음")
        self.step()                                                # 관문이 이 주소가 빠진 목록을 오류 없이 적용했다
        self.assertEqual(self.cols(), (None, None, None))
        self.assertEqual(self.states(self.IP), {"fw": "confirmed"})
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)
        for _ in range(3):
            self.step()                                            # ② 같은 확인이 이어져도 한 번이다
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)

    def test_전체_모드라_관문_목록에_다시_들면_깨끗한_보고여도_세_열을_둔다(self):
        self.fw = Gateway(self.s3, key=FW_STATUS)                  # 옛 판 내부 방화벽 동기화 (list 없음 → 전체 모드)
        self.fw.sync(self.store.now + timedelta(seconds=40))
        self.rearm()
        self.tick()
        self.run_once()
        self.assertIn(self.IP, self.gw_ips())
        for _ in range(3):
            self.step()                                            # 관문은 이 주소가 든 목록을 오류 없이 적용 중이다
        self.held("③ 전체 모드")
        self.fw = Gateway(self.s3, key=FW_STATUS, point="fw")      # 새 판으로 돌아오면 지점별 → 관문 목록에서 빠진다
        self.step()
        self.assertNotIn(self.IP, self.gw_ips())
        self.held("관문은 아직 빠지기 전 목록")
        self.step()
        self.assertEqual(self.cols(), (None, None, None))
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)

    def test_전체_모드로_다시_들기_전에_관문이_뺐으면_그때_한_번_비우고_다시_넣은_것은_적지_않는다(self):
        self.gw.sync(self.store.now + timedelta(seconds=20))       # 관문이 이 주소가 빠진 목록을 오류 없이 적용했다 (집행기는 아직 모른다)
        self.fw = Gateway(self.s3, key=FW_STATUS)                  # 옛 판 내부 방화벽 동기화 (list 없음 → 전체 모드)
        self.fw.sync(self.store.now + timedelta(seconds=40))
        self.rearm()
        self.tick()
        self.run_once()                                            # 전체 모드라 관문 목록에 다시 든다. 관문이 그 전에 뺀 것을 본다
        self.assertIn(self.IP, self.gw_ips())
        self.assertEqual((self.cols(), self.states(self.IP)["gateway"]), ((None, None, None), "removing"))
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)
        for _ in range(3):
            self.step()                                            # 관문이 다시 넣었다 (관문 미요청이라 적지 않고 빠짐 확인 전을 잇는다)
        self.assertEqual((self.cols(), self.states(self.IP)["gateway"]), ((None, None, None), "removing"))
        self.fw = Gateway(self.s3, key=FW_STATUS, point="fw")      # 새 판으로 돌아오면 지점별 → 관문 목록에서 빠진다
        self.step()
        self.assertNotIn(self.IP, self.gw_ips())
        self.step()
        self.assertEqual(self.states(self.IP), {"fw": "confirmed"})
        self.assertEqual([a for a in self.store.audit if a[1] == self.IP], [("enforced", self.IP), ("unenforced", self.IP)])

    def test_관문_보고가_끊기면_관문이_마지막으로_받은_만료_24시간_뒤에_비운다(self):
        until = self.row(self.IP)["expires_at"]                    # 관문 목록에서 빠질 때의 until (다시 걸기 전 만료)
        self.rearm(7 * DAY)                                        # 새 만료는 훨씬 뒤다
        self.gw.sync(self.store.now + timedelta(seconds=20), errors=["목록 밖 원소 1개를 빼지 못함"])
        self.tick()
        self.run_once()
        self.held("③ 오류가 있는 보고")
        self.store.now = until + DAY - MIN                         # 관문 보고는 그 뒤 멈췄다
        self.run_once()
        self.assertNotIn(self.IP, self.gw_ips())
        self.held("③ 관문이 마지막으로 받은 만료 + 24시간 전")
        self.tick(2 * MIN)
        self.run_once()                                            # 관문 원소는 어느 방식이든 빠졌다 (새 만료 + 24시간을 기다리지 않는다)
        self.assertEqual(self.cols(), (None, None, None))
        self.assertNotIn("gateway", self.pts(self.IP))
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)
        self.tick()
        self.run_once()
        self.assertEqual(self.store.audit.count(("unenforced", self.IP)), 1)

    def test_관문이_이미_뺀_행을_다시_걸면_남은_쪽지_방식만_비우고_감사는_없다(self):
        self.step()                                                # 관문이 해제 행을 뺐다 (unenforced why=released)
        r = self.row(self.IP)
        self.assertEqual((r["enforced_at"], r["method"], self.pts(self.IP)), (None, "nft", None))   # 쪽지 · 방식은 기록으로 남는다
        audit = list(self.store.audit)
        self.rearm()
        self.tick()
        self.run_once()
        self.assertEqual(self.cols(), (None, None, None))
        self.assertEqual(list(self.pts(self.IP)), ["fw"])          # 관문 칸은 미요청
        self.assertEqual(self.store.audit, audit)


class RearmGatewayTest(ChoiceBase):
    """해제 · 만료된 두 지점 행을 관문을 포함해({gateway,fw}) 다시 걸기 (이슈 #77, 2026-10-01 결정 2). 콘솔 · triage · 흡수는 관문 세 열 ·
    지점 결과를 요청 시각에 비우지 않는다. 집행기가 판단한다: 관문이 이 주소가 빠진 목록을 오류 없이 적용했다고 확인했으면 unenforced 를
    한 번 남기고 새로 확인하고, 아니면(관문 차단이 이어짐) unenforced 없이 다시 든 목록을 올린 뒤의 보고로만 확인해 쪽지 끝에
    '기존 차단 유지' 를 붙인다. 그 전에는 관문 결과가 대기라 종합 상태도 대기다. 세 경로의 실제 문장 · DB 는 RearmPgTest."""

    IP = "203.0.113.10"

    def setUp(self):
        super().setUp()
        self.store.add("198.51.100.7")
        self.store.add(self.IP)
        self.per_point()
        self.step()
        self.at = self.row(self.IP)["enforced_at"]
        self.old = self.s3.objects[STATUS]                         # 이 주소가 든 목록의 관문 보고 (해제 전 회차)

    def kill(self):
        self.row(self.IP)["released_at"] = self.store.now          # 사람이 풀었다 (만료도 목록에서 빠지는 것은 같다)

    def rearm(self, points=("gateway", "fw"), expires=DAY):
        """콘솔 · triage · 흡수의 다시 걸기. 새 만료 · 요청 지점만 바뀌고 관문 세 열 · 지점 결과는 그대로다."""
        self.row(self.IP).update(released_at=None, expires_at=self.store.now + expires, created_at=self.store.now,
                                 points=list(points))

    def removing(self):
        """해제하고 한 회차: 목록에서 빠지고 두 지점 모두 빠짐 확인 전이다. 관문은 아직 빠지기 전 목록이다."""
        self.kill()
        self.tick()
        self.run_once()
        self.assertEqual(self.states(self.IP), {"gateway": "removing", "fw": "removing"})

    def cols(self):
        r = self.row(self.IP)
        return r["enforced_at"], r["method"], r["note"]

    def audit(self):
        return [a[0] for a in self.store.audit if a[1] == self.IP]

    def waiting(self):
        """종합 상태가 대기인가(block_points.STATE_CASE · format.ts blockState 의 대기 규칙, 두 지점 행)."""
        r, s = self.row(self.IP), self.states(self.IP) or {}
        return r["enforced_at"] is None or s.get("gateway") in ("pending", "removing") or s.get("fw") != "confirmed"

    def held(self, why, kept, state="pending"):
        with self.subTest(why=why):
            self.assertEqual((self.cols(), self.states(self.IP)["gateway"]), (kept, state))
            self.assertTrue(self.waiting())
            self.assertEqual(self.audit(), ["enforced"])

    def kept_confirmed(self, at):
        """다시 든 목록의 새 보고로 기존 차단 유지를 확인했다. 감사는 처음 확인 뒤 한 줄뿐이고 이어져도 늘지 않는다."""
        self.confirmed(self.IP, at, kept=True)
        self.assertEqual(self.states(self.IP), {"gateway": "confirmed", "fw": "confirmed"})
        self.assertFalse(self.waiting())
        self.assertEqual(self.audit(), ["enforced", "enforced"])
        for _ in range(3):
            self.step()
        self.assertEqual(self.audit(), ["enforced", "enforced"])

    def test_관문_유지_재차단은_unenforced_없이_새_보고로만_확인한다(self):
        self.removing()                                            # removing 진행 중
        kept = self.cols()
        self.rearm()
        self.assertEqual(self.cols(), kept)                        # 요청 시각: 세 열 그대로 · 남은 빠짐 확인 전이라 대기
        self.assertTrue(self.waiting())
        self.s3.objects[STATUS] = self.old                         # 다시 걸기 전 회차의 보고 (이 주소 · 옛 만료)
        self.tick()
        self.run_once()
        self.held("다시 걸기 전 회차의 보고", kept)
        self.tick()
        self.run_once()
        self.held("같은 옛 보고 한 회차 더", kept)
        del self.s3.objects[STATUS]
        self.tick()
        self.run_once()
        self.held("보고 없음", kept)
        self.gw.sync(self.store.now + timedelta(seconds=20), applied=0)
        self.tick()
        self.run_once()
        self.held("셈이 맞지 않는 보고", kept)
        self.gw.sync(self.store.now + timedelta(seconds=20), rejected=[(self.IP, "형식 틀림")])
        self.tick()
        self.run_once()                                            # 관문이 거부: 불일치 쪽지 · 실패, 세 열의 확인 시각은 그대로
        self.assertEqual((self.row(self.IP)["enforced_at"], self.states(self.IP)["gateway"]), (self.at, "failed"))
        self.assertTrue(self.row(self.IP)["note"].startswith("관문 불일치 · 관문 거부"))
        self.assertEqual(self.audit(), ["enforced"])
        at = self.store.now + timedelta(seconds=20)
        self.step()                                                # 거부를 거쳤으니 기존 차단 유지가 아니라 새로 확인한다
        self.confirmed(self.IP, at)
        self.assertEqual(self.audit(), ["enforced", "enforced"])

    def test_관문_유지_재차단은_새_보고로_기존_차단_유지를_적는다(self):
        self.removing()
        self.rearm()
        self.tick()
        self.run_once()                                            # 관문 보고는 해제 직전 목록(빠진 목록을 적용한 적 없다)
        self.held("다시 든 목록을 올린 회차", (self.at, "nft", self.row(self.IP)["note"]))
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.kept_confirmed(at)

    def test_관문이_빼기_직전_회차의_목록을_적용_중에_다시_걸어도_유지다(self):
        self.gw.sync(self.store.now + timedelta(seconds=10))       # 관문이 해제 직전 회차 목록(이 주소 있음)을 막 적용했다
        self.removing()
        self.rearm()
        self.tick()
        self.run_once()
        self.held("빠지기 직전 회차의 보고", (self.at, "nft", self.row(self.IP)["note"]))
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.kept_confirmed(at)

    def test_같은_만료로_다시_걸어도_다시_걸기_전의_보고로는_확인하지_않는다(self):
        # 흡수 후속 차단이 같은 약속 만료로 다시 걸면 다시 든 목록이 해제 전과 같은 내용 · digest 다. 옛 보고도 그 목록 회차를
        # 적용한 것으로 보이지만 다시 든 목록을 올리기 전의 보고라 확인하지 않는다
        self.removing()
        kept = self.cols()
        self.row(self.IP).update(released_at=None)
        self.s3.objects[STATUS] = self.old
        self.tick()
        self.run_once()
        self.assertEqual(self.s3.listed()["digest"], json.loads(self.old)["list_digest"])
        self.held("같은 digest 의 옛 보고", kept)
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.kept_confirmed(at)

    def test_관문이_빠진_목록을_적용한_직후_다시_걸면_unenforced_한_번_뒤_새로_확인한다(self):
        self.removing()
        self.gw.sync(self.store.now + timedelta(seconds=20))       # 관문이 뺐다 (집행기는 아직 모른다)
        self.rearm()
        self.assertEqual(self.cols()[0], self.at)                  # 요청 시각에는 그대로
        self.tick()
        self.run_once()                                            # 다시 든 목록을 올리고 관문이 그 전에 뺀 것을 본다
        self.assertEqual((self.cols(), self.states(self.IP)["gateway"]), ((None, None, None), "pending"))
        self.assertTrue(self.waiting())
        self.assertEqual(self.audit(), ["enforced", "unenforced"])
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.confirmed(self.IP, at)                                # 새 적용 (기존 차단 유지가 아니다)
        self.assertEqual(self.audit(), ["enforced", "unenforced", "enforced"])
        for _ in range(3):
            self.step()
        self.assertEqual(self.audit(), ["enforced", "unenforced", "enforced"])

    def test_관문이_빠진_목록을_오류와_함께_적용했으면_뺐다고_보지_않는다(self):
        self.removing()
        self.gw.sync(self.store.now + timedelta(seconds=20), errors=["목록 밖 원소 1개를 빼지 못함"])
        self.rearm()
        self.tick()
        self.run_once()
        self.held("오류가 있는 빠진 목록 보고", (self.at, "nft", self.row(self.IP)["note"]))
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.kept_confirmed(at)

    def test_관문이_뺐다고_확인한_뒤_다시_걸면_남은_방식_쪽지만_감사_없이_비우고_새로_확인한다(self):
        self.removing()
        self.step()                                                # 관문이 뺐다 → unenforced(why=released), 방식 · 쪽지는 남는다
        r = self.row(self.IP)
        self.assertEqual((r["enforced_at"], r["method"], self.pts(self.IP)), (None, "nft", None))
        self.rearm()
        self.tick()
        self.run_once()
        self.assertEqual(self.cols(), (None, None, None))
        self.assertTrue(self.waiting())
        self.assertEqual(self.audit(), ["enforced", "unenforced"])
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.confirmed(self.IP, at)
        self.assertEqual(self.audit(), ["enforced", "unenforced", "enforced"])

    def test_집행기_회차_없이_풀고_다시_걸면_옛_확인을_새_만료로_옮기지_않는다(self):
        kept = self.cols()
        self.kill()
        self.rearm()                                               # 같은 회차 안에 풀고 다시 걸었다 (집행기는 해제를 보지 못했다)
        del self.s3.objects[STATUS]                                # 판정할 수 없는 회차여도
        self.tick()
        self.run_once()
        self.held("판정할 수 없는 회차", kept)
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.kept_confirmed(at)

    def test_관문_없이_다시_건_행을_빠짐_확인_전에_풀고_관문을_포함해_다시_걸면_유지다(self):
        self.removing()
        self.rearm(points=["fw"])
        self.tick()
        self.run_once()                                            # 지점별: 관문 목록 밖, 관문 빠짐 확인 전
        self.assertNotIn(self.IP, self.gw_ips())
        self.assertEqual(self.states(self.IP)["gateway"], "removing")
        self.removing()                                            # 관문은 그동안 빠진 목록을 적용하지 않았다
        kept = self.cols()
        self.rearm()
        self.tick()
        self.run_once()
        self.held("관문을 포함해 다시 건 회차", kept)
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.kept_confirmed(at)

    def test_전체_모드에서_관문_없이_다시_건_행을_풀고_관문을_포함해_다시_걸면_유지다(self):
        self.removing()
        self.fw = Gateway(self.s3, key=FW_STATUS)                  # 옛 판 내부 방화벽 동기화 (list 없음 → 전체 모드)
        self.fw.sync(self.store.now + timedelta(seconds=40))
        self.rearm(points=["fw"])
        self.tick()
        self.run_once()                                            # 전체 모드라 관문 목록에 다시 든다 (관문 미요청 · 빠짐 확인 전)
        self.assertIn(self.IP, self.gw_ips())
        for _ in range(2):
            self.step()                                            # 관문이 이 주소가 든 목록을 적용한다
        self.assertEqual(self.states(self.IP)["gateway"], "removing")
        self.assertEqual(self.audit(), ["enforced"])
        self.removing_full()
        kept = self.cols()
        self.rearm()
        self.tick()
        self.run_once()
        self.assertFalse(self.st["fw_list_ok"])
        self.held("전체 모드에서 관문을 포함해 다시 건 회차", kept)
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.kept_confirmed(at)

    def test_상태_파일을_잃어도_기존_차단_유지_쪽지를_이어받는다(self):
        self.removing()
        self.rearm()
        self.tick()
        self.run_once()
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.confirmed(self.IP, at, kept=True)
        writes, audit = self.store.writes, list(self.store.audit)
        self.st = be.new_state()                                   # 상태 파일을 잃었다: DB 의 확인(표지 포함)을 그대로 이어받는다
        self.run_once()
        self.step()
        self.step()
        self.confirmed(self.IP, at, kept=True)
        self.assertEqual(self.store.audit, audit)
        self.assertEqual(self.store.writes - writes, 0)

    def regain(self, why):
        """같은 회차 안에 풀고 관문을 포함해 다시 건다. 내부 방화벽 목록에서는 빠진 적이 없어 두 목록에 같은 회차에 다시 든 행(rearmed)이
        아니지만, 다시 걸기 전의 확인을 이어받지 않고(outdated) 다시 든 목록의 새 보고로 기존 차단 유지를 적는다(검토 3차 V9)."""
        self.assertEqual(self.states(self.IP)["gateway"], "removing")
        kept = self.cols()
        self.kill()
        self.rearm()
        self.tick()
        self.run_once()
        self.assertFalse(be.rearmed(self.IP, self.st))
        self.held(why, kept)
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.kept_confirmed(at)

    def test_관문_없이_다시_건_행을_같은_회차에_풀고_관문을_포함해_다시_걸어도_새_보고로_유지다(self):
        self.removing()
        self.rearm(points=["fw"])
        self.tick()
        self.run_once()                                            # 관문 빠짐 확인 전 (관문은 빠진 목록을 적용하지 않았다)
        self.regain("관문 없이 다시 건 행을 관문을 포함해 다시 건 회차")

    def test_관리자_관문_빼기_뒤_같은_회차에_풀고_관문을_포함해_다시_걸어도_새_보고로_유지다(self):
        self.row(self.IP).update(points=["fw"], created_at=self.store.now)   # 관리자 관문 빼기 (풀고 {fw} 로 다시 건다 · 만료 그대로)
        self.tick()
        self.run_once()
        self.regain("관문 빼기 뒤 관문을 포함해 다시 건 회차")

    def lost(self, applied):
        """관문 유지 다시 걸기가 확인되기 전에 상태 파일을 잃었다(장부가 그 회차부터다). applied 면 관문이 다시 든 목록을 이미 적용했다.
        DB 에 남은 확인(다시 걸기 전)을 이어받지 않고 다시 든 목록의 보고로 기존 차단 유지를 적는다."""
        self.removing()
        kept = self.cols()
        self.rearm()
        self.tick()
        self.run_once()
        self.held("다시 든 목록을 올린 회차", kept)
        at = self.store.now + timedelta(seconds=20)
        if applied:
            self.gw.sync(at)
            self.fw.sync(at + timedelta(seconds=20))
        self.st = be.new_state()
        self.tick()
        self.run_once()
        if not applied:
            self.held("잃은 뒤 다시 걸기 전의 보고", kept)
            at = self.store.now + timedelta(seconds=20)
            self.step()
        self.kept_confirmed(at)

    def test_확인_전에_상태_파일을_잃어도_다시_걸기_전의_확인을_이어받지_않는다(self):
        self.lost(applied=False)

    def test_관문이_다시_든_목록을_적용한_뒤_상태_파일을_잃어도_다시_걸기_전의_확인을_이어받지_않는다(self):
        self.lost(applied=True)

    def test_옛_집행기가_이어받은_확인은_새_보고로_기존_차단_유지를_적는다(self):
        # 되돌린 동안 옛 집행기는 다시 건 행에 남은 확인을 새 만료로 이어받는다(요청 시각 기록 없음). 새 판으로 돌아오면 낡은 확인이다
        self.removing()
        kept = self.cols()
        self.rearm()
        self.tick()
        self.run_once()
        self.held("다시 든 목록을 올린 회차", kept)
        self.st["confirmed"][self.IP] = {"until": be.iso(self.row(self.IP)["expires_at"]), "at": be.iso(self.at),
                                         "d8": be.APPLIED_RE.fullmatch(kept[2]).group(1), "mode": "nft"}
        at = self.store.now + timedelta(seconds=20)
        self.step()
        self.kept_confirmed(at)

    def test_관문_목록이_그대로인_재요청은_남은_확인을_잇는다(self):
        # 살아 있는 차단을 같은 만료로 다시 요청했다(요청 시각만 바뀜). 관문이 새로 적용할 것이 없어 다시 확인하지 않는다
        self.row(self.IP)["created_at"] = self.store.now
        for _ in range(3):
            self.step()
        self.confirmed(self.IP, self.at)
        self.assertEqual(self.audit(), ["enforced"])

    def removing_full(self):
        """전체 모드에서 해제하고 한 회차 (내부 방화벽 결과 기록은 옛 판 보고라 그대로일 수 있다)."""
        self.kill()
        self.tick()
        self.run_once()
        self.assertEqual(self.states(self.IP)["gateway"], "removing")


class RearmPgTest(PgBase):
    """해제 · 만료된 두 지점 행 다시 걸기 (이슈 #77, 2026-10-01 결정 · 결정 2). 실제 schema.sql · 20261003 · 집행 역할에서 세 경로(콘솔
    main.BLOCK_SQL · triage record(OWN_BLOCK_SQL) · 흡수 후속 차단 AbsorbedFollower(BLOCK_ABSORBED_SQL))가 요청 시각에는 다시 걸기 기록만
    남기고 관문 세 열 · 지점 결과를 둔다.
      관문 없이({fw}): 집행기가 관문이 이 주소가 빠진 목록을 오류 없이 적용했다고 확인한 뒤에만 세 열을 비우고 unenforced 를 한 번
        남긴다(① 다시 걸기 전 회차의 보고 · ③ 오류 있는 보고 · 보고 없음 · 전체 모드로는 끝내지 않는다).
      관문을 포함해({gateway,fw}, 결정 2): 관문이 그 전에 뺐으면 unenforced 한 번 뒤 새로 확인하고, 관문 차단이 이어졌으면 unenforced
        없이 다시 든 목록의 새 보고로만 확인해 기존 차단 유지로 적는다. 기간 보고서(app/reports.py ENFORCE_SQL)는 기존 차단 유지를
        따로 세고 관문 반영 지연에서 뺀다. 관문 빠짐 확인 전 행(관문 없이 다시 건 행 · 관리자 관문 빼기 뒤)을 같은 회차 안에 풀고
        다시 걸거나 확인 전에 상태 파일을 잃어도 다시 걸기 전의 확인을 이어받지 않는다(regain)."""

    IP = "203.0.113.40"

    def setUp(self):
        super().setUp()
        self.cfg["fw"] = FW
        self.fw = Gateway(self.s3, key=FW_STATUS, point="fw")
        self.app = psycopg2.connect(with_db(URL, self.db))        # 콘솔 · triage 쪽 연결 (트랜잭션마다 행위자를 넘긴다)
        self.clock = None

    def tearDown(self):
        self.app.close()
        super().tearDown()

    def now(self):
        """동기화 보고 시각. 시험이 1초 안에 돌아도 보고마다 시각이 달라지게 3초씩 늘린다(지점 시계는 2분까지 앞서도 받는다)."""
        t = datetime.now(timezone.utc).replace(microsecond=0)
        self.clock = max(t, (self.clock or t) + timedelta(seconds=3))
        return self.clock

    def step(self, gw=True):
        if gw:
            self.gw.sync(self.now())
        self.fw.sync(self.now())
        self.cycle()

    def expire(self):
        self.sql("UPDATE blocklist SET expires_at = now() - interval '1 second' WHERE actor_ip = %s", (self.IP,))

    def cols(self):
        return self.sql("SELECT enforced_at, method, enforce_note FROM blocklist WHERE actor_ip = %s", (self.IP,))[0]

    def states(self):
        [(e,)] = self.sql("SELECT enforcement FROM blocklist WHERE actor_ip = %s", (self.IP,))
        return None if e is None else {p: v["state"] for p, v in e.items()}

    def unenforced(self):
        return [d for (d,) in self.sql("SELECT input FROM events WHERE sensor = 'audit'"
                                       " AND eventid = 'console.block.unenforced' AND input LIKE %s", (f"% ip={self.IP} %",))]

    def gw_ips(self):
        return [e["ip"] for e in self.s3.listed()["entries"]]

    def scenario(self, dead, rearm, event):
        self.sql("INSERT INTO blocklist (actor_ip, reason, requested_by, expires_at)"
                 " VALUES (%s, '시험', 'han', now() + interval '1 day')", (self.IP,))           # 두 지점(기본값)
        self.cycle()
        self.step()
        self.step()
        self.assertTrue(self.st["fw_list_ok"])
        self.assertEqual(self.states(), {"gateway": "confirmed", "fw": "confirmed"})
        kept = self.cols()
        self.assertEqual(kept[1], "nft")
        old = self.s3.objects[STATUS]                               # 이 주소가 든 목록의 관문 보고 (다시 걸기 전 회차)
        dead()
        self.cycle()                                                # 목록에서 빠진다. 관문은 아직 옛 목록이다
        self.assertEqual((self.cols(), self.states()), (kept, {"gateway": "removing", "fw": "removing"}))
        mark = len(self.audit())
        rearm()
        self.assertEqual(self.sql("SELECT points, released_at FROM blocklist WHERE actor_ip = %s", (self.IP,)),
                         [(["fw"], None)])
        # 요청 시각: 다시 걸기 기록만 남고 관문 세 열 · 지점 결과는 그대로다
        self.assertEqual((self.cols(), self.states()), (kept, {"gateway": "removing", "fw": "removing"}))
        self.assertIn(event, self.audit()[mark:])
        self.assertEqual(self.unenforced(), [])

        def held(why):
            with self.subTest(why=why):
                self.assertEqual((self.cols(), self.states()["gateway"]), (kept, "removing"))
                self.assertEqual(self.unenforced(), [])
        self.s3.objects[STATUS] = old
        self.step(gw=False)
        held("① 다시 걸기 전 회차의 보고")
        self.gw.sync(self.now(), errors=["목록 밖 원소 1개를 빼지 못함"])
        self.step(gw=False)
        held("③ 오류가 있는 보고")
        del self.s3.objects[STATUS]
        self.step(gw=False)
        held("③ 보고 없음")
        legacy = Gateway(self.s3, key=FW_STATUS)                    # 옛 판 내부 방화벽 동기화 (list 없음 → 전체 모드)
        legacy.sync(self.now())
        self.cycle()
        self.assertIn(self.IP, self.gw_ips())
        for _ in range(2):
            self.gw.sync(self.now())
            legacy.sync(self.now())
            self.cycle()
        held("③ 전체 모드라 관문 목록에 다시 듦")
        self.step()                                                 # 새 판 보고 → 지점별: 관문 목록에서 빠진다
        self.assertNotIn(self.IP, self.gw_ips())
        held("관문은 아직 빠지기 전 목록")
        self.step()                                                 # 관문이 이 주소가 빠진 목록을 오류 없이 적용했다
        self.assertEqual(self.cols(), (None, None, None))
        self.assertEqual(self.states(), {"fw": "confirmed"})
        [detail] = self.unenforced()
        self.assertTrue(detail.startswith("by=db:opsloop_enforcer ") and detail.endswith(" why=reset"), detail)
        for _ in range(3):
            self.step()                                             # ② 같은 확인이 이어져도 한 번이다
        self.assertEqual(len(self.unenforced()), 1)

    def test_콘솔_차단(self):
        sql = console_block_sql()

        def rearm():                                                # 관리자가 푼 행을 관문 없이 다시 건다
            q, args = positional(sql, self.IP, "console", None, "han", 24, ["fw"], False)
            with self.app, self.app.cursor() as c:
                c.execute("SELECT set_config('opsloop.actor', 'han', true)")
                c.execute(q, args)
        self.scenario(lambda: self.sql("UPDATE blocklist SET released_at = now(), released_by = 'boss' WHERE actor_ip = %s",
                                       (self.IP,)), rearm, "console.block.rearmed")

    def test_triage_판정(self):
        tr = load_file("triage_for_enforcer_test", TRIAGE_PY)
        key = f"R001|v3|{self.IP}|x"
        self.sql("INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip, first_ts, last_ts,"
                 " signal_count) VALUES (%s, 'R001', 'v3', '시험 규칙', 'high', %s, now(), now(), 1)", (key, self.IP))

        def rearm():                                                # R001 의 기본값은 내부 방화벽만이다
            self.assertIsNone(tr.record(self.app, key, self.IP, "threat", "근거", 1.0, "han", None, True))
        self.scenario(self.expire, rearm, "console.block.extended")

    def test_흡수_후속_차단(self):
        try:
            import asyncpg
        except ImportError:
            self.skipTest("asyncpg 가 없다 (후속 차단은 콘솔 연결로 돈다)")
        ab = load_file("absorbed_for_enforcer_test", os.path.join(APP_DIR, "absorbed.py"), near=APP_DIR)
        first = "R006|v3|192.0.2.1|x"
        self.sql("INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip, first_ts, last_ts,"
                 " signal_count) VALUES (%s, 'R006', 'v3', '시험 규칙', 'critical', '192.0.2.1', now(), now(), 1)", (first,))
        self.sql("INSERT INTO incident_absorbed (first_key, member_key, kind, rule_id, rule_version, actor_ip, first_ts,"
                 " last_ts, signal_count) VALUES (%s, 'm1', 'absorbed', 'R006', 'v3', %s, now(), now(), 1)", (first, self.IP))
        self.sql("INSERT INTO verdicts (incident_key, verdict, operator) VALUES (%s, 'threat', 'han')", (first,))

        async def follow():
            c = await asyncpg.connect(with_db(URL, self.db))
            try:
                return await ab.AbsorbedFollower(None).step(c)
            finally:
                await c.close()

        def rearm():                                                # 내부 방화벽만인 약속이 만료된 흡수 출발지를 다시 건다
            self.sql("INSERT INTO absorbed_blocks (first_key, expires_at, requested_by, points)"
                     " VALUES (%s, now() + interval '1 day', 'han', '{fw}')", (first,))
            self.assertEqual(asyncio.run(follow()), [(first, 1)])
        self.scenario(self.expire, rearm, "console.block.extended")

    # ── 관문을 포함해 다시 걸기 (결정 2) ────────────────────────────────────────────────────────────────────
    def state(self):
        """종합 상태(콘솔 block_points.STATE_CASE 그대로)."""
        bp = load_file("block_points_for_enforcer_state", os.path.join(APP_DIR, "block_points.py"))
        [(s,)] = self.sql("SELECT " + bp.STATE_CASE.replace("%", "%%") + " FROM blocklist WHERE actor_ip = %s", (self.IP,))
        return s

    def enforce_report(self, since):
        """기간 보고서의 관문 반영 지연 (created, enforced, maintained)(app/reports.py ENFORCE_SQL 그대로). 앱 의존(FastAPI)이 없으면 None."""
        if importlib.util.find_spec("fastapi") is None:
            return None
        rp = load_file("reports_for_enforcer_test", os.path.join(APP_DIR, "reports.py"), near=APP_DIR)
        q, args = positional(rp.ENFORCE_SQL, since, datetime.now(timezone.utc) + timedelta(minutes=1))
        [row] = self.sql(q, args)
        return row[:3]

    CASES = ("유지", "빼기 직전", "전체 모드", "뺀 뒤")

    def gw_scenario(self, dead, rearm, event, case):
        """case 가 '뺀 뒤' 면 관문이 이 주소가 빠진 목록을 오류 없이 적용한 뒤(집행기 확인 전) 다시 건다: 집행기가 다시 든 목록을 올리는
        회차에 unenforced 를 한 번 남기고 새로 확인한다(관문 반영 지연에 든다). 그 밖은 관문 차단이 이어진 채 다시 건다(unenforced 없음):
          유지      removing 진행 중(관문은 빠지기 전 목록). 다시 걸기 전 회차의 보고 · 보고 없음 · 셈이 맞지 않는 보고로는 확인하지 않는다
          빼기 직전 관문이 해제 직전 회차의 목록을 막 적용했다
          전체 모드 옛 판 내부 방화벽 보고(list 없음)라 관문 목록이 모든 행이다
        그때까지 관문 결과 · 종합 상태는 대기이고, 다시 든 목록의 새 보고로만 확인해 기존 차단 유지로 적는다(지연에서 뺀다). 확인이
        이어져도 감사는 늘지 않는다."""
        self.assertIn(case, self.CASES)
        removed = case == "뺀 뒤"
        start = self.sql("SELECT now()")[0][0]
        self.sql("INSERT INTO blocklist (actor_ip, reason, requested_by, expires_at)"
                 " VALUES (%s, '시험', 'han', now() + interval '2 days')", (self.IP,))          # 두 지점(기본값) · 다시 걸기와 다른 만료
        self.cycle()
        self.step()
        self.step()
        if case == "전체 모드":
            self.fw = Gateway(self.s3, key=FW_STATUS)               # 옛 판 내부 방화벽 동기화 (list 없음 → 전체 모드)
            self.step()
            self.assertFalse(self.st["fw_list_ok"])
        self.assertEqual((self.states(), self.state()), ({"gateway": "confirmed", "fw": "confirmed"}, "enforced"))
        kept = self.cols()
        old = self.s3.objects[STATUS]                               # 이 주소가 든 목록의 관문 보고 (다시 걸기 전 회차)
        if case == "빼기 직전":
            self.gw.sync(self.now())                                # 관문이 해제 직전 회차 목록(이 주소 있음)을 막 적용했다
        dead()
        self.cycle()                                                # 목록에서 빠진다. 관문은 아직 옛 목록이다
        self.assertEqual((self.cols(), self.states()), (kept, {"gateway": "removing", "fw": "removing"}))
        if removed:
            self.gw.sync(self.now())                                # 관문이 뺐다 (집행기는 아직 모른다)
        mark = len(self.audit())
        rearm()
        self.assertEqual(self.sql("SELECT points, released_at FROM blocklist WHERE actor_ip = %s", (self.IP,)),
                         [(["gateway", "fw"], None)])
        # 요청 시각: 다시 걸기 기록만 남고 관문 세 열 · 지점 결과는 그대로다. 남은 빠짐 확인 전이라 종합 상태는 대기다
        self.assertEqual((self.cols(), self.states(), self.state()), (kept, {"gateway": "removing", "fw": "removing"}, "pending"))
        self.assertIn(event, self.audit()[mark:])
        self.assertEqual(self.unenforced(), [])
        if removed:
            self.fw.sync(self.now())
            self.cycle()                                            # 다시 든 목록을 올리고 관문이 그 전에 뺀 것을 본다
            self.assertEqual((self.cols(), self.states()["gateway"], self.state()), ((None, None, None), "pending", "pending"))
            [detail] = self.unenforced()
            self.assertTrue(detail.startswith("by=db:opsloop_enforcer ") and detail.endswith(" why=reset"), detail)
        else:
            def held(why):
                with self.subTest(why=why):
                    self.assertEqual((self.cols(), self.states()["gateway"], self.state()), (kept, "pending", "pending"))
                    self.assertEqual(self.unenforced(), [])
            if case == "유지":
                self.s3.objects[STATUS] = old
                self.step(gw=False)
                held("다시 걸기 전 회차의 보고")
                del self.s3.objects[STATUS]
                self.step(gw=False)
                held("보고 없음")
                self.gw.sync(self.now(), applied=0)
                self.step(gw=False)
                held("셈이 맞지 않는 보고")
            else:
                self.step(gw=False)
                held("다시 든 목록을 올린 회차 · 관문은 빠지기 전 목록")
        self.step()                                                 # 관문이 다시 든 목록을 오류 없이 적용했다
        enforced_at, method, note = self.cols()
        self.assertEqual(method, "nft")
        self.assertGreater(enforced_at, kept[0])
        self.assertEqual(note.endswith(be.NOTE_KEPT), not removed, note)
        self.assertEqual((self.states(), self.state()), ({"gateway": "confirmed", "fw": "confirmed"}, "enforced"))
        marks = ("console.block.enforced", "console.block.unenforced")
        want = [marks[0]] + ([marks[1]] if removed else []) + [marks[0]]
        self.assertEqual([e for e in self.audit() if e in marks], want)
        for _ in range(3):
            self.step()                                             # 같은 확인이 이어져도 감사는 늘지 않는다
        self.assertEqual([e for e in self.audit() if e in marks], want)
        report = self.enforce_report(start)
        if report is not None:                                      # 새 요청 2(처음 · 다시 걸기), 기존 차단 유지는 지연에서 뺀다
            self.assertEqual(tuple(report), (2, 2, 0) if removed else (2, 1, 1))

    def console_rearm(self, points):
        def rearm():
            q, args = positional(console_block_sql(), self.IP, "console", None, "han", 24, points, False)
            with self.app, self.app.cursor() as c:
                c.execute("SELECT set_config('opsloop.actor', 'han', true)")
                c.execute(q, args)
        return rearm

    def release(self):
        self.sql("UPDATE blocklist SET released_at = now(), released_by = 'boss' WHERE actor_ip = %s", (self.IP,))

    def console_gw(self, case):
        self.gw_scenario(self.release, self.console_rearm(["gateway", "fw"]), "console.block.rearmed", case)

    def test_콘솔_차단_관문_포함_유지(self):
        self.console_gw("유지")

    def test_콘솔_차단_관문_포함_빼기_직전(self):
        self.console_gw("빼기 직전")

    def test_콘솔_차단_관문_포함_전체_모드(self):
        self.console_gw("전체 모드")

    def test_콘솔_차단_관문_포함_관문이_뺀_뒤(self):
        self.console_gw("뺀 뒤")

    def triage_rearm(self):
        tr = load_file("triage_for_enforcer_test", TRIAGE_PY)
        key = f"R004|v3|{self.IP}|x"
        self.sql("INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip, first_ts, last_ts,"
                 " signal_count) VALUES (%s, 'R004', 'v3', '시험 규칙', 'high', %s, now(), now(), 1)", (key, self.IP))

        def rearm():                                                # R004 의 기본값은 관문 + 내부 방화벽이다
            self.assertIsNone(tr.record(self.app, key, self.IP, "threat", "근거", 1.0, "han", None, True))
        return rearm

    def triage_gw(self, case):
        self.gw_scenario(self.expire, self.triage_rearm(), "console.block.extended", case)

    def test_triage_판정_관문_포함_유지(self):
        self.triage_gw("유지")

    def test_triage_판정_관문_포함_빼기_직전(self):
        self.triage_gw("빼기 직전")

    def test_triage_판정_관문_포함_전체_모드(self):
        self.triage_gw("전체 모드")

    def test_triage_판정_관문_포함_관문이_뺀_뒤(self):
        self.triage_gw("뺀 뒤")

    def follow_rearm(self):
        try:
            import asyncpg
        except ImportError:
            self.skipTest("asyncpg 가 없다 (후속 차단은 콘솔 연결로 돈다)")
        ab = load_file("absorbed_for_enforcer_test", os.path.join(APP_DIR, "absorbed.py"), near=APP_DIR)
        first = "R006|v3|192.0.2.1|x"
        self.sql("INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip, first_ts, last_ts,"
                 " signal_count) VALUES (%s, 'R006', 'v3', '시험 규칙', 'critical', '192.0.2.1', now(), now(), 1)", (first,))
        self.sql("INSERT INTO incident_absorbed (first_key, member_key, kind, rule_id, rule_version, actor_ip, first_ts,"
                 " last_ts, signal_count) VALUES (%s, 'm1', 'absorbed', 'R006', 'v3', %s, now(), now(), 1)", (first, self.IP))
        self.sql("INSERT INTO verdicts (incident_key, verdict, operator) VALUES (%s, 'threat', 'han')", (first,))

        async def follow():
            c = await asyncpg.connect(with_db(URL, self.db))
            try:
                return await ab.AbsorbedFollower(None).step(c)
            finally:
                await c.close()

        def rearm():                                                # 관문을 포함한 약속이 만료된 흡수 출발지를 다시 건다
            self.sql("INSERT INTO absorbed_blocks (first_key, expires_at, requested_by, points)"
                     " VALUES (%s, now() + interval '1 day', 'han', '{gateway,fw}')", (first,))
            self.assertEqual(asyncio.run(follow()), [(first, 1)])
        return rearm

    def follow_gw(self, case):
        self.gw_scenario(self.expire, self.follow_rearm(), "console.block.extended", case)

    def test_흡수_후속_차단_관문_포함_유지(self):
        self.follow_gw("유지")

    def test_흡수_후속_차단_관문_포함_빼기_직전(self):
        self.follow_gw("빼기 직전")

    def test_흡수_후속_차단_관문_포함_전체_모드(self):
        self.follow_gw("전체 모드")

    def test_흡수_후속_차단_관문_포함_관문이_뺀_뒤(self):
        self.follow_gw("뺀 뒤")

    # ── 관문 빠짐 확인 전 행을 풀고 관문을 포함해 다시 걸기 · 확인 전 상태 파일 분실 (검토 3차 V9 · 검토 4차) ─────────────────────
    def console_narrow(self):
        """관리자 관문 빼기(app/main.py add_action): 한 트랜잭션에서 풀고 '{fw}' 로 다시 건다(만료는 앞당기지 않는다)."""
        q, args = positional(console_block_sql(), self.IP, "console", None, "boss", 24, ["fw"], True)
        with self.app, self.app.cursor() as c:
            c.execute("SELECT set_config('opsloop.actor', 'boss', true)")
            c.execute(*positional(main_sql("RELEASE_FOR_NARROW_SQL"), self.IP, "boss"))
            c.execute(q, args)

    def regain(self, before, lost=None):
        """관문 차단이 이어진 채(관문은 이 주소가 빠진 목록을 적용한 적 없다) 콘솔이 관문을 포함해 다시 건다:
          fw       관문 없이 다시 건 행(관문 빠짐 확인 전)을 같은 회차 안에 풀고 다시 건다(검토 3차 V9)
          narrow   관리자 관문 빼기 뒤(관문 빠짐 확인 전) 같은 회차 안에 풀고 다시 건다
          released 풀고 한 회차 뒤(두 지점 빠짐 확인 전) 다시 건다
        lost 가 있으면 확인 전에 상태 파일을 잃는다('before' 관문이 다시 든 목록을 적용하기 전 · 'after' 적용한 뒤). 어느 경우든 다시 걸기
        전의 확인(T1)을 이어받지 않고 다시 든 목록의 새 보고로 기존 차단 유지를 적는다(감사 enforced 한 줄 · 보고서 maintained)."""
        start = self.sql("SELECT now()")[0][0]
        self.sql("INSERT INTO blocklist (actor_ip, reason, requested_by, expires_at)"
                 " VALUES (%s, '시험', 'han', now() + interval '2 days')", (self.IP,))          # 두 지점(기본값) · 다시 걸기와 다른 만료
        self.cycle()
        self.step()
        self.step()
        self.assertEqual((self.states(), self.state()), ({"gateway": "confirmed", "fw": "confirmed"}, "enforced"))
        kept = self.cols()
        for _ in range(50):                                         # 보고 시각(self.now)은 DB 시계보다 앞서 간다. 요청은 확인 뒤에 한다
            if self.sql("SELECT now() > %s", (kept[0],))[0][0]:
                break
            time.sleep(0.2)
        if before == "narrow":
            self.console_narrow()
        else:
            self.release()
            if before == "fw":
                self.console_rearm(["fw"])()
        self.fw.sync(self.now())
        self.cycle()                                                # 관문 목록에서 빠진다. 관문은 빠진 목록을 적용하지 않는다
        self.assertNotIn(self.IP, self.gw_ips())
        self.assertEqual((self.cols(), self.states()["gateway"]), (kept, "removing"))
        if before != "released":
            self.release()                                          # 같은 회차 안에 풀고 다시 건다
        self.console_rearm(["gateway", "fw"])()
        self.assertEqual((self.cols(), self.state()), (kept, "pending"))

        def held(why):
            with self.subTest(why=why):
                self.assertEqual((self.cols(), self.states()["gateway"], self.state()), (kept, "pending", "pending"))
                self.assertEqual(self.unenforced(), [])
        self.fw.sync(self.now())
        self.cycle()                                                # 다시 든 목록을 올린다. 관문은 이 주소가 든 옛 목록 그대로다
        self.assertIn(self.IP, self.gw_ips())
        held("다시 든 목록을 올린 회차")
        if lost == "after":
            self.gw.sync(self.now())                                # 관문이 다시 든 목록을 적용했다 (집행기는 아직 모른다)
        if lost:
            self.st = be.new_state()                                # 확인 전에 상태 파일을 잃었다
            self.fw.sync(self.now())
            self.cycle()
        if lost != "after":
            if lost:
                held("잃은 뒤 다시 걸기 전의 보고")
            self.step()                                             # 관문이 다시 든 목록을 오류 없이 적용했다
        enforced_at, method, note = self.cols()
        self.assertEqual(method, "nft")
        self.assertGreater(enforced_at, kept[0])
        self.assertTrue(note.endswith(be.NOTE_KEPT), note)
        self.assertEqual((self.states(), self.state()), ({"gateway": "confirmed", "fw": "confirmed"}, "enforced"))
        marks = ("console.block.enforced", "console.block.unenforced")
        self.assertEqual([e for e in self.audit() if e in marks], [marks[0]] * 2)
        for _ in range(3):
            self.step()                                             # 같은 확인이 이어져도 감사는 늘지 않는다
        self.assertEqual([e for e in self.audit() if e in marks], [marks[0]] * 2)
        report = self.enforce_report(start)
        if report is not None:                                      # 관문 요청 2(처음 · 관문 포함 다시 걸기), 다시 걸기는 기존 차단 유지
            self.assertEqual(tuple(report), (2, 1, 1))

    def test_콘솔_관문_없이_다시_건_행을_같은_회차에_풀고_관문_포함_다시_걸기(self):
        self.regain("fw")

    def test_콘솔_관리자_관문_빼기_뒤_같은_회차에_풀고_관문_포함_다시_걸기(self):
        self.regain("narrow")

    def test_콘솔_관문_포함_다시_걸기_확인_전_상태_파일_분실_관문_적용_전(self):
        self.regain("released", lost="before")

    def test_콘솔_관문_포함_다시_걸기_확인_전_상태_파일_분실_관문_적용_뒤(self):
        self.regain("released", lost="after")

    def test_콘솔_관문_없이_다시_건_행을_풀고_관문_포함_다시_걸기_확인_전_상태_파일_분실(self):
        self.regain("fw", lost="before")


class OvercapGuardTest(ChoiceBase):
    def test_상한은_내부_방화벽_목록에_걸고_관문_쪽지는_관문을_요청한_행만(self):
        with mock.patch.object(be, "LIST_MAX", 2):
            self.store.add("198.51.100.1", created=T0 - 4 * MIN)                       # 두 지점 · 상한 밖
            self.store.add("198.51.100.2", created=T0 - 3 * MIN, points=FW_ONLY)       # 전용 · 상한 밖
            self.store.add("198.51.100.3", created=T0 - 2 * MIN, points=FW_ONLY)
            self.store.add("198.51.100.4", created=T0 - MIN)
            self.per_point()
        self.assertEqual((self.gw_ips(), self.fw_ips()), (["198.51.100.4"], ["198.51.100.3", "198.51.100.4"]))
        self.assertEqual(self.row("198.51.100.1")["note"], "관문 불일치 · 목록 상한 2 초과")
        self.assertIsNone(self.row("198.51.100.2")["note"])
        cap = {"state": "stale", "note": "목록 상한 2 초과"}
        self.assertEqual({p: {k: v[k] for k in cap} for p, v in self.pts("198.51.100.1").items()}, {"gateway": cap, "fw": cap})
        self.assertEqual({p: {k: v[k] for k in cap} for p, v in self.pts("198.51.100.2").items()}, {"fw": cap})
        self.assertEqual(self.states("198.51.100.3"), {"fw": "confirmed"})

    def test_읽은_뒤_콘솔이_넓힌_행은_쓰지_않는다(self):
        self.store.add("203.0.113.10", points=FW_ONLY)
        sent = []
        real = self.store.apply

        def apply(updates):
            sent.extend(updates)
            return real(updates)

        def widen():                                               # 읽은 뒤 콘솔이 관문을 더했다
            self.row("203.0.113.10")["points"] = ["gateway", "fw"]
        self.store.apply, self.store.before_apply = apply, widen
        self.run_once()
        self.assertEqual(sent[0]["guard"]["points"], ["fw"])
        self.assertIsNone(self.pts("203.0.113.10"))
        self.assertTrue(any("다음 회차" in m for _, m in self.logs))
        self.store.before_apply = None
        self.tick()
        self.run_once()
        self.assertEqual(set(self.pts("203.0.113.10")), {"gateway", "fw"})


class ResumeTest(ChoiceBase):
    """옛 집행기로 되돌렸다 다시 올린 상태 파일 (계약 결정 4 · 2.1). 옛 집행기는 fw_book · fw_list_* 를 모르는 채 저장한다."""

    def old_cycle(self):
        """#77 전 판 집행기의 한 회차 흉내: 모든 행을 entries 에 싣고(points 없음) 기존 장부만 적는다."""
        self.tick()
        self.st["seq"] += 1
        entries = sorted(({"ip": r["ip"], "until": be.iso(r["expires_at"])} for r in self.store.fetch()["rows"]
                          if be.classify(r, self.store.now)[0] == "list"), key=lambda e: e["ip"])
        doc = be_p.list_doc(entries, self.store.now)
        self.s3.objects[be.LIST_KEY] = json.dumps(doc).encode("utf-8")
        be.bookkeep(self.st, entries, doc["digest"], self.st["seq"], self.store.now)
        self.st["published"] = {"digest": doc["digest"], "generated_at": doc["generated_at"],
                                "uploaded_at": be.iso_full(self.store.now), "count": len(entries)}

    def test_되돌렸다_다시_올리면_기존_장부에서_다시_만들고_첫_회차에_모르는_목록이_없다(self):
        self.store.add("198.51.100.7")
        self.store.add("203.0.113.10", points=FW_ONLY)
        self.per_point()
        self.step()
        stale = {k: copy.deepcopy(self.st[k]) for k in ("fw_book", "fw_list_ok", "fw_list_seq")}
        self.store.add("198.51.100.9")                             # 옛 집행기가 도는 동안 든 행
        for _ in range(4):
            self.old_cycle()
            self.gw.sync(self.store.now + timedelta(seconds=20))
            self.fw.sync(self.store.now + timedelta(seconds=40))   # 새 판 내부 방화벽은 points 가 없어 entries · legacy
        self.st.update(stale)
        with tempfile.TemporaryDirectory() as d:
            be.save_state(os.path.join(d, "state.json"), self.st)
            self.st = be.load_state(os.path.join(d, "state.json"))
        self.assertEqual({k: self.st["fw_book"][k] for k in ("seen", "entries", "gone")},
                         {k: self.st[k] for k in ("seen", "entries", "gone")})
        self.assertEqual((self.st["fw_book"]["seq"], self.st["fw_list_ok"]), (self.st["seq"], False))
        self.logs.clear()
        self.tick()
        self.assertEqual(self.run_once(), 0)
        self.assertFalse(any("모르는 목록" in m or "관문 목록을 적용했다" in m for _, m in self.logs), self.logs)
        for ip in ("198.51.100.7", "198.51.100.9", "203.0.113.10"):
            self.assertEqual(self.pts(ip)["fw"]["state"], "confirmed", ip)
        self.assertEqual(self.gw_ips(), ["198.51.100.7", "198.51.100.9", "203.0.113.10"])     # list legacy 라 전체
        self.step()
        self.assertEqual(self.gw_ips(), ["198.51.100.7", "198.51.100.9"])

    def test_resume_은_여러_번_불러도_같다(self):
        self.store.add("198.51.100.7")
        self.per_point()
        self.st["seq"] += 2
        be.resume(self.st)
        once = copy.deepcopy(self.st)
        be.resume(self.st)
        self.assertEqual(self.st, once)


class CrossVersionTest(ChoiceBase):
    """#77 판과 P 판(#77 직전 main)이 주고받는 보고 · 목록 (enforcer/testdata/block_enforcer_p.py)."""

    def test_P_판_validate_status_는_list_가_든_새_보고를_받는다(self):
        self.store.add("198.51.100.7")
        self.store.add("203.0.113.10", points=FW_ONLY)
        self.per_point()
        now = self.store.now
        reports = [json.loads(self.s3.objects[FW_STATUS])]
        Gateway(self.s3, point="gateway").sync(now)
        reports.append(json.loads(self.s3.objects[STATUS]))
        Gateway(self.s3).sync(now)
        reports.append(dict(json.loads(self.s3.objects[STATUS]), list="legacy"))
        reports.append({"v": 1, "at": be.iso(now), "mode": "nft", "list": None, "list_digest": None, "list_generated_at": None,
                        "applied": 0, "set_count": None, "rejected": [], "errors": ["목록을 읽지 못함 (SlowDown)"],
                        "selftest": None})
        self.assertEqual([r["list"] for r in reports], ["fw", "gateway", "legacy", None])
        for r in reports:
            old, why = be_p.validate_status(r, now)
            self.assertIsNone(why, r["list"])
            new, why = be.validate_status(r, now)
            self.assertIsNone(why, r["list"])
            self.assertEqual({k: v for k, v in new.items() if k != "list"}, old)
            self.assertEqual(new["list"], r["list"])

    def test_list_는_선택_필드고_모르는_값은_legacy_로_본다(self):
        base = {"v": 1, "at": be.iso(T0), "mode": "nft", "list_digest": None, "applied": 0}
        self.assertEqual(be.validate_status(base, T0)[0]["list"], "legacy")          # 키가 없으면 #77 전 판
        self.assertIsNone(be.validate_status(dict(base, list=None), T0)[0]["list"])   # 목록을 못 읽은 회차
        # 모르는 값은 보고를 버리지 않고 legacy(전체 모드)로 보고 등급 4 로 알린다 (계약 12장 2번)
        for bad in ("points", "FW", 1, True, ["fw"]):
            self.logs.clear()
            got, why_ = be.validate_status(dict(base, list=bad), T0, label="내부 방화벽")
            self.assertEqual((got["list"], why_), ("legacy", None), bad)
            self.assertEqual([lv for lv, m in self.logs if m.startswith("내부 방화벽 보고의 list 를 모른다")], [4], bad)

    @unittest.skipUnless(shutil.which("git"), "git 이 없다")
    def test_사본은_P_판_글자_그대로다(self):
        p = subprocess.run(["git", "-C", HERE, "show", f"{be_p.P_COMMIT}:enforcer/block_enforcer.py"],
                           capture_output=True, text=True)
        if p.returncode != 0:
            self.skipTest(f"P 판을 읽지 못함: {p.stderr.strip()[:80]}")
        with open(os.path.join(HERE, "testdata", "block_enforcer_p.py"), encoding="utf-8") as f:
            src = f.read()
        nodes = [n for n in ast.parse(src).body if isinstance(n, (ast.Assign, ast.FunctionDef))
                 and not (isinstance(n, ast.Assign) and n.targets[0].id == "P_COMMIT")]
        self.assertEqual(len(nodes), 17)
        for n in nodes:
            self.assertIn(ast.get_source_segment(src, n), p.stdout, getattr(n, "name", None))


class _Conn:
    def close(self):
        pass


class CommandTest(ChoiceBase):
    """status · list 명령 (이슈 #77: 관문 목록 모드 · 지점별 요청 · 확인 수 · 보고의 list)."""

    def setUp(self):
        super().setUp()
        self.store.add("198.51.100.7")
        self.store.add("203.0.113.10", points=FW_ONLY)
        self.per_point()
        self.step()
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home)
        test = self

        class Clock(datetime):                                     # status 가 보고를 읽는 시각
            @classmethod
            def now(cls, tz=None):
                return test.store.now
        for p in (mock.patch.object(be, "settings", lambda: dict(self.cfg, home=self.home)),
                  mock.patch.object(be, "datetime", Clock),
                  mock.patch.object(be, "db_connect", _Conn), mock.patch.object(be, "PgStore", lambda c: self.store),
                  mock.patch.object(be, "s3_client", lambda cfg, name: self.s3)):
            p.start()
            self.addCleanup(p.stop)

    def save(self):
        be.save_state(os.path.join(self.home, "state.json"), self.st)

    def test_status_는_모드_지점별_수_보고의_list_를_찍는다(self):
        self.save()
        out = []
        self.assertEqual(be.cmd_status(None, out=out.append), 0)
        self.assertIn("관문 목록: 지점별", out)
        self.assertIn("DB (지난 2일 안의 만료 · 집행 기록이 남은 행 포함): 집행 확인 2", out)
        self.assertIn("지점별 (목록 행): 관문 요청 1 · 확인 1 · 미요청 1 / 내부 방화벽 요청 2 · 확인 2", out)
        self.store.rows["198.51.100.7"]["points"] = ["fw"]           # 관문 빼기 직후 (관문 세 열 · 관문 결과가 남음)
        out = []
        be.cmd_status(None, out=out.append)
        self.assertIn("지점별 (목록 행): 관문 요청 0 · 확인 0 · 미요청 1 · 빠짐 확인 전 1 / 내부 방화벽 요청 2 · 확인 2", out)
        self.assertTrue(any(ln.startswith("관문 보고: ") and " · 목록 legacy " in ln for ln in out), out)
        fdg = self.s3.listed()["points"]["fw"]["digest"][:8]
        self.assertTrue(any(ln.startswith("내부 방화벽 보고: ") and f" · 목록 fw {fdg} " in ln for ln in out), out)

    def test_status_는_끊긴_상태_파일이면_전체라고_찍는다(self):
        self.st["seq"] += 1
        self.save()
        out = []
        be.cmd_status(None, out=out.append)
        self.assertIn("관문 목록: 전체 · 내부 방화벽 확인 전", out)

    def test_list_는_마지막_회차의_모드로_만든다(self):
        for bump, want in ((0, ["198.51.100.7"]), (1, BOTH)):
            with self.subTest(bump=bump):
                self.st["seq"] += bump
                self.save()
                buf, err = io.StringIO(), io.StringIO()
                with mock.patch("sys.stdout", buf), mock.patch("sys.stderr", err):
                    self.assertEqual(be.cmd_list(None), 0)
                doc = json.loads(buf.getvalue())
                self.assertEqual([e["ip"] for e in doc["entries"]], want)
                self.assertEqual([e["ip"] for e in doc["points"]["fw"]["entries"]], BOTH)
                self.assertEqual(err.getvalue().splitlines()[-1], "# 행 2: list 2")


class InstallerTest(unittest.TestCase):
    """enforcer/install-enforcer.sh (이슈 #77: 마이그레이션 27 → 29 → 30 → 77, 사전 확인 · 사용 예 · 권한 확인)."""
    PATH = os.path.join(HERE, "install-enforcer.sh")

    def text(self):
        with open(self.PATH, encoding="utf-8") as f:
            return f.read()

    def test_마이그레이션을_반영_순서대로_적용한다(self):
        text = self.text()
        self.assertEqual(re.findall(r'< "\$SRC/\$(MIGRATION[0-9]*)"', text),
                         ["MIGRATION", "MIGRATION51", "MIGRATION52", "MIGRATION77"])
        files = dict(re.findall(r"^(MIGRATION[0-9]*)=(\S+)$", text, re.M))
        self.assertEqual(files["MIGRATION77"], "infra/migrations/20261003_block_points_choice.sql")
        for name, path in files.items():
            self.assertTrue(os.path.exists(os.path.join(ROOT, path)), path)
            self.assertIn(f'"${name}"', text[text.index("== 사전 확인"):text.index("== 패키지")], name)
        usage = next(ln for ln in text.splitlines() if "git archive" in ln)
        self.assertEqual(re.findall(r"infra/migrations/\S+\.sql", usage), [files[k] for k in sorted(files)])
        self.assertIn('check_priv "집행 points 읽기 · points 갱신" "t f"', text)

    @unittest.skipUnless(shutil.which("bash"), "bash 가 없다")
    def test_문법(self):
        p = subprocess.run(["bash", "-n", self.PATH], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck 가 없다")
    def test_shellcheck(self):
        p = subprocess.run(["shellcheck", self.PATH], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
