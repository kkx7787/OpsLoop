#!/usr/bin/env python3
"""차단 집행기 시험 (이슈 #47). 가짜 DB · 가짜 S3 · 관문 흉내로 목록 · digest · 확인 · 불일치 · 만료 · 제외 · 멱등을 본다.

  python3 enforcer/test_block_enforcer.py
  OPSLOOP_TEST_DATABASE_URL=postgresql://… python3 enforcer/test_block_enforcer.py   # 실제 PostgreSQL 시험도

실제 PostgreSQL 시험은 시험마다 새 DB 를 만들어 infra/schema.sql 과 infra/migrations/20260927_block_enforce.sql 을
그대로 적용하고, opsloop_enforcer 역할로 붙어 한 회차를 돌린다(권한 · 트리거 · 감사 · 만료 기록). 끝나면 DB 를 지운다.
역할 opsloop_enforcer 는 클러스터 전체라 시험 전용 PostgreSQL 에서만 돌린다.
"""
import copy
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import secrets
import subprocess
import sys
import tempfile
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
            enforcement=None):
        net = ipaddress.ip_network(ip, strict=False)
        host = net.prefixlen == net.max_prefixlen
        key = str(net.network_address) if host else str(net)
        self.rows[key] = {"key": key, "ip": str(net.network_address), "fam": net.version, "mask": net.prefixlen,
                          "created_at": created or self.now,
                          "expires_at": (self.now + expires) if isinstance(expires, timedelta) else expires,
                          "released_at": released, "enforced_at": enforced, "method": method, "note": note,
                          "enforcement": enforcement, "exempt_net": exempt_net}
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
                   "method": r["method"], "enforce_note": r["note"], "enforcement": r["enforcement"]}
            if any(cur[k] != u["guard"][k] for k in be.GUARD):
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
    """관문(또는 내부 방화벽) block-sync.py 흉내. S3 목록을 읽어 digest 를 따로 확인하고 보고를 hb 경로에 쓴다."""

    def __init__(self, s3, mode="nft", key=STATUS):
        self.s3, self.mode, self.key = s3, mode, key

    def sync(self, at, rejected=(), errors=(), digest=None, applied=None, set_count=None):
        doc = self.s3.listed()
        assert contract_digest(doc["entries"]) == doc["digest"], "관문이 digest 를 거부할 목록이다"
        live = [e for e in doc["entries"] if be.parse_ts(e["until"]) > at and e["ip"] not in dict(rejected)]
        n = len(live) if applied is None else applied
        self.put({"v": 1, "at": be.iso(at), "mode": self.mode, "list_digest": digest or doc["digest"],
                  "list_generated_at": doc["generated_at"], "applied": n, "set_count": n if set_count is None else set_count,
                  "rejected": [{"ip": ip, "why": w} for ip, w in rejected], "errors": list(errors), "selftest": None})

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

    def confirmed(self, ip, at, mode="nft"):
        r = self.row(ip)
        self.assertEqual(r["enforced_at"], at.replace(microsecond=0))
        self.assertEqual(r["method"], mode)
        self.assertRegex(r["note"], r"^관문 반영 · [0-9a-f]{8} · " + be.iso(at) + "$")

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
        self.assertEqual(list(doc), ["v", "generated_at", "entries", "digest"])
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
        self.confirmed("198.51.100.7", at)

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
        self.confirmed("198.51.100.7", at, mode="nft")

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
        self.confirmed("198.51.100.7", at)
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
        doc = be.list_doc(entries, T0)
        wire = json.loads(json.dumps(doc, ensure_ascii=True).encode("utf-8"))    # 올린 바이트를 관문이 읽은 모양
        self.assertEqual(bs.canonical_digest(wire["entries"]), doc["digest"])
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


def with_db(url, db, user=None, password=None):
    u = urllib.parse.urlsplit(url)
    netloc = u.netloc if user is None else f"{user}:{urllib.parse.quote(password)}@{u.hostname}:{u.port or 5432}"
    return urllib.parse.urlunsplit((u.scheme, netloc, "/" + db, u.query, ""))


@unittest.skipUnless(REAL_PG and URL and os.path.exists(MIGRATION), "PostgreSQL 시험 연결 · 마이그레이션 없음")
class PgTest(unittest.TestCase):
    """스키마 · 마이그레이션을 그대로 적용한 새 DB 에서 opsloop_enforcer 역할로 한 회차를 돌린다."""

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
            for path in (SCHEMA, MIGRATION, MIGRATION51, MIGRATION52):
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
                  "SELECT count(*) FROM events", "INSERT INTO block_exempt (cidr, note) VALUES ('198.51.100.0/24', 'x')"):
            with self.subTest(q=q), self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                with self.conn, self.conn.cursor() as c:
                    c.execute(q)


class PointsTest(Base):
    """집행 지점별 결과 (이슈 #51). 관문의 세 열 · 감사는 그대로고 enforcement 에 지점마다 state · since · mode · note 가 붙는다."""

    def points(self, ip):
        return self.row(ip)["enforcement"]

    def test_관문만_설정하면_gateway_갈래만_적힌다(self):
        self.settle()
        pts = self.points("198.51.100.7")
        self.assertEqual(list(pts), ["gateway"])
        self.assertEqual(pts["gateway"], {"state": "confirmed", "since": be.iso(T0 + timedelta(seconds=30)),
                                          "mode": "nft", "note": None})
        # 확인이 이어져도 다시 쓰지 않는다
        w = self.store.writes
        self.gw.sync(self.store.now + timedelta(seconds=30))
        self.tick()
        self.run_once()
        self.assertEqual(self.store.writes, w)

    def test_첫_회차는_대기로_적고_since_는_그때다(self):
        self.store.add("198.51.100.7")
        self.run_once()
        self.assertEqual(self.points("198.51.100.7"), {"gateway": {"state": "pending", "since": be.iso(T0), "mode": None,
                                                                    "note": None}})
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
        self.assertIsNone(self.points("203.0.113.10"))
        self.assertNotIn("203.0.113.10", self.st["points"]["fw"])

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
        self.assertEqual(list(self.points("203.0.113.10")), ["gateway"])
        self.assertNotIn("fw", self.st["points"])
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
