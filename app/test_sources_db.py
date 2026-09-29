"""출발지 분석(sources.py · 이슈 #58)의 PostgreSQL 시험.  OPSLOOP_TEST_DATABASE_URL=... python3 -m unittest discover -s app

연결 전용 임시 표만 쓰고 search_path 로 운영 표를 가린다. 표 정의는 infra/schema.sql 의 CREATE TABLE 과 뒤따른 ADD COLUMN 을
그대로 임시 표로 옮긴다(트리거 · 권한은 infra 시험이 본다). 시험 대역 함수(is_test_source)는 임시 스키마에서 함수를 찾지 않으므로
test_dashboard_db 와 같이 무작위 스키마에 둔다. 처리기는 가짜 요청으로 직접 부른다(쿼리 인자는 모두 넘긴다).

  - 목록: 출발지별 사건 수 · 미판정 · 최신 판정 분포가 독립 SQL(사건마다 상관 부질의로 마지막 판정)과 같다 ·
    critical + medium 출발지의 최고 심각도가 critical(글자 max 면 medium) · 같은 시각 판정은 id 가 큰 것 ·
    시험 대역 표시와 기본 제외(include_test) · 차단 제외(코드 상수 · block_exempt 표 · 표를 못 읽으면 null) ·
    주소 없는 사건(target 만)은 없음 · 노린 대상(실제 이벤트의 발생원만, 감사 기록 제외. 등록 노드 발생원은 그 노드,
    nodes 표가 없거나 폐기된 노드면 버림) · 차단 행 · 정렬 세 가지(동률은 주소 순) ·
    q 앞부분(IPv6 대문자) · 쪽 넘김 · 마지막 관측(실제 이벤트의 마지막 시각. 감사 기록 제외 · 마지막 사건과 따로)
  - 지문: hassh · ssh_version · user_agent 값과 출발지 · 연결 · 사건 있는 출발지 수. 모의 · 시험 자료 이벤트 · 콘솔 UA · 빈 버전은
    빠지고 긴 UA 는 512자로 잘린다. 지문 조건 목록(fp_kind · fp)은 그 지문을 쓴 출발지 가운데 사건 있는 곳뿐이다
  - 상세: 사건 흐름(첫 시각 순 · 마지막 판정) · 이벤트 종류(실제만) · 지문 · 조치(차단 · 해제만, 최근 순) · 차단 행 · 차단 금지 대역 ·
    흡수 기록 수 · 집행기 확인 · 이벤트만 있는 출발지(요약 null) · 404 · 422 · 감사 기록은 늘 빠지고 콘솔 기록은 사건 있는 주소만 ·
    감사 · 콘솔 기록만 있는 주소는 조회자에게 404 · 머리의 마지막 관측 · 차단 제외(exempt_flag, 요약이 없어도 목록과 같은 판단)
  - 표가 없는 DB: 생존 신호 · 흡수 기록 · 차단 금지 표가 없으면 그 값은 null(차단 제외는 코드 상수 대역만 참)
  - main.py 요약 상위 출발지(TOP_ACTORS_SQL): critical + medium 출발지가 critical
"""
import ipaddress
import json
import os
import re
import secrets
import unittest
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from fastapi import HTTPException

import sources as s

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = (ROOT / "infra" / "schema.sql").read_text()

A, B, C, D, E, F = "198.51.100.7", "192.0.2.10", "203.0.113.5", "10.0.0.5", "2001:db8::1", "198.51.100.99"
G, H = "198.51.100.200", "192.0.2.77"          # 이벤트만 있는 출발지(사건 없음)
# 사건 없는 주소: 감사 기록(우리 DB 접속 주소)만 · 콘솔 로그인만 · 콘솔 · 감사 기록과 실제 이벤트
AUD, CON, MIX = "192.0.2.60", "192.0.2.61", "192.0.2.62"
X1, X2 = "198.51.100.100", "172.16.5.5"         # 사건 없이 이벤트만: block_exempt 표 대역 · 코드 상수 대역(표에 없음)
# 정렬 동률 시험(F 와 주소만 다르다. 제외 대역 198.51.100.96/28 밖). 넣는 순서를 주소 순과 다르게 둔다
TIES = [f"198.51.100.{n}" for n in (40, 8, 95, 21, 3, 64)]
H1, H2, H3 = "a" * 32, "b" * 32, "c" * 32       # HASSH. H3 는 시험 자료(fixture) 이벤트에만 있다
LONG_UA = "x" * 600


def temp_table(name: str) -> str:
    """schema.sql 의 표 정의(첫 CREATE TABLE 과 뒤따른 ADD COLUMN)를 임시 표로 옮긴다."""
    body = re.search(rf"^CREATE TABLE IF NOT EXISTS {name} \(\n.*?\n\);", SCHEMA, re.S | re.M).group(0)
    alters = re.findall(rf"^ALTER TABLE {name} ADD COLUMN IF NOT EXISTS .*?;$", SCHEMA, re.M)
    return "\n".join([body.replace("CREATE TABLE IF NOT EXISTS", "CREATE TEMP TABLE", 1), *alters])


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class Base(unittest.IsolatedAsyncioTestCase):
    with_exempt = True
    with_heartbeats = True
    with_absorbed = True

    async def asyncSetUp(self):
        import asyncpg
        self.conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        await self.conn.execute("SET search_path TO pg_temp")
        tables = ["incidents", "verdicts", "actions", "events", "blocklist", "test_ranges"]
        tables += ["block_exempt"] * self.with_exempt + ["sensor_heartbeats"] * self.with_heartbeats
        tables += ["incident_absorbed"] * self.with_absorbed
        for name in tables:
            await self.conn.execute(temp_table(name))
        # 시험 대역 함수. 표는 그대로 임시 표다(스키마가 비어 pg_temp 에서 찾는다)
        self.schema = f"t58_{secrets.token_hex(4)}"
        await self.conn.execute(f"""
            INSERT INTO test_ranges (cidr, note) VALUES ('203.0.113.0/24', '시험');
            CREATE SCHEMA {self.schema};
            CREATE FUNCTION {self.schema}.is_test_source(ip inet) RETURNS boolean LANGUAGE sql STABLE
                AS $$ SELECT EXISTS (SELECT 1 FROM pg_temp.test_ranges t WHERE ip <<= t.cidr) $$;
            SET search_path TO {self.schema}, pg_temp;""")
        self.now = await self.conn.fetchval("SELECT now()")
        self.lines = 0
        self.request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
            pool=SimpleNamespace(acquire=self.acquire))), state=SimpleNamespace(user={"u": "tester", "r": "viewer"}))
        await self.fixture()

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def asyncTearDown(self):
        await self.conn.execute(f"DROP SCHEMA IF EXISTS {self.schema} CASCADE")
        await self.conn.close()

    def ago(self, minutes):
        return self.now - timedelta(minutes=minutes)

    async def incident(self, key, ip, rule, severity, first, last, target=None):
        await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
            actor_ip, target, first_ts, last_ts, signal_count) VALUES ($1, $2, 'v3', $3, $4, $5::inet, $6, $7, $8, 1)""",
            key, rule, f"{rule} 시험 규칙", severity, ip, target, self.ago(first), self.ago(last))

    async def verdict(self, key, verdict, minutes):
        await self.conn.execute("INSERT INTO verdicts (incident_key, verdict, created_at) VALUES ($1, $2, $3)",
                                key, verdict, self.ago(minutes))

    async def event(self, minutes, eventid, sensor, ip, message=None, user_agent=None, provenance="real"):
        self.lines += 1
        await self.conn.execute("""INSERT INTO events (line_hash, ts, eventid, src_ip, sensor, message, user_agent,
            provenance) VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8)""",
            f"t58-{self.lines}", self.ago(minutes), eventid, ip, sensor, message, user_agent, provenance)

    async def fixture(self):
        # A: critical · medium · low. a1 은 위협 → 오탐으로 고침, a3 은 같은 시각 두 판정(id 가 큰 미결이 마지막)
        await self.incident("a1", A, "R001", "critical", 300, 290)
        await self.incident("a2", A, "R003", "medium", 200, 190)
        await self.incident("a3", A, "R101", "low", 50, 40)
        await self.verdict("a1", "threat", 280)
        await self.verdict("a1", "false_positive", 100)
        await self.verdict("a3", "threat", 30)
        await self.verdict("a3", "undetermined", 30)
        # B: 새 사건이 medium, 옛 사건이 critical. 글자 max 면 medium 이다
        await self.incident("b1", B, "R002", "medium", 30, 20)
        await self.incident("b2", B, "R004", "critical", 400, 395)
        await self.verdict("b2", "threat", 390)
        await self.incident("c1", C, "R001", "high", 10, 5)                 # 시험 대역
        await self.incident("d1", D, "R101", "low", 60, 60)                 # 사설(코드 상수 대역)
        await self.incident("e1", E, "R001", "high", 500, 480)
        await self.incident("e2", E, "R001", "high", 470, 460)
        await self.incident("e3", E, "R005", "high", 450, 445)
        await self.verdict("e1", "threat", 440)
        await self.verdict("e2", "non_actionable", 440)
        await self.verdict("e3", "benign_positive", 440)
        await self.incident("f1", F, "R001", "low", 700, 700)               # block_exempt 표에만 있는 대역
        await self.incident("t1", None, "R201", "medium", 5, 5, target="user:han")   # 주소 없는 사건

        await self.event(300, "cowrie.session.connect", "cowrie", A)
        await self.event(299, "cowrie.session.connect", "cowrie", A)
        await self.event(299, "cowrie.client.version", "cowrie", A, "Remote SSH version: SSH-2.0-Go")
        await self.event(299, "cowrie.client.kex", "cowrie", A, f"SSH client hassh fingerprint: {H1}")
        await self.event(298, "cowrie.client.kex", "cowrie", A, f"SSH client hassh fingerprint: {H1}")
        await self.event(297, "cowrie.client.kex", "cowrie", A, f"SSH client hassh fingerprint: {H3}",
                         provenance="fixture")
        await self.event(200, "decoy.request", "decoy", A, user_agent="curl/8.0")
        await self.event(30, "cowrie.client.kex", "cowrie", B, f"SSH client hassh fingerprint: {H1}")
        await self.event(30, "cowrie.client.version", "cowrie", B, "Remote SSH version: SSH-2.0-libssh_0.9")
        await self.event(25, "gateway.block.drop", "gateway", B)
        await self.event(25, "nginx.request", "web-01", B, provenance="simulated")
        await self.event(60, "console.login.failed", "console", D, user_agent="curl/8.0")
        await self.event(480, "nginx.request", "web-01", E, user_agent="Mozilla/5.0")
        await self.event(10, "cowrie.client.kex", "cowrie", G, f"SSH client hassh fingerprint: {H1}")
        await self.event(9, "cowrie.client.kex", "cowrie", G, f"SSH client hassh fingerprint: {H2}")
        await self.event(9, "cowrie.client.version", "cowrie", G, "Remote SSH version: ")
        await self.event(8, "decoy.request", "decoy", H, user_agent=LONG_UA)
        await self.event(8, "cowrie.client.kex", "cowrie", "192.0.2.201", f"SSH client hassh fingerprint: {H2}",
                         provenance="fixture")
        # 우리 쪽 기록. 감사 행의 src_ip 는 DB 접속 주소다. A 의 감사 행은 가장 늦어 마지막 관측 · 노린 대상 · 이벤트 종류에 들면 드러난다
        await self.event(1, "console.block.created", "audit", A, f"by=han ip={A}")
        await self.event(3, "console.block.created", "audit", AUD)
        await self.event(2, "console.block.enforced", "audit", AUD)
        await self.event(4, "console.login.failed", "console", CON, user_agent="Mozilla/5.0")
        await self.event(3, "console.login.success", "console", CON, user_agent="Mozilla/5.0")
        await self.event(2, "console.logout", "console", CON)
        await self.event(20, "cowrie.session.connect", "cowrie", MIX)
        await self.event(6, "console.login.success", "console", MIX)
        await self.event(5, "console.block.created", "audit", MIX)
        await self.event(40, "cowrie.session.connect", "cowrie", X1)
        await self.event(40, "cowrie.session.connect", "cowrie", X2)

        await self.conn.execute("""INSERT INTO actions (incident_key, action, operator, note, created_at) VALUES
            ('a1', 'block_ip', 'han', '차단', $1), ('a1', 'note', 'han', '메모', $2),
            ('a2', 'unblock_ip', 'kim', '해제', $3), ('b1', 'block_ip', 'han', NULL, $1)""",
            self.ago(250), self.ago(240), self.ago(100))
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, created_at, expires_at,
            method, requested_by, enforced_at, enforce_note, enforcement) VALUES
            ($1::inet, 'SSH 무차별 대입', 'a1', $2, $3, 'nft', 'han', $4, '관문 반영 · 0123abcd · 시험', $5::jsonb)""",
            A, self.ago(250), self.now + timedelta(hours=20), self.ago(249),
            json.dumps({"gateway": {"state": "confirmed", "since": "2026-09-29T00:00:00Z", "mode": "nft", "note": None}}))
        if self.with_exempt:
            await self.conn.execute("""INSERT INTO block_exempt (cidr, note) VALUES
                ('10.0.0.0/8', '사설 · AWS VPC'), ('198.51.100.96/28', '시험 제외')""")
        if self.with_heartbeats:
            await self.conn.execute("""INSERT INTO sensor_heartbeats (source, kind, role, host, seen_at, checked_at)
                VALUES ('block:gateway', 'block_report', 'gateway', 'i-0', $1, $1)""", self.ago(1))
        if self.with_absorbed:
            for member in ("m1", "m2"):
                await self.conn.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, rule_id,
                    rule_version, actor_ip, first_ts, last_ts, signal_count) VALUES
                    ('x1', $1, 'absorbed', 'R003', 'v3', $2::inet, $3, $3, 1)""", member, A, self.ago(100))

    async def listing(self, q=None, sort="recent", include_test=False, fp_kind=None, fp=None, limit=50, offset=0):
        return await s.list_sources(self.request, q=q, sort=sort, include_test=include_test, fp_kind=fp_kind, fp=fp,
                                    limit=limit, offset=offset)

    async def ips(self, **kw):
        return [i["ip"] for i in (await self.listing(**kw))["items"]]

    async def detail(self, ip):
        return await s.source_detail(self.request, ip=ip)

    async def groups(self, kind, limit=50, offset=0):
        return await s.fingerprint_groups(self.request, kind=kind, limit=limit, offset=offset)


class ListTests(Base):
    async def test_사건_수_미판정_판정_분포가_독립_SQL_과_같다(self):
        rows = await self.conn.fetch("""
            SELECT host(x.actor_ip) AS ip, x.verdict, count(*) AS n FROM (
                SELECT i.actor_ip, (SELECT v.verdict FROM verdicts v WHERE v.incident_key = i.incident_key
                                    ORDER BY v.created_at DESC, v.id DESC LIMIT 1) AS verdict
                FROM incidents i WHERE i.actor_ip IS NOT NULL) x
            GROUP BY 1, 2""")
        expected = {}
        for r in rows:
            e = expected.setdefault(r["ip"], {"incidents": 0, "unjudged": 0, "verdicts": dict.fromkeys(s.VERDICTS, 0)})
            e["incidents"] += r["n"]
            if r["verdict"] is None:
                e["unjudged"] += r["n"]
            else:
                e["verdicts"][r["verdict"]] += r["n"]
        body = await self.listing(include_test=True)
        got = {i["ip"]: {k: i[k] for k in ("incidents", "unjudged", "verdicts")} for i in body["items"]}
        self.assertEqual(got, expected)
        self.assertEqual(body["total"], 6)
        # 손으로 셈: a1 은 고친 오탐, a3 은 같은 시각 두 판정 중 id 가 큰 미결
        self.assertEqual(got[A], {"incidents": 3, "unjudged": 1, "verdicts": {
            "threat": 0, "non_actionable": 0, "false_positive": 1, "benign_positive": 0, "undetermined": 1}})
        self.assertEqual((got[E]["unjudged"], got[E]["verdicts"]["threat"], got[E]["verdicts"]["non_actionable"],
                          got[E]["verdicts"]["benign_positive"]), (0, 1, 1, 1))

    async def test_최고_심각도는_순위로_고른다(self):
        items = {i["ip"]: i for i in (await self.listing(include_test=True))["items"]}
        self.assertEqual({ip: i["severity"] for ip, i in items.items()},
                         {A: "critical", B: "critical", C: "high", D: "low", E: "high", F: "low"})
        # 글자 max 였다면 B 는 medium 이다
        self.assertEqual(await self.conn.fetchval("SELECT max(severity) FROM incidents WHERE actor_ip = $1::inet", B),
                         "medium")
        self.assertEqual(items[A]["rules"], ["R001", "R003", "R101"])
        self.assertEqual((items[A]["first_ts"], items[A]["last_ts"]),
                         (self.ago(300).isoformat(), self.ago(40).isoformat()))

    async def test_시험_대역은_표시하고_기본으로_뺀다(self):
        body = await self.listing()
        self.assertEqual((body["total"], [i["ip"] for i in body["items"]]), (5, [B, A, D, E, F]))
        self.assertTrue(all(i["test_source"] is False for i in body["items"]))
        body = await self.listing(include_test=True)
        self.assertEqual([(i["ip"], i["test_source"]) for i in body["items"]][0], (C, True))

    async def test_차단_제외와_주소_없는_사건(self):
        items = {i["ip"]: i for i in (await self.listing(include_test=True))["items"]}
        self.assertEqual({ip: i["exempt"] for ip, i in items.items()},
                         {A: False, B: False, C: False, D: True, E: False, F: True})
        # 주소 없는 사건(target 만)은 출발지가 아니다
        self.assertNotIn(None, items)
        self.assertEqual(len(items), 6)

    async def test_노린_대상과_차단_행(self):
        items = {i["ip"]: i for i in (await self.listing(include_test=True))["items"]}
        # 실제 이벤트의 발생원만 본다(B 의 모의 web-01 이벤트는 넣지 않는다). 콘솔 로그인 실패는 콘솔이다
        self.assertEqual({ip: i["targets"] for ip, i in items.items()},
                         {A: ["aws-sensor"], B: ["aws-sensor"], C: [], D: ["console"], E: ["web-01"], F: []})
        block = items[A]["block"]
        self.assertEqual({k: block[k] for k in ("reason", "method", "requested_by", "released_at", "enforce_note")},
                         {"reason": "SSH 무차별 대입", "method": "nft", "requested_by": "han", "released_at": None,
                          "enforce_note": "관문 반영 · 0123abcd · 시험"})
        self.assertEqual(block["enforcement"]["gateway"]["state"], "confirmed")
        self.assertEqual(block["enforced_at"], self.ago(249).isoformat())
        self.assertTrue(all(items[ip]["block"] is None for ip in (B, C, D, E, F)))
        self.assertEqual((await self.listing())["checkers"], {"gateway_stale": False, "fw_stale": True})

    async def test_노린_대상은_등록_노드_발생원도_그_노드로_본다(self):
        await self.event(15, "nginx.request", "web-02", E)
        # nodes 표가 없으면(이 시험 자료) 등록 노드를 몰라 버린다
        self.assertEqual({i["ip"]: i["targets"] for i in (await self.listing())["items"]}[E], ["web-01"])
        await self.conn.execute(temp_table("nodes"))
        await self.conn.execute("""INSERT INTO nodes (node_id, hostname, sensor, status) VALUES
            ('web-01', 'web-01', 'web-01', 'active'), ('web-02', 'web02.lab', 'web-02', 'active')""")
        self.assertEqual({i["ip"]: i["targets"] for i in (await self.listing())["items"]}[E], ["web-01", "web-02"])
        self.assertEqual((await self.detail(E))["summary"]["targets"], ["web-01", "web-02"])
        await self.conn.execute("UPDATE nodes SET status = 'revoked' WHERE node_id = 'web-02'")
        self.assertEqual((await self.detail(E))["summary"]["targets"], ["web-01"])

    async def test_정렬_세_가지(self):
        # 최근: 마지막 시각 내림차순
        self.assertEqual(await self.ips(sort="recent"), [B, A, D, E, F])
        # 사건 수: 같은 수면 주소 순(inet 순서는 IPv4 가 IPv6 앞)
        self.assertEqual(await self.ips(sort="incidents"), [A, E, B, D, F])
        # 심각도: 순위 다음 마지막 시각 내림차순
        self.assertEqual(await self.ips(sort="severity"), [B, A, E, D, F])

    async def test_정렬_동률은_주소_순이다(self):
        # F 와 사건 수 · 심각도 · 마지막 시각이 모두 같고 주소만 다른 출발지 여섯 곳을 주소가 뒤섞인 순서로 넣는다. 줄이 일곱 이상이면
        #   PostgreSQL 정렬이 동률의 순서를 지키지 않으므로(주소로 가르지 않은 변이에서 세 정렬 모두 틀림을 확인) 주소 순이어야 통과한다
        for n, ip in enumerate(TIES):
            await self.incident(f"y{n}", ip, "R001", "low", 710, 700)
        tied = sorted([*TIES, F], key=ipaddress.ip_address)
        self.assertEqual(await self.ips(sort="recent"), [B, A, D, E, *tied])
        self.assertEqual(await self.ips(sort="incidents"), [A, E, B, D, *tied])
        self.assertEqual(await self.ips(sort="severity"), [B, A, E, D, *tied])
        # 쪽을 넘겨도 같은 순서다
        self.assertEqual(await self.ips(limit=3, offset=4) + await self.ips(limit=10, offset=7), tied)

    async def test_주소_앞부분_검색과_쪽_넘김(self):
        self.assertEqual(await self.ips(q="198.51"), [A, F])
        self.assertEqual(await self.ips(q="2001:DB8"), [E])
        self.assertEqual(await self.ips(q="203.0"), [])
        self.assertEqual(await self.ips(q="203.0", include_test=True), [C])
        self.assertEqual(await self.ips(q="198.51.100.9"), [F])
        body = await self.listing(limit=2, offset=2)
        self.assertEqual((body["total"], [i["ip"] for i in body["items"]]), (5, [D, E]))
        body = await self.listing(offset=10)
        self.assertEqual((body["total"], body["items"]), (5, []))

    async def test_마지막_관측은_실제_이벤트의_마지막_시각이다(self):
        items = {i["ip"]: i for i in (await self.listing(include_test=True))["items"]}
        # A 의 감사 행(1분 전)은 넣지 않는다. 사건 있는 주소의 콘솔 기록(D)은 넣는다. 실제 이벤트가 없으면 null
        self.assertEqual({ip: i["last_seen"] for ip, i in items.items()},
                         {A: self.ago(200).isoformat(), B: self.ago(25).isoformat(), C: None,
                          D: self.ago(60).isoformat(), E: self.ago(480).isoformat(), F: None})
        # 차단 뒤에도 관문을 두드리면 마지막 사건(last_ts)은 그대로이고 마지막 관측만 늘어난다. 상세 머리 · 요약도 같다
        await self.event(2, "gateway.block.drop", "gateway", A)
        item = {i["ip"]: i for i in (await self.listing())["items"]}[A]
        self.assertEqual((item["last_ts"], item["last_seen"]), (self.ago(40).isoformat(), self.ago(2).isoformat()))
        body = await self.detail(A)
        self.assertEqual((body["last_seen"], body["summary"]["last_seen"]), (self.ago(2).isoformat(),) * 2)

    async def test_지문_조건은_그_지문을_쓴_사건_있는_출발지다(self):
        self.assertEqual(await self.ips(fp_kind="hassh", fp=H1), [B, A])     # G 는 사건이 없다
        self.assertEqual(await self.ips(fp_kind="hassh", fp=H2), [])
        self.assertEqual(await self.ips(fp_kind="hassh", fp=H3), [])         # 시험 자료 이벤트뿐
        self.assertEqual(await self.ips(fp_kind="ssh_version", fp="SSH-2.0-Go"), [A])
        # 콘솔 로그인 UA(D)는 지문이 아니다
        self.assertEqual(await self.ips(fp_kind="user_agent", fp="curl/8.0"), [A])
        self.assertEqual((await self.listing(fp_kind="hassh", fp=H1, q="192"))["total"], 1)


class FingerprintTests(Base):
    async def test_지문별_출발지_연결_사건_있는_출발지(self):
        body = await self.groups("hassh")
        self.assertEqual(body["total"], 2)
        self.assertEqual([{k: i[k] for k in ("value", "sources", "connections", "incident_sources")} for i in body["items"]],
                         [{"value": H1, "sources": 3, "connections": 4, "incident_sources": 2},
                          {"value": H2, "sources": 1, "connections": 1, "incident_sources": 0}])
        self.assertEqual((body["items"][0]["first_ts"], body["items"][0]["last_ts"]),
                         (self.ago(299).isoformat(), self.ago(10).isoformat()))
        # 독립 SQL: 실제 kex 이벤트의 지문별 출발지 수
        rows = await self.conn.fetch("""
            SELECT right(message, 32) AS value, count(DISTINCT src_ip) AS n FROM events
            WHERE eventid = 'cowrie.client.kex' AND provenance = 'real' GROUP BY 1 ORDER BY 1""")
        self.assertEqual({r["value"]: r["n"] for r in rows}, {i["value"]: i["sources"] for i in body["items"]})

    async def test_SSH_버전과_UA(self):
        body = await self.groups("ssh_version")
        # 빈 버전(G)은 지문이 아니다
        self.assertEqual([(i["value"], i["sources"], i["incident_sources"]) for i in body["items"]],
                         [("SSH-2.0-Go", 1, 1), ("SSH-2.0-libssh_0.9", 1, 1)])
        body = await self.groups("user_agent")
        # 디코이 UA 만 센다. 긴 UA 는 512자로 자른다
        self.assertEqual([(i["value"], i["sources"], i["connections"], i["incident_sources"]) for i in body["items"]],
                         [("curl/8.0", 1, 1, 1), ("x" * 512, 1, 1, 0)])
        # 잘린 값으로 조건을 걸어도 같은 식이라 맞는다(사건이 없어 목록은 비지만 오류가 아니다)
        self.assertEqual(await self.ips(fp_kind="user_agent", fp="x" * 512), [])

    async def test_쪽_넘김(self):
        body = await self.groups("hassh", limit=1, offset=1)
        self.assertEqual((body["total"], [i["value"] for i in body["items"]]), (2, [H2]))


class DetailTests(Base):
    async def test_사건_흐름_이벤트_종류_지문_조치(self):
        body = await self.detail(A)
        listed = {i["ip"]: i for i in (await self.listing())["items"]}[A]
        self.assertEqual(body["summary"], listed)
        self.assertEqual(body["ip"], A)
        self.assertEqual(body["incidents_total"], 3)
        self.assertEqual([(i["incident_key"], i["severity"], i["verdict"], i["status"]) for i in body["incidents"]],
                         [("a1", "critical", "false_positive", "open"), ("a2", "medium", None, "open"),
                          ("a3", "low", "undetermined", "open")])
        self.assertEqual(body["incidents"][0]["first_ts"], self.ago(300).isoformat())
        # 시험 자료 이벤트(H3)는 세지 않는다
        self.assertEqual([(k["sensor"], k["eventid"], k["count"]) for k in body["event_kinds"]],
                         [("cowrie", "cowrie.client.kex", 2), ("cowrie", "cowrie.session.connect", 2),
                          ("cowrie", "cowrie.client.version", 1), ("decoy", "decoy.request", 1)])
        self.assertEqual(body["fingerprints"], {"hassh": [{"value": H1, "count": 2}],
                                                "ssh_version": [{"value": "SSH-2.0-Go", "count": 1}],
                                                "user_agent": [{"value": "curl/8.0", "count": 1}]})
        # 이 주소 사건의 차단 · 해제만, 최근 순(메모 · 다른 주소 사건의 차단은 없다)
        self.assertEqual([(a["incident_key"], a["action"], a["operator"]) for a in body["actions"]],
                         [("a2", "unblock_ip", "kim"), ("a1", "block_ip", "han")])
        self.assertEqual(body["actions"][0]["created_at"], self.ago(100).isoformat())
        self.assertEqual(body["block"], listed["block"])
        self.assertEqual((body["exempt"], body["absorbed"]), (None, 2))
        self.assertEqual(body["checkers"], {"gateway_stale": False, "fw_stale": True})

    async def test_차단_금지_대역(self):
        body = await self.detail(D)
        self.assertEqual((body["summary"]["exempt"], body["exempt"]), (True, {"cidr": "10.0.0.0/8", "note": "사설 · AWS VPC"}))
        body = await self.detail(F)
        self.assertEqual((body["summary"]["exempt"], body["exempt"]), (True, {"cidr": "198.51.100.96/28", "note": "시험 제외"}))
        self.assertEqual((await self.detail(C))["summary"]["test_source"], True)

    async def test_차단_제외는_요약이_없어도_목록과_같이_판단한다(self):
        # 사건 있는 주소는 요약(목록 항목) 값과 같다
        for ip in (A, D, F):
            body = await self.detail(ip)
            self.assertEqual(body["exempt_flag"], body["summary"]["exempt"], ip)
        # 사건 없는 주소: 대역 밖 · block_exempt 표 대역 · 코드 상수 대역. 상수 대역은 표에 없어 exempt(든 대역 객체)가 null 이어도 참이다
        bodies = [await self.detail(ip) for ip in (G, X1, X2)]
        self.assertEqual([(b["summary"], b["exempt_flag"]) for b in bodies], [(None, False), (None, True), (None, True)])
        self.assertEqual([b["exempt"] for b in bodies], [None, {"cidr": "198.51.100.96/28", "note": "시험 제외"}, None])

    async def test_이벤트만_있는_출발지는_요약이_없다(self):
        body = await self.detail(G)
        self.assertEqual((body["summary"], body["incidents"], body["incidents_total"], body["actions"], body["block"],
                          body["absorbed"]), (None, [], 0, [], None, 0))
        self.assertEqual(body["last_seen"], self.ago(9).isoformat())
        self.assertEqual([(k["eventid"], k["count"]) for k in body["event_kinds"]],
                         [("cowrie.client.kex", 2), ("cowrie.client.version", 1)])
        self.assertEqual(body["fingerprints"]["hassh"], [{"value": H1, "count": 1}, {"value": H2, "count": 1}])
        self.assertEqual(body["fingerprints"]["ssh_version"], [])

    async def test_없는_출발지는_404_주소가_아니면_422(self):
        for ip in ("192.0.2.250", "192.0.2.201"):       # 없음 · 시험 자료 이벤트뿐
            with self.subTest(ip=ip), self.assertRaises(HTTPException) as caught:
                await self.detail(ip)
            self.assertEqual(caught.exception.status_code, 404)
        with self.assertRaises(HTTPException) as caught:
            await self.detail("198.51.100.0/24")
        self.assertEqual(caught.exception.status_code, 422)
        # IPv6 는 정규화해 찾는다
        self.assertEqual((await self.detail("2001:DB8:0::1"))["summary"]["incidents"], 3)

    async def test_감사_기록이나_콘솔_로그인만_있는_주소는_조회자에게_없는_출발지다(self):
        # 감사 행의 src_ip 는 우리 DB 접속 주소, 콘솔 로그인은 우리 사용자의 접속이다. 관리자 전용 기록이 주소별로 새지 않는다
        self.assertEqual(self.request.state.user["r"], "viewer")
        for ip in (AUD, CON):
            with self.subTest(ip=ip), self.assertRaises(HTTPException) as caught:
                await self.detail(ip)
            self.assertEqual(caught.exception.status_code, 404)

    async def test_사건_없는_주소는_콘솔_감사_기록을_싣지_않는다(self):
        body = await self.detail(MIX)
        # 콘솔 로그인(6분 전) · 감사(5분 전)가 더 늦지만 마지막 관측도 실제 이벤트만 본다
        self.assertEqual((body["summary"], body["last_seen"]), (None, self.ago(20).isoformat()))
        self.assertEqual([(k["sensor"], k["eventid"], k["count"]) for k in body["event_kinds"]],
                         [("cowrie", "cowrie.session.connect", 1)])

    async def test_사건_있는_주소는_콘솔_기록을_싣고_감사_기록은_싣지_않는다(self):
        # A 에는 감사 행이 있지만 이벤트 종류 · 노린 대상에 없다(목록 시험의 A 도 같다)
        self.assertEqual(await self.conn.fetchval(
            "SELECT count(*) FROM events WHERE src_ip = $1::inet AND sensor = 'audit'", A), 1)
        body = await self.detail(A)
        self.assertNotIn("audit", {k["sensor"] for k in body["event_kinds"]})
        self.assertEqual(body["summary"]["targets"], ["aws-sensor"])
        # 콘솔 무차별 대입 출발지(D)의 로그인 실패는 근거로 남는다
        body = await self.detail(D)
        self.assertEqual([(k["sensor"], k["eventid"], k["count"]) for k in body["event_kinds"]],
                         [("console", "console.login.failed", 1)])
        self.assertEqual((body["summary"]["targets"], body["last_seen"]), (["console"], self.ago(60).isoformat()))

    async def test_시간_상한은_트랜잭션_안에만_걸린다(self):
        await self.detail(A)
        self.assertEqual(await self.conn.fetchval("SHOW statement_timeout"), "0")


class MissingTablesTests(Base):
    """생존 신호 · 흡수 기록 · 차단 금지 표가 없는 DB. 그 값은 null 이고 나머지는 그대로다."""
    with_exempt = False
    with_heartbeats = False
    with_absorbed = False

    async def test_표가_없으면_null(self):
        body = await self.listing(include_test=True)
        self.assertEqual(body["checkers"], {"gateway_stale": None, "fw_stale": None})
        # 코드 상수 대역(D)만 참이고 나머지는 모른다. 표에만 있던 대역(F)도 모른다
        self.assertEqual({i["ip"]: i["exempt"] for i in body["items"]},
                         {A: None, B: None, C: None, D: True, E: None, F: None})
        detail = await self.detail(A)
        self.assertEqual((detail["exempt"], detail["absorbed"], detail["checkers"]),
                         (None, None, {"gateway_stale": None, "fw_stale": None}))
        self.assertEqual(detail["incidents_total"], 3)

    async def test_표가_없으면_차단_제외는_코드_상수_대역만_안다(self):
        # 사건 없는 주소도 목록과 같다: 대역 밖 · 표에만 있던 대역은 모르고(null) 코드 상수 대역은 참이다
        self.assertEqual([(await self.detail(ip))["exempt_flag"] for ip in (G, X1, X2)], [None, None, True])
        self.assertEqual((await self.detail(A))["exempt_flag"], None)


class TopActorsTests(Base):
    async def test_요약_상위_출발지는_순위로_심각도를_고른다(self):
        import main
        rows = await self.conn.fetch(main.TOP_ACTORS_SQL)
        self.assertEqual([(r["ip"], r["n"], r["sev"]) for r in rows],
                         [(A, 3, "critical"), (E, 3, "high"), (B, 2, "critical"), (D, 1, "low"), (F, 1, "low"),
                          (C, 1, "high")])


if __name__ == "__main__":
    unittest.main()
