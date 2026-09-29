"""관제 대상별 상태판(targets.py · 이슈 #52)의 PostgreSQL 시험.  OPSLOOP_TEST_DATABASE_URL=... python3 -m unittest discover -s app

연결 전용 임시 표만 쓰고 search_path=pg_temp 로 운영 표를 가린다. 생존 신호 표(sensor_heartbeats)는 계약서 1장 DDL 을
그대로 임시 표로 만든다(트리거 · 권한은 infra/test_status_board_db.py 가 본다). CTI 표는 마이그레이션(20260925_cti.sql)의
표 정의를 그대로 쓴다. 규칙 정의는 실제 규칙 파일(detector/rules*.json)을 넣는다.

  - 대상별 집계: 최근 1시간(경계 포함) · 높은 심각도 · 미판정(기간 무관) · AWS 발생원 나눔 · 한 사건이 여러 대상 ·
    붙이지 못한 사건(규칙 정의 없음 · 이벤트가 없는 섞인 규칙) · 24시간 밖 판정된 사건은 읽지 않음 · 최근 중요 탐지
  - 사건 → 대상: node:<id> · user:… · 근거의 발생원 · 규칙 발생원 · 섞인 규칙은 이벤트(실제 · 창 안 · 규칙 이벤트)로 고름.
    이벤트 조회는 섞인 규칙의 사건만 한 번의 묶음 질의로 한다
  - 수집: 업로더 생존 신호(떼어 둔 호스트의 남은 행은 보지 않음) · 노드 수신(/api/nodes 와 같은 판정) · 탐지 실행 ·
    적재기 · 집행기 확인. 모의(simulated) 로그는 로그 시각에 넣지 않는다
  - 시스템: web-01 최신 지표 · 오래됨(10분 경계) · 행 없음 · 표 없음(권한 없음으로 흉내)
  - 대응: 지점별 적용 확인 · 미확인(해제 · 만료 · 만료 없음 · 집행 제외는 세지 않음, 만료 경계) · 차단 금지 대역(코드 상수 +
    block_exempt) · 차단 보고 신호
  - 취약점: 자산별 수 · KEV · 오래됨(48시간) · 자산 없음 · CTI 표 없음
  - 표가 없는 DB: 생존 신호 표 없음 → heartbeats_available=false · 미확인. node_metrics 없음 → no_privilege
  - 등록 노드(이슈 #64): 노드를 하나 더 등록하면 카드가 하나 늘고(고정 대상 뒤 · node_id 순, 폐기 노드는 없음) 고정 네 대상 ·
    미분류는 그대로다. 그 노드의 이벤트(수집 · 로그) · 사건(발생원 · node:<id> · 노드 에이전트 이벤트)이 그 카드로 가고
    미분류에서 빠진다. web-01 의 노드 에이전트 사건은 이벤트로 고르고 고르지 못해도 web-01 이다.
    nodes 는 운영 콘솔처럼 열 권한만 있어도 읽고, 권한 · 표가 없으면 고정 네 대상만이다(web-01 수신은 미확인.
    카드 열 hostname 만 없으면 web-01 은 그대로)
"""
import json
import os
import unittest
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import operations as ops
import targets as t

ROOT = Path(__file__).resolve().parents[1]
CTI_MIGRATION = ROOT / "infra" / "migrations" / "20260925_cti.sql"
RULE_FILES = sorted((ROOT / "detector").glob("rules*.json"))

BASE_TABLES = """
    CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text NOT NULL, rule_version text NOT NULL,
        rule_name text, severity text NOT NULL, actor_ip inet, target text, first_ts timestamptz NOT NULL,
        last_ts timestamptz NOT NULL, signal_count integer DEFAULT 1, evidence jsonb, status text DEFAULT 'open',
        created_at timestamptz DEFAULT now());
    CREATE TEMP TABLE verdicts (id bigserial PRIMARY KEY, incident_key text NOT NULL, verdict text NOT NULL,
        created_at timestamptz DEFAULT now());
    CREATE TEMP TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL);
    CREATE TEMP TABLE events (ts timestamptz NOT NULL, eventid text NOT NULL, src_ip inet, session text, url text,
        http_status integer, provenance text NOT NULL DEFAULT 'real', sensor text NOT NULL DEFAULT 'cowrie');
    CREATE INDEX ON events (src_ip);
    CREATE INDEX ON events (session);
    CREATE INDEX ON events (sensor, ts DESC);
    CREATE TEMP TABLE nodes (node_id text PRIMARY KEY, hostname text, role text, sensor text, addr inet, logs text[],
        status text NOT NULL DEFAULT 'pending', token_hash text, registered_at timestamptz, last_seen_at timestamptz,
        first_loaded_at timestamptz, last_loaded_at timestamptz);
    CREATE TEMP TABLE node_enrollments (id bigserial PRIMARY KEY, node_id text, token_hash text, issued_by text,
        issued_at timestamptz DEFAULT now(), expires_at timestamptz, used_at timestamptz, canceled_at timestamptz);
    CREATE TEMP TABLE detector_runs (id bigserial PRIMARY KEY, rule_version text, since timestamptz, until timestamptz,
        started_at timestamptz NOT NULL, finished_at timestamptz NOT NULL, incidents integer);
    CREATE TEMP TABLE blocklist (actor_ip inet PRIMARY KEY, reason text, incident_key text,
        created_at timestamptz DEFAULT now(), expires_at timestamptz, released_at timestamptz, method text,
        requested_by text, enforced_at timestamptz, enforce_note text, released_by text, enforcement jsonb);
    CREATE TEMP TABLE block_exempt (cidr cidr PRIMARY KEY, note text NOT NULL);
"""
METRICS_TABLE = """
    CREATE TEMP TABLE node_metrics (line_hash text PRIMARY KEY, node_id text NOT NULL, ts timestamptz NOT NULL,
        seq bigint, cpu_pct real, mem_used_pct real, mem_avail_mb integer, swap_used_pct real, disk_root_pct real,
        load1 real, nginx_active boolean, sshd_active boolean, loaded_at timestamptz NOT NULL DEFAULT now());
"""
# 계약서 1장 DDL 그대로(트리거 · 권한 제외)
HEARTBEATS_TABLE = """
    CREATE TEMP TABLE sensor_heartbeats (
        source     text        PRIMARY KEY,
        kind       text        NOT NULL CHECK (kind IN ('uploader', 'block_report')),
        role       text        NOT NULL CHECK (role IN ('sensor', 'gateway', 'fw')),
        host       text        NOT NULL,
        seen_at    timestamptz,
        checked_at timestamptz NOT NULL,
        problem    text
    );
"""


def cti_tables() -> str:
    """CTI 마이그레이션의 표 · 색인 정의(BEGIN; 뒤 ~ 권한 블록 앞)."""
    return CTI_MIGRATION.read_text().split("BEGIN;", 1)[1].split("\nDO $$", 1)[0]


class Recorder:
    """연결을 감싸 fetch 로 들어온 (질의, 인자)를 남긴다. 이벤트 조회가 몇 번 · 어느 사건에 도는지 본다."""

    def __init__(self, conn):
        self.conn, self.fetched = conn, []

    async def fetch(self, sql, *args):
        self.fetched.append((sql, args))
        return await self.conn.fetch(sql, *args)

    def __getattr__(self, name):
        return getattr(self.conn, name)


class Base(unittest.IsolatedAsyncioTestCase):
    with_heartbeats = True
    with_metrics = True
    with_cti = True

    async def asyncSetUp(self):
        import asyncpg
        self.conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        await self.conn.execute("SET search_path TO pg_temp")
        await self.conn.execute(BASE_TABLES)
        if self.with_metrics:
            await self.conn.execute(METRICS_TABLE)
        if self.with_heartbeats:
            await self.conn.execute(HEARTBEATS_TABLE)
        if self.with_cti:
            await self.conn.execute(cti_tables())
        for path in RULE_FILES:
            doc = json.loads(path.read_text())
            await self.conn.execute("INSERT INTO rule_versions VALUES ($1, $2::jsonb)", doc["rule_version"],
                                    path.read_text())
        self.now = await self.conn.fetchval("SELECT now()")
        self.request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
            pool=SimpleNamespace(acquire=self.acquire))), state=SimpleNamespace(user={"u": "tester", "r": "viewer"}))

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def asyncTearDown(self):
        await self.conn.close()

    def ago(self, seconds):
        return self.now - timedelta(seconds=seconds)

    async def incident(self, key, rule, version, severity, actor, first, last=None, target=None, evidence=None,
                       judged=False):
        await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
            actor_ip, target, first_ts, last_ts, evidence) VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10::jsonb)""",
            key, rule, version, f"{rule} 시험 규칙", severity, actor, target, self.ago(first),
            self.ago(first if last is None else last), json.dumps(evidence) if evidence is not None else None)
        if judged:
            await self.conn.execute("INSERT INTO verdicts (incident_key, verdict) VALUES ($1, 'threat')", key)

    async def event(self, seconds, eventid, sensor, ip=None, provenance="real", session=None, url=None, status=None):
        await self.conn.execute("""INSERT INTO events (ts, eventid, src_ip, provenance, sensor, session, url, http_status)
            VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8)""", self.ago(seconds), eventid, ip, provenance, sensor, session, url,
                                status)

    def window_at(self, offset, window=600, back=1500):
        """탐지의 고정 창(초 단위 시각 ÷ 창, 내림)에 맞춘 '몇 초 전'. back 초보다 앞선 창의 시작 + offset 초.
        창 경계가 지금 시각에 따라 움직이므로, 시험 자료를 창 안에 두려면 창 시작에서 잰다."""
        epoch = self.now.timestamp()
        start = int(epoch - back) // window * window
        return epoch - (start + offset)

    async def view(self, conn=None):
        return await t.targets_view(conn or self.conn, self.now)


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class TargetsDatabaseTests(Base):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        # (키, 규칙, 버전, 심각도, 출발지, 첫 시각(초 전), 끝 시각, 대상, 근거, 판정됨)
        for row in [
                ("c-new", "R001", "v3", "medium", "192.0.2.10", 600, 300, None, None, False),
                ("c-edge", "R004", "v3", "high", "192.0.2.11", 3600, None, None, None, True),     # 1시간 경계(포함)
                ("c-out", "R003", "v3", "critical", "192.0.2.12", 3601, None, None, None, False),
                ("w-mixed", "R101", "w2", "medium", "198.51.100.20", self.window_at(100), None, None, None, False),
                ("w-none", "R102", "w2", "low", "198.51.100.21", 1200, None, None, None, False),
                ("w-upload", "R104", "w2", "high", "198.51.100.22", 300, None, None, None, True),
                ("node", "R301", "i2", "high", None, 7200, 1800, "node:web-01", None, False),
                ("audit", "R201", "a1", "high", None, 100, None, "user:han", None, False),
                ("self", "R202", "s1", "high", "10.0.0.5", 200, None, None, None, False),
                ("cve", "R106", "c1", "medium", "198.51.100.70", 400, None, None,
                 {"signatures": ["apache-path-traversal"], "sensors": ["decoy", "web-01"]}, True),
                ("old", "R001", "v3", "high", "192.0.2.13", 90000, None, None, None, True),        # 25시간 전 · 판정됨
                ("old-pending", "R001", "v3", "low", "192.0.2.14", 200000, None, None, None, False),
                ("nodef", "R999", "zz", "medium", "192.0.2.15", 500, None, None, None, False)]:
            key, rule, version, severity, actor, first, last, target, evidence, judged = row
            await self.incident(key, rule, version, severity, actor, first, last, target, evidence, judged)
        # 섞인 규칙의 실제 발생원. w-mixed(R101 w2, 창 600초 · 임계치 5)는 한 창 안의 디코이 2 · web-01 3 로그인 실패로 떴다.
        #   탐지처럼 끝 시각은 그 창의 첫 행이다. 앞 창의 콘솔 실패 · 모의 콘솔 · 규칙 밖 이벤트는 들지 않는다
        w = self.window_at
        for seconds, eventid, sensor, ip, prov in [
                (w(100), "decoy.login.failed", "decoy", "198.51.100.20", "real"),
                (w(150), "decoy.login.failed", "decoy", "198.51.100.20", "real"),
                (w(200), "sshd.login.failed", "web-01", "198.51.100.20", "real"),
                (w(300), "sshd.login.failed", "web-01", "198.51.100.20", "real"),
                (w(400), "sshd.login.failed", "web-01", "198.51.100.20", "real"),
                (w(-300), "console.login.failed", "console", "198.51.100.20", "real"),
                (w(250), "console.login.failed", "console", "198.51.100.20", "simulated"),
                (w(250), "decoy.request", "gateway", "198.51.100.20", "real"),
                (300, "console.action.upload", "console", "198.51.100.22", "real"),
                (1800, "cowrie.session.connect", "cowrie", "192.0.2.10", "real"),
                (10, "gateway.request", "gateway", "192.0.2.10", "simulated")]:
            await self.event(seconds, eventid, sensor, ip, prov)
        await self.conn.execute("INSERT INTO block_exempt VALUES ('198.51.100.64/26', '시험 금지 대역')")
        # 생존 신호: 센서 업로더 · 관문 업로더 · 떼어 둔 호스트의 남은 행 · 관문 · 내부 방화벽 차단 보고
        for source, kind, role, host, seen, checked, problem in [
                ("uploader:i-0123456789abcdef0", "uploader", "sensor", "i-0123456789abcdef0", 180, 60, None),
                ("uploader:i-0fedcba9876543210", "uploader", "gateway", "i-0fedcba9876543210", 120, 60, None),
                ("uploader:i-0aaaaaaaaaaaaaaaa", "uploader", "sensor", "i-0aaaaaaaaaaaaaaaa", 172800, 172800, None),
                ("block:gateway", "block_report", "gateway", "i-0fedcba9876543210", 120, 30, None),
                ("block:fw", "block_report", "fw", "fw-opsloop", None, 30, "보고 파일 없음")]:
            await self.conn.execute("""INSERT INTO sensor_heartbeats VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                                    source, kind, role, host, self.ago(seen) if seen is not None else None,
                                    self.ago(checked), problem)
        await self.conn.execute("""INSERT INTO nodes (node_id, sensor, status, registered_at, last_seen_at, last_loaded_at)
            VALUES ('web-01', 'web-01', 'active', $1, $2, $2)""", self.ago(172800), self.ago(120))
        await self.conn.execute("INSERT INTO detector_runs (rule_version, started_at, finished_at) VALUES ('v3', $1, $1), ('v3', $2, $2)",
                                self.ago(240), self.ago(3600))
        for line, node, seconds, cpu in [("m1", "web-01", 60, 12.34), ("m2", "web-01", 120, 90.0), ("m3", "web-02", 10, 1.0)]:
            await self.conn.execute("""INSERT INTO node_metrics (line_hash, node_id, ts, cpu_pct, mem_used_pct, disk_root_pct, load1)
                VALUES ($1, $2, $3, $4, 41.5, 73.5, 0.5)""", line, node, self.ago(seconds), cpu)
        live = self.now + timedelta(hours=1)
        both = {"gateway": {"state": "confirmed"}, "fw": {"state": "confirmed"}}
        for ip, expires, released, note, enforcement in [
                ("203.0.113.1", live, None, None, both),
                ("203.0.113.2", live, None, None, {"gateway": {"state": "confirmed"}, "fw": {"state": "pending"}}),
                ("203.0.113.3", live, None, None, None),
                ("203.0.113.4", live, self.now, None, both),                           # 해제
                ("203.0.113.5", self.now, None, None, both),                            # 만료(경계)
                ("203.0.113.6", None, None, None, None),                                # 만료 없음(집행 제외)
                ("203.0.113.7", live, None, "집행 제외 · 금지 대역", None),
                ("203.0.113.8", live, None, None, {"gateway": {"state": "stale"}, "fw": {"state": "failed"}})]:
            await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, released_at, enforce_note, enforcement)
                VALUES ($1, $2, $3, $4, $5::jsonb)""", ip, expires, released, note,
                json.dumps(enforcement) if enforcement is not None else None)
        snap = await self.conn.fetchval("""INSERT INTO cti_snapshots (source, s3_key, status)
            VALUES ('osv', 'cti/v1/source=osv/x.json', 'ok') RETURNING id""")
        await self.conn.execute("""INSERT INTO cti_kev (cve_id, vendor_project, product, name, date_added, snapshot_id)
            VALUES ('CVE-2024-1086', 'Linux', 'Kernel', '시험', '2024-05-30', $1)""", snap)
        for osv, cve in [("UBUNTU-CVE-2024-1086", "CVE-2024-1086"), ("UBUNTU-CVE-2026-82474", "CVE-2026-82474")]:
            await self.conn.execute("INSERT INTO cti_osv (osv_id, cve_id, snapshot_id) VALUES ($1, $2, $3)", osv, cve, snap)
        for asset_id, role, collected in [("web-01", "target", 3600), ("honeypot-dmz", "sensor", 49 * 3600),
                                          ("console-a", "platform", 3600)]:
            await self.conn.execute("""INSERT INTO asset_inventory (asset_id, role, method, collected_at, checked_at)
                VALUES ($1, $2, 'ssh', $3, $3)""", asset_id, role, self.ago(collected))
        for osv, cve in [("UBUNTU-CVE-2024-1086", "CVE-2024-1086"), ("UBUNTU-CVE-2026-82474", "CVE-2026-82474")]:
            await self.conn.execute("""INSERT INTO asset_vulnerabilities (asset_id, source_package, version, osv_id, cve_id,
                fix_state, snapshot_id) VALUES ('web-01', 'linux', '1', $1, $2, 'fix_available', $3)""", osv, cve, snap)

    def target(self, body, tid):
        return next(x for x in body["targets"] if x["id"] == tid)

    async def node(self, node_id, status="active", hostname=None, sensor=None, registered=172800, seen=60):
        await self.conn.execute("""INSERT INTO nodes (node_id, hostname, sensor, status, registered_at, last_seen_at,
            last_loaded_at) VALUES ($1, $2, $3, $4, $5, $6, $6)""", node_id, hostname, sensor, status,
            self.ago(registered) if registered is not None else None, self.ago(seen) if seen is not None else None)

    async def test_대상별_보안_집계와_붙이지_못한_사건(self):
        body = await self.view()
        self.assertEqual([x["id"] for x in body["targets"]], ["aws-sensor", "web-01", "console", "data-node"])
        sec = {x["id"]: x["security"] for x in body["targets"]}
        counts = {tid: (s["incidents_1h"], s["high_1h"], s["pending"]) for tid, s in sec.items()}
        self.assertEqual(counts, {"aws-sensor": (4, 1, 4), "web-01": (2, 0, 2), "console": (2, 2, 1),
                                  "data-node": (1, 1, 1)})
        self.assertEqual([(p["key"], p["incidents_1h"], p["pending"]) for p in sec["aws-sensor"]["parts"]],
                         [("cowrie", 2, 3), ("decoy", 2, 1), ("gateway", 0, 0)])
        # 섞인 규칙인데 이벤트가 없는 사건(w-none) · 규칙 정의가 없는 사건(nodef)
        self.assertEqual(body["unmapped"], {"incidents_1h": 2, "pending": 2})
        latest = {tid: (s["latest"] or {}).get("incident_key") for tid, s in sec.items()}
        self.assertEqual(latest, {"aws-sensor": "c-edge", "web-01": "node", "console": "audit", "data-node": "self"})
        self.assertEqual(sec["aws-sensor"]["latest"], {
            "incident_key": "c-edge", "rule_id": "R004", "rule_name": "R004 시험 규칙", "severity": "high",
            "actor_ip": "192.0.2.11", "target": None, "last_ts": t.cti.iso(self.ago(3600)), "judged": True})
        self.assertEqual((sec["web-01"]["latest"]["target"], sec["web-01"]["latest"]["actor_ip"]), ("node:web-01", None))
        # 대시보드 미판정(판정 기록 없음 전체)과 같은 사건을 센다: 붙은 곳 ∪ 붙이지 못한 곳
        total = await self.conn.fetchval("SELECT count(*) FROM incidents i WHERE NOT EXISTS "
                                         "(SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key)")
        self.assertEqual(total, 9)
        json.dumps(body)

    async def test_섞인_규칙의_사건만_한_번에_이벤트로_고른다(self):
        conn = Recorder(self.conn)
        await self.view(conn)
        joins = [args for sql, args in conn.fetched if sql == t.JOIN_SQL]
        self.assertEqual(len(joins), 1)
        items = json.loads(joins[0][0])
        self.assertEqual(sorted(i["k"] for i in items), ["w-mixed", "w-none", "w-upload"])
        upload = next(i for i in items if i["k"] == "w-upload")
        self.assertEqual((upload["ids"], upload["lk"], upload["ss"]), (None, "%.action.upload", ["decoy", "console"]))
        # 규칙 정의는 쓰인 버전만 한 번 읽는다(25시간 전 판정된 사건은 읽지 않는다)
        rules = [args for sql, args in conn.fetched if sql == t.RULES_SQL]
        self.assertEqual(rules, [(["a1", "c1", "i2", "s1", "v3", "w2", "zz"],)])
        [(_, (incidents_args))] = [(sql, args) for sql, args in conn.fetched if sql == t.INCIDENTS_SQL]
        keys = [r["incident_key"] for r in await self.conn.fetch(t.INCIDENTS_SQL, *incidents_args)]
        self.assertNotIn("old", keys)
        self.assertIn("old-pending", keys)

    async def test_섞인_규칙의_발생원은_실제_창_안_규칙_이벤트로_고른다(self):
        attached = await t.attach_incidents(self.conn, [dict(r) for r in await self.conn.fetch(
            t.INCIDENTS_SQL, self.now, t.WINDOW_SECONDS, t.LATEST_HOURS)])
        self.assertEqual(attached["w-mixed"], {("aws-sensor", "decoy"), ("web-01", None)})
        self.assertEqual(attached["w-upload"], {("console", None)})
        self.assertEqual(attached["w-none"], set())
        self.assertEqual(attached["cve"], {("aws-sensor", "decoy"), ("web-01", None)})
        self.assertEqual(attached["node"], {("web-01", None)})
        self.assertEqual(attached["audit"], {("console", None)})
        self.assertEqual(attached["self"], {("data-node", None)})
        self.assertEqual(attached["nodef"], set())
        # 같은 창에서 끝 시각(첫 행) 뒤에 온 콘솔 로그인 실패도 탐지가 센 것이다. 콘솔에도 붙는다
        await self.event(self.window_at(450), "console.login.failed", "console", "198.51.100.20")
        attached = await t.attach_incidents(self.conn, [dict(r) for r in await self.conn.fetch(
            t.INCIDENTS_SQL, self.now, t.WINDOW_SECONDS, t.LATEST_HOURS)])
        self.assertEqual(attached["w-mixed"], {("aws-sensor", "decoy"), ("web-01", None), ("console", None)})

    async def test_수집_상태(self):
        body = await self.view()
        self.assertTrue(body["heartbeats_available"])
        aws = self.target(body, "aws-sensor")["collection"]
        self.assertEqual((aws["state"], aws["reason"]),
                         ("ok", "업로더 생존 신호 3분 전 · 적재기 확인 1분 전 · 최근 1시간 로그 있음"))
        self.assertEqual(aws["signal"], {"label": "업로더 생존 신호", "seen_at": t.cti.iso(self.ago(180)),
                                         "checked_at": t.cti.iso(self.ago(60)), "stale_after_seconds": 900,
                                         "problem": None})
        # 모의 관문 기록은 로그 시각에 넣지 않는다
        self.assertEqual([(l["key"], l["last_at"]) for l in aws["logs"]],
                         [("cowrie", t.cti.iso(self.ago(1800))), ("decoy", t.cti.iso(self.ago(self.window_at(150)))),
                          ("gateway", t.cti.iso(self.ago(self.window_at(250))))])
        web = self.target(body, "web-01")["collection"]
        self.assertEqual((web["state"], web["reason"]), ("ok", "노드 수신 2분 전 · 최근 1시간 로그 있음"))
        self.assertEqual(web["extra"], [{"label": "마지막 적재", "at": t.cti.iso(self.ago(120)), "note": None}])
        console = self.target(body, "console")["collection"]
        self.assertEqual((console["state"], console["signal"], console["logs"][0]["last_at"]),
                         ("unknown", None, t.cti.iso(self.ago(300))))
        data = self.target(body, "data-node")["collection"]
        self.assertEqual((data["state"], data["reason"], data["signal"]["seen_at"]),
                         ("ok", "마지막 탐지 실행 4분 전", t.cti.iso(self.ago(240))))
        self.assertEqual(data["extra"], [{"label": "적재기 확인", "at": t.cti.iso(self.ago(60)), "note": None},
                                         {"label": "집행기 확인", "at": t.cti.iso(self.ago(30)), "note": None}])
        # 코우리 · 디코이 로그가 1시간 넘게 없으면 신호가 정상이어도 요청 없음이다
        await self.conn.execute("DELETE FROM events WHERE sensor IN ('cowrie', 'decoy')")
        aws = self.target(await self.view(), "aws-sensor")["collection"]
        self.assertEqual((aws["state"], aws["reason"]),
                         ("quiet", "업로더 생존 신호 3분 전 · 적재기 확인 1분 전 · 최근 1시간 요청 없음"))
        # 받기가 길어 기록이 늦었을 뿐이면(확인 때 신호가 5분 전) 신호 시각이 18분 전이어도 수신 없음이 아니다
        await self.conn.execute("UPDATE sensor_heartbeats SET seen_at = $1, checked_at = $2 WHERE source = 'uploader:i-0123456789abcdef0'",
                                self.ago(1080), self.ago(780))
        aws = self.target(await self.view(), "aws-sensor")["collection"]
        self.assertEqual(aws["state"], "quiet")
        # 확인 때 이미 15분 넘게 새 신호가 없었으면 수신 없음이다
        await self.conn.execute("UPDATE sensor_heartbeats SET seen_at = $1, checked_at = $2 WHERE source = 'uploader:i-0123456789abcdef0'",
                                self.ago(1100), self.ago(120))
        aws = self.target(await self.view(), "aws-sensor")["collection"]
        self.assertEqual((aws["state"], aws["reason"]),
                         ("no_signal", "업로더 생존 신호 18분 전 · 적재기 확인 2분 전 · 확인 때 이미 15분 넘게 새 신호 없음"))
        # 적재기가 30분 넘게 확인하지 않으면 미확인이다
        await self.conn.execute("UPDATE sensor_heartbeats SET checked_at = $1 WHERE kind = 'uploader'", self.ago(1801))
        aws = self.target(await self.view(), "aws-sensor")["collection"]
        self.assertEqual((aws["state"], aws["reason"]), ("unknown", "적재기 확인 중단 · 마지막 확인 30분 전"))
        data = self.target(await self.view(), "data-node")["collection"]
        self.assertEqual((data["state"], data["reason"], data["extra"][0]["note"]),
                         ("ok", "마지막 탐지 실행 4분 전 · 적재기 확인 중단 · 마지막 30분 전", "멈춤"))

    async def test_web_01_수신_판정은_노드_목록과_같다(self):
        cases = [("active", 172800, 120, "normal"), ("active", 172800, 601, "silent"), ("pending", None, None, "waiting"),
                 ("revoked", 172800, 60, "revoked"), ("active", 60, None, "waiting"), ("active", 1200, None, "silent")]
        for status, registered, seen, expected in cases:
            await self.conn.execute("UPDATE nodes SET status = $1, registered_at = $2, last_seen_at = $3 WHERE node_id = 'web-01'",
                                    status, self.ago(registered) if registered else None, self.ago(seen) if seen else None)
            listed = next(r for r in (await ops.nodes(self.request))["rows"] if r["node_id"] == "web-01")
            mine = await self.conn.fetchrow(t.NODE_SQL, "web-01", await self.conn.fetchval("SELECT now()"))
            with self.subTest(status=status, seen=seen):
                self.assertEqual((mine["reception"], listed["reception"]), (expected, expected))
        state = self.target(await self.view(), "web-01")["collection"]["state"]
        self.assertEqual(state, "no_signal")
        await self.conn.execute("DELETE FROM nodes")
        web = self.target(await self.view(), "web-01")["collection"]
        self.assertEqual((web["state"], web["reason"], web["extra"][0]["at"]), ("unknown", "노드 등록 기록 없음", None))

    async def test_시스템_지표(self):
        body = await self.view()
        self.assertTrue(body["metrics_available"])
        system = self.target(body, "web-01")["system"]
        self.assertEqual(system, {"state": "ok", "metrics": {"ts": t.cti.iso(self.ago(60)), "cpu_pct": 12.3,
                                                             "mem_used_pct": 41.5, "disk_root_pct": 73.5,
                                                             "load1": 0.5}})
        self.assertEqual([self.target(body, x)["system"]["state"] for x in ("aws-sensor", "console", "data-node")],
                         ["not_collected"] * 3)
        await self.conn.execute("DELETE FROM node_metrics WHERE line_hash = 'm1'")
        await self.conn.execute("UPDATE node_metrics SET ts = $1 WHERE line_hash = 'm2'", self.ago(601))
        self.assertEqual(self.target(await self.view(), "web-01")["system"]["state"], "stale")
        await self.conn.execute("UPDATE node_metrics SET ts = $1 WHERE line_hash = 'm2'", self.ago(600))
        self.assertEqual(self.target(await self.view(), "web-01")["system"]["state"], "ok")
        await self.conn.execute("DELETE FROM node_metrics WHERE node_id = 'web-01'")
        self.assertEqual(self.target(await self.view(), "web-01")["system"], {"state": "no_data", "metrics": None})

    async def test_대응은_지점이_확인한_것만_적용이다(self):
        body = await self.view()
        aws, web = self.target(body, "aws-sensor")["response"], self.target(body, "web-01")["response"]
        # 203.0.113.8 은 관문 stale(미확인) · 내부 방화벽 failed(실패). 실패는 미확인에 섞지 않는다
        self.assertEqual((aws["point"], aws["point_label"], aws["applied"], aws["failed"], aws["unverified"], aws["stalled"]),
                         ("gateway", "AWS 관문", 2, 0, 2, None))
        self.assertEqual((web["point"], web["point_label"], web["applied"], web["failed"], web["unverified"], web["stalled"]),
                         ("fw", "내부 방화벽", 1, 1, 2, None))
        self.assertEqual(aws["report"], {"seen_at": t.cti.iso(self.ago(120)), "checked_at": t.cti.iso(self.ago(30)),
                                         "problem": None})
        self.assertEqual(web["report"], {"seen_at": None, "checked_at": t.cti.iso(self.ago(30)),
                                         "problem": "보고 파일 없음"})
        # 차단 금지 대역: block_exempt(198.51.100.64/26) · 코드 상수(10.0.0.0/8). 대상에 붙은 사건의 서로 다른 출발지
        self.assertEqual({x["id"]: x["response"]["exempt"] for x in body["targets"]},
                         {"aws-sensor": 1, "web-01": 1, "console": 0, "data-node": 1})
        for tid in ("console", "data-node"):
            r = self.target(body, tid)["response"]
            self.assertEqual((r["point"], r["applied"], r["failed"], r["unverified"], r["report"], r["stalled"]),
                             (None, None, None, None, None, None))
        # 집행기가 10분 넘게 확인하지 않으면 옛 '적용 확인' 을 믿지 않는다. 적용 · 실패 · 미확인을 모두 미확인으로 합친다
        await self.conn.execute("UPDATE sensor_heartbeats SET checked_at = $1 WHERE source = 'block:gateway'", self.ago(601))
        await self.conn.execute("DELETE FROM sensor_heartbeats WHERE source = 'block:fw'")
        body = await self.view()
        aws, web = self.target(body, "aws-sensor")["response"], self.target(body, "web-01")["response"]
        self.assertEqual((aws["applied"], aws["failed"], aws["unverified"], aws["stalled"]),
                         (0, 0, 4, "집행기 확인 중단 · 마지막 확인 10분 전"))
        self.assertEqual((web["applied"], web["failed"], web["unverified"], web["stalled"]), (0, 0, 4, "집행기 확인 기록 없음"))
        self.assertEqual(self.target(body, "data-node")["collection"]["extra"][1]["note"], "멈춤")

    async def test_취약점(self):
        body = await self.view()
        web = self.target(body, "web-01")["vulns"]
        self.assertEqual(web, {"available": True, "assets": [{
            "asset_id": "web-01", "vuln_total": 2, "vuln_kev": 1, "collected_at": t.cti.iso(self.ago(3600)),
            "checked_at": t.cti.iso(self.ago(3600)), "stale": False, "missing": False}]})
        aws = self.target(body, "aws-sensor")["vulns"]["assets"]
        self.assertEqual([(a["asset_id"], a["stale"], a["missing"], a["vuln_total"]) for a in aws],
                         [("honeypot-dmz", True, False, 0), ("gateway", True, True, 0)])
        console = self.target(body, "console")["vulns"]["assets"]
        self.assertEqual([(a["asset_id"], a["missing"]) for a in console], [("console-a", False), ("console-b", True)])
        self.assertEqual(self.target(body, "data-node")["vulns"]["assets"][0]["missing"], True)

    async def test_출발지_빈도_규칙은_탐지와_같은_조건으로_발생원을_고른다(self):
        # R102 w2(404 · 제외 경로 · 창 600초 · 임계치 5). web-01 404 다섯 건으로 떴고, 같은 창의 디코이 요청은 200 · 제외 경로다
        await self.incident("w-404", "R102", "w2", "medium", "198.51.100.30", self.window_at(50))
        w = self.window_at
        for off in (50, 60, 70, 80, 90):
            await self.event(w(off), "nginx.request", "web-01", "198.51.100.30", url="/wp-login.php", status=404)
        await self.event(w(100), "decoy.request", "decoy", "198.51.100.30", url="/admin", status=200)
        await self.event(w(110), "decoy.request", "decoy", "198.51.100.30", url="/robots.txt", status=404)
        # 임계치에 못 미친 앞 창의 디코이 404 는 사건에 들지 않았다
        await self.event(w(-100), "decoy.request", "decoy", "198.51.100.30", url="/x", status=404)
        rows = [dict(r) for r in await self.conn.fetch(t.INCIDENTS_SQL, self.now, t.WINDOW_SECONDS, t.LATEST_HOURS)]
        attached = await t.attach_incidents(self.conn, [r for r in rows if r["incident_key"] == "w-404"])
        self.assertEqual(attached["w-404"], {("web-01", None)})
        # 같은 창에 디코이 404 가 들어오면 그것도 탐지가 센 것이다
        await self.event(w(120), "decoy.request", "decoy", "198.51.100.30", url="/phpmyadmin", status=404)
        attached = await t.attach_incidents(self.conn, [r for r in rows if r["incident_key"] == "w-404"])
        self.assertEqual(attached["w-404"], {("web-01", None), ("aws-sensor", "decoy")})

    async def test_발생원_조건_없는_세션_규칙은_세션으로_나눈다(self):
        # v3 R002 는 sessions 표 전체를 본다. 디코이 세션에서 뜬 사건은 웹 디코이, 세션 근거가 없으면 전처럼 Cowrie 다
        for key, sessions in [("s-decoy", ["d1"]), ("s-both", ["d2", "c2"]), ("s-cowrie", ["c3"]), ("s-bare", None)]:
            await self.incident(key, "R002", "v3", "high", "192.0.2.40", 300,
                                evidence={"sessions": sessions} if sessions else {})
        for session, sensor, eventid in [("d1", "decoy", "decoy.login.success"), ("d1", "decoy", "decoy.action.view"),
                                         ("d2", "decoy", "decoy.action.view"), ("c2", "cowrie", "cowrie.command.input"),
                                         ("c3", "cowrie", "cowrie.command.input"), ("c3", "gateway", "gateway.request")]:
            await self.event(300, eventid, sensor, "192.0.2.40", session=session)
        rows = [dict(r) for r in await self.conn.fetch(t.INCIDENTS_SQL, self.now, t.WINDOW_SECONDS, t.LATEST_HOURS)]
        conn = Recorder(self.conn)
        attached = await t.attach_incidents(conn, [r for r in rows if r["incident_key"].startswith("s-")])
        self.assertEqual({k: attached[k] for k in ("s-decoy", "s-both", "s-cowrie", "s-bare")}, {
            "s-decoy": {("aws-sensor", "decoy")}, "s-both": {("aws-sensor", "decoy"), ("aws-sensor", "cowrie")},
            "s-cowrie": {("aws-sensor", "cowrie")}, "s-bare": {("aws-sensor", "cowrie")}})
        self.assertEqual(len([1 for sql, _ in conn.fetched if sql == t.SESSION_JOIN_SQL]), 1)

    async def test_CTI_표는_있고_권한이_없으면_취약점만_정보_없음이다(self):
        # 역할 블록만 다시 적용한 상태: 콘솔 역할이 CTI 표를 못 읽는다. 상태판이 500 이 아니라 취약점 구역만 물러난다
        before = await self.view()
        role = "opsloop_t52_no_cti"
        await self.conn.execute(f"DROP ROLE IF EXISTS {role}")
        await self.conn.execute(f"CREATE ROLE {role} NOLOGIN")
        try:
            for table in ("incidents", "verdicts", "rule_versions", "events", "nodes", "detector_runs", "blocklist",
                          "block_exempt", "node_metrics", "sensor_heartbeats"):
                await self.conn.execute(f"GRANT SELECT ON pg_temp.{table} TO {role}")
            await self.conn.execute(f"SET ROLE {role}")
            async with self.conn.transaction(isolation="repeatable_read", readonly=True):
                body = await self.view()
            # 같은 선검사(cti.TABLES_SQL)를 쓰는 CVE 배지도 권한 오류 대신 available=false 다
            badges = await t.cti.cti_badges(self.request, key=["cve"])
            await self.conn.execute("RESET ROLE")
        finally:
            await self.conn.execute("RESET ROLE")
            await self.conn.execute(f"DROP OWNED BY {role}")
            await self.conn.execute(f"DROP ROLE {role}")
        self.assertEqual([x["vulns"] for x in body["targets"]], [{"available": False, "assets": []}] * 4)
        strip = lambda b: [{k: v for k, v in x.items() if k != "vulns"} for x in b["targets"]]
        self.assertEqual(strip(body), strip(before))
        self.assertEqual((body["heartbeats_available"], body["metrics_available"]), (True, True))
        self.assertEqual((badges["available"], badges["badges"]), (False, {}))

    async def test_노드를_하나_더_등록하면_카드가_늘고_고정_대상은_그대로다(self):
        # web-01 의 노드 에이전트 사건(n1 R101): 한 창의 web-01 sshd 실패 다섯 건 · 이벤트가 없는 사건
        w = self.window_at
        await self.incident("n-web01", "R101", "n1", "medium", "198.51.100.40", w(10))
        for off in (10, 20, 30, 40, 50):
            await self.event(w(off), "sshd.login.failed", "web-01", "198.51.100.40")
        await self.incident("n-bare", "R101", "n1", "low", "198.51.100.41", 900)
        before = await self.view()
        self.assertEqual(len(before["targets"]), 4)
        await self.node("web-02", hostname="web02.lab", sensor="web-02")
        await self.node("web-03", status="pending", registered=None, seen=None)
        await self.node("probe-01", status="revoked", sensor="probe-01")
        conn = Recorder(self.conn)
        body = await self.view(conn)
        self.assertEqual([(x["id"], x["kind"]) for x in body["targets"]],
                         [("aws-sensor", "fixed"), ("web-01", "fixed"), ("console", "fixed"), ("data-node", "fixed"),
                          ("web-02", "node"), ("web-03", "node")])
        # 고정 네 대상(web-01 값 포함) · 미분류는 노드를 등록하기 전과 같다. n1 R101 은 이제 이벤트로 고르고(web-01),
        #   이벤트가 없는 사건은 전처럼 web-01 이다
        self.assertEqual(body["targets"][:4], before["targets"][:4])
        self.assertEqual(body["unmapped"], before["unmapped"])
        joins = [json.loads(args[0]) for sql, args in conn.fetched if sql == t.JOIN_SQL]
        self.assertEqual(len(joins), 1)
        self.assertEqual(sorted(i["k"] for i in joins[0]), ["n-bare", "n-web01", "w-mixed", "w-none", "w-upload"])
        self.assertEqual(self.target(body, "web-01")["security"]["pending"], 4)      # 전의 2 + n-web01 · n-bare
        web02 = self.target(body, "web-02")
        self.assertEqual((web02["label"], web02["role"]), ("web02.lab", "등록 노드"))
        self.assertEqual((web02["collection"]["state"], web02["collection"]["reason"]),
                         ("quiet", "노드 수신 1분 전 · 최근 1시간 요청 없음"))
        self.assertEqual(web02["collection"]["logs"], [{"key": "web-02", "label": "web02.lab 로그", "last_at": None}])
        self.assertEqual(web02["collection"]["extra"], [{"label": "마지막 적재", "at": t.cti.iso(self.ago(60)), "note": None}])
        # 지표를 보내는 노드(node_metrics 에 web-02 행이 있다)는 실값이다
        self.assertEqual(web02["system"], {"state": "ok", "metrics": {"ts": t.cti.iso(self.ago(10)), "cpu_pct": 1.0,
                                                                     "mem_used_pct": 41.5, "disk_root_pct": 73.5,
                                                                     "load1": 0.5}})
        self.assertEqual({k: web02["response"][k] for k in ("point", "applied", "failed", "unverified", "exempt")},
                         {"point": None, "applied": None, "failed": None, "unverified": None, "exempt": 0})
        self.assertEqual(web02["vulns"], {"available": True, "assets": []})
        self.assertEqual(web02["security"], {"incidents_1h": 0, "high_1h": 0, "pending": 0, "parts": [], "latest": None})
        web03 = self.target(body, "web-03")
        self.assertEqual((web03["label"], web03["collection"]["state"], web03["collection"]["reason"], web03["system"]),
                         ("web-03", "unknown", "노드 등록 대기 · 수신 전", {"state": "not_collected", "metrics": None}))
        self.assertEqual(web03["collection"]["logs"][0]["key"], "web-03")          # 발생원이 없으면 node_id
        # 같은 이름의 자산이 있으면 그 자산이다
        await self.conn.execute("""INSERT INTO asset_inventory (asset_id, role, method, collected_at, checked_at)
            VALUES ('web-02', 'target', 'ssh', $1, $1)""", self.ago(3600))
        self.assertEqual([(a["asset_id"], a["missing"]) for a in self.target(await self.view(), "web-02")["vulns"]["assets"]],
                         [("web-02", False)])
        json.dumps(body)

    async def test_등록_노드의_이벤트와_사건은_그_카드로_가고_미분류에서_빠진다(self):
        await self.node("web-02", hostname="web02.lab", sensor="web-02")
        w = self.window_at
        # n1 R101: 한 창의 web-02 sshd 실패 다섯 건
        await self.incident("n-web02", "R101", "n1", "high", "198.51.100.50", w(10))
        for off in (10, 20, 30, 40, 50):
            await self.event(w(off), "sshd.login.failed", "web-02", "198.51.100.50")
        # url_signature: 근거의 발생원 · 차단 금지 대역(198.51.100.64/26) 출발지
        await self.event(300, "nginx.request", "web-02", "198.51.100.71")
        await self.incident("u-web02", "R106", "c1", "medium", "198.51.100.71", 300, None, None,
                            {"signatures": ["apache-path-traversal"], "sensors": ["web-02"]})
        await self.incident("s-web02", "R301", "i2", "high", None, 600, None, "node:web-02")
        await self.incident("s-probe", "R301", "i2", "high", None, 600, None, "node:probe-01")   # 등록되지 않은 노드
        body = await self.view()
        web02 = self.target(body, "web-02")
        self.assertEqual((web02["security"]["incidents_1h"], web02["security"]["high_1h"], web02["security"]["pending"]),
                         (3, 2, 3))
        self.assertEqual(web02["security"]["latest"]["incident_key"], "s-web02")
        self.assertEqual(web02["response"]["exempt"], 1)
        self.assertEqual((web02["collection"]["state"], web02["collection"]["logs"][0]["last_at"]),
                         ("ok", t.cti.iso(self.ago(300))))
        # web-01 은 web-02 의 sshd 사건을 가져가지 않는다(시험 자료의 web-01 값 그대로)
        self.assertEqual((self.target(body, "web-01")["security"]["incidents_1h"],
                          self.target(body, "web-01")["security"]["pending"]), (2, 2))
        # 미분류: 시험 자료(w-none · nodef) + 등록되지 않은 노드(s-probe)
        self.assertEqual(body["unmapped"], {"incidents_1h": 3, "pending": 3})
        # 등록을 지우면 지금처럼: sshd 사건은 web-01, 근거 · node:<id> 로만 붙던 사건은 미분류다
        await self.conn.execute("DELETE FROM nodes WHERE node_id = 'web-02'")
        bare = await self.view()
        self.assertEqual([x["id"] for x in bare["targets"]], ["aws-sensor", "web-01", "console", "data-node"])
        self.assertEqual((self.target(bare, "web-01")["security"]["incidents_1h"],
                          self.target(bare, "web-01")["security"]["high_1h"]), (3, 1))
        self.assertEqual(bare["unmapped"], {"incidents_1h": 5, "pending": 5})

    async def test_nodes_는_열_권한만_있어도_읽고_권한이_없으면_고정_네_대상만이다(self):
        await self.node("web-02", hostname="web02.lab", sensor="web-02")
        role = "opsloop_t64_nodes"
        columns = ("node_id, hostname, role, sensor, addr, logs, status, registered_at, last_seen_at, first_loaded_at, "
                   "last_loaded_at")       # 운영 콘솔의 열 권한(schema.sql, 임시 표에 없는 agent_fp · receipt 빼고)
        await self.conn.execute(f"DROP ROLE IF EXISTS {role}")
        await self.conn.execute(f"CREATE ROLE {role} NOLOGIN")
        seen = {}
        try:
            for table in ("incidents", "verdicts", "rule_versions", "events", "detector_runs", "blocklist",
                          "block_exempt", "node_metrics", "sensor_heartbeats"):
                await self.conn.execute(f"GRANT SELECT ON pg_temp.{table} TO {role}")
            for name, grant in [("columns", f"GRANT SELECT ({columns}) ON pg_temp.nodes TO {role}"),
                                ("no_hostname", f"REVOKE SELECT (hostname) ON pg_temp.nodes FROM {role}"),
                                ("none", f"REVOKE SELECT ({columns}) ON pg_temp.nodes FROM {role}")]:
                await self.conn.execute(grant)
                await self.conn.execute(f"SET ROLE {role}")
                async with self.conn.transaction(isolation="repeatable_read", readonly=True):
                    seen[name] = (await self.conn.fetchval("SELECT has_table_privilege('nodes', 'SELECT')"),
                                  await self.view())
                await self.conn.execute("RESET ROLE")
        finally:
            await self.conn.execute("RESET ROLE")
            await self.conn.execute(f"DROP OWNED BY {role}")
            await self.conn.execute(f"DROP ROLE {role}")
        table_privilege, body = seen["columns"]
        self.assertFalse(table_privilege)
        self.assertEqual([x["id"] for x in body["targets"]], ["aws-sensor", "web-01", "console", "data-node", "web-02"])
        self.assertEqual(self.target(body, "web-01")["collection"]["state"], "ok")
        for name in ("no_hostname", "none"):
            body = seen[name][1]
            with self.subTest(grant=name):
                self.assertEqual([x["id"] for x in body["targets"]], ["aws-sensor", "web-01", "console", "data-node"])
                self.assertEqual(self.target(body, "aws-sensor")["security"],
                                 self.target(seen["columns"][1], "aws-sensor")["security"])
        # 카드 열(hostname)만 없으면 web-01 수신은 전처럼 읽는다. web-01 이 읽는 열까지 없으면 모른다
        self.assertEqual(self.target(seen["no_hostname"][1], "web-01")["collection"],
                         self.target(seen["columns"][1], "web-01")["collection"])
        web = self.target(seen["none"][1], "web-01")["collection"]
        self.assertEqual((web["state"], web["reason"]), ("unknown", "노드 표를 읽을 수 없음"))

    async def test_API_는_한_트랜잭션에서_DB_시각으로_답한다(self):
        body = await t.dashboard_targets(self.request)
        self.assertIsInstance(body["as_of"], str)
        self.assertEqual(body["window_seconds"], 3600)
        self.assertEqual(len(body["targets"]), 4)
        json.dumps(body)


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class TargetsWithoutTablesTests(Base):
    """생존 신호 표 · node_metrics · CTI 표가 없는 DB. 500 이 아니라 미확인 · 권한 없음 · 취약점 정보 없음이다."""
    with_heartbeats = False
    with_metrics = False
    with_cti = False

    async def test_표가_없으면_미확인으로_답한다(self):
        await self.incident("c-new", "R001", "v3", "high", "192.0.2.10", 600)
        await self.event(600, "cowrie.login.failed", "cowrie", "192.0.2.10")
        body = await t.dashboard_targets(self.request)
        self.assertEqual((body["heartbeats_available"], body["metrics_available"]), (False, False))
        aws = next(x for x in body["targets"] if x["id"] == "aws-sensor")
        self.assertEqual((aws["collection"]["state"], aws["collection"]["reason"]),
                         ("unknown", "생존 신호 미기록 · 생존 신호 표를 읽을 수 없음"))
        self.assertEqual((aws["security"]["incidents_1h"], aws["security"]["high_1h"], aws["security"]["pending"]),
                         (1, 1, 1))
        self.assertIsNone(aws["response"]["report"])
        self.assertEqual((aws["response"]["applied"], aws["response"]["unverified"]), (0, 0))
        web = next(x for x in body["targets"] if x["id"] == "web-01")
        self.assertEqual(web["system"], {"state": "no_privilege", "metrics": None})
        data = next(x for x in body["targets"] if x["id"] == "data-node")
        self.assertEqual([e["note"] for e in data["collection"]["extra"]], ["생존 신호 표를 읽을 수 없음"] * 2)
        self.assertEqual([x["vulns"] for x in body["targets"]], [{"available": False, "assets": []}] * 4)
        json.dumps(body)

    async def test_nodes_표가_없으면_고정_네_대상만이다(self):
        await self.conn.execute("DROP TABLE nodes")
        body = await t.dashboard_targets(self.request)
        self.assertEqual([x["id"] for x in body["targets"]], ["aws-sensor", "web-01", "console", "data-node"])
        web = next(x for x in body["targets"] if x["id"] == "web-01")["collection"]
        self.assertEqual((web["state"], web["reason"]), ("unknown", "노드 표를 읽을 수 없음"))


if __name__ == "__main__":
    unittest.main()
