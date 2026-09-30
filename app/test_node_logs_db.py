"""보호 대상 장비 최근 로그(node_logs.py · 이슈 #73)의 PostgreSQL 시험.  OPSLOOP_TEST_DATABASE_URL=... python3 -m unittest discover -s app

연결 전용 임시 표만 쓰고 search_path=pg_temp 로 운영 표를 가린다. events 는 schema.sql 의 열 전부와 운영 색인 셋
(idx_events_sensor_ts · idx_events_prov_ts · idx_events_src_ip)을 같은 이름으로 만든다. nodes 는 schema.sql 의 열(receipt 포함)이다.
규칙 정의는 실제 규칙 파일(detector/rules*.json)을 넣는다.

  1. web-01 은 발생원 'web-01' 의 실제 nginx. · sshd. 줄만 나온다(시험 표식 · 모의 · 다른 이벤트 · 다른 발생원은 빠짐).
     최신 순 · 같은 시각은 id 내림차순 · 기본 100 · 200 까지
  2. 등록 노드는 node_id 발생원 줄만. 폐기 · 발생원이 겹친 노드는 404, 등록 대기는 200 빈 목록.
     nodes 열 권한이 없는 역할이면 web-01 은 200 · unreadable, 등록 노드는 404
  3. 필터: 종류 · 출발지 · 응답 코드와 그 조합(응답 코드가 있으면 SSH 줄은 빠짐)
  4. 가림: 응답 JSON 에 쿼리 비밀 · Bearer JWT · password 열 값 · 저장된 line_hash 가 없고 has_password 는 참
  5. 창: 8일 전 줄은 빠짐. now+10분 줄은 목록에서 빠지고 future=1(목록과 같은 필터). 1,001 에서 멈춤
  6. 늦은 줄: 첫 조회 뒤 옛 시각 줄을 넣으면 다음 조회에 제자리로 들어옴
  7. 시각: 마지막 적재 · job 별 마지막 줄 · 선언 · nodes 행 없음. 탐지는 w2 · c1 · sg1 로 정해지고 더 늦은 i2 · 허니팟 실행은 쓰지 않음
  8. 색인: 세 색인 · 다른 발생원 줄 수천 · ANALYZE 뒤, 순차 · 비트맵 읽기를 끈 계획에서 필터 없음 · 종류 필터가
     idx_events_sensor_ts 로 내려가고 일반 Sort 가 없음(같은 시각 사이는 Incremental Sort)
  9. 사건 상세(main.get_incident): 같은 출발지 · 구간에 섞인 줄 가운데 관제 대상(web-01 · 등록 노드) 줄만 ② 행위 · ④ 원문에서
     가려지고, 허니팟 · 디코이 · 관문 · 콘솔 줄은 원문 그대로다(password 원문 칸은 없고 has_password 는 그대로).
     요청 경로 서명 사건(R107 · sg1)은 jsonb 근거의 ① 표본도 web-01 항목만 ④ 와 같은 값으로 가려지고 디코이 항목은 원문이다.
     노드를 폐기하거나 · nodes 열 권한이 없는 역할이거나 · 발생원이 nodes 표에 없어도 그 줄과 표본은 가린 채다(이슈 #81)
"""
import hashlib
import json
import os
import unittest
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

import cti
import node_logs as nl

ROOT = Path(__file__).resolve().parents[1]
RULE_FILES = sorted((ROOT / "detector").glob("rules*.json"))
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
HEX32 = "5f4dcc3b5aa765d61d8327deb882cf99"
HEX_USER = "9f86d081884c7d659a2feaa0c55ad015"
SECRET_INPUT = "echo cGFzc3dvcmQ9aHVudGVyMg== | base64 -d; passwd=hunter2"     # 허니팟 명령(공격 증거)

# schema.sql 의 events · nodes 열과 운영 색인(이름 그대로)
TABLES = """
    CREATE TEMP TABLE events (line_hash text PRIMARY KEY, ts timestamptz NOT NULL, eventid text NOT NULL, session text,
        src_ip inet, src_port integer, dst_port integer, protocol text, username text, password text, input text, url text,
        shasum text, duration_ms integer,
        provenance text NOT NULL DEFAULT 'real' CHECK (provenance IN ('real', 'simulated', 'fixture')),
        message text, http_method text, http_status integer, user_agent text, sensor text NOT NULL DEFAULT 'cowrie');
    CREATE INDEX idx_events_src_ip ON events (src_ip);
    CREATE INDEX idx_events_prov_ts ON events (provenance, ts DESC);
    CREATE INDEX idx_events_sensor_ts ON events (sensor, ts DESC);
    CREATE TEMP TABLE nodes (node_id text PRIMARY KEY, hostname text, role text, sensor text, token_hash text,
        registered_at timestamptz, last_seen_at timestamptz, status text NOT NULL DEFAULT 'pending', addr inet,
        logs text[] NOT NULL DEFAULT '{}', agent_fp text, first_loaded_at timestamptz, last_loaded_at timestamptz,
        receipt jsonb NOT NULL DEFAULT '{}');
    CREATE TEMP TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL);
    CREATE TEMP TABLE detector_runs (id bigserial PRIMARY KEY, rule_version text, since timestamptz, until timestamptz,
        started_at timestamptz NOT NULL, finished_at timestamptz NOT NULL, incidents integer);
"""
# 사건 상세(main.get_incident)가 더 읽는 표(test_proposals_db 와 같은 꼴). 흡수 기록 · 후속 차단은 비어 있다
DETAIL_TABLES = """
    CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_version text NOT NULL,
        rule_name text, severity text, actor_ip inet, target text, first_ts timestamptz,
        last_ts timestamptz, signal_count integer, session_count integer, evidence jsonb,
        status text DEFAULT 'open', created_at timestamptz DEFAULT now());
    CREATE TEMP TABLE verdicts (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, verdict text,
        reason text, observed_value double precision, operator text, proposed text,
        decision_seconds integer, created_at timestamptz DEFAULT now());
    CREATE TEMP TABLE actions (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, action text,
        operator text, note text, created_at timestamptz DEFAULT now());
    CREATE TEMP TABLE blocklist (actor_ip inet PRIMARY KEY, reason text, method text,
        created_at timestamptz DEFAULT now(), expires_at timestamptz, released_at timestamptz,
        enforced_at timestamptz, enforce_note text, incident_key text, requested_by text, released_by text,
        enforcement jsonb);
    CREATE TEMP TABLE incident_absorbed (first_key text, member_key text, kind text, via_key text,
        rule_id text, rule_version text, actor_ip inet, first_ts timestamptz, last_ts timestamptz,
        signal_count integer, sessions text[] DEFAULT '{}', payloads text[] DEFAULT '{}');
    CREATE TEMP TABLE absorbed_blocks (first_key text PRIMARY KEY, expires_at timestamptz NOT NULL,
        requested_by text, created_at timestamptz DEFAULT now(), released_at timestamptz, released_by text);
"""


def plan_nodes(plan):
    """EXPLAIN (FORMAT JSON) 계획의 모든 마디."""
    yield plan
    for child in plan.get("Plans", []):
        yield from plan_nodes(child)


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class NodeLogsDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncpg
        self.conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        await self.conn.execute("SET search_path TO pg_temp")
        await self.conn.execute(TABLES)
        for path in RULE_FILES:
            doc = json.loads(path.read_text())
            await self.conn.execute("INSERT INTO rule_versions VALUES ($1, $2::jsonb)", doc["rule_version"],
                                    path.read_text())
        self.now = await self.conn.fetchval("SELECT now()")
        self.key = nl.line_id_key()
        self.count = 0
        self.request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
            pool=SimpleNamespace(acquire=self.acquire))), state=SimpleNamespace(user={"u": "tester", "r": "viewer"}))
        await self.node("web-01", hostname="opsloop-web-01", logs=["nginx", "auth", "metrics"])

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def asyncTearDown(self):
        await self.conn.close()

    def ago(self, seconds):
        return self.now - timedelta(seconds=seconds)

    async def node(self, node_id, status="active", hostname=None, sensor=None, logs=(), loaded=None, receipt=None):
        """등록 절차(operations.py)처럼 sensor 는 기본으로 node_id 다."""
        await self.conn.execute("""INSERT INTO nodes (node_id, hostname, sensor, status, logs, registered_at, last_seen_at,
                last_loaded_at, receipt) VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8::jsonb)""",
                                node_id, hostname, sensor or node_id, status, list(logs), self.ago(3600),
                                self.ago(loaded) if loaded is not None else None, json.dumps(receipt or {}))

    async def line(self, seconds, eventid="nginx.request", sensor="web-01", provenance="real", ip="203.0.113.7", **cols):
        """events 한 줄. line_hash 는 파서처럼 sha1(원문 줄)이다. 돌려주는 값은 그 line_hash 다."""
        self.count += 1
        row = {"line_hash": hashlib.sha1(f"줄 {self.count}".encode()).hexdigest(), "ts": self.ago(seconds),
               "eventid": eventid, "sensor": sensor, "provenance": provenance, "src_ip": ip, **cols}
        await self.conn.execute(f"INSERT INTO events ({', '.join(row)}) VALUES "
                                f"({', '.join(f'${i}' for i in range(1, len(row) + 1))})", *row.values())
        return row["line_hash"]

    async def ssh(self, seconds, ip="198.51.100.9", user="root", eventid="sshd.login.failed", **cols):
        message = {"sshd.login.failed": f"Failed password for {user} from {ip} port 40022 ssh2",
                   "sshd.login.invalid_user": f"Invalid user {user} from {ip} port 40022"}[eventid]
        return await self.line(seconds, eventid, ip=ip, username=user, message=message, src_port=40022, **cols)

    def ids(self, *hashes):
        return {nl.line_id(h, self.key) for h in hashes}

    async def get(self, device="web-01", kind=None, src_ip=None, status=None, limit=nl.DEFAULT_LIMIT):
        return await nl.device_logs(self.request, device, kind=kind, src_ip=src_ip, status=status, limit=limit)

    async def missing(self, device):
        with self.assertRaises(HTTPException) as caught:
            await self.get(device)
        return caught.exception.status_code, caught.exception.detail

    # ------------------------------------------------------------------

    async def test_web_01_은_발생원_web_01_의_실제_줄만_최신_순이다(self):
        keep = [await self.line(10, http_method="GET", url="/", http_status=200, src_port=51234),
                await self.ssh(20)]
        same = [await self.line(30), await self.line(30)]              # 같은 시각
        await self.line(5, provenance="fixture")
        await self.line(6, provenance="simulated")
        await self.line(7, "console.login.failed")
        await self.line(8, "collector.agent.rejected")
        await self.line(9, sensor="web-02")
        await self.line(9, "decoy.request", sensor="decoy")
        await self.line(9, "console.block.released", sensor="audit")
        await self.line(9, "nginx.request", sensor="console")
        body = await self.get()
        self.assertEqual({x["id"] for x in body["items"]}, self.ids(*keep, *same))
        self.assertEqual(body["items"], sorted(body["items"], key=lambda x: (x["ts"], x["id"]), reverse=True))
        self.assertEqual([x["ts"] for x in body["items"]][:2],
                         [nl.line_ts(self.ago(10)), nl.line_ts(self.ago(20))])
        web, ssh = body["items"][:2]
        self.assertEqual((web["kind"], web["eventid"], web["src_ip"], web["src_port"], web["http_method"], web["url"],
                          web["http_status"], web["username"], web["has_password"]),
                         ("web", "nginx.request", "203.0.113.7", 51234, "GET", "/", 200, None, False))
        self.assertEqual((ssh["kind"], ssh["username"], ssh["message"], ssh["http_status"]),
                         ("ssh", "root", "Failed password for root from 198.51.100.9 port 40022 ssh2", None))
        self.assertEqual((body["device"], body["limit"], body["window_days"], body["future"]),
                         ({"id": "web-01", "label": "web-01", "kind": "fixed"}, 100, 7, 0))
        json.dumps(body)

    async def test_기본_100줄이고_200줄까지_받는다(self):
        await self.conn.execute("""INSERT INTO events (line_hash, ts, eventid, sensor, src_ip)
            SELECT md5(g::text), $1::timestamptz - make_interval(secs => g), 'nginx.request', 'web-01', '203.0.113.7'
            FROM generate_series(1, 205) g""", self.now)
        body = await self.get()
        self.assertEqual(len(body["items"]), 100)
        self.assertEqual(body["items"][0]["ts"], nl.line_ts(self.ago(1)))
        self.assertEqual(body["items"][-1]["ts"], nl.line_ts(self.ago(100)))
        self.assertEqual(len((await self.get(limit=200))["items"]), 200)

    async def test_등록_노드는_node_id_발생원_줄만이고_폐기_겹침은_404_대기는_빈_목록이다(self):
        await self.node("web-02", hostname="web02.lab", logs=["nginx"])
        await self.node("web-03", sensor="web-02", logs=["nginx"])       # 발생원이 web-02 와 겹침(카드에서 빠짐)
        await self.node("web-04", status="pending")
        await self.node("web-05", status="revoked")
        mine = [await self.line(10, sensor="web-02"), await self.ssh(20, sensor="web-02")]
        await self.line(15)                                              # web-01
        await self.line(16, sensor="web-03")
        await self.line(17, sensor="web-05")
        body = await self.get("web-02")
        self.assertEqual(body["device"], {"id": "web-02", "label": "web02.lab", "kind": "node"})
        self.assertEqual({x["id"] for x in body["items"]}, self.ids(*mine))
        self.assertEqual(len((await self.get())["items"]), 1)
        for device in ("web-03", "web-05", "aws-sensor", "console", "data-node", "web-09"):
            with self.subTest(device=device):
                self.assertEqual(await self.missing(device), (404, nl.NOT_FOUND))
        pending = await self.get("web-04")
        self.assertEqual((pending["items"], pending["times"]["state"]), ([], "ok"))
        self.assertEqual([x["declared"] for x in pending["times"]["lines"]], [False, False])

    async def test_nodes_열_권한이_없으면_web_01_은_모름이고_등록_노드는_404_다(self):
        await self.node("web-02", hostname="web02.lab")
        await self.line(10)
        role = "opsloop_t73_no_nodes"
        await self.conn.execute(f"DROP ROLE IF EXISTS {role}")
        await self.conn.execute(f"CREATE ROLE {role} NOLOGIN")
        try:
            for table in ("events", "rule_versions", "detector_runs"):
                await self.conn.execute(f"GRANT SELECT ON pg_temp.{table} TO {role}")
            await self.conn.execute(f"SET ROLE {role}")
            body = await self.get()
            node = await self.missing("web-02")
            await self.conn.execute("RESET ROLE")
        finally:
            await self.conn.execute("RESET ROLE")
            await self.conn.execute(f"DROP OWNED BY {role}")
            await self.conn.execute(f"DROP ROLE {role}")
        self.assertEqual((body["times"]["state"], body["times"]["loaded_at"]), ("unreadable", None))
        self.assertEqual([(x["declared"], x["last_line_at"]) for x in body["times"]["lines"]], [(None, None)] * 2)
        self.assertEqual(len(body["items"]), 1)
        self.assertEqual(node, (404, nl.NOT_FOUND))

    async def test_필터와_그_조합(self):
        a = await self.line(10, ip="203.0.113.7", http_status=200)
        b = await self.line(20, ip="203.0.113.7", http_status=404)
        c = await self.line(30, ip="198.51.100.9", http_status=404)
        d = await self.ssh(40, ip="198.51.100.9")
        e = await self.ssh(50, ip="203.0.113.7", eventid="sshd.login.invalid_user")
        for filters, want in [({}, {a, b, c, d, e}), ({"kind": "web"}, {a, b, c}), ({"kind": "ssh"}, {d, e}),
                              ({"src_ip": "203.0.113.7"}, {a, b, e}), ({"status": 404}, {b, c}),
                              ({"kind": "web", "src_ip": "198.51.100.9"}, {c}), ({"kind": "ssh", "status": 404}, set()),
                              ({"src_ip": "198.51.100.9", "status": 404}, {c}),
                              ({"kind": "ssh", "src_ip": "198.51.100.9", "status": None}, {d}),
                              ({"src_ip": "2001:db8::1"}, set())]:
            with self.subTest(filters=filters):
                body = await self.get(**filters)
                self.assertEqual({x["id"] for x in body["items"]}, self.ids(*want))
                self.assertEqual(body["filters"], {"kind": None, "src_ip": None, "status": None} | filters)

    async def test_응답에는_비밀도_저장된_line_hash_도_없다(self):
        stored = [await self.line(10, url="/login?user=a&password=hunter2&token=abcSECRET", password="hunter2pw!",
                                  user_agent=f"Authorization: Bearer {JWT}", http_method="POST"),
                  await self.ssh(20, user="admin", password="s3cr3t-pw")]
        body = await self.get()
        text = json.dumps(body, ensure_ascii=False)
        for secret in ("hunter2", "abcSECRET", JWT, "s3cr3t-pw", *stored):
            with self.subTest(secret=secret[:12]):
                self.assertNotIn(secret, text)
        web, ssh = body["items"]
        self.assertEqual((web["url"], web["user_agent"], web["has_password"]),
                         ("/login?user=…&password=…&token=…", f"Authorization: {nl.MASK}", True))
        self.assertEqual((ssh["username"], ssh["has_password"]), ("admin", True))

    async def test_창은_7일이고_앞선_시각_줄은_빼고_센다(self):
        inside = await self.line(6 * 86400)
        await self.line(8 * 86400)
        await self.line(-600)                                            # now + 10분(노드가 적은 시각)
        near = await self.line(-120)                                     # now + 2분은 목록에 든다
        body = await self.get()
        self.assertEqual({x["id"] for x in body["items"]}, self.ids(inside, near))
        self.assertEqual(body["future"], 1)
        # 목록과 같은 필터를 따른다
        self.assertEqual((await self.get(kind="ssh"))["future"], 0)
        self.assertEqual((await self.get(src_ip="198.51.100.9"))["future"], 0)
        self.assertEqual((await self.get(kind="web", src_ip="203.0.113.7"))["future"], 1)
        # 1,001 에서 멈춘다
        await self.conn.execute("""INSERT INTO events (line_hash, ts, eventid, sensor, src_ip)
            SELECT md5('future' || g), $1::timestamptz + interval '1 day' + make_interval(secs => g), 'nginx.request',
                   'web-01', '203.0.113.7' FROM generate_series(1, 1005) g""", self.now)
        self.assertEqual((await self.get())["future"], nl.FUTURE_CAP)

    async def test_늦게_도착한_줄은_다음_조회에_제자리로_들어온다(self):
        first = [await self.line(10), await self.line(300)]
        before = await self.get()
        self.assertEqual([x["id"] for x in before["items"]], [nl.line_id(h, self.key) for h in first])
        late = await self.line(120)
        after = await self.get()
        self.assertEqual([x["id"] for x in after["items"]], [nl.line_id(h, self.key) for h in (first[0], late, first[1])])

    async def test_시각_네_가지(self):
        nginx_at, auth_at = self.ago(20).isoformat(timespec="microseconds"), self.ago(90).isoformat(timespec="microseconds")
        await self.conn.execute("DELETE FROM nodes")
        await self.node("web-01", logs=["nginx", "metrics"], loaded=24,
                        receipt={"nginx": {"lines": 9, "last_line_at": nginx_at},
                                 "auth": {"lines": 2, "last_line_at": auth_at},
                                 "_other": {"last_line_at": self.ago(1).isoformat()}})
        for version, seconds in [("w2", 100), ("c1", 200), ("sg1", 300), ("i2", 10), ("v3", 5), ("s1", 20), ("a1", 30)]:
            await self.conn.execute("INSERT INTO detector_runs (rule_version, started_at, finished_at) VALUES ($1, $2, $2)",
                                    version, self.ago(seconds))
        body = await self.get()
        times = body["times"]
        self.assertIsInstance(body["as_of"], str)
        self.assertEqual((times["state"], times["loaded_at"]), ("ok", cti.iso(self.ago(24))))
        self.assertEqual([(x["key"], x["declared"], x["last_line_at"]) for x in times["lines"]],
                         [("web", True, cti.iso(self.ago(20))), ("ssh", False, cti.iso(self.ago(90)))])
        detect = times["detect"]
        self.assertEqual((detect["last_at"], detect["stale"], detect["reason"]), (cti.iso(self.ago(300)), False, None))
        self.assertEqual([(v["rule_version"], v["last_at"]) for v in detect["versions"]],
                         [("c1", cti.iso(self.ago(200))), ("sg1", cti.iso(self.ago(300))), ("w2", cti.iso(self.ago(100)))])
        # 등록 노드도 같은 버전이다
        await self.node("web-02")
        self.assertEqual([v["rule_version"] for v in (await self.get("web-02"))["times"]["detect"]["versions"]],
                         ["c1", "sg1", "w2"])
        # nodes 에 행이 없으면(web-01) 선언 · 시각이 모두 null 이다
        await self.conn.execute("DELETE FROM nodes WHERE node_id = 'web-01'")
        times = (await self.get())["times"]
        self.assertEqual((times["state"], times["loaded_at"]), ("no_node", None))
        self.assertEqual([(x["declared"], x["last_line_at"]) for x in times["lines"]], [(None, None)] * 2)

    async def test_색인은_발생원_시각_색인이고_일반_정렬이_없다(self):
        # 다른 발생원(실제) 줄 수천 개와 web-01 줄. 운영 색인 셋이 모두 있다
        await self.conn.execute("""INSERT INTO events (line_hash, ts, eventid, sensor, src_ip)
            SELECT md5('other' || g), $1::timestamptz - make_interval(secs => g * 60),
                   (ARRAY['cowrie.login.failed', 'decoy.request', 'nginx.request'])[g % 3 + 1],
                   (ARRAY['cowrie', 'decoy', 'web-02'])[g % 3 + 1], ('198.51.100.' || (g % 200))::inet
            FROM generate_series(1, 6000) g""", self.now)
        await self.conn.execute("""INSERT INTO events (line_hash, ts, eventid, sensor, src_ip)
            SELECT md5('mine' || g), $1::timestamptz - make_interval(secs => g * 600),
                   CASE WHEN g % 4 = 0 THEN 'sshd.login.failed' ELSE 'nginx.request' END, 'web-01', '203.0.113.7'
            FROM generate_series(1, 300) g""", self.now)
        await self.conn.execute("ANALYZE events")
        for kind in (None, "web"):
            with self.subTest(kind=kind):
                async with self.conn.transaction():
                    await self.conn.execute("SET LOCAL enable_seqscan = off")
                    await self.conn.execute("SET LOCAL enable_bitmapscan = off")
                    sql = nl.LINES_SQL.format(extra="", limit=5)
                    raw = await self.conn.fetchval(f"EXPLAIN (FORMAT JSON) {sql}", "web-01", self.now, nl.WINDOW_DAYS,
                                                   nl.patterns(kind), nl.DEFAULT_LIMIT)
                nodes = list(plan_nodes(json.loads(raw)[0]["Plan"]))
                self.assertIn("idx_events_sensor_ts", [n.get("Index Name") for n in nodes])
                self.assertNotIn("Sort", [n["Node Type"] for n in nodes])

    async def test_사건_상세는_보호_대상_줄만_가리고_허니팟_디코이_관문_줄은_원문이다(self):
        import main
        await self.conn.execute(DETAIL_TABLES)
        await self.node("web-02", hostname="web02.lab", logs=["auth"])
        actor, key = "203.0.113.50", "R102|w2|203.0.113.50|t"
        await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip,
                first_ts, last_ts, signal_count, session_count) VALUES ($1, 'R102', 'w2', '시험 규칙', 'medium', $2, $3, $4, 5, 0)""",
                                key, actor, self.ago(120), self.ago(60))
        # 같은 출발지 · 구간: 보호 대상(web-01 · 등록 노드 web-02) 줄과 허니팟 · 디코이 · 관문 · 콘솔 줄이 섞였다
        await self.line(100, ip=actor, http_method="GET", url="/login?user=admin&password=hunter2", http_status=200,
                        user_agent=f"Authorization: Bearer {JWT}", password="hunter2pw!")
        await self.line(95, "sshd.login.success", ip=actor, session="web-01/sshd/77", username=HEX_USER,
                        message=f"Accepted password for {HEX_USER} from {actor} port 40022 ssh2")
        await self.ssh(90, ip=actor, user=HEX_USER, eventid="sshd.login.invalid_user", sensor="web-02")
        await self.line(85, "cowrie.command.input", sensor="cowrie", ip=actor, session="c0ffee", username="root",
                        input=SECRET_INPUT)
        await self.line(84, "cowrie.login.failed", sensor="cowrie", ip=actor, session="c0ffee", username="root",
                        password="hunter2", message="login attempt [root/hunter2] failed")
        await self.line(80, "decoy.request", sensor="decoy", ip=actor, http_method="GET", url="/wp-login.php?pwd=hunter2",
                        user_agent="sqlmap token=abc123", http_status=404)
        await self.line(79, "decoy.action.login", sensor="decoy", ip=actor, url="/login?password=hunter2", username="admin")
        await self.line(75, "gateway.denied", sensor="gateway", ip=actor, input="in=eth0 dst=10.0.0.1",
                        message=f"deny token={HEX32}")
        await self.line(70, "console.login.failed", sensor="console", ip=actor, username="admin",
                        url="/api/login?password=hunter2")
        with patch.object(main.app.state, "pool", SimpleNamespace(acquire=self.acquire), create=True):
            detail = await main.get_incident(key)
        raw = {(r["sensor"], r["eventid"]): r for r in detail["raw"]}
        behavior = {(r["sensor"], r["eventid"]): r for r in detail["behavior"]}
        self.assertEqual(len(detail["raw"]), 9)
        self.assertEqual(set(behavior), {("web-01", "sshd.login.success"), ("cowrie", "cowrie.command.input"),
                                         ("decoy", "decoy.action.login")})
        # 보호 대상 줄: 장비 최근 로그와 같은 가림. 세션 · has_password 는 그대로다
        web = raw["web-01", "nginx.request"]
        self.assertEqual((web["url"], web["user_agent"], web["http_method"], web["has_password"]),
                         ("/login?user=…&password=…", f"Authorization: {nl.MASK}", "GET", True))
        for row in (raw["web-01", "sshd.login.success"], behavior["web-01", "sshd.login.success"]):
            self.assertEqual((row["username"], row["session"]), (nl.MASK, "web-01/sshd/77"))
        self.assertEqual(raw["web-01", "sshd.login.success"]["message"],
                         f"Accepted password for {nl.MASK} from {actor} port 40022 ssh2")
        node = raw["web-02", "sshd.login.invalid_user"]
        self.assertEqual((node["username"], node["message"]),
                         (nl.MASK, f"Invalid user {nl.MASK} from {actor} port 40022"))
        mine = [r for r in detail["raw"] + detail["behavior"] if r["sensor"] in ("web-01", "web-02")]
        text = json.dumps(mine, ensure_ascii=False)
        for secret in ("hunter2", JWT, HEX_USER):
            with self.subTest(secret=secret[:12]):
                self.assertNotIn(secret, text)
        # 허니팟 · 디코이 · 관문 · 콘솔 줄: 원문 그대로(공격 증거 · 그 밖의 발생원)
        self.assertEqual(raw["cowrie", "cowrie.command.input"]["input"], SECRET_INPUT)
        self.assertEqual(behavior["cowrie", "cowrie.command.input"]["input"], SECRET_INPUT)
        login = raw["cowrie", "cowrie.login.failed"]
        self.assertEqual((login["message"], login["has_password"]), ("login attempt [root/hunter2] failed", True))
        decoy = raw["decoy", "decoy.request"]
        self.assertEqual((decoy["url"], decoy["user_agent"]), ("/wp-login.php?pwd=hunter2", "sqlmap token=abc123"))
        self.assertEqual(behavior["decoy", "decoy.action.login"]["url"], "/login?password=hunter2")
        gateway = raw["gateway", "gateway.denied"]
        self.assertEqual((gateway["input"], gateway["message"]), ("in=eth0 dst=10.0.0.1", f"deny token={HEX32}"))
        self.assertEqual(raw["console", "console.login.failed"]["url"], "/api/login?password=hunter2")
        # password 원문 칸은 어느 줄에도 없다
        self.assertTrue(all("password" not in r for r in detail["raw"] + detail["behavior"]))

    async def test_서명_사건의_근거_표본도_보호_대상은_가리고_디코이는_원문이다(self):
        import main
        await self.conn.execute(DETAIL_TABLES)
        actor, key, secret = "203.0.113.51", "R107|sg1|203.0.113.51|t", "webS3cret99"
        url = f"/cgi-bin/luci/;stok=/locale?form=country&password={secret}&token={JWT}"
        decoy_url = "/cgi-bin/luci/;stok=/locale?password=hunter2"
        # detect.signals_url_signature 의 detail 모양 그대로 · run() 이 붙이는 signatures · sensors
        sample = [{"eventid": "nginx.request", "sensor": "web-01", "http_method": "GET", "url": url, "http_status": 404,
                   "signatures": ["sg-luci"]},
                  {"eventid": "decoy.request", "sensor": "decoy", "http_method": "GET", "url": decoy_url, "http_status": 404,
                   "signatures": ["sg-luci"]}]
        evidence = {"sample": sample, "sessions": [], "signatures": ["sg-luci"], "sensors": ["decoy", "web-01"]}
        await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip,
                first_ts, last_ts, signal_count, session_count, evidence)
                VALUES ($1, 'R107', 'sg1', '시험 규칙', 'medium', $2, $3, $4, 2, 0, $5::jsonb)""",
                                key, actor, self.ago(120), self.ago(60), json.dumps(evidence))
        await self.line(100, ip=actor, http_method="GET", url=url, http_status=404)
        await self.line(90, "decoy.request", sensor="decoy", ip=actor, http_method="GET", url=decoy_url, http_status=404)
        with patch.object(main.app.state, "pool", SimpleNamespace(acquire=self.acquire), create=True):
            detail = await main.get_incident(key)
        web, decoy = detail["evidence"]["sample"]
        raw = {r["sensor"]: r for r in detail["raw"]}
        masked = "/cgi-bin/luci/;stok=/locale?form=…&password=…&token=…"
        self.assertEqual((web["url"], raw["web-01"]["url"]), (masked, masked))
        self.assertEqual({k: v for k, v in web.items() if k != "url"}, {k: v for k, v in sample[0].items() if k != "url"})
        self.assertEqual((decoy, raw["decoy"]["url"]), (sample[1], decoy_url))
        self.assertEqual(detail["evidence"]["sensors"], ["decoy", "web-01"])
        text = json.dumps(detail, ensure_ascii=False, default=str)
        for value in (secret, JWT):
            with self.subTest(secret=value[:12]):
                self.assertNotIn(value, text)

    async def test_노드를_폐기하거나_nodes_를_읽을_수_없어도_사건_상세는_가린_채다(self):
        import main
        await self.conn.execute(DETAIL_TABLES)
        await self.node("web-02", hostname="web02.lab", logs=["nginx"])
        actor, key, secret = "203.0.113.52", "R107|sg1|203.0.113.52|t", "webS3cret99"
        url, other = f"/geoserver/web/?api_key={secret}", f"/a?token={JWT}"
        masked, other_masked = "/geoserver/web/?api_key=…", "/a?token=…"
        sample = [{"eventid": "nginx.request", "sensor": "web-02", "http_method": "GET", "url": url, "http_status": 404,
                   "signatures": ["sg-x"]},
                  {"eventid": "nginx.request", "sensor": "web-09", "http_method": "GET", "url": other, "http_status": 404,
                   "signatures": ["sg-x"]}]
        evidence = {"sample": sample, "sessions": [], "signatures": ["sg-x"], "sensors": ["web-02", "web-09"]}
        await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip,
                first_ts, last_ts, signal_count, session_count, evidence)
                VALUES ($1, 'R107', 'sg1', '시험 규칙', 'medium', $2, $3, $4, 2, 0, $5::jsonb)""",
                                key, actor, self.ago(120), self.ago(60), json.dumps(evidence))
        await self.line(100, sensor="web-02", ip=actor, http_method="GET", url=url, http_status=404)
        await self.line(95, sensor="web-09", ip=actor, http_method="GET", url=other, http_status=404)   # nodes 표에 없는 발생원

        async def detail():
            with patch.object(main.app.state, "pool", SimpleNamespace(acquire=self.acquire), create=True):
                return await main.get_incident(key)

        got = {"활성": await detail()}
        await self.conn.execute("UPDATE nodes SET status = 'revoked' WHERE node_id = 'web-02'")
        got["폐기"] = await detail()
        # nodes 열 권한이 없는 역할: 관련 장비 계산이 등록 노드 카드를 만들지 못한다
        role = "opsloop_t81_no_nodes"
        tables = await self.conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname = pg_my_temp_schema()::regnamespace::text")
        await self.conn.execute(f"DROP ROLE IF EXISTS {role}")
        await self.conn.execute(f"CREATE ROLE {role} NOLOGIN")
        try:
            for row in tables:
                if row["tablename"] != "nodes":
                    await self.conn.execute(f"GRANT SELECT ON pg_temp.{row['tablename']} TO {role}")
            await self.conn.execute(f"SET ROLE {role}")
            got["nodes 못 읽음"] = await detail()
        finally:
            await self.conn.execute("RESET ROLE")
            await self.conn.execute(f"DROP OWNED BY {role}")
            await self.conn.execute(f"DROP ROLE {role}")
        for state, body in got.items():
            with self.subTest(state=state):
                raw = {r["sensor"]: r for r in body["raw"]}
                self.assertEqual((raw["web-02"]["url"], raw["web-09"]["url"]), (masked, other_masked))
                self.assertEqual([s["url"] for s in body["evidence"]["sample"]], [masked, other_masked])
                text = json.dumps(body, ensure_ascii=False, default=str)
                for value in (secret, JWT):
                    self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
