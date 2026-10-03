"""관제 대상별 상태판(targets.py · 이슈 #52 · #64 · #72 · #82)의 PostgreSQL 시험.  OPSLOOP_TEST_DATABASE_URL=... python3 -m unittest discover -s app

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
  - 등록 노드(이슈 #64): 노드를 하나 더 등록하면 카드가 하나 늘고(고정 대상 뒤 · node_id 순, 폐기 노드는 없음) web-01 을 뺀
    고정 대상은 그대로다. 그 노드의 이벤트(수집 · 로그) · 사건(발생원 · node:<id> · 노드 에이전트 이벤트)이 그 카드로 가고
    미분류에서 빠진다. web-01 의 노드 에이전트 사건은 이벤트로 고르고, 고르지 못하면 대체 추정(장비 미확인)이다.
    nodes 는 운영 콘솔처럼 열 권한만 있어도 읽고, 권한 · 표가 없으면 고정 네 대상만이다(web-01 수신은 미확인.
    카드 열 hostname 만 없으면 web-01 은 그대로)
  - 관련 장비(이슈 #72): 카드 미판정 수 = 장비 필터 목록 수(고정 네 대상 · 등록 노드 · 장비 미확인, 대체 추정 사건 포함) ·
    장비 필터는 쪽을 나누기 전에 거름 · 연결 근거 · 상세와 목록의 장비가 같음 · 탐지 경로 판별(실제 규칙 정의) ·
    관제 이상 · 먼저 처리할 사건이 요약과 같은 기준 · 취약점 수정 상태별 수
  - 관제 이상 보완(이슈 #82): 같은 스냅숏에서 카드가 이상 · 확인 불가로 보이면 띠에 대응 항목이 있다(생존 신호 표가 없는 DB 포함) ·
    관제 이상 질의 8개 이하 · 1분 다리 버전이 23 · 25시간 멈춰도 띠와 데이터 노드 카드에 남고 옛 버전 기록은 보지 않음 ·
    등록 노드 열만 없으면 모름 · 지점 불일치 수 · 생존 신호 표가 없을 때의 대응
  - 대시보드 개편(이슈 #83): 미결 = 최신 판정이 사람의 판단 유보(같은 사건 두 번 → 1건 · 재판정 → 제외 · 시스템 전환 기록 → 제외,
    기록은 남음) · 창 밖 미결도 세지만 최근 중요 탐지 · 대응 금지 대역 수는 그대로 · 카드 미결 수 = 장비 · 미결 필터 목록 수 = 요약 ·
    앞선 시각(기준 + 5분 넘게) 줄은 마지막 로그 · 웹 로그 적재 판정에서 빠짐 · 취약점 대조 실패 · 대조 오래됨
  - 수집 · 관제 상태(이슈 #76 · #84): 콘솔 DB 연결은 실제 pg_stat_activity 에서 같은 역할의 이름표 연결만 셈(이름표 있는 연결 ·
    다른 역할이 같은 이름을 쓴 연결 · 이름표 없는 연결 · 콘솔 B 없음 · 닫으면 다음 조회에 없음 · 읽기 실패는 확인 불가) ·
    미확인은 확인 중(5분 안) · 확인 지연(5분 넘은 확인 전 · 지점 불일치)으로 나뉘고 시각 글자가 아니어도 오류가 아님(관문을 다시 요청한
    행에 남은 removing 은 요청 시각으로 잼) · 요약과 같음 · 카드 보고 문제(report_issue)는 띠 report:<지점> 과 같은 글 · 확인 지연은
    띠에도 있음(그 지점 보고가 이상이면 그 항목)
"""
import asyncio
import json
import os
import secrets
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import operations as ops
import targets as t
from dashboard import dashboard_metrics

ROOT = Path(__file__).resolve().parents[1]
CTI_MIGRATION = ROOT / "infra" / "migrations" / "20260925_cti.sql"
RULE_FILES = sorted((ROOT / "detector").glob("rules*.json"))

BASE_TABLES = """
    CREATE TEMP TABLE console_users (username text PRIMARY KEY, role text, disabled_at timestamptz);
    CREATE TEMP TABLE incidents (assigned_to text, incident_key text PRIMARY KEY, rule_id text NOT NULL, rule_version text NOT NULL,
        rule_name text, severity text NOT NULL, actor_ip inet, target text, first_ts timestamptz NOT NULL,
        last_ts timestamptz NOT NULL, signal_count integer DEFAULT 1, session_count integer DEFAULT 0, evidence jsonb,
        status text DEFAULT 'open', created_at timestamptz DEFAULT now());
    CREATE TEMP TABLE verdicts (id bigserial PRIMARY KEY, incident_key text NOT NULL, verdict text NOT NULL,
        operator text, created_at timestamptz DEFAULT now());
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
        requested_by text, enforced_at timestamptz, enforce_note text, released_by text, enforcement jsonb,
        points text[] NOT NULL DEFAULT '{gateway,fw}' CHECK (points IN ('{gateway,fw}'::text[], '{fw}'::text[])));
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


# 상세(main.get_incident)가 더 읽는 표 · 열(test_proposals_db 와 같은 꼴). 상세와 목록의 장비를 견줄 때만 더한다
DETAIL_TABLES = """
    ALTER TABLE verdicts ADD COLUMN reason text, ADD COLUMN observed_value double precision,
        ADD COLUMN proposed text, ADD COLUMN decision_seconds integer;
    ALTER TABLE events ADD COLUMN username text, ADD COLUMN password text, ADD COLUMN input text, ADD COLUMN shasum text,
        ADD COLUMN http_method text, ADD COLUMN user_agent text, ADD COLUMN message text;
    CREATE TEMP TABLE actions (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, action text,
        operator text, note text, created_at timestamptz DEFAULT now());
    CREATE TEMP TABLE incident_absorbed (first_key text, member_key text, kind text, via_key text,
        rule_id text, rule_version text, actor_ip inet, first_ts timestamptz, last_ts timestamptz,
        signal_count integer, sessions text[] DEFAULT '{}', payloads text[] DEFAULT '{}',
        recorded_at timestamptz DEFAULT now());
    CREATE TEMP TABLE absorbed_blocks (first_key text PRIMARY KEY, expires_at timestamptz NOT NULL,
        requested_by text, created_at timestamptz DEFAULT now(), released_at timestamptz, released_by text);
"""
DEVICE_KEYS = ("devices", "device_state", "device_fallback")


def cti_tables() -> str:
    """CTI 마이그레이션의 표 · 색인 정의(BEGIN; 뒤 ~ 권한 블록 앞)."""
    return CTI_MIGRATION.read_text().split("BEGIN;", 1)[1].split("\nDO $$", 1)[0]


class Counted:
    """연결을 감싸 질의(fetch · fetchrow · fetchval)를 남긴다. 관제 이상의 질의 수를 본다."""

    def __init__(self, conn):
        self.conn, self.queries = conn, []

    def __getattr__(self, name):
        attr = getattr(self.conn, name)
        if name not in ("fetch", "fetchrow", "fetchval"):
            return attr

        async def call(sql, *args):
            self.queries.append(sql)
            return await attr(sql, *args)
        return call


def band_needs(body) -> list[tuple[str, set]]:
    """카드 ⇒ 띠 불변식(이슈 #82): 카드가 이상 · 확인 불가로 보이는 것마다 (까닭, 띠에 있어야 할 키 후보). 후보 하나라도 띠에 있어야
    한다. 의도한 상태(등록 대기 · 폐기 노드와 그 옛 지표, 조용한 서버의 요청 없음, 생존 신호를 보내지 않는 콘솔)는 이상이 아니다.
    콘솔 DB 연결 없음 · 확인 불가(이슈 #76)도 띠에 올리지 않는다(B 는 평소 꺼 두는 예비이고, 응답하는 콘솔은 자기 연결이 있으며,
    A 없음은 B 가 응답 중인 상황이라 콘솔 장애 알림 몫이다). 카드 보고 문제(report_issue, #84)는 띠 report:<지점> 과 같은 판정이다.
    카드 적용 확인 지연(delayed, #84) 가운데 지점 불일치를 뺀 5분 넘은 확인 전은 띠 point_delayed:<지점>, 그 지점 보고가 이상이면 그 항목이다."""
    as_of = datetime.fromisoformat(body["as_of"])
    detect = {"detect:honeypot", "detect:bridge"}
    needs = []
    for card in body["targets"]:
        tid, c, r = card["id"], card["collection"], card["response"]
        if tid == "aws-sensor" and c["state"] in ("no_signal", "unknown"):
            needs.append((f"{tid} 수집 {c['state']}", {"sensor", "heartbeats", "loader"}))
        if tid == t.WEB_NODE or card["kind"] == "node":
            idle = c["reason"] in ("노드 폐기됨", "노드 등록 대기 · 수신 전")
            if c["state"] == "no_signal":
                needs.append((f"{tid} 수신 끊김", {"nodes_silent"}))
            elif c["reason"] in ("노드 표를 읽을 수 없음", "노드 등록 기록 없음"):
                needs.append((f"{tid} {c['reason']}", {"nodes"}))
            needs += [(f"{tid} {w['key']}", {f"parse:{tid}"}) for w in c["warnings"]]
            if card["system"]["state"] == "stale" and not idle:
                needs.append((f"{tid} 자원 지표", {f"metrics:{tid}", "nodes_silent"}))
        if tid == "data-node":
            if c["state"] in ("no_signal", "unknown"):
                needs.append((f"{tid} 탐지 {c['state']}", detect))
            enforcers = {f"enforcer:{p}" for p in t.POINT_LABELS}
            needs += [(f"{tid} {stop} 멈춤", {"loader": {"loader"}, "enforcer": enforcers, "detect": detect}[stop])
                      for stop in c["stopped"]]
        point, report = r["point"], r["report"]
        if point is None:
            continue
        if r["stalled"]:
            needs.append((f"{tid} {r['stalled']}", {f"enforcer:{point}", "heartbeats"}))
        if r["failed"]:
            needs.append((f"{tid} 적용 실패", {f"block_failed:{point}"}))
        if r["stale"]:
            needs.append((f"{tid} 지점 불일치", {f"point_stale:{point}", "gateway_mismatch"}))
        if r["delayed"] > r["stale"]:
            needs.append((f"{tid} 적용 확인 지연", {f"point_delayed:{point}", f"report:{point}"}))
        age = as_of - datetime.fromisoformat(report["seen_at"]) if report and report["seen_at"] else None
        if report and (age is None or age > timedelta(seconds=t.HEARTBEAT_STALE)
                       or report["problem"] and age > timedelta(seconds=t.REPORT_PROBLEM_GRACE)):
            needs.append((f"{tid} 지점 보고", {f"report:{point}", f"enforcer:{point}"}))
        if r["report_issue"]:
            needs.append((f"{tid} 보고 문제 {r['report_issue']}", {f"report:{point}"}))
    return needs


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

    async def verdict(self, key, verdict, operator="han", seconds=0):
        """판정 한 건(seconds 초 전). operator 'system:…' 은 시스템 전환 기록이다."""
        await self.conn.execute("INSERT INTO verdicts (incident_key, verdict, operator, created_at) VALUES ($1, $2, $3, $4)",
                                key, verdict, operator, self.ago(seconds))

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
        # 1분 다리가 돌려야 할 버전은 모두 5분 전에 돌았다
        await self.conn.executemany("INSERT INTO detector_runs (rule_version, started_at, finished_at) VALUES ($1, $2, $2)",
                                    [(v, self.ago(300)) for v in t.BRIDGE_VERSIONS])
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
        self.assertEqual(body["unmapped"], {"incidents_1h": 2, "pending": 2, "undetermined": 0})
        latest = {tid: (s["latest"] or {}).get("incident_key") for tid, s in sec.items()}
        self.assertEqual(latest, {"aws-sensor": "c-edge", "web-01": "node", "console": "audit", "data-node": "self"})
        self.assertEqual(sec["aws-sensor"]["latest"], {
            "incident_key": "c-edge", "rule_id": "R004", "rule_name": "R004 시험 규칙", "severity": "high",
            "actor_ip": "192.0.2.11", "target": None, "last_ts": t.cti.iso(self.ago(3600)), "judged": True,
            "verdict": "threat"})
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
        # 관문 업로더(role=gateway) 신호 시각은 까닭 끝에 붙는다(state 는 센서 판정 그대로다)
        self.assertEqual((aws["state"], aws["reason"]),
                         ("ok", "업로더 생존 신호 3분 전 · 적재기 확인 1분 전 · 최근 1시간 로그 있음 · 관문 기록 신호 2분 전"))
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
        # 콘솔은 응답 중이다. 시험 연결에는 콘솔 이름표가 없어 둘 다 없음이다(이슈 #76)
        console = self.target(body, "console")["collection"]
        self.assertEqual((console["state"], console["signal"], console["logs"][0]["last_at"]),
                         ("responding", None, t.cti.iso(self.ago(300))))
        self.assertEqual(console["reason"], "DB 연결 확인: 콘솔 A 없음 · 콘솔 B 없음(평소 꺼 두는 예비)")
        data = self.target(body, "data-node")["collection"]
        self.assertEqual((data["state"], data["reason"], data["signal"]["seen_at"]),
                         ("ok", "마지막 탐지 실행 4분 전", t.cti.iso(self.ago(240))))
        self.assertEqual(data["extra"], [{"label": "적재기 확인", "at": t.cti.iso(self.ago(60)), "note": None},
                                         {"label": "집행기 확인", "at": t.cti.iso(self.ago(30)), "note": None}])
        # 코우리 · 디코이 로그가 1시간 넘게 없으면 신호가 정상이어도 요청 없음이다
        await self.conn.execute("DELETE FROM events WHERE sensor IN ('cowrie', 'decoy')")
        aws = self.target(await self.view(), "aws-sensor")["collection"]
        self.assertEqual((aws["state"], aws["reason"]),
                         ("quiet", "업로더 생존 신호 3분 전 · 적재기 확인 1분 전 · 최근 1시간 요청 없음 · 관문 기록 신호 2분 전"))
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
                         ("no_signal", "업로더 생존 신호 18분 전 · 적재기 확인 2분 전 · 확인 때 이미 15분 넘게 새 신호 없음"
                                       " · 관문 기록 신호 2분 전"))
        # 적재기가 30분 넘게 확인하지 않으면 미확인이다. 관문 기록 신호도 확인하지 않은 것이라 붙이지 않는다
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
                         ["not_collected", "not_collected", "no_data"])
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
        # 203.0.113.8 은 관문 stale(미확인 가운데 지점 불일치) · 내부 방화벽 failed(실패). 실패는 미확인에 섞지 않는다
        #   미확인은 확인 중(기록 없음 · 방금 대기) · 확인 지연(지점 불일치)으로 나뉜다(이슈 #84)
        self.assertEqual((aws["point"], aws["point_label"], aws["applied"], aws["failed"], aws["unverified"], aws["stale"],
                          aws["checking"], aws["delayed"], aws["stalled"]), ("gateway", "허니팟 관문", 2, 0, 2, 1, 1, 1, None))
        self.assertEqual((web["point"], web["point_label"], web["applied"], web["failed"], web["unverified"], web["stale"],
                          web["checking"], web["delayed"], web["stalled"]), ("fw", "내부 방화벽", 1, 1, 2, 0, 2, 0, None))
        # 보고 문제: 관문 보고는 2분 전(없음), 내부 방화벽은 받은 보고가 없다(띠 report:fw 와 같은 글)
        self.assertEqual((aws["report_issue"], web["report_issue"]), (None, "받은 보고 없음 · 보고 파일 없음"))
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
        self.assertEqual(self.target(body, "data-node")["collection"]["stopped"], ["enforcer"])

    async def test_내부_방화벽_보고만_없어도_데이터_노드는_집행기_멈춤이다(self):
        self.assertEqual(self.target(await self.view(), "data-node")["collection"]["stopped"], [])
        await self.conn.execute("DELETE FROM sensor_heartbeats WHERE source = 'block:fw'")
        data = self.target(await self.view(), "data-node")["collection"]
        # 관문 집행기는 확인 중이라 문장 · state 는 그대로다. 주의 표시(stopped)는 관제 이상 enforcer:fw 와 같은 판정이다
        self.assertEqual((data["state"], data["reason"], data["stopped"]), ("ok", "마지막 탐지 실행 4분 전", ["enforcer"]))
        items = (await t.monitor_view(self.conn, self.now))["items"]
        self.assertEqual([(x["key"], x["reason"]) for x in items if x["key"].startswith("enforcer:")],
                         [("enforcer:fw", "집행기 확인 기록 없음")])

    async def test_취약점(self):
        body = await self.view()
        web = self.target(body, "web-01")["vulns"]
        self.assertEqual(web, {"available": True, "assets": [{
            "asset_id": "web-01", "vuln_total": 2, "vuln_kev": 1, "vuln_fix_available": 2, "vuln_reboot_pending": 0,
            "vuln_fix_unknown": 0, "collected_at": t.cti.iso(self.ago(3600)),
            "checked_at": t.cti.iso(self.ago(3600)), "stale": False, "missing": False, "check_failed": False,
            "check_stale": False}]})
        aws = self.target(body, "aws-sensor")["vulns"]["assets"]
        self.assertEqual([(a["asset_id"], a["stale"], a["missing"], a["vuln_total"]) for a in aws],
                         [("honeypot-dmz", True, False, 0), ("gateway", True, True, 0)])
        console = self.target(body, "console")["vulns"]["assets"]
        self.assertEqual([(a["asset_id"], a["missing"]) for a in console], [("console-a", False), ("console-b", True)])
        self.assertEqual(self.target(body, "data-node")["vulns"]["assets"][0]["missing"], True)
        # 수정 상태 네 값(fix_available · reboot_pending · no_fix · unknown). 수정판 없음은 따로 세지 않는다(전체에만 든다)
        snap = await self.conn.fetchval("SELECT id FROM cti_snapshots")
        for osv, cve, state in [("UBUNTU-CVE-2026-90001", "CVE-2026-90001", "reboot_pending"),
                                ("UBUNTU-CVE-2026-90002", "CVE-2026-90002", "no_fix"),
                                ("UBUNTU-CVE-2026-90003", "CVE-2026-90003", "unknown"),
                                ("UBUNTU-CVE-2026-90004", "CVE-2026-90004", "unknown")]:
            await self.conn.execute("INSERT INTO cti_osv (osv_id, cve_id, snapshot_id) VALUES ($1, $2, $3)", osv, cve, snap)
            await self.conn.execute("""INSERT INTO asset_vulnerabilities (asset_id, source_package, version, osv_id, cve_id,
                fix_state, snapshot_id) VALUES ('web-01', 'openssl', '1', $1, $2, $3, $4)""", osv, cve, state, snap)
        web = self.target(await self.view(), "web-01")["vulns"]["assets"][0]
        self.assertEqual({k: v for k, v in web.items() if k.startswith("vuln_")},
                         {"vuln_total": 6, "vuln_kev": 1, "vuln_fix_available": 2, "vuln_reboot_pending": 1,
                          "vuln_fix_unknown": 2})
        # 자산 화면(cti.asset_row)도 같은 수다
        row = await self.conn.fetchrow(t.cti.ASSETS_SQL, "web-01")
        self.assertEqual(t.cti.asset_row(row, self.now)["vuln_fix_unknown"], 2)

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
        # web-01 을 뺀 고정 대상은 노드를 등록하기 전과 같다. n1 R101 은 이제 이벤트로 고르고(n-web01 은 web-01 확인),
        #   이벤트가 없는 사건(n-bare)은 web-01 대체 추정이라 web-01 카드에서 빠져 장비 미확인으로 간다
        self.assertEqual([x for x in body["targets"][:4] if x["id"] != "web-01"],
                         [x for x in before["targets"][:4] if x["id"] != "web-01"])
        self.assertEqual(body["unmapped"], {"incidents_1h": before["unmapped"]["incidents_1h"] + 1,
                                            "pending": before["unmapped"]["pending"] + 1, "undetermined": 0})
        joins = [json.loads(args[0]) for sql, args in conn.fetched if sql == t.JOIN_SQL]
        self.assertEqual(len(joins), 1)
        self.assertEqual(sorted(i["k"] for i in joins[0]), ["n-bare", "n-web01", "w-mixed", "w-none", "w-upload"])
        self.assertEqual(self.target(before, "web-01")["security"]["pending"], 4)    # 등록 전: 2 + n-web01 · n-bare(규칙 범위)
        self.assertEqual(self.target(body, "web-01")["security"]["pending"], 3)      # 전의 2 + n-web01
        import main
        bare = next(x for x in (await main.incident_page(self.conn, device=t.UNCONFIRMED, limit=500))["items"]
                    if x["incident_key"] == "n-bare")
        self.assertEqual((bare["devices"], bare["device_state"]), ([], "unconfirmed"))
        self.assertEqual([(d["id"], d["basis"], d["logs"]) for d in bare["device_fallback"]],
                         [("web-01", "fallback", ["SSH 인증"])])
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
        self.assertEqual(web02["security"], {"incidents_1h": 0, "high_1h": 0, "pending": 0, "undetermined": 0, "parts": [],
                                             "latest": None})
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
        self.assertEqual(body["unmapped"], {"incidents_1h": 3, "pending": 3, "undetermined": 0})
        # 등록을 지우면 지금처럼: sshd 사건은 web-01, 근거 · node:<id> 로만 붙던 사건은 미분류다
        await self.conn.execute("DELETE FROM nodes WHERE node_id = 'web-02'")
        bare = await self.view()
        self.assertEqual([x["id"] for x in bare["targets"]], ["aws-sensor", "web-01", "console", "data-node"])
        self.assertEqual((self.target(bare, "web-01")["security"]["incidents_1h"],
                          self.target(bare, "web-01")["security"]["high_1h"]), (3, 1))
        self.assertEqual(bare["unmapped"], {"incidents_1h": 5, "pending": 5, "undetermined": 0})

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
                                  await self.view(), await t.monitor_view(self.conn, self.now))
                await self.conn.execute("RESET ROLE")
        finally:
            await self.conn.execute("RESET ROLE")
            await self.conn.execute(f"DROP OWNED BY {role}")
            await self.conn.execute(f"DROP ROLE {role}")
        table_privilege, body, _ = seen["columns"]
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
        # 관제 이상: 카드 열만 없으면 등록 노드 열 모름(web-01 은 판정한다), 다 없으면 노드 표 모름이다
        self.assertEqual({name: [(x["key"], x["reason"]) for x in seen[name][2]["items"] if x["key"].startswith("nodes")]
                          for name in seen},
                         {"columns": [], "no_hostname": [("nodes", "등록 노드 열을 읽을 수 없음")],
                          "none": [("nodes", "노드 표를 읽을 수 없음")]})

    async def test_API_는_한_트랜잭션에서_DB_시각으로_답한다(self):
        body = await t.dashboard_targets(self.request)
        self.assertIsInstance(body["as_of"], str)
        self.assertEqual(body["window_seconds"], 3600)
        self.assertEqual(len(body["targets"]), 4)
        self.assertEqual(body["queue"]["total"], 9)
        json.dumps(body)
        monitor = await t.dashboard_monitor(self.request)
        self.assertIsInstance(monitor["as_of"], str)
        json.dumps(monitor)

    async def test_카드_미판정_수는_장비_필터_목록_수와_같다(self):
        import main
        # 대체 추정이 생기는 사건: 기준선(R005, 출발지 없음) · 세션 근거 없는 R002 · 등록 노드가 있을 때 이벤트 없는 n1 R101.
        #   등록 노드 web-02 와 그 노드의 사건(node:web-02)도 넣는다
        await self.incident("r005", "R005", "v3", "medium", None, 400)
        await self.incident("s-bare", "R002", "v3", "high", "192.0.2.40", 300, evidence={})
        await self.incident("n-bare", "R101", "n1", "low", "198.51.100.41", 900)
        await self.incident("s-web02", "R301", "i2", "high", None, 600, None, "node:web-02")
        await self.node("web-02", hostname="web02.lab", sensor="web-02")
        # 같은 연결 · 두 조회 사이에 쓰기 없음
        body = await self.view()
        lists = {}
        for device in ["aws-sensor", "web-01", "console", "data-node", "web-02", t.UNCONFIRMED]:
            page = await main.incident_page(self.conn, judged=False, device=device, limit=500)
            lists[device] = [x["incident_key"] for x in page["items"]]
            want = body["unmapped"]["pending"] if device == t.UNCONFIRMED else \
                self.target(body, device)["security"]["pending"]
            with self.subTest(device=device):
                self.assertEqual((page["total"], len(lists[device])), (want, want))
        self.assertEqual(lists["web-02"], ["s-web02"])
        self.assertIn("s-bare", lists["aws-sensor"])
        self.assertNotIn("r005", lists["aws-sensor"])
        self.assertNotIn("n-bare", lists["web-01"])
        self.assertEqual(sorted(lists[t.UNCONFIRMED]), ["n-bare", "nodef", "r005", "w-none"])
        # 여러 장비에 붙은 사건은 그 장비 목록마다 한 번씩
        for device in ("web-01", "aws-sensor"):
            self.assertEqual(lists[device].count("w-mixed"), 1)
        # 모르는 장비는 0 건이다
        self.assertEqual((await main.incident_page(self.conn, device="web-09"))["total"], 0)

    async def test_미결은_최신_판정이_사람의_판단_유보인_사건만_센다(self):
        import main
        # web-01 에 붙는 사건(node:web-01). 낮은 심각도라 web-01 의 최근 중요 탐지(node)는 그대로다
        for key, first in [("u-twice", 600), ("u-rejudged", 600), ("u-system", 600), ("u-old", 3 * 86400),
                           ("u-old-system", 3 * 86400), ("u-old-rejudged", 3 * 86400)]:
            await self.incident(key, "R301", "i2", "low", None, first, None, "node:web-01")
        await self.verdict("u-twice", "undetermined", seconds=500)
        await self.verdict("u-twice", "undetermined", "kim", seconds=400)               # 같은 사건 두 번 → 1건
        await self.verdict("u-rejudged", "undetermined", seconds=500)
        await self.verdict("u-rejudged", "threat", seconds=400)                         # 미결 뒤 재판정 → 제외
        await self.verdict("u-system", "undetermined", "system:v3-cutover")             # 시스템 전환 기록 → 제외
        await self.verdict("u-old", "undetermined", None, 2 * 86400)                    # 창(24시간) 밖 · 판정자 없음
        await self.verdict("u-old-system", "undetermined", "system:v3-cutover", 2 * 86400)
        await self.verdict("u-old-rejudged", "undetermined", seconds=2 * 86400)         # 창 밖 사람 미결 뒤 재판정 → 제외
        await self.verdict("u-old-rejudged", "threat", seconds=86400 + 600)
        # 판정 대기이던 audit(콘솔)가 미결이 되면 미판정에서 빠지고, 최근 사건 줄은 판정됨이면서 값이 undetermined 다
        await self.verdict("audit", "undetermined")
        body = await self.view()
        web, console = self.target(body, "web-01")["security"], self.target(body, "console")["security"]
        self.assertEqual((web["undetermined"], web["pending"]), (2, 2))
        self.assertEqual(web["latest"]["incident_key"], "node")          # 창 밖 미결은 최근 사건 줄 후보가 아니다
        self.assertEqual((console["undetermined"], console["pending"]), (1, 0))
        self.assertEqual({k: console["latest"][k] for k in ("incident_key", "judged", "verdict")},
                         {"incident_key": "audit", "judged": True, "verdict": "undetermined"})
        self.assertEqual(self.target(body, "data-node")["security"]["latest"]["verdict"], None)     # self: 판정 없음
        self.assertEqual(body["unmapped"]["undetermined"], 0)
        rows = {r["incident_key"]: r for r in await self.conn.fetch(t.INCIDENTS_SQL, self.now, t.WINDOW_SECONDS,
                                                                        t.LATEST_HOURS)}
        self.assertEqual((rows["u-old"]["undetermined"], rows["u-old"]["in_window"]), (True, False))
        self.assertNotIn("u-old-system", rows)             # 시스템 기록뿐인 창 밖 사건은 읽지 않는다(778건이 매핑 비용이 되지 않게)
        self.assertNotIn("u-old-rejudged", rows)           # 사람 미결 기록이 있어 후보에 들어도 최신 판정이 미결이 아니면 뺀다
        self.assertEqual({k: (rows[k]["verdict"], rows[k]["undetermined"]) for k in ("u-twice", "u-rejudged", "u-system")},
                         {"u-twice": ("undetermined", True), "u-rejudged": ("threat", False),
                          "u-system": ("undetermined", False)})
        self.assertEqual(await self.conn.fetchval("SELECT count(*) FROM verdicts WHERE operator LIKE 'system:%'"), 2)
        # 요약 미결 수 = 미결 목록 수(u-twice · u-old · audit). 목록 행의 판정 값은 undetermined 다
        import test_dashboard_db
        schema = await test_dashboard_db.with_test_source(self.conn)     # 요약의 규칙 품질이 is_test_source 를 쓴다
        try:
            metrics = await dashboard_metrics(self.conn, self.now)
        finally:
            await self.conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        listed = await main.incident_page(self.conn, undetermined=True, limit=500)
        self.assertEqual((metrics["pending"]["undetermined"], listed["total"]), (3, 3))
        self.assertEqual(sorted(x["incident_key"] for x in listed["items"]), ["audit", "u-old", "u-twice"])
        self.assertEqual({x["verdict"] for x in listed["items"]}, {"undetermined"})
        self.assertNotIn("operator", listed["items"][0])
        # judged 와 함께 주면 AND 다
        self.assertEqual((await main.incident_page(self.conn, undetermined=True, judged=True, limit=500))["total"], 3)
        self.assertEqual((await main.incident_page(self.conn, undetermined=True, judged=False, limit=500))["total"], 0)
        everything = (await main.incident_page(self.conn, limit=500))["total"]
        others = await main.incident_page(self.conn, undetermined=False, limit=500)
        self.assertEqual(others["total"], everything - 3)
        self.assertIn("u-system", {x["incident_key"] for x in others["items"]})
        # 카드 미결 수 = 장비 · 미결 필터 목록 수(대체 추정을 뺀 같은 매핑)
        for device in ("aws-sensor", "web-01", "console", "data-node", t.UNCONFIRMED):
            page = await main.incident_page(self.conn, undetermined=True, device=device, limit=500)
            want = body["unmapped"]["undetermined"] if device == t.UNCONFIRMED else \
                self.target(body, device)["security"]["undetermined"]
            with self.subTest(device=device):
                self.assertEqual(page["total"], want)

    async def test_창_밖_미결은_대응_금지_대역_수와_최근_중요_탐지를_바꾸지_않는다(self):
        before = await self.view()
        # 금지 대역(10.0.0.0/8) 출발지의 높은 심각도 사건. 사흘 전이고 이틀 전 사람이 미결로 두었다
        await self.incident("u-exempt", "R301", "i2", "critical", "10.9.9.9", 3 * 86400, None, "node:web-01")
        await self.verdict("u-exempt", "undetermined", seconds=2 * 86400)
        body = await self.view()
        web, old = self.target(body, "web-01"), self.target(before, "web-01")
        self.assertEqual(web["security"]["undetermined"], old["security"]["undetermined"] + 1)
        self.assertEqual((web["response"]["exempt"], web["security"]["latest"]), (old["response"]["exempt"],
                                                                                 old["security"]["latest"]))
        # 창 안이면(24시간 안에 이어짐) 대응 금지 대역 수에 든다: 위 비교가 수를 세는 경로를 거친다
        await self.conn.execute("UPDATE incidents SET last_ts = $1 WHERE incident_key = 'u-exempt'", self.ago(600))
        self.assertEqual(self.target(await self.view(), "web-01")["response"]["exempt"], old["response"]["exempt"] + 1)

    async def test_마지막_로그와_웹_로그_적재_판정은_앞선_시각_줄을_뺀다(self):
        # 장비 로그 목록(node_logs)과 같은 기준: 기준 시각 + 5분까지는 넣고, 넘는 줄은 없는 것과 같다
        await self.conn.execute("DELETE FROM events WHERE sensor IN ('web-01', 'cowrie', 'decoy')")
        await self.conn.execute("ALTER TABLE nodes ADD COLUMN receipt jsonb NOT NULL DEFAULT '{}'")
        receipt = json.dumps({"nginx": {"lines": 3, "malformed": 0, "last_line_at": t.cti.iso(self.ago(60))}})
        await self.conn.execute("UPDATE nodes SET logs = '{nginx,auth,metrics}', receipt = $1 WHERE node_id = 'web-01'",
                                receipt)
        await self.event(-600, "nginx.request", "web-01", "198.51.100.90")          # 10분 앞선 줄만 있다
        await self.event(-600, "decoy.request", "decoy", "198.51.100.90")
        body = await self.view()
        web, aws = self.target(body, "web-01")["collection"], self.target(body, "aws-sensor")["collection"]
        self.assertEqual((web["state"], web["logs"][0]["last_at"]), ("quiet", None))
        self.assertEqual([w["key"] for w in web["warnings"]], ["parse"])            # 앞선 줄이 적재 없음 경고를 가리지 않는다
        self.assertEqual((aws["state"], {x["key"]: x["last_at"] for x in aws["logs"]}["decoy"]), ("quiet", None))
        self.assertIn("parse:web-01", [x["key"] for x in (await t.monitor_view(self.conn, self.now))["items"]])
        # 4분 앞선 줄(상한 안)은 넣는다
        await self.event(-240, "nginx.request", "web-01", "198.51.100.90")
        web = self.target(await self.view(), "web-01")["collection"]
        self.assertEqual((web["state"], web["logs"][0]["last_at"], web["warnings"]), ("ok", t.cti.iso(self.ago(-240)), []))

    async def test_취약점_대조_실패와_대조_오래됨은_수를_두고_칸으로_보인다(self):
        await self.conn.execute("UPDATE asset_inventory SET check_error = '대조 오류 시험' WHERE asset_id = 'web-01'")
        await self.conn.execute("UPDATE asset_inventory SET checked_at = $1 WHERE asset_id = 'console-a'", self.ago(49 * 3600))
        body = await self.view()
        [web] = self.target(body, "web-01")["vulns"]["assets"]
        self.assertEqual((web["check_failed"], web["check_stale"], web["vuln_total"], web["vuln_kev"],
                          web["vuln_fix_available"]), (True, False, 2, 1, 2))
        self.assertNotIn("check_error", web)
        console = {a["asset_id"]: a for a in self.target(body, "console")["vulns"]["assets"]}
        self.assertEqual((console["console-a"]["check_failed"], console["console-a"]["check_stale"],
                          console["console-a"]["stale"]), (False, True, False))
        self.assertEqual((console["console-b"]["missing"], console["console-b"]["check_failed"],
                          console["console-b"]["check_stale"]), (True, False, False))
        # 조사 · 대조가 모두 49시간 전인 허니팟 자산은 조사 오래됨이면서 대조 오래됨이다
        honeypot = self.target(body, "aws-sensor")["vulns"]["assets"][0]
        self.assertEqual((honeypot["asset_id"], honeypot["stale"], honeypot["check_stale"]), ("honeypot-dmz", True, True))

    async def test_장비_필터는_쪽을_나누기_전에_거른다(self):
        import main
        full = await main.incident_page(self.conn, device="aws-sensor", limit=500)
        keys = [x["incident_key"] for x in full["items"]]
        self.assertEqual(full["total"], len(keys))
        self.assertGreaterEqual(len(keys), 5)
        paged = []
        for offset in range(len(keys) + 1):
            page = await main.incident_page(self.conn, device="aws-sensor", limit=1, offset=offset)
            self.assertEqual(page["total"], full["total"])
            paged += [x["incident_key"] for x in page["items"]]
        self.assertEqual(paged, keys)          # 겹치거나 빠지지 않는다
        # 정렬(미판정 · 최근)은 필터 없는 목록의 부분열이다
        for sort in ("pending", "recent"):
            everything = [x["incident_key"] for x in (await main.incident_page(self.conn, sort=sort, limit=500))["items"]]
            for device in ("aws-sensor", "web-01", t.UNCONFIRMED):
                picked = [x["incident_key"]
                          for x in (await main.incident_page(self.conn, sort=sort, device=device, limit=500))["items"]]
                with self.subTest(sort=sort, device=device):
                    self.assertTrue(picked)
                    self.assertEqual(picked, [k for k in everything if k in set(picked)])

    async def test_연결_근거와_상세의_장비는_목록과_같다(self):
        import main
        await self.incident("s-bare", "R002", "v3", "high", "192.0.2.40", 300, evidence={})
        # 근거의 sensors · sessions 가 배열이 아니면(글자) 목록 · 상세 모두 없는 것으로 본다(JSON 으로 다시 읽지 않는다)
        await self.incident("ev-str", "R001", "v3", "medium", "192.0.2.41", 300, evidence={"sensors": "cowrie"})
        await self.incident("ev-json", "R001", "v3", "medium", "192.0.2.42", 300, evidence={"sensors": json.dumps(["web-01"])})
        await self.incident("ev-sess", "R002", "v3", "high", "192.0.2.43", 300, evidence={"sessions": "x"})
        page = await main.incident_page(self.conn, limit=500)
        items = {x["incident_key"]: x for x in page["items"]}
        self.assertEqual({k: items[k]["device_state"] for k in ("w-mixed", "cve", "node", "audit", "self", "w-none",
                                                                  "nodef", "s-bare")},
                         {"w-mixed": "confirmed", "cve": "confirmed", "node": "confirmed", "audit": "confirmed",
                          "self": "rule_scope", "w-none": "unconfirmed", "nodef": "unconfirmed", "s-bare": "rule_scope"})
        self.assertEqual([(d["id"], d["part"], d["basis"], d["logs"]) for d in items["w-mixed"]["devices"]],
                         [("web-01", None, "confirmed", ["SSH 인증"]), ("aws-sensor", "decoy", "confirmed", ["웹 요청"])])
        self.assertEqual([(d["label"], d["logs"]) for d in items["self"]["devices"]],
                         [("데이터 노드", ["수집 관문", "원장 가져오기"])])
        self.assertEqual([(d["id"], d["part"], d["basis"]) for d in items["s-bare"]["devices"]],
                         [("aws-sensor", None, "rule_scope")])
        self.assertEqual([(d["id"], d["part"], d["basis"]) for d in items["s-bare"]["device_fallback"]],
                         [("aws-sensor", "cowrie", "fallback")])
        for key in ("ev-str", "ev-json"):
            self.assertEqual([(d["id"], d["part"], d["basis"]) for d in items[key]["devices"]],
                             [("aws-sensor", "cowrie", "rule_scope")])
        self.assertEqual({k: items["ev-sess"][k] for k in DEVICE_KEYS}, {k: items["s-bare"][k] for k in DEVICE_KEYS})
        self.assertFalse({"sensors", "sessions"} & set(items["cve"]))
        self.assertEqual([o["id"] for o in page["device_options"]], ["web-01", "aws-sensor", "console", "data-node"])
        # 상세는 목록 항목과 같은 장비를 싣는다
        await self.conn.execute(DETAIL_TABLES)
        with patch.object(main.app.state, "pool", SimpleNamespace(acquire=self.acquire), create=True):
            for key in ("w-mixed", "cve", "node", "audit", "self", "w-none", "nodef", "s-bare",
                        "ev-str", "ev-json", "ev-sess"):
                detail = await main.get_incident(key)
                with self.subTest(key=key):
                    self.assertEqual({k: detail[k] for k in DEVICE_KEYS}, {k: items[key][k] for k in DEVICE_KEYS})

    async def test_탐지_경로는_규칙_정의로_가르고_24시간_안만_읽는다(self):
        await self.conn.execute("DELETE FROM detector_runs")
        for version, seconds in [("v3", 60), ("v3", 1200), ("v1", 7200), ("s1", 30), ("w2", 1000), ("a1", 45),
                                 ("i2", 50), ("c1", 70), ("sg1", 80), ("zz", 100), ("n1", 90000)]:
            await self.conn.execute("INSERT INTO detector_runs (rule_version, started_at, finished_at) VALUES ($1, $2, $2)",
                                    version, self.ago(seconds))
        rows = await self.conn.fetch(t.DETECT_PATHS_SQL, self.now)
        # 규칙 id 가 모두 R0xx 인 버전만 허니팟이다. 규칙 정의가 없는 버전(zz)은 허니팟이 아니다. 25시간 전(n1)은 읽지 않는다
        self.assertEqual({r["rule_version"]: r["honeypot"] for r in rows},
                         {"v1": True, "v3": True, "a1": False, "c1": False, "i2": False, "s1": False, "sg1": False,
                          "w2": False, "zz": False})
        self.assertEqual(next(r["last_at"] for r in rows if r["rule_version"] == "v3"), self.ago(60))
        honeypot, bridge = t.detect_paths(rows, self.now)
        self.assertEqual((honeypot["stale"], [v["rule_version"] for v in honeypot["versions"]]), (False, ["v1", "v3"]))
        # 1분 다리는 돌아야 할 버전만 본다(정의 없는 zz 는 보지 않는다)
        self.assertEqual((bridge["stale"], bridge["reason"]), (True, "w2 마지막 실행 16분 전"))
        self.assertEqual([v["rule_version"] for v in bridge["versions"]], sorted(t.BRIDGE_VERSIONS))
        monitor = await t.monitor_view(self.conn, self.now)
        self.assertEqual(monitor["detect_paths"], [honeypot, bridge])
        self.assertEqual([x["key"] for x in monitor["items"] if x["key"].startswith("detect:")], ["detect:bridge"])

    async def test_1분_다리_버전은_하루_넘게_멈춰도_띠와_데이터_노드_카드에_남는다(self):
        for hours, reason in ((23, "c1 마지막 실행 23시간 전"), (25, "c1 24시간 넘게 실행 없음")):
            await self.conn.execute("DELETE FROM detector_runs WHERE rule_version = 'c1'")
            await self.conn.execute("INSERT INTO detector_runs (rule_version, started_at, finished_at) VALUES ('c1', $1, $1)",
                                    self.ago(hours * 3600))
            monitor = await t.monitor_view(self.conn, self.now)
            data = self.target(await self.view(), "data-node")["collection"]
            with self.subTest(hours=hours):
                self.assertEqual([(x["key"], x["reason"]) for x in monitor["items"] if x["key"].startswith("detect:")],
                                 [("detect:bridge", reason)])
                # 전체 최신 실행(4분 전)만 보면 정상이다. 한 경로가 멈췄으니 주의(stopped)이고 까닭 끝에 붙는다
                self.assertEqual((data["state"], data["reason"], data["stopped"]),
                                 ("ok", f"마지막 탐지 실행 4분 전 · 노드 · 관제 탐지(1분) 멈춤 · {reason}", ["detect"]))
        # 교체된 옛 버전(w1) · 떼어 낸 버전(n1)의 기록은 멈춰 있어도 보지 않는다
        await self.conn.execute("DELETE FROM detector_runs WHERE rule_version = 'c1'")
        await self.conn.execute("""INSERT INTO detector_runs (rule_version, started_at, finished_at)
            VALUES ('c1', $1, $1), ('w1', $2, $2), ('n1', $3, $3)""", self.ago(300), self.ago(3660), self.ago(23 * 3600))
        monitor = await t.monitor_view(self.conn, self.now)
        self.assertEqual([x["key"] for x in monitor["items"] if x["key"].startswith("detect:")], [])
        self.assertEqual(self.target(await self.view(), "data-node")["collection"]["stopped"], [])

    async def test_카드가_이상이면_띠에도_항목이_있다(self):
        # 센서 · 관문 기록 신호 끊김, 1분 다리 c1 기록 없음, 지점 불일치(관문 · 내부 방화벽) · 실패 · 보고 문제(block:fw),
        #   등록 노드 web-02 수신 끊김(지표도 오래됨), web-01 웹 로그 적재 없음 · 자원 지표 오래됨. web-03 은 정상이다
        await self.conn.execute("ALTER TABLE nodes ADD COLUMN receipt jsonb NOT NULL DEFAULT '{}'")
        await self.conn.execute("UPDATE sensor_heartbeats SET seen_at = $1, checked_at = $2 WHERE source = $3",
                                self.ago(1100), self.ago(120), "uploader:i-0123456789abcdef0")
        await self.conn.execute("UPDATE sensor_heartbeats SET seen_at = $1 WHERE source = $2", self.ago(1500),
                                "uploader:i-0fedcba9876543210")
        await self.conn.execute("DELETE FROM detector_runs WHERE rule_version = 'c1'")
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, enforcement) VALUES
            ('203.0.113.9', $1, '{"gateway": {"state": "confirmed"}, "fw": {"state": "stale"}}')""",
                                self.now + timedelta(hours=1))
        receipt = json.dumps({"nginx": {"lines": 30, "malformed": 30, "last_line_at": t.cti.iso(self.ago(60))}})
        await self.conn.execute("UPDATE nodes SET logs = '{nginx,auth,metrics}', receipt = $1 WHERE node_id = 'web-01'", receipt)
        await self.node("web-02", hostname="web02.lab", sensor="web-02", seen=1200)
        await self.node("web-03", sensor="web-03")
        await self.conn.execute("UPDATE nodes SET logs = '{nginx}', receipt = $1 WHERE node_id = 'web-03'", receipt)
        await self.event(30, "nginx.request", "web-03", "203.0.113.30")
        await self.conn.execute("UPDATE node_metrics SET ts = ts - interval '12 minutes'")
        conn = Counted(self.conn)
        async with self.conn.transaction(isolation="repeatable_read", readonly=True):
            body = await self.view()
            monitor = await t.monitor_view(conn, self.now)
        keys = [x["key"] for x in monitor["items"]]
        needs = band_needs(body)
        self.assertGreaterEqual(len(needs), 10)
        for why, want in needs:
            with self.subTest(card=why):
                self.assertTrue(want & set(keys), f"{why}: 띠 {keys} 에 {sorted(want)} 가 없다")
        self.assertEqual(keys, ["sensor", "gateway_uploader", "detect:bridge", "block_failed:fw", "point_stale:gateway",
                                "point_stale:fw", "report:fw", "nodes_silent", "parse:web-01", "metrics:web-01", "data_resources"])
        items = {x["key"]: x for x in monitor["items"]}
        # 센서 까닭은 카드 까닭 그대로다(관문 기록 신호 시각까지)
        self.assertEqual(items["sensor"]["reason"], "업로더 생존 신호 18분 전 · 적재기 확인 2분 전 · 확인 때 이미 15분 넘게 새 신호 없음"
                                                    " · 관문 기록 신호 25분 전")
        self.assertEqual(items["sensor"]["reason"], self.target(body, "aws-sensor")["collection"]["reason"])
        self.assertEqual(items["nodes_silent"]["reason"], "web-02 수신 끊김 · 마지막 수신 20분 전")
        self.assertEqual(items["report:fw"]["reason"], "받은 보고 없음 · 보고 파일 없음")
        self.assertEqual(self.target(body, "web-01")["response"]["report_issue"], items["report:fw"]["reason"])
        self.assertEqual(items["parse:web-01"]["reason"], "로그는 도착하는데 적재되지 않음 · 마지막 도착 1분 전")
        web = self.target(body, "web-01")
        self.assertEqual((web["collection"]["state"], [w["key"] for w in web["collection"]["warnings"]],
                          web["response"]["stale"]), ("ok", ["parse"], 1))
        self.assertEqual(self.target(body, "web-03")["collection"]["warnings"], [])
        # 데이터 노드 조회 2개와 now 를 더해 10개 이하다
        self.assertLessEqual(len(conn.queries), 9)
        self.assertEqual(conn.queries.count(t.PARSE_SQL), 1)

    async def test_시험_출발지로_적재된_웹_로그도_적재다(self):
        # 노드 추가의 첫 수신 탐침(127.0.0.1 한 줄) · 운영자 회선 요청은 시험 출발지라 fixture 로 적재된다. 적재됐으니 경고가 아니다
        await self.conn.execute("ALTER TABLE nodes ADD COLUMN receipt jsonb NOT NULL DEFAULT '{}'")
        await self.node("web-02", sensor="web-02")
        receipt = json.dumps({"nginx": {"lines": 1, "malformed": 0, "last_line_at": t.cti.iso(self.ago(120))}})
        await self.conn.execute("UPDATE nodes SET logs = '{nginx,auth,metrics}', receipt = $1 WHERE node_id = 'web-02'", receipt)
        await self.event(120, "nginx.request", "web-02", "127.0.0.1", provenance="fixture")

        async def parse():
            monitor = await t.monitor_view(self.conn, self.now)
            card = self.target(await self.view(), "web-02")["collection"]
            return [x["key"] for x in monitor["items"] if x["key"].startswith("parse:")], [w["key"] for w in card["warnings"]]
        self.assertEqual(await parse(), ([], []))
        # 적재된 줄이 없으면 카드 · 띠 모두 경고다
        await self.conn.execute("DELETE FROM events WHERE sensor = 'web-02'")
        self.assertEqual(await parse(), (["parse:web-02"], ["parse"]))

    async def test_폐기_등록_대기인_web_01_의_옛_지표는_띠에_없다(self):
        await self.conn.execute("UPDATE node_metrics SET ts = ts - interval '2 hours'")
        for status, want in (("active", ["metrics:web-01"]), ("revoked", []), ("pending", [])):
            await self.conn.execute("UPDATE nodes SET status = $1 WHERE node_id = 'web-01'", status)
            monitor = await t.monitor_view(self.conn, self.now)
            body = await self.view()
            with self.subTest(status=status):
                self.assertEqual([x["key"] for x in monitor["items"] if x["key"].startswith("metrics:")], want)
                keys = {x["key"] for x in monitor["items"]}
                for why, need in band_needs(body):
                    self.assertTrue(need & keys, f"{why}: 띠 {sorted(keys)} 에 {sorted(need)} 가 없다")

    async def test_관제_이상과_먼저_처리할_사건은_요약과_같은_기준이다(self):
        import main
        import test_dashboard_db
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, enforce_note) VALUES
            ('203.0.113.20', $1, '관문 불일치 · 관문 상태가 7분 전'), ('203.0.113.21', NULL, '관문 불일치 · 만료 없음')""",
                                self.now + timedelta(hours=1))
        schema = await test_dashboard_db.with_test_source(self.conn)     # 요약의 규칙 품질이 is_test_source 를 쓴다
        try:
            with patch.object(main.app.state, "pool", SimpleNamespace(acquire=self.acquire), create=True):
                summary = await main.summary()
            monitor = await t.monitor_view(self.conn, self.now)
            view = await t.targets_view(self.conn, self.now, queue=True)
            metrics = await dashboard_metrics(self.conn, self.now)
        finally:
            await self.conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        mismatch = next(x for x in monitor["items"] if x["key"] == "gateway_mismatch")
        self.assertEqual((mismatch["count"], summary["blocks"]["mismatch"]), (1, 1))
        # 요약의 지점별 수 = 카드 대응
        for point, tid in (("gateway", "aws-sensor"), ("fw", "web-01")):
            card = self.target(view, tid)["response"]
            got = next(x for x in summary["blocks_by_point"] if x["point"] == point)
            keys = ("applied", "failed", "unverified", "stale", "checking", "delayed", "stalled")
            self.assertEqual({k: got[k] for k in keys}, {k: card[k] for k in keys})
        # 먼저 처리할 사건: 미판정 전체(대시보드 판정 대기와 같은 수)를 앞 · 뒤로 가른다
        queue = view["queue"]
        self.assertEqual(queue["total"], metrics["pending"]["total"])
        self.assertEqual({k: queue[k] for k in ("total", "front", "back", "unconfirmed")},
                         {"total": 9, "front": 6, "back": 3, "unconfirmed": 2})
        self.assertEqual([(x["incident_key"], x["lane"]) for x in queue["items"]],
                         [("node", "front"), ("w-mixed", "front"), ("w-none", "front"), ("nodef", "front"),
                          ("self", "front"), ("audit", "front"), ("old-pending", "back"), ("c-out", "back")])
        self.assertEqual(queue["overdue"], metrics["pending"]["overdue"])

    async def test_미확인은_확인_중과_확인_지연으로_나뉜다(self):
        # 이슈 #84 결정 6: 확인 전(pending · 기록 없음)이 그 상태가 된 시각(enforcement.<지점>.since, 없으면 요청 시각 created_at)부터
        #   5분 안이면 확인 중, 넘었으면 지점 불일치(stale)와 함께 확인 지연이다. 합은 미확인이다. 시각 글자가 아니어도(캐스트 오류
        #   대신) 요청 시각으로 잰다. 관문을 뺀 뒤 다시 요청한 행에 남은 removing(집행기가 다음 회차까지 이어받지 않는다)도 요청 시각으로
        #   잰다(방금 다시 요청했으면 확인 중). 요청하지 않은 지점 · 확인 · 실패는 어느 쪽에도 들지 않는다
        live, TWO = self.now + timedelta(hours=1), ["gateway", "fw"]

        def since(seconds):
            return t.cti.iso(self.ago(seconds))
        await self.conn.execute("DELETE FROM blocklist")
        for ip, created, enforcement, points in [
                ("198.51.100.101", 60, {"gateway": {"state": "pending", "since": since(60)},
                                        "fw": {"state": "pending", "since": since(290)}}, TWO),
                ("198.51.100.102", 600, {"gateway": {"state": "pending", "since": since(310)},
                                         "fw": {"state": "stale", "since": since(30)}}, TWO),
                ("198.51.100.103", 400, None, TWO),                                  # 기록 없음 · 요청 6분 40초 전
                ("198.51.100.104", 10, None, TWO),                                   # 기록 없음 · 방금 요청
                ("198.51.100.105", 600, {"gateway": {"state": "pending", "since": "2026-13-45T00:00:00+00:00"},
                                         "fw": {"state": "pending", "since": "어제"}}, TWO),
                ("198.51.100.106", 600, {"gateway": {"state": "confirmed"}, "fw": {"state": "failed"}}, TWO),
                ("198.51.100.107", 600, {"fw": {"state": "pending", "since": since(30)}}, ["fw"]),       # 관문 미요청
                ("198.51.100.108", 10, {"gateway": {"state": "removing", "since": since(1200)},           # 관문 다시 요청 직후
                                        "fw": {"state": "confirmed"}}, TWO)]:
            await self.conn.execute("""INSERT INTO blocklist (actor_ip, created_at, expires_at, enforcement, points)
                VALUES ($1, $2, $3, $4::jsonb, $5::text[])""", ip, self.ago(created), live,
                json.dumps(enforcement) if enforcement is not None else None, points)
        body = await self.view()
        keys = ("applied", "failed", "unverified", "stale", "checking", "delayed", "unrequested")
        aws, web = (self.target(body, tid)["response"] for tid in ("aws-sensor", "web-01"))
        self.assertEqual({k: aws[k] for k in keys}, {"applied": 1, "failed": 0, "unverified": 6, "stale": 0,
                                                     "checking": 3, "delayed": 3, "unrequested": 1})
        self.assertEqual({k: web[k] for k in keys}, {"applied": 1, "failed": 1, "unverified": 6, "stale": 1,
                                                     "checking": 3, "delayed": 3, "unrequested": 0})
        for r in (aws, web):
            self.assertEqual(r["checking"] + r["delayed"], r["unverified"])
        # 집행기가 멈춘 지점은 나누지 않는다(미확인에 모두 합치고 화면은 그 지점 경고 하나다)
        await self.conn.execute("DELETE FROM sensor_heartbeats WHERE source = 'block:fw'")
        web = self.target(await self.view(), "web-01")["response"]
        self.assertEqual((web["unverified"], web["checking"], web["delayed"], web["stalled"]), (8, 0, 0, "집행기 확인 기록 없음"))

    async def test_확인_지연은_띠에도_있고_그_지점_보고가_이상이면_그_항목이다(self):
        # 이슈 #84 결정 6 · 카드 ⇒ 띠: 관문 보고가 8분 전(15분 안 · 문제 없음)이면 집행기는 판정하지 못한 회차에 직전 대기와 그 시각을
        #   둔다. 5분을 넘긴 대기는 카드 '적용 확인 지연' 이고 띠에는 지점 확인 지연 항목(불일치를 뺀 수)이 있다. 내부 방화벽처럼 그 지점
        #   보고가 이상이면(받은 보고 없음) 같은 현상이라 보고 항목 하나다. 관문 보고가 15분을 넘기면 관문도 보고 항목 하나가 된다
        def since(seconds):
            return t.cti.iso(self.ago(seconds))
        await self.conn.execute("DELETE FROM blocklist")
        await self.conn.execute("UPDATE sensor_heartbeats SET seen_at = $1, checked_at = $2 WHERE source = 'block:gateway'",
                                self.ago(480), self.ago(10))
        live = self.now + timedelta(hours=1)
        for ip, enforcement in [("198.51.100.111", {"gateway": {"state": "pending", "since": since(360)},
                                                    "fw": {"state": "pending", "since": since(360)}}),
                                ("198.51.100.112", {"gateway": {"state": "stale", "since": since(60)}, "fw": {"state": "confirmed"}})]:
            await self.conn.execute("""INSERT INTO blocklist (actor_ip, created_at, expires_at, enforcement)
                VALUES ($1, $2, $3, $4::jsonb)""", ip, self.ago(360), live, json.dumps(enforcement))

        async def look():
            async with self.conn.transaction(isolation="repeatable_read", readonly=True):
                body = await self.view()
                items = (await t.monitor_view(self.conn, self.now))["items"]
            for why, need in band_needs(body):
                self.assertTrue(need & {x["key"] for x in items}, f"{why}: 띠 {[x['key'] for x in items]} 에 {sorted(need)} 가 없다")
            return body, {x["key"]: x for x in items if x["key"].endswith((":gateway", ":fw"))}
        body, band = await look()
        aws, web = (self.target(body, tid)["response"] for tid in ("aws-sensor", "web-01"))
        self.assertEqual((aws["delayed"], aws["stale"], aws["report_issue"], web["delayed"], web["report_issue"]),
                         (2, 1, None, 1, "받은 보고 없음 · 보고 파일 없음"))
        self.assertEqual({k: x["count"] for k, x in band.items()}, {"point_stale:gateway": 1, "report:fw": None,
                                                                    "point_delayed:gateway": 1})
        self.assertEqual(band["point_delayed:gateway"]["label"], "허니팟 관문 적용 확인 지연")
        await self.conn.execute("UPDATE sensor_heartbeats SET seen_at = $1 WHERE source = 'block:gateway'", self.ago(960))
        body, band = await look()
        self.assertEqual(list(band), ["point_stale:gateway", "report:gateway", "report:fw"])
        self.assertEqual(self.target(body, "aws-sensor")["response"]["report_issue"], band["report:gateway"]["reason"])

    async def test_내부_방화벽만_요청한_행은_관문_수와_관문_항목에_들지_않는다(self):
        # 이슈 #77. 지점 수는 그 지점을 요청한 행만 세고 관문 미요청은 따로 센다. 관문 불일치 · 관문 띠 항목은 관문 요청 행만이다.
        #   남은 관문 결과 · 쪽지(관문 빼기 뒤 관문이 뺐다고 확인하기 전)가 있으면 미요청이 아니라 빠짐 확인 전이고(결정 14) 관문 칸 ·
        #   띠에 들지 않는다. 기존 행(두 지점) 수는 그대로다
        def counts(body, tid):
            return {k: self.target(body, tid)["response"][k] for k in ("applied", "failed", "unverified", "stale",
                                                                        "unrequested", "removing")}

        def band(monitor):
            return {x["key"]: x["count"] for x in monitor["items"]}
        before = await self.view()
        band_before = band(await t.monitor_view(self.conn, self.now))
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, enforce_note, enforcement, points) VALUES
            ('203.0.113.40', $1, NULL, '{"fw": {"state": "confirmed"}}', '{fw}'),
            ('203.0.113.41', $1, '관문 불일치 · 관문 빼기 전 쪽지', '{"gateway": {"state": "failed"}, "fw": {"state": "stale"}}',
             '{fw}')""", self.now + timedelta(hours=1))
        after = await self.view()
        band_after = band(await t.monitor_view(self.conn, self.now))
        self.assertEqual(counts(after, "aws-sensor"), counts(before, "aws-sensor") | {"unrequested": 1, "removing": 1})
        gained = {k: counts(after, "web-01")[k] - counts(before, "web-01")[k] for k in counts(before, "web-01")}
        self.assertEqual(gained, {"applied": 1, "failed": 0, "unverified": 1, "stale": 1, "unrequested": 0, "removing": 0})
        self.assertEqual((counts(before, "aws-sensor")["unrequested"], counts(before, "aws-sensor")["removing"]), (0, 0))
        # 띠: 내부 방화벽 불일치만 새로 뜨고 관문 적용 실패 · 관문 불일치 · 관문 지점 불일치 수는 그대로다
        self.assertEqual({k: v for k, v in band_after.items() if band_before.get(k) != v}, {"point_stale:fw": 1})
        self.assertNotIn("gateway_mismatch", band_after)


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class ConsoleLinksTests(Base):
    """콘솔 DB 연결(이슈 #76). 실제 pg_stat_activity 에서 이 DB 의 같은 역할(current_user) 연결 가운데 콘솔 이름표인 것만 센다.
    시험 연결(postgres)과 같은 역할로 이름표를 단 연결을 따로 열어 콘솔을 흉내 낸다. 상태판은 조회마다 새 트랜잭션이다."""
    with_cti = False

    async def link(self, name=None, **kw):
        import asyncpg
        conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"],
                                     server_settings={"application_name": name} if name else None, **kw)
        self.addAsyncCleanup(conn.close)
        return conn

    async def console(self):
        async with self.conn.transaction(isolation="repeatable_read", readonly=True):
            body = await self.view()
        return next(x for x in body["targets"] if x["id"] == "console")["collection"]

    async def test_이름표_있는_연결만_있음이고_닫으면_다음_조회에_없음이다(self):
        none = "DB 연결 확인: 콘솔 A 없음 · 콘솔 B 없음(평소 꺼 두는 예비)"
        self.assertEqual((await self.console())["reason"], none)
        await self.link()                                           # 이름표 없는 연결은 세지 않는다
        await self.link("opsloop-console-c")                        # 모르는 콘솔 이름도 세지 않는다
        self.assertEqual((await self.console())["reason"], none)
        a = await self.link("opsloop-console-a")
        await self.link("opsloop-console-a")                        # 같은 이름 연결이 여럿이어도 있음 하나다(수는 보지 않는다)
        got = await self.console()
        self.assertEqual((got["state"], got["reason"]), ("responding", "DB 연결 확인: 콘솔 A 있음 · 콘솔 B 없음(평소 꺼 두는 예비)"))
        self.assertEqual([(x["name"], x["present"]) for x in got["db_links"]],
                         [("opsloop-console-a", True), ("opsloop-console-b", False)])
        b = await self.link("opsloop-console-b")
        self.assertEqual((await self.console())["reason"], "DB 연결 확인: 콘솔 A 있음 · 콘솔 B 있음")
        # 콘솔 B 를 멈추면(연결을 닫으면) 다음 조회에 없음이다. 백엔드 종료는 비동기라 5초 안에서 다시 묻는다
        await b.close()
        reason = None
        for _ in range(50):
            reason = (await self.console())["reason"]
            if reason.endswith("콘솔 B 없음(평소 꺼 두는 예비)"):
                break
            await asyncio.sleep(0.1)
        self.assertEqual(reason, "DB 연결 확인: 콘솔 A 있음 · 콘솔 B 없음(평소 꺼 두는 예비)")
        self.assertFalse(a.is_closed())

    async def test_다른_역할이_같은_이름표를_써도_세지_않는다(self):
        import asyncpg
        role, password = f"t76_{secrets.token_hex(4)}", secrets.token_urlsafe(18)
        await self.conn.execute(f"CREATE ROLE {role} LOGIN PASSWORD '{password}'")
        try:
            try:
                other = await self.link("opsloop-console-b", user=role, password=password)
            except (asyncpg.InvalidAuthorizationSpecificationError, asyncpg.InvalidPasswordError, OSError) as e:
                self.skipTest(f"합성 역할로 붙을 수 없다(pg_hba): {e}")
            self.assertEqual(await other.fetchval("SELECT current_setting('application_name')"), "opsloop-console-b")
            self.assertEqual((await self.console())["reason"], "DB 연결 확인: 콘솔 A 없음 · 콘솔 B 없음(평소 꺼 두는 예비)")
            await other.close()
        finally:
            for _ in range(50):                                     # 백엔드가 끝나야 역할을 지울 수 있다
                if not await self.conn.fetchval("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename = $1", role):
                    break
                await asyncio.sleep(0.1)
            await self.conn.execute(f"DROP ROLE IF EXISTS {role}")

    async def test_연결_목록을_읽지_못하면_확인_불가다(self):
        # 역할 블록과 무관하게 pg_stat_activity 읽기가 막힌 DB 를 흉내 낸다. 바꾼 권한은 트랜잭션을 되돌려 남기지 않는다
        await self.link("opsloop-console-a")
        role = f"t76_{secrets.token_hex(4)}"
        tx = self.conn.transaction()
        await tx.start()
        try:
            await self.conn.execute(f"CREATE ROLE {role} NOLOGIN")
            for table in ("incidents", "verdicts", "rule_versions", "events", "nodes", "detector_runs", "blocklist",
                          "block_exempt", "node_metrics", "sensor_heartbeats"):
                await self.conn.execute(f"GRANT SELECT ON pg_temp.{table} TO {role}")
            await self.conn.execute("REVOKE SELECT ON pg_catalog.pg_stat_activity FROM PUBLIC")
            await self.conn.execute(f"SET LOCAL ROLE {role}")
            self.assertFalse(await self.conn.fetchval(t.CONSOLE_LINKS_READABLE_SQL))
            body = await self.view()
        finally:
            await tx.rollback()
        console = next(x for x in body["targets"] if x["id"] == "console")["collection"]
        self.assertEqual((console["state"], console["reason"], console["db_links"]), ("responding", "DB 연결 확인 불가", None))
        self.assertTrue(await self.conn.fetchval("SELECT has_table_privilege('public', 'pg_catalog.pg_stat_activity', 'SELECT')"))
        self.assertFalse(await self.conn.fetchval("SELECT count(*) > 0 FROM pg_roles WHERE rolname = $1", role))


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
        self.assertEqual((aws["response"]["applied"], aws["response"]["unverified"], aws["response"]["stalled"]),
                         (0, 0, "집행 보고를 읽을 수 없음 · 적용 여부 확인 불가"))
        web = next(x for x in body["targets"] if x["id"] == "web-01")
        self.assertEqual(web["system"], {"state": "no_privilege", "metrics": None})
        data = next(x for x in body["targets"] if x["id"] == "data-node")
        self.assertEqual([e["note"] for e in data["collection"]["extra"]], ["생존 신호 표를 읽을 수 없음"] * 2)
        self.assertEqual([x["vulns"] for x in body["targets"]], [{"available": False, "assets": []}] * 4)
        json.dumps(body)

    async def test_표가_없어도_카드가_이상이면_띠에도_항목이_있다(self):
        # 생존 신호 표가 없으면 센서 · 대응(옛 '적용 확인' 은 미확인으로 합침)이 확인 불가이고 띠는 '생존 신호' 하나가 말한다
        await self.conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, enforcement) VALUES
            ('203.0.113.1', $1, '{"gateway": {"state": "confirmed"}, "fw": {"state": "failed"}}')""",
                                self.now + timedelta(hours=1))
        body = await self.view()
        keys = [x["key"] for x in (await t.monitor_view(self.conn, self.now))["items"]]
        needs = band_needs(body)
        #   web-01 등록 기록이 없으면(카드 '노드 등록 기록 없음') 노드 수신 모름이다
        self.assertLessEqual({"aws-sensor 수집 unknown", "data-node 탐지 unknown", "web-01 노드 등록 기록 없음",
                              "aws-sensor 집행 보고를 읽을 수 없음 · 적용 여부 확인 불가"}, {why for why, _ in needs})
        for why, want in needs:
            with self.subTest(card=why):
                self.assertTrue(want & set(keys), f"{why}: 띠 {keys} 에 {sorted(want)} 가 없다")
        self.assertEqual(keys, ["heartbeats", "detect:honeypot", "detect:bridge", "nodes", "data_resources"])
        web = next(x for x in body["targets"] if x["id"] == "web-01")["response"]
        self.assertEqual((web["applied"], web["failed"], web["unverified"]), (0, 0, 1))

    async def test_nodes_표가_없으면_고정_네_대상만이다(self):
        await self.conn.execute("DROP TABLE nodes")
        body = await t.dashboard_targets(self.request)
        self.assertEqual([x["id"] for x in body["targets"]], ["aws-sensor", "web-01", "console", "data-node"])
        web = next(x for x in body["targets"] if x["id"] == "web-01")["collection"]
        self.assertEqual((web["state"], web["reason"]), ("unknown", "노드 표를 읽을 수 없음"))


if __name__ == "__main__":
    unittest.main()
