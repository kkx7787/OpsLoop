"""기간 보고서(reports.py · 이슈 #58)의 PostgreSQL 시험.  OPSLOOP_TEST_DATABASE_URL=... python3 -m unittest discover -s app

이름이 무작위인 스키마를 만들어 infra/schema.sql 의 표 정의(CREATE TABLE 과 뒤에 붙인 ALTER TABLE) · audit_log 뷰 · is_test_source 를
글자 그대로 넣고 끝나면 지운다. 트리거 · 권한 · 초기값은 넣지 않는다(infra 시험이 본다). search_path 를 그 스키마로만 두어 운영 표를
가린다. 시험 대역은 203.0.113.0/24 만 둔다(기존 app 시험과 같다. 192.0.2.x · 198.51.100.x 는 실제 출발지로 센다).
기준 시각을 고정해 넘긴다(reports.build). 24시간 기간은 2026-09-27 03:00 ~ 09-28 03:00 UTC(12:00 ~ 12:00 KST)이고
KST 날짜는 09-27 15:00 UTC 에 바뀐다.

  - 경계: [since, until). since 와 같은 시각은 넣고 until 과 같은 시각은 뺀다(사건 · 판정 · 조치 · 감사 · 흡수 · 버전 · 실행 · 지표 · 알림)
  - KST 날짜: UTC 14:59:59 는 09-27, 15:00 은 09-28 이다(생성 · 판정). 사건 · 판정이 없는 날도 0 으로 낸다
  - 사건 수는 발생 시각, 판정 대기 · 날짜별 생성은 생성 시각 기준이다(다시 만든 사건). 발생원(R0xx … R3xx · other) · 심각도별
  - 판정 대기 · 판정 소요 백분위(percentile_cont) · 재판정 · 기간 끝 뒤 판정은 대기에 넣지 않음 · 시험 출발지는 빼고 수만 따로
  - 잔량 · 목표 초과는 대시보드(dashboard_metrics)와 같다 · 상위 출발지의 최고 심각도는 순위(high > medium)
  - 규칙: operations.quality 와 같은 행 · 흡수 · 억제 수(시험 출발지 제외) · 기간 중 규칙 버전
  - 차단: 조치 수 · 새 요청(created · rearmed · 만료 뒤 extended)의 요청자 종류 · extended 도 감사 수에 든다 ·
    관문 반영 지연(감사 요청 → 같은 주소의 다음 요청 전 첫 enforced 의 at. 해제 · 만료된 차단도 든다) · 지금 차단 상태.
    이슈 #77: 감사의 points= 를 읽어 관문 반영 지연은 관문 요청만(points= 없는 옛 감사 · '-' 는 두 지점), 새 요청 수는 모든 요청,
    지점 넓힘(console.block.points)은 감사 수에만 든다. 지금 차단 상태는 요청 지점이 모두 확인이어야 적용이다. 관문이 뺐다는 보고
    없이 다시 건 요청(짝 확인의 쪽지가 '· 기존 차단 유지' · '· 연속성 확인 불가', 결정 2 · 3)은 따로 세고 지연(평균 포함)에서 뺀다
  - 대상: 상태판에서 추린 행 · 센서별 실제 이벤트 · 탐지 실행 · 지표 최대와 공백(기간 시작 · 끝 포함) · 상태판이 창 밖 미결을
    읽어도(이슈 #83) 대응 금지 대역 수는 그대로 · 잔량의 판단 유보는 시스템 기록 포함(대시보드 미결은 사람 판정만) ·
    출력 시각보다 5분 넘게 앞선 줄은 수집 판정에서 뺀다(대시보드 카드와 같다)
  - CTI: 자산별 취약점 · 주목 CVE · 기간 KST 날짜 안의 KEV 등재 가운데 우리 자산 · 신선도
  - 운영 기록: 감사 종류별 수만 · 로그인 실패(실제만) · 알림 발송(시험 발송 제외) · 행위자 · detail · 알림 주소가 실리지 않음
  - 표가 없거나 읽기 권한이 없으면(시험 안에서 만든 역할): 구역은 available=false 와 빠진 표,
    곁 표(흡수 · 주목 CVE · 알림 · 지표)는 그 부분만 null
  - 처리기: 실제 트랜잭션(반복 읽기 · 읽기 전용 · statement_timeout)에서 모든 구역이 돈다
"""
import json
import os
import re
import secrets
import unittest
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import operations as ops
import reports as r

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "infra" / "schema.sql"
# 참조되는 표가 먼저 오게 둔다
TABLES = ["events", "rule_versions", "incidents", "actions", "verdicts", "blocklist", "nodes", "detector_runs",
          "node_metrics", "incident_absorbed", "notify_channels", "notify_deliveries", "cti_snapshots", "cti_kev",
          "cti_cve", "cti_osv", "cti_watch", "asset_inventory", "asset_vulnerabilities", "block_exempt", "test_ranges",
          "sensor_heartbeats"]

UTC = timezone.utc
AS_OF = datetime(2026, 9, 28, 3, 0, tzinfo=UTC)
SINCE = AS_OF - timedelta(hours=24)
KST_MIDNIGHT = datetime(2026, 9, 27, 15, 0, tzinfo=UTC)      # 2026-09-28 00:00 KST
# 보고서에 실리면 안 되는 값: 행위자 · 감사 detail 속 주소 · 알림 주소
ACTORS = ("actor-kim-58", "actor-lee-58")
SECRET_ADDR = "198.51.100.201"
BLOCK_ADDRS = ("198.51.100.22", "198.51.100.23", "198.51.100.24", "198.51.100.26", "198.51.100.27", "198.51.100.28")
HOOK_URL = "https://hooks.example.test/secret-url-58"


def schema_sql(schema: str) -> str:
    """schema.sql 의 표 정의와 audit_log 뷰 · is_test_source. is_test_source 는 search_path 를 public 으로 고정하므로
    시험 스키마로 바꾼다(아니면 public.test_ranges 를 읽는다)."""
    text = SCHEMA.read_text()
    parts = []
    for name in TABLES:
        parts.append(re.search(rf"^CREATE TABLE IF NOT EXISTS {name} \(.*?^\);", text, re.S | re.M).group(0))
        parts += re.findall(rf"^ALTER TABLE {name} [^;]*;", text, re.M)
        # 요청 지점(이슈 #77)은 열이 없을 때만 더하는 DO 블록 안에 있다
        parts += [a.strip() for a in re.findall(rf"^\s+ALTER TABLE {name} ADD COLUMN points [^;]*;", text, re.M)]
    parts.append(re.search(r"^CREATE OR REPLACE VIEW audit_log AS.*?;", text, re.S | re.M).group(0))
    function = re.search(r"^CREATE OR REPLACE FUNCTION is_test_source\(ip inet\).*?\$\$;", text, re.S | re.M).group(0)
    assert "SET search_path = public, pg_temp" in function
    parts.append(function.replace("SET search_path = public, pg_temp", f"SET search_path = {schema}, pg_temp"))
    return "\n".join(parts)


def at(seconds=0, base=SINCE):
    return base + timedelta(seconds=seconds)


def pg(value: datetime) -> str:
    """감사 detail 속 시각 글자(트리거의 timestamptz::text, UTC 세션)."""
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S+00")


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class ReportsDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncpg
        self.conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.addAsyncCleanup(self.conn.close)
        self.schema = f"t58r_{secrets.token_hex(4)}"
        await self.conn.execute(f"CREATE SCHEMA {self.schema}; SET search_path TO {self.schema}, pg_temp")
        # 준비가 중간에 실패해도 스키마를 지운다(asyncTearDown 은 준비가 실패하면 돌지 않는다)
        self.addAsyncCleanup(self.conn.execute, f"DROP SCHEMA IF EXISTS {self.schema} CASCADE")
        await self.conn.execute(schema_sql(self.schema))
        await self.conn.execute("INSERT INTO test_ranges (cidr, note) VALUES ('203.0.113.0/24', '시험')")
        self.lines = 0
        await self.fixture()

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    def request(self, role="admin"):
        return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=SimpleNamespace(acquire=self.acquire))),
                               state=SimpleNamespace(user={"u": "tester", "r": role}))

    async def incident(self, key, rule, severity, actor, first, created=None, target=None, version="v3"):
        await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip,
            target, first_ts, last_ts, signal_count, created_at) VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $8, 1, $9)""",
            key, rule, version, f"{rule} 시험 규칙", severity, actor, target, first, created or first)

    async def verdict(self, key, verdict, when, seconds=None):
        await self.conn.execute("""INSERT INTO verdicts (incident_key, verdict, operator, decision_seconds, created_at)
            VALUES ($1, $2, $3, $4, $5)""", key, verdict, ACTORS[0], seconds, when)

    async def event(self, when, eventid, sensor, actor=None, detail=None, provenance="real"):
        self.lines += 1
        await self.conn.execute("""INSERT INTO events (line_hash, ts, eventid, src_ip, username, input, provenance, sensor)
            VALUES ($1, $2, $3, '192.0.2.200', $4, $5, $6, $7)""",
            f"line-{self.lines}", when, eventid, actor, detail, provenance, sensor)

    async def fixture(self):
        # 사건 (키, 규칙, 심각도, 출발지, 발생, 생성, 대상)
        for row in [
                ("edge-since", "R001", "high", "192.0.2.1", at(0), None, None),               # since 와 같은 시각: 넣는다
                ("edge-until", "R001", "critical", "192.0.2.2", AS_OF, None, None),          # until 과 같은 시각: 뺀다
                ("before", "R001", "medium", "192.0.2.3", at(-1), None, None),
                ("kst-27", "R101", "medium", "192.0.2.1", KST_MIDNIGHT - timedelta(seconds=1), None, None),
                ("kst-28", "R201", "high", None, KST_MIDNIGHT, None, "user:someone"),
                ("web2", "R102", "low", "198.51.100.7", at(7 * 3600), None, None),
                ("node", "R301", "low", None, at(-7200, AS_OF), None, "node:web-01"),
                ("lab", "R001", "critical", "203.0.113.5", at(-3 * 3600, AS_OF), None, None),   # 시험 출발지
                # 다시 만든 사건: 발생은 기간 밖, 생성은 기간 안(09-28 05:00 KST)
                ("recreated", "R002", "high", "198.51.100.8", datetime(2026, 9, 20, tzinfo=UTC), at(17 * 3600), None),
                ("sig", "S01", "low", "198.51.100.9", at(3600), None, None)]:
            await self.incident(*row)
        # 판정 (키, 판정, 시각, 판정 소요)
        for row in [
                ("edge-since", "threat", at(600), 30),                                         # 대기 600
                ("before", "non_actionable", at(100), None),                                    # 사건은 기간 밖, 판정은 안
                ("kst-27", "false_positive", KST_MIDNIGHT + timedelta(seconds=1199), 90),       # 대기 1200 · 09-28
                ("kst-27", "threat", at(-3600, AS_OF), 50),                                    # 재판정: 첫 판정이 아니다
                ("kst-28", "undetermined", KST_MIDNIGHT + timedelta(hours=1), None),           # 대기 3600
                ("web2", "benign_positive", at(9 * 3600), 100),                                # 대기 7200
                ("lab", "threat", at(-3 * 3600 + 60, AS_OF), 10),                              # 시험 출발지
                ("edge-until", "threat", AS_OF, 5)]:                                           # until: 뺀다
            await self.verdict(*row)
        await self.conn.execute("""INSERT INTO rule_versions (rule_version, definition, reason, created_at) VALUES
            ('v3', '{"rules": [{"id": "R001"}]}', '기준', '2026-09-01'),
            ('x9', '{"rules": [{"id": "R001"}, {"id": "R002"}]}', '임계치 조정', $1),
            ('x10', '{"rules": []}', '끝 시각', $2)""", at(3600), AS_OF)
        for first, member, kind, via, rule, actor, recorded in [
                ("edge-since", "m1", "absorbed", None, "R001", "192.0.2.50", at(60)),
                ("edge-since", "m2", "suppressed", "m1", "R005", "192.0.2.50", at(120)),
                ("edge-since", "m3", "absorbed", None, "R001", "192.0.2.51", AS_OF),
                ("lab", "m4", "absorbed", None, "R001", "203.0.113.6", at(60)),
                ("before", "m5", "absorbed", None, "R003", "192.0.2.52", at(-1))]:
            await self.conn.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, via_key, rule_id, rule_version,
                actor_ip, first_ts, last_ts, signal_count, recorded_at) VALUES ($1, $2, $3, $4, $5, 'v3', $6, $7, $7, 1, $7)""",
                first, member, kind, via, rule, actor, recorded)

        # 조치 · 차단 감사 · 차단 목록
        for key, action, when in [("edge-since", "block_ip", at(10)), ("edge-since", "unblock_ip", at(20)),
                                  ("kst-27", "block_ip", KST_MIDNIGHT), ("edge-since", "note", at(30)),
                                  ("edge-until", "block_ip", AS_OF), ("before", "block_ip", at(-1))]:
            await self.conn.execute("INSERT INTO actions (incident_key, action, operator, created_at) VALUES ($1, $2, $3, $4)",
                                    key, action, ACTORS[0], when)
        a, b = ACTORS
        # 차단 감사(schema.sql audit_blocklist 꼴). 새 요청 r1 ~ r7 과 집행 확인. 지연은 확인의 at(관문 적용 시각) - 요청 시각
        live, later = pg(AS_OF + timedelta(hours=1)), pg(AS_OF + timedelta(hours=2))
        g22, g23, g24, g26, g27, g28 = BLOCK_ADDRS
        enforcer = "by=db:opsloop_enforcer"
        for when, eventid, detail in [
                (at(10), "console.block.created",
                 f"by={a} ip={SECRET_ADDR} incident=x expires={live} requested_by={a}"),                  # r1 콘솔
                (at(20), "console.block.created",
                 f"by={b} ip={g22} incident=x expires={live} requested_by=triage:{b}"),                    # r2 triage
                (at(30), "console.block.rearmed",
                 f"by={a} ip={g23} incident=x expires={live} released_by={a} requested_by=system:absorbed-follow"),  # r3
                (at(40), "console.block.extended", f"by={a} ip={g24} from={pg(at(-60))} to={live}"),        # r4 만료 뒤 다시 건 차단
                (at(45), "console.block.extended", f"by={a} ip={SECRET_ADDR} from={live} to={later}"),      # 살아 있는 차단 연장
                (at(47), "console.block.extended", f"by={a} ip={g22} from=none to={live}"),                 # 시각이 아닌 from
                (at(50), "console.block.enforced",
                 f"{enforcer} ip={SECRET_ADDR} method=nft at={pg(at(40))} note=관문 반영 · abcd1234 · x"),  # r1 지연 30
                (at(90), "console.block.enforced",
                 f"{enforcer} ip={SECRET_ADDR} method=nft at={pg(at(80))} note=관문 반영 · abcd1234 · y"),  # 연장 뒤 다시 확인
                (at(95), "console.block.enforced", f"{enforcer} ip={g23} method=nft at=- note=-"),        # r3 at 없음: 기록 시각 65
                (at(100), "console.block.enforced", f"{enforcer} ip={g24} method=nft at={pg(at(90))} note=-"),   # r4 지연 50
                (at(150), "console.block.enforced", f"{enforcer} ip={g22} method=nft at={pg(at(140))} note=-"),  # r2 지연 120
                (at(200), "console.block.created", f"by={a} ip={g26} incident=x expires={live} requested_by={a}"),  # r5
                (at(210), "console.block.released", f"by={a} ip={g26} incident=x verdict=threat past_expiry=no"),
                (at(300), "console.block.rearmed",
                 f"by={a} ip={g26} incident=x expires={live} released_by={a} requested_by={a}"),          # r6
                (at(330), "console.block.enforced", f"{enforcer} ip={g26} method=nft at={pg(at(320))} note=-"),  # r6 지연 20
                (at(-1), "console.block.created", f"by={a} ip={g27} incident=x expires={live} requested_by={a}"),  # 기간 앞
                (at(5), "console.block.enforced", f"{enforcer} ip={g27} method=nft at={pg(at(3))} note=-"),
                (at(-30, AS_OF), "console.block.created",
                 f"by={b} ip={g28} incident=x expires={later} requested_by=triage:{b}"),                   # r7
                (AS_OF, "console.block.enforced", f"{enforcer} ip={g28} method=nft at={pg(at(-20, AS_OF))} note=-"),
                (AS_OF, "console.block.expired", f"by={a} ip={SECRET_ADDR}"),
                (at(60), "console.node.token.issued", f"by={a} node=web-09 enrollment=1 addr={SECRET_ADDR}"),
                (at(70), "console.notify.channel.created", f"by={a} channel=1 kind=webhook")]:
            await self.event(when, eventid, "audit", a, detail)
        for when, eventid, provenance in [(at(100), "console.login.failed", "real"), (at(200), "console.login.failed", "real"),
                                          (at(300), "console.login.failed", "simulated"),
                                          (AS_OF, "console.login.failed", "real"),
                                          (at(400), "console.login.success", "real")]:
            await self.event(when, eventid, "console", a, None, provenance)
        for when, sensor, provenance in [(at(10), "cowrie", "real"), (at(-10, AS_OF), "cowrie", "real"),
                                         (at(20), "cowrie", "simulated"), (AS_OF, "cowrie", "real"),
                                         (at(-1), "decoy", "real"), (at(30), "decoy", "real")]:
            await self.event(when, f"{sensor}.test", sensor, None, None, provenance)
        live = AS_OF + timedelta(hours=1)
        for ip, created, expires, released, enforced, note in [
                ("198.51.100.1", at(100), live, None, at(160), "관문 반영 · abcd1234 · x"),      # 집행 확인
                ("198.51.100.2", at(200), live, None, at(320), "관문 불일치 · 거부"),           # 불일치
                ("198.51.100.3", at(300), live, None, None, None),                             # 집행 대기
                ("198.51.100.4", at(400), live, None, at(0), None),                            # 살아 있는 차단을 다시 걸었다
                ("198.51.100.5", at(-3600), None, None, None, None),                           # 만료 없음(집행 제외)
                ("198.51.100.6", AS_OF, live, None, None, None),                               # until 에 만듦
                ("198.51.100.10", at(500), AS_OF, None, at(530), None),                        # 만료(경계)
                ("198.51.100.11", at(600), live, at(-60, AS_OF), None, None)]:                 # 해제
            await self.conn.execute("""INSERT INTO blocklist (actor_ip, reason, created_at, expires_at, released_at, enforced_at,
                enforce_note, requested_by) VALUES ($1, '시험', $2, $3, $4, $5, $6, $7)""",
                ip, created, expires, released, enforced, note, a)
        # 두 지점 행의 적용은 내부 방화벽 확인도 있어야 한다(이슈 #77)
        await self.conn.execute("""UPDATE blocklist SET enforcement = '{"gateway": {"state": "confirmed"},
            "fw": {"state": "confirmed"}}' WHERE actor_ip IN ('198.51.100.1', '198.51.100.4')""")

        # 관제 대상: 노드 · 탐지 실행 · 자원 지표
        await self.conn.execute("""INSERT INTO nodes (node_id, sensor, status, registered_at, last_seen_at, last_loaded_at)
            VALUES ('web-01', 'web-01', 'active', $1, $2, $2)""", at(-86400), at(-120, AS_OF))
        for started in [at(600), at(1200), at(-300, AS_OF), at(-10), AS_OF]:
            await self.conn.execute("""INSERT INTO detector_runs (rule_version, started_at, finished_at)
                VALUES ('v3', $1, $1)""", started)
        for line, node, ts, cpu, mem, disk in [("m1", "web-01", at(60), 10, 40, 70), ("m2", "web-01", at(120), 95.5, 41, 70),
                                               ("m3", "web-01", at(-60, AS_OF), 20, 55.5, 71.5),
                                               ("m4", "web-01", AS_OF, 100, 100, 100), ("m5", "web-01", at(-60), 99, 99, 99),
                                               ("m6", "web-02", at(300), 99, 99, 99)]:
            await self.conn.execute("""INSERT INTO node_metrics (line_hash, node_id, ts, cpu_pct, mem_used_pct, disk_root_pct)
                VALUES ($1, $2, $3, $4, $5, $6)""", line, node, ts, cpu, mem, disk)

        # CTI
        snap = await self.conn.fetchval("""INSERT INTO cti_snapshots (source, s3_key, status)
            VALUES ('kev', 'cti/v1/source=kev/x.json', 'ok') RETURNING id""")
        for cve, added in [("CVE-2026-10001", date(2026, 9, 27)), ("CVE-2026-10002", date(2026, 9, 28)),
                           ("CVE-2026-10003", date(2026, 9, 26)), ("CVE-2024-1086", date(2024, 5, 30))]:
            await self.conn.execute("""INSERT INTO cti_kev (cve_id, vendor_project, product, name, date_added, snapshot_id)
                VALUES ($1, 'Vendor', 'Product', $1 || ' 시험', $2, $3)""", cve, added, snap)
        for asset, role, collected in [("web-01", "target", at(-3600, AS_OF)), ("honeypot-dmz", "sensor", at(-49 * 3600, AS_OF))]:
            await self.conn.execute("""INSERT INTO asset_inventory (asset_id, role, method, collected_at, checked_at)
                VALUES ($1, $2, 'ssh', $3, $3)""", asset, role, collected)
        for package, cve, fix in [("linux", "CVE-2026-10001", "fix_available"), ("openssl", "CVE-2024-1086", "reboot_pending")]:
            await self.conn.execute("INSERT INTO cti_osv (osv_id, cve_id, snapshot_id) VALUES ($1, $2, $3)",
                                    f"UBUNTU-{cve}", cve, snap)
            await self.conn.execute("""INSERT INTO asset_vulnerabilities (asset_id, source_package, version, osv_id, cve_id,
                fix_state, snapshot_id) VALUES ('web-01', $1, '1', $2, $3, $4, $5)""", package, f"UBUNTU-{cve}", cve, fix, snap)
        await self.conn.execute("INSERT INTO cti_watch (cve_id, reason) VALUES ('CVE-2024-6387', 'regreSSHion')")

        # 알림 발송
        channel = await self.conn.fetchval("""INSERT INTO notify_channels (name, kind, url, grade)
            VALUES ('시험', 'webhook', $1, 'immediate') RETURNING id""", HOOK_URL)
        for event, subject, status, created, sent in [
                ("incident.created", "a", "sent", at(100), at(130)),
                ("incident.created", "b", "failed", at(150), None),
                ("pending.overdue", "c", "sent", at(200), at(290)),
                ("test", "test:x", "sent", at(300), at(301)),
                ("daily.summary", "2026-09-28", "queued", AS_OF, None),
                ("node.silent", "n", "sent", at(-10), at(-5))]:
            await self.conn.execute("""INSERT INTO notify_deliveries (channel_id, event, subject_key, payload, status, created_at,
                sent_at) VALUES ($1, $2, $3, '{}', $4, $5, $6)""", channel, event, subject, status, created, sent)

    async def report(self, names=r.SECTIONS):
        return await r.build(self.conn, AS_OF, "24h", list(names), "tester")

    async def test_머리와_모든_구역이_JSON_으로_나간다(self):
        body = await self.report()
        self.assertEqual((body["as_of"], body["since"], body["until"], body["period"], body["tz"], body["generated_by"]),
                         (AS_OF.isoformat(), SINCE.isoformat(), AS_OF.isoformat(), "24h", "Asia/Seoul", "tester"))
        self.assertEqual(list(body["sections"]), list(r.SECTIONS))
        for name, section in body["sections"].items():
            with self.subTest(name=name):
                self.assertTrue(section["available"])
                self.assertIn(section["basis"], ("period", "as_of", "mixed"))
                self.assertTrue(section["notes"])
        json.dumps(body)        # datetime · Decimal 없이 그대로 나간다

    async def test_사건_수는_발생_시각_기준이고_경계는_반열림이다(self):
        o = (await self.report(["overview"]))["sections"]["overview"]
        # edge-since · kst-27 · kst-28 · web2 · node · sig. edge-until · before · recreated(발생 09-20) 는 뺀다
        self.assertEqual(o["incidents"], {
            "total": 6, "by_severity": {"critical": 0, "high": 2, "medium": 1, "low": 3},
            "by_origin": {"R0xx": 1, "R1xx": 2, "R2xx": 1, "R3xx": 1, "other": 1}, "test_source": 1})
        # 기간 안에 기록된 판정(재판정 포함 · 사건이 기간 밖이어도). until 의 판정은 뺀다
        self.assertEqual(o["verdicts"], {
            "total": 6, "by_verdict": {"threat": 2, "non_actionable": 1, "false_positive": 1, "benign_positive": 1,
                                       "undetermined": 1}, "test_source": 1})

    async def test_날짜는_KST_로_묶고_UTC_15시에_바뀐다(self):
        o = (await self.report(["overview"]))["sections"]["overview"]
        # 생성(created_at): 09-27 edge-since · sig · web2 · kst-27(14:59:59 UTC), 09-28 kst-28(15:00 UTC) · recreated · node
        # 판정: 09-27 before · edge-since · web2, 09-28 kst-27 두 번 · kst-28
        self.assertEqual(o["daily"], [{"date": "2026-09-27", "created": 4, "judged": 3},
                                      {"date": "2026-09-28", "created": 3, "judged": 3}])
        # 30일이면 판정 · 사건이 없는 날도 0 으로 낸다(31개 날짜: 08-29 12:00 KST ~ 09-28 12:00 KST)
        month = await r.build(self.conn, AS_OF, "30d", ["overview"], "tester")
        days = month["sections"]["overview"]["daily"]
        self.assertEqual((len(days), days[0], days[-1]["date"]), (31, {"date": "2026-08-29", "created": 0, "judged": 0},
                                                                   "2026-09-28"))

    async def test_판정_대기와_판정_소요_백분위(self):
        o = (await self.report(["overview"]))["sections"]["overview"]
        # 기간 안에 만든 실제 사건 7건(recreated 포함) 중 판정된 4건의 대기 [600, 1200, 3600, 7200]. 재판정 · until 의 판정은 뺀다
        self.assertEqual(o["wait"], {"incidents": 7, "judged": 4, "p50_seconds": 2400.0, "p90_seconds": 6120.0})
        # 판정 소요 [30, 50, 90, 100](재판정 포함, 시험 출발지 · until 제외)
        self.assertEqual(o["decision"], {"n": 4, "p50_seconds": 70.0, "p90_seconds": 97.0})

    async def test_기간_끝_뒤의_판정은_대기에_넣지_않는다(self):
        await self.verdict("node", "threat", AS_OF + timedelta(minutes=1), 20)
        o = (await self.report(["overview"]))["sections"]["overview"]
        self.assertEqual((o["wait"]["judged"], o["decision"]["n"]), (4, 4))

    async def test_잔량_목표_초과는_대시보드와_같고_상위_출발지는_순위로(self):
        from dashboard import dashboard_metrics
        o = (await self.report(["overview"]))["sections"]["overview"]
        pending = (await dashboard_metrics(self.conn, AS_OF))["pending"]
        # 판정 없음: node · recreated · sig. recreated(high · 8일) 초과, sig(low · 23시간) 주의
        self.assertEqual(o["backlog"], {"unjudged": 3, "undetermined": 1, "overdue": 1, "warning": 1,
                                        "oldest_seconds": float(8 * 86400 + 3 * 3600)})
        self.assertEqual((o["backlog"]["unjudged"], o["backlog"]["overdue"]), (pending["total"], pending["overdue"]))
        # 192.0.2.1 은 high · medium 이다. 글자 max 면 medium 이 된다. 시험 출발지 · 출발지 없는 사건은 뺀다
        self.assertEqual(o["top_sources"], {"total": 3, "items": [
            {"ip": "192.0.2.1", "incidents": 2, "severity": "high",
             "last_ts": (KST_MIDNIGHT - timedelta(seconds=1)).isoformat()},
            {"ip": "198.51.100.7", "incidents": 1, "severity": "low", "last_ts": at(7 * 3600).isoformat()},
            {"ip": "198.51.100.9", "incidents": 1, "severity": "low", "last_ts": at(3600).isoformat()}]})

    async def test_규칙_구역은_규칙_화면과_같은_행이다(self):
        rules = (await self.report(["rules"]))["sections"]["rules"]
        expected = (await ops.quality(self.request(), True, SINCE, AS_OF))["rows"]
        self.assertEqual(rules["rows"], [{k: float(v) if isinstance(v, Decimal) else v for k, v in dict(row).items()}
                                         for row in expected])
        by_rule = {(x["rule_id"], x["rule_version"]): x for x in rules["rows"]}
        self.assertEqual((by_rule[("R001", "v3")]["incidents"], by_rule[("R001", "v3")]["threats"]), (1, 1))   # lab 제외
        self.assertEqual(by_rule[("R101", "v3")]["false_positives"], 0)                                         # 최신은 threat
        # 흡수 · 억제: since 는 넣고 until · 시험 출발지 · 기간 앞은 뺀다
        self.assertEqual(rules["absorbed"], {"absorbed": 1, "suppressed": 1, "rules": [
            {"rule_id": "R001", "rule_version": "v3", "absorbed": 1, "suppressed": 0},
            {"rule_id": "R005", "rule_version": "v3", "absorbed": 0, "suppressed": 1}]})
        self.assertEqual(rules["versions"], [{"rule_version": "x9", "reason": "임계치 조정",
                                              "created_at": at(3600).isoformat(), "rules": ["R001", "R002"]}])
        # 규칙 버전 정의는 고칠 수 없으니 모양이 틀린 정의(규칙이 배열이 아님 · 객체가 아닌 항목 · id 없는 항목)로 조회가 멈추지 않는다
        await self.conn.execute("""INSERT INTO rule_versions (rule_version, definition, created_at) VALUES
            ('odd1', '{"rules": [{"id": "R009"}, "junk", 3, {"name": "id 없음"}]}', $1), ('odd2', '{"rules": "none"}', $2)""",
            at(7200), at(7300))
        versions = (await self.report(["rules"]))["sections"]["rules"]["versions"]
        self.assertEqual([(v["rule_version"], v["reason"], v["rules"]) for v in versions],
                         [("x9", "임계치 조정", ["R001", "R002"]), ("odd1", None, ["R009"]), ("odd2", None, [])])

    async def test_차단_구역(self):
        blocks = (await self.report(["blocks"]))["sections"]["blocks"]
        self.assertEqual(blocks["actions"], {"block_ip": 2, "unblock_ip": 1})
        # 콘솔 r1 · r5 · r6, triage r2 · r7, system r3, 미기록 r4(만료 뒤 다시 건 차단은 요청자가 남지 않는다)
        self.assertEqual(blocks["requests"], {"total": 7, "console": 3, "triage": 2, "system": 1, "unknown": 1})
        # 만료 뒤 다시 건 차단 · 살아 있는 차단 연장(extended)도 센다. until 의 expired · enforced 와 since 앞의 created 는 뺀다
        self.assertEqual({x["eventid"]: x["count"] for x in blocks["audit"]}, {
            "console.block.created": 4, "console.block.rearmed": 2, "console.block.extended": 3,
            "console.block.shortened": 0, "console.block.points": 0, "console.block.released": 1,
            "console.block.expired": 0, "console.block.enforced": 7, "console.block.unenforced": 0})
        self.assertEqual([x["eventid"] for x in blocks["audit"]], list(r.BLOCK_EVENTS))
        # 새 요청 r1 ~ r7(기간 앞 · 살아 있는 차단 연장 · from 이 시각이 아닌 extended 제외).
        #   지연 r1 30 · r2 120 · r3 65(at 없음) · r4 50 · r6 20 (평균 57).
        #   r5 는 다음 요청(r6) 전에 확인이 없고, r7 의 확인은 until 이라 뺀다. 차단 목록 행(집행 기록이 비워진 것)과 무관하다
        self.assertEqual(blocks["enforcement"], {"created": 7, "enforced": 5, "maintained": 0, "uncertain": 0,
                                                 "mean_seconds": 57.0, "p50_seconds": 50.0, "max_seconds": 120.0})
        # 지금: 만료 경계(expires_at = as_of) · 해제는 살아 있지 않다
        self.assertEqual(blocks["states"], {"total": 6, "enforced": 2, "pending": 2, "excluded": 1, "mismatch": 1,
                                            "failed": 0})

    async def test_차단_구역_관문_반영_지연은_관문_요청만(self):
        # 이슈 #77. 감사 detail 의 points= 로 요청 지점을 읽는다. 내부 방화벽만 요청한 r8 은 새 요청 수에는 들고 관문 반영 지연에서는
        #   빠진다(뒤에 관문을 더해 관문 확인이 와도 짝짓지 않는다). points= 없는 옛 감사(r1 ~ r7) · '-'(열이 없던 DB, r10)는 두 지점이다
        a = ACTORS[0]
        live, enforcer = pg(AS_OF + timedelta(hours=1)), "by=db:opsloop_enforcer"
        fw_only, both, dash, failed = "198.51.100.30", "198.51.100.31", "198.51.100.32", "198.51.100.33"
        for when, eventid, detail in [
                (at(250), "console.block.created",
                 f"by={a} ip={fw_only} incident=x expires={live} points=fw requested_by={a}"),                # r8
                (at(252), "console.block.points", f"by={a} ip={fw_only} from=fw to=gateway,fw"),
                (at(256), "console.block.enforced", f"{enforcer} ip={fw_only} method=nft at={pg(at(254))} note=-"),
                (at(260), "console.block.created",
                 f"by={a} ip={both} incident=x expires={live} points=gateway,fw requested_by={a}"),          # r9 지연 5
                (at(270), "console.block.enforced", f"{enforcer} ip={both} method=nft at={pg(at(265))} note=-"),
                (at(280), "console.block.rearmed",
                 f"by={a} ip={dash} incident=x expires={live} points=- released_by={a} requested_by={a}")]:  # r10
            await self.event(when, eventid, "audit", a, detail)
        # 내부 방화벽만 요청한 행: 내부 방화벽 확인이면 적용(관문 열이 비어도), 내부 방화벽 실패면 실패
        for ip, fw in ((fw_only, "confirmed"), (failed, "failed")):
            await self.conn.execute("""INSERT INTO blocklist (actor_ip, reason, expires_at, requested_by, points, enforcement)
                VALUES ($1, '시험', $2, $3, '{fw}', $4::jsonb)""", ip, AS_OF + timedelta(hours=1), a,
                json.dumps({"fw": {"state": fw}}))
        blocks = (await self.report(["blocks"]))["sections"]["blocks"]
        self.assertEqual(blocks["requests"], {"total": 10, "console": 6, "triage": 2, "system": 1, "unknown": 1})
        # 지연 r1 30 · r2 120 · r3 65 · r4 50 · r6 20 · r9 5, 요청은 r8 을 뺀 9
        self.assertEqual(blocks["enforcement"], {"created": 9, "enforced": 6, "maintained": 0, "uncertain": 0,
                                                 "mean_seconds": 48.3, "p50_seconds": 40.0, "max_seconds": 120.0})
        audit = {x["eventid"]: x["count"] for x in blocks["audit"]}
        self.assertEqual((audit["console.block.created"], audit["console.block.rearmed"], audit["console.block.points"],
                          audit["console.block.enforced"]), (6, 3, 1, 9))
        self.assertIn("관문 반영 지연(관문 요청만)", " ".join(blocks["notes"]))
        self.assertIn("살아 있는 차단에 관문을 더한 것(차단 지점 넓힘)은 넣지 않는다", " ".join(blocks["notes"]))
        self.assertEqual(blocks["states"], {"total": 8, "enforced": 3, "pending": 2, "excluded": 1, "mismatch": 1,
                                            "failed": 1})

    async def test_차단_구역_기존_차단_유지와_연속성_확인_불가는_따로_세고_지연에서_뺀다(self):
        # 결정 2 · 3. 해제 · 만료 행을 관문을 포함해 다시 걸면 요청 시각에 관문 세 열을 비우지 않는다. 관문이 뺐다는 오류 없는 보고 없이
        #   다시 건 요청은 집행기가 새 보고로 확인하며 쪽지 끝에 관문 보고가 이어졌으면 '· 기존 차단 유지', 보고 누락 · 덮임 · 오류 ·
        #   다시 걸기 전 만료면 '· 연속성 확인 불가' 를 붙인다(unenforced 없음) → 새 반영이 아니라 따로 세고 지연에서 뺀다. 관문이 뺀 뒤
        #   다시 건 요청(unenforced 뒤 새 확인)은 지연에 든다. 살아 있는 차단 연장의 유지 확인은 새 요청이 아니다
        a = ACTORS[0]
        live, enforcer = pg(AS_OF + timedelta(hours=1)), "by=db:opsloop_enforcer"
        kept, removed, expired, extended = "198.51.100.40", "198.51.100.41", "198.51.100.42", "198.51.100.43"
        unsure, unsure_expired = "198.51.100.44", "198.51.100.45"

        def applied(ip, n, suffix=""):
            return (at(n + 5), "console.block.enforced",
                    f"{enforcer} ip={ip} method=nft at={pg(at(n))} note=관문 반영 · abcd1234 · {pg(at(n))}{suffix}")

        def created(ip, n):
            return (at(n), "console.block.created", f"by={a} ip={ip} incident=x expires={live} points=gateway,fw requested_by={a}")
        for when, eventid, detail in [
                created(kept, 700), applied(kept, 705),                                                     # r11 지연 5
                (at(720), "console.block.released", f"by={a} ip={kept} incident=x verdict=threat past_expiry=no"),
                (at(730), "console.block.rearmed",
                 f"by={a} ip={kept} incident=x expires={live} points=gateway,fw released_by={a} requested_by={a}"),  # r12
                applied(kept, 785, " · 기존 차단 유지"),                                                        # r12 유지
                created(removed, 800), applied(removed, 805),                                               # r13 지연 5
                (at(820), "console.block.released", f"by={a} ip={removed} incident=x verdict=threat past_expiry=no"),
                (at(830), "console.block.unenforced", f"{enforcer} ip={removed} method=nft was={pg(at(805))} why=released"),
                (at(840), "console.block.rearmed",
                 f"by={a} ip={removed} incident=x expires={live} points=gateway,fw released_by={a} requested_by={a}"),  # r14
                applied(removed, 895),                                                                      # r14 지연 55
                created(expired, 1000), applied(expired, 1005),                                             # r15 지연 5
                (at(1100), "console.block.extended",
                 f"by={a} ip={expired} from={pg(at(1050))} to={live} points=gateway,fw"),                   # r16 만료 뒤 다시 건 차단
                applied(expired, 1150, " · 기존 차단 유지"),                                                    # r16 유지
                created(extended, 1200), applied(extended, 1205),                                           # r17 지연 5
                (at(1300), "console.block.extended", f"by={a} ip={extended} from={live} to={live} points=gateway,fw"),
                applied(extended, 1350, " · 기존 차단 유지"),                                                    # 연장: 새 요청 아님
                created(unsure, 1400), applied(unsure, 1405),                                               # r18 지연 5
                (at(1420), "console.block.released", f"by={a} ip={unsure} incident=x verdict=threat past_expiry=no"),
                (at(1430), "console.block.rearmed",
                 f"by={a} ip={unsure} incident=x expires={live} points=gateway,fw released_by={a} requested_by={a}"),  # r19
                applied(unsure, 1700, " · 연속성 확인 불가"),                                                  # r19 보고 누락 · 덮임 · 오류
                created(unsure_expired, 1800), applied(unsure_expired, 1805),                               # r20 지연 5
                (at(1900), "console.block.extended",
                 f"by={a} ip={unsure_expired} from={pg(at(1850))} to={live} points=gateway,fw"),           # r21 만료 뒤 다시 건 차단
                applied(unsure_expired, 1960, " · 연속성 확인 불가")]:                                         # r21 다시 걸기 전 만료
            await self.event(when, eventid, "audit", a, detail)
        blocks = (await self.report(["blocks"]))["sections"]["blocks"]
        # 지연: r1 30 · r2 120 · r3 65 · r4 50 · r6 20 · r11 5 · r13 5 · r14 55 · r15 5 · r17 5 · r18 5 · r20 5
        #   (평균 370/12, 중앙값 (5 + 20)/2). 유지 r12 · r16 과 확인 불가 r19 · r21 은 뺀다
        self.assertEqual(blocks["enforcement"], {"created": 18, "enforced": 12, "maintained": 2, "uncertain": 2,
                                                 "mean_seconds": 30.8, "p50_seconds": 12.5, "max_seconds": 120.0})
        notes = " ".join(blocks["notes"])
        self.assertIn("관문 보고가 오류 없이 이어졌으면 '기존 차단 유지'", notes)
        self.assertIn("'연속성 확인 불가' 로 따로 세고 둘 다 지연(확인 수 · 평균 · 중앙값 · 최대)에서 뺀다", notes)

    async def test_대상_구역(self):
        section = (await self.report(["targets"]))["sections"]["targets"]
        self.assertEqual([x["id"] for x in section["targets"]], ["aws-sensor", "web-01", "console", "data-node"])
        web = next(x for x in section["targets"] if x["id"] == "web-01")
        self.assertEqual(web["collection"]["state"], "quiet")          # 노드 수신 2분 전 · web-01 로그 없음
        self.assertEqual(set(web["response"]), {"point_label", "applied", "failed", "unverified", "unrequested", "removing",
                                                "exempt", "stalled"})
        self.assertEqual(set(web), {"id", "label", "collection", "response"})
        # 실제 이벤트만 · until 과 같은 시각 제외 · 감사 · 로그인 기록도 센서로 센다
        self.assertEqual(section["sensors"], [{"sensor": "audit", "events": 19}, {"sensor": "console", "events": 3},
                                              {"sensor": "cowrie", "events": 2}, {"sensor": "decoy", "events": 1}])
        # 실행 [since+600, since+1200, until-300]. 공백: 600 · 600 · 84900 · 300
        self.assertEqual(section["detector"], {"runs": 3, "max_gap_seconds": 84900.0})
        # web-01 만, 기간 안만. 공백: 60 · 60 · 86220 · 60
        self.assertEqual(section["web"], {"samples": 3, "cpu_pct": 95.5, "mem_used_pct": 55.5, "disk_root_pct": 71.5,
                                          "max_gap_seconds": 86220.0})

    async def test_창_밖_미결은_대상_구역의_대응_금지_대역_수를_바꾸지_않는다(self):
        # 상태판(targets_view)은 창(24시간) 밖 미결 사건도 읽어 미결 수에 세지만(이슈 #83) 카드 rows 에는 넣지 않는다.
        #   금지 대역(10.0.0.0/8) 출발지라 rows 에 들면 web-01 대응 exempt 가 1 늘어난다
        before = (await self.report(["targets"]))["sections"]["targets"]["targets"]
        await self.incident("u-old", "R301", "critical", "10.9.9.9", at(-3 * 86400, AS_OF), target="node:web-01")
        await self.verdict("u-old", "undetermined", at(-2 * 86400, AS_OF))
        self.assertEqual((await self.report(["targets"]))["sections"]["targets"]["targets"], before)
        web = next(x for x in (await r.targets.targets_view(self.conn, AS_OF))["targets"] if x["id"] == "web-01")
        self.assertEqual((web["security"]["undetermined"], web["response"]["exempt"]), (1, 0))
        # 잔량의 판단 유보는 시스템 전환 기록을 포함한 수 그대로이고, 대시보드 미결은 사람 판정만 센다(kst-28 · u-old)
        await self.conn.execute("""INSERT INTO verdicts (incident_key, verdict, operator, created_at)
            VALUES ('recreated', 'undetermined', 'system:v3-cutover', $1)""", at(-3600, AS_OF))
        backlog = (await self.report(["overview"]))["sections"]["overview"]["backlog"]
        self.assertEqual((backlog["undetermined"], (await r.dashboard_metrics(self.conn, AS_OF))["pending"]["undetermined"]),
                         (3, 2))

    async def test_대상_구역의_수집_판정은_출력_시각보다_5분_넘게_앞선_줄을_뺀다(self):
        # 보고서 대상 구역은 상태판(targets_view)을 그대로 쓴다. 앞선 시각 줄 상한(출력 시각 + 5분)도 대시보드 카드와 같다
        def web(section):
            return next(x for x in section["targets"] if x["id"] == "web-01")["collection"]
        await self.event(AS_OF + timedelta(minutes=10), "nginx.request", "web-01")
        section = (await self.report(["targets"]))["sections"]["targets"]
        card = next(x for x in (await r.targets.targets_view(self.conn, AS_OF))["targets"] if x["id"] == "web-01")
        self.assertEqual((web(section)["state"], web(section)["reason"]), ("quiet", "노드 수신 2분 전 · 최근 1시간 요청 없음"))
        self.assertEqual((web(section)["state"], web(section)["reason"]), (card["collection"]["state"], card["collection"]["reason"]))
        # 상한 안(+4분)의 줄은 최근 로그로 센다
        await self.event(AS_OF + timedelta(minutes=4), "nginx.request", "web-01")
        section = (await self.report(["targets"]))["sections"]["targets"]
        self.assertEqual((web(section)["state"], web(section)["reason"]), ("ok", "노드 수신 2분 전 · 최근 1시간 로그 있음"))

    async def test_실행이_없으면_공백은_기간_전체다(self):
        await self.conn.execute("DELETE FROM detector_runs")
        section = (await self.report(["targets"]))["sections"]["targets"]
        self.assertEqual(section["detector"], {"runs": 0, "max_gap_seconds": 86400.0})

    async def test_CTI_구역(self):
        section = (await self.report(["cti"]))["sections"]["cti"]
        self.assertEqual([(a["asset_id"], a["vuln_total"], a["vuln_kev"], a["vuln_fix_available"], a["vuln_reboot_pending"],
                           a["stale"]) for a in section["assets"]],
                         [("web-01", 2, 2, 1, 1, False), ("honeypot-dmz", 0, 0, 0, 0, True)])
        self.assertEqual(section["watch"], {"total": 1, "affected": 0, "unknown": 1, "not_affected": 0, "affected_cves": []})
        # 기간의 KST 날짜(09-27 · 09-28) 안 등재 2건, 그중 우리 자산에 걸린 것 1건
        self.assertEqual(section["kev_added"], {"total": 2, "ours": [
            {"cve_id": "CVE-2026-10001", "name": "CVE-2026-10001 시험", "date_added": "2026-09-27", "assets": ["web-01"]}]})
        self.assertEqual(set(section["freshness"]), {"kev", "epss", "osv", "nvd", "assets"})

    async def test_운영_기록은_수만_싣는다(self):
        body = await self.report(["blocks", "ops"])
        section = body["sections"]["ops"]
        self.assertEqual(section["audit"], [
            {"eventid": "console.block.created", "count": 4}, {"eventid": "console.block.enforced", "count": 7},
            {"eventid": "console.block.extended", "count": 3}, {"eventid": "console.block.rearmed", "count": 2},
            {"eventid": "console.block.released", "count": 1},
            {"eventid": "console.node.token.issued", "count": 1}, {"eventid": "console.notify.channel.created", "count": 1}])
        self.assertEqual(section["login_failed"], 2)
        # 시험 발송 · until · 기간 앞은 뺀다. 지연 [30, 90]
        self.assertEqual(section["notify"], {"total": 3, "failed": 1, "p50_seconds": 60.0, "rows": [
            {"event": "incident.created", "status": "failed", "count": 1},
            {"event": "incident.created", "status": "sent", "count": 1},
            {"event": "pending.overdue", "status": "sent", "count": 1}]})
        text = json.dumps(body, ensure_ascii=False)
        for secret in (*ACTORS, SECRET_ADDR, *BLOCK_ADDRS, HOOK_URL, "hooks.example.test", "by=", "triage:", "requested_by"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, text)

    async def test_표가_없으면_구역은_빠지고_곁_표는_그_부분만_null(self):
        await self.conn.execute("""DROP VIEW audit_log;
            DROP TABLE incident_absorbed, notify_deliveries, cti_watch, node_metrics""")
        sections = (await self.report())["sections"]
        for name in ("blocks", "ops"):
            with self.subTest(name=name):
                self.assertEqual(sections[name], {"available": False, "reason": "표가 없거나 읽기 권한이 없음: audit_log"})
        self.assertIsNone(sections["rules"]["absorbed"])
        self.assertIsNone(sections["cti"]["watch"])
        self.assertIsNone(sections["targets"]["web"])
        # 빠진 부분은 null 로만 알린다. 화면 · 인쇄물이 null 을 보고 빠졌다는 문장을 한 번 찍으므로 notes 에 되풀이하지 않고,
        #   내지 않은 값의 기준(web-01 자원)도 싣지 않는다
        for name in ("rules", "targets", "cti"):
            with self.subTest(name=name):
                self.assertEqual([n for n in sections[name]["notes"] if "읽을 수 없" in n or "web-01 자원" in n], [])
        self.assertTrue(sections["overview"]["available"])
        await self.conn.execute("DROP TABLE asset_vulnerabilities")
        self.assertEqual((await self.report(["cti"]))["sections"]["cti"],
                         {"available": False, "reason": "표가 없거나 읽기 권한이 없음: asset_vulnerabilities"})

    async def test_읽기_권한이_없는_표도_표가_없는_것과_같다(self):
        # 역할 블록만 다시 적용해 뒤쪽 블록의 권한이 빠진 콘솔 역할을 흉내 낸다. 역할은 이 시험 안에서 만들고 지운다
        role = f"t58r_{secrets.token_hex(4)}"
        await self.conn.execute(f"""CREATE ROLE {role} NOLOGIN; GRANT USAGE ON SCHEMA {self.schema} TO {role};
            GRANT SELECT ON ALL TABLES IN SCHEMA {self.schema} TO {role};
            REVOKE SELECT ON audit_log, incident_absorbed FROM {role}""")
        try:
            await self.conn.execute(f"SET ROLE {role}")
            sections = (await self.report(["rules", "blocks"]))["sections"]
        finally:
            await self.conn.execute(f"RESET ROLE; DROP OWNED BY {role}; DROP ROLE {role}")
        self.assertEqual(sections["blocks"], {"available": False, "reason": "표가 없거나 읽기 권한이 없음: audit_log"})
        self.assertTrue(sections["rules"]["available"])
        self.assertIsNone(sections["rules"]["absorbed"])

    async def test_처리기는_실제_트랜잭션에서_모든_구역을_낸다(self):
        body = await r.period_report(self.request("admin"), "30d", None)
        self.assertEqual(body["generated_by"], "tester")
        self.assertEqual([name for name, s in body["sections"].items() if s["available"]], list(r.SECTIONS))
        # 트랜잭션이 끝나면 시간 제한(SET LOCAL)도 풀린다
        self.assertNotEqual(await self.conn.fetchval("SHOW statement_timeout"), r.STATEMENT_TIMEOUT)
        viewer = await r.period_report(self.request("viewer"), "7d", None)
        self.assertNotIn("ops", viewer["sections"])


if __name__ == "__main__":
    unittest.main()
