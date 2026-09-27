#!/usr/bin/env python3
"""정상 트래픽 정의 · 생성기 시험 (WBS 3.7 · 이슈 #49).  python3 detector/test_normal_traffic.py

DB 없이 도는 것: 정의 파일(normal_traffic.json)의 모양, 정의에 적은 '세는 수 · 기대 반응'이 규칙 파일(rules_w1.json)로 계산한
값과 같은지, 시나리오가 10분 창 하나에 들고 시나리오 사이가 통합 창보다 긴지, 행 만들기(열 · 표식 · 해시 · 출발지), 실험 DB
주소가 아니면 거부(종료 2 — localhost · 운영 주소 · 다른 포트 · 질의 문자열 ?hostaddr= · 호스트 둘 이상), --table 출력이
정의서(docs/2026-09-28-정상-트래픽-정의.md)의 표와 글자 그대로 같은지.

도커가 있으면(postgres:16-alpine 이미지가 로컬에 있을 때만 · 이미지를 받지 않는다): 임시 컨테이너를 127.0.0.1 의 빈 포트에
띄워 schema.sql · 마이그레이션을 넣고 씨앗 몇 행(디코이 404 · message 가 NULL 인 콘솔 행 · 표식을 흉내 낸 남의 행)을 둔 뒤
dry-run(무쓰기) → 실데이터 구간 거부(NULL message 포함) → 주소를 돌리는 PG* 환경변수 무시 → 지금도 이벤트가 들어오는 DB 거부(종료 5)
→ apply(행 수 · 표식 · 사건 키 집계 불변 · 재적용 멱등) → detect.py actor_rate 와 같은 신호 문장으로 임계치 5 · 3 · 8 의 기대 반응
→ (psycopg2 가 있으면) detect.py 실제 실행 → rollback 이 우리 행만 지우고 남의 행은 남기는지. 컨테이너는 끝에 지운다. 생성기는 호스트에 psycopg2 나 asyncpg 가 있으면 호스트에서, 없으면 로컬
opsloop-api 이미지(asyncpg) 안에서 컨테이너 네트워크를 공유해 돈다. OPSLOOP_NORMAL49_SKIP_DOCKER=1 이면 도커 시험을 건너뛴다.
"""
import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import normal_traffic as nt  # noqa: E402

TOOL = os.path.join(HERE, "normal_traffic.py")
DETECT = os.path.join(HERE, "detect.py")
DOC = os.path.join(ROOT, "docs", "2026-09-28-정상-트래픽-정의.md")
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
MIGRATIONS = os.path.join(ROOT, "infra", "migrations")
TABLE_START, TABLE_END = "<!-- normal49-table:start -->", "<!-- normal49-table:end -->"
PG_IMAGE, API_IMAGE = "postgres:16-alpine", "opsloop-api:latest"
CANDIDATES = {"w2": 5, "w2-c3": 3, "w2-c8": 8}


def clean_env():
    env = dict(os.environ)
    env.pop("DATABASE_URL", None)
    return env


def host_driver():
    for name in ("psycopg2", "asyncpg"):
        try:
            if hasattr(__import__(name), "connect"):
                return name
        except ImportError:
            pass
    return None


def image_present(name):
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


# ======================================================================
#  DB 없이
# ======================================================================

class 정의파일(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = nt.load_scenarios()
        cls.rules = nt.load_rules()

    def test_모양과_id(self):
        ids = [s["id"] for s in self.doc["scenarios"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids))
        self.assertGreaterEqual(len(ids), 16)
        names = " ".join(s["name"] for s in self.doc["scenarios"])
        # 계약이 정한 최소 시나리오
        for word in ("로그인 성공", "오타 2회", "오타 4회", "오타 5회", "로그아웃", "SSH 성공", "SSH 오타 2회", "SSH 오타 5회",
                     "200", "404 2회", "404 4회", "404 5회", "메타데이터", "헬스체크", "자산 수집"):
            self.assertIn(word, names)
        self.assertEqual({k: v for k, v in self.doc["candidates"].items() if k != "comment"}, CANDIDATES)

    def test_세는_수와_기대_반응이_규칙_파일과_같다(self):
        self.assertEqual(nt.check_consistency(self.doc, self.rules), [])
        # 후보별 오탐(정상 시나리오가 걸림) 건수는 정의가 정하는 설계값이다. 결과표의 분자가 이것과 달라지면 규칙 · 창 문제다
        fired = {c: sorted((s["id"], r) for s in self.doc["scenarios"] for r in s["fires"][c]) for c in CANDIDATES}
        self.assertEqual(fired["w2"], [("C04", "R101"), ("S03", "R101"), ("W04", "R102")])
        self.assertEqual(fired["w2-c3"], [("C03", "R101"), ("C04", "R101"), ("S03", "R101"),
                                          ("W03", "R102"), ("W04", "R102"), ("W07", "R102")])
        self.assertEqual(fired["w2-c8"], [])
        for s in self.doc["scenarios"]:
            self.assertEqual(s["verdict_if_fired"], "false_positive")

    def test_후보_w2_는_현행_규칙_파일과_같다(self):
        """정의의 candidates.w2 는 rules_w1.json 의 R101 · R102 임계치다. 규칙 파일이 바뀌면 정의도 바꿔야 한다."""
        self.assertEqual(self.rules["rule_version"], "w2")
        for rid in ("R101", "R102"):
            self.assertEqual(nt._rule(self.rules, rid)["params"]["threshold"], self.doc["candidates"]["w2"], rid)

    def test_시나리오는_한_창_안이고_사이는_통합_창보다_길다(self):
        slot = self.doc["timing"]["slot_seconds"]
        spacing = self.doc["timing"]["scenario_spacing_seconds"]
        gaps = [r["aggregation_gap_seconds"] for r in self.rules["rules"] if r["id"] in ("R101", "R102")]
        self.assertEqual(slot, 600)
        for r in self.rules["rules"]:
            if r["id"] in ("R101", "R102"):
                self.assertEqual(r["params"]["window_seconds"], slot)
        self.assertGreater(spacing, max(gaps))           # 같은 출발지 · 같은 규칙이 따로 뜬다
        offsets = [s["offset_seconds"] for s in self.doc["scenarios"]]
        for a, b in zip(offsets, offsets[1:]):
            self.assertGreaterEqual(b - a, spacing)
        for s in self.doc["scenarios"]:
            self.assertLess(nt.scenario_span(s), slot, s["id"])
            self.assertEqual(s["offset_seconds"] % slot, 0, s["id"])

    def test_메타데이터_404_는_w2_제외_패턴에_전부_맞는다(self):
        pats = nt._rule(self.rules, "R102")["params"]["exclude_url_patterns"]
        w05 = next(s for s in self.doc["scenarios"] if s["id"] == "W05")
        for g in w05["events"]:
            self.assertTrue(nt.excluded_url(g["url"], pats), g["url"])
        self.assertFalse(nt.excluded_url("/docs/old-link", pats))
        self.assertFalse(nt.excluded_url("/robots.txt?x=1", pats))

    def test_검사가_깨진_정의를_거른다(self):
        def broken(mutate):
            d = copy.deepcopy(self.doc)
            mutate(d)
            with self.assertRaises(ValueError):
                nt.validate(d)
        broken(lambda d: d["scenarios"].__setitem__(1, dict(d["scenarios"][1], id="C01")))            # id 중복
        broken(lambda d: d["scenarios"][1].__setitem__("offset_seconds", 1801))                        # 창 경계 아님
        broken(lambda d: d["scenarios"][1].__setitem__("offset_seconds", 600))                         # 간격 부족
        broken(lambda d: d["scenarios"][3]["events"][0].__setitem__("interval_seconds", 200))          # 5회 × 200초 > 600 한 창 초과
        broken(lambda d: d["scenarios"][4]["events"][1].__setitem__("gap_before_seconds", 600))       # 묶음 사이 간격으로 창을 넘김
        broken(lambda d: d["scenarios"][0]["events"][0].__setitem__("eventid", "sshd.login.success"))  # 발생원에 없는 eventid
        broken(lambda d: d["scenarios"][0]["events"][0].__setitem__("username", "operator"))           # 표식 없는 계정
        broken(lambda d: d["scenarios"][0].__setitem__("verdict_if_fired", "threat"))
        broken(lambda d: d["scenarios"][0]["fires"].__setitem__("w9", []))
        d = copy.deepcopy(self.doc)
        d["scenarios"][3]["fires"]["w2"] = []                                                           # 계산과 다른 기대 반응
        self.assertEqual([b[0] for b in nt.check_consistency(d, self.rules)], ["C04"])


class 행만들기(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = nt.load_scenarios()
        cls.start = datetime(2026, 9, 27, 9, 0, tzinfo=timezone.utc)
        cls.rows, cls.summary = nt.build_rows(cls.doc, cls.start)

    def test_행_수_열_표식(self):
        self.assertEqual(len(self.rows), 66)
        slot = self.doc["timing"]["slot_seconds"]
        end = nt.window_end(self.doc, self.start)
        self.assertEqual(end, self.start + timedelta(seconds=27000 + 1800))
        seen_slots = {}
        prev = None
        for r in self.rows:
            self.assertEqual(tuple(r), nt.COLUMNS)
            m = nt.MARKER_RE.match(r["message"])
            self.assertIsNotNone(m, r["message"])
            sid = r["message"][len("[정상 시나리오 "):len("[정상 시나리오 ") + 3]
            self.assertEqual(r["provenance"], "real")
            self.assertIn(r["sensor"], nt.TARGETS)
            self.assertTrue(self.start <= r["ts"] < end)
            if prev is not None:
                self.assertGreater(r["ts"], prev)
            prev = r["ts"]
            if r["eventid"] in nt.HTTP_EVENTIDS:
                self.assertTrue(r["user_agent"].startswith(f"OpsLoop-Normal49/{sid} "), r["user_agent"])
                self.assertIsNotNone(r["http_status"])
                self.assertIsNotNone(r["url"])
            if r["eventid"] in nt.AUTH_EVENTIDS:
                self.assertTrue(r["username"].startswith("normal49."), r["username"])
            if r["eventid"].startswith("sshd."):
                self.assertRegex(r["session"], r"^web-01/sshd/[0-9]+$")
                self.assertEqual((r["sensor"], r["src_ip"], r["dst_port"], r["protocol"]), ("web-01", "192.168.50.1", 22, "ssh"))
            elif r["eventid"] == "nginx.request":
                self.assertIsNone(r["session"])
                self.assertEqual((r["sensor"], r["src_ip"], r["dst_port"], r["protocol"]), ("web-01", "192.168.70.1", 80, "http"))
            else:
                self.assertEqual((r["sensor"], r["src_ip"], r["dst_port"], r["protocol"]), ("console", "192.168.70.1", 8000, "http"))
                if r["eventid"] == "console.login.success":
                    self.assertLessEqual(len(r["session"]), 17)
                else:
                    self.assertIsNone(r["session"])
            seen_slots.setdefault(sid, set()).add(int(r["ts"].timestamp()) // slot)
        # 시나리오 하나 = 창 하나, 시나리오마다 다른 창
        self.assertTrue(all(len(v) == 1 for v in seen_slots.values()), seen_slots)
        self.assertEqual(len({next(iter(v)) for v in seen_slots.values()}), len(seen_slots))
        self.assertEqual([s["rows"] for s in self.summary], [1, 3, 5, 6, 2, 1, 3, 6, 1, 3, 2, 4, 5, 6, 12, 6])

    def test_해시는_정의된_식이고_구간이_바뀌면_바뀐다(self):
        import hashlib
        seq = 0
        for s in self.doc["scenarios"]:
            for _ in nt.scenario_times(s):
                seq += 1
                r = self.rows[seq - 1]
                self.assertEqual(r["line_hash"], hashlib.sha256(f"normal49|{s['id']}|{seq}|{r['ts'].isoformat()}".encode()).hexdigest())
                self.assertEqual(r["src_port"], 40000 + seq)
        other, _ = nt.build_rows(self.doc, self.start + timedelta(seconds=600))
        self.assertTrue(set(r["line_hash"] for r in other).isdisjoint(r["line_hash"] for r in self.rows))

    def test_창_경계_정렬(self):
        self.assertEqual(nt.align_slot(datetime(2026, 9, 27, 7, 31, 5, tzinfo=timezone.utc), 600),
                         datetime(2026, 9, 27, 7, 40, tzinfo=timezone.utc))
        self.assertEqual(nt.align_slot(self.start, 600), self.start)
        with self.assertRaises(ValueError):
            nt.build_rows(self.doc, self.start + timedelta(seconds=1))
        self.assertEqual(nt.parse_ts("2026-09-27T09:00:00Z"), self.start)
        self.assertEqual(nt.parse_ts("2026-09-27T09:00:00"), self.start)
        self.assertEqual(nt.parse_ts("2026-09-27T18:00:00+09:00"), self.start)


class 주소검사(unittest.TestCase):
    def refused(self, url, **kw):
        with redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as cm:
            nt.check_db_url(url, **kw)
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("거부", err.getvalue())

    def test_실험_DB_만_받는다(self):
        self.assertEqual(nt.check_db_url("postgresql://opsloop:x@127.0.0.1:55449/opsloop"), ("127.0.0.1", 55449))
        self.assertEqual(nt.check_db_url("postgres://opsloop:x@127.0.0.1:55001/opsloop", allow_ports=[55001]), ("127.0.0.1", 55001))
        self.refused("postgresql://opsloop:x@localhost:55449/opsloop")            # 이름은 어디로든 풀릴 수 있다
        self.refused("postgresql://opsloop:x@192.168.50.1:5432/opsloop")          # 운영 쪽 주소
        self.refused("postgresql://opsloop:x@data01/opsloop")
        self.refused("postgresql://opsloop:x@127.0.0.1:5432/opsloop")             # 포트 다름
        self.refused("postgresql://opsloop:x@127.0.0.1/opsloop")                  # 기본 포트 5432
        self.refused("postgresql://opsloop:x@127.0.0.1:55001/opsloop", allow_ports=[55002])
        self.refused("mysql://opsloop:x@127.0.0.1:55449/opsloop")
        self.refused("")
        self.refused(None)
        # libpq 는 질의 문자열 · 환경변수로 netloc 과 다른 주소에 붙는다(재현: ?port=1 → 127.0.0.1:1, ?hostaddr=127.0.0.2 → 127.0.0.2)
        self.refused("postgresql://opsloop:x@127.0.0.1:55449/opsloop?hostaddr=192.168.60.11")
        self.refused("postgresql://opsloop:x@127.0.0.1:55449/opsloop?host=localhost")
        self.refused("postgresql://opsloop:x@127.0.0.1:55449/opsloop?port=5432")
        self.refused("postgresql://opsloop:x@127.0.0.1:55449/opsloop?service=prod")
        self.refused("postgresql://opsloop:x@127.0.0.1:55449/opsloop?sslmode=disable")     # 질의 문자열은 통째로
        self.refused("postgresql://opsloop:x@127.0.0.1:55449/opsloop#x")
        # 호스트 둘 이상: libpq · asyncpg 모두 첫 호스트가 죽으면 둘째로 붙는다
        self.refused("postgresql://opsloop:x@127.0.0.1:55449,192.168.60.11:5432/opsloop")
        self.refused("postgresql://opsloop:x@127.0.0.1,192.168.60.11:55449/opsloop")
        self.refused("postgresql://opsloop:x@[::1]:55449/opsloop")
        self.refused("postgresql://opsloop:x@127%2E0%2E0%2E1:55449/opsloop")
        self.refused("postgresql://opsloop:x@127.0.0.1.:55449/opsloop")


class 정의서와표(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = nt.load_scenarios()
        cls.rules = nt.load_rules()
        cls.table = nt.render_table(cls.doc, cls.rules)

    def test_표_열과_행(self):
        lines = self.table.splitlines()
        self.assertEqual(lines[0], "| " + " | ".join(nt.TABLE_HEADER) + " |")
        self.assertEqual(len(lines), 2 + len(self.doc["scenarios"]))
        self.assertIn("| C04 | 콘솔 | 콘솔 오타 5회 뒤 성공 (10분 창) | 192.168.70.1 | 로그인 실패 5 · 로그인 성공 1 | 160초 (10분 창 1개) | "
                      "R101: w2 뜸 · c3 뜸 · c8 안 뜸 | false_positive (오탐) |", lines)
        self.assertIn("| W05 | web-01 nginx | web-01 메타데이터 404 (robots · favicon · security.txt 등) | 192.168.70.1 | 404 메타데이터 6 | "
                      "5초 (10분 창 1개) | 안 뜸 (R101 0 · R102 0) | false_positive (오탐) |", lines)

    def test_정의서의_표는_JSON_에서_뽑은_것과_글자_그대로_같다(self):
        with open(DOC, encoding="utf-8") as f:
            text = f.read()
        self.assertIn(TABLE_START, text)
        self.assertIn(TABLE_END, text)
        block = text.split(TABLE_START, 1)[1].split(TABLE_END, 1)[0].strip()
        self.assertEqual(block, self.table)
        # 정의서가 후보 임계치 · 표식 · 판정값 규칙을 적는다
        for word in ("false_positive", "benign_positive", "OpsLoop-Normal49/", "normal49.", "[정상 시나리오 ", "127.0.0.1:55449",
                     "--apply", "--rollback", "--dry-run", "sha256", "1800", "600"):
            self.assertIn(word, text)

    def test_CLI(self):
        env = clean_env()
        p = subprocess.run([sys.executable, TOOL, "--table"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertEqual(p.stdout.decode("utf-8").strip(), self.table)
        for url in ("postgresql://opsloop:x@192.168.50.1:5432/opsloop", "postgresql://opsloop:x@127.0.0.1:5432/opsloop",
                    "postgresql://opsloop:x@localhost:55449/opsloop",
                    "postgresql://opsloop:x@127.0.0.1:55449/opsloop?hostaddr=192.168.60.11",
                    "postgresql://opsloop:x@127.0.0.1:55449,192.168.60.11:5432/opsloop"):
            for mode in ("--dry-run", "--apply", "--rollback"):
                p = subprocess.run([sys.executable, TOOL, "--db-url", url, mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                self.assertEqual(p.returncode, 2, (url, mode, p.stderr.decode()))
                self.assertIn("거부", p.stderr.decode("utf-8"))
                self.assertNotIn("Traceback", p.stderr.decode("utf-8"))
                self.assertEqual(p.stdout, b"")
        p = subprocess.run([sys.executable, TOOL, "--apply"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.assertEqual(p.returncode, 2)                                          # --db-url 없음. 환경변수는 읽지 않는다
        env2 = dict(env, DATABASE_URL="postgresql://opsloop:x@127.0.0.1:55449/opsloop")
        p = subprocess.run([sys.executable, TOOL, "--apply"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env2)
        self.assertEqual(p.returncode, 2)


# ======================================================================
#  임시 postgres 컨테이너
# ======================================================================

SKIP_DOCKER = os.environ.get("OPSLOOP_NORMAL49_SKIP_DOCKER") == "1"
HOST_DRIVER = host_driver()
CAN_RUN_TOOL = HOST_DRIVER is not None or image_present(API_IMAGE)


@unittest.skipIf(SKIP_DOCKER, "OPSLOOP_NORMAL49_SKIP_DOCKER=1")
@unittest.skipUnless(image_present(PG_IMAGE), f"도커 또는 로컬 이미지 {PG_IMAGE} 없음 (받지 않는다)")
@unittest.skipUnless(CAN_RUN_TOOL, f"호스트에 psycopg2 · asyncpg 가 없고 {API_IMAGE} 이미지도 없다")
class 임시실험DB(unittest.TestCase):
    """컨테이너 하나를 클래스 전체가 쓴다. 메서드는 이름 순(1 → 9)으로 상태를 이어 간다."""

    PASSWORD = "lab49test"

    @classmethod
    def setUpClass(cls):
        cls.doc = nt.load_scenarios()
        cls.rules = nt.load_rules()
        cls.name = f"opsloop-normal49-test-{os.getpid()}"
        subprocess.run(["docker", "rm", "-f", cls.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r = subprocess.run(["docker", "run", "-d", "--rm", "--name", cls.name, "-e", "POSTGRES_USER=opsloop",
                            "-e", f"POSTGRES_PASSWORD={cls.PASSWORD}", "-e", "POSTGRES_DB=opsloop",
                            "-p", "127.0.0.1:0:5432", PG_IMAGE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode:
            raise unittest.SkipTest(f"컨테이너를 띄우지 못했다: {r.stderr.decode()[:200]}")
        try:
            for _ in range(60):
                if subprocess.run(["docker", "exec", cls.name, "pg_isready", "-U", "opsloop", "-d", "opsloop", "-q"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("postgres 가 준비되지 않았다")
            time.sleep(1)
            port = subprocess.run(["docker", "port", cls.name, "5432"], stdout=subprocess.PIPE, check=True).stdout.decode()
            cls.port = int(port.strip().splitlines()[0].rsplit(":", 1)[1])
            cls.url_host = f"postgresql://opsloop:{cls.PASSWORD}@127.0.0.1:{cls.port}/opsloop"
            cls.psql_file(SCHEMA)
            for m in sorted(os.listdir(MIGRATIONS)):
                if m.endswith(".sql"):
                    cls.psql_file(os.path.join(MIGRATIONS, m))
            # 씨앗: 디코이 출발지 하나의 404 6건(9/20)과 그것으로 뜬 w2 사건 하나(사건 키 집계가 비어 있지 않게), message 가 NULL 인
            # 실제 콘솔 로그인 행(9/20 · 실데이터 구간 검사가 NULL 도 세는지), 표식 message 를 흉내 냈지만 우리 행이 아닌 것 둘(9/19 ·
            # sensor 가 decoy 인 것과 UA · username 머리가 없는 것 — rollback 이 남겨야 한다)
            cls.psql("""
INSERT INTO events (line_hash, ts, eventid, src_ip, src_port, dst_port, protocol, url, http_method, http_status, provenance, sensor, message)
SELECT md5('seed' || g), timestamptz '2026-09-20 10:00:00+00' + (g * interval '10 seconds'), 'decoy.request', '203.0.113.9',
       50000 + g, 8080, 'http', '/x' || g, 'GET', 404, 'real', 'decoy', 'seed' FROM generate_series(1, 6) g;
INSERT INTO events (line_hash, ts, eventid, src_ip, src_port, dst_port, protocol, username, provenance, http_method, http_status, user_agent, sensor, url, message)
VALUES (md5('seed-console-null'), '2026-09-20 10:00:30+00', 'console.login.success', '192.168.70.1', 50100, 8000, 'http', 'han', 'real',
        'POST', 302, 'Mozilla/5.0', 'console', '/login', NULL);
INSERT INTO events (line_hash, ts, eventid, src_ip, provenance, sensor, username, user_agent, message) VALUES
  (md5('seed-fake-decoy'), '2026-09-19 10:00:00+00', 'decoy.request', '203.0.113.10', 'real', 'decoy', NULL, 'curl/8', '[정상 시나리오 Z99] 남의 행'),
  (md5('seed-fake-console'), '2026-09-19 10:01:00+00', 'console.login.failed', '192.168.70.1', 'real', 'console', 'han', 'Mozilla/5.0', '[정상 시나리오 Z98] 남의 행');
INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip, first_ts, last_ts, signal_count, evidence, status)
VALUES ('R102|w2|203.0.113.9|2026-09-20T10:00:10+00:00', 'R102', 'w2', '경로 탐색', 'medium', '203.0.113.9',
        '2026-09-20 10:00:10+00', '2026-09-20 10:01:00+00', 1, '{}', 'open');""")
            cls.seed_events = 9                       # 디코이 6 + 콘솔 NULL 1 + 흉내 2
            cls.seed_in_0920_window = 7               # 9/20 10:00 부터의 구간에 든 표식 아닌 행(디코이 6 + 콘솔 NULL 1)
            cls.seed_fp = cls.fingerprint()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["docker", "rm", "-f", cls.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # ── 도우미 ──

    @classmethod
    def psql(cls, sql):
        p = subprocess.run(["docker", "exec", "-i", cls.name, "psql", "-U", "opsloop", "-d", "opsloop", "-v", "ON_ERROR_STOP=1", "-At"],
                           input=sql.encode("utf-8"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode:
            raise RuntimeError(p.stderr.decode("utf-8"))
        return [line for line in p.stdout.decode("utf-8").splitlines() if line]

    @classmethod
    def psql_file(cls, path):
        with open(path, encoding="utf-8") as f:
            cls.psql(f.read())

    @classmethod
    def fingerprint(cls):
        return cls.psql(nt.FINGERPRINT_SQL)[0]

    def count(self, sql="SELECT count(*) FROM events"):
        return int(self.psql(sql)[0])

    def tool(self, *args, expect=0, extra_env=None):
        """생성기를 돌린다. 호스트 드라이버가 있으면 호스트에서, 없으면 opsloop-api 이미지 안에서(컨테이너 네트워크 공유).
        extra_env 는 생성기 프로세스에 주는 환경변수(이미지 안에서는 -e 로). stderr 는 self.last_stderr 에 남긴다."""
        env = clean_env()
        env.update(extra_env or {})
        if HOST_DRIVER:
            cmd = [sys.executable, TOOL, "--db-url", self.url_host, "--allow-port", str(self.port), *args]
        else:
            cmd = ["docker", "run", "--rm", "--network", f"container:{self.name}"]
            for k, v in (extra_env or {}).items():
                cmd += ["-e", f"{k}={v}"]
            cmd += ["-v", f"{ROOT}:/repo:ro", "--entrypoint", "python", API_IMAGE, "/repo/detector/normal_traffic.py",
                    "--db-url", f"postgresql://opsloop:{self.PASSWORD}@127.0.0.1:5432/opsloop", "--allow-port", "5432", *args]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.last_stderr = p.stderr.decode("utf-8")
        self.assertEqual(p.returncode, expect, self.last_stderr[-800:])
        return json.loads(p.stdout.decode("utf-8")) if p.stdout.strip() else None

    def slot_to_id(self, ts_text, window_start):
        ws = nt.parse_ts(window_start)
        ts = nt.parse_ts(ts_text.replace(" ", "T"))
        off = int((ts - ws).total_seconds()) // 600 * 600
        for s in self.doc["scenarios"]:
            if s["offset_seconds"] == off:
                return s["id"]
        return f"?{off}"

    def signal_windows(self, threshold, ws, we):
        """detect.py signals_actor_rate 가 만드는 문장과 같은 뜻의 SQL. (규칙, 시나리오 id) 집합을 돌려준다."""
        r101, r102 = nt._rule(self.rules, "R101")["params"], nt._rule(self.rules, "R102")["params"]
        pats = ", ".join(f"$q${'^(?:' + p + ')$'}$q$" for p in r102["exclude_url_patterns"])
        ids = lambda xs: ", ".join(f"'{x}'" for x in xs)
        sql = f"""
SELECT 'R101', min(ts), src_ip, count(*) FROM events
WHERE provenance = 'real' AND ts >= '{ws}' AND ts < '{we}' AND eventid = ANY(ARRAY[{ids(r101['eventids'])}]) AND src_ip IS NOT NULL
GROUP BY src_ip, floor(extract(epoch FROM ts) / {r101['window_seconds']}) HAVING count(*) >= {threshold}
UNION ALL
SELECT 'R102', min(ts), src_ip, count(*) FROM events
WHERE provenance = 'real' AND ts >= '{ws}' AND ts < '{we}' AND eventid = ANY(ARRAY[{ids(r102['eventids'])}]) AND src_ip IS NOT NULL
  AND http_status = ANY(ARRAY[{", ".join(str(c) for c in r102['http_status'])}])
  AND (url IS NULL OR NOT (url ~ ANY(ARRAY[{pats}])))
GROUP BY src_ip, floor(extract(epoch FROM ts) / {r102['window_seconds']}) HAVING count(*) >= {threshold}
ORDER BY 1, 2"""
        out = set()
        for line in self.psql(sql):
            rule, ts, ip, n = line.split("|")
            out.add((rule, self.slot_to_id(ts, ws), ip, int(n)))
        return out

    def expected(self, cand):
        out = set()
        for s in self.doc["scenarios"]:
            for r in s["fires"][cand]:
                out.add((r, s["id"], self.doc["sources"][s["source"]]["src_ip"], s["countable"][r]))
        return out

    # ── 순서대로 ──

    def test_1_dry_run_은_쓰지_않는다(self):
        out = self.tool()
        self.assertEqual(out["mode"], "dry-run")
        self.assertEqual((out["rows_planned"], out["rows_inserted"], out["foreign_rows_in_window"]), (66, 0, 0))
        self.assertEqual(out["window_seconds"], 28800)
        self.assertEqual(nt.parse_ts(out["window_start"]),
                         nt.align_slot(datetime(2026, 9, 20, 10, 1, 0, tzinfo=timezone.utc) + timedelta(hours=1), 600))
        self.assertEqual(self.count(), self.seed_events)
        self.assertEqual(self.fingerprint(), self.seed_fp)
        self.assertEqual(out["incident_keys_before"]["count"], 1)
        self.assertEqual(out["driver"], HOST_DRIVER or "asyncpg")

    def test_2_구간에_실데이터가_있으면_거부한다(self):
        """디코이 6건과 message 가 NULL 인 콘솔 행 1건이 함께 세어져야 한다(NULL ~ x 는 NULL 이라 NOT 으로는 빠졌다)."""
        out = self.tool("--apply", "--window-start", "2026-09-20T10:00:00+00:00", expect=3)
        self.assertEqual(out["foreign_rows_in_window"], self.seed_in_0920_window)
        self.assertIn("refused", out)
        self.assertEqual(self.count(), self.seed_events)

    def test_2b_주소를_돌리는_환경변수를_무시한다(self):
        """PGHOSTADDR · PGHOST · PGPORT · PGSERVICE 가 있어도 --db-url 의 127.0.0.1:<포트> 에 붙는다.
        libpq 는 PGHOSTADDR 로 URL 과 다른 주소에, PGSERVICE 로 service 파일의 주소에 붙는다(재현: 127.0.0.2 로 가서 시간 초과)."""
        out = self.tool(extra_env={"PGHOSTADDR": "127.0.0.2", "PGHOST": "localhost", "PGPORT": "1", "PGSERVICE": "evil",
                                   "PGCONNECT_TIMEOUT": "5"})
        self.assertEqual((out["mode"], out["rows_inserted"]), ("dry-run", 0))
        self.assertEqual(out["db"], f"127.0.0.1:{self.port}" if HOST_DRIVER else "127.0.0.1:5432")
        self.assertEqual(self.count(), self.seed_events)

    def test_2c_지금도_이벤트가_들어오는_DB_는_손대지_않는다(self):
        """표식 아닌 이벤트의 max(ts) 가 now() 근처면 운영 DB 로 본다(종료 5). --allow-port 와 컨테이너 네트워크 공유로
        주소 검사를 지나도 여기서 막힌다. dry-run · apply · rollback 모두."""
        self.psql("INSERT INTO events (line_hash, ts, eventid, src_ip, provenance, sensor, message) "
                  "VALUES (md5('seed-live'), now() - interval '2 minutes', 'collector.heartbeat', '192.168.50.1', 'real', 'collector', NULL)")
        try:
            for mode in ((), ("--apply",), ("--rollback",)):
                with self.subTest(mode=mode):
                    self.assertIsNone(self.tool(*mode, expect=5))
                    self.assertIn("들어오는 DB", self.last_stderr)
            self.assertEqual(self.count(), self.seed_events + 1)
            self.assertEqual(self.fingerprint(), self.seed_fp)
        finally:
            self.psql("DELETE FROM events WHERE line_hash = md5('seed-live')")
        self.assertEqual(self.count(), self.seed_events)

    def test_3_apply_는_66행을_넣고_사건_키_집계를_바꾸지_않는다(self):
        out = self.tool("--apply")
        type(self).window = (out["window_start"], out["window_end"])
        self.assertEqual((out["rows_inserted"], out["rows_marked_in_window"], out["incident_keys_unchanged"]), (66, 66, True))
        self.assertEqual(out["events_after"], self.seed_events + 66)
        self.assertEqual(self.count(), self.seed_events + 66)
        self.assertEqual(self.fingerprint(), self.seed_fp)
        marked = "message ~ '^\\[정상 시나리오 [A-Z][0-9]{2}\\] '"
        self.assertEqual(self.count(f"SELECT count(*) FROM events WHERE {marked} AND ts >= '{self.window[0]}'"), 66)
        self.assertEqual(self.count(f"SELECT count(*) FROM events WHERE {marked} AND ts >= '{self.window[0]}' AND provenance = 'real'"), 66)
        self.assertEqual(self.psql(f"SELECT sensor, count(*) FROM events WHERE {marked} AND ts >= '{self.window[0]}' GROUP BY 1 ORDER BY 1"),
                         ["console|17", "web-01|49"])
        self.assertEqual(self.count("SELECT count(*) FROM events WHERE sensor = 'console'"), 17 + 2)     # 씨앗 콘솔 2행은 그대로
        ours = f"{marked} AND ts >= '{self.window[0]}'"
        self.assertEqual(self.count(f"SELECT count(*) FROM events WHERE {ours} AND eventid IN ('console.login.success','console.login.failed',"
                                    f"'console.logout','nginx.request') AND user_agent NOT LIKE 'OpsLoop-Normal49/%'"), 0)
        self.assertEqual(self.count(f"SELECT count(*) FROM events WHERE {ours} AND eventid LIKE '%login%' AND username NOT LIKE 'normal49.%'"), 0)
        # 우리 행은 모두 2차 표식(UA 머리 또는 username 머리)도 갖는다 — rollback 이 이것으로 남의 행과 가른다
        self.assertEqual(self.count(f"SELECT count(*) FROM events WHERE {ours} AND NOT (user_agent LIKE 'OpsLoop-Normal49/%' OR username LIKE 'normal49.%')"), 0)
        self.assertEqual(self.psql(f"SELECT DISTINCT host(src_ip) FROM events WHERE {ours} ORDER BY 1"), ["192.168.50.1", "192.168.70.1"])
        # 해시는 정의된 식이라 파이썬이 만든 것과 DB 의 것이 같다
        rows, _ = nt.build_rows(self.doc, nt.parse_ts(out["window_start"]))
        self.assertEqual(self.count(f"SELECT count(*) FROM events WHERE line_hash = ANY(ARRAY[{', '.join(repr(r['line_hash']) for r in rows)}])"), 66)

    def test_4_같은_구간_재적용은_멱등이다(self):
        out = self.tool("--apply", "--window-start", self.window[0])
        self.assertEqual((out["rows_inserted"], out["events_after"]), (0, self.seed_events + 66))
        self.assertEqual(self.fingerprint(), self.seed_fp)

    def test_5_신호_문장으로_본_임계치별_기대_반응(self):
        ws, we = self.window
        for cand, th in CANDIDATES.items():
            with self.subTest(cand=cand):
                self.assertEqual(self.signal_windows(th, ws, we), self.expected(cand))
        self.assertEqual(len(self.expected("w2")), 3)
        self.assertEqual(len(self.expected("w2-c3")), 6)
        self.assertEqual(len(self.expected("w2-c8")), 0)

    def test_6_detect_py_실행(self):
        """psycopg2 가 호스트에 있을 때만. w2 · w2-c3 · w2-c8 를 구간에 돌리면 사건이 기대 반응과 같다."""
        if HOST_DRIVER != "psycopg2":
            self.skipTest("호스트에 psycopg2 없음 — detect.py 는 psycopg2 만 쓴다")
        ws, we = self.window
        with tempfile.TemporaryDirectory() as tmp:
            files = {"w2": os.path.join(HERE, "rules_w1.json")}
            for cand, th in CANDIDATES.items():
                if cand == "w2":
                    continue
                d = copy.deepcopy(self.rules)
                d["rule_version"] = cand
                for r in d["rules"]:
                    if r["id"] in ("R101", "R102"):
                        r["params"]["threshold"] = th
                files[cand] = os.path.join(tmp, f"rules_{cand}.json")
                with open(files[cand], "w", encoding="utf-8") as f:
                    json.dump(d, f, ensure_ascii=False)
            for cand, path in files.items():
                p = subprocess.run([sys.executable, DETECT, "--db-url", self.url_host, "--rules", path, "--run", "--quiet",
                                    "--since", ws, "--until", we], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env())
                self.assertEqual(p.returncode, 0, p.stderr.decode())
                got = set()
                for line in self.psql(f"SELECT rule_id, first_ts, host(actor_ip), signal_count FROM incidents "
                                      f"WHERE rule_version = '{cand}' AND first_ts >= '{ws}' AND first_ts < '{we}'"):
                    rid, ts, ip, n = line.split("|")
                    got.add((rid, self.slot_to_id(ts, ws), ip))
                self.assertEqual(got, {(r, sid, ip) for r, sid, ip, _ in self.expected(cand)}, cand)
        type(self).incidents_in_window = 3 + 6

    def test_7_rollback_은_우리_행만_지운다(self):
        """66행만 지운다. message 가 NULL 인 콘솔 행, 표식 message 를 흉내 냈지만 sensor 가 decoy 인 행, UA · username 머리가 없는 콘솔 행은 남는다."""
        fp_before = self.fingerprint()                       # detect.py 가 만든 사건이 있어도 rollback 은 incidents 를 건드리지 않는다
        out = self.tool("--rollback")
        self.assertEqual(out["rows_deleted"], 66)
        self.assertEqual(out["events_after"], self.seed_events)
        self.assertEqual(self.count(), self.seed_events)
        self.assertEqual(out["incidents_in_window"], getattr(self, "incidents_in_window", 0))
        self.assertEqual(self.count("SELECT count(*) FROM incidents WHERE rule_version = 'w2' AND actor_ip = '203.0.113.9'"), 1)
        self.assertEqual(self.count("SELECT count(*) FROM events WHERE line_hash IN (md5('seed-console-null'), md5('seed-fake-decoy'), md5('seed-fake-console'))"), 3)
        self.assertEqual(self.count("SELECT count(*) FROM events WHERE message ~ '^\\[정상 시나리오'"), 2)     # 흉내 2행만 남는다
        self.assertEqual(self.fingerprint(), fp_before)
        self.assertEqual(out["incident_keys_after"], out["incident_keys_before"])
        out = self.tool("--rollback")
        self.assertEqual(out["rows_deleted"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
