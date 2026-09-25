#!/usr/bin/env python3
"""CVE · KEV 연계(이슈 #39) 스키마 시험.  python3 cti/test_cti_schema.py

DB 없이 도는 글자 시험: infra/schema.sql 의 'CVE · KEV 연계' 절이 infra/migrations/20260925_cti.sql 에 글자 그대로
들어 있는지, 역할 블록 뒤에 있는지, 권한 줄이 기대와 정확히 같은지, verify-db-roles.sh 에 CTI 줄이 있고 수집기의
쓰기 권한(표 · 권한마다 허용 또는 거부)을 빠짐없이 보는지 본다.

OPSLOOP_TEST_DATABASE_URL 이 있으면 이름이 무작위인 스키마에 마이그레이션 파일을 그대로 적용해 CHECK · 참조 키 ·
기본값이 기대대로 막고 채우는지 본다. 권한은 이름이 무작위인 역할로 바꾼 권한 블록을 적용해, verify-db-roles.sh 의
CTI 줄이 운영에서 낼 답과 같은 답을 내는지와 수집기 역할로 적재 문장이 실제로 되는지 본다.
스키마와 역할은 끝나면 지운다. 운영 표 · 운영 역할은 건드리지 않는다.
"""
import contextlib
import os
import re
import secrets
import unittest

try:
    import psycopg2
    import psycopg2.errors
except ImportError:
    psycopg2 = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "infra/schema.sql")
MIGRATION = os.path.join(ROOT, "infra/migrations/20260925_cti.sql")
VERIFY = os.path.join(ROOT, "infra/vmware/scripts/verify-db-roles.sh")
HEADER = "-- CVE · KEV 연계 (이슈 #39)"
TABLES = ["cti_snapshots", "cti_kev", "cti_cve", "cti_osv", "cti_watch", "asset_inventory", "asset_vulnerabilities"]
WRITES = ("INSERT", "UPDATE", "DELETE")
CTI_TABLE = re.compile(r"\b(cti_[a-z_]+|asset_inventory|asset_vulnerabilities)\b")

# 권한 블록의 문장 전부(줄 끝 주석을 뗀 것). 수집기는 원본 기록을 추가만 하고, CTI 표 밖은 규칙 정의 읽기뿐이다
GRANTS = [
    "EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_cti', current_database());",
    "GRANT USAGE ON SCHEMA public TO opsloop_cti;",
    "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_cti;",
    "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_cti;",
    "GRANT SELECT, INSERT ON cti_snapshots TO opsloop_cti;",
    "GRANT USAGE ON SEQUENCE cti_snapshots_id_seq TO opsloop_cti;",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON cti_kev TO opsloop_cti;",
    "GRANT SELECT, INSERT, UPDATE ON cti_cve, cti_osv TO opsloop_cti;",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON cti_watch TO opsloop_cti;",
    "GRANT SELECT, INSERT, UPDATE ON asset_inventory TO opsloop_cti;",
    "GRANT SELECT, INSERT, DELETE ON asset_vulnerabilities TO opsloop_cti;",
    "GRANT SELECT ON rule_versions TO opsloop_cti;",
    "GRANT SELECT ON cti_snapshots, cti_kev, cti_cve, cti_osv, cti_watch, asset_inventory, asset_vulnerabilities"
    " TO opsloop_console;",
]

# 권한 블록이 가리키는 CTI 밖 표와, 수집기가 보지 못해야 하는 표를 흉내 낸다 (verify-db-roles.sh 의 문장이 쓰는 열만)
STUBS = """
    CREATE TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL, reason text,
        created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE nodes (node_id text PRIMARY KEY, hostname text, token_hash text);
    CREATE TABLE events (line_hash text PRIMARY KEY, ts timestamptz, url text);
    CREATE TABLE incidents (incident_key text PRIMARY KEY, rule_id text);
"""
S3_KEY = "cti/v1/source=kev/date=2026-09-25/0123456789abcdef.json"
SHA = "0123456789abcdef" * 4


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def cti_block(text):
    """'CVE · KEV 연계' 절(머리 주석 · 표 · 색인 · 권한)을 파일에서 그대로 떼어 낸다."""
    start = text.index(HEADER + "\n")
    end = text.index("END\n$$;", text.index("CREATE TABLE IF NOT EXISTS cti_snapshots", start)) + len("END\n$$;")
    return text[start:end]


def grant_lines(block):
    """권한 문장만. 줄 끝 주석을 떼고 공백을 하나로 줄인다. 여러 줄에 걸친 문장은 ; 까지 한 줄로 잇는다."""
    stmts, cur = [], None
    for ln in block.splitlines():
        ln = " ".join(ln.split(" --")[0].split())
        if not ln or ln.startswith("--"):
            continue
        if cur is None and not ln.startswith(("GRANT", "REVOKE", "EXECUTE")):
            continue
        cur = ln if cur is None else f"{cur} {ln}"
        if cur.endswith(";"):
            stmts.append(cur)
            cur = None
    return stmts


def granted_writes(block, role="opsloop_cti"):
    """권한 블록이 역할에 준 표 쓰기 권한 (표, 권한) 집합."""
    out = set()
    for stmt in grant_lines(block):
        m = re.fullmatch(r"GRANT ([A-Z, ]+) ON ([a-z_, ]+) TO (\w+);", stmt)
        if m and m.group(3) == role:
            privs = {p.strip() for p in m.group(1).split(",")} & set(WRITES)
            out |= {(t.strip(), p) for t in m.group(2).split(",") for p in privs}
    return out


def exercised(stmt):
    """검증 문장이 실제로 쓰는 (표, 권한). ON CONFLICT … DO UPDATE 는 행이 없어도 INSERT 와 UPDATE 를 함께 본다."""
    m = re.match(r"(INSERT INTO|UPDATE|DELETE FROM) (\w+)", stmt)
    if not m:
        return set()
    verb = m.group(1).split()[0]
    privs = {verb, "UPDATE"} if verb == "INSERT" and "DO UPDATE" in stmt else {verb}
    return {(m.group(2), p) for p in privs}


def verify_lines():
    """verify-db-roles.sh 의 q · p 줄을 (종류, 역할, 문장, 기대) 로."""
    pat = re.compile(r'^([qp]) (opsloop_[a-z]+) +"(.+)" (허용|거부|t|f)$')
    return [m.groups() for m in map(pat.match, read(VERIFY).splitlines()) if m]


def cti_verify_lines():
    """CTI 표를 건드리는 줄과 수집기 역할의 줄 전부."""
    return [ln for ln in verify_lines() if ln[1] == "opsloop_cti" or CTI_TABLE.search(ln[2])]


class CtiSchemaTextTest(unittest.TestCase):
    """스키마 절 · 마이그레이션 · 역할 검증 스크립트의 글자 시험. DB 없이 돈다."""

    def test_마이그레이션은_스키마_절과_글자가_같다(self):
        block, mig = cti_block(read(SCHEMA)), read(MIGRATION)
        head, body = mig.split("\nBEGIN;\n", 1)
        self.assertTrue(all(ln.startswith("--") for ln in head.splitlines()))     # 머리는 주석뿐이다
        self.assertEqual(body.rstrip("\n"), block + "\nCOMMIT;")                  # 본문은 절 그대로 + COMMIT;

    def test_절은_역할_블록_뒤에_있다(self):
        # 역할 블록이 모든 표의 권한을 먼저 거두므로, 뒤에 있어야 스키마를 다시 적용해도 권한이 남는다
        schema = read(SCHEMA)
        at = schema.index(cti_block(schema))
        self.assertGreater(at, schema.index("GRANT pg_read_all_data TO opsloop_backup"))
        self.assertGreater(at, schema.index("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console')"))

    def test_표_일곱과_권한_줄이_기대와_같다(self):
        block = cti_block(read(SCHEMA))
        self.assertEqual(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", block), TABLES)
        self.assertEqual(grant_lines(block), GRANTS)
        # 권한을 받는 역할은 수집기 · 콘솔뿐이다. 탐지 · 적재 · 관문은 이 표를 보지 못한다
        self.assertEqual(re.findall(r"rolname = '(\w+)'", block), ["opsloop_cti", "opsloop_console"])

    def test_가려야_할_열_역할_생성_행_보안이_없다(self):
        block = cti_block(read(SCHEMA))
        self.assertNotIn("token_hash", block)
        self.assertFalse([g for g in grant_lines(block) if " nodes " in g + " "])
        self.assertNotIn("CREATE ROLE", block)             # 역할은 cti/install-cti.sh 가 비밀번호와 함께 만든다
        self.assertNotIn("ROW LEVEL SECURITY", block)      # 백업 역할이 NOBYPASSRLS 라 pg_dump 가 실패한다
        for role in ("opsloop_detector", "opsloop_ingest", "opsloop_gate", "opsloop_backup"):
            self.assertNotIn(role, block)

    def test_역할_검증_스크립트에_CTI_줄이_있다(self):
        lines = cti_verify_lines()
        by_role = {}
        for _, role, _, want in lines:
            by_role.setdefault(role, set()).add(want)
        self.assertEqual(by_role["opsloop_cti"], {"허용", "거부", "t", "f"})
        self.assertEqual(by_role["opsloop_console"], {"허용", "거부"})
        self.assertEqual(by_role["opsloop_detector"], {"거부"})
        self.assertEqual(by_role["opsloop_ingest"], {"거부"})
        self.assertEqual(by_role["opsloop_backup"], {"허용"})
        # 콘솔 · 백업은 일곱 표를 모두 읽는다
        for role in ("opsloop_console", "opsloop_backup"):
            reads = [stmt for _, r, stmt, want in lines if r == role and want == "허용"]
            self.assertTrue(any(all(t in stmt for t in TABLES) for stmt in reads), role)
        # 콘솔은 주목 CVE 목록을 고치지 못한다 (목록은 수집기가 목록 파일과 같게 둔다)
        console_denied = set().union(*(exercised(stmt) for _, r, stmt, want in lines
                                       if r == "opsloop_console" and want == "거부"))
        self.assertIn(("cti_watch", "DELETE"), console_denied)

    def test_역할_검증_스크립트는_수집기_쓰기_권한을_표마다_빠짐없이_본다(self):
        # 수집기가 받은 쓰기 권한은 모두 허용 줄로, CTI 표에서 받지 않은 쓰기는 모두 거부 줄로 본다.
        #   검토: 수집기의 cti_kev 적재(INSERT … ON CONFLICT DO UPDATE)를 보는 줄이 없었다
        granted = granted_writes(cti_block(read(SCHEMA)))
        self.assertIn(("cti_kev", "INSERT"), granted)
        allowed, denied = set(), set()
        for kind, role, stmt, want in cti_verify_lines():
            if kind == "q" and role == "opsloop_cti":
                (allowed if want == "허용" else denied).update(exercised(stmt))
        every = {(t, p) for t in TABLES for p in WRITES}
        self.assertEqual(allowed, granted)
        self.assertEqual(denied & every, every - granted)


@unittest.skipUnless(psycopg2 is not None and os.environ.get("OPSLOOP_TEST_DATABASE_URL"),
                     "PostgreSQL 시험 연결 미지정")
class CtiSchemaDatabaseTest(unittest.TestCase):
    """무작위 스키마에 마이그레이션 파일을 그대로 적용한다. 끝나면 스키마와 시험 역할을 지운다."""

    def setUp(self):
        self.tag = f"{os.getpid()}_{secrets.token_hex(4)}"
        self.schema, self.roles = f"opsloop_test_cti_{self.tag}", {}
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"], application_name="opsloop-test-cti")
        self.conn.autocommit = True               # 마이그레이션의 BEGIN; … COMMIT; 을 그대로 돌린다
        self.cur = self.conn.cursor()
        try:
            self.cur.execute(f"CREATE SCHEMA {self.schema}")
        except psycopg2.Error as e:
            self.conn.close()
            self.skipTest(f"시험 스키마를 만들 수 없습니다: {e}")
        self.addCleanup(self.drop)
        self.cur.execute(f"SET search_path TO {self.schema}")
        self.cur.execute(STUBS)
        self.cur.execute(read(MIGRATION))

    def drop(self):
        self.cur.execute("RESET ROLE")
        self.cur.execute(f"DROP SCHEMA IF EXISTS {self.schema} CASCADE")
        for name in self.roles.values():
            self.cur.execute(f"DROP OWNED BY {name}")       # 도중에 실패해 남은 권한이 있으면 거둔다
            self.cur.execute(f"DROP ROLE IF EXISTS {name}")
        self.conn.close()

    def one(self, sql, args=None):
        self.cur.execute(sql, args)
        return self.cur.fetchone()

    def snapshot(self, source="kev", status="ok", s3_key=S3_KEY, **cols):
        cols = {"source": source, "status": status, "s3_key": s3_key, **cols}
        sql = f"INSERT INTO cti_snapshots ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) RETURNING id"
        return self.one(sql, list(cols.values()))[0]

    def rejects(self, error, sql, args=None):
        with self.assertRaises(error):
            self.cur.execute(sql, args)

    # 제약 · 기본값 (소유자로)

    def test_원본_기록은_출처_상태_원본_위치가_맞아야_들어간다(self):
        sid = self.snapshot(sha256=SHA, bytes=1700000, records=1721, source_version="2026.09.23")
        fetched, status = self.one("SELECT fetched_at, status FROM cti_snapshots WHERE id = %s", (sid,))
        self.assertIsNotNone(fetched)                                   # 기본값 now()
        self.assertEqual(status, "ok")
        self.snapshot(source="epss", status="failed", s3_key=None, error="S3 쓰기 실패")
        bad = {
            "모르는 출처": {"source": "cisa"},
            "성공인데 원본 위치 없음": {"s3_key": None},
            "실패인데 원본 위치 있음": {"status": "failed"},
            "모르는 상태": {"status": "unchanged"},
            "해시 대문자": {"sha256": SHA.upper()},
            "해시 길이": {"sha256": SHA[:63]},
            "음수 크기": {"bytes": -1},
        }
        good = {"source": "kev", "status": "ok", "s3_key": S3_KEY, "sha256": SHA, "bytes": 1}
        for name, cols in bad.items():
            with self.subTest(name):
                row = {**good, **cols}
                self.rejects(psycopg2.errors.CheckViolation,
                             "INSERT INTO cti_snapshots (source, status, s3_key, sha256, bytes)"
                             " VALUES (%(source)s, %(status)s, %(s3_key)s, %(sha256)s, %(bytes)s)", row)
        with self.assertRaises(psycopg2.errors.CheckViolation) as ctx:
            self.cur.execute("INSERT INTO cti_snapshots (source, status) VALUES ('kev', 'ok')")
        self.assertEqual(ctx.exception.diag.constraint_name, "cti_snapshots_s3_key_ok")

    def test_KEV_는_CVE_형식과_원본_기록을_지킨다(self):
        sid = self.snapshot()
        sql = ("INSERT INTO cti_kev (cve_id, vendor_project, product, name, date_added, snapshot_id)"
               " VALUES (%s, 'OSGeo', 'GeoServer', 'GeoServer RCE', '2024-07-15', %s)")
        self.cur.execute(sql, ("CVE-2024-36401", sid))
        self.assertEqual(self.one("SELECT ransomware, due_date FROM cti_kev"), (None, None))
        for cve in ("CVE-2024-123", "cve-2024-36401", "CVE-24-36401", "UBUNTU-CVE-2024-6387"):
            with self.subTest(cve):
                self.rejects(psycopg2.errors.CheckViolation, sql, (cve, sid))
        self.rejects(psycopg2.errors.ForeignKeyViolation, sql, ("CVE-2024-0001", sid + 1000))
        self.rejects(psycopg2.errors.NotNullViolation, sql, ("CVE-2024-0002", None))

    def test_CVE_점수는_범위를_지킨다(self):
        sid = self.snapshot(source="epss")
        self.cur.execute("INSERT INTO cti_cve (cve_id, epss, epss_percentile, epss_date, epss_snapshot_id, cvss_score)"
                         " VALUES ('CVE-2024-6387', 0.99506, 0.99944, '2026-09-24', %s, 8.15)", (sid,))
        score, nvd = self.one("SELECT cvss_score, nvd_snapshot_id FROM cti_cve")
        self.assertEqual((str(score), nvd), ("8.2", None))              # numeric(3,1) 로 반올림, NVD 는 아직 없다
        self.cur.execute("INSERT INTO cti_cve (cve_id) VALUES ('CVE-2021-44228')")     # 점수 없이도 된다
        bad = {"epss": 1.01, "epss_percentile": -0.1, "cvss_score": 10.5}
        for col, value in bad.items():
            with self.subTest(col):
                self.rejects(psycopg2.errors.CheckViolation,
                             f"INSERT INTO cti_cve (cve_id, {col}) VALUES ('CVE-2020-0001', %s)", (value,))
        self.rejects(psycopg2.errors.CheckViolation, "INSERT INTO cti_cve (cve_id) VALUES ('GHSA-xxxx')")
        self.rejects(psycopg2.errors.ForeignKeyViolation,
                     "INSERT INTO cti_cve (cve_id, nvd_snapshot_id) VALUES ('CVE-2020-0002', %s)", (sid + 1000,))

    def test_배포판_기록은_상세_없이도_들어간다(self):
        sid = self.snapshot(source="osv")
        self.cur.execute("INSERT INTO cti_osv (osv_id, modified, snapshot_id) VALUES ('UBUNTU-CVE-2024-6387', now(), %s)",
                         (sid,))
        self.assertEqual(self.one("SELECT detailed, fixed, affected, cve_id FROM cti_osv"), (False, {}, {}, None))
        # 수정판은 fixed 에 있는 것만, 영향 항목은 수정판이 없는 것(null)까지 affected 에 둔다
        self.cur.execute("UPDATE cti_osv SET detailed = true, fixed = %s::jsonb, affected = %s::jsonb",
                         ('{"Ubuntu:24.04:LTS/openssh": "1:9.6p1-3ubuntu13.3"}',
                          '{"Ubuntu:24.04:LTS/openssh": "1:9.6p1-3ubuntu13.3", "Ubuntu:22.04:LTS/openssh": null}'))
        self.assertEqual(self.one("SELECT affected FROM cti_osv")[0],
                         {"Ubuntu:24.04:LTS/openssh": "1:9.6p1-3ubuntu13.3", "Ubuntu:22.04:LTS/openssh": None})
        self.rejects(psycopg2.errors.ForeignKeyViolation,
                     "INSERT INTO cti_osv (osv_id, snapshot_id) VALUES ('USN-6859-1', %s)", (sid + 1000,))
        self.rejects(psycopg2.errors.NotNullViolation,
                     "INSERT INTO cti_osv (osv_id, snapshot_id) VALUES ('USN-6859-1', NULL)")
        for col in ("fixed", "affected"):
            with self.subTest(col):
                self.rejects(psycopg2.errors.NotNullViolation,
                             f"INSERT INTO cti_osv (osv_id, {col}, snapshot_id) VALUES ('USN-6859-1', NULL, %s)", (sid,))

    def test_주목_CVE_는_CVE_형식과_배포판_기록_원본을_지킨다(self):
        sid = self.snapshot(source="osv")
        self.cur.execute("INSERT INTO cti_osv (osv_id, cve_id, snapshot_id)"
                         " VALUES ('UBUNTU-CVE-2024-6387', 'CVE-2024-6387', %s)", (sid,))
        # 목록 파일에서 막 읽은 CVE 는 조회 전이다 (배포판 기록 · 조회 결과 · 시각 · 원본 기록 모두 NULL)
        self.cur.execute("INSERT INTO cti_watch (cve_id, reason) VALUES ('CVE-2021-4034', 'polkit PwnKit')")
        self.assertEqual(self.one("SELECT osv_id, record_found, checked_at, snapshot_id FROM cti_watch"),
                         (None, None, None, None))
        sql = ("INSERT INTO cti_watch (cve_id, reason, osv_id, record_found, checked_at, snapshot_id)"
               " VALUES (%s, %s, %s, %s, now(), %s)")
        self.cur.execute(sql, ("CVE-2024-6387", "OpenSSH regreSSHion", "UBUNTU-CVE-2024-6387", True, sid))
        self.cur.execute(sql, ("CVE-2021-3156", "sudo Baron Samedit", None, False, sid))   # 배포판 기록 없음(404)
        self.rejects(psycopg2.errors.UniqueViolation, sql, ("CVE-2024-6387", "중복", None, None, sid))
        for cve in ("CVE-2024-123", "cve-2024-6387", "UBUNTU-CVE-2024-6387", "CVE-2024-6387 "):
            with self.subTest(cve):
                self.rejects(psycopg2.errors.CheckViolation, sql, (cve, "형식", None, None, sid))
        self.rejects(psycopg2.errors.NotNullViolation, sql, ("CVE-2023-4911", None, None, None, sid))
        refs = {"배포판 기록 없음": ("UBUNTU-CVE-2023-4911", sid), "원본 기록 없음": (None, sid + 1000)}
        for name, (osv, snap) in refs.items():
            with self.subTest(name):
                self.rejects(psycopg2.errors.ForeignKeyViolation, sql, ("CVE-2023-4911", "glibc", osv, True, snap))
        # 주목 CVE 가 가리키는 배포판 기록은 지우지 못한다
        self.rejects(psycopg2.errors.ForeignKeyViolation,
                     "DELETE FROM cti_osv WHERE osv_id = 'UBUNTU-CVE-2024-6387'")
        self.assertEqual(self.one("SELECT string_agg(cve_id, ',' ORDER BY cve_id) FROM cti_watch"),
                         ("CVE-2021-3156,CVE-2021-4034,CVE-2024-6387",))

    def test_자산은_이름_역할_방법을_지키고_빈_목록으로_시작한다(self):
        self.cur.execute("INSERT INTO asset_inventory (asset_id, role, method) VALUES ('web-01', 'target', 'ssh')")
        self.assertEqual(self.one("SELECT packages, images, probe_errors, collected_at, last_attempt_at IS NOT NULL"
                                  " FROM asset_inventory"), ([], [], [], None, True))
        self.cur.execute("INSERT INTO asset_inventory (asset_id, role, method) VALUES (%s, 'sensor', 'ssm')", ("a" * 63,))
        bad = {"대문자": ("Web-01", "target", "ssh"), "하이픈 시작": ("-web", "target", "ssh"),
               "64자": ("a" * 64, "target", "ssh"), "밑줄": ("web_01", "target", "ssh"),
               "모르는 역할": ("fw", "honeypot", "ssh"), "모르는 방법": ("fw", "platform", "winrm")}
        for name, row in bad.items():
            with self.subTest(name):
                self.rejects(psycopg2.errors.CheckViolation,
                             "INSERT INTO asset_inventory (asset_id, role, method) VALUES (%s, %s, %s)", row)

    def test_자산_취약점은_자산_배포판_기록_원본을_가리킨다(self):
        sid = self.snapshot(source="osv")
        self.cur.execute("INSERT INTO asset_inventory (asset_id, role, method) VALUES ('web-01', 'target', 'ssh')")
        self.cur.execute("INSERT INTO cti_osv (osv_id, snapshot_id) VALUES ('UBUNTU-CVE-2026-82474', %s)", (sid,))
        sql = ("INSERT INTO asset_vulnerabilities (asset_id, source_package, version, osv_id, cve_id, fix_state,"
               " fixed_version, snapshot_id) VALUES (%s, 'sudo', '1.9.15p5-3ubuntu5.24.04.2', %s, 'CVE-2026-82474',"
               " %s, '1.9.15p5-3ubuntu5.24.04.3', %s)")
        self.cur.execute(sql, ("web-01", "UBUNTU-CVE-2026-82474", "fix_available", sid))
        self.rejects(psycopg2.errors.UniqueViolation, sql, ("web-01", "UBUNTU-CVE-2026-82474", "no_fix", sid))
        self.cur.execute("DELETE FROM asset_vulnerabilities")
        self.rejects(psycopg2.errors.CheckViolation, sql, ("web-01", "UBUNTU-CVE-2026-82474", "patched", sid))
        refs = {"자산 없음": ("fw", "UBUNTU-CVE-2026-82474", sid),
                "배포판 기록 없음": ("web-01", "UBUNTU-CVE-2000-0001", sid),
                "원본 기록 없음": ("web-01", "UBUNTU-CVE-2026-82474", sid + 1000)}
        for name, (asset, osv, snap) in refs.items():
            with self.subTest(name):
                self.rejects(psycopg2.errors.ForeignKeyViolation, sql, (asset, osv, "unknown", snap))

    def test_색인이_있고_두_번_적용해도_같다(self):
        sid = self.snapshot()
        self.cur.execute(read(MIGRATION))                                 # 여러 번 적용해도 오류가 없고 행이 남는다
        self.assertEqual(self.one("SELECT count(*) FROM cti_snapshots WHERE id = %s", (sid,)), (1,))
        self.cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname = %s", (self.schema,))
        names = {r[0] for r in self.cur.fetchall()}
        for name in ("idx_cti_snapshots_source", "idx_cti_osv_cve", "idx_asset_vulnerabilities_cve"):
            self.assertIn(name, names)
        self.cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (self.schema,))
        self.assertEqual({r[0] for r in self.cur.fetchall()} & set(TABLES), set(TABLES))

    # 권한 (무작위 역할로 바꾼 권한 블록)

    def grant_roles(self):
        """운영 역할 대신 무작위 역할을 만들고 권한 블록을 그 이름으로 적용한다.
        콘솔의 스키마 사용 권한은 운영에서 역할 블록이 주므로 여기서 따로 준다. 백업은 운영처럼 pg_read_all_data 를 받는다.
        탐지 · 적재는 권한 블록에 없는 역할(other)로 본다."""
        for key in ("cti", "console", "backup", "other"):
            self.roles[key] = f"opsloop_test_{key}_{self.tag}"
            self.cur.execute(f"CREATE ROLE {self.roles[key]} NOLOGIN NOINHERIT")
        self.cur.execute(f"GRANT pg_read_all_data TO {self.roles['backup']} WITH INHERIT TRUE")
        for key in ("console", "other"):
            self.cur.execute(f"GRANT USAGE ON SCHEMA {self.schema} TO {self.roles[key]}")
        block = cti_block(read(SCHEMA))
        # 공유 시험 DB 의 접속 권한(CONNECT)은 건드리지 않는다. 시험 역할은 NOLOGIN 이고 SET ROLE 로만 쓴다
        do = block[block.index("DO $$"):].replace(GRANTS[0], "")
        self.cur.execute(do.replace("opsloop_cti", self.roles["cti"]).replace("opsloop_console", self.roles["console"])
                         .replace("SCHEMA public", f"SCHEMA {self.schema}"))
        return {"opsloop_cti": self.roles["cti"], "opsloop_console": self.roles["console"],
                "opsloop_backup": self.roles["backup"], "opsloop_detector": self.roles["other"],
                "opsloop_ingest": self.roles["other"]}

    @contextlib.contextmanager
    def as_role(self, role):
        self.cur.execute(f"SET ROLE {role}")
        try:
            yield
        finally:
            self.cur.execute("RESET ROLE")

    def test_권한_블록은_역할_검증_스크립트의_CTI_줄과_같은_답을_낸다(self):
        names = self.grant_roles()
        lines = cti_verify_lines()
        self.assertGreater(len(lines), 20)
        for kind, role, stmt, want in lines:
            with self.subTest(role=role, stmt=stmt):
                if kind == "p":        # 스크립트처럼 소유자로 권한만 본다
                    expr = stmt
                    for real, fake in names.items():
                        expr = expr.replace(f"'{real}'", f"'{fake}'")
                    got = "t" if self.one(f"SELECT {expr}")[0] else "f"
                else:
                    with self.as_role(names[role]):
                        try:
                            self.cur.execute(stmt)
                            got = "허용"
                        except psycopg2.errors.InsufficientPrivilege:
                            got = "거부"
                self.assertEqual(got, want)

    def test_수집기_역할로_적재_문장이_되고_콘솔은_읽는다(self):
        names = self.grant_roles()
        self.cur.execute("INSERT INTO rule_versions (rule_version, definition) VALUES ('c1', '{\"rules\": []}')")
        with self.as_role(names["opsloop_cti"]):
            self.assertEqual(self.one("SELECT count(*) FROM rule_versions"), (1,))
            sid = self.one("INSERT INTO cti_snapshots (source, source_url, s3_key, sha256, bytes, records, status)"
                           " VALUES ('kev', 'https://example.invalid/kev.json', %s, %s, 10, 2, 'ok') RETURNING id",
                           (S3_KEY, SHA))[0]
            kev = ("INSERT INTO cti_kev (cve_id, vendor_project, product, name, date_added, snapshot_id)"
                   " VALUES (%s, 'OSGeo', 'GeoServer', %s, '2024-07-15', %s)"
                   " ON CONFLICT (cve_id) DO UPDATE SET name = EXCLUDED.name, snapshot_id = EXCLUDED.snapshot_id")
            for cve, name in (("CVE-2024-36401", "옛 이름"), ("CVE-2024-36401", "새 이름"), ("CVE-2022-0001", "빠질 항목")):
                self.cur.execute(kev, (cve, name, sid))
            self.cur.execute("DELETE FROM cti_kev WHERE NOT (cve_id = ANY(%s))", (["CVE-2024-36401"],))
            self.assertEqual(self.one("SELECT string_agg(cve_id || ' ' || name, ',') FROM cti_kev"),
                             ("CVE-2024-36401 새 이름",))
            cve = ("INSERT INTO cti_cve (cve_id, epss, epss_snapshot_id) VALUES ('CVE-2024-36401', %s, %s)"
                   " ON CONFLICT (cve_id) DO UPDATE SET epss = EXCLUDED.epss, epss_snapshot_id = EXCLUDED.epss_snapshot_id")
            self.cur.execute(cve, (0.9, sid))
            self.cur.execute(cve, (0.95, sid))
            osv = ("INSERT INTO cti_osv (osv_id, cve_id, detailed, fixed, affected, snapshot_id)"
                   " VALUES ('UBUNTU-CVE-2024-36401', 'CVE-2024-36401', %s, %s::jsonb, %s::jsonb, %s)"
                   " ON CONFLICT (osv_id) DO UPDATE SET detailed = EXCLUDED.detailed, fixed = EXCLUDED.fixed,"
                   " affected = EXCLUDED.affected")
            self.cur.execute(osv, (False, "{}", "{}", sid))
            self.cur.execute(osv, (True, '{"Ubuntu:24.04:LTS/geoserver": "1.0"}',
                                   '{"Ubuntu:24.04:LTS/geoserver": "1.0", "Ubuntu:22.04:LTS/geoserver": null}', sid))
            # 주목 CVE 는 목록 파일과 같게 둔다: 넣고 · 조회 결과로 고치고 · 목록에서 빠진 CVE 는 지운다
            watch = ("INSERT INTO cti_watch (cve_id, reason, osv_id, record_found, checked_at, snapshot_id)"
                     " VALUES (%s, %s, %s, %s, now(), %s) ON CONFLICT (cve_id) DO UPDATE SET reason = EXCLUDED.reason,"
                     " osv_id = EXCLUDED.osv_id, record_found = EXCLUDED.record_found,"
                     " checked_at = EXCLUDED.checked_at, snapshot_id = EXCLUDED.snapshot_id")
            self.cur.execute(watch, ("CVE-2024-36401", "옛 이유", None, None, sid))
            self.cur.execute(watch, ("CVE-2024-36401", "GeoServer 원격 코드 실행", "UBUNTU-CVE-2024-36401", True, sid))
            self.cur.execute(watch, ("CVE-2021-3156", "sudo Baron Samedit", None, False, sid))
            self.cur.execute("DELETE FROM cti_watch WHERE cve_id <> ALL(%s::text[])", (["CVE-2024-36401"],))
            asset = ("INSERT INTO asset_inventory (asset_id, role, method, host, collected_at, received_at, packages)"
                     " VALUES ('web-01', 'target', 'ssh', 'opsloop-web-01', now(), now(), '[]')"
                     " ON CONFLICT (asset_id) DO UPDATE SET last_attempt_at = now(), last_error = %s")
            self.cur.execute(asset, (None,))
            self.cur.execute(asset, ("연결 실패",))
            self.cur.execute("UPDATE asset_inventory SET checked_at = now(), check_snapshot_id = %s, check_error = NULL"
                             " WHERE asset_id = 'web-01'", (sid,))
            for _ in range(2):         # 대조할 때마다 자산 단위로 지우고 다시 넣는다
                self.cur.execute("DELETE FROM asset_vulnerabilities WHERE asset_id = 'web-01'")
                self.cur.execute("INSERT INTO asset_vulnerabilities (asset_id, source_package, version, osv_id, cve_id,"
                                 " fix_state, snapshot_id) VALUES ('web-01', 'geoserver', '0.9', 'UBUNTU-CVE-2024-36401',"
                                 " 'CVE-2024-36401', 'fix_available', %s)", (sid,))
            # 원본을 남기지 못한 회차는 실패 기록만 남긴다. 남긴 기록은 고치지 못한다
            self.cur.execute("INSERT INTO cti_snapshots (source, status, error) VALUES ('epss', 'failed', 'S3 쓰기 실패')")
            with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                self.cur.execute("UPDATE cti_snapshots SET status = 'failed', s3_key = NULL WHERE id = %s", (sid,))
        with self.as_role(names["opsloop_console"]):
            row = self.one("SELECT v.asset_id, k.name, c.epss, o.detailed, i.last_error, s.status"
                           " FROM asset_vulnerabilities v JOIN cti_kev k USING (cve_id) JOIN cti_cve c USING (cve_id)"
                           " JOIN cti_osv o USING (osv_id) JOIN asset_inventory i USING (asset_id)"
                           " JOIN cti_snapshots s ON s.id = v.snapshot_id")
            self.assertEqual(row, ("web-01", "새 이름", 0.95, True, "연결 실패", "ok"))
            watch = self.one("SELECT string_agg(w.cve_id || ' ' || w.reason, ','), bool_and(w.record_found),"
                             " min(o.affected::text) FROM cti_watch w JOIN cti_osv o USING (osv_id)")
            self.assertEqual(watch, ("CVE-2024-36401 GeoServer 원격 코드 실행", True,
                                     '{"Ubuntu:22.04:LTS/geoserver": null, "Ubuntu:24.04:LTS/geoserver": "1.0"}'))
            with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                self.cur.execute("DELETE FROM asset_vulnerabilities")
            with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                self.cur.execute("UPDATE cti_watch SET reason = reason")


if __name__ == "__main__":
    unittest.main()
