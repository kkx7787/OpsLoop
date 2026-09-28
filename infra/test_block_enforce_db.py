#!/usr/bin/env python3
"""차단 자동 집행(이슈 #47) DB 시험.  python3 infra/test_block_enforce_db.py

DB 없이 도는 글자 시험: 마이그레이션(infra/migrations/20260927_block_enforce.sql)이 schema.sql 의 audit_blocklist ·
trg_audit_blocklist 문장과 '차단 집행 (이슈 #47)' 블록을 글자 그대로 담는지, 블록이 역할 블록 뒤(파일 끝)에 있는지, 차단 금지
대역 초기값 · 권한 줄이 계약과 같은지, verify-db-roles.sh 에 집행 역할 줄이 있는지, R201(a1) 이 새 감사 이벤트를 세지 않는지 본다.

OPSLOOP_TEST_DATABASE_URL 이 슈퍼유저 연결이면 이름이 무작위인 데이터베이스를 만들어 schema.sql 전체와 마이그레이션을 두 번씩
적용하고(역할 이름은 무작위로 바꾼다) 트리거 · 함수 · 권한을 실제로 돌린다. 역할로 바꿔 돌리는 것은
SET SESSION AUTHORIZATION 이라 감사 행위자('db:<역할>')까지 본다. 마이그레이션 전 DB(옛 감사 트리거 · 금지 대역 없음)에
기존 13행을 넣고 마이그레이션을 올리는 경우도 따로 만든다. 시험마다 되돌리고, 끝나면 데이터베이스와 역할을 지운다.
운영 DB · 운영 역할은 건드리지 않는다.
"""
import contextlib
import json
import os
import re
import secrets
import unittest

try:
    import psycopg2
    import psycopg2.extensions
except ImportError:
    psycopg2 = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20260927_block_enforce.sql")
VERIFY = os.path.join(ROOT, "infra", "vmware", "scripts", "verify-db-roles.sh")
RULES_AUDIT = os.path.join(ROOT, "detector", "rules_audit.json")
URL = os.environ.get("OPSLOOP_TEST_DATABASE_URL")

HEADER = "-- 차단 집행 (이슈 #47)"
NEXT_HEADER = "-- 차단 집행 지점 · 시험 출발지 (이슈 #51)"      # 이 블록 뒤에 오는 다음 블록(infra/test_block_points_db.py)
AUDIT_START = "CREATE OR REPLACE FUNCTION audit_blocklist()"
AUDIT_END = "EXECUTE FUNCTION audit_blocklist();"
# 계약의 초기값. 문서용 대역은 시험 출발지로 쓰므로 넣지 않는다
EXEMPT = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
          "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "15.164.37.49/32",
          "::1/128", "fc00::/7", "fe80::/10"]
DOC_NETS = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
# 대역마다 그 안의 주소 하나 (인프라에서 실제로 쓰는 주소를 고른다)
INSIDE = {"0.0.0.0/8": "0.1.2.3", "10.0.0.0/8": "10.0.1.10", "100.64.0.0/10": "100.101.102.103",
          "127.0.0.0/8": "127.0.0.1", "169.254.0.0/16": "169.254.169.254", "172.16.0.0/12": "172.18.0.1",
          "192.0.0.0/24": "192.0.0.8", "192.168.0.0/16": "192.168.50.1", "198.18.0.0/15": "198.19.255.1",
          "224.0.0.0/4": "239.255.255.250", "240.0.0.0/4": "255.255.255.255", "15.164.37.49/32": "15.164.37.49",
          "::1/128": "::1", "fc00::/7": "fd7a:115c:a1e0::1", "fe80::/10": "fe80::1"}
GRANTS = [
    "EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_enforcer', current_database());",
    "GRANT USAGE ON SCHEMA public TO opsloop_enforcer;",
    "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_enforcer;",
    "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_enforcer;",
    "GRANT SELECT ON blocklist, block_exempt TO opsloop_enforcer;",
    "GRANT UPDATE (method, enforced_at, enforce_note) ON blocklist TO opsloop_enforcer;",
    "GRANT EXECUTE ON FUNCTION note_block_expired(inet, timestamptz) TO opsloop_enforcer;",
    "GRANT SELECT ON block_exempt TO opsloop_console;",
]
NEW_EVENTS = ["console.block.created", "console.block.rearmed", "console.block.enforced", "console.block.unenforced",
              "console.block.expired"]
R201_EVENTS = ["console.block.released", "console.block.shortened"]
ROLE = re.compile(r"\bopsloop_(gate|ingest|detector|console|backup|cti|enforcer)\b")
ROLE_KEYS = ("gate", "ingest", "detector", "console", "backup", "cti", "enforcer")
# 운영의 기존 13행과 같은 꼴(2026-09-08 triage, 만료 · 요청자 · 집행 없음, 모두 공인 /32). 주소는 문서용 대역으로 바꿨다
LEGACY = [f"{net}.{n}" for net in ("192.0.2", "198.51.100", "203.0.113") for n in (11, 12, 13, 14)][:13]
APP_MAIN = os.path.join(ROOT, "app", "main.py")
TRIAGE = os.path.join(ROOT, "detector", "triage.py")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def console_block_sql():
    """콘솔 add_action 의 차단 문장 그대로(app/main.py BLOCK_SQL). 앱을 불러오지 않고 글자에서 떼어 낸다(FastAPI 없이 돈다).
    f-문자열의 {_LIVE} 를 채우고 $1 · $3 · $4 · $5 는 %s, $2(사유)는 'console' 로 바꾼다. 인자는 (주소, 사건 키, 요청자, 시간)."""
    text = read(APP_MAIN)
    live = re.search(r'^_LIVE = "(.+)"$', text, re.M).group(1)
    sql = re.search(r'^BLOCK_SQL = f"""(.+?)"""', text, re.M | re.S).group(1).replace("{_LIVE}", live)
    assert "{" not in sql and "%" not in sql, sql
    assert re.findall(r"\$(\d)", sql) == ["1", "2", "3", "4", "5"], sql     # 자리표시자가 차례대로 한 번씩이다
    return re.sub(r"\$(\d)", lambda m: "'console'" if m.group(1) == "2" else "%s", sql)


def triage_module():
    """detector/triage.py (psycopg2 · 표준 모듈만 쓴다). triage 의 이 출발지 차단 문장(OWN_BLOCK_SQL)을 실제 트리거에 댄다."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("triage_for_block47", TRIAGE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# 콘솔 add_action 의 차단 문장(app/main.py BLOCK_SQL). 살아 있는 차단의 만료는 줄이지 않고 집행 열도 둔다.
# 풀리거나 만료된 차단은 새 만료로 걸고 집행 열을 비운다(새 요청)
CONSOLE_BLOCK = console_block_sql()


def block47(text):
    """'차단 집행 (이슈 #47)' 블록(머리 주석 · 표 · 초기값 · 트리거 · 함수 · 권한)을 그대로 떼어 낸다.
    뒤에 #51 블록이 있으면 그 앞까지다."""
    start = text.index(HEADER + "\n")
    stop = text.find("\n" + NEXT_HEADER, start)
    region = text if stop < 0 else text[:stop]
    end = region.rindex("END\n$$;") + len("END\n$$;")
    return text[start:end]


def audit_sql(text):
    """감사 트리거 함수 · 권한 회수 · 트리거 문장."""
    start = text.index(AUDIT_START)
    return text[start:text.index(AUDIT_END, start) + len(AUDIT_END)]


def grant_lines(block):
    """권한 문장만. 줄 끝 주석을 떼고 공백을 하나로 줄인다."""
    stmts, cur = [], None
    for ln in block[block.rindex("DO $$"):].splitlines():
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


def seed(block):
    """초기값 INSERT 의 (대역, 설명)."""
    body = block[block.index("INSERT INTO block_exempt (cidr, note) VALUES"):block.index("ON CONFLICT (cidr) DO NOTHING;")]
    return re.findall(r"\('([0-9a-f.:/]+)',\s+'([^']+)'\)", body)


def verify_lines():
    """verify-db-roles.sh 의 q · p 줄을 (종류, 역할, 문장, 기대) 로."""
    pat = re.compile(r'^([qp]) (opsloop_[a-z]+) +"(.+)" (허용|거부|t|f)$')
    return [m.groups() for m in map(pat.match, read(VERIFY).splitlines()) if m]


def verify_lines47():
    """verify-db-roles.sh 에서 #51 절('# 집행 지점') 앞까지의 q · p 줄."""
    text = read(VERIFY)
    stop = text.find("# 집행 지점 (이슈 #51)")
    pat = re.compile(r'^([qp]) (opsloop_[a-z]+) +"(.+)" (허용|거부|t|f)$')
    return [m.groups() for m in map(pat.match, (text if stop < 0 else text[:stop]).splitlines()) if m]


def block_verify_lines():
    """집행 역할 줄과 금지 대역 · 만료 기록 함수를 건드리는 줄 (#47 절)."""
    return [ln for ln in verify_lines47()
            if ln[1] == "opsloop_enforcer" or "block_exempt" in ln[2] or "note_block_expired" in ln[2]
            or "blocklist_guard" in ln[2]]


def exercised(stmt):
    """검증 문장이 실제로 쓰는 (표, 권한[, 열])."""
    m = re.match(r"(INSERT INTO|UPDATE|DELETE FROM|SELECT .+? FROM) (\w+)", stmt)
    if not m:
        return set()
    verb = m.group(1).split()[0]
    return {(m.group(2), verb)}


class BlockEnforceTextTest(unittest.TestCase):
    """스키마 블록 · 마이그레이션 · 역할 검증 스크립트 · R201 의 글자 시험. DB 없이 돈다."""

    def test_마이그레이션은_스키마의_감사_트리거와_집행_블록_그대로다(self):
        schema, mig = read(SCHEMA), read(MIGRATION)
        head, body = mig.split("\nBEGIN;\n", 1)
        self.assertTrue(all(ln.startswith("--") for ln in head.splitlines()))       # 머리는 주석뿐이다
        self.assertEqual(body.rstrip("\n"), audit_sql(schema) + "\n" + block47(schema) + "\nCOMMIT;")
        self.assertEqual(schema.count(AUDIT_START), 1)                              # 감사 함수는 한 벌뿐이다

    def test_집행_블록은_역할_블록과_CTI_블록_뒤_파일_끝에_있다(self):
        # 역할 블록이 모든 표의 권한을 먼저 거두므로, 뒤에 있어야 스키마를 다시 적용해도 권한이 남는다
        schema = read(SCHEMA)
        at = schema.index(block47(schema))
        self.assertGreater(at, schema.index("GRANT pg_read_all_data TO opsloop_backup"))
        self.assertGreater(at, schema.index("-- CVE · KEV 연계 (이슈 #39)"))
        # 이 블록 뒤에는 #51 블록(집행 지점 · 시험 출발지)만 온다
        rest = schema[at + len(block47(schema)):].strip("\n")
        self.assertTrue(rest.startswith(NEXT_HEADER), rest[:80])
        self.assertEqual(schema.count(HEADER + "\n"), 1)

    def test_금지_대역_초기값은_계약과_같고_문서용_대역은_없다(self):
        rows = seed(block47(read(SCHEMA)))
        self.assertEqual([c for c, _ in rows], EXEMPT)
        self.assertTrue(all(note.strip() for _, note in rows))
        for net in DOC_NETS:
            self.assertNotIn(net.rsplit(".", 1)[0], " ".join(c for c, _ in rows))
        self.assertEqual(sorted(INSIDE), sorted(EXEMPT))

    def test_권한_줄은_계약과_같다(self):
        block = block47(read(SCHEMA))
        self.assertEqual(grant_lines(block), GRANTS)
        self.assertEqual(re.findall(r"rolname = '(\w+)'", block), ["opsloop_enforcer", "opsloop_console"])
        self.assertNotIn("CREATE ROLE", block)             # 역할은 enforcer/install-enforcer.sh 가 비밀번호와 함께 만든다
        self.assertNotIn("ROW LEVEL SECURITY", block)
        for role in ("opsloop_detector", "opsloop_ingest", "opsloop_gate", "opsloop_backup", "opsloop_cti"):
            self.assertNotIn(role, block)
        self.assertIn("REVOKE ALL ON FUNCTION note_block_expired(inet, timestamptz) FROM PUBLIC;", block)

    def test_트리거와_함수의_약속(self):
        block, audit = block47(read(SCHEMA)), audit_sql(read(SCHEMA))
        self.assertIn("CREATE OR REPLACE TRIGGER blocklist_guard\n    BEFORE INSERT OR UPDATE OF actor_ip ON blocklist", block)
        for name in ("blocklist_host_only", "blocklist_exempt"):
            self.assertIn(f"ERRCODE = 'check_violation', CONSTRAINT = '{name}'", block)
        self.assertIn("CREATE OR REPLACE FUNCTION note_block_expired(ip inet, expires timestamptz)", block)
        # 금지 대역 검사는 소유자 권한으로 돈다. 콘솔에 block_exempt 읽기가 없어도(역할 블록만 다시 적용) 차단이 막히지 않는다
        guard = block[block.index("CREATE OR REPLACE FUNCTION blocklist_guard()"):block.index("CREATE OR REPLACE TRIGGER blocklist_guard")]
        self.assertIn("\nSECURITY DEFINER\n", guard)
        self.assertIn("REVOKE ALL ON FUNCTION blocklist_guard() FROM PUBLIC;", block)
        self.assertIn("SECURITY DEFINER", audit)
        self.assertIn("AFTER INSERT OR UPDATE OF released_at, expires_at, actor_ip, enforced_at OR DELETE ON blocklist", audit)
        self.assertIn("REVOKE ALL ON FUNCTION audit_blocklist() FROM PUBLIC;", audit)
        for ev in NEW_EVENTS[:-1]:
            self.assertIn(f"'{ev}'", audit)
        self.assertIn("'console.block.expired'", block)

    def test_콘솔_차단_문장은_앱_문장_그대로다(self):
        # 앱 문장을 글자에서 떼어 온다. 살아 있는 차단은 만료 · 집행 열을 두고 새 요청이면 비운다
        self.assertIn("INSERT INTO blocklist (actor_ip, reason, incident_key, requested_by, expires_at)", CONSOLE_BLOCK)
        self.assertIn("VALUES (%s::inet, 'console', %s, %s, now() + make_interval(hours => %s))", CONSOLE_BLOCK)
        live = "(blocklist.released_at IS NULL AND (blocklist.expires_at IS NULL OR blocklist.expires_at > now()))"
        for col in ("method", "enforced_at", "enforce_note"):
            self.assertRegex(CONSOLE_BLOCK, rf"{col}\s+= CASE WHEN {re.escape(live)} THEN blocklist\.{col} END")
        self.assertEqual(CONSOLE_BLOCK.count("%s"), 4)

    def test_R201_은_해제와_단축만_세고_근거가_새_이벤트와_맞다(self):
        with open(RULES_AUDIT, encoding="utf-8") as f:
            doc = json.load(f)
        [rule] = doc["rules"]
        self.assertEqual(doc["rule_version"], "a1")            # 문구만 고쳤다. 규칙은 그대로다
        self.assertEqual(rule["params"]["eventids"], R201_EVENTS)
        why = rule["rationale"]
        self.assertNotIn("만료가 지난 뒤의 해제는 console.block.expired", why)     # 트리거는 그런 해제를 released 로 남긴다
        for s in ("note_block_expired", "console.block.expired", "past_expiry=yes", "console.block.created", "rearmed",
                  "enforced", "unenforced", "세지 않는다"):
            self.assertIn(s, why)

    def test_역할_검증_스크립트에_집행_줄이_있다(self):
        lines = block_verify_lines()
        by_role = {}
        for _, role, _, want in lines:
            by_role.setdefault(role, set()).add(want)
        self.assertEqual(by_role["opsloop_enforcer"], {"허용", "거부", "t", "f"})
        self.assertEqual(by_role["opsloop_console"], {"허용", "거부", "t", "f"})
        self.assertEqual(by_role["opsloop_detector"], {"거부", "f"})
        self.assertEqual(by_role["opsloop_ingest"], {"거부"})
        enforcer = [(stmt, want) for kind, role, stmt, want in lines if role == "opsloop_enforcer" and kind == "q"]
        allowed = set().union(*(exercised(s) for s, w in enforcer if w == "허용"))
        denied = set().union(*(exercised(s) for s, w in enforcer if w == "거부"))
        self.assertEqual(allowed, {("blocklist", "SELECT"), ("block_exempt", "SELECT"), ("blocklist", "UPDATE")})
        for want in (("blocklist", "INSERT"), ("blocklist", "DELETE"), ("block_exempt", "INSERT"), ("events", "SELECT"),
                     ("events", "INSERT"), ("incidents", "SELECT")):
            self.assertIn(want, denied)
        # 허용되는 UPDATE 는 집행 열 세 개뿐이고, 해제 · 만료 · 주소 열은 거부 줄로 본다
        upd = {w: [re.findall(r"SET (\w+) =|, (\w+) =", s) for s, ww in enforcer if ww == w and s.startswith("UPDATE")]
               for w in ("허용", "거부")}
        cols = lambda found: {c for pairs in found for pair in pairs for c in pair if c}   # noqa: E731
        self.assertEqual(cols(upd["허용"]), {"method", "enforced_at", "enforce_note"})
        self.assertEqual(cols(upd["거부"]), {"released_at", "expires_at", "actor_ip"})
        text = read(VERIFY)
        self.assertIn("rolname = 'opsloop_enforcer'", text)
        self.assertIn('[ "$att" = "true false false 2" ]', text)


def role_attr_sql():
    """verify-db-roles.sh 의 집행 역할 속성 문장."""
    m = re.search(r'att=\$\(psql_as opsloop "(SELECT [^"]+)"', read(VERIFY))
    return m.group(1)


def superuser_url():
    """연결이 되고 슈퍼유저면 True. 아니면 건너뛸 사유 문자열."""
    if psycopg2 is None or not URL:
        return "PostgreSQL 시험 연결 미지정"
    try:
        conn = psycopg2.connect(URL, connect_timeout=5)
    except psycopg2.Error as e:
        return f"시험 DB 에 붙지 못했습니다: {e}"
    try:
        cur = conn.cursor()
        cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        return True if cur.fetchone()[0] else "시험 연결이 슈퍼유저가 아닙니다(데이터베이스 · 역할 생성, 세션 권한 바꾸기)"
    finally:
        conn.close()


SKIP = superuser_url()


class DbCase(unittest.TestCase):
    """무작위 데이터베이스 · 역할. 시험마다 한 트랜잭션이고 끝나면 되돌린다."""

    tag = None
    roles = None
    dbname = None

    @classmethod
    def sub(cls, text):
        return ROLE.sub(lambda m: cls.roles[m.group(1)], text)

    @classmethod
    def create(cls, keys=ROLE_KEYS):
        cls.tag = f"{os.getpid()}_{secrets.token_hex(4)}"
        cls.dbname = f"opsloop_t47_{cls.tag}"
        cls.roles = {k: f"t47_{cls.tag}_{k}" for k in ROLE_KEYS}
        cls.admin = psycopg2.connect(URL)
        cls.admin.autocommit = True
        cls.made = []
        cls.addClassCleanup(cls.cleanup)            # setUpClass 가 도중에 실패해도 지운다
        a = cls.admin.cursor()
        a.execute(f"CREATE DATABASE {cls.dbname}")
        for k in keys:
            cls.make_role(k)
        cls.setup = psycopg2.connect(psycopg2.extensions.make_dsn(URL, dbname=cls.dbname))
        cls.setup.autocommit = True               # 마이그레이션의 BEGIN; … COMMIT; 을 그대로 돌린다
        cls.scur = cls.setup.cursor()
        cls.scur.execute("SET client_min_messages = warning")

    @classmethod
    def make_role(cls, key):
        # 집행 역할은 설치 스크립트와 같은 속성으로 만든다(비밀번호 없음). 나머지는 SET SESSION AUTHORIZATION 으로만 쓴다
        attrs = "LOGIN NOINHERIT CONNECTION LIMIT 2" if key == "enforcer" else "NOLOGIN NOINHERIT"
        cls.admin.cursor().execute(f"CREATE ROLE {cls.roles[key]} {attrs}")
        cls.made.append(cls.roles[key])

    @classmethod
    def connect(cls):
        cls.conn = psycopg2.connect(psycopg2.extensions.make_dsn(URL, dbname=cls.dbname),
                                    application_name="opsloop-test-block47")
        cls.cur = cls.conn.cursor()

    @classmethod
    def cleanup(cls):
        for c in ("conn", "setup"):
            if getattr(cls, c, None) is not None:
                getattr(cls, c).close()
        a = cls.admin.cursor()
        a.execute(f"DROP DATABASE IF EXISTS {cls.dbname} WITH (FORCE)")
        for name in cls.made:
            a.execute(f"DROP ROLE IF EXISTS {name}")
        cls.admin.close()

    def tearDown(self):
        self.conn.rollback()

    # ── 도우미 ──

    def q(self, sql, args=None):
        self.cur.execute(sql, args)
        return self.cur.fetchall()

    def one(self, sql, args=None):
        self.cur.execute(sql, args)
        return self.cur.fetchone()

    @contextlib.contextmanager
    def as_role(self, key, actor=None):
        """그 역할로 세션을 바꾼다(session_user 도 바뀐다). actor 가 있으면 앱처럼 opsloop.actor 를 넘긴다."""
        self.cur.execute(f"SET SESSION AUTHORIZATION {self.roles[key]}")
        if actor:
            self.cur.execute("SELECT set_config('opsloop.actor', %s, true)", (actor,))
        try:
            yield
        finally:
            self.cur.execute("RESET SESSION AUTHORIZATION")
            self.cur.execute("SELECT set_config('opsloop.actor', '', true)")

    def fails(self, sql, args=None):
        """문장이 실패해야 한다. 저장점으로 되돌려 트랜잭션은 이어 쓴다. 예외를 돌려준다."""
        self.cur.execute("SAVEPOINT t")
        try:
            self.cur.execute(sql, args)
        except psycopg2.Error as e:
            self.cur.execute("ROLLBACK TO SAVEPOINT t")
            return e
        self.cur.execute("RELEASE SAVEPOINT t")
        self.fail(f"실패해야 하는데 됐다: {sql} {args}")

    def denied(self, sql, args=None):
        e = self.fails(sql, args)
        self.assertEqual(e.pgcode, "42501", f"{sql}: {e}")

    def refused(self, constraint, sql, args=None):
        e = self.fails(sql, args)
        self.assertEqual((e.pgcode, e.diag.constraint_name, e.diag.table_name), ("23514", constraint, "blocklist"),
                         f"{sql} {args}: {e}")
        return e

    def audit(self, ip=None, eventid=None):
        """감사 이벤트 (eventid, username, input). 넣은 차례대로."""
        return self.q("SELECT eventid, username, input FROM events WHERE sensor = 'audit'"
                      " AND (%(ip)s::text IS NULL OR input ~ ('(^| )ip=' || %(ip)s || '( |$)'))"
                      " AND (%(ev)s::text IS NULL OR eventid = %(ev)s) ORDER BY ts, line_hash",
                      {"ip": ip, "ev": eventid})

    def events_of(self, ip):
        return [e for e, _, _ in self.audit(ip)]

    def put(self, ip, expires="now() + interval '1 day'", key="console", actor="han"):
        """콘솔 역할로 차단 한 줄(콘솔 문장과 같은 꼴은 CONSOLE_BLOCK)."""
        with self.as_role(key, actor):
            self.cur.execute(f"INSERT INTO blocklist (actor_ip, reason, incident_key, requested_by, expires_at)"
                             f" VALUES (%s, 'console', 'R001|v3|x', %s, {expires})", (ip, actor))

    def console_block(self, ip, hours=24, actor="han"):
        with self.as_role("console", actor):
            self.cur.execute(CONSOLE_BLOCK, (ip, f"R001|v3|{ip}", actor, hours))

    def enforce(self, ip, at="now()", method="nft", note=None):
        """집행 역할로 집행 열을 쓴다(집행기의 '관문 반영')."""
        with self.as_role("enforcer"):
            self.cur.execute(f"UPDATE blocklist SET method = %s, enforced_at = {at}, enforce_note = %s"
                             f" WHERE actor_ip = %s", (method, note or "관문 반영 · abcd1234 · 2026-09-27T00:00:00Z", ip))
            return self.cur.rowcount

    def unenforce(self, ip):
        with self.as_role("enforcer"):
            self.cur.execute("UPDATE blocklist SET enforced_at = NULL WHERE actor_ip = %s", (ip,))

    def note_expired(self, ip, expires, key="enforcer"):
        with self.as_role(key):
            return self.one("SELECT note_block_expired(%s::inet, %s::timestamptz)", (ip, expires))[0]


@unittest.skipUnless(SKIP is True, SKIP if SKIP is not True else "")
class BlockEnforceDatabaseTest(DbCase):
    """schema.sql 전체와 마이그레이션을 두 번씩 적용한 새 데이터베이스. 역할은 모두 있다."""

    @classmethod
    def setUpClass(cls):
        cls.create()
        for text in (read(SCHEMA), read(SCHEMA), read(MIGRATION), read(MIGRATION)):
            cls.scur.execute(cls.sub(text))
        cls.connect()

    # ── 금지 대역 · 대역 주소 ──

    def test_금지_대역의_주소는_콘솔로도_소유자로도_넣지_못하고_걸린_대역을_보인다(self):
        for cidr in EXEMPT:
            ip = INSIDE[cidr]
            with self.subTest(cidr=cidr), self.as_role("console", "han"):
                e = self.refused("blocklist_exempt", CONSOLE_BLOCK, (ip, "k", "han", 24))
                self.assertIn(cidr, e.diag.message_primary)
                self.assertIn(ip, e.diag.message_primary)
                self.assertEqual(e.diag.message_detail, f"cidr={cidr}")
            with self.subTest(cidr=cidr, who="소유자"):
                self.refused("blocklist_exempt", "INSERT INTO blocklist (actor_ip) VALUES (%s)", (ip,))
        self.assertEqual(self.one("SELECT count(*) FROM blocklist")[0], 0)
        self.assertEqual(self.audit(), [])                 # 거부는 되돌려지므로 감사도 남지 않는다

    def test_대역_주소는_주소_하나가_아니면_거부한다(self):
        # 금지 대역을 품은 대역(15.164.37.48/28)도 대역이라 먼저 걸린다
        for net in ("203.0.113.0/24", "0.0.0.0/0", "198.51.100.8/31", "15.164.37.48/28", "2001:db8::/64", "::/0"):
            with self.subTest(net=net), self.as_role("console", "han"):
                e = self.refused("blocklist_host_only", CONSOLE_BLOCK, (net, "k", "han", 24))
                self.assertIn(net, e.diag.message_primary)

    def test_공인_주소와_문서용_대역의_주소는_넣는다(self):
        ips = ["203.0.113.7", "198.51.100.9", "192.0.2.44", "15.164.37.48", "15.164.37.50", "2001:db8::1",
               "203.0.113.8/32", "2001:db8::2/128"]
        for ip in ips:
            self.console_block(ip)
        self.assertEqual(self.one("SELECT count(*) FROM blocklist")[0], len(ips))

    def test_주소를_바꿀_때만_다시_보고_다른_열은_막지_않는다(self):
        # 금지 대역 표가 생기기 전에 들어온 행(또는 나중에 대역을 더한 경우)을 흉내 낸다
        self.cur.execute("ALTER TABLE blocklist DISABLE TRIGGER blocklist_guard")
        self.cur.execute("INSERT INTO blocklist (actor_ip, reason) VALUES ('192.168.50.21', 'r'), ('203.0.113.0/24', 'r')")
        self.cur.execute("ALTER TABLE blocklist ENABLE TRIGGER blocklist_guard")
        with self.as_role("console", "han"):
            self.cur.execute("UPDATE blocklist SET expires_at = now() + interval '1 hour', reason = 'x'")
            self.cur.execute("UPDATE blocklist SET actor_ip = actor_ip")            # 값이 같으면 보지 않는다
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'han'")
            self.assertEqual(self.cur.rowcount, 2)
            self.refused("blocklist_exempt", "UPDATE blocklist SET actor_ip = '10.0.0.5' WHERE actor_ip = '192.168.50.21'")
            self.refused("blocklist_host_only",
                         "UPDATE blocklist SET actor_ip = '198.51.100.0/24' WHERE actor_ip = '192.168.50.21'")
            self.cur.execute("UPDATE blocklist SET actor_ip = '198.51.100.21' WHERE actor_ip = '192.168.50.21'")
        with self.as_role("enforcer"):
            self.cur.execute("UPDATE blocklist SET enforce_note = '집행 제외 · 대역 주소' WHERE actor_ip = '203.0.113.0/24'")
            self.assertEqual(self.cur.rowcount, 1)

    def test_금지_대역_검사는_가장_좁은_대역을_보인다(self):
        self.cur.execute("INSERT INTO block_exempt (cidr, note) VALUES ('10.0.1.0/24', '관문 서브넷')")
        e = self.refused("blocklist_exempt", "INSERT INTO blocklist (actor_ip) VALUES ('10.0.1.10')")
        self.assertIn("10.0.1.0/24 (관문 서브넷)", e.diag.message_primary)

    # ── 감사 ──

    def test_생성_해제_재차단이_남고_재차단은_사람의_해제를_보인다(self):
        ip = "203.0.113.30"
        self.console_block(ip)
        [(ev, who, detail)] = self.audit(ip)
        self.assertEqual((ev, who), ("console.block.created", "han"))
        self.assertRegex(detail, rf"^by=han ip={re.escape(ip)} incident=R001\|v3\|{re.escape(ip)} expires=\S+.* requested_by=han$")
        self.console_block(ip)                                      # 살아 있는 차단에 다시: 만료를 줄이지 않는다
        self.assertEqual(self.events_of(ip), ["console.block.created"])
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1' WHERE actor_ip = %s", (ip,))
        self.console_block(ip, actor="kim")
        self.assertEqual(self.events_of(ip), ["console.block.created", "console.block.released", "console.block.rearmed"])
        ev, who, detail = self.audit(ip)[-1]
        self.assertEqual(who, "kim")
        self.assertIn("released_by=admin1 requested_by=kim", detail)

    def test_집행_기록은_값이_바뀔_때만_남고_행위자는_집행_역할이다(self):
        ip = "203.0.113.31"
        self.console_block(ip)
        self.assertEqual(self.enforce(ip, at="'2026-09-27 00:00:00+00'"), 1)
        self.enforce(ip, at="'2026-09-27 00:00:00+00'")                   # 같은 값: 남지 않는다
        with self.as_role("enforcer"):
            self.cur.execute("UPDATE blocklist SET enforce_note = '관문 불일치 · 목록 digest 다름', method = 'fail2ban'"
                             " WHERE actor_ip = %s", (ip,))               # 집행 열 중 시각이 아니면 남지 않는다
        self.enforce(ip, at="'2026-09-27 01:00:00+00'", method="fail2ban")
        self.unenforce(ip)
        self.unenforce(ip)                                                # 이미 비었으면 남지 않는다
        got = self.audit(ip)
        self.assertEqual([e for e, _, _ in got], ["console.block.created", "console.block.enforced",
                                                  "console.block.enforced", "console.block.unenforced"])
        self.assertEqual({w for e, w, _ in got[1:]}, {f"db:{self.roles['enforcer']}"})
        self.assertIn("method=nft at=2026-09-27 00:00:00+00 note=관문 반영 · abcd1234 · 2026-09-27T00:00:00Z", got[1][2])
        self.assertIn("method=fail2ban at=2026-09-27 01:00:00+00", got[2][2])
        self.assertRegex(got[3][2], r"method=fail2ban was=2026-09-27 01:00:00\+00 why=reset$")

    def test_집행_해제의_까닭은_해제_만료_새_요청이다(self):
        rel, exp, new, live = "203.0.113.40", "203.0.113.41", "203.0.113.42", "203.0.113.43"
        self.console_block(rel)
        self.put(exp, expires="now() - interval '1 minute'")
        self.put(new, expires="now() - interval '1 minute'")
        self.console_block(live)
        for ip in (rel, exp, new, live):
            self.enforce(ip)
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1' WHERE actor_ip = %s", (rel,))
        self.unenforce(rel)
        self.unenforce(exp)
        self.console_block(new)                        # 만료된 차단에 다시(집행기가 지우기 전): 새 요청이라 집행 열을 비운다
        for ip, why in ((rel, "released"), (exp, "expired"), (new, "reset")):
            with self.subTest(why=why):
                self.assertTrue(self.audit(ip, "console.block.unenforced")[-1][2].endswith(f"why={why}"))
        # 살아 있는 차단에 다시(앱 문장 그대로): 관문에 이미 있으므로 집행 열을 두고 만료만 늦춘다. unenforced 가 남지 않는다
        self.console_block(live, hours=48)
        self.assertEqual(self.events_of(live), ["console.block.created", "console.block.enforced", "console.block.extended"])
        self.assertEqual(self.one("SELECT method, enforced_at IS NOT NULL FROM blocklist WHERE actor_ip = %s", (live,)),
                         ("nft", True))

    def test_triage_재차단은_사람의_해제를_되살리지_않고_감사도_남기지_않는다(self):
        # detector/triage.py OWN_BLOCK_SQL 을 콘솔 역할 · 실제 트리거에 댄다. 사람이 푼 행은 돌려받는 행이 없고 그대로다.
        # 누가 풀었는지 없는 해제 · 만료된 행은 새 만료로 다시 걸고 집행 열을 비운다. 만료 없는 옛 차단은 만료 없이 남는다
        tr = triage_module()
        human, anon, legacy = "198.51.100.70", "198.51.100.71", "198.51.100.72"
        self.console_block(human)
        self.enforce(human)
        self.put(anon, expires="now() - interval '1 minute'")
        self.enforce(anon)
        self.put(legacy, expires="NULL")
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1' WHERE actor_ip = %s", (human,))
        before = self.one("SELECT * FROM blocklist WHERE actor_ip = %s", (human,))
        n_before = len(self.audit(human))

        def triage_block(ip):
            with self.as_role("console", "han"):
                self.cur.execute(tr.OWN_BLOCK_SQL, {"ip": ip, "reason": "근거", "key": f"R002|v3|{ip}",
                                                    "who": tr.requested_by("han"), "hours": 24})
                return self.cur.fetchall()
        self.assertEqual(triage_block(human), [])
        self.assertEqual(self.one("SELECT * FROM blocklist WHERE actor_ip = %s", (human,)), before)
        self.assertEqual(len(self.audit(human)), n_before)                   # rearmed 가 남지 않는다
        [(expires,)] = triage_block(anon)
        self.assertEqual(self.one("SELECT expires_at > now(), enforced_at, method, requested_by FROM blocklist"
                                  " WHERE actor_ip = %s", (anon,)), (True, None, None, "triage:han"))
        self.assertEqual(self.events_of(anon)[-2:], ["console.block.extended", "console.block.unenforced"])
        self.assertTrue(self.audit(anon, "console.block.unenforced")[-1][2].endswith("why=reset"))
        self.assertEqual(triage_block(legacy), [(None,)])                      # 만료 없는 옛 차단: 그대로 없다(집행 제외)
        with self.as_role("console", "han"):
            e = self.refused("blocklist_exempt", tr.OWN_BLOCK_SQL, {"ip": "192.168.50.21", "reason": "근거",
                                                                   "key": "k", "who": "triage:han", "hours": 24})
        self.assertIn("192.168.0.0/16", e.diag.message_primary)

    def test_재차단이_집행_기록을_비우면_두_줄이_남는다(self):
        ip = "203.0.113.32"
        self.console_block(ip)
        self.enforce(ip)
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1' WHERE actor_ip = %s", (ip,))
        self.console_block(ip)                         # 집행기가 아직 집행 기록을 지우기 전에 다시 걸었다
        self.assertEqual(self.events_of(ip)[-2:], ["console.block.rearmed", "console.block.unenforced"])

    def test_기존_분류는_그대로다(self):
        a, b = "198.51.100.50", "198.51.100.51"
        self.console_block(a)
        with self.as_role("console", "han"):
            self.cur.execute("UPDATE blocklist SET expires_at = expires_at + interval '1 day' WHERE actor_ip = %s", (a,))
            self.cur.execute("UPDATE blocklist SET expires_at = expires_at - interval '2 day' WHERE actor_ip = %s", (a,))
            self.cur.execute("UPDATE blocklist SET actor_ip = %s WHERE actor_ip = %s", (b, a))
        self.cur.execute("DELETE FROM blocklist WHERE actor_ip = %s", (b,))
        got = self.audit()
        self.assertEqual([e for e, _, _ in got], ["console.block.created", "console.block.extended",
                                                  "console.block.shortened", "console.block.released",
                                                  "console.block.released"])
        self.assertIn(f"ip={a} incident=R001|v3|{a} how=readdress to={b}", got[3][2])
        self.assertIn(f"ip={b} incident=R001|v3|{a} how=delete past_expiry=yes", got[4][2])

    def test_새_이벤트는_감사_화면에_보이고_고칠_수_없다(self):
        ip = "203.0.113.33"
        self.put(ip, expires="now() - interval '1 minute'")
        self.enforce(ip)
        self.unenforce(ip)
        self.assertTrue(self.note_expired(ip, self.one("SELECT expires_at FROM blocklist WHERE actor_ip = %s", (ip,))[0]))
        with self.as_role("console"):
            seen = [r[0] for r in self.q("SELECT eventid FROM audit_log WHERE detail LIKE %s ORDER BY ts", (f"% ip={ip} %",))]
        self.assertEqual(seen, ["console.block.created", "console.block.enforced", "console.block.unenforced",
                                "console.block.expired"])
        for ev in seen:
            with self.subTest(ev=ev):
                e = self.fails("UPDATE events SET input = '' WHERE eventid = %s", (ev,))
                self.assertIn("감사 이벤트는 고치거나 지울 수 없다", str(e))
                self.fails("DELETE FROM events WHERE eventid = %s", (ev,))

    def test_R201_입력은_생성_집행_만료_재차단에서_늘지_않는다(self):
        ip = "203.0.113.34"
        self.put(ip, expires="now() - interval '1 minute'")
        self.enforce(ip)
        self.unenforce(ip)
        self.note_expired(ip, self.one("SELECT expires_at FROM blocklist WHERE actor_ip = %s", (ip,))[0])
        self.console_block(ip)                         # 만료된 차단에 다시: 만료를 늦춘다(extended)
        self.enforce(ip)
        counted = self.q("SELECT eventid FROM events WHERE sensor = 'audit' AND eventid = ANY(%s)", (R201_EVENTS,))
        self.assertEqual(counted, [])
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1' WHERE actor_ip = %s", (ip,))
        self.assertEqual(len(self.q("SELECT 1 FROM events WHERE sensor = 'audit' AND eventid = ANY(%s)", (R201_EVENTS,))), 1)

    # ── 만료 기록 ──

    def test_만료_기록은_같은_만료에_한_번만_시간대와_무관하게(self):
        ip = "198.51.100.60"
        self.put(ip, expires="'2026-09-26 03:04:05.123456+00'")
        exp = self.one("SELECT expires_at FROM blocklist WHERE actor_ip = %s", (ip,))[0]
        self.assertTrue(self.note_expired(ip, exp))
        self.assertFalse(self.note_expired(ip, exp))
        self.cur.execute("SET LOCAL TimeZone = 'Asia/Seoul'")
        self.assertFalse(self.note_expired(ip, "2026-09-26 12:04:05.123456+09"))
        [(ev, who, detail)] = self.audit(ip, "console.block.expired")
        self.assertEqual(who, f"db:{self.roles['enforcer']}")
        self.assertEqual(detail, f"by=db:{self.roles['enforcer']} ip={ip} incident=R001|v3|x"
                                 f" expires=2026-09-26T03:04:05.123456Z")
        # 다시 걸어 새 만료가 지나면 새 줄이다. 앱이 넘긴 행위자가 있으면 그 이름이다
        self.cur.execute("UPDATE blocklist SET expires_at = '2026-09-26 05:00:00+00' WHERE actor_ip = %s", (ip,))
        with self.as_role("enforcer", actor="enforcer"):
            self.assertTrue(self.one("SELECT note_block_expired(%s, '2026-09-26 05:00:00+00')", (ip,))[0])
        self.assertEqual([w for _, w, _ in self.audit(ip, "console.block.expired")], [f"db:{self.roles['enforcer']}",
                                                                                     "enforcer"])

    def test_만료_기록은_실제로_지난_그_만료만_받는다(self):
        live, unset, early, late = "198.51.100.61", "198.51.100.62", "198.51.100.63", "198.51.100.64"
        self.put(live)
        self.put(unset, expires="NULL")
        self.put(early, expires="now() - interval '1 hour'")
        self.put(late, expires="now() - interval '2 hour'")
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = expires_at - interval '1 minute' WHERE actor_ip = %s",
                             (early,))                                  # 만료 전에 풀렸다: 해제다
            self.cur.execute("UPDATE blocklist SET released_at = now() WHERE actor_ip = %s", (late,))   # 만료 뒤에 풀렸다
        exp = dict(self.q("SELECT host(actor_ip), expires_at FROM blocklist"))
        self.assertFalse(self.note_expired(live, exp[live]))              # 아직 살아 있다
        self.assertFalse(self.note_expired(unset, "2026-01-01 00:00:00+00"))   # 만료 없음
        self.assertFalse(self.note_expired(early, exp[early]))
        self.assertFalse(self.note_expired(late, "2026-01-01 00:00:00+00"))    # 행의 만료와 다르다
        self.assertFalse(self.note_expired("198.51.100.99", "2026-01-01 00:00:00+00"))   # 행이 없다
        self.assertFalse(self.note_expired(None, None))
        self.assertTrue(self.note_expired(late, exp[late]))
        self.assertEqual([self.audit(ip, "console.block.expired") != [] for ip in (live, unset, early, late)],
                         [False, False, False, True])

    def test_만료_기록_함수는_집행_역할만_부른다(self):
        ip = "198.51.100.65"
        self.put(ip, expires="now() - interval '1 hour'")
        for key in ("console", "detector", "ingest", "gate", "backup", "cti"):
            with self.subTest(role=key), self.as_role(key):
                self.denied("SELECT note_block_expired('198.51.100.65', now())")
        self.assertEqual(self.audit(ip, "console.block.expired"), [])

    # ── 권한 ──

    def test_집행_역할은_집행_열만_고치고_다른_표를_보지_못한다(self):
        ip = "203.0.113.35"
        self.console_block(ip)
        with self.as_role("enforcer"):
            self.assertEqual(self.one("SELECT count(*) FROM blocklist WHERE released_at IS NULL")[0], 1)
            self.assertEqual(self.one("SELECT count(*) FROM block_exempt")[0], len(EXEMPT))
            for sql in ("UPDATE blocklist SET released_at = now()", "UPDATE blocklist SET expires_at = now()",
                        "UPDATE blocklist SET reason = 'x'", "UPDATE blocklist SET released_by = 'x'",
                        "UPDATE blocklist SET actor_ip = '203.0.113.36'",
                        "INSERT INTO blocklist (actor_ip) VALUES ('203.0.113.37')", "DELETE FROM blocklist",
                        "TRUNCATE blocklist", "INSERT INTO block_exempt (cidr, note) VALUES ('203.0.113.0/24', 'x')",
                        "DELETE FROM block_exempt", "SELECT count(*) FROM events", "SELECT count(*) FROM incidents",
                        "SELECT count(*) FROM verdicts", "SELECT count(*) FROM absorbed_blocks",
                        "SELECT count(*) FROM audit_log", "SELECT audit_event('console.block.released', 'ip=1.2.3.4')",
                        "ALTER TABLE blocklist DISABLE TRIGGER trg_audit_blocklist"):
                with self.subTest(sql=sql):
                    self.denied(sql)
        self.assertEqual(self.one("SELECT released_at, expires_at > now() FROM blocklist WHERE actor_ip = %s", (ip,)),
                         (None, True))

    def test_권한은_계약과_정확히_같다(self):
        enforcer, console = self.roles["enforcer"], self.roles["console"]
        privs = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
        rels = [r[0] for r in self.q("SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace"
                                     " AND relkind IN ('r', 'v', 'p', 'S') ORDER BY 1")]
        self.assertIn("block_exempt", rels)
        got = {(rel, p) for rel in rels for p in privs
               if self.one("SELECT has_table_privilege(%s, %s, %s)", (enforcer, f"public.{rel}", p))[0]}
        # #52 블록의 sensor_heartbeats 권한(차단 보고 생존 신호)은 이 마이그레이션을 다시 적용하면 빠진다. 여기서는 #47 이 마지막이다.
        #   #52 를 뒤에 적용했을 때는 infra/test_status_board_db.py 가 본다
        self.assertEqual(got, {("blocklist", "SELECT"), ("block_exempt", "SELECT")})
        cols = [r[0] for r in self.q("SELECT attname FROM pg_attribute WHERE attrelid = 'blocklist'::regclass"
                                     " AND attnum > 0 AND NOT attisdropped")]
        upd = {c for c in cols if self.one("SELECT has_column_privilege(%s, 'blocklist', %s, 'UPDATE')", (enforcer, c))[0]}
        self.assertEqual(upd, {"method", "enforced_at", "enforce_note"})
        # 소유자 권한으로 도는 함수는 부를 수 있는 것만 본다: 집행 역할은 만료 기록뿐, 콘솔 · 탐지는 없다
        definer = lambda role: {r[0] for r in self.q(   # noqa: E731
            "SELECT proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND prosecdef"
            " AND has_function_privilege(%s, oid, 'EXECUTE')", (role,))}
        # is_test_source(#51)는 시험 출발지 판단만 하는 PUBLIC 실행 함수라 모든 역할이 부른다 (infra/test_block_points_db.py)
        public = {"is_test_source"}
        self.assertEqual(definer(enforcer) - public, {"note_block_expired"})
        self.assertEqual(definer(console) - public, set())
        self.assertEqual(definer(self.roles["detector"]) - public, set())
        self.assertEqual(definer(self.roles["gate"]) - public, {"enroll_node"})
        self.assertTrue(public <= definer(console))
        # 콘솔은 금지 대역을 읽기만, 탐지 · 적재 · 관문 · CTI 는 보지 못한다. 백업은 전부 읽는다(pg_read_all_data)
        for key, want in (("console", {"SELECT"}), ("detector", set()), ("ingest", set()), ("gate", set()),
                          ("cti", set()), ("enforcer", {"SELECT"})):
            with self.subTest(role=key):
                self.assertEqual({p for p in privs if self.one("SELECT has_table_privilege(%s, 'block_exempt', %s)",
                                                               (self.roles[key], p))[0]}, want)

    def test_콘솔은_금지_대역을_읽기만_한다(self):
        with self.as_role("console"):
            self.assertEqual(self.one("SELECT count(*) FROM block_exempt WHERE '192.168.50.1'::inet <<= cidr")[0], 1)
            for sql in ("INSERT INTO block_exempt (cidr, note) VALUES ('203.0.113.0/24', 'x')",
                        "UPDATE block_exempt SET note = 'x'", "DELETE FROM block_exempt", "TRUNCATE block_exempt"):
                with self.subTest(sql=sql):
                    self.denied(sql)
        for key in ("detector", "ingest"):
            with self.subTest(role=key), self.as_role(key):
                self.denied("SELECT count(*) FROM block_exempt")
                self.denied("INSERT INTO blocklist (actor_ip) VALUES ('203.0.113.9')")

    def test_콘솔이_금지_대역을_읽지_못해도_검사는_되고_정상_주소는_들어간다(self):
        # 역할 블록(schema.sql · 20260924_db_roles.sql)만 다시 적용하면 콘솔의 block_exempt 읽기가 사라진다. 검사가 호출자 권한으로
        # 돌면 그 순간부터 콘솔의 모든 차단(정상 주소까지)이 permission denied 로 막혔다. SECURITY DEFINER 라 검사도 거부도 그대로다
        tr = triage_module()
        self.cur.execute(f"REVOKE SELECT ON block_exempt FROM {self.roles['console']}")
        with self.as_role("console", "han"):
            self.denied("SELECT count(*) FROM block_exempt")
            e = self.refused("blocklist_exempt", CONSOLE_BLOCK, ("192.168.50.21", "k", "han", 24))
            self.assertIn("192.168.0.0/16", e.diag.message_primary)
            self.refused("blocklist_host_only", CONSOLE_BLOCK, ("203.0.113.0/24", "k", "han", 24))
            self.cur.execute(CONSOLE_BLOCK, ("203.0.113.70", "k", "han", 24))
            self.fails("SELECT blocklist_guard()")                                # 직접 부르지 못한다
            # 앱 · triage 가 보는 식(has_exempt_table): 표는 있지만 읽지 못하면 false → 상수만 거르고 사유 없이 거절만 보인다
            self.assertEqual(self.one(tr.EXEMPT_READABLE_SQL)[0], False)
        self.assertEqual(self.one(tr.EXEMPT_READABLE_SQL)[0], True)
        self.assertEqual(self.one("SELECT count(*) FROM blocklist")[0], 1)
        self.assertEqual(self.events_of("203.0.113.70"), ["console.block.created"])

    def test_역할_검증_스크립트_줄이_시험_DB_에서_같은_답을_낸다(self):
        lines = block_verify_lines()
        self.assertGreater(len(lines), 20)
        for kind, role, stmt, want in lines:
            key = role.removeprefix("opsloop_")
            with self.subTest(role=role, stmt=stmt):
                if kind == "p":
                    got = "t" if self.one("SELECT " + self.sub(stmt))[0] else "f"
                else:
                    self.cur.execute("SAVEPOINT v")
                    self.cur.execute(f"SET SESSION AUTHORIZATION {self.roles[key]}")
                    try:
                        self.cur.execute(self.sub(stmt))
                        got = "허용"
                    except psycopg2.Error as e:
                        got = "거부" if e.pgcode == "42501" else f"오류({e.pgcode} {e})"
                    self.cur.execute("ROLLBACK TO SAVEPOINT v")
                    self.cur.execute("RESET SESSION AUTHORIZATION")
                self.assertEqual(got, want)
        # 역할 속성 줄: 설치 스크립트와 같은 속성으로 만든 역할이면 기대값이 나온다
        [(att,)] = self.q(self.sub(role_attr_sql()))
        self.assertEqual(att, "true false false 2")

    def test_두_번_적용해도_초기값과_권한이_같다(self):
        self.assertEqual(self.one("SELECT count(*), count(*) FILTER (WHERE created_at IS NOT NULL) FROM block_exempt"),
                         (len(EXEMPT), len(EXEMPT)))
        self.assertEqual(sorted(r[0] for r in self.q("SELECT text(cidr) FROM block_exempt")),
                         sorted(EXEMPT))
        trg = dict(self.q("SELECT tgname, pg_get_triggerdef(oid) FROM pg_trigger"
                          " WHERE tgrelid = 'blocklist'::regclass AND NOT tgisinternal"))
        # blocklist_enforcement_guard 는 #51 블록(지점별 결과 열 보호)이 더한다. 시험은 infra/test_block_points_db.py
        self.assertEqual(sorted(set(trg) - {"blocklist_enforcement_guard"}), ["blocklist_guard", "trg_audit_blocklist"])
        self.assertIn("BEFORE INSERT OR UPDATE OF actor_ip ON public.blocklist", trg["blocklist_guard"])
        self.assertIn("AFTER INSERT OR DELETE OR UPDATE OF released_at, expires_at, actor_ip, enforced_at ON public.blocklist",
                      trg["trg_audit_blocklist"])


@unittest.skipUnless(SKIP is True, SKIP if SKIP is not True else "")
class BlockEnforceMigrationTest(DbCase):
    """마이그레이션 전 DB(옛 감사 트리거 · 금지 대역 없음 · 집행 역할 없음)에 기존 13행을 두고 마이그레이션을 올린다.
    운영 순서대로 마이그레이션 → 집행 역할 생성(install-enforcer.sh) → 마이그레이션 다시 적용이다."""

    @classmethod
    def old_schema(cls):
        """schema.sql 에서 이번 블록을 빼고 감사 트리거를 옛 모양(호출자 권한 · 해제 · 만료 · 주소 · 삭제만)으로 되돌린다."""
        text = read(SCHEMA)
        text = text.replace(block47(text), "")
        audit = audit_sql(text)
        revoke = audit[audit.index("-- 트리거 함수는 직접 부를 수 없지만"):audit.index("FROM PUBLIC;\n") + len("FROM PUBLIC;\n")]
        old = (audit.replace("LANGUAGE plpgsql\nSECURITY DEFINER\n", "LANGUAGE plpgsql\n", 1)
               .replace(revoke, "")
               .replace("AFTER INSERT OR UPDATE OF released_at, expires_at, actor_ip, enforced_at OR DELETE",
                        "AFTER UPDATE OF released_at, expires_at, actor_ip OR DELETE"))
        assert old.count("SECURITY DEFINER") == 0 and old != audit
        return text.replace(audit, old)

    @classmethod
    def setUpClass(cls):
        cls.create(keys=[k for k in ROLE_KEYS if k != "enforcer"])
        cls.scur.execute(cls.sub(cls.old_schema()))
        # 기존 13행(9/8 triage, 만료 없음)과, 검사가 없던 때 들어온 대역 한 줄 · 금지 대역 한 줄
        for ip in LEGACY:
            cls.scur.execute("INSERT INTO blocklist (actor_ip, reason, incident_key, created_at)"
                             " VALUES (%s, 'triage', %s, '2026-09-08 11:50:00+00')", (ip, f"R002|v1|{ip}|x"))
        cls.scur.execute("INSERT INTO blocklist (actor_ip, reason) VALUES ('192.168.50.21', 'R202'), ('203.0.113.0/24', 'x')")
        cls.scur.execute("SELECT count(*) FROM events")
        cls.events_before = cls.scur.fetchone()[0]
        cls.scur.execute(cls.sub(read(MIGRATION)))              # 집행 역할이 아직 없다
        cls.scur.execute("SELECT count(*) FROM events")
        cls.events_after_first = cls.scur.fetchone()[0]
        cls.scur.execute("SELECT has_table_privilege(%s, 'block_exempt', 'SELECT')", (cls.roles["console"],))
        cls.console_read_first = cls.scur.fetchone()[0]
        cls.make_role("enforcer")                               # install-enforcer.sh 가 역할을 만들고
        cls.scur.execute(cls.sub(read(MIGRATION)))              # 마이그레이션을 다시 적용한다
        cls.connect()

    def test_마이그레이션은_기존_행을_다시_보지_않고_감사도_남기지_않는다(self):
        self.assertEqual(self.one("SELECT count(*) FROM blocklist")[0], len(LEGACY) + 2)
        self.assertEqual(self.events_after_first, self.events_before)
        self.assertEqual(self.one("SELECT count(*) FROM events")[0], self.events_before)
        self.assertTrue(self.console_read_first)                # 콘솔 읽기는 첫 적용부터 된다
        self.assertEqual(self.one("SELECT count(*) FROM block_exempt")[0], len(EXEMPT))

    def test_감사_트리거는_새_모양이고_집행_역할_권한이_붙었다(self):
        self.assertEqual(self.one("SELECT prosecdef FROM pg_proc WHERE proname = 'audit_blocklist'")[0], True)
        self.assertIn("AFTER INSERT OR DELETE OR UPDATE OF released_at, expires_at, actor_ip, enforced_at",
                      self.one("SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname = 'trg_audit_blocklist'")[0])
        enforcer = self.roles["enforcer"]
        self.assertEqual(self.one("SELECT has_column_privilege(%s, 'blocklist', 'enforced_at', 'UPDATE'),"
                                  " has_column_privilege(%s, 'blocklist', 'released_at', 'UPDATE'),"
                                  " has_function_privilege(%s, 'note_block_expired(inet, timestamptz)', 'EXECUTE')",
                                  (enforcer, enforcer, enforcer)), (True, False, True))

    def test_기존_13행은_해제_만료_재차단_집행_표시가_막히지_않는다(self):
        # 집행기: 만료 없는 행 · 금지 대역 · 대역 주소는 집행 제외로 표시한다(감사 없음)
        with self.as_role("enforcer"):
            self.cur.execute("UPDATE blocklist SET enforce_note = '집행 제외 · 만료 없음' WHERE expires_at IS NULL"
                             " AND masklen(actor_ip) = 32 AND NOT EXISTS (SELECT 1 FROM block_exempt WHERE cidr >>= actor_ip)")
            self.assertEqual(self.cur.rowcount, len(LEGACY))
            self.cur.execute("UPDATE blocklist SET enforce_note = '집행 제외 · 금지 대역' WHERE actor_ip = '192.168.50.21'")
            self.cur.execute("UPDATE blocklist SET enforce_note = '집행 제외 · 대역 주소' WHERE actor_ip = '203.0.113.0/24'")
        self.assertEqual(self.audit(), [])
        # 콘솔: 기존 행에 다시 차단, 만료 부여, 해제. 살아 있는 차단의 만료는 줄이지 않으므로(app/main.py) 다시 걸어도
        #   만료 없는 행은 만료 없이 남는다(요청자만 바뀐다 · 감사 없음). 만료를 주는 것은 관리자의 단축(shortened)이다
        self.console_block(LEGACY[0])
        self.console_block(LEGACY[1], hours=1)
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET expires_at = now() + interval '30 day' WHERE actor_ip = %s", (LEGACY[2],))
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1'"
                             " WHERE actor_ip = ANY(%s::inet[]) OR actor_ip IN ('192.168.50.21', '203.0.113.0/24')",
                             (LEGACY[3:5],))
            self.assertEqual(self.cur.rowcount, 4)
            # 금지 대역 행에 콘솔이 다시 걸면 거부된다
            self.refused("blocklist_exempt", CONSOLE_BLOCK, ("192.168.50.21", "k", "admin1", 24))
        self.assertEqual(self.one("SELECT count(*) FROM blocklist WHERE requested_by = 'han' AND expires_at IS NULL")[0], 2)
        self.assertEqual(sorted(e for e, _, _ in self.audit()),
                         sorted(["console.block.shortened"] + ["console.block.released"] * 4))


if __name__ == "__main__":
    unittest.main()
