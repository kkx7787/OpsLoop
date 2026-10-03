#!/usr/bin/env python3
"""콘솔 계정 관리(이슈 #59) DB 시험.  python3 infra/test_console_accounts_db.py

DB 없이 도는 글자 시험: 마이그레이션(infra/migrations/20261001_console_accounts.sql)이 schema.sql 의 감사 조회 뷰 · 추가만 되는 행
보호 문장과 '콘솔 계정 관리 (이슈 #59)' 블록을 글자 그대로 담는지, 블록이 #52 블록 뒤에 있고 그 뒤에는 #63 블록만 오는지, 열 · 도장 · 함수 · 감사
트리거 · 권한 줄이 계약과 같은지(콘솔 역할에 계정 표 쓰기 권한을 늘리지 않는지, 감사 detail 에 해시가 없는지), verify-db-roles.sh 에
#59 절이 있고 기존 계정 줄(:38 · :39) · install-collector.sh 의 role 갱신 검사가 그대로인지, 복원 훈련의 구조 기대값 · 계정 지문이
새 열을 반영하는지 본다.

OPSLOOP_TEST_DATABASE_URL 이 슈퍼유저 연결이면 infra/test_block_enforce_db.py 와 같은 방식(무작위 데이터베이스 · 역할,
SET SESSION AUTHORIZATION)으로 schema.sql 과 마이그레이션을 두 번씩 적용하고, 콘솔 역할이 계정 표를 고치지 못하고 함수만 부르는지,
함수 결과(no_actor · self · not_found · cli_only · unchanged · ok), 변경 한 번에 감사 한 줄(by= · target= · 해시 없음) · 같은 값 0줄 ·
감사 행 변경 거부, 로그인 기록(last_login_at)으로 도장(updated_at)이 바뀌지 않는지, 역할 블록 · 옛 마이그레이션을 다시 적용한 뒤의
권한 · 감사 조건, 역할 검증 스크립트의 #59 절 · 기존 계정 줄 · install-collector.sh 검사가 같은 답을 내는지, 구조 수치가 복원 훈련
기대값과 같은지 본다. 기존 계정이 있는 옛 DB 에 마이그레이션을 올리는 경우도 따로 만든다.
역할은 시험 안에서 만들고 지운다. 운영 DB · 운영 역할은 건드리지 않는다. 비밀번호 해시는 형식만 흉내 낸 가짜 값이다.
"""
import importlib.util
import os
import re
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
NOTIFY = os.path.join(ROOT, "infra", "notify.sql")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20261001_console_accounts.sql")
ROLES_SQL = os.path.join(ROOT, "infra", "migrations", "20260924_db_roles.sql")
M23 = os.path.join(ROOT, "infra", "migrations", "20260923_console_ops.sql")
M24_NOTIFY = os.path.join(ROOT, "infra", "migrations", "20260924_notify.sql")
VERIFY = os.path.join(ROOT, "infra", "vmware", "scripts", "verify-db-roles.sh")
COLLECTOR = os.path.join(ROOT, "collector", "install-collector.sh")
OPERATIONS = os.path.join(ROOT, "app", "operations.py")
BLOCK47 = os.path.join(ROOT, "infra", "test_block_enforce_db.py")

HEADER = "-- 콘솔 계정 관리 (이슈 #59)"
HEADER52 = "-- 관제 대상 상태판 (이슈 #52)"
NEXT_HEADER = "-- 콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63)"      # 이 블록 뒤에 오는 다음 블록(infra/test_console_accounts_manage_db.py)
AUDIT_START = "-- 감사 기록 조회 (S-14)."
AUDIT_END = "EXECUTE FUNCTION audit_append_only();"
VERIFY_SECTION = 'echo "== 콘솔 계정 관리 (이슈 #59'
SIG = "console_account_set(text, text, boolean)"
FUNCS = ("audit_console_users", "console_account_set", "console_users_stamp")
RESULTS = ["no_actor", "self", "not_found", "cli_only", "unchanged", "ok"]
# 감사 이벤트와 detail 모양(계약 1절). 행위자는 audit_event 가 by= 로 앞에 붙인다. 해시 열은 어디에도 싣지 않는다
AUDIT_FORMATS = [
    ("console.account.deleted", "target=%s role=%s", "OLD.username, OLD.role"),
    ("console.account.created", "target=%s role=%s", "NEW.username, NEW.role"),
    ("console.account.role.changed", "target=%s from=%s to=%s", "NEW.username, OLD.role, NEW.role"),
    ("console.account.disabled", "target=%s", "NEW.username"),
    ("console.account.enabled", "target=%s", "NEW.username"),
    ("console.account.password.changed", "target=%s", "NEW.username"),
]
AUDIT_KINDS = ["console.block.%", "console.node.token.%", "console.notify.%", "console.account.%"]
GRANTS = ["GRANT EXECUTE ON FUNCTION console_account_set(text, text, boolean) TO opsloop_console;"]
VERIFY_LINES = [
    ("q", "opsloop_console", "UPDATE console_users SET disabled_at = now() WHERE false", "거부"),
    ("q", "opsloop_console", "UPDATE console_users SET updated_at = now() WHERE false", "거부"),
    ("q", "opsloop_console", "UPDATE console_users SET password_hash = password_hash WHERE false", "거부"),
    ("q", "opsloop_console", "DELETE FROM console_users WHERE false", "거부"),
    ("q", "opsloop_console", "UPDATE console_users SET last_login_at = last_login_at WHERE false", "허용"),
    ("q", "opsloop_console", "SELECT console_account_set(NULL, NULL, NULL)", "허용"),
    ("q", "opsloop_detector", "SELECT console_account_set(NULL, NULL, NULL)", "거부"),
    ("p", "opsloop_console", "has_function_privilege('opsloop_console', 'console_account_set(text, text, boolean)', 'EXECUTE')", "t"),
    ("p", "opsloop_detector", "has_function_privilege('opsloop_detector', 'console_account_set(text, text, boolean)', 'EXECUTE')", "f"),
    ("p", "opsloop_ingest", "has_function_privilege('opsloop_ingest', 'console_account_set(text, text, boolean)', 'EXECUTE')", "f"),
    ("p", "opsloop_console", "(SELECT prosecdef FROM pg_proc WHERE proname = 'console_account_set')", "t"),
    ("p", "opsloop_console", "(SELECT count(*) = 2 FROM pg_trigger WHERE tgname IN ('console_users_stamp', 'trg_audit_console_users')"
                             " AND tgenabled = 'O')", "t"),
    ("p", "opsloop_console", "(SELECT pg_get_viewdef('audit_log'::regclass) LIKE '%console.account.%')", "t"),
    ("p", "opsloop_console", "(SELECT pg_get_triggerdef(oid) LIKE '%console.account.%' FROM pg_trigger"
                             " WHERE tgname = 'trg_audit_append_only')", "t"),
]
# 기존 계정 줄(verify-db-roles.sh :38 · :39). 콘솔 역할에 계정 표 UPDATE · INSERT 권한을 늘리지 않으므로 그대로 거부다
OLD_LINES = [("q", "opsloop_console", "UPDATE console_users SET role='admin' WHERE false", "거부"),
             ("q", "opsloop_console", "INSERT INTO console_users SELECT * FROM console_users WHERE false", "거부")]
COLLECTOR_ROLE = "has_column_privilege('opsloop_console','console_users','role','UPDATE')"
FAKE_HASH = "pbkdf2_sha256$240000$c2FsdHNhbHQ=$ZmFrZWhhc2g="
FAKE_HASH2 = "pbkdf2_sha256$240000$bmV3c2FsdA==$bmV3aGFzaA=="
T0 = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)        # 만든 때 · 마지막 변경 (과거)
T1 = datetime(2026, 9, 20, 9, 30, tzinfo=timezone.utc)      # 마지막 로그인


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


QUERIES = load("drill_queries_59", os.path.join(ROOT, "infra", "vmware", "restore-drill", "queries.py"))
MOD = load("block47_for_59", BLOCK47)
# 감사 화면 대상 필터(app/operations.py /api/audit)가 detail 에서 대상을 뽑는 식. 앱을 불러오지 않고 글자에서 떼어 낸다
TARGET_RE = re.search(r"substring\(detail from '([^']+)'\) AS target", read(OPERATIONS)).group(1)


def audit_sql(text):
    """감사 조회 뷰(audit_log) · 추가만 되는 행 보호(audit_append_only · trg_audit_append_only) 문장. 머리 주석부터다."""
    start = text.index(AUDIT_START)
    return text[start:text.index(AUDIT_END, start) + len(AUDIT_END)]


def block59(text):
    """'콘솔 계정 관리 (이슈 #59)' 블록(머리 주석 · 열 · 도장 · 함수 · 감사 트리거 · 권한). 뒤에 #63 블록이 있으면 그 앞까지다."""
    start = text.index(HEADER + "\n")
    stop = text.find("\n" + NEXT_HEADER, start)
    region = text if stop < 0 else text[:stop]
    end = region.rindex("END\n$$;") + len("END\n$$;")
    return text[start:end]


def func(block, name):
    """CREATE OR REPLACE FUNCTION <name> 부터 본문 끝($$;)까지."""
    start = block.index(f"CREATE OR REPLACE FUNCTION {name}")
    return block[start:block.index("\n$$;", start) + len("\n$$;")]


def verify_lines59():
    """verify-db-roles.sh 의 #59 절(echo 머리부터 다음 echo 앞까지) q · p 줄."""
    text = read(VERIFY)
    sec = text[text.index(VERIFY_SECTION):]
    sec = sec[sec.index("\n"):].split("\necho", 1)[0]
    pat = re.compile(r'^([qp]) (opsloop_[a-z]+) +"(.+)" (허용|거부|t|f)$')
    return [m.groups() for m in map(pat.match, sec.splitlines()) if m]


def collector_check():
    """install-collector.sh 의 콘솔 권한 검사(마지막 값이 console_users.role 갱신) → (기대 [t|f …], SQL)."""
    m = re.search(r'check_priv "[^"]*console_users\.role 갱신" "([tf ]+)" \\\n\s*"(SELECT [^"]+)"', read(COLLECTOR))
    return m.group(1).split(), m.group(2)


class ConsoleAccountsTextTest(unittest.TestCase):
    """스키마 블록 · 마이그레이션 · 역할 검증 스크립트 · 복원 훈련 기대값의 글자 시험. DB 없이 돈다."""

    def test_마이그레이션은_스키마의_감사_조회_문장과_블록_그대로다(self):
        schema, mig = read(SCHEMA), read(MIGRATION)
        head, body = mig.split("\nBEGIN;\n", 1)
        self.assertTrue(all(ln.startswith("--") for ln in head.splitlines()))      # 머리는 주석뿐이다
        self.assertEqual(body.rstrip("\n"), audit_sql(schema) + "\n\n" + block59(schema) + "\nCOMMIT;")
        self.assertEqual(schema.count("CREATE OR REPLACE VIEW audit_log AS"), 1)      # 감사 조회 문장은 한 벌뿐이다(제자리 수정)
        self.assertEqual(schema.count("CREATE OR REPLACE TRIGGER trg_audit_append_only"), 1)

    def test_머리말은_적용_순서와_옛_마이그레이션_재적용을_적는다(self):
        head = read(MIGRATION).split("\nBEGIN;\n", 1)[0]
        self.assertIn("20260923_console_ops.sql · 20260924_notify.sql 을 다시 적용하면 이 파일도 다시 적용한다", head)
        self.assertIn("콘솔 새 이미지(요청마다 계정 상태를 읽는다)보다 먼저 적용하고", head)
        self.assertIn("< infra/migrations/20261001_console_accounts.sql", head)
        self.assertIn("infra/vmware/scripts/verify-db-roles.sh 의 '콘솔 계정 관리' 줄", head)

    def test_블록은_52_블록_뒤에_있고_그_뒤에는_63_블록만_온다(self):
        # 역할 블록이 표 권한을 먼저 거두므로 뒤에 둔다(이 블록은 함수 실행 권한만 주므로 역할 블록을 다시 적용해도 남는다)
        schema = read(SCHEMA)
        at = schema.index(HEADER + "\n")
        self.assertGreater(at, schema.index(HEADER52 + "\n"))
        self.assertGreater(at, schema.index("GRANT pg_read_all_data TO opsloop_backup"))
        rest = schema[at + len(block59(schema)):].strip("\n")
        self.assertTrue(rest.startswith(NEXT_HEADER), rest[:80])
        self.assertEqual(schema.count(HEADER + "\n"), 1)

    def test_감사_조회_뷰와_보호_트리거는_같은_네_갈래를_본다(self):
        audit = audit_sql(read(SCHEMA))
        start = audit.index("CREATE OR REPLACE VIEW audit_log")
        view = audit[start:audit.index(";\n", start)]
        trig = audit[audit.index("CREATE OR REPLACE TRIGGER trg_audit_append_only"):]
        # 한쪽만 고치면 보이지만 지울 수 있는 행(또는 지울 수 없지만 안 보이는 행)이 생긴다
        self.assertEqual(re.findall(r"(?<!OLD\.)\beventid LIKE '([^']+)'", view), AUDIT_KINDS)
        self.assertEqual(re.findall(r"OLD\.eventid LIKE '([^']+)'", trig), AUDIT_KINDS)
        self.assertNotIn("계정(console_users) 감사는 아직 두지 않는다", read(SCHEMA))

    def test_열_도장_함수_감사_트리거의_약속(self):
        blk = block59(read(SCHEMA))
        for col in ("disabled_at", "updated_at"):
            self.assertIn(f"ALTER TABLE console_users ADD COLUMN IF NOT EXISTS {col} timestamptz;", blk)
        self.assertIn("UPDATE console_users SET updated_at = created_at WHERE updated_at IS NULL;", blk)
        self.assertIn("CREATE OR REPLACE TRIGGER console_users_stamp\n"
                      "    BEFORE INSERT OR UPDATE OF role, disabled_at, password_hash ON console_users\n"
                      "    FOR EACH ROW EXECUTE FUNCTION console_users_stamp();", blk)
        self.assertIn("CREATE OR REPLACE TRIGGER trg_audit_console_users\n"
                      "    AFTER INSERT OR UPDATE OF role, disabled_at, password_hash OR DELETE ON console_users\n"
                      "    FOR EACH ROW EXECUTE FUNCTION audit_console_users();", blk)
        for name, definer in (("console_users_stamp()", False), ("console_account_set(", True), ("audit_console_users()", True)):
            with self.subTest(name):
                body = func(blk, name)
                self.assertIn("\nSET search_path = public, pg_temp\n", body)
                self.assertEqual("\nSECURITY DEFINER\n" in body, definer)
                self.assertNotRegex(body, r"\bEXECUTE\b")                          # 동적 SQL 이 없다
        for sig in ("console_users_stamp()", SIG, "audit_console_users()"):
            self.assertIn(f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC;", blk)
        setf = func(blk, "console_account_set(")
        self.assertIn("CREATE OR REPLACE FUNCTION console_account_set(p_username text, p_role text, p_active boolean)\n"
                      "RETURNS text\n", setf)
        self.assertEqual(re.findall(r"RETURN '(\w+)';", setf), RESULTS)                 # 계약의 차례대로 가른다
        self.assertIn("v_actor text := nullif(current_setting('opsloop.actor', true), '');", setf)
        self.assertIn("SELECT * INTO u FROM console_users WHERE username = p_username FOR UPDATE;", setf)
        self.assertIn("p_role NOT IN ('viewer', 'operator')", setf)
        aud = func(blk, "audit_console_users()")
        found = re.findall(r"audit_event\('(console\.account\.[a-z.]+)',\s*format\('([^']*)',\s*([^)]*)\)\)", aud)
        self.assertEqual(found, AUDIT_FORMATS)
        self.assertEqual(aud.count("audit_event("), len(AUDIT_FORMATS))

    def test_권한_줄은_콘솔의_함수_실행뿐이고_계정_표_쓰기를_늘리지_않는다(self):
        blk = block59(read(SCHEMA))
        self.assertEqual(MOD.grant_lines(blk), GRANTS)
        self.assertEqual(re.findall(r"rolname = '(\w+)'", blk), ["opsloop_console"])
        self.assertNotIn("REVOKE ALL ON ALL", blk)
        self.assertNotIn("CREATE ROLE", blk)
        # 콘솔의 계정 표 쓰기는 역할 블록의 로그인 기록 열뿐이다(verify-db-roles.sh :38 · :39 · install-collector.sh)
        writes = re.findall(r"GRANT (?:UPDATE|INSERT|DELETE|TRUNCATE|ALL)\b[^;]*\bconsole_users\b[^;]*;", read(SCHEMA))
        self.assertEqual([" ".join(w.split()) for w in writes], ["GRANT UPDATE (last_login_at) ON console_users TO opsloop_console;"])

    def test_역할_검증_스크립트에_59_절이_있고_기존_계정_검사는_그대로다(self):
        self.assertEqual(verify_lines59(), VERIFY_LINES)
        lines = MOD.verify_lines()
        for want in OLD_LINES:
            self.assertIn(want, lines)
        self.assertIn("infra/migrations/20261001_console_accounts.sql", read(VERIFY))
        want, sql = collector_check()
        self.assertEqual(want[-1], "f")
        self.assertTrue(" ".join(sql.split()).endswith(COLLECTOR_ROLE), sql)

    def test_복원_훈련은_새_트리거_함수를_세고_계정_지문에_비활성과_변경_시각을_넣는다(self):
        # 함수 18 = #59 뒤 15 + #63 의 계정 추가 · 삭제 · 비밀번호 함수 셋(infra/test_console_accounts_manage_db.py),
        # #77 이 트리거 +1 · 함수 +1(infra/test_block_points_choice_db.py)
        self.assertEqual(QUERIES.EXPECT, {"tables": 27, "fk": 15, "triggers": 10, "functions": 20, "views": 3})
        [fp] = [f for f in QUERIES.FINGERPRINTS if f[0] == "console_users"]
        self.assertEqual(fp[1:], ("username", "ROW(username, role, created_at, disabled_at, md5(password_hash))",
                                  "greatest(created_at, updated_at)", "console_users", ""))
        self.assertNotIn("last_login_at", fp[2])                   # 로그인마다 바뀌는 열은 뺀다
        QUERIES.assert_read_only(QUERIES.q_fingerprint())


class AccountsCase(MOD.DbCase):
    """계정 시험 도우미. 시험마다 한 트랜잭션이고 끝나면 되돌린다."""

    def seed(self):
        """관리자 둘 · 관제사 · 조회자 · 비활성 관제사. 만든 때 · 마지막 변경은 과거로 둔다(도장이 찍히는지 보려고).
        updated_at 만 고치는 문장은 도장 · 감사 트리거의 열 목록 밖이라 돌지 않는다."""
        self.cur.execute("INSERT INTO console_users (username, password_hash, role, disabled_at) VALUES"
                         " ('root', %(h)s, 'admin', NULL), ('root2', %(h)s, 'admin', NULL), ('op1', %(h)s, 'operator', NULL),"
                         " ('vw1', %(h)s, 'viewer', NULL), ('gone', %(h)s, 'operator', %(t)s)", {"h": FAKE_HASH, "t": T0})
        self.cur.execute("UPDATE console_users SET created_at = %s, updated_at = %s, last_login_at = %s", (T0, T0, T1))
        self.mark = self.one("SELECT clock_timestamp()")[0]

    def audit(self):
        """seed 뒤에 남은 계정 감사 (eventid, username, input). 남은 차례대로."""
        return self.q("SELECT eventid, username, input FROM events WHERE sensor = 'audit'"
                      " AND eventid LIKE 'console.account.%%' AND ts > %s ORDER BY ts", (self.mark,))

    def users(self):
        """(아이디, 역할, 활성, 이 트랜잭션에서 도장이 찍혔나). 도장은 clock_timestamp() 라 트랜잭션 시작(now()) 이후다."""
        return self.q("SELECT username, role, disabled_at IS NULL, updated_at >= now() FROM console_users ORDER BY username")

    def set(self, username, role=None, active=None, actor="root", key="console"):
        """콘솔처럼 행위자를 넘기고 함수를 부른다(app/accounts.py)."""
        with self.as_role(key, actor):
            return self.one("SELECT console_account_set(%s, %s, %s)", (username, role, active))[0]

    def apply(self, path):
        self.cur.execute(self.sub(read(path).replace("BEGIN;", "").replace("COMMIT;", "")))

    @staticmethod
    def acl(expr):
        """ACL 을 '역할:권한' 정렬 배열로. 거두고 다시 주면 항목 차례가 바뀌어도 같다."""
        return (f"(SELECT array_agg(g ORDER BY g) FROM (SELECT a.grantee::regrole::text || ':' || a.privilege_type AS g"
                f" FROM aclexplode({expr}) a) s)")


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class ConsoleAccountsDatabaseTest(AccountsCase):
    """schema.sql 전체(+ infra/notify.sql)와 마이그레이션을 두 번씩 적용한 새 데이터베이스. 역할은 모두 있다."""

    @classmethod
    def setUpClass(cls):
        cls.create()
        for text in (read(SCHEMA), read(SCHEMA), read(MIGRATION), read(MIGRATION), read(NOTIFY)):
            cls.scur.execute(cls.sub(text))
        cls.connect()

    def catalog(self):
        """다시 적용해도 같아야 하는 것: 계정 표 열 · 기본값 · 열 권한, 트리거, 함수 본문 · 권한, 감사 뷰, 표 권한, 행, 이벤트 수."""
        return {
            "cols": self.q("SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, pg_get_expr(d.adbin, d.adrelid),"
                           f" {self.acl('a.attacl')} FROM pg_attribute a"
                           " LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum"
                           " WHERE a.attrelid = 'console_users'::regclass AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum"),
            "triggers": self.q("SELECT tgname, tgenabled, pg_get_triggerdef(oid) FROM pg_trigger"
                               " WHERE tgrelid IN ('console_users'::regclass, 'events'::regclass) AND NOT tgisinternal ORDER BY tgname"),
            "functions": self.q(f"SELECT proname, prosecdef, proconfig, md5(prosrc), {self.acl('proacl')} FROM pg_proc"
                                " WHERE proname IN ('console_users_stamp', 'console_account_set', 'audit_console_users',"
                                " 'audit_event', 'audit_append_only') ORDER BY proname"),
            "view": self.one("SELECT pg_get_viewdef('audit_log'::regclass)"),
            "tables": self.q(f"SELECT relname, {self.acl('relacl')} FROM pg_class"
                             " WHERE relname IN ('console_users', 'events', 'audit_log') ORDER BY relname"),
            "rows": self.q("SELECT username, role, created_at, disabled_at, updated_at, last_login_at FROM console_users"
                           " ORDER BY username"),
            "events": self.one("SELECT count(*) FROM events"),
        }

    # ── 함수 ──

    def test_함수_결과는_계약의_일곱_경우다(self):
        self.seed()
        before = self.users()
        cases = [("행위자 없음", ("op1", "viewer", None, None), "no_actor"),
                 ("행위자 자신", ("root", "viewer", None, "root"), "self"),
                 ("행위자 자신 (관리자 아닌 이름)", ("op1", None, False, "op1"), "self"),
                 ("없는 계정", ("ghost", "viewer", None, "root"), "not_found"),
                 ("아이디 없음", (None, None, False, "root"), "not_found"),
                 ("관리자 대상 역할", ("root2", "operator", None, "root"), "cli_only"),
                 ("관리자 대상 비활성", ("root2", None, False, "root"), "cli_only"),
                 ("관리자로 올리기", ("op1", "admin", None, "root"), "cli_only"),
                 ("모르는 역할", ("op1", "superuser", None, "root"), "cli_only"),
                 ("같은 역할", ("op1", "operator", None, "root"), "unchanged"),
                 ("이미 활성", ("op1", None, True, "root"), "unchanged"),
                 ("이미 비활성", ("gone", None, False, "root"), "unchanged"),
                 ("바꿀 것 없음", ("vw1", None, None, "root"), "unchanged")]
        for name, (u, role, active, actor), want in cases:
            with self.subTest(name):
                self.assertEqual(self.set(u, role, active, actor), want)
        with self.as_role("console"):
            self.cur.execute("SELECT set_config('opsloop.actor', '', true)")          # 끝난 연결의 빈 값도 없음이다
            self.assertEqual(self.one("SELECT console_account_set('op1', 'viewer', NULL)")[0], "no_actor")
        self.assertEqual(self.users(), before)                    # 거부 · 변경 없음은 행도 도장도 그대로다
        self.assertEqual(self.audit(), [])
        # 적용: 관제사 ↔ 조회자, 비활성 · 재활성. 바뀐 행만 도장이 찍힌다
        self.assertEqual(self.set("op1", "viewer"), "ok")
        self.assertEqual(self.set("vw1", "operator"), "ok")
        self.assertEqual(self.set("op1", None, False), "ok")
        self.assertEqual(self.set("gone", None, True), "ok")
        self.assertEqual(self.users(), [("gone", "operator", True, True), ("op1", "viewer", False, True),
                                        ("root", "admin", True, False), ("root2", "admin", True, False),
                                        ("vw1", "operator", True, True)])
        self.assertEqual(self.audit(), [
            ("console.account.role.changed", "root", "by=root target=op1 from=operator to=viewer"),
            ("console.account.role.changed", "root", "by=root target=vw1 from=viewer to=operator"),
            ("console.account.disabled", "root", "by=root target=op1"),
            ("console.account.enabled", "root", "by=root target=gone")])

    def test_역할과_활성을_한_번에_바꾸면_두_줄이_남는다(self):
        self.seed()
        self.assertEqual(self.set("op1", "viewer", False), "ok")
        self.assertEqual(self.users()[1], ("op1", "viewer", False, True))
        self.assertEqual([e for e, _, _ in self.audit()], ["console.account.role.changed", "console.account.disabled"])

    def test_비활성_계정도_역할은_바꾸고_활성은_그대로다(self):
        self.seed()
        self.assertEqual(self.set("gone", "viewer"), "ok")
        self.assertEqual(self.users()[0], ("gone", "viewer", False, True))

    # ── 감사 · 도장 ──

    def test_명령줄_변경마다_감사_한_줄이고_해시는_싣지_않는다(self):
        # 명령줄(auth.py)은 소유자로 붙어 행위자 cli:<이름> 을 건 뒤 표를 직접 고친다
        self.seed()
        self.cur.execute("SELECT set_config('opsloop.actor', 'cli:han', true)")
        self.cur.execute("INSERT INTO console_users (username, password_hash, role) VALUES ('newbie', %s, 'operator')", (FAKE_HASH,))
        self.cur.execute("UPDATE console_users SET password_hash = %s WHERE username = 'newbie'", (FAKE_HASH2,))
        self.cur.execute("UPDATE console_users SET role = 'admin' WHERE username = 'newbie'")
        self.cur.execute("UPDATE console_users SET disabled_at = now() WHERE username = 'newbie'")
        self.cur.execute("UPDATE console_users SET disabled_at = NULL WHERE username = 'newbie'")
        self.cur.execute("DELETE FROM console_users WHERE username = 'newbie'")
        # 옛 add(ON CONFLICT DO UPDATE 로 비밀번호 · 역할을 덮는다)도 바뀐 것만 남는다
        self.cur.execute("INSERT INTO console_users (username, password_hash, role) VALUES ('op1', %s, 'operator')"
                         " ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role",
                         (FAKE_HASH2,))
        self.assertEqual(self.audit(), [
            ("console.account.created", "cli:han", "by=cli:han target=newbie role=operator"),
            ("console.account.password.changed", "cli:han", "by=cli:han target=newbie"),
            ("console.account.role.changed", "cli:han", "by=cli:han target=newbie from=operator to=admin"),
            ("console.account.disabled", "cli:han", "by=cli:han target=newbie"),
            ("console.account.enabled", "cli:han", "by=cli:han target=newbie"),
            ("console.account.deleted", "cli:han", "by=cli:han target=newbie role=admin"),
            ("console.account.password.changed", "cli:han", "by=cli:han target=op1")])
        text = " ".join(" ".join(r) for r in self.q("SELECT eventid, coalesce(username, ''), coalesce(input, '')"
                                                     " FROM events WHERE sensor = 'audit' AND ts > %s", (self.mark,)))
        for secret in (FAKE_HASH, FAKE_HASH2, "pbkdf2", "c2FsdHNhbHQ", "ZmFrZWhhc2g", "bmV3aGFzaA"):
            self.assertNotIn(secret, text)
        # 행위자를 넘기지 않은 psql 직접 변경은 db:<DB 역할> 이다
        self.cur.execute("SELECT set_config('opsloop.actor', '', true)")
        self.cur.execute("UPDATE console_users SET role = 'viewer' WHERE username = 'vw1'")      # 같은 값: 남지 않는다
        self.cur.execute("UPDATE console_users SET role = 'viewer' WHERE username = 'op1'")
        su = self.one("SELECT session_user")[0]
        self.assertEqual(self.audit()[7:], [("console.account.role.changed", f"db:{su}",
                                             f"by=db:{su} target=op1 from=operator to=viewer")])

    def test_같은_값으로_고치면_감사도_도장도_없다(self):
        self.seed()
        self.cur.execute("SELECT set_config('opsloop.actor', 'cli:han', true)")
        self.cur.execute("UPDATE console_users SET role = role, disabled_at = disabled_at, password_hash = password_hash")
        self.assertEqual(self.cur.rowcount, 5)
        self.assertEqual(self.audit(), [])
        self.assertEqual(self.one("SELECT count(*) FROM console_users WHERE updated_at <> %s", (T0,))[0], 0)

    def test_도장은_넣을_때와_역할_활성_비밀번호가_바뀔_때만_찍힌다(self):
        self.seed()
        # 넣을 때는 준 값과 상관없이 지금이다(손 입력으로 옛 시각을 넣어 옛 쿠키를 살리지 못한다)
        self.cur.execute("INSERT INTO console_users (username, password_hash, updated_at) VALUES ('fresh', %s, %s)", (FAKE_HASH, T0))
        stamped = lambda u: self.one("SELECT updated_at >= now() FROM console_users WHERE username = %s", (u,))[0]  # noqa: E731
        self.assertTrue(stamped("fresh"))
        for user, change in (("op1", "role = 'viewer'"), ("vw1", "disabled_at = now()"), ("gone", "disabled_at = NULL"),
                             ("root2", "password_hash = 'x'")):
            with self.subTest(user=user, change=change):
                self.assertFalse(stamped(user))
                self.cur.execute(f"UPDATE console_users SET {change} WHERE username = %s", (user,))
                self.assertTrue(stamped(user))
        self.assertFalse(stamped("root"))
        # 도장은 트랜잭션 시작이 아니라 행을 고치는 때다. 변경 트랜잭션이 시작된 뒤 · 행을 고치기 전에 다른 연결에서 로그인한 쿠키
        # (발급 시각 = 그 로그인 문장의 now())도 무효가 되어야 한다. 그 발급 시각을 이 트랜잭션 안의 clock_timestamp() 로 흉내 낸다
        self.cur.execute("SELECT pg_sleep(0.01)")
        issued = self.one("SELECT clock_timestamp()")[0]
        self.cur.execute("UPDATE console_users SET password_hash = 'y' WHERE username = 'root'")
        self.assertGreater(self.one("SELECT updated_at FROM console_users WHERE username = 'root'")[0], issued)

    def test_로그인_기록은_도장을_찍지_않고_감사도_남기지_않는다(self):
        self.seed()
        with self.as_role("console"):
            # 로그인 성공 문장 꼴(app/auth.py authenticate). 돌려준 DB 시각이 쿠키의 발급 시각이 된다
            self.cur.execute("UPDATE console_users SET last_login_at = now() WHERE username = 'op1' AND disabled_at IS NULL"
                             " RETURNING extract(epoch FROM now())")
            self.assertEqual(self.cur.rowcount, 1)
        self.assertEqual(self.one("SELECT updated_at, last_login_at = now() FROM console_users WHERE username = 'op1'"), (T0, True))
        self.assertEqual(self.audit(), [])

    def test_감사_행은_감사_화면에_보이고_대상_필터가_잡으며_고칠_수_없다(self):
        self.seed()
        self.set("op1", "viewer")
        self.set("vw1", None, False)
        with self.as_role("console"):
            rows = self.q("SELECT eventid, actor, substring(detail from %s) FROM audit_log"
                          " WHERE eventid LIKE 'console.account.%%' AND ts > %s ORDER BY ts", (TARGET_RE, self.mark))
        self.assertEqual(rows, [("console.account.role.changed", "root", "op1"), ("console.account.disabled", "root", "vw1")])
        for sql in ("UPDATE events SET input = 'x' WHERE eventid LIKE 'console.account.%%' AND ts > %s",
                    "DELETE FROM events WHERE eventid LIKE 'console.account.%%' AND ts > %s"):
            with self.subTest(sql=sql):
                e = self.fails(sql, (self.mark,))                    # 소유자(슈퍼유저)도 트리거가 막는다
                self.assertIn("감사 이벤트는 고치거나 지울 수 없다", str(e))
        with self.as_role("console"):
            self.denied("UPDATE events SET input = 'x' WHERE eventid LIKE 'console.account.%'")
            self.denied("DELETE FROM events WHERE eventid LIKE 'console.account.%'")
        self.assertEqual(len(self.audit()), 2)

    # ── 권한 ──

    def test_콘솔_역할은_계정_표를_고치지_못하고_함수만_부른다(self):
        self.seed()
        with self.as_role("console", "root"):
            for sql in ("UPDATE console_users SET disabled_at = now() WHERE username = 'op1'",
                        "UPDATE console_users SET role = 'admin' WHERE username = 'op1'",
                        "UPDATE console_users SET password_hash = 'x' WHERE username = 'op1'",
                        "UPDATE console_users SET updated_at = now() WHERE username = 'op1'",
                        "INSERT INTO console_users (username, password_hash, role) VALUES ('evil', 'x', 'admin')",
                        "DELETE FROM console_users WHERE username = 'op1'",
                        "TRUNCATE console_users",
                        "ALTER TABLE console_users DISABLE TRIGGER trg_audit_console_users",
                        "SELECT audit_console_users()",
                        "SELECT console_users_stamp()"):
                with self.subTest(sql=sql):
                    self.denied(sql)
            self.assertEqual(self.one("SELECT console_account_set('op1', 'viewer', NULL)")[0], "ok")
        for key in ("detector", "ingest", "enforcer", "gate", "cti", "backup"):
            with self.subTest(role=key), self.as_role(key, "root"):
                self.denied("SELECT console_account_set('vw1', 'operator', NULL)")
        self.assertEqual([r[:2] for r in self.users()][1:], [("op1", "viewer"), ("root", "admin"), ("root2", "admin"),
                                                              ("vw1", "viewer")])
        self.assertEqual([e for e, _, _ in self.audit()], ["console.account.role.changed"])

    def test_권한은_계약과_같다(self):
        for key in MOD.ROLE_KEYS:
            with self.subTest(role=key):
                self.assertEqual(self.one("SELECT has_function_privilege(%s, %s, 'EXECUTE')", (self.roles[key], SIG))[0],
                                 key == "console")
                self.assertFalse(self.one("SELECT has_function_privilege(%s, 'audit_console_users()', 'EXECUTE')"
                                          " OR has_function_privilege(%s, 'console_users_stamp()', 'EXECUTE')",
                                          (self.roles[key], self.roles[key]))[0])
        for sig in (SIG, "audit_console_users()", "console_users_stamp()"):
            self.assertFalse(self.one("SELECT has_function_privilege('public', %s, 'EXECUTE')", (sig,))[0], sig)
        self.assertEqual(self.q("SELECT proname, prosecdef, proconfig FROM pg_proc WHERE proname = ANY(%s) ORDER BY proname",
                                (list(FUNCS),)),
                         [("audit_console_users", True, ["search_path=public, pg_temp"]),
                          ("console_account_set", True, ["search_path=public, pg_temp"]),
                          ("console_users_stamp", False, ["search_path=public, pg_temp"])])
        # 콘솔의 계정 표 권한: 표 전체 읽기(로그인), 쓰기는 로그인 기록 열뿐이다
        console = self.roles["console"]
        cols = [c for (c,) in self.q("SELECT attname FROM pg_attribute WHERE attrelid = 'console_users'::regclass"
                                     " AND attnum > 0 AND NOT attisdropped ORDER BY attnum")]
        self.assertEqual(cols, ["username", "password_hash", "role", "created_at", "last_login_at", "disabled_at", "updated_at"])
        self.assertEqual([c for c in cols if self.one("SELECT has_column_privilege(%s, 'console_users', %s, 'UPDATE')",
                                                      (console, c))[0]], ["last_login_at"])
        self.assertEqual(self.one("SELECT has_table_privilege(%(r)s, 'console_users', 'SELECT'),"
                                  " has_table_privilege(%(r)s, 'console_users', 'UPDATE'),"
                                  " has_table_privilege(%(r)s, 'console_users', 'INSERT'),"
                                  " has_table_privilege(%(r)s, 'console_users', 'DELETE'),"
                                  " has_table_privilege(%(r)s, 'console_users', 'TRUNCATE')", {"r": console}),
                         (True, False, False, False, False))
        for key in ("detector", "ingest", "enforcer", "gate", "cti"):
            with self.subTest(role=key):
                self.assertFalse(self.one("SELECT has_any_column_privilege(%s, 'console_users', 'UPDATE')",
                                          (self.roles[key],))[0])

    def test_열과_트리거는_계약과_같다(self):
        self.assertEqual(self.q("SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, pg_get_expr(d.adbin, d.adrelid)"
                                " FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum"
                                " WHERE a.attrelid = 'console_users'::regclass AND a.attname IN ('disabled_at', 'updated_at')"
                                " ORDER BY a.attnum"),
                         [("disabled_at", "timestamp with time zone", False, None),
                          ("updated_at", "timestamp with time zone", True, "now()")])
        trg = dict(self.q("SELECT tgname, pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid = 'console_users'::regclass"
                          " AND NOT tgisinternal"))
        self.assertEqual(sorted(trg), ["console_users_stamp", "trg_audit_console_users"])
        self.assertIn("BEFORE INSERT OR UPDATE OF role, disabled_at, password_hash ON public.console_users FOR EACH ROW",
                      trg["console_users_stamp"])
        self.assertIn("AFTER INSERT OR DELETE OR UPDATE OF role, disabled_at, password_hash ON public.console_users FOR EACH ROW",
                      trg["trg_audit_console_users"])

    # ── 다시 적용 ──

    def test_두_번_적용해도_같다(self):
        self.seed()
        before = self.catalog()
        self.cur.execute(self.sub(read(SCHEMA)))
        self.apply(MIGRATION)
        self.assertEqual(self.catalog(), before)
        self.assertEqual(self.audit(), [])

    def test_역할_블록을_다시_적용해도_함수_실행_권한은_남는다(self):
        self.seed()
        self.apply(ROLES_SQL)
        console = self.roles["console"]
        self.assertEqual(self.one("SELECT has_function_privilege(%s, %s, 'EXECUTE'), has_column_privilege(%s, 'console_users',"
                                  " 'last_login_at', 'UPDATE'), has_column_privilege(%s, 'console_users', 'role', 'UPDATE')",
                                  (console, SIG, console, console)), (True, True, False))
        self.assertEqual(self.set("op1", "viewer"), "ok")

    def test_옛_마이그레이션을_다시_적용하면_계정_감사가_빠지고_이_파일로_되살아난다(self):
        view = "SELECT pg_get_viewdef('audit_log'::regclass) LIKE '%console.account.%'"
        trig = "SELECT pg_get_triggerdef(oid) LIKE '%console.account.%' FROM pg_trigger WHERE tgname = 'trg_audit_append_only'"
        for path in (M23, M24_NOTIFY):
            with self.subTest(path=os.path.basename(path)):
                self.apply(path)
                self.assertEqual((self.one(view)[0], self.one(trig)[0]), (False, False))
                self.apply(MIGRATION)
                self.assertEqual((self.one(view)[0], self.one(trig)[0]), (True, True))

    # ── 역할 검증 스크립트 · 설치기 검사 · 복원 훈련 ──

    def test_역할_검증_스크립트_줄이_시험_DB_에서_같은_답을_낸다(self):
        self.seed()
        lines = verify_lines59() + OLD_LINES
        self.assertEqual(len(lines), len(VERIFY_LINES) + len(OLD_LINES))
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
                        if stmt.startswith("SELECT console_account_set"):
                            self.assertEqual(self.cur.fetchone(), ("no_actor",))      # 행위자가 없어 아무것도 바꾸지 않는다
                    except MOD.psycopg2.Error as e:
                        got = "거부" if e.pgcode == "42501" else f"오류({e.pgcode} {e})"
                    self.cur.execute("ROLLBACK TO SAVEPOINT v")
                    self.cur.execute("RESET SESSION AUTHORIZATION")
                self.assertEqual(got, want)
        self.assertEqual(self.audit(), [])

    def test_설치기의_콘솔_권한_검사가_그대로_기대대로다(self):
        want, sql = collector_check()
        self.assertEqual(["t" if v else "f" for v in self.one(self.sub(sql))], want)

    def test_구조_수치는_복원_훈련_기대값과_같다(self):
        # 복원 훈련이 운영 카탈로그를 세는 문장 그대로(infra/notify.sql 의 알림 트리거 · 함수를 더한 운영 모양)
        cat = {}
        for stmt in QUERIES.Q_CATALOG.split(";\n"):
            _tag, name, value = self.one(stmt)[0].split("|", 2)
            cat[name] = value
        got = {"tables": int(cat["tables"]), "fk": int(cat["fk"]),
               "triggers": len([x for x in cat["triggers"].split(",") if x]),
               "functions": len([x for x in cat["functions"].split(",") if x]),
               "views": len([x for x in cat["views"].split(",") if x])}
        self.assertEqual(got, QUERIES.EXPECT)
        for name in ("console_users_stamp=O", "trg_audit_console_users=O"):
            self.assertIn(name, cat["triggers"].split(","))
        for name in FUNCS:
            self.assertIn(name, cat["functions"].split(","))

    def test_계정_지문은_변경을_잡고_시각은_마지막_변경이다(self):
        self.seed()
        [fp] = [f for f in QUERIES.FINGERPRINTS if f[0] == "console_users"]
        sql = f"SELECT md5(({fp[2]})::text), ({fp[3]})::timestamptz FROM console_users WHERE username = 'op1'"
        md, ts = self.one(sql)
        self.assertEqual(ts, T0)
        with self.as_role("console"):
            self.cur.execute("UPDATE console_users SET last_login_at = now() WHERE username = 'op1'")
        self.assertEqual(self.one(sql), (md, T0))                # 로그인은 지문도 시각도 바꾸지 않는다
        self.set("op1", None, False)
        md2, ts2 = self.one(sql)
        self.assertNotEqual(md2, md)
        self.assertGreaterEqual(ts2, self.one("SELECT now()")[0])


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class ConsoleAccountsMigrationTest(AccountsCase):
    """마이그레이션 전 DB(계정 열 · 도장 · 함수 · 감사 트리거 없음, 감사 조건 셋)에 기존 계정 셋을 두고 마이그레이션을 두 번 올린다."""

    @classmethod
    def old_schema(cls):
        """schema.sql 에서 이번 블록(과 그 뒤의 #63 블록)을 빼고 감사 조회 뷰 · 보호 트리거를 옛 모양(계정 조건 없음)으로 되돌린다."""
        text = read(SCHEMA)
        text = text[:text.index(HEADER + "\n")]
        audit = audit_sql(text)
        old = audit.replace(" OR eventid LIKE 'console.account.%'", "").replace(" OR OLD.eventid LIKE 'console.account.%'", "")
        assert "console.account" not in old and old != audit
        return text.replace(audit, old)

    @classmethod
    def setUpClass(cls):
        cls.create()
        cls.scur.execute(cls.sub(cls.old_schema()))
        cls.scur.execute("INSERT INTO console_users (username, password_hash, role, created_at, last_login_at) VALUES"
                         " ('root', %(h)s, 'admin', %(t0)s, %(t1)s), ('op1', %(h)s, 'operator', %(t0)s, NULL),"
                         " ('vw1', %(h)s, 'viewer', %(t1)s, %(t1)s)", {"h": FAKE_HASH, "t0": T0, "t1": T1})
        cls.scur.execute("SELECT count(*) FROM events")
        cls.events_before = cls.scur.fetchone()[0]
        for _ in range(2):
            cls.scur.execute(cls.sub(read(MIGRATION)))
        cls.connect()

    def test_기존_계정은_활성이고_변경_시각은_만든_때이며_감사는_남지_않는다(self):
        # 적용만으로 열린 세션을 끊지 않는다(쿠키 발급 시각은 만든 때보다 늦다)
        self.assertEqual(self.q("SELECT username, role, disabled_at, updated_at, last_login_at FROM console_users ORDER BY username"),
                         [("op1", "operator", None, T0, None), ("root", "admin", None, T0, T1), ("vw1", "viewer", None, T1, T1)])
        self.assertEqual(self.one("SELECT count(*) FROM events")[0], self.events_before)

    def test_마이그레이션_뒤_콘솔은_함수로_바꾸고_감사가_보인다(self):
        self.mark = self.one("SELECT clock_timestamp()")[0]
        self.assertEqual(self.set("op1", "viewer"), "ok")
        with self.as_role("console"):
            self.assertEqual(self.q("SELECT eventid, actor, detail FROM audit_log WHERE ts > %s", (self.mark,)),
                             [("console.account.role.changed", "root", "by=root target=op1 from=operator to=viewer")])
        self.assertTrue(self.one("SELECT has_function_privilege(%s, %s, 'EXECUTE')", (self.roles["console"], SIG))[0])


if __name__ == "__main__":
    unittest.main(verbosity=1)
