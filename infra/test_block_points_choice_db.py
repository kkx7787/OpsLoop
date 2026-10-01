#!/usr/bin/env python3
"""차단 적용 지점 선택(이슈 #77) DB 시험.  python3 infra/test_block_points_choice_db.py

DB 없이 도는 글자 시험: 마이그레이션(infra/migrations/20261003_block_points_choice.sql)이 schema.sql 의 '차단 적용 지점 선택
(이슈 #77)' 블록을 글자 그대로 담는지(lock_timeout 한 줄과 머리 주석의 관문 이름 한 줄(이슈 #78)만 다르다), 블록이 #63 블록 뒤 파일 끝에
있는지, 값 제약이 두 값뿐인지, 블록에 표 · 열 권한이 없는지(함수 PUBLIC 실행 회수 한 줄뿐), 감사 함수(audit_blocklist)가 한 벌 ·
20260927 과 같은 글자이고 points= 자리가 계약대로인지, verify-db-roles.sh 의 #77 절, 복원 훈련 기대값 · 지문을 본다.

OPSLOOP_TEST_DATABASE_URL 이 슈퍼유저 연결이면 infra/test_block_enforce_db.py 와 같은 방식(무작위 데이터베이스 · 역할,
SET SESSION AUTHORIZATION)으로 schema.sql 과 마이그레이션을 두 번씩 적용하고, 열을 모르는 옛 문장의 기본값, 값 제약, 살아 있는 행
좁히기 거부 · 넓히기 감사, 해제 · 만료 행 다시 걸기, 역할마다의 권한, 역할 블록 · 20260927 · 20260929 · 20260930 을 다시 적용한 뒤,
역할 검증 스크립트 #77 절, 복원 훈련 구조 수치 · 지문을 실제로 돌린다. #77 전 DB(기존 차단 · 약속이 있다)에 마이그레이션을 올리는
경우도 따로 만든다(잠금을 얻지 못하면 아무것도 바꾸지 않고 실패하는 것, 다시 적용은 읽는 트랜잭션을 기다리지 않는 것 포함).
운영 DB · 운영 역할은 건드리지 않는다.
"""
import importlib.util
import os
import re
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
NOTIFY = os.path.join(ROOT, "infra", "notify.sql")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20261003_block_points_choice.sql")
REAPPLY = [os.path.join(ROOT, "infra", "migrations", f) for f in
           ("20260924_db_roles.sql", "20260927_block_enforce.sql", "20260929_block_points.sql", "20260930_status_board.sql")]
M27 = REAPPLY[1]
VERIFY = os.path.join(ROOT, "infra", "vmware", "scripts", "verify-db-roles.sh")
BLOCK47 = os.path.join(ROOT, "infra", "test_block_enforce_db.py")
QUERIES_PY = os.path.join(ROOT, "infra", "vmware", "restore-drill", "queries.py")

HEADER = "-- 차단 적용 지점 선택 (이슈 #77)"
HEADER63 = "-- 콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63)"
BLOCK_END = "FOR EACH ROW EXECUTE FUNCTION blocklist_points_change();"
LOCK = "SET LOCAL lock_timeout = '5s';"
# 머리 주석 가운데 관문 이름만 바꾼 한 줄(이슈 #78). 적용된 마이그레이션은 옛 글자 그대로다
NAME_OLD = "--   차단 요청마다 적용 지점을 고른다. 내부 방화벽은 늘 막고 AWS 관문은 고른 요청만 막는다(관문 전용은 없다)."
NAME_NEW = "--   차단 요청마다 적용 지점을 고른다. 내부 방화벽은 늘 막고 허니팟 관문은 고른 요청만 막는다(관문 전용은 없다)."
CHECK = "CHECK (points IN ('{gateway,fw}'::text[], '{fw}'::text[]))"
TWO, FW = ["gateway", "fw"], ["fw"]
BAD = ["{}", "{gateway}", "{fw,gateway}", "{fw,fw}", "{x}"]
VERIFY_SECTION = 'echo "== 차단 적용 지점 (이슈 #77'
VERIFY_LINES = [
    ("q", "opsloop_enforcer", "SELECT actor_ip, points FROM blocklist LIMIT 0", "허용"),
    ("q", "opsloop_enforcer", "UPDATE blocklist SET points = points WHERE false", "거부"),
    ("p", "opsloop_enforcer", "has_column_privilege('opsloop_enforcer', 'blocklist', 'points', 'UPDATE')", "f"),
    ("q", "opsloop_console", "INSERT INTO blocklist (actor_ip, points) SELECT actor_ip, points FROM blocklist WHERE false", "허용"),
    ("q", "opsloop_console", "UPDATE blocklist SET points = '{gateway,fw}' WHERE false", "허용"),
    ("q", "opsloop_console", "UPDATE absorbed_blocks SET points = '{gateway,fw}' WHERE false", "허용"),
    ("q", "opsloop_detector", "SELECT points FROM blocklist LIMIT 0", "거부"),
    ("p", "opsloop_console", "has_function_privilege('opsloop_console', 'blocklist_points_change()', 'EXECUTE')", "f"),
    ("p", "opsloop_console", "(SELECT prosecdef AND prosrc LIKE '%blocklist_points_narrow%' FROM pg_proc"
                             " WHERE proname = 'blocklist_points_change')", "t"),
    ("p", "opsloop_console", "(SELECT tgenabled = 'O' FROM pg_trigger WHERE tgname = 'trg_blocklist_points')", "t"),
    ("p", "opsloop_console", "(SELECT count(*) = 2 FROM pg_constraint"
                             " WHERE conname IN ('blocklist_points_valid', 'absorbed_blocks_points_valid'))", "t"),
]
# 반영 계약 6장의 찾기 · 넓히기 SQL (운영자가 psql 로 돌린다)
FIND_SQL = ("SELECT host(b.actor_ip), b.incident_key, i.rule_id, b.created_at FROM blocklist b LEFT JOIN incidents i USING (incident_key)"
            " WHERE b.points = '{fw}' AND b.released_at IS NULL AND b.expires_at > now() AND b.created_at > %s ORDER BY b.created_at")
WIDEN_SQL = ("UPDATE blocklist SET points='{gateway,fw}' WHERE points='{fw}' AND released_at IS NULL AND expires_at > now()"
             " RETURNING host(actor_ip)")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load("block47_for_77", BLOCK47)
QUERIES = load("restore_queries_for_77", QUERIES_PY)


def block77(text):
    """'차단 적용 지점 선택 (이슈 #77)' 블록(머리 주석 · 열 · 제약 · 함수 · 트리거)."""
    start = text.index(HEADER + "\n")
    return text[start:text.index(BLOCK_END, start) + len(BLOCK_END)]


def verify_lines77():
    """verify-db-roles.sh 의 #77 절(echo 머리부터 다음 echo 앞까지) q · p 줄."""
    text = read(VERIFY)
    sec = text[text.index(VERIFY_SECTION):]
    sec = sec[sec.index("\n"):].split("\necho", 1)[0]
    pat = re.compile(r'^([qp]) (opsloop_[a-z]+) +"(.+)" (허용|거부|t|f)$')
    return [m.groups() for m in map(pat.match, sec.splitlines()) if m]


def acl(expr):
    """ACL 을 '역할:권한' 정렬 배열로(PUBLIC 은 '-'). 거두고 다시 주면 항목 차례가 바뀌어도 같다."""
    return (f"(SELECT array_agg(g ORDER BY g) FROM (SELECT a.grantee::regrole::text || ':' || a.privilege_type AS g"
            f" FROM aclexplode({expr}) a) s)")


def unwrap(text):
    """마이그레이션을 시험 트랜잭션 안에서 돌린다(BEGIN; · COMMIT; 을 뗀다)."""
    return text.replace("BEGIN;", "").replace("COMMIT;", "")


class PointsChoiceTextTest(unittest.TestCase):
    """스키마 블록 · 마이그레이션 · 감사 함수 · 역할 검증 스크립트 · 복원 훈련의 글자 시험. DB 없이 돈다."""

    def test_마이그레이션은_스키마_블록_그대로이고_잠금_한_줄만_다르다(self):
        schema, mig = read(SCHEMA), read(MIGRATION)
        head, body = mig.split("\nBEGIN;\n", 1)
        self.assertTrue(all(ln.startswith("--") for ln in head.splitlines()))      # 머리는 주석뿐이다
        self.assertEqual((schema.count(NAME_NEW), schema.count(NAME_OLD), mig.count(NAME_OLD), mig.count(NAME_NEW)), (1, 0, 1, 0))
        self.assertEqual(body.rstrip("\n"), LOCK + "\n" + block77(schema).replace(NAME_NEW, NAME_OLD) + "\nCOMMIT;")
        self.assertNotIn(LOCK, block77(schema))                                     # 스키마 전체 적용에는 잠금 상한을 걸지 않는다

    def test_머리말은_적용_순서_잠금_되돌리기를_적는다(self):
        head = read(MIGRATION).split("\nBEGIN;\n", 1)[0]
        for s in ("20260927 은 여기서 다시 적용하지 않는다", "콘솔 · triage 새 판(이 열을 쓴다)보다 먼저 적용한다",
                  "5초 안에 잠금을 얻지 못하면 실패하고 아무것도 바꾸지", "복원 뒤에는 다시 적용한다",
                  "다시 적용할 때는 열 · 제약이 있으면 표를 잠그지 않고",
                  "DROP TRIGGER IF EXISTS trg_blocklist_points ON blocklist; ALTER TABLE blocklist DROP CONSTRAINT IF EXISTS"
                  " blocklist_points_valid;", "< infra/migrations/20261003_block_points_choice.sql",
                  "infra/vmware/scripts/verify-db-roles.sh 의 '차단 적용 지점' 줄"):
            self.assertIn(s, head)

    def test_블록은_63_블록_뒤_파일_끝에_있다(self):
        # 표(blocklist · absorbed_blocks)가 앞에서 만들어지고, 권한을 주지 않으므로 역할 블록 뒤 어디든 되지만 마지막 블록으로 둔다
        schema = read(SCHEMA)
        at = schema.index(HEADER + "\n")
        self.assertGreater(at, schema.index(HEADER63 + "\n"))
        self.assertGreater(at, schema.index("GRANT pg_read_all_data TO opsloop_backup"))
        self.assertGreater(at, schema.index("CREATE TABLE IF NOT EXISTS absorbed_blocks"))
        self.assertEqual(schema.rstrip("\n"), schema[:at] + block77(schema))
        self.assertEqual(schema.count(HEADER + "\n"), 1)

    def test_열_두_개와_값_제약은_두_값뿐이다(self):
        blk = block77(read(SCHEMA))
        self.assertNotIn("ADD COLUMN IF NOT EXISTS", blk)                       # IF NOT EXISTS 여도 ACCESS EXCLUSIVE 를 잡는다
        for table in ("blocklist", "absorbed_blocks"):
            with self.subTest(table=table):
                # 열도 pg_attribute 를 보고 없을 때만 더한다(있으면 표를 잠그지 않는다)
                self.assertIn(f"WHERE attrelid = '{table}'::regclass AND attname = 'points' AND NOT attisdropped) THEN\n"
                              f"        ALTER TABLE {table} ADD COLUMN points text[] NOT NULL DEFAULT '{{gateway,fw}}';", blk)
                # 여러 번 적용할 수 있게 pg_constraint 를 보고 없을 때만 더한다
                self.assertIn(f"WHERE conrelid = '{table}'::regclass AND conname = '{table}_points_valid') THEN\n"
                              f"        ALTER TABLE {table} ADD CONSTRAINT {table}_points_valid\n            {CHECK};", blk)
        self.assertEqual(blk.count(CHECK), 2)
        self.assertEqual(set(re.findall(r"'(\{[^']*\})'", blk)), {"{gateway,fw}", "{fw}"})    # 관문 전용 · 다른 차례가 없다

    def test_블록에_표_열_권한이_없고_함수_실행_회수_한_줄뿐이다(self):
        code = "\n".join(ln for ln in block77(read(SCHEMA)).splitlines() if not ln.lstrip().startswith("--"))
        self.assertEqual(re.findall(r"^\s*((?:GRANT|REVOKE)\b.*)$", code, re.M),
                         ["REVOKE ALL ON FUNCTION blocklist_points_change() FROM PUBLIC;"])
        for word in ("rolname", "CREATE ROLE", "ROW LEVEL SECURITY"):
            self.assertNotIn(word, code)

    def test_지점_트리거의_약속(self):
        blk = block77(read(SCHEMA))
        func = blk[blk.index("CREATE OR REPLACE FUNCTION blocklist_points_change()"):blk.index("CREATE OR REPLACE TRIGGER")]
        self.assertIn("RETURNS trigger\nLANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = public, pg_temp\n", func)
        self.assertNotRegex(func, r"\bEXECUTE\b")                                   # 동적 SQL 이 없다
        # 살아 있는 행(해제 전 · 만료 전)만 본다. 좁히기는 거부, 넓히기는 감사
        self.assertIn("IF OLD.released_at IS NOT NULL OR OLD.expires_at <= now() THEN\n        RETURN NULL;", func)
        self.assertIn("IF NEW.released_at IS NULL AND NOT NEW.points @> OLD.points THEN", func)
        self.assertIn("ERRCODE = 'check_violation', CONSTRAINT = 'blocklist_points_narrow'", func)
        self.assertIn("PERFORM audit_event('console.block.points',", func)
        self.assertIn("format('ip=%s from=%s to=%s', host(NEW.actor_ip), array_to_string(OLD.points, ','),", func)
        self.assertIn("CREATE OR REPLACE TRIGGER trg_blocklist_points\n    AFTER UPDATE OF points ON blocklist\n    " + BLOCK_END, blk)

    def test_감사_함수는_한_벌이고_20260927_과_같고_지점_자리는_계약대로다(self):
        schema = read(SCHEMA)
        audit = MOD.audit_sql(schema)
        self.assertEqual(schema.count(MOD.AUDIT_START), 1)
        self.assertIn(audit, read(M27))
        # 열이 없는 DB(20261003 전)에서도 돌게 to_jsonb 로 읽고, 없으면 '-'
        self.assertIn("p := coalesce(nullif(array_to_string(ARRAY(SELECT jsonb_array_elements_text(to_jsonb(NEW) -> 'points')),"
                      " ','), ''), '-');", audit)
        # created · rearmed 는 expires= 바로 뒤, extended · shortened 는 끝. requested_by= · from= … to= 읽기(app/reports.py)가 그대로다
        for fmt in ("format('ip=%s incident=%s expires=%s points=%s requested_by=%s'",
                    "format('ip=%s incident=%s expires=%s points=%s released_by=%s requested_by=%s'",
                    "format('ip=%s from=%s to=%s points=%s'"):
            self.assertIn(fmt, audit)
        self.assertNotIn("console.block.points", audit)                    # 넓히기 감사는 #77 트리거가 남긴다

    def test_역할_검증_스크립트에_77_절이_있다(self):
        self.assertEqual(verify_lines77(), VERIFY_LINES)
        text = read(VERIFY)
        self.assertIn("infra/migrations/20261003_block_points_choice.sql 을 적용한 뒤에 돌린다", text)
        self.assertLess(text.index('echo "== 콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63'), text.index(VERIFY_SECTION))

    def test_복원_훈련은_새_트리거_함수를_세고_지문에_지점을_넣는다(self):
        # 트리거 10 = #63 뒤 9 + trg_blocklist_points, 함수 19 = 18 + blocklist_points_change. 표 · FK · 뷰는 그대로다
        self.assertEqual(QUERIES.EXPECT, {"tables": 26, "fk": 15, "triggers": 10, "functions": 19, "views": 3})
        fps = {f[0]: f for f in QUERIES.FINGERPRINTS}
        self.assertTrue(fps["blocklist"][2].endswith(" enforced_at, enforce_note, points)"), fps["blocklist"][2])
        self.assertTrue(fps["absorbed_blocks"][2].endswith(", released_by, points)"), fps["absorbed_blocks"][2])
        QUERIES.assert_read_only(QUERIES.q_fingerprint())


class PointsCase(MOD.DbCase):
    """#77 시험 도우미. 시험마다 한 트랜잭션이고 끝나면 되돌린다."""

    def block(self, ip, points=None, expires="now() + interval '1 day'", actor="han"):
        """콘솔 역할로 차단 한 줄. points 가 없으면 열을 모르는 옛 문장이다(MOD.DbCase.put)."""
        if points is None:
            return self.put(ip, expires=expires, actor=actor)
        with self.as_role("console", actor):
            self.cur.execute(f"INSERT INTO blocklist (actor_ip, reason, incident_key, requested_by, expires_at, points)"
                             f" VALUES (%s, 'console', 'R001|v3|x', %s, {expires}, %s::text[])", (ip, actor, points))

    def set_points(self, ip, points, actor="han", key="console"):
        with self.as_role(key, actor):
            self.cur.execute("UPDATE blocklist SET points = %s::text[] WHERE actor_ip = %s", (points, ip))

    def points_of(self, ip):
        return self.one("SELECT points FROM blocklist WHERE actor_ip = %s", (ip,))[0]

    def check_refused(self, table, constraint, sql, args=None):
        e = self.fails(sql, args)
        self.assertEqual((e.pgcode, e.diag.constraint_name, e.diag.table_name), ("23514", constraint, table), f"{sql} {args}: {e}")
        return e

    def catalog(self, tables=True):
        """다시 적용해도 같아야 하는 것: 열 · 기본값 · 열 권한, 제약, 트리거, 함수, (표 권한), 행, 이벤트 수."""
        got = {
            "cols": self.q("SELECT a.attrelid::regclass::text, format_type(a.atttypid, a.atttypmod), a.attnotnull,"
                           " pg_get_expr(d.adbin, d.adrelid), a.attacl::text FROM pg_attribute a"
                           " LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum"
                           " WHERE a.attrelid IN ('blocklist'::regclass, 'absorbed_blocks'::regclass) AND a.attname = 'points'"
                           " AND NOT a.attisdropped ORDER BY 1"),
            "checks": self.q("SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid), convalidated FROM pg_constraint"
                             " WHERE conname IN ('blocklist_points_valid', 'absorbed_blocks_points_valid') ORDER BY conname"),
            "trigger": self.q("SELECT tgname, tgenabled, pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname = 'trg_blocklist_points'"),
            "func": self.q(f"SELECT prosecdef, proconfig, md5(prosrc), {acl('proacl')} FROM pg_proc"
                           " WHERE proname = 'blocklist_points_change'"),
            "rows": self.q("SELECT host(actor_ip), points, expires_at, released_at FROM blocklist ORDER BY actor_ip"),
            "events": self.one("SELECT count(*) FROM events"),
        }
        if tables:
            got["tables"] = self.q(f"SELECT relname, {acl('relacl')} FROM pg_class"
                                   " WHERE relname IN ('blocklist', 'absorbed_blocks') ORDER BY relname")
        return got


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class PointsChoiceDatabaseTest(PointsCase):
    """schema.sql 전체(+ infra/notify.sql)와 마이그레이션을 두 번씩 적용한 새 데이터베이스. 역할은 모두 있다."""

    @classmethod
    def setUpClass(cls):
        cls.create()
        for text in (read(SCHEMA), read(SCHEMA), read(MIGRATION), read(MIGRATION), read(NOTIFY)):
            cls.scur.execute(cls.sub(text))
        cls.connect()

    # ── 기본값 · 값 제약 ──

    def test_열을_모르는_옛_문장과_새_행은_두_지점이다(self):
        self.block("203.0.113.10")                                  # 콘솔 · triage 옛 판의 INSERT(열 없음)
        self.assertEqual(self.points_of("203.0.113.10"), TWO)
        with self.as_role("console", "han"):
            self.cur.execute("INSERT INTO absorbed_blocks (first_key, expires_at, requested_by) VALUES ('k1', now(), 'han')")
        self.assertEqual(self.one("SELECT points FROM absorbed_blocks WHERE first_key = 'k1'")[0], TWO)
        [(_, _, detail)] = self.audit("203.0.113.10")
        self.assertRegex(detail, r" expires=\S+.* points=gateway,fw requested_by=han$")
        # 옛 문장의 재차단은 points 를 건드리지 않는다: 해제된 fw 전용 행을 다시 걸면 {fw} 가 남는다(반영 계약 6장)
        self.block("203.0.113.11", FW)
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1' WHERE actor_ip = '203.0.113.11'")
            self.cur.execute("INSERT INTO blocklist (actor_ip, reason, incident_key, requested_by, expires_at)"
                             " VALUES ('203.0.113.11', 'console', 'k', 'admin1', now() + interval '1 hour')"
                             " ON CONFLICT (actor_ip) DO UPDATE SET released_at = NULL, released_by = NULL,"
                             " expires_at = EXCLUDED.expires_at, requested_by = EXCLUDED.requested_by")
        self.assertEqual(self.points_of("203.0.113.11"), FW)
        self.assertEqual(self.events_of("203.0.113.11"), ["console.block.created", "console.block.released",
                                                          "console.block.rearmed"])

    def test_값_제약은_두_값만_받는다(self):
        self.block("203.0.113.20")
        with self.as_role("console", "han"):
            self.cur.execute("INSERT INTO absorbed_blocks (first_key, expires_at) VALUES ('k2', now())")
            for bad in BAD:
                with self.subTest(bad=bad):
                    self.check_refused("blocklist", "blocklist_points_valid",
                                       "INSERT INTO blocklist (actor_ip, expires_at, points) VALUES ('203.0.113.21', now(), %s)",
                                       (bad,))
                    self.check_refused("blocklist", "blocklist_points_valid",
                                       "UPDATE blocklist SET points = %s WHERE actor_ip = '203.0.113.20'", (bad,))
                    self.check_refused("absorbed_blocks", "absorbed_blocks_points_valid",
                                       "INSERT INTO absorbed_blocks (first_key, expires_at, points) VALUES ('k3', now(), %s)",
                                       (bad,))
                    self.check_refused("absorbed_blocks", "absorbed_blocks_points_valid",
                                       "UPDATE absorbed_blocks SET points = %s WHERE first_key = 'k2'", (bad,))
            for sql in ("UPDATE blocklist SET points = NULL WHERE actor_ip = '203.0.113.20'",
                        "UPDATE absorbed_blocks SET points = NULL WHERE first_key = 'k2'"):
                self.assertEqual(self.fails(sql).pgcode, "23502")                  # NOT NULL
            self.cur.execute("INSERT INTO absorbed_blocks (first_key, expires_at, points) VALUES ('k4', now(), '{fw}')")
        self.assertEqual(self.points_of("203.0.113.20"), TWO)
        self.assertEqual(self.events_of("203.0.113.20"), ["console.block.created"])

    # ── 살아 있는 행: 좁히기 거부 · 넓히기 감사 ──

    def test_살아_있는_행의_지점은_좁히지_못하고_감사도_남지_않는다(self):
        self.block("203.0.113.30")
        self.block("203.0.113.31", expires="NULL")                  # 만료 없는 옛 차단도 살아 있다
        for ip in ("203.0.113.30", "203.0.113.31"):
            with self.subTest(ip=ip):
                with self.as_role("console", "admin1"):
                    e = self.refused("blocklist_points_narrow", "UPDATE blocklist SET points = '{fw}' WHERE actor_ip = %s", (ip,))
                self.assertEqual(e.diag.column_name, "points")
                self.assertIn(ip, e.diag.message_primary)
                self.refused("blocklist_points_narrow", "UPDATE blocklist SET points = '{fw}' WHERE actor_ip = %s", (ip,))   # 소유자도
                self.assertEqual(self.points_of(ip), TWO)
                self.assertEqual(self.events_of(ip), ["console.block.created"])

    def test_살아_있는_행을_넓히면_감사_한_줄이고_같은_값은_남지_않는다(self):
        ip = "203.0.113.40"
        self.block(ip, FW)
        [(_, _, detail)] = self.audit(ip)
        self.assertRegex(detail, r" expires=\S+.* points=fw requested_by=han$")
        self.set_points(ip, TWO, actor="kim")
        self.set_points(ip, TWO, actor="kim")                       # 같은 값: 남지 않는다
        self.assertEqual(self.points_of(ip), TWO)
        self.assertEqual(self.audit(ip, "console.block.points"),
                         [("console.block.points", "kim", f"by=kim ip={ip} from=fw to=gateway,fw")])
        self.assertEqual(self.events_of(ip), ["console.block.created", "console.block.points"])
        # R201(차단 대량 해제)은 세지 않는다
        self.assertNotIn("console.block.points", MOD.R201_EVENTS)

    def test_찾기_넓히기_SQL_은_살아_있는_fw_전용_행만_넓힌다(self):
        live, rel, exp, both = "198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"
        for ip in (live, rel, exp):
            self.block(ip, FW, expires="now() - interval '1 minute'" if ip == exp else "now() + interval '1 day'")
        self.block(both)
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1' WHERE actor_ip = %s", (rel,))
        self.assertEqual([r[0] for r in self.q(FIND_SQL, ("-infinity",))], [live])
        self.cur.execute("SELECT set_config('opsloop.actor', 'admin1', true)")
        self.assertEqual(self.q(WIDEN_SQL), [(live,)])
        self.cur.execute("SELECT set_config('opsloop.actor', '', true)")
        self.assertEqual(self.q(FIND_SQL, ("-infinity",)), [])
        self.assertEqual([(e, w) for e, w, _ in self.audit(eventid="console.block.points")], [("console.block.points", "admin1")])
        self.assertEqual([self.points_of(ip) for ip in (live, rel, exp, both)], [TWO, FW, FW, TWO])

    # ── 해제 · 만료된 행: 어느 값으로든 다시 건다 ──

    def test_해제_만료된_행은_fw_전용으로_다시_걸고_rearmed_extended_한_줄뿐이다(self):
        rel, exp = "203.0.113.50", "203.0.113.51"
        self.block(rel)
        self.block(exp, expires="now() - interval '1 minute'")
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1' WHERE actor_ip = %s", (rel,))
        with self.as_role("console", "kim"):
            for ip in (rel, exp):
                self.cur.execute("UPDATE blocklist SET released_at = NULL, released_by = NULL, requested_by = 'kim',"
                                 " expires_at = now() + interval '1 hour', points = '{fw}' WHERE actor_ip = %s", (ip,))
        self.assertEqual([self.points_of(ip) for ip in (rel, exp)], [FW, FW])
        self.assertEqual(self.events_of(rel), ["console.block.created", "console.block.released", "console.block.rearmed"])
        self.assertIn(" points=fw released_by=admin1 requested_by=kim", self.audit(rel)[-1][2])
        self.assertEqual(self.events_of(exp), ["console.block.created", "console.block.extended"])
        self.assertRegex(self.audit(exp)[-1][2], r" to=[^=]+ points=fw$")

    def test_관리자의_관문_빼기는_한_트랜잭션의_해제와_재요청이다(self):
        # 콘솔(app/main.py add_action)이 하는 순서: 살아 있는 두 지점 행을 풀고 같은 트랜잭션에서 {fw} 로 다시 건다
        ip = "203.0.113.60"
        self.block(ip)
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1' WHERE actor_ip = %s", (ip,))
            self.cur.execute("UPDATE blocklist SET released_at = NULL, released_by = NULL, requested_by = 'admin1',"
                             " points = '{fw}' WHERE actor_ip = %s", (ip,))
        self.assertEqual(self.one("SELECT points, released_at IS NULL FROM blocklist WHERE actor_ip = %s", (ip,)), (FW, True))
        self.assertEqual(self.events_of(ip), ["console.block.created", "console.block.released", "console.block.rearmed"])
        # 푸는 문장에서 함께 좁히는 것도 받는다(풀린 행의 지점은 목록에 들지 않는다)
        self.block("203.0.113.61")
        with self.as_role("console", "admin1"):
            self.cur.execute("UPDATE blocklist SET released_at = now(), released_by = 'admin1', points = '{fw}'"
                             " WHERE actor_ip = '203.0.113.61'")
        self.assertEqual(self.events_of("203.0.113.61"), ["console.block.created", "console.block.released"])

    # ── 역할마다의 권한 ──

    def test_집행_역할은_지점을_읽기만_하고_대조_조건에_쓴다(self):
        ip = "203.0.113.70"
        self.block(ip, FW)
        with self.as_role("enforcer"):
            # 집행기 FETCH_SQL · GUARD(enforcer/block_enforcer.py)의 모양. 열이 없는 DB 에서도 돌게 to_jsonb 로 읽는다
            self.assertEqual(self.one("SELECT to_jsonb(b) -> 'points' FROM blocklist b WHERE actor_ip = %s", (ip,))[0], FW)
            guard = ("UPDATE blocklist SET enforce_note = 'x' WHERE actor_ip = %s"
                     " AND to_jsonb(blocklist) -> 'points' IS NOT DISTINCT FROM %s::jsonb")
            self.cur.execute(guard, (ip, '["gateway", "fw"]'))
            self.assertEqual(self.cur.rowcount, 0)
            self.cur.execute(guard, (ip, '["fw"]'))
            self.assertEqual(self.cur.rowcount, 1)
            self.denied("UPDATE blocklist SET points = '{gateway,fw}' WHERE actor_ip = %s", (ip,))
            self.denied("SELECT points FROM absorbed_blocks")
        self.assertEqual(self.points_of(ip), FW)

    def test_콘솔은_지점을_넣고_넓히고_탐지는_보지_못하고_백업은_읽는다(self):
        self.block("203.0.113.80", FW)
        self.set_points("203.0.113.80", TWO)
        with self.as_role("console", "han"):
            self.cur.execute("INSERT INTO absorbed_blocks (first_key, expires_at, points) VALUES ('k5', now(), '{fw}')")
            self.cur.execute("UPDATE absorbed_blocks SET points = '{gateway,fw}' WHERE first_key = 'k5'")
            self.fails("SELECT blocklist_points_change()")                            # 트리거 함수는 부를 수 없다
        for key in ("detector", "ingest"):
            with self.subTest(role=key), self.as_role(key):
                self.denied("SELECT points FROM blocklist")
                self.denied("SELECT points FROM absorbed_blocks")
        with self.as_role("backup"):
            self.assertEqual(self.q("SELECT host(actor_ip), points FROM blocklist"), [("203.0.113.80", TWO)])
            self.assertEqual(self.q("SELECT points FROM absorbed_blocks"), [(TWO,)])

    def test_권한은_새로_주지_않고_함수는_소유자_권한_PUBLIC_실행_없음이다(self):
        # 지점 열에 따로 준 열 권한이 없다(표 권한은 역할 블록 · #47 블록 그대로)
        self.assertEqual(self.q("SELECT attrelid::regclass::text, attacl FROM pg_attribute WHERE attname = 'points'"
                                " AND attrelid IN ('blocklist'::regclass, 'absorbed_blocks'::regclass) ORDER BY 1"),
                         [("absorbed_blocks", None), ("blocklist", None)])
        [(secdef, config, grants)] = self.q(f"SELECT prosecdef, proconfig, {acl('proacl')} FROM pg_proc"
                                            " WHERE proname = 'blocklist_points_change'")
        self.assertEqual((secdef, config), (True, ["search_path=public, pg_temp"]))
        self.assertFalse([g for g in grants or [] if g.startswith("-:")])            # PUBLIC 실행 권한이 없다
        for key in ("console", "enforcer", "detector"):
            self.assertFalse(self.one("SELECT has_function_privilege(%s, 'blocklist_points_change()', 'EXECUTE')",
                                      (self.roles[key],))[0])

    # ── 다시 적용 ──

    def test_두_번_적용해도_같다(self):
        self.block("203.0.113.90", FW)
        self.block("203.0.113.91")
        before = self.catalog()
        self.cur.execute(self.sub(read(SCHEMA)))
        self.cur.execute(self.sub(unwrap(read(MIGRATION))))
        self.assertEqual(self.catalog(), before)

    def test_역할_블록과_20260927_29_30_을_다시_적용해도_열_제약_트리거가_남는다(self):
        self.block("203.0.113.95", FW)
        before = self.catalog(tables=False)
        for path in REAPPLY:
            self.cur.execute(self.sub(unwrap(read(path))))
        self.assertEqual(self.catalog(tables=False), before)
        # 동작도 그대로다: 좁히기 거부 · 넓히기 감사(행위자) · 집행 역할의 지점 갱신 거부 · 감사 detail 의 지점
        self.set_points("203.0.113.95", TWO, actor="kim")
        self.assertEqual(self.audit("203.0.113.95", "console.block.points")[0][1], "kim")
        self.refused("blocklist_points_narrow", "UPDATE blocklist SET points = '{fw}' WHERE actor_ip = '203.0.113.95'")
        with self.as_role("enforcer"):
            self.denied("UPDATE blocklist SET points = points WHERE actor_ip = '203.0.113.95'")
        self.block("203.0.113.96", FW)
        self.assertRegex(self.audit("203.0.113.96")[0][2], r" points=fw requested_by=han$")

    # ── 역할 검증 스크립트 · 복원 훈련 ──

    def test_역할_검증_스크립트_77_절이_시험_DB_에서_같은_답을_내고_데이터를_바꾸지_않는다(self):
        self.block("203.0.113.100", FW)
        before = (self.q("SELECT * FROM blocklist"), self.one("SELECT count(*) FROM events")[0])
        lines = verify_lines77()
        self.assertEqual(len(lines), len(VERIFY_LINES))
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
                    except MOD.psycopg2.Error as e:
                        got = "거부" if e.pgcode == "42501" else f"오류({e.pgcode} {e})"
                        self.cur.execute("ROLLBACK TO SAVEPOINT v")
                    self.cur.execute("RESET SESSION AUTHORIZATION")
                    self.assertEqual((self.q("SELECT * FROM blocklist"), self.one("SELECT count(*) FROM events")[0]), before)
                    self.cur.execute("ROLLBACK TO SAVEPOINT v")
                self.assertEqual(got, want)

    def test_구조_수치는_복원_훈련_기대값과_같고_지문이_지점을_읽는다(self):
        cat = {}
        for stmt in QUERIES.Q_CATALOG.split(";\n"):
            _tag, name, value = self.one(stmt)[0].split("|", 2)
            cat[name] = value
        funcs, trigs = [x for x in cat["functions"].split(",") if x], [x for x in cat["triggers"].split(",") if x]
        got = {"tables": int(cat["tables"]), "fk": int(cat["fk"]), "triggers": len(trigs), "functions": len(funcs),
               "views": len([x for x in cat["views"].split(",") if x])}
        self.assertEqual(got, QUERIES.EXPECT)
        self.assertIn("blocklist_points_change", funcs)
        self.assertIn("trg_blocklist_points=O", trigs)
        # 지문 문장이 새 열로 돈다. 지점만 넓혀도 지문이 바뀐다
        self.block("203.0.113.110", FW)
        self.cur.execute("INSERT INTO absorbed_blocks (first_key, expires_at, points) VALUES ('k6', now(), '{fw}')")

        def prints():
            rows = {}
            for stmt in QUERIES.q_fingerprint().splitlines()[1:]:
                for (line,) in self.q(stmt):
                    tag, name, key, md5, _ts = line.split("|", 4)
                    rows[(name, key)] = md5
            return rows
        first = prints()
        self.set_points("203.0.113.110", TWO)
        self.cur.execute("UPDATE absorbed_blocks SET points = '{gateway,fw}' WHERE first_key = 'k6'")
        second = prints()
        self.assertNotEqual(first[("blocklist", "203.0.113.110/32")], second[("blocklist", "203.0.113.110/32")])
        self.assertNotEqual(first[("absorbed_blocks", "k6")], second[("absorbed_blocks", "k6")])


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class PointsChoiceMigrationTest(PointsCase):
    """#77 전 DB(#63 까지 적용, points 열 없음)에 기존 차단 · 약속을 두고 마이그레이션을 올린다. 첫 시도는 다른 연결이
    absorbed_blocks 를 읽는 중이라 잠금을 얻지 못하고, 그 뒤 두 번 적용한다."""

    ROWS = ("SELECT host(actor_ip), reason, incident_key, requested_by, created_at, expires_at, released_at, released_by, method,"
            " enforced_at, enforce_note, enforcement FROM blocklist ORDER BY actor_ip")

    @classmethod
    def setUpClass(cls):
        cls.create()
        text = read(SCHEMA)
        cls.scur.execute(cls.sub(text[:text.index(HEADER + "\n")]))
        s = cls.scur
        s.execute("SELECT count(*) FROM pg_attribute WHERE attname = 'points' AND attrelid IN ('blocklist'::regclass,"
                  " 'absorbed_blocks'::regclass)")
        assert s.fetchone()[0] == 0, "#77 전 DB 가 아니다"
        # 살아 있는 차단(만료 있음 · 없음) · 풀린 차단 · 만료된 차단 · 흡수 약속
        s.execute("INSERT INTO blocklist (actor_ip, reason, incident_key, requested_by, expires_at, released_at, released_by) VALUES"
                  " ('203.0.113.10', 'console', 'k1', 'han', now() + interval '1 day', NULL, NULL),"
                  " ('203.0.113.11', 'triage', 'k2', NULL, NULL, NULL, NULL),"
                  " ('203.0.113.12', 'console', 'k3', 'han', now() + interval '1 day', now(), 'admin1'),"
                  " ('203.0.113.13', 'console', 'k4', 'han', now() - interval '1 hour', NULL, NULL)")
        s.execute("INSERT INTO absorbed_blocks (first_key, expires_at, requested_by) VALUES ('k1', now() + interval '1 day', 'han')")
        s.execute("SELECT input FROM events WHERE eventid = 'console.block.created' AND input LIKE '%ip=203.0.113.10 %'")
        cls.created_before = s.fetchone()[0]
        s.execute("SELECT to_jsonb(b) -> 'points' FROM blocklist b WHERE actor_ip = '203.0.113.10'")
        cls.fetch_before = s.fetchone()[0]                     # 집행기 FETCH_SQL 모양은 열이 없어도 돈다(NULL → 두 지점)
        s.execute(cls.ROWS)
        cls.rows_before = s.fetchall()
        s.execute("SELECT count(*) FROM events")
        cls.events_before = s.fetchone()[0]
        s.execute(f"SELECT relname, {acl('relacl')} FROM pg_class WHERE relname IN ('blocklist', 'absorbed_blocks') ORDER BY 1")
        cls.acl_before = s.fetchall()
        # 첫 시도: 다른 연결(집행기 · 콘솔의 읽기 트랜잭션)이 absorbed_blocks 를 쥐고 있다
        other = MOD.psycopg2.connect(MOD.psycopg2.extensions.make_dsn(MOD.URL, dbname=cls.dbname))
        try:
            other.cursor().execute("SELECT count(*) FROM absorbed_blocks")
            t0 = time.monotonic()
            try:
                s.execute(cls.sub(read(MIGRATION)))
                cls.lock_error = None
            except MOD.psycopg2.Error as e:
                cls.lock_error = e.pgcode
                s.execute("ROLLBACK")
            cls.lock_seconds = time.monotonic() - t0
        finally:
            other.rollback()
            other.close()
        s.execute("SELECT count(*) FROM pg_attribute WHERE attname = 'points' AND NOT attisdropped"
                  " AND attrelid IN ('blocklist'::regclass, 'absorbed_blocks'::regclass)")
        cls.cols_after_fail = s.fetchone()[0]
        for _ in range(2):
            s.execute(cls.sub(read(MIGRATION)))
        # 다시 적용: 다른 연결(백업 pg_dump · 콘솔 조회)이 두 표를 읽는 중이어도 표를 잠그지 않아 기다리지 않는다
        other = MOD.psycopg2.connect(MOD.psycopg2.extensions.make_dsn(MOD.URL, dbname=cls.dbname))
        try:
            other.cursor().execute("SELECT count(*) FROM blocklist, absorbed_blocks")
            t0 = time.monotonic()
            try:
                s.execute(cls.sub(read(MIGRATION)))
                cls.reapply_error = None
            except MOD.psycopg2.Error as e:
                cls.reapply_error = e.pgcode
                s.execute("ROLLBACK")
            cls.reapply_seconds = time.monotonic() - t0
        finally:
            other.rollback()
            other.close()
        cls.connect()

    def test_잠금을_얻지_못하면_아무것도_바꾸지_않고_실패한다(self):
        self.assertEqual(self.lock_error, "55P03")                   # lock_not_available
        self.assertGreater(self.lock_seconds, 4)
        self.assertLess(self.lock_seconds, 30)
        self.assertEqual(self.cols_after_fail, 0)                    # 먼저 더한 blocklist 열도 되돌려졌다

    def test_다시_적용은_읽는_트랜잭션을_기다리지_않는다(self):
        self.assertIsNone(self.reapply_error)
        self.assertLess(self.reapply_seconds, 3)

    def test_기존_행과_약속은_두_지점이고_다른_열_이벤트_권한은_그대로다(self):
        self.assertEqual(self.q(self.ROWS), self.rows_before)
        self.assertEqual(self.q("SELECT DISTINCT points FROM blocklist"), [(TWO,)])
        self.assertEqual(self.q("SELECT points FROM absorbed_blocks"), [(TWO,)])
        self.assertEqual(self.one("SELECT count(*) FROM events")[0], self.events_before)     # 마이그레이션은 감사를 남기지 않는다
        self.assertEqual(self.q(f"SELECT relname, {acl('relacl')} FROM pg_class"
                                " WHERE relname IN ('blocklist', 'absorbed_blocks') ORDER BY 1"), self.acl_before)
        self.assertEqual(self.fetch_before, None)

    def test_열이_없던_DB_의_감사는_지점이_빈칸이고_뒤에는_지점이_붙는다(self):
        self.assertRegex(self.created_before, r" expires=\S+.* points=- requested_by=han$")
        self.block("203.0.113.20", FW)
        self.assertRegex(self.audit("203.0.113.20")[0][2], r" points=fw requested_by=han$")

    def test_마이그레이션_뒤_기존_행은_좁히지_못하고_넓히기만_남는다(self):
        for ip in ("203.0.113.10", "203.0.113.11"):                 # 만료 있음 · 없음
            self.refused("blocklist_points_narrow", "UPDATE blocklist SET points = '{fw}' WHERE actor_ip = %s", (ip,))
        # 풀린 행 · 만료된 행은 {fw} 로 다시 걸 수 있다
        with self.as_role("console", "kim"):
            self.cur.execute("UPDATE blocklist SET released_at = NULL, released_by = NULL, expires_at = now() + interval '1 hour',"
                             " points = '{fw}' WHERE actor_ip IN ('203.0.113.12', '203.0.113.13')")
            self.assertEqual(self.cur.rowcount, 2)
        self.assertEqual(self.q("SELECT host(actor_ip), points FROM blocklist ORDER BY actor_ip"),
                         [("203.0.113.10", TWO), ("203.0.113.11", TWO), ("203.0.113.12", FW), ("203.0.113.13", FW)])
        self.assertEqual(self.audit(eventid="console.block.points"), [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
