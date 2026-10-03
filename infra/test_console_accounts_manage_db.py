#!/usr/bin/env python3
"""콘솔 계정 추가 · 삭제 · 비밀번호(이슈 #63) DB 시험.  python3 infra/test_console_accounts_manage_db.py

DB 없이 도는 글자 시험: 마이그레이션(infra/migrations/20261002_console_accounts_manage.sql)이 schema.sql 의 '콘솔 계정 추가 · 삭제 ·
비밀번호 (이슈 #63)' 블록을 글자 그대로 담는지, 블록이 #59 블록 뒤(그 뒤에는 #77 블록만)에 있는지, 세 함수(console_account_create ·
console_account_delete · console_account_password)의 모양 · 결과 차례 · 해시 형식 검사(app/auth.py hash_password 와 같은 모양) ·
아이디 검사(명령줄과 같은 식) · 권한 줄이 계약과 같은지(콘솔 역할에 계정 표 쓰기 권한을 늘리지 않는지), verify-db-roles.sh 에 #63 절이
있고 #59 절이 그대로인지, 복원 훈련의 함수 수 기대값이 늘었는지 본다.

OPSLOOP_TEST_DATABASE_URL 이 슈퍼유저 연결이면 infra/test_block_enforce_db.py 와 같은 방식(무작위 데이터베이스 · 역할,
SET SESSION AUTHORIZATION)으로 schema.sql 과 마이그레이션을 두 번씩 적용하고, 세 함수의 결과 전부, 변경 한 번에 감사 한 줄(by= · target= ·
해시 없음), 이력(로그인 · 판정 · 조치 · 차단 요청 · 해제)이 있는 계정의 in_use, 비밀번호를 바꾸면 updated_at 이 바뀌는지, 콘솔 역할이
계정 표를 직접 고치지 못하고 함수만 부르는지, 역할 블록 · #59 마이그레이션을 다시 적용한 뒤의 실행 권한, 역할 검증 스크립트 #63 절이
같은 답을 내는지(실행 줄은 no_actor · 데이터 불변), 구조 수치가 복원 훈련 기대값과 같은지 본다. 같은 아이디를 동시에 만드는 경우와
#63 전 DB(기존 계정이 있다)에 마이그레이션을 올리는 경우도 따로 만든다.
역할은 시험 안에서 만들고 지운다. 운영 DB · 운영 역할은 건드리지 않는다. 비밀번호 해시는 형식만 흉내 낸 가짜 값이다.
"""
import hashlib
import importlib.util
import os
import re
import threading
import time
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
NOTIFY = os.path.join(ROOT, "infra", "notify.sql")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20261002_console_accounts_manage.sql")
M59 = os.path.join(ROOT, "infra", "migrations", "20261001_console_accounts.sql")
ROLES_SQL = os.path.join(ROOT, "infra", "migrations", "20260924_db_roles.sql")
VERIFY = os.path.join(ROOT, "infra", "vmware", "scripts", "verify-db-roles.sh")
AUTH = os.path.join(ROOT, "app", "auth.py")
ACCOUNTS59 = os.path.join(ROOT, "infra", "test_console_accounts_db.py")

HEADER = "-- 콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63)"
HEADER59 = "-- 콘솔 계정 관리 (이슈 #59)"
NEXT_HEADER = "-- 차단 적용 지점 선택 (이슈 #77)"      # 이 블록 뒤에 오는 다음 블록(infra/test_block_points_choice_db.py)
VERIFY_SECTION = 'echo "== 콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63'
SIGS = {"console_account_create": "console_account_create(text, text, text)",
        "console_account_delete": "console_account_delete(text)",
        "console_account_password": "console_account_password(text, text)"}
HEADS = {"console_account_create": "(p_username text, p_role text, p_password_hash text)",
         "console_account_delete": "(p_username text)",
         "console_account_password": "(p_username text, p_password_hash text)"}
# 계약 1절의 차례대로 가른다
RESULTS = {"console_account_create": ["no_actor", "invalid", "cli_only", "exists", "ok"],
           "console_account_delete": ["no_actor", "self", "not_found", "cli_only", "in_use", "ok"],
           "console_account_password": ["no_actor", "invalid", "self", "not_found", "cli_only", "ok"]}
# 함수 안의 쓰기는 계정 표 한 곳뿐이다
WRITES = {"console_account_create": [("INSERT INTO", "console_users")],
          "console_account_delete": [("DELETE FROM", "console_users")],
          "console_account_password": [("UPDATE", "console_users")]}
HASH_SQL = r"'^pbkdf2_sha256\$[1-9][0-9]{4,6}\$[0-9a-f]{32}\$[0-9a-f]{64}$'"
GRANTS = [f"GRANT EXECUTE ON FUNCTION {sig} TO opsloop_console;" for sig in SIGS.values()]
VERIFY_LINES = [
    ("q", "opsloop_console", "INSERT INTO console_users (username, password_hash, role) SELECT username, password_hash, 'viewer'"
                             " FROM console_users WHERE false", "거부"),
    ("q", "opsloop_console", "DELETE FROM console_users WHERE false", "거부"),
    ("q", "opsloop_console", "SELECT console_account_create(NULL, NULL, NULL)", "허용"),
    ("q", "opsloop_console", "SELECT console_account_delete(NULL)", "허용"),
    ("q", "opsloop_console", "SELECT console_account_password(NULL, NULL)", "허용"),
    ("q", "opsloop_detector", "SELECT console_account_create(NULL, NULL, NULL)", "거부"),
] + [("p", f"opsloop_{role}", f"has_function_privilege('opsloop_{role}', '{sig}', 'EXECUTE')", want)
     for role, want in (("console", "t"), ("detector", "f"), ("ingest", "f")) for sig in SIGS.values()] + [
    ("p", "opsloop_console", f"(SELECT prosecdef FROM pg_proc WHERE proname = '{name}')", "t") for name in SIGS]
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


ACC = load("accounts59_for_63", ACCOUNTS59)
MOD = ACC.MOD
QUERIES = ACC.QUERIES


def fake_hash(n):
    """app/auth.py hash_password 와 같은 모양(pbkdf2_sha256$<반복>$<솔트 16진>$<값 16진>)의 가짜 해시."""
    salt = hashlib.sha256(f"salt{n}".encode()).hexdigest()[:32]
    return f"pbkdf2_sha256$240000${salt}${hashlib.sha256(f'hash{n}'.encode()).hexdigest()}"


H1, H2, H3 = fake_hash(1), fake_hash(2), fake_hash(3)
# 형식이 아닌 값. 평문 · #59 시험의 base64 모양 · 대문자 16진 · 끝 줄바꿈 · 빈 반복 수 · 다른 알고리즘 · 앞 공백 · 범위 밖
BAD_HASHES = [None, "", "correct horse battery", ACC.FAKE_HASH, H1.upper(), H1 + "\n", "pbkdf2_sha256$$ab$cd",
              "pbkdf2_sha1$240000$ab$cd", H1.replace("$", "$$", 1), " " + H1,
              # 반복 수 · 길이 범위 밖: 1조 번 반복(로그인 한 번에 콘솔이 멈춤) · 0 으로 시작 · 짧은 솔트 · 짧은 값
              H1.replace("$240000$", "$999999999999$"), H1.replace("$240000$", "$0240000$"), H1.replace("$240000$", "$9999$"),
              "pbkdf2_sha256$240000$" + "ab" * 8 + "$" + "cd" * 32, "pbkdf2_sha256$240000$" + "ab" * 16 + "$" + "cd" * 16]
BAD_NAMES = [None, "", "a" * 65, "han seong", "op1\n", "관제사", "op1;drop", "o'p", "op/1"]


def block63(text):
    """'콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63)' 블록(머리 주석 · 함수 셋 · 권한). 뒤에 #77 블록이 있으면 그 앞까지다."""
    start = text.index(HEADER + "\n")
    stop = text.find("\n" + NEXT_HEADER, start)
    region = text if stop < 0 else text[:stop]
    end = region.rindex("END\n$$;") + len("END\n$$;")
    return text[start:end]


def verify_lines63():
    """verify-db-roles.sh 의 #63 절(echo 머리부터 다음 echo 앞까지) q · p 줄."""
    text = read(VERIFY)
    sec = text[text.index(VERIFY_SECTION):]
    sec = sec[sec.index("\n"):].split("\necho", 1)[0]
    pat = re.compile(r'^([qp]) (opsloop_[a-z]+) +"(.+)" (허용|거부|t|f)$')
    return [m.groups() for m in map(pat.match, sec.splitlines()) if m]


class ManageTextTest(unittest.TestCase):
    """스키마 블록 · 마이그레이션 · 역할 검증 스크립트 · 복원 훈련 기대값의 글자 시험. DB 없이 돈다."""

    def test_마이그레이션은_스키마_블록_그대로다(self):
        schema, mig = read(SCHEMA), read(MIGRATION)
        head, body = mig.split("\nBEGIN;\n", 1)
        self.assertTrue(all(ln.startswith("--") for ln in head.splitlines()))      # 머리는 주석뿐이다
        self.assertEqual(body.rstrip("\n"), block63(schema) + "\nCOMMIT;")

    def test_머리말은_적용_순서와_다시_적용_조건을_적는다(self):
        head = read(MIGRATION).split("\nBEGIN;\n", 1)[0]
        self.assertIn("적용 순서: 20261001_console_accounts.sql 뒤", head)
        self.assertIn("콘솔 새 이미지(계정 추가 · 삭제 ·\n--   비밀번호 재설정 API · 화면)보다 먼저 적용하고", head)
        self.assertIn("다시 적용: 콘솔 역할(opsloop_console)이 없을 때 적용했으면 역할을 만든 뒤 다시 적용한다", head)
        self.assertIn("< infra/migrations/20261002_console_accounts_manage.sql", head)
        self.assertIn("infra/vmware/scripts/verify-db-roles.sh 의 '콘솔 계정 추가 · 삭제 · 비밀번호' 줄", head)

    def test_블록은_59_블록_뒤에_있고_그_뒤에는_77_블록만_온다(self):
        # #59 블록의 도장 · 감사 트리거가 이 함수들의 변경을 찍고 남긴다. 역할 블록보다도 뒤다(실행 권한만 주므로 다시 적용해도 남는다).
        # 스키마 끝은 #77 블록이다(infra/test_block_points_choice_db.py)
        schema = read(SCHEMA)
        at = schema.index(HEADER + "\n")
        self.assertGreater(at, schema.index(HEADER59 + "\n"))
        self.assertGreater(at, schema.index("GRANT pg_read_all_data TO opsloop_backup"))
        rest = schema[at + len(block63(schema)):].strip("\n")
        self.assertTrue(rest.startswith(NEXT_HEADER), rest[:80])
        self.assertEqual(schema.count(HEADER + "\n"), 1)

    def test_세_함수의_약속(self):
        blk = block63(read(SCHEMA))
        for name, sig in SIGS.items():
            with self.subTest(name):
                body = ACC.func(blk, name + "(")
                self.assertIn(f"CREATE OR REPLACE FUNCTION {name}{HEADS[name]}\nRETURNS text\n", body)
                self.assertIn("\nSECURITY DEFINER\n", body)
                self.assertIn("\nSET search_path = public, pg_temp\n", body)
                self.assertNotRegex(body, r"\bEXECUTE\b")                          # 동적 SQL 이 없다
                self.assertIn(f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC;", blk)
                self.assertEqual(re.findall(r"RETURN '(\w+)';", body), RESULTS[name])
                self.assertIn("v_actor text := nullif(current_setting('opsloop.actor', true), '');", body)
                self.assertEqual(re.findall(r"\b(INSERT INTO|UPDATE|DELETE FROM) (\w+)", body), WRITES[name])
        create, delete, password = (ACC.func(blk, n + "(") for n in SIGS)
        # 해시 형식 검사는 추가 · 비밀번호 둘 다 같은 식이고, 아이디 검사는 추가에만 있다
        for body in (create, password):
            self.assertIn(f"(p_password_hash ~ {HASH_SQL}) IS NOT TRUE", body)
        self.assertIn("p_role IS NULL OR p_role NOT IN ('viewer', 'operator')", create)
        self.assertIn("ON CONFLICT (username) DO NOTHING;", create)
        for body in (delete, password):
            self.assertIn("SELECT * INTO u FROM console_users WHERE username = p_username FOR UPDATE;", body)
            self.assertIn("IF u.role = 'admin' THEN", body)
        # 이력: 로그인 기록 · 판정자 · 조치자 · 차단 요청자 · 해제자
        for cond in ("u.last_login_at IS NOT NULL", "EXISTS (SELECT 1 FROM verdicts WHERE operator = p_username)",
                     "EXISTS (SELECT 1 FROM actions WHERE operator = p_username)",
                     "EXISTS (SELECT 1 FROM blocklist WHERE requested_by = p_username OR released_by = p_username)"):
            self.assertIn(cond, delete)

    def test_아이디_해시_검사는_명령줄과_같은_모양이다(self):
        auth = read(AUTH)
        name = re.search(r'NEW_USERNAME = re\.compile\(r"([^"]+)"\)', auth).group(1)
        create = ACC.func(block63(read(SCHEMA)), "console_account_create(")
        self.assertIn(f"(p_username ~ '^{name}$') IS NOT TRUE", create)
        # 콘솔이 만드는 해시(auth.hash_password)는 받고, 형식이 아닌 값은 거른다. 이 식은 PostgreSQL · Python 에서 뜻이 같다
        # (끝 줄바꿈은 DB 시험이 따로 본다. Python 의 $ 는 끝 줄바꿈 앞에서도 맞는다)
        self.assertIn('return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${dk.hex()}"', auth)
        pat = re.compile(HASH_SQL.strip("'"))
        self.assertTrue(pat.fullmatch(H1))
        for bad in BAD_HASHES:
            if bad is not None:
                with self.subTest(bad=bad):
                    self.assertIsNone(pat.fullmatch(bad))

    def test_권한_줄은_콘솔의_함수_실행뿐이고_계정_표_쓰기를_늘리지_않는다(self):
        blk = block63(read(SCHEMA))
        self.assertEqual(MOD.grant_lines(blk), GRANTS)
        self.assertEqual(re.findall(r"rolname = '(\w+)'", blk), ["opsloop_console"])
        self.assertNotIn("REVOKE ALL ON ALL", blk)
        self.assertNotIn("CREATE ROLE", blk)
        writes = re.findall(r"GRANT (?:UPDATE|INSERT|DELETE|TRUNCATE|ALL)\b[^;]*\bconsole_users\b[^;]*;", read(SCHEMA))
        self.assertEqual([" ".join(w.split()) for w in writes], ["GRANT UPDATE (last_login_at) ON console_users TO opsloop_console;"])

    def test_역할_검증_스크립트에_63_절이_있고_59_절은_그대로다(self):
        self.assertEqual(verify_lines63(), VERIFY_LINES)
        self.assertEqual(ACC.verify_lines59(), ACC.VERIFY_LINES)
        text = read(VERIFY)
        self.assertIn("infra/migrations/20261002_console_accounts_manage.sql", text)
        self.assertLess(text.index('echo "== 콘솔 계정 관리 (이슈 #59'), text.index(VERIFY_SECTION))

    def test_복원_훈련은_새_함수_셋을_센다(self):
        # 함수 18 = #59 뒤 15 + 이 블록의 셋. #77 이 트리거 +1 · 함수 +1 을 더했다(infra/test_block_points_choice_db.py)
        self.assertEqual(QUERIES.EXPECT, {"tables": 27, "fk": 15, "triggers": 10, "functions": 20, "views": 3})


class ManageCase(ACC.AccountsCase):
    """계정 추가 · 삭제 · 비밀번호 시험 도우미. 시험마다 한 트랜잭션이고 끝나면 되돌린다."""

    def seed(self):
        """관리자 둘(로그인함 · 안 함) · 관제사(로그인함) · 조회자 · 관제사(이력 없음) · 비활성 관제사(이력 없음).
        만든 때 · 마지막 변경은 과거로 둔다(도장이 찍히는지 보려고)."""
        self.cur.execute("INSERT INTO console_users (username, password_hash, role, disabled_at) VALUES"
                         " ('root', %(h)s, 'admin', NULL), ('root2', %(h)s, 'admin', NULL), ('op1', %(h)s, 'operator', NULL),"
                         " ('vw1', %(h)s, 'viewer', NULL), ('fresh', %(h)s, 'operator', NULL), ('gone', %(h)s, 'operator', %(t)s)",
                         {"h": H1, "t": T0})
        self.cur.execute("UPDATE console_users SET created_at = %s, updated_at = %s,"
                         " last_login_at = CASE WHEN username IN ('root', 'op1') THEN %s::timestamptz END", (T0, T0, T1))
        self.mark = self.one("SELECT clock_timestamp()")[0]

    def seed_disabled_admin(self):
        """비활성 관리자(로그인한 적 없음)를 더한다. 비활성이어도 관리자라 콘솔은 건드리지 못한다(재활성은 명령줄).
        넣은 감사 줄은 seed 처럼 기준 시각 앞으로 둔다."""
        self.cur.execute("INSERT INTO console_users (username, password_hash, role, disabled_at) VALUES ('oldroot', %s, 'admin', %s)",
                         (H1, T0))
        self.cur.execute("UPDATE console_users SET created_at = %s, updated_at = %s WHERE username = 'oldroot'", (T0, T0))
        self.mark = self.one("SELECT clock_timestamp()")[0]

    def rows(self):
        """(아이디, 역할, 활성, 마지막 변경, 해시). 거부 · 변경 없음은 이것이 그대로다."""
        return self.q("SELECT username, role, disabled_at IS NULL, updated_at, password_hash FROM console_users ORDER BY username")

    def call(self, name, *args, actor="root", key="console"):
        """콘솔처럼 행위자를 넘기고 함수를 부른다(app/accounts.py)."""
        with self.as_role(key, actor):
            marks = ", ".join(["%s"] * len(args))
            return self.one(f"SELECT {name}({marks})", args)[0]

    def add(self, username, role, h, **kw):
        return self.call("console_account_create", username, role, h, **kw)

    def remove(self, username, **kw):
        return self.call("console_account_delete", username, **kw)

    def passwd(self, username, h, **kw):
        return self.call("console_account_password", username, h, **kw)

    def assert_no_secret(self, *hashes):
        """seed 뒤 감사 행(eventid · 행위자 · detail)에 해시 · 솔트 · 값이 없다."""
        text = " ".join(" ".join(r) for r in self.q("SELECT eventid, coalesce(username, ''), coalesce(input, '')"
                                                     " FROM events WHERE sensor = 'audit' AND ts > %s", (self.mark,)))
        self.assertNotIn("pbkdf2", text)
        for h in hashes:
            for part in h.split("$")[2:]:
                self.assertNotIn(part, text)

    def incident(self, key):
        self.cur.execute("INSERT INTO incidents (incident_key, rule_id, rule_version, severity, first_ts, last_ts, signal_count)"
                         " VALUES (%s, 'R001', 'v3', 'low', now(), now(), 1)", (key,))


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class ManageDatabaseTest(ManageCase):
    """schema.sql 전체(+ infra/notify.sql)와 마이그레이션을 두 번씩 적용한 새 데이터베이스. 역할은 모두 있다."""

    @classmethod
    def setUpClass(cls):
        cls.create()
        for text in (read(SCHEMA), read(SCHEMA), read(MIGRATION), read(MIGRATION), read(NOTIFY)):
            cls.scur.execute(cls.sub(text))
        cls.connect()

    def functions(self):
        """세 함수(와 #59 함수)의 본문 · 설정 · 권한."""
        return self.q(f"SELECT proname, prosecdef, proconfig, md5(prosrc), {self.acl('proacl')} FROM pg_proc"
                      " WHERE proname IN ('console_account_create', 'console_account_delete', 'console_account_password',"
                      " 'console_account_set') ORDER BY proname")

    def catalog(self):
        """다시 적용해도 같아야 하는 것: 함수, 계정 표 권한 · 열 권한, 트리거, 행, 이벤트 수."""
        return {
            "functions": self.functions(),
            "table": self.q(f"SELECT {self.acl('relacl')} FROM pg_class WHERE relname = 'console_users'"),
            "cols": self.q(f"SELECT attname, {self.acl('attacl')} FROM pg_attribute WHERE attrelid = 'console_users'::regclass"
                           " AND attnum > 0 AND NOT attisdropped ORDER BY attnum"),
            "triggers": self.q("SELECT tgname, tgenabled, pg_get_triggerdef(oid) FROM pg_trigger"
                               " WHERE tgrelid = 'console_users'::regclass AND NOT tgisinternal ORDER BY tgname"),
            "rows": self.rows(),
            "events": self.one("SELECT count(*) FROM events"),
        }

    # ── 추가 ──

    def test_추가_결과는_계약의_경우다(self):
        self.seed()
        before = self.rows()
        cases = [("행위자 없음", ("new1", "viewer", H1, None), "no_actor"),
                 ("관리자 역할 · 평문 · 행위자 없음", ("new1", "admin", "plain", None), "no_actor"),
                 ("관리자 역할 · 아이디 형식 아님", ("new 1", "admin", H1, "root"), "invalid"),
                 ("관리자 역할 · 평문", ("new1", "admin", "correct horse battery", "root"), "invalid"),
                 ("관리자 역할", ("new1", "admin", H1, "root"), "cli_only"),
                 ("역할 없음", ("new1", None, H1, "root"), "cli_only"),
                 ("모르는 역할", ("new1", "superuser", H1, "root"), "cli_only"),
                 ("대문자 역할", ("new1", "Viewer", H1, "root"), "cli_only"),
                 ("있는 관리자 · 관리자 역할", ("root2", "admin", H1, "root"), "cli_only"),
                 ("있는 관제사", ("op1", "viewer", H1, "root"), "exists"),
                 ("있는 비활성 계정", ("gone", "operator", H1, "root"), "exists"),
                 ("있는 관리자", ("root2", "viewer", H1, "root"), "exists"),
                 ("행위자 자신", ("root", "viewer", H1, "root"), "exists")]
        cases += [(f"아이디 {bad!r}", (bad, "viewer", H1, "root"), "invalid") for bad in BAD_NAMES]
        cases += [(f"해시 {bad!r}", ("new1", "viewer", bad, "root"), "invalid") for bad in BAD_HASHES]
        for name, (u, role, h, actor), want in cases:
            with self.subTest(name):
                self.assertEqual(self.add(u, role, h, actor=actor), want)
        with self.as_role("console"):
            self.cur.execute("SELECT set_config('opsloop.actor', '', true)")          # 끝난 연결의 빈 값도 없음이다
            self.assertEqual(self.one("SELECT console_account_create('new1', 'viewer', %s)", (H1,))[0], "no_actor")
        self.assertEqual(self.rows(), before)                    # 거부는 행도 도장도 그대로다
        self.assertEqual(self.audit(), [])
        # 만든다: 역할 · 해시 그대로, 활성, 로그인 기록 없음, 도장은 지금이다
        edge = "A._-" + "z" * 60                                  # 64자, 쓸 수 있는 글자 전부
        self.assertEqual(self.add("new1", "viewer", H1), "ok")
        self.assertEqual(self.add("new2", "operator", H2, actor="cli:han"), "ok")
        self.assertEqual(self.add(edge, "viewer", H3), "ok")
        self.assertEqual(self.q("SELECT username, role, password_hash, disabled_at, last_login_at, updated_at >= now()"
                                " FROM console_users WHERE username IN ('new1', 'new2', %s) ORDER BY username", (edge,)),
                         [(edge, "viewer", H3, None, None, True), ("new1", "viewer", H1, None, None, True),
                          ("new2", "operator", H2, None, None, True)])
        self.assertEqual(self.add("new1", "operator", H2), "exists")           # 두 번째는 이미 있다
        self.assertEqual(self.audit(), [
            ("console.account.created", "root", "by=root target=new1 role=viewer"),
            ("console.account.created", "cli:han", "by=cli:han target=new2 role=operator"),
            ("console.account.created", "root", f"by=root target={edge} role=viewer")])
        self.assert_no_secret(H1, H2, H3)

    # ── 삭제 ──

    def test_삭제_결과는_계약의_경우다(self):
        self.seed()
        self.seed_disabled_admin()
        before = self.rows()
        cases = [("행위자 없음", ("vw1", None), "no_actor"),
                 ("행위자 자신", ("root", "root"), "self"),
                 ("행위자 자신 (계정 없음)", ("ghost", "ghost"), "self"),
                 ("행위자 자신 (관리자 아닌 이름)", ("vw1", "vw1"), "self"),
                 ("없는 계정", ("ghost", "root"), "not_found"),
                 ("아이디 없음", (None, "root"), "not_found"),
                 ("관리자 (로그인한 적 없음)", ("root2", "root"), "cli_only"),
                 ("관리자 (로그인함)", ("root", "root2"), "cli_only"),
                 ("비활성 관리자 (이력 없음)", ("oldroot", "root"), "cli_only"),
                 ("로그인한 관제사", ("op1", "root"), "in_use")]
        for name, (u, actor), want in cases:
            with self.subTest(name):
                self.assertEqual(self.remove(u, actor=actor), want)
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.audit(), [])
        # 이력 없는 계정은 비활성이어도 지운다
        self.assertEqual(self.remove("vw1"), "ok")
        self.assertEqual(self.remove("gone"), "ok")
        self.assertEqual(self.remove("vw1"), "not_found")
        self.assertEqual([r[0] for r in self.rows()], ["fresh", "oldroot", "op1", "root", "root2"])
        self.assertEqual(self.audit(), [("console.account.deleted", "root", "by=root target=vw1 role=viewer"),
                                        ("console.account.deleted", "root", "by=root target=gone role=operator")])
        self.assert_no_secret(H1)

    def test_이력이_있는_계정은_in_use_이고_남는다(self):
        self.seed()
        self.incident("R001|v3|203.0.113.40")
        histories = [
            ("로그인 기록", "UPDATE console_users SET last_login_at = now() WHERE username = %(u)s"),
            ("판정자", "INSERT INTO verdicts (incident_key, verdict, operator) VALUES ('R001|v3|203.0.113.40', 'threat', %(u)s)"),
            ("조치자", "INSERT INTO actions (incident_key, action, operator) VALUES ('R001|v3|203.0.113.40', 'note', %(u)s)"),
            ("차단 요청자", "INSERT INTO blocklist (actor_ip, reason, requested_by) VALUES ('203.0.113.41', 'console', %(u)s)"),
            ("차단 해제자", "INSERT INTO blocklist (actor_ip, reason, requested_by, released_at, released_by)"
                        " VALUES ('203.0.113.42', 'console', 'root', now(), %(u)s)")]
        for name, sql in histories:
            with self.subTest(name):
                self.cur.execute("SAVEPOINT h")
                self.cur.execute(sql, {"u": "fresh"})
                self.assertEqual(self.remove("fresh"), "in_use")
                self.assertEqual(self.one("SELECT count(*) FROM console_users WHERE username = 'fresh'")[0], 1)
                self.cur.execute("ROLLBACK TO SAVEPOINT h")
        # 다른 계정 · 비슷한 이름의 이력은 상관없다
        for _name, sql in histories[1:]:
            self.cur.execute(sql.replace("'203.0.113.4", "'203.0.113.5"), {"u": "fresh2"})       # 차단 주소만 바꾼다
        self.assertEqual(self.audit(), [])
        self.assertEqual(self.remove("fresh"), "ok")
        self.assertEqual([e for e, _, _ in self.audit()], ["console.account.deleted"])

    # ── 비밀번호 ──

    def test_비밀번호_결과는_계약의_경우다(self):
        self.seed()
        self.seed_disabled_admin()
        before = self.rows()
        cases = [("행위자 없음", ("op1", H2, None), "no_actor"),
                 ("행위자 없음 · 평문", ("op1", "plain", None), "no_actor"),
                 ("행위자 자신 · 평문", ("root", "correct horse battery", "root"), "invalid"),
                 ("관리자 · 평문", ("root2", "correct horse battery", "root"), "invalid"),
                 ("없는 계정 · 평문", ("ghost", "correct horse battery", "root"), "invalid"),
                 ("행위자 자신", ("root", H2, "root"), "self"),
                 ("행위자 자신 (관리자 아닌 이름)", ("op1", H2, "op1"), "self"),
                 ("없는 계정", ("ghost", H2, "root"), "not_found"),
                 ("아이디 없음", (None, H2, "root"), "not_found"),
                 ("관리자", ("root2", H2, "root"), "cli_only"),
                 ("비활성 관리자", ("oldroot", H2, "root"), "cli_only")]
        cases += [(f"해시 {bad!r}", ("op1", bad, "root"), "invalid") for bad in BAD_HASHES]
        for name, (u, h, actor), want in cases:
            with self.subTest(name):
                self.assertEqual(self.passwd(u, h, actor=actor), want)
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.audit(), [])
        # 관제사 · 조회자 · 비활성 계정. 해시가 바뀌고 도장이 찍히며 역할 · 활성 · 로그인 기록은 그대로다
        for user in ("op1", "vw1", "gone"):
            self.assertEqual(self.passwd(user, H2), "ok")
        self.assertEqual(self.q("SELECT username, role, disabled_at IS NULL, password_hash, updated_at >= now(), last_login_at"
                                " FROM console_users WHERE username IN ('op1', 'vw1', 'gone') ORDER BY username"),
                         [("gone", "operator", False, H2, True, None), ("op1", "operator", True, H2, True, T1),
                          ("vw1", "viewer", True, H2, True, None)])
        self.assertEqual(self.audit(), [("console.account.password.changed", "root", f"by=root target={u}")
                                        for u in ("op1", "vw1", "gone")])
        self.assert_no_secret(H1, H2)

    def test_비밀번호를_바꾸면_updated_at_이_바뀌어_그_전_쿠키가_무효다(self):
        # 콘솔은 쿠키 발급 시각이 updated_at 보다 앞이면 무효로 본다(app/auth.py). 발급 시각을 이 트랜잭션의 clock_timestamp() 로 흉내 낸다
        self.seed()
        self.cur.execute("SELECT pg_sleep(0.01)")
        issued = self.one("SELECT clock_timestamp()")[0]
        self.assertEqual(self.passwd("op1", H2), "ok")
        stamp = self.one("SELECT updated_at FROM console_users WHERE username = 'op1'")[0]
        self.assertGreater(stamp, issued)
        self.assertGreater(stamp, T1)                               # 마지막 로그인(쿠키 발급)보다 뒤다
        # 다른 계정의 도장은 그대로다
        self.assertEqual(self.one("SELECT count(*) FROM console_users WHERE username <> 'op1' AND updated_at <> %s", (T0,))[0], 0)

    # ── 감사 ──

    def test_변경마다_감사_한_줄이고_감사_화면에_보이며_해시는_없다(self):
        self.seed()
        self.assertEqual(self.add("temp1", "operator", H1), "ok")
        self.assertEqual(self.passwd("temp1", H2), "ok")
        self.assertEqual(self.remove("temp1"), "ok")
        self.assertEqual(self.audit(), [("console.account.created", "root", "by=root target=temp1 role=operator"),
                                        ("console.account.password.changed", "root", "by=root target=temp1"),
                                        ("console.account.deleted", "root", "by=root target=temp1 role=operator")])
        with self.as_role("console"):
            rows = self.q("SELECT eventid, actor, substring(detail from %s) FROM audit_log"
                          " WHERE eventid LIKE 'console.account.%%' AND ts > %s ORDER BY ts", (ACC.TARGET_RE, self.mark))
        self.assertEqual(rows, [(e, "root", "temp1") for e in ("console.account.created", "console.account.password.changed",
                                                                  "console.account.deleted")])
        self.assert_no_secret(H1, H2)
        e = self.fails("DELETE FROM events WHERE eventid LIKE 'console.account.%%' AND ts > %s", (self.mark,))
        self.assertIn("감사 이벤트는 고치거나 지울 수 없다", str(e))

    # ── 권한 ──

    def test_콘솔_역할은_계정_표를_고치지_못하고_세_함수만_부른다(self):
        self.seed()
        with self.as_role("console", "root"):
            for sql in ("INSERT INTO console_users (username, password_hash, role) VALUES ('evil', 'x', 'viewer')",
                        "DELETE FROM console_users WHERE username = 'vw1'",
                        "UPDATE console_users SET password_hash = 'x' WHERE username = 'op1'",
                        "TRUNCATE console_users"):
                with self.subTest(sql=sql):
                    self.denied(sql)
            self.assertEqual(self.one("SELECT console_account_create('new1', 'viewer', %s)", (H1,))[0], "ok")
            self.assertEqual(self.one("SELECT console_account_password('op1', %s)", (H2,))[0], "ok")
            self.assertEqual(self.one("SELECT console_account_delete('vw1')")[0], "ok")
        for key in ("detector", "ingest", "enforcer", "gate", "cti", "backup"):
            with self.subTest(role=key), self.as_role(key, "root"):
                self.denied("SELECT console_account_create('new2', 'viewer', %s)", (H1,))
                self.denied("SELECT console_account_password('fresh', %s)", (H2,))
                self.denied("SELECT console_account_delete('fresh')")
        self.assertEqual([r[0] for r in self.rows()], ["fresh", "gone", "new1", "op1", "root", "root2"])
        self.assertEqual([e for e, _, _ in self.audit()], ["console.account.created", "console.account.password.changed",
                                                          "console.account.deleted"])

    def test_권한은_계약과_같다(self):
        for key in MOD.ROLE_KEYS:
            for sig in SIGS.values():
                with self.subTest(role=key, sig=sig):
                    self.assertEqual(self.one("SELECT has_function_privilege(%s, %s, 'EXECUTE')", (self.roles[key], sig))[0],
                                     key == "console")
        for sig in SIGS.values():
            self.assertFalse(self.one("SELECT has_function_privilege('public', %s, 'EXECUTE')", (sig,))[0], sig)
        self.assertEqual(self.q("SELECT proname, prosecdef, proconfig FROM pg_proc WHERE proname = ANY(%s) ORDER BY proname",
                                (list(SIGS),)),
                         [(name, True, ["search_path=public, pg_temp"]) for name in sorted(SIGS)])
        # 콘솔의 계정 표 권한은 #59 그대로다: 표 전체 읽기, 쓰기는 로그인 기록 열뿐
        console = self.roles["console"]
        self.assertEqual(self.one("SELECT has_table_privilege(%(r)s, 'console_users', 'SELECT'),"
                                  " has_table_privilege(%(r)s, 'console_users', 'INSERT'),"
                                  " has_table_privilege(%(r)s, 'console_users', 'UPDATE'),"
                                  " has_table_privilege(%(r)s, 'console_users', 'DELETE'),"
                                  " has_table_privilege(%(r)s, 'console_users', 'TRUNCATE')", {"r": console}),
                         (True, False, False, False, False))
        cols = [c for (c,) in self.q("SELECT attname FROM pg_attribute WHERE attrelid = 'console_users'::regclass"
                                     " AND attnum > 0 AND NOT attisdropped ORDER BY attnum")]
        self.assertEqual([c for c in cols if self.one("SELECT has_column_privilege(%s, 'console_users', %s, 'UPDATE')",
                                                      (console, c))[0]], ["last_login_at"])

    # ── 다시 적용 ──

    def test_두_번_적용해도_같다(self):
        self.seed()
        before = self.catalog()
        self.cur.execute(self.sub(read(SCHEMA)))
        self.apply(MIGRATION)
        self.assertEqual(self.catalog(), before)
        self.assertEqual(self.audit(), [])

    def test_역할_블록을_다시_적용해도_실행_권한은_남는다(self):
        self.seed()
        self.apply(ROLES_SQL)
        console = self.roles["console"]
        for sig in SIGS.values():
            self.assertTrue(self.one("SELECT has_function_privilege(%s, %s, 'EXECUTE')", (console, sig))[0], sig)
        self.assertEqual(self.one("SELECT has_table_privilege(%(r)s, 'console_users', 'INSERT')"
                                  " OR has_table_privilege(%(r)s, 'console_users', 'DELETE')", {"r": console})[0], False)
        self.assertEqual(self.add("new1", "viewer", H1), "ok")
        self.assertEqual(self.passwd("new1", H2), "ok")
        self.assertEqual(self.remove("new1"), "ok")

    def test_59_마이그레이션을_다시_적용해도_세_함수는_그대로다(self):
        self.seed()
        before = self.functions()
        self.apply(M59)
        self.assertEqual(self.functions(), before)
        self.assertEqual(self.passwd("op1", H2), "ok")
        self.assertEqual([e for e, _, _ in self.audit()], ["console.account.password.changed"])

    # ── 역할 검증 스크립트 · 복원 훈련 ──

    def test_역할_검증_스크립트_줄이_시험_DB_에서_같은_답을_내고_데이터를_바꾸지_않는다(self):
        self.seed()
        before = (self.rows(), self.one("SELECT count(*) FROM events")[0])
        lines = verify_lines63()
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
                        if stmt.startswith("SELECT console_account_"):
                            self.assertEqual(self.cur.fetchone(), ("no_actor",))      # 행위자가 없어 아무것도 바꾸지 않는다
                    except MOD.psycopg2.Error as e:
                        got = "거부" if e.pgcode == "42501" else f"오류({e.pgcode} {e})"
                        self.cur.execute("ROLLBACK TO SAVEPOINT v")
                    self.cur.execute("RESET SESSION AUTHORIZATION")
                    # 검증 스크립트는 문장마다 따로 붙어 자동 확정한다. 되돌리기 전에 바뀐 것이 없는지 본다
                    self.assertEqual((self.rows(), self.one("SELECT count(*) FROM events")[0]), before)
                    self.cur.execute("ROLLBACK TO SAVEPOINT v")
                self.assertEqual(got, want)

    def test_구조_수치는_복원_훈련_기대값과_같다(self):
        cat = {}
        for stmt in QUERIES.Q_CATALOG.split(";\n"):
            _tag, name, value = self.one(stmt)[0].split("|", 2)
            cat[name] = value
        funcs = [x for x in cat["functions"].split(",") if x]
        got = {"tables": int(cat["tables"]), "fk": int(cat["fk"]),
               "triggers": len([x for x in cat["triggers"].split(",") if x]), "functions": len(funcs),
               "views": len([x for x in cat["views"].split(",") if x])}
        self.assertEqual(got, QUERIES.EXPECT)
        for name in SIGS:
            self.assertIn(name, funcs)


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class ManageRaceTest(ManageCase):
    """같은 아이디를 두 연결이 동시에 만든다. 고유 키 오류 없이 하나만 들어가고, 늦은 쪽은 먼저 쪽이 확정하면 exists 다."""

    @classmethod
    def setUpClass(cls):
        cls.create()
        cls.scur.execute(cls.sub(read(SCHEMA)))
        cls.connect()

    def race(self, username, finish):
        """이 연결이 먼저 만들고(확정 전), 다른 연결이 같은 아이디를 만들다 기다리는 동안 finish(commit · rollback)한다."""
        other = MOD.psycopg2.connect(MOD.psycopg2.extensions.make_dsn(MOD.URL, dbname=self.dbname))
        self.addCleanup(other.close)
        ocur = other.cursor()
        ocur.execute(f"SET SESSION AUTHORIZATION {self.roles['console']}")
        ocur.execute("SELECT set_config('opsloop.actor', 'root2', false)")
        other.commit()
        self.assertEqual(self.add(username, "viewer", H1), "ok")
        got = {}

        def late():
            try:
                ocur.execute("SELECT console_account_create(%s, 'operator', %s)", (username, H2))
                got["result"] = ocur.fetchone()[0]
                other.commit()
            except MOD.psycopg2.Error as e:          # 고유 키 오류(23505)가 나면 안 된다
                got["error"] = f"{e.pgcode} {e}"
                other.rollback()

        t = threading.Thread(target=late)
        t.start()
        pid, deadline, waiting = other.get_backend_pid(), time.monotonic() + 10, None
        with self.admin.cursor() as a:                # 다른 연결이 고유 키 확인에서 이 트랜잭션을 기다리는지 본다
            while time.monotonic() < deadline and waiting != "Lock":
                time.sleep(0.02)
                a.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s", (pid,))
                waiting = (a.fetchone() or [None])[0]
        getattr(self.conn, finish)()
        t.join(10)
        self.assertFalse(t.is_alive())
        self.assertEqual(waiting, "Lock")
        return got

    def test_먼저_쪽이_확정하면_늦은_쪽은_exists_다(self):
        self.assertEqual(self.race("race1", "commit"), {"result": "exists"})
        self.assertEqual(self.q("SELECT role, password_hash FROM console_users WHERE username = 'race1'"), [("viewer", H1)])
        self.assertEqual(self.q("SELECT eventid, username FROM events WHERE sensor = 'audit' AND input LIKE '%%target=race1 %%'"),
                         [("console.account.created", "root")])

    def test_먼저_쪽이_되돌리면_늦은_쪽이_만든다(self):
        self.assertEqual(self.race("race2", "rollback"), {"result": "ok"})
        self.assertEqual(self.q("SELECT role, password_hash FROM console_users WHERE username = 'race2'"), [("operator", H2)])
        self.assertEqual(self.q("SELECT eventid, username FROM events WHERE sensor = 'audit' AND input LIKE '%%target=race2 %%'"),
                         [("console.account.created", "root2")])


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class ManageMigrationTest(ManageCase):
    """#63 전 DB(#59 까지 적용, 세 함수 없음)에 기존 계정을 두고 마이그레이션을 두 번 올린다."""

    @classmethod
    def setUpClass(cls):
        cls.create()
        text = read(SCHEMA)
        cls.scur.execute(cls.sub(text[:text.index(HEADER + "\n")]))
        cls.scur.execute("SELECT array_agg(proname::text ORDER BY proname) FROM pg_proc WHERE proname LIKE 'console_account%'")
        assert cls.scur.fetchone()[0] == ["console_account_set"], "#63 전 DB 가 아니다"
        cls.scur.execute("INSERT INTO console_users (username, password_hash, role, created_at, last_login_at) VALUES"
                         " ('root', %(h)s, 'admin', %(t0)s, %(t1)s), ('op1', %(h)s, 'operator', %(t0)s, NULL)",
                         {"h": H1, "t0": T0, "t1": T1})
        cls.scur.execute(STATE)
        cls.before = cls.scur.fetchall()
        for _ in range(2):
            cls.scur.execute(cls.sub(read(MIGRATION)))
        cls.connect()

    def test_기존_계정과_이벤트는_그대로다(self):
        self.assertEqual(self.q(STATE), self.before)

    def test_마이그레이션_뒤_콘솔은_세_함수를_부르고_감사가_남는다(self):
        self.mark = self.one("SELECT clock_timestamp()")[0]
        for sig in SIGS.values():
            self.assertTrue(self.one("SELECT has_function_privilege(%s, %s, 'EXECUTE')", (self.roles["console"], sig))[0], sig)
        self.assertEqual(self.add("new1", "viewer", H2), "ok")
        self.assertEqual(self.passwd("op1", H3), "ok")
        self.assertEqual(self.remove("op1"), "ok")
        self.assertEqual(self.remove("root"), "self")
        self.assertEqual(self.remove("root", actor="root2"), "cli_only")
        with self.as_role("console"):
            self.assertEqual(self.q("SELECT eventid, actor, detail FROM audit_log WHERE ts > %s ORDER BY ts", (self.mark,)),
                             [("console.account.created", "root", "by=root target=new1 role=viewer"),
                              ("console.account.password.changed", "root", "by=root target=op1"),
                              ("console.account.deleted", "root", "by=root target=op1 role=operator")])


# 마이그레이션 전후로 같아야 하는 계정 행 · 이벤트 수
STATE = ("SELECT username, role, created_at, disabled_at, updated_at, last_login_at, password_hash,"
         " (SELECT count(*) FROM events) FROM console_users ORDER BY username")


if __name__ == "__main__":
    unittest.main(verbosity=1)
