#!/usr/bin/env python3
"""차단 집행 지점 · 시험 출발지(이슈 #51) DB 시험.  python3 infra/test_block_points_db.py

DB 없이 도는 글자 시험: 마이그레이션(infra/migrations/20260929_block_points.sql)이 schema.sql 의 '차단 집행 지점 · 시험 출발지
(이슈 #51)' 블록을 글자 그대로 담는지(머리 주석의 관문 이름 한 줄만 다르다, 이슈 #78), 블록이 #47 블록 뒤(그 뒤에는 #52 블록만)에 있는지,
시험 출발지 초기값이 문서용 대역 셋인지(차단 금지 대역과 겹치지 않는지), 규칙 품질 뷰의 두 정의(차단 목록 앞 · 블록 안)가 같고 시험
출발지를 빼는지, 권한 줄이 계약과 같은지, 대시보드 · 규칙 화면의 규칙별 집계와 집행기 열 목록이 같은 조건을 쓰는지 본다.

OPSLOOP_TEST_DATABASE_URL 이 슈퍼유저 연결이면(infra/test_block_enforce_db.py 와 같은 방식) 무작위 데이터베이스에 schema.sql 과
마이그레이션을 두 번 적용하고, 시험 출발지의 사건이 rule_quality 에서 빠지는지, 집행 역할이 enforcement 열만 더 쓰는지 본다.
"""
import importlib.util
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20260929_block_points.sql")
VERIFY = os.path.join(ROOT, "infra", "vmware", "scripts", "verify-db-roles.sh")
DASHBOARD = os.path.join(ROOT, "app", "dashboard.py")
OPERATIONS = os.path.join(ROOT, "app", "operations.py")
ENFORCER = os.path.join(ROOT, "enforcer", "block_enforcer.py")
BLOCK47 = os.path.join(ROOT, "infra", "test_block_enforce_db.py")

HEADER = "-- 차단 집행 지점 · 시험 출발지 (이슈 #51)"
HEADER47 = "-- 차단 집행 (이슈 #47)"
NEXT_HEADER = "-- 관제 대상 상태판 (이슈 #52)"      # 이 블록 뒤에 오는 다음 블록(infra/test_status_board_db.py)
DOC_NETS = [("192.0.2.0/24", "문서용 · 동기화 자가 시험 주소"), ("198.51.100.0/24", "문서용 · 차단 집행 끝-끝 시험 주소"),
            ("203.0.113.0/24", "문서용 · 외부 역할 세그먼트 (시연용 공격자 VM)")]
EXCLUDE = "WHERE NOT is_test_source(i.actor_ip)"
FUNC = """CREATE OR REPLACE FUNCTION is_test_source(ip inet) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$ SELECT EXISTS (SELECT 1 FROM test_ranges t WHERE ip <<= t.cidr) $$;"""
GRANTS = ["GRANT UPDATE (enforcement) ON blocklist TO opsloop_enforcer;",
          "GRANT SELECT ON test_ranges TO opsloop_console;"]
# 머리 주석 가운데 관문 이름만 바꾼 한 줄(이슈 #78). 적용된 마이그레이션은 옛 글자 그대로다
NAME_OLD = "--   집행 지점이 관문 하나에서 둘(AWS 관문 · 온프레미스 내부 방화벽)이 된다."
NAME_NEW = "--   집행 지점이 관문 하나에서 둘(허니팟 관문 · 온프레미스 내부 방화벽)이 된다."


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def block51(text):
    """'차단 집행 지점 · 시험 출발지 (이슈 #51)' 블록. 뒤에 #52 블록이 있으면 그 앞까지다."""
    start = text.index(HEADER + "\n")
    stop = text.find("\n" + NEXT_HEADER, start)
    region = text if stop < 0 else text[:stop]
    end = region.rindex("END\n$$;") + len("END\n$$;")
    return text[start:end]


def view_defs(text):
    """CREATE OR REPLACE VIEW rule_quality 정의 전부 (세미콜론까지)."""
    return re.findall(r"CREATE OR REPLACE VIEW rule_quality AS\n.*?;\n", text, re.S)


class BlockPointsTextTest(unittest.TestCase):
    def test_마이그레이션은_스키마_블록_그대로다(self):
        schema, mig = read(SCHEMA), read(MIGRATION)
        head, body = mig.split("\nBEGIN;\n", 1)
        self.assertTrue(all(ln.startswith("--") for ln in head.splitlines()))
        self.assertEqual((schema.count(NAME_NEW), schema.count(NAME_OLD), mig.count(NAME_OLD), mig.count(NAME_NEW)), (1, 0, 1, 0))
        self.assertEqual(body.rstrip("\n"), block51(schema).replace(NAME_NEW, NAME_OLD) + "\nCOMMIT;")

    def test_블록은_47_블록_뒤에_있고_그_뒤에는_52_블록만_온다(self):
        schema = read(SCHEMA)
        at = schema.index(HEADER + "\n")
        self.assertGreater(at, schema.index(HEADER47 + "\n"))
        rest = schema[at + len(block51(schema)):].strip("\n")
        self.assertTrue(rest.startswith(NEXT_HEADER), rest[:80])
        self.assertEqual(schema.count(HEADER + "\n"), 1)

    def test_시험_출발지_초기값은_문서용_대역_셋이고_금지_대역과_겹치지_않는다(self):
        block = block51(read(SCHEMA))
        body = block[block.index("INSERT INTO test_ranges (cidr, note) VALUES"):block.index("ON CONFLICT (cidr) DO NOTHING;")]
        self.assertEqual(re.findall(r"\('([0-9./]+)',\s+'([^']+)'\)", body), DOC_NETS)
        spec = importlib.util.spec_from_file_location("block47_test", BLOCK47)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual([c for c, _ in DOC_NETS], mod.DOC_NETS)
        self.assertFalse(set(c for c, _ in DOC_NETS) & set(mod.EXEMPT))

    def test_규칙_품질_뷰는_두_곳이_같고_시험_출발지를_뺀다(self):
        schema = read(SCHEMA)
        defs = view_defs(schema)
        self.assertEqual(len(defs), 2)                      # 차단 목록 앞의 정의와 #51 블록 안의 정의
        self.assertEqual(defs[0], defs[1])
        self.assertIn(EXCLUDE, defs[0])
        self.assertLess(schema.index("CREATE TABLE IF NOT EXISTS test_ranges"), schema.index(defs[0]))   # 표가 뷰보다 먼저
        self.assertLess(schema.index(FUNC), schema.index(defs[0]))                                       # 함수도 뷰보다 먼저
        self.assertEqual(schema.count(FUNC), 2)                                                           # 앞 정의와 블록 안
        self.assertIn(FUNC, block51(schema))
        self.assertNotIn("GRANT EXECUTE", block51(schema))       # PUBLIC 기본 실행 권한을 그대로 둔다(역할 블록이 거두지 않는다)
        # 열은 그대로다 (뷰 교체는 열 이름 · 순서를 바꾸지 못한다)
        cols = re.findall(r"AS (\w+),?\n", defs[0])
        self.assertEqual(cols, ["incidents", "judged", "threats", "non_actionable", "false_positives", "false_positive_rate",
                                "non_action_rate", "benign_positives", "undetermined", "judged_effective"])
        self.assertIn("ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS enforcement jsonb;", block51(schema))
        # 지점별 결과는 집행 역할 · 슈퍼유저만 쓴다 (콘솔은 표 전체 UPDATE 권한이 있어 트리거로 막는다)
        blk = block51(schema)
        self.assertIn("CREATE OR REPLACE TRIGGER blocklist_enforcement_guard\n    BEFORE INSERT OR UPDATE OF enforcement ON blocklist", blk)
        self.assertIn("session_user::text <> 'opsloop_enforcer'", blk)
        self.assertIn("REVOKE ALL ON FUNCTION blocklist_enforcement_guard() FROM PUBLIC;", blk)

    def test_권한_줄은_계약과_같다(self):
        block = block51(read(SCHEMA))
        grants = [" ".join(ln.split()) for ln in block[block.rindex("DO $$"):].splitlines()
                  if ln.strip().startswith("GRANT")]
        self.assertEqual(grants, GRANTS)
        self.assertEqual(re.findall(r"rolname = '(\w+)'", block), ["opsloop_enforcer", "opsloop_console"])
        for role in ("opsloop_ingest", "opsloop_gate", "opsloop_backup", "opsloop_cti", "opsloop_detector"):
            self.assertNotIn(role, block)

    def test_역할_검증_스크립트에_집행_지점_줄이_있다(self):
        text = read(VERIFY)
        sec = text.split("# 집행 지점 (이슈 #51)", 1)[1].split("\necho", 1)[0]
        pat = re.compile(r'^q (opsloop_[a-z]+) +"(.+)" (허용|거부)$', re.M)
        lines = pat.findall(sec)
        self.assertEqual(lines, [("opsloop_enforcer", "UPDATE blocklist SET enforcement = enforcement WHERE false", "허용"),
                                 ("opsloop_console", "SELECT cidr, note FROM test_ranges LIMIT 0", "허용"),
                                 ("opsloop_console", "INSERT INTO test_ranges (cidr, note) VALUES ('192.0.2.0/24', 'x')", "거부"),
                                 ("opsloop_detector", "SELECT is_test_source('203.0.113.10'::inet)", "허용"),
                                 ("opsloop_console", "SELECT is_test_source('203.0.113.10'::inet)", "허용")])

    def test_대시보드와_규칙_화면의_집계도_시험_출발지를_뺀다(self):
        for path in (DASHBOARD, OPERATIONS):
            self.assertIn("NOT is_test_source(i.actor_ip)", read(path), path)
            self.assertNotIn("FROM test_ranges", read(path), path)      # 표를 직접 읽지 않는다(역할 블록 재적용에 견딘다)

    def test_집행기는_열_목록과_대조_열에_enforcement_를_가진다(self):
        text = read(ENFORCER)
        self.assertIn('"enforcement", "exempt_net")', text)
        self.assertIn('GUARD = ("released_at", "expires_at", "enforced_at", "method", "enforce_note", "enforcement")', text)
        self.assertIn("b.enforce_note, b.enforcement,", text)


def db_case():
    spec = importlib.util.spec_from_file_location("block47_db", BLOCK47)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = db_case()


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class BlockPointsDatabaseTest(MOD.DbCase):
    @classmethod
    def setUpClass(cls):
        cls.create()
        for _ in range(2):                                   # 두 번 적용해도 같다
            cls.scur.execute(cls.sub(read(SCHEMA)))
            cls.scur.execute(cls.sub(read(MIGRATION)))
        cls.connect()

    def incident(self, key, ip, verdict=None):
        self.cur.execute("INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip, first_ts, last_ts,"
                         " signal_count, session_count, evidence, status) VALUES (%s, 'R102', 'w2', 'x', 'medium', %s, now(), now(),"
                         " 1, 1, '{}', 'open')", (key, ip))
        if verdict:
            self.cur.execute("INSERT INTO verdicts (incident_key, verdict, operator) VALUES (%s, %s, 'han')", (key, verdict))

    def quality(self):
        return {r[0]: r[1:] for r in self.q("SELECT rule_id || ' ' || rule_version, incidents, judged FROM rule_quality")}

    def test_콘솔은_지점별_결과를_쓰지_못하고_집행_역할은_쓴다(self):
        self.put("203.0.113.30")
        with self.as_role("console", "han"):
            self.denied("UPDATE blocklist SET enforcement = '{\"fw\": {\"state\": \"confirmed\"}}' WHERE actor_ip = '203.0.113.30'")
            self.denied("INSERT INTO blocklist (actor_ip, enforcement) VALUES ('203.0.113.31', '{}')")
            # 해제 · 연장처럼 enforcement 를 건드리지 않는 갱신은 그대로 된다
            self.cur.execute("UPDATE blocklist SET expires_at = now() + interval '2 hours' WHERE actor_ip = '203.0.113.30'")
        with self.as_role("enforcer"):
            self.cur.execute("UPDATE blocklist SET enforcement = '{\"fw\": {\"state\": \"pending\"}}' WHERE actor_ip = '203.0.113.30'")
            self.cur.execute("UPDATE blocklist SET enforcement = NULL WHERE actor_ip = '203.0.113.30'")

    def test_시험_출발지의_사건은_규칙_품질에서_빠진다(self):
        self.incident("R102|w2|203.0.113.10|t", "203.0.113.10", "benign_positive")
        self.incident("R102|w2|8.8.8.8|t", "8.8.8.8", "threat")
        self.assertEqual(self.quality().get("R102 w2"), (1, 1))
        self.assertEqual(self.q("SELECT cidr::text FROM test_ranges ORDER BY cidr"),
                         [("192.0.2.0/24",), ("198.51.100.0/24",), ("203.0.113.0/24",)])

    def test_역할_블록을_다시_적용해도_콘솔_집계는_된다(self):
        self.incident("R102|w2|203.0.113.20|t", "203.0.113.20", "benign_positive")
        roles = read(os.path.join(ROOT, "infra", "migrations", "20260924_db_roles.sql"))
        self.cur.execute(self.sub(roles.replace("BEGIN;", "").replace("COMMIT;", "")))
        with self.as_role("console"):
            self.denied("SELECT count(*) FROM test_ranges")                 # 표 권한은 거둬졌다
            self.assertEqual(self.one("SELECT is_test_source('203.0.113.20'::inet), is_test_source('8.8.8.8'::inet),"
                                      " is_test_source(NULL)"), (True, False, False))
            self.q("SELECT * FROM rule_quality")                          # 뷰도 된다

    def test_47_마이그레이션을_다시_적용하면_enforcement_권한이_빠지고_51_로_되살아난다(self):
        m47 = read(os.path.join(ROOT, "infra", "migrations", "20260927_block_enforce.sql"))
        self.cur.execute(self.sub(m47.replace("BEGIN;", "").replace("COMMIT;", "")))
        priv = "SELECT has_column_privilege(%s, 'blocklist', 'enforcement', 'UPDATE')"
        self.assertEqual(self.one(priv, (self.roles["enforcer"],)), (False,))
        self.cur.execute(self.sub(read(MIGRATION).replace("BEGIN;", "").replace("COMMIT;", "")))
        self.assertEqual(self.one(priv, (self.roles["enforcer"],)), (True,))

    def test_집행_역할은_enforcement_만_더_쓰고_콘솔은_시험_대역을_읽기만_한다(self):
        self.put("203.0.113.10")
        with self.as_role("enforcer"):
            self.cur.execute("UPDATE blocklist SET enforcement = %s::jsonb WHERE actor_ip = %s",
                             ('{"gateway": {"state": "pending"}}', "203.0.113.10"))
            self.denied("UPDATE blocklist SET released_at = now() WHERE actor_ip = %s", ("203.0.113.10",))
            self.denied("SELECT count(*) FROM test_ranges")
        self.assertEqual(self.one("SELECT enforcement ->> 'gateway' FROM blocklist WHERE actor_ip = %s", ("203.0.113.10",))[0],
                         '{"state": "pending"}')
        with self.as_role("console"):
            self.assertEqual(len(self.q("SELECT cidr FROM test_ranges")), 3)
            self.denied("INSERT INTO test_ranges (cidr, note) VALUES ('192.0.2.0/24', 'x')")
        # enforcement 갱신은 감사 이벤트를 만들지 않는다
        self.assertEqual([e for e in self.events_of("203.0.113.10") if e.startswith("console.block.enf")], [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
