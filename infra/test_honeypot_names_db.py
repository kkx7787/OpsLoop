#!/usr/bin/env python3
"""허니팟 명칭 데이터 마이그레이션(이슈 #78 · #84) 시험.  python3 infra/test_honeypot_names_db.py

DB 없이 도는 글자 시험: 마이그레이션(infra/migrations/20261004_honeypot_names.sql)이 머리 주석과 한 트랜잭션 안의 UPDATE 한 문장뿐인지,
바꾸는 글자가 schema.sql 초기값(새 글자) · 20260927_block_enforce.sql 초기값(옛 글자)과 같은지, schema.sql 에 옛 글자가 없는지 본다.

OPSLOOP_TEST_DATABASE_URL 이 슈퍼유저 연결이면 infra/test_block_enforce_db.py 와 같은 방식(무작위 데이터베이스 · 역할)으로
schema.sql 을 적용한다. 옛 글자로 되돌린 DB 에 마이그레이션 파일을 그대로 두 번 적용해 그 줄의 메모만 바뀌는지(다른 줄 · 만든 시각
그대로), 새 DB 에는 아무것도 바꾸지 않는지, 20260927 을 다시 적용해도 새 글자가 남는지, 그 줄을 지우고 20260927 을 다시 적용했으면
이 파일을 다시 적용해 맞추는지, 차단 금지 대역 거부 사유가 새 글자인지 본다. 운영 DB · 운영 역할은 건드리지 않는다.
"""
import importlib.util
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "infra", "schema.sql")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20261004_honeypot_names.sql")
M47 = os.path.join(ROOT, "infra", "migrations", "20260927_block_enforce.sql")
BLOCK47 = os.path.join(ROOT, "infra", "test_block_enforce_db.py")

EIP = "15.164.37.49/32"
OLD_NOTE, NEW_NOTE = "AWS 관문 EIP", "허니팟 관문 EIP"
UPDATE = f"UPDATE block_exempt SET note = '{NEW_NOTE}' WHERE note = '{OLD_NOTE}';"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load("block47_for_78", BLOCK47)


class HoneypotNamesTextTest(unittest.TestCase):
    def test_마이그레이션은_머리_주석과_UPDATE_한_문장뿐이다(self):
        head, body = read(MIGRATION).split("\nBEGIN;\n", 1)
        self.assertTrue(all(ln.startswith("--") for ln in head.splitlines()))       # 머리는 주석뿐이다
        self.assertEqual(body, UPDATE + "\nCOMMIT;\n")                               # 표 · 권한 · 대역은 건드리지 않는다

    def test_바꾸는_글자는_두_초기값과_같다(self):
        self.assertIn((EIP, NEW_NOTE), MOD.seed(MOD.block47(read(SCHEMA))))       # 새 DB(schema.sql)는 이미 새 글자다
        self.assertIn((EIP, OLD_NOTE), MOD.seed(read(M47)))                        # 옛 DB 는 20260927 초기값 그대로다
        self.assertNotIn(OLD_NOTE, read(SCHEMA))


@unittest.skipUnless(MOD.SKIP is True, str(MOD.SKIP))
class HoneypotNamesDatabaseTest(MOD.DbCase):
    """schema.sql 을 적용한 무작위 DB. 옛 DB 는 그 줄의 메모를 옛 글자로 되돌려 만든다."""

    @classmethod
    def setUpClass(cls):
        cls.create()
        cls.scur.execute(cls.sub(read(SCHEMA)))
        cls.scur.execute("SELECT text(cidr), note, created_at FROM block_exempt ORDER BY cidr")
        cls.fresh = cls.scur.fetchall()
        # 옛 DB: 마이그레이션 파일을 그대로(BEGIN · COMMIT 포함) 두 번 적용한다
        cls.scur.execute("UPDATE block_exempt SET note = %s WHERE cidr = %s", (OLD_NOTE, EIP))
        for _ in range(2):
            cls.scur.execute(read(MIGRATION))
        cls.scur.execute("SELECT text(cidr), note, created_at FROM block_exempt ORDER BY cidr")
        cls.migrated = cls.scur.fetchall()
        cls.connect()

    def rows(self):
        return self.q("SELECT text(cidr), note, created_at FROM block_exempt ORDER BY cidr")

    def note(self):
        return self.one("SELECT note FROM block_exempt WHERE cidr = %s", (EIP,))[0]

    def apply(self, path):
        """시험 트랜잭션 안에서 적용한다(끝나면 되돌린다)."""
        self.cur.execute(self.sub(read(path).replace("BEGIN;", "").replace("COMMIT;", "")))

    def test_옛_DB_에_두_번_적용하면_그_줄의_메모만_새_글자다(self):
        # 대역 수 · 다른 줄 · 만든 시각은 그대로다. 새 DB(schema.sql 초기값)와 같아진다
        self.assertEqual(self.migrated, self.fresh)
        self.assertEqual([n for c, n, _ in self.migrated if c == EIP], [NEW_NOTE])
        self.assertEqual(len(self.migrated), len(MOD.EXEMPT))

    def test_새_DB_에는_바꿀_것이_없다(self):
        before = self.rows()
        self.apply(MIGRATION)
        self.assertEqual(self.cur.rowcount, 0)
        self.assertEqual(self.rows(), before)

    def test_20260927_을_다시_적용해도_새_글자가_남고_지운_줄은_이_파일로_맞춘다(self):
        self.apply(M47)
        self.assertEqual(self.note(), NEW_NOTE)                         # 있는 줄은 ON CONFLICT DO NOTHING
        self.cur.execute("DELETE FROM block_exempt WHERE cidr = %s", (EIP,))
        self.apply(M47)
        self.assertEqual(self.note(), OLD_NOTE)                         # 지운 줄은 옛 초기값으로 되살아난다
        self.apply(MIGRATION)
        self.assertEqual(self.note(), NEW_NOTE)

    def test_차단_금지_대역_거부_사유는_새_글자다(self):
        e = self.fails("INSERT INTO blocklist (actor_ip, reason) VALUES ('15.164.37.49', 'x')")
        self.assertEqual((e.pgcode, e.diag.constraint_name), ("23514", "blocklist_exempt"))
        self.assertIn(f"차단 금지 대역 {EIP} ({NEW_NOTE}) 에 속하는 주소다", e.diag.message_primary)


if __name__ == "__main__":
    unittest.main(verbosity=1)
