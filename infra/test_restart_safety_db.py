"""#130: 제한 DB 역할의 집행 증거 위조 거부와 요청·집행 경로 보존."""
import unittest
from pathlib import Path
import test_block_enforce_db as base


@unittest.skipUnless(base.URL, '임시 PostgreSQL 필요')
class EnforcementGuardTest(base.DbCase):
    @classmethod
    def setUpClass(cls):
        cls.create()
        cls.scur.execute(cls.sub(base.read(base.SCHEMA)))
        cls.connect()

    def test_console_cannot_forge_any_legacy_result(self):
        self.cur.execute("INSERT INTO blocklist(actor_ip) VALUES ('203.0.113.90')")
        for col, value in [('method', "'forged'"), ('enforced_at', 'now()'), ('enforce_note', "'관문 반영'"),
                           ('enforcement', "'{}'::jsonb")]:
            with self.as_role('console', actor='test'):
                self.denied(f"UPDATE blocklist SET {col}={value} WHERE actor_ip='203.0.113.90'")
                self.denied(f"INSERT INTO blocklist(actor_ip,{col}) VALUES ('203.0.113.91',{value})")
        with self.as_role('enforcer'):
            self.cur.execute("UPDATE blocklist SET method='gateway', enforced_at=now(), enforce_note='관문 반영' WHERE actor_ip='203.0.113.90'")
        with self.as_role('console', actor='test'):
            self.cur.execute("UPDATE blocklist SET expires_at=now()+interval '1 hour' WHERE actor_ip='203.0.113.90'")
            self.cur.execute("UPDATE blocklist SET released_at=now(), released_by='test' WHERE actor_ip='203.0.113.90'")
        self.assertEqual(self.one("SELECT method FROM blocklist WHERE actor_ip='203.0.113.90'")[0], 'gateway')

    def test_catalog_matches_restore_expectations(self):
        # 운영 설치는 기본 스키마 뒤 실시간 알림 트리거도 설치한다.
        self.cur.execute(self.sub(base.read(str(Path(__file__).parent/'notify.sql'))))
        queries = base.load('restart_restore_queries', str(Path(__file__).parent/'vmware/restore-drill/queries.py'))
        got = {
            'tables': self.one("SELECT count(*) FROM pg_tables WHERE schemaname='public'")[0],
            'fk': self.one("SELECT count(*) FROM pg_constraint WHERE connamespace='public'::regnamespace AND contype='f'")[0],
            'functions': self.one("SELECT count(*) FROM pg_proc WHERE pronamespace='public'::regnamespace")[0],
            'triggers': self.one("SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace AND NOT t.tgisinternal")[0],
            'views': self.one("SELECT count(*) FROM pg_views WHERE schemaname='public'")[0],
        }
        self.assertEqual(got, queries.EXPECT)
        self.assertIn('console_session_revocations', queries.TABLES)

    def test_repeat_migration_keeps_enforcement_evidence(self):
        self.cur.execute("INSERT INTO blocklist(actor_ip,method,enforced_at,enforce_note) VALUES ('203.0.113.90','gateway',now(),'evidence')")
        before = self.one("SELECT to_jsonb(b) FROM blocklist b WHERE actor_ip='203.0.113.90'")
        path = Path(__file__).parent / 'migrations/20261018_restart_safety.sql'
        body = path.read_text().split('BEGIN;\n',1)[1].removesuffix('COMMIT;\n')
        for _ in range(2):
            self.cur.execute(self.sub(body))
        self.assertEqual(self.one("SELECT to_jsonb(b) FROM blocklist b WHERE actor_ip='203.0.113.90'"), before)


@unittest.skipUnless(base.URL, '임시 PostgreSQL 필요')
class UpgradeTest(base.DbCase):
    @classmethod
    def setUpClass(cls):
        cls.create()
        # 현재 스키마의 #130 블록 직전 상태가 이번 수정의 업그레이드 출발점이다.
        before = base.read(base.SCHEMA).split('-- #130:', 1)[0]
        cls.scur.execute(cls.sub(before))
        cls.connect()

    def test_existing_data_upgrade_and_new_permissions(self):
        self.cur.execute("INSERT INTO blocklist(actor_ip,method,enforced_at,enforce_note) VALUES ('203.0.113.90','gateway',now(),'before-upgrade')")
        path = Path(__file__).parent / 'migrations/20261018_restart_safety.sql'
        body = path.read_text().split('BEGIN;\n',1)[1].removesuffix('COMMIT;\n')
        self.cur.execute(self.sub(body))
        self.assertEqual(self.one("SELECT enforce_note FROM blocklist WHERE actor_ip='203.0.113.90'")[0], 'before-upgrade')
        with self.as_role('console', actor='test'):
            self.denied("UPDATE blocklist SET method='forged' WHERE actor_ip='203.0.113.90'")
            self.cur.execute("SELECT console_session_revoke(repeat('a',64), now()+interval '1 hour')")
            self.assertEqual(self.one("SELECT count(*) FROM console_session_revocations")[0], 1)
            self.denied("DELETE FROM console_session_revocations")


if __name__ == '__main__':
    unittest.main()
