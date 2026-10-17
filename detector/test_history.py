"""삭제 전 추천 보존, 재등장 관계 정리, 롤백, 마이그레이션 재실행 시험."""
import json
import os
from pathlib import Path
import secrets
import unittest
import psycopg2

MIGRATION = Path(__file__).resolve().parents[1] / 'infra/migrations/20261017_incident_history.sql'


@unittest.skipUnless(os.environ.get('OPSLOOP_TEST_DATABASE_URL'), 'PostgreSQL required')
class IncidentHistoryTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg2.connect(os.environ['OPSLOOP_TEST_DATABASE_URL'])
        self.conn.autocommit = True
        self.cur = self.conn.cursor()
        self.schema = 'history_test_' + secrets.token_hex(6)
        self.cur.execute(f'CREATE SCHEMA {self.schema}; SET search_path TO {self.schema}')
        self.cur.execute('''CREATE TABLE incidents(incident_key text PRIMARY KEY, evidence jsonb, created_at timestamptz DEFAULT now());
            CREATE TABLE ai_recommendations(id serial, incident_key text REFERENCES incidents ON DELETE CASCADE, reasons jsonb);
            CREATE TABLE incident_absorbed(first_key text, member_key text, via_key text, recorded_at timestamptz DEFAULT now());
        ''')
        self.sql = MIGRATION.read_text().replace('public', self.schema)
        self.cur.execute(self.sql)

    def tearDown(self):
        self.conn.rollback()
        self.conn.autocommit = True
        self.cur.execute(f'DROP SCHEMA {self.schema} CASCADE')
        self.conn.close()

    def test_removal_keeps_original_evidence_and_recommendation(self):
        self.cur.execute("INSERT INTO incidents VALUES ('child','{\"sample\":[\"original\"]}',now())")
        self.cur.execute("INSERT INTO ai_recommendations(incident_key,reasons) VALUES ('child','[\"reason\"]')")
        self.cur.execute("DELETE FROM incidents WHERE incident_key='child'")
        self.cur.execute('SELECT snapshot, recommendations FROM incident_history')
        snapshot, recs = self.cur.fetchone()
        self.assertEqual(snapshot['evidence']['sample'], ['original'])
        self.assertEqual(recs[0]['reasons'], ['reason'])
        self.cur.execute('SELECT count(*) FROM ai_recommendations')
        self.assertEqual(self.cur.fetchone()[0], 0)
        with self.assertRaises(psycopg2.Error):
            self.cur.execute('DELETE FROM incident_history')

    def test_reappeared_incident_is_not_an_active_absorption_member(self):
        self.cur.execute("INSERT INTO incident_absorbed VALUES ('parent','child',NULL,now())")
        self.cur.execute("INSERT INTO incidents VALUES ('child','{}',now())")
        self.cur.execute('SELECT count(*) FROM incident_absorbed')
        self.assertEqual(self.cur.fetchone()[0], 0)
        self.cur.execute('SELECT snapshot FROM incident_history')
        self.assertEqual(self.cur.fetchone()[0]['first_key'], 'parent')
        self.cur.execute(self.sql)  # 다시 적용해도 이력을 지우지 않는다.
        self.cur.execute('SELECT count(*) FROM incident_history')
        self.assertEqual(self.cur.fetchone()[0], 1)

    def test_transaction_failure_restores_event_and_history(self):
        self.cur.execute("INSERT INTO incidents VALUES ('child','{}',now())")
        self.conn.autocommit = False
        self.cur.execute("DELETE FROM incidents WHERE incident_key='child'")
        self.conn.rollback()
        self.cur.execute('SELECT count(*) FROM incidents')
        self.assertEqual(self.cur.fetchone()[0], 1)
        self.cur.execute('SELECT count(*) FROM incident_history')
        self.assertEqual(self.cur.fetchone()[0], 0)

    def test_identical_replay_does_not_grow_archive(self):
        for _ in range(3):
            self.cur.execute("INSERT INTO incidents VALUES ('child','{}',now())")
            self.cur.execute("DELETE FROM incidents WHERE incident_key='child'")
        self.cur.execute('SELECT count(*) FROM incident_history')
        self.assertEqual(self.cur.fetchone()[0], 1)

    def test_restricted_detector_can_archive_but_cannot_rewrite_history(self):
        role = 'history_role_' + secrets.token_hex(6)
        self.cur.execute(f'CREATE ROLE {role}')
        try:
            self.cur.execute(f'GRANT USAGE ON SCHEMA {self.schema} TO {role}')
            self.cur.execute(f'GRANT SELECT, INSERT, DELETE ON incidents TO {role}')
            self.cur.execute(f'SET ROLE {role}')
            self.cur.execute("INSERT INTO incidents VALUES ('restricted','{}',now())")
            self.cur.execute("DELETE FROM incidents WHERE incident_key='restricted'")
            with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                self.cur.execute("INSERT INTO incident_history(kind,incident_key,snapshot) VALUES ('removed','fake','{}')")
            self.cur.execute('RESET ROLE')
            self.cur.execute('SELECT count(*) FROM incident_history')
            self.assertEqual(self.cur.fetchone()[0], 1)
        finally:
            self.cur.execute('RESET ROLE')
            self.cur.execute(f'DROP OWNED BY {role}; DROP ROLE {role}')

    def test_schema_contains_exact_migration_body(self):
        body = MIGRATION.read_text().replace('BEGIN;\n', '', 1).removesuffix('COMMIT;\n')
        schema = (MIGRATION.parents[1] / 'schema.sql').read_text()
        self.assertIn(body, schema)
