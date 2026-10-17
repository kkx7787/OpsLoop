"""#129: 합성 자료와 실제 PostgreSQL로 재현성 경계를 검증한다."""
import copy
import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import psycopg2
from psycopg2.extras import execute_batch
import detect


class RegexIntegrityTests(unittest.TestCase):
    def test_postgres_quantity_limit(self):
        for pattern in ('a{256}', 'a{1,256}', 'a{256,}'):
            with self.subTest(pattern=pattern):
                self.assertIsNotNone(detect.regex_gap(pattern))
        for pattern in ('a{255}', 'a{1,255}', r'a\{256\}', '[{256}]'):
            self.assertIsNone(detect.regex_gap(pattern))


@unittest.skipUnless(os.environ.get('OPSLOOP_TEST_DATABASE_URL'), 'PostgreSQL required')
class DetectorIntegrityTests(unittest.TestCase):
    def setUp(self):
        batch = patch.object(detect, 'execute_batch', execute_batch)
        batch.start()
        self.addCleanup(batch.stop)
        self.conn = psycopg2.connect(os.environ['OPSLOOP_TEST_DATABASE_URL'])
        self.cur = self.conn.cursor()
        self.cur.execute('''SET search_path TO pg_temp;
            CREATE TEMP TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb, reason text);
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_version text,
                rule_name text, severity text, actor_ip inet, first_ts timestamptz, last_ts timestamptz,
                signal_count int, session_count int, evidence jsonb, status text DEFAULT 'open',
                created_at timestamptz DEFAULT now(), target text);
            CREATE TEMP TABLE actions (id bigint, incident_key text);
            CREATE TEMP TABLE verdicts (id bigint, incident_key text);
            CREATE TEMP TABLE events (ts timestamptz, src_ip inet, session text, sensor text,
                provenance text, eventid text);
        ''')
        self.doc = {'rule_version': 'test-integrity', 'aggregation': {'window_gap_seconds': 300},
                    'rules': [{'id': 'R001', 'name': 'test', 'type': 'actor_rate', 'severity': 'high',
                               'params': {'eventids': ['test'], 'window_seconds': 60, 'threshold': 1}}]}
        self.cur.execute("INSERT INTO events VALUES ('2026-10-01T00:00:00Z','192.0.2.1','s','cowrie','real','test')")
        self.conn.commit()

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def test_version_cannot_be_redefined(self):
        detect.run(self.conn, self.doc, None, None, verbose=False)
        changed = copy.deepcopy(self.doc)
        changed['rules'][0]['params']['threshold'] = 2
        with self.assertRaisesRegex(ValueError, '규칙 버전'):
            detect.run(self.conn, changed, None, None, verbose=False)
        self.conn.rollback()
        self.cur.execute('SELECT definition FROM rule_versions')
        self.assertEqual(self.cur.fetchone()[0], self.doc)
        self.cur.execute('SELECT count(*) FROM incidents')
        self.assertEqual(self.cur.fetchone()[0], 1)

    def test_timezone_does_not_change_incident_key(self):
        for tz in ('UTC', 'Asia/Seoul', 'America/New_York'):
            self.cur.execute('SET TIME ZONE %s', (tz,))
            detect.run(self.conn, self.doc, None, None, verbose=False)
        self.cur.execute('SELECT incident_key FROM incidents')
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 1, rows)
        self.assertIn('+00:00', rows[0][0])

    def test_partial_since_keeps_full_baseline_bucket(self):
        self.cur.execute('DELETE FROM events')
        start = datetime(2026, 10, 1, tzinfo=timezone.utc)
        for hour, count in enumerate([10, 20, 10, 20, 100]):
            for n in range(count):
                self.cur.execute("INSERT INTO events VALUES (%s,'192.0.2.1','s','cowrie','real','test')",
                                 (start + timedelta(hours=hour, minutes=1),))
        rule = {'id': 'R005', 'params': {'baseline_days': 1, 'settle_seconds': 1800,
                                       'min_buckets': 2, 'sigma': 2}}
        # since 전에 끝났으나 settle 중이던 시간 칸도 대상이다. 그 칸의 기준선 시작까지 읽어야 한다.
        lo = start + timedelta(days=1, hours=1, minutes=15)
        self.cur.execute("INSERT INTO events SELECT %s::timestamptz,'192.0.2.1','s','cowrie','real','test' FROM generate_series(1,200)",
                         (start + timedelta(days=1, minutes=1),))
        until = start + timedelta(days=1, hours=3)
        full = detect.signals_baseline_trailing(self.cur, rule, None, until)
        part = detect.signals_baseline_trailing(self.cur, rule, lo, until)
        relevant = [r for r in full if r[0] + timedelta(hours=1, minutes=30) >= lo]
        self.assertTrue(relevant)
        self.assertEqual(part, relevant)

    def test_quantifier_boundary_matches_real_postgres(self):
        self.cur.execute("SELECT %s ~ %s", ('a' * 255, '^a{255}$'))
        self.assertTrue(self.cur.fetchone()[0])
        with self.assertRaises(psycopg2.errors.InvalidRegularExpression):
            self.cur.execute("SELECT %s ~ %s", ('a' * 256, '^a{256}$'))
