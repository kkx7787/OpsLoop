"""격리 DB에서 재적용 · 최소 권한 · 최신 한 행을 검증한다. 운영 DB는 건드리지 않는다."""
import importlib.util
from pathlib import Path
import unittest

import test_block_enforce_db as base

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT/'infra/migrations/20261003_data_node_health.sql'
spec=importlib.util.spec_from_file_location('data_health_collector', ROOT/'collector/data_node_health.py')
collector=importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)


@unittest.skipUnless(base.URL and base.psycopg2, 'PostgreSQL 시험 연결 미지정')
class DataNodeHealthDatabaseTests(base.DbCase):
    @classmethod
    def setUpClass(cls):
        cls.create()
        for source in (ROOT/'infra/schema.sql', ROOT/'infra/schema.sql', MIGRATION, MIGRATION):
            cls.scur.execute(cls.sub(source.read_text()))
        cls.connect()

    def test_latest_one_row_and_console_readonly(self):
        result={'cpu_pct':10,'mem_used_pct':40,'load1':0.5,'disks':[{'labels':['루트','PostgreSQL','Loki'],
                 'used_pct':20,'available_bytes':9000000000,'inode_used_pct':1}], 'problems':[]}
        with self.as_role('ingest'):
            # 같은 SQL을 두 번 실행해도 행이 늘지 않는다.
            for cpu in (10,20):
                result['cpu_pct']=cpu
                import json
                self.cur.execute(collector.UPSERT, (cpu,40,0.5,json.dumps(result['disks']),[]))
        with self.as_role('console'):
            self.assertEqual(self.one('SELECT count(*), max(cpu_pct), bool_and(checked_at <= clock_timestamp()) FROM data_node_health'),(1,20,True))
            for sql in ('DELETE FROM data_node_health','UPDATE data_node_health SET cpu_pct=1','TRUNCATE data_node_health'):
                self.denied(sql)
        with self.as_role('ingest'):
            self.denied('DELETE FROM data_node_health')
            self.denied('TRUNCATE data_node_health')
        with self.as_role('detector'):
            self.denied('SELECT * FROM data_node_health')

    def test_invalid_second_key_and_metrics_rejected(self):
        for sql in ("INSERT INTO data_node_health(singleton,disks) VALUES(false,'[{}]')",
                    "INSERT INTO data_node_health(disks,cpu_pct) VALUES('[{}]',101)",
                    "INSERT INTO data_node_health(disks) VALUES('{}')",
                    "INSERT INTO data_node_health(disks) VALUES('[]')"):
            self.assertIsNotNone(self.fails(sql))

    def test_schema_and_migration_match(self):
        content=MIGRATION.read_text().replace('BEGIN;\n','',1).removesuffix('COMMIT;\n')
        self.assertIn(content, (ROOT/'infra/schema.sql').read_text())
