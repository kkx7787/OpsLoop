"""#27 PostgreSQL 통합 시험. 연결 전용 임시 테이블만 사용한다.

audit_event는 public 쓰기를 하므로 반드시 임시 감사 삽입으로 교체한다.
운영 데이터/계정/토큰은 만들지 않는다.
"""
import hashlib
import json
import os
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from fastapi import HTTPException, Response
import operations as ops

@unittest.skipUnless(os.environ.get('OPSLOOP_TEST_DATABASE_URL'), 'PostgreSQL 시험 연결 미지정')
class OperationsDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncpg
        self.conn=await asyncpg.connect(os.environ['OPSLOOP_TEST_DATABASE_URL'])
        await self.conn.execute('SET search_path TO pg_temp')
        await self.conn.execute('''
            CREATE TEMP TABLE nodes(node_id text PRIMARY KEY, hostname text, role text, sensor text,
                addr inet, logs text[], status text, token_hash text, registered_at timestamptz,
                last_seen_at timestamptz, first_loaded_at timestamptz, last_loaded_at timestamptz);
            CREATE TEMP TABLE node_enrollments(id bigserial PRIMARY KEY,node_id text REFERENCES nodes(node_id),
                token_hash text UNIQUE,issued_by text,issued_at timestamptz DEFAULT now(),expires_at timestamptz,
                used_at timestamptz,canceled_at timestamptz);
            CREATE TEMP TABLE incidents(incident_key text PRIMARY KEY,rule_id text,rule_version text,first_ts timestamptz);
            CREATE TEMP TABLE verdicts(id bigserial,incident_key text,verdict text,created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE rule_versions(rule_version text,definition jsonb,reason text,created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE detector_runs(id bigserial,rule_version text,since timestamptz,until timestamptz,
                started_at timestamptz,finished_at timestamptz,incidents integer);
            CREATE TEMP TABLE events(ts timestamptz,eventid text,username text,src_ip inet,input text,sensor text);
            CREATE FUNCTION pg_temp.audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'audit events are append-only'; END $$;
        ''')
        migration=Path(__file__).resolve().parents[1]/'infra/migrations/20260923_console_ops.sql'
        await self.conn.execute(migration.read_text().replace('EXECUTE FUNCTION audit_append_only()', 'EXECUTE FUNCTION pg_temp.audit_append_only()'))
        self.request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=SimpleNamespace(acquire=self.acquire))),
                                     state=SimpleNamespace(user={'u':'test-admin','r':'admin'}))
        self.body=ops.EnrollmentIn(node_id='test-node',hostname='test-node',addr='192.0.2.9',logs=['nginx'])
        self.audit_patch=patch.object(ops,'audit',self.temp_audit)
        self.audit_patch.start()

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def temp_audit(self,c,actor,event,detail):
        await c.execute("INSERT INTO events VALUES(now(),$1,$2,'192.0.2.1',$3,'audit')",event,actor,detail)

    async def asyncTearDown(self):
        self.audit_patch.stop()
        await self.conn.close()

    async def issue(self):
        response=Response()
        result=await ops.issue_enrollment(self.body,self.request,response)
        self.assertEqual(response.headers['cache-control'],'no-store')
        return result

    async def test_issue_hash_only_expiry_audit_and_atomic_reissue(self):
        first=await self.issue()
        self.assertTrue(first['token'].startswith('olE_'))
        self.assertEqual(first['expires_at']-first['issued_at'],timedelta(hours=1))
        row=await self.conn.fetchrow('SELECT * FROM node_enrollments')
        self.assertEqual(row['token_hash'],hashlib.sha256(first['token'].encode()).hexdigest())
        second=await self.issue()
        self.assertNotEqual(first['token'],second['token'])
        self.assertIsNotNone(await self.conn.fetchval('SELECT canceled_at FROM node_enrollments WHERE id=$1',first['id']))
        listing=await ops.nodes(self.request)
        self.assertNotIn('token_hash',listing['rows'][0])
        self.assertNotIn(first['token'],json.dumps(listing,default=str))
        details=await self.conn.fetchval('SELECT string_agg(detail, chr(10)) FROM audit_log')
        self.assertIn('node=test-node',details)
        self.assertNotIn(first['token'],details)
        self.assertNotIn(row['token_hash'],details)

    async def test_conflicting_target_does_not_cancel_existing_token(self):
        first=await self.issue()
        body=self.body.model_copy(update={'addr':'192.0.2.20'})
        with self.assertRaises(HTTPException) as error:
            await ops.issue_enrollment(body,self.request,Response())
        self.assertEqual(error.exception.status_code,409)
        self.assertIsNone(await self.conn.fetchval('SELECT canceled_at FROM node_enrollments WHERE id=$1',first['id']))
        self.assertEqual(await self.conn.fetchval('SELECT count(*) FROM node_enrollments'),1)

    async def test_audit_failure_rolls_back_issuance_and_previous_cancellation(self):
        first=await self.issue()
        async def failed(*args): raise RuntimeError('audit unavailable')
        with patch.object(ops,'audit',failed),self.assertRaises(RuntimeError):
            await self.issue()
        self.assertEqual(await self.conn.fetchval('SELECT count(*) FROM node_enrollments'),1)
        self.assertIsNone(await self.conn.fetchval('SELECT canceled_at FROM node_enrollments WHERE id=$1',first['id']))

    async def test_cancel_idempotent_and_used_or_other_node_rejected(self):
        first=await self.issue()
        await ops.cancel_enrollment('test-node',first['id'],self.request)
        await ops.cancel_enrollment('test-node',first['id'],self.request)
        self.assertEqual(await self.conn.fetchval("SELECT count(*) FROM audit_log WHERE eventid='console.node.token.canceled'"),1)
        second=await self.issue()
        await self.conn.execute('UPDATE node_enrollments SET used_at=now() WHERE id=$1',second['id'])
        for node,status in [('test-node',409),('other',404)]:
            with self.assertRaises(HTTPException) as error:
                await ops.cancel_enrollment(node,second['id'],self.request)
            self.assertEqual(error.exception.status_code,status)

    async def test_reception_status_and_expired_enrollments(self):
        await self.issue()
        await self.conn.execute("""INSERT INTO nodes(node_id,status,registered_at,last_seen_at) VALUES
            ('normal','active',now()-interval '1 day',now()-interval '9 minutes'),
            ('silent','active',now()-interval '1 day',now()-interval '11 minutes'),
            ('never','active',now()-interval '11 minutes',NULL),
            ('new','active',now(),NULL),('revoked','revoked',now(),now())""")
        data=await ops.nodes(self.request)
        self.assertEqual({r['node_id']:r['reception'] for r in data['rows']},
            {'test-node':'waiting','normal':'normal','silent':'silent','never':'silent','new':'waiting','revoked':'revoked'})

    async def test_quality_latest_verdict_default_contract_and_half_open_interval(self):
        await self.conn.execute("""INSERT INTO incidents VALUES
            ('a','R001','v1','2026-09-22'),('b','R001','v1','2026-09-23'),('c','R001','v1','2026-09-23');
            INSERT INTO verdicts(incident_key,verdict,created_at) VALUES
            ('a','false_positive','2026-09-23'),('a','threat','2026-09-23'),
            ('b','undetermined','2026-09-23'),('c','benign_positive','2026-09-23');
            INSERT INTO rule_versions(rule_version,definition,reason) VALUES
            ('v1','{"rules":[{"id":"R001","name":"시험","enabled":true}]}','초안');""")
        result=await ops.quality(self.request)
        self.assertIsInstance(result,list)
        row=result[0]
        self.assertEqual((row['incidents'],row['judged'],row['threats'],row['false_positives']),(3,3,1,0))
        self.assertEqual(float(row['non_action_rate']),50.0)
        details=await ops.quality(self.request,True)
        self.assertEqual(details['rows'][0],row)
        start=datetime(2026,9,22,tzinfo=timezone.utc)
        scoped=await ops.quality(self.request,True,start,start+timedelta(days=1))
        self.assertEqual(scoped['rows'][0]['incidents'],1)
        self.assertEqual(scoped['rows'][0]['threats'],1)
        self.assertEqual(scoped['versions'][0]['rules'][0]['name'],'시험')

    async def test_audit_target_actor_time_literal_filters_and_page(self):
        await self.conn.execute("""INSERT INTO events VALUES
            ('2026-09-22','console.block.released','Admin','192.0.2.1','by=Admin ip=192.0.2.8 reason=ok','audit'),
            ('2026-09-23','console.node.token.issued','Admin','192.0.2.1','by=Admin node=web-01 enrollment=1','audit'),
            ('2026-09-23','console.login.failed','Admin','192.0.2.1','ignored','console');""")
        async def query(**kw):
            return await ops.audit_log(self.request,**(dict(actor='',target='',since=None,until=None,limit=25,offset=0)|kw))
        self.assertEqual((await query(actor='admin'))['total'],2)
        self.assertEqual((await query(target='web-'))['rows'][0]['target'],'web-01')
        self.assertEqual((await query(actor='%'))['total'],0)
        self.assertEqual((await query(target='enrollment'))['total'],0)
        paged=await query(limit=1,offset=1)
        self.assertEqual(paged['total'],2)
        self.assertEqual(paged['rows'][0]['target'],'192.0.2.8')
        start=datetime(2026,9,22,tzinfo=timezone.utc)
        self.assertEqual((await query(since=start,until=start+timedelta(days=1)))['total'],1)

    async def test_token_audit_is_append_only_in_migration(self):
        import asyncpg
        await self.issue()
        for sql in ['DELETE FROM events',"UPDATE events SET input='changed'"]:
            with self.assertRaises(asyncpg.RaiseError):
                await self.conn.execute(sql)
        self.assertEqual(await self.conn.fetchval('SELECT count(*) FROM audit_log'),1)
