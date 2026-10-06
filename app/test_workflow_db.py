"""#105: 실제 DB 역할·배정·동시 쓰기·이력 보존 검사."""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from test_accounts_db import DbCase, db_url
import accounts
import main
import workflow


class WorkflowDB(DbCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.seed(('boss', 'admin'), ('one', 'operator'), ('two', 'operator'), ('view', 'viewer'))
        await self.owner.execute("""INSERT INTO incidents(incident_key, rule_id, rule_version, severity, actor_ip,
            first_ts, last_ts, signal_count) VALUES ('case','R102','w2','medium','203.0.113.10',now(),now(),1)""")

    def req(self, name='one', pool=None):
        return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=pool or self.pool)),
            state=SimpleNamespace(user={'u': name, 'r': 'admin' if name=='boss' else 'viewer' if name=='view' else 'operator'}))

    async def current(self):
        return await self.owner.fetchval(workflow.VERSION_SQL, 'case')

    async def assign(self, who, target, version=None):
        return await workflow.assign('case', workflow.AssignmentIn(username=target, expected_version=version or await self.current()), self.req(who))

    async def test_claim_release_reassignment_and_audit(self):
        first = await self.assign('one', 'one')
        self.assertNotEqual(first['workflow_version'], '0:0')
        for target in ('two', None):
            with self.assertRaises(HTTPException) as e:
                await self.assign('two', target)
            self.assertEqual(e.exception.status_code, 403)
        await self.assign('boss', 'two')
        await self.assign('two', None)
        rows = await self.owner.fetch("SELECT action, operator, note FROM actions ORDER BY id")
        self.assertEqual([(r['action'], r['operator']) for r in rows], [('assign','one'),('assign','boss'),('assign','two')])
        self.assertEqual(rows[-1]['note'], '담당 two → 미배정')
        self.assertIsNone(await self.owner.fetchval("SELECT assigned_to FROM incidents WHERE incident_key='case'"))

    async def test_inactive_owner_can_be_taken_over_and_invalid_target_cannot_be_assigned(self):
        await self.assign('one', 'one')
        await accounts.set_active(accounts.ActiveIn(username='one', active=False), self.req('boss'))
        await self.assign('two', 'two')
        for target in ('one', 'view', 'missing'):
            with self.assertRaises(HTTPException) as e:
                await self.assign('boss', target)
            self.assertEqual(e.exception.status_code, 409)

    async def test_assigned_user_delete_is_clear_conflict_and_noop_does_not_add_history(self):
        await self.assign('boss', 'two')
        before = await self.current()
        await self.assign('boss', 'two')
        self.assertEqual(await self.current(), before)
        listing = await accounts.list_accounts(self.req('boss'))
        self.assertFalse(next(a for a in listing['accounts'] if a['username']=='two')['deletable'])
        await self.console.execute("SELECT set_config('opsloop.actor', 'boss', false)")
        self.assertEqual(await self.console.fetchval('SELECT console_account_delete($1)', 'two'), 'assigned')

    async def test_missing_version_and_viewer_cannot_mutate(self):
        for who, expected in [('one',428),('view',403)]:
            with self.assertRaises(HTTPException) as e:
                await workflow.assign('case', workflow.AssignmentIn(username=who), self.req(who))
            self.assertEqual(e.exception.status_code, expected)
        with patch.object(main.app.state, 'pool', self.pool, create=True):
            for handler, body in [(main.add_verdict, main.VerdictIn(verdict='threat')), (main.add_action, main.ActionIn(action='acknowledge'))]:
                with self.assertRaises(HTTPException) as e:
                    await handler('case', body, self.req())
                self.assertEqual(e.exception.status_code, 428)
        self.assertEqual(await self.current(), '0:0')

    async def test_stale_verdict_preserves_history_and_signal_growth_does_not_conflict(self):
        await self.owner.execute("UPDATE incidents SET signal_count=9 WHERE incident_key='case'")
        with patch.object(main.app.state, 'pool', self.pool, create=True):
            first = await main.add_verdict('case', main.VerdictIn(verdict='threat', expected_version='0:0'), self.req())
            for handler, body in [(main.add_verdict, main.VerdictIn(verdict='false_positive',expected_version='0:0')),
                                  (main.add_action, main.ActionIn(action='acknowledge',expected_version='0:0'))]:
                with self.assertRaises(HTTPException) as e:
                    await handler('case', body, self.req('two'))
                self.assertEqual(e.exception.status_code, 409)
            revised = await main.add_verdict('case', main.VerdictIn(verdict='false_positive',expected_version=first['workflow_version']), self.req('two'))
            self.assertNotEqual(first['workflow_version'], revised['workflow_version'])
        self.assertEqual(await self.owner.fetchval('SELECT count(*) FROM verdicts'), 2)
        self.assertEqual(await self.owner.fetchval('SELECT count(*) FROM actions'), 0)

    async def test_list_verdict_actor_and_time_belong_to_latest_verdict(self):
        async with self.console.transaction(isolation='repeatable_read', readonly=True):
            row = (await main.incident_page(self.console))['items'][0]
        self.assertIsNone(row['verdict_operator'])
        self.assertIsNone(row['verdict_at'])
        with patch.object(main.app.state, 'pool', self.pool, create=True):
            first = await main.add_verdict('case', main.VerdictIn(verdict='threat', expected_version='0:0'), self.req())
            await main.add_verdict('case', main.VerdictIn(verdict='false_positive', expected_version=first['workflow_version']), self.req('two'))
        async with self.console.transaction(isolation='repeatable_read', readonly=True):
            row = (await main.incident_page(self.console))['items'][0]
        latest = await self.owner.fetchrow('SELECT operator, created_at FROM verdicts ORDER BY id DESC LIMIT 1')
        self.assertEqual(row['verdict'], 'false_positive')
        self.assertEqual(row['verdict_operator'], 'two')
        self.assertEqual(row['verdict_at'], latest['created_at'].isoformat())
        self.assertEqual(await self.owner.fetchval('SELECT count(*) FROM verdicts'), 2)

    async def test_two_connections_compete_for_assignment_or_verdict_only_one_succeeds(self):
        import asyncpg
        async def auth(conn): await conn.execute(f'SET SESSION AUTHORIZATION {self.role}')
        pool = await asyncpg.create_pool(db_url(self.dbname), min_size=2, max_size=4, init=auth)
        try:
            with patch.object(main.app.state, 'pool', pool, create=True):
                out = await asyncio.gather(
                    workflow.assign('case', workflow.AssignmentIn(username='one',expected_version='0:0'), self.req('one',pool)),
                    main.add_verdict('case', main.VerdictIn(verdict='threat',expected_version='0:0'), self.req('two',pool)),
                    return_exceptions=True)
                self.assertEqual(sum(isinstance(x,dict) for x in out), 1)
                self.assertEqual([x.status_code for x in out if isinstance(x,HTTPException)], [409])
                self.assertEqual(await self.owner.fetchval('SELECT (SELECT count(*) FROM verdicts)+(SELECT count(*) FROM actions)'),1)
        finally:
            await pool.close()

    async def test_assignee_filters_and_detail_read_the_same_saved_assignment(self):
        await self.assign('one', 'one')
        # #73 장비 조회는 전체 스키마를 사용한다. 담당 조건은 쪽 나누기 전에 적용한다.
        async with self.console.transaction(isolation='repeatable_read', readonly=True):
            mine = await main.incident_page(self.console, assignment='mine', username='one')
            other = await main.incident_page(self.console, assignment='mine', username='two')
            unassigned = await main.incident_page(self.console, assignment='unassigned')
        self.assertEqual((mine['total'],other['total'],unassigned['total']), (1,0,0))
        self.assertEqual(mine['items'][0]['assigned_to'],'one')
        self.assertTrue(mine['items'][0]['assignee_available'])
        with patch.object(main.app.state, 'pool', self.pool, create=True):
            detail = await main.get_incident('case')
        self.assertEqual(detail['assigned_to'], 'one')
        self.assertEqual(detail['workflow_version'],await self.current())

    async def test_workflow_migration_is_repeatable_without_resetting_assignment(self):
        import re
        from pathlib import Path
        await self.assign('one', 'one')
        before = await self.current()
        sql = Path(__file__).resolve().parents[1].joinpath('infra/migrations/20261003_incident_workflow.sql').read_text()
        for _ in range(2):
            await self.owner.execute(re.sub(r'\bopsloop_console\b', self.role, sql))
        self.assertEqual(await self.owner.fetchval("SELECT assigned_to FROM incidents WHERE incident_key='case'"),'one')
        self.assertEqual(await self.current(),before)
