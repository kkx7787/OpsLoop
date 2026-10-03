"""격리 PostgreSQL에서 A/B 공유 제한·권한·자동 해제·마이그레이션 반복 검증."""
import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

from test_accounts_db import DbCase, db_url
import login_limits


class LoginLimitDB(DbCase):
    async def test_schema_reapply_does_not_commit_callers_transaction(self):
        schema = (Path(__file__).resolve().parents[1] / 'infra/schema.sql').read_text()
        schema = re.sub(r'\bopsloop_console\b', self.role, schema)
        transaction = self.owner.transaction()
        await transaction.start()
        try:
            await self.owner.execute("INSERT INTO console_login_limits VALUES('transaction-test', now(), 1)")
            await self.owner.execute(schema)
        finally:
            await transaction.rollback()
        self.assertEqual(await self.owner.fetchval('SELECT count(*) FROM console_login_limits'), 0)

    async def take(self, ip='192.0.2.1', name='unknown'):
        request = SimpleNamespace(client=SimpleNamespace(host=ip))
        return await login_limits.take(self.pool, request, name)

    async def test_concurrent_consoles_only_admit_five_and_rejections_do_not_extend_window(self):
        import asyncpg
        async def role(conn):
            await conn.execute(f'SET SESSION AUTHORIZATION {self.role}')
        pool = await asyncpg.create_pool(db_url(self.dbname), min_size=2, max_size=12, init=role)
        try:
            request = SimpleNamespace(client=SimpleNamespace(host='192.0.2.1'))
            results = await asyncio.gather(*(login_limits.take(pool, request, 'absent') for _ in range(24)))
            self.assertEqual(results.count(0), 5)
            self.assertTrue(all(0 < r <= 60 for r in results if r))
            before = await self.owner.fetch('SELECT * FROM console_login_limits ORDER BY key')
            self.assertGreater(await login_limits.take(pool, request, 'absent'), 0)
            self.assertEqual(before, await self.owner.fetch('SELECT * FROM console_login_limits ORDER BY key'))
        finally:
            await pool.close()

    async def test_account_limit_across_ips_and_ip_limit_across_accounts(self):
        for n in range(10):
            self.assertEqual(await self.take(f'192.0.2.{n+1}', 'same'), 0)
        self.assertGreater(await self.take('192.0.2.99', 'same'), 0)
        await self.owner.execute('TRUNCATE console_login_limits')
        for n in range(30):
            self.assertEqual(await self.take(name=f'unknown{n}'), 0)
        self.assertGreater(await self.take(name='next'), 0)

    async def test_expiry_and_old_keys_cleanup(self):
        for _ in range(5):
            self.assertEqual(await self.take(), 0)
        self.assertGreater(await self.take(), 0)
        await self.owner.execute("UPDATE console_login_limits SET started_at=now()-interval '61 seconds'")
        self.assertEqual(await self.take(), 0)
        await self.owner.execute("UPDATE console_login_limits SET started_at=now()-interval '11 minutes'")
        self.assertEqual(await self.take('192.0.2.2', 'new'), 0)
        self.assertEqual(await self.owner.fetchval('SELECT count(*) FROM console_login_limits'), 3)

    async def test_console_cannot_edit_counters_and_migration_can_be_repeated(self):
        import asyncpg
        with self.assertRaises(asyncpg.InsufficientPrivilegeError):
            await self.console.execute('DELETE FROM console_login_limits')
        migration = Path(__file__).resolve().parents[1] / 'infra/migrations/20261003_login_limits.sql'
        sql = re.sub(r'\bopsloop_console\b', self.role, migration.read_text())
        await self.take()
        for _ in range(2):
            await self.owner.execute(sql)
        self.assertEqual(await self.owner.fetchval('SELECT max(attempts) FROM console_login_limits'), 1)
        self.assertEqual(await self.take(), 0)
        with self.assertRaises(asyncpg.RaiseError):
            await self.console.fetchval(login_limits.TAKE, 'bad', 'bad', 'bad')

    async def test_backup_role_can_read_new_table_but_cannot_change_limits(self):
        import asyncpg
        backup = self.role + '_backup'
        await self.owner.execute(f'CREATE ROLE {backup} NOLOGIN')
        try:
            sql = (Path(__file__).resolve().parents[1] / 'infra/migrations/20261003_login_limits.sql').read_text()
            sql = re.sub(r'\bopsloop_console\b', self.role, sql)
            sql = re.sub(r'\bopsloop_backup\b', backup, sql)
            await self.owner.execute(sql)
            await self.take()
            await self.owner.execute(f'SET ROLE {backup}')
            self.assertEqual(await self.owner.fetchval('SELECT count(*) FROM console_login_limits'), 3)
            with self.assertRaises(asyncpg.InsufficientPrivilegeError):
                await self.owner.execute('DELETE FROM console_login_limits')
            with self.assertRaises(asyncpg.InsufficientPrivilegeError):
                await self.owner.fetchval(login_limits.TAKE, 'a'*64, 'b'*64, 'c'*64)
        finally:
            await self.owner.execute('RESET ROLE')
            await self.owner.execute(f'DROP OWNED BY {backup}')
            await self.owner.execute(f'DROP ROLE {backup}')
