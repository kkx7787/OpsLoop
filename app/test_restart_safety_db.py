"""#130: 두 콘솔 세션 철회, 재생 공격, 권한·마이그레이션을 실제 임시 DB로 검증."""
import hashlib
import re
import unittest
from pathlib import Path
from unittest.mock import patch

import test_accounts_db as db
import auth
import main


@unittest.skipUnless(db.URL, '임시 PostgreSQL 필요')
class SessionRevocationTest(db.DbCase):
    async def test_logout_replay_http_ws_and_other_session(self):
        import httpx
        import asyncpg
        await self.seed(('op', 'operator'))
        login = await auth.authenticate(self.pool, 'op', db.PASSWORD)
        token = auth.issue('op', 'operator', login['issued_at'])
        other = auth.issue('op', 'operator', login['issued_at'])
        self.assertNotEqual(token, other, '동시 로그인도 서로 다른 세션')
        headers = {'cookie': f'{auth.COOKIE}={token}', 'origin': 'http://testserver'}
        old_pool = getattr(main.app.state, "pool", None)
        main.app.state.pool = self.pool
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://testserver') as c:
                self.assertEqual((await c.get('/api/me', headers=headers)).status_code, 200)
                self.assertTrue(await main.ws_session_valid(token))
                self.assertEqual((await c.post('/logout', headers=headers)).status_code, 302)
                self.assertEqual((await c.get('/api/me', headers=headers)).status_code, 401)
                self.assertFalse(await main.ws_session_valid(token))
                self.assertTrue(await main.ws_session_valid(other))
                self.assertEqual((await c.post('/logout', headers=headers)).status_code, 302)
        finally:
            main.app.state.pool = old_pool
        # 다른 콘솔에 해당하는 별도 DB 풀도 철회된 쿠키를 거부한다.
        pool_b = await asyncpg.create_pool(db.db_url(self.dbname), min_size=1, max_size=1,
                                         server_settings={'session_authorization': self.role})
        try:
            self.assertIsNone(await auth.lookup(pool_b, 'op', token))
            self.assertIsNotNone(await auth.lookup(pool_b, 'op', other))
        finally:
            await pool_b.close()
        row = await self.owner.fetchrow('SELECT token_hash, expires_at FROM console_session_revocations WHERE token_hash=$1',
                                       hashlib.sha256(token.encode()).hexdigest())
        self.assertIsNotNone(row)
        self.assertNotIn(token, str(row))

    async def test_logout_db_failure_is_not_success(self):
        import httpx
        token = auth.issue('op', 'operator')
        old_pool = getattr(main.app.state, 'pool', None)
        main.app.state.pool = self.pool
        self.addAsyncCleanup(self.restore_pool, old_pool)
        with patch.object(auth, 'revoke', side_effect=OSError('unavailable')) as revoke:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://testserver') as c:
                r = await c.post('/logout', headers={'cookie': f'{auth.COOKIE}={token}', 'origin': 'http://testserver'})
        revoke.assert_awaited_once_with(self.pool, token)
        self.assertEqual(r.status_code, 503)
        self.assertNotIn('set-cookie', r.headers)

    async def restore_pool(self, pool):
        main.app.state.pool = pool

    async def test_permissions_expiry_and_repeat_migration(self):
        import asyncpg
        await self.console.execute("SELECT console_session_revoke($1, now() + interval '1 hour')", 'a'*64)
        for sql in ("DELETE FROM console_session_revocations", "UPDATE console_session_revocations SET expires_at=now()",
                    "INSERT INTO console_session_revocations VALUES ('"+'b'*64+"',now())"):
            with self.assertRaises(asyncpg.InsufficientPrivilegeError):
                await self.console.execute(sql)
        await self.owner.execute("INSERT INTO console_session_revocations VALUES ($1, now() - interval '1 second')", 'c'*64)
        await self.console.execute("SELECT console_session_revoke($1, now() + interval '1 hour')", 'd'*64)
        self.assertEqual(await self.owner.fetchval("SELECT count(*) FROM console_session_revocations WHERE token_hash=$1", 'c'*64), 0)
        migration = Path(__file__).resolve().parents[1] / 'infra/migrations/20261018_restart_safety.sql'
        sql = re.sub(r'\bopsloop_console\b', self.role, migration.read_text())
        for _ in range(2):
            await self.owner.execute(sql)
        self.assertEqual(await self.owner.fetchval("SELECT count(*) FROM console_session_revocations WHERE token_hash=$1", 'a'*64), 1)
        with self.assertRaises(asyncpg.InvalidParameterValueError):
            await self.console.execute("SELECT console_session_revoke('invalid', now())")


if __name__ == '__main__':
    unittest.main()
