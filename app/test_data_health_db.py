import json
from datetime import timedelta

import data_health as h
import targets
import test_accounts_db as db


class DataHealthDatabaseTests(db.DbCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.owner.execute('TRUNCATE data_node_health')
        self.now = await self.owner.fetchval('SELECT now()')

    async def test_card_and_band_read_same_fresh_and_stale_state(self):
        disks=[{'labels':['루트','PostgreSQL','Loki'], 'used_pct':90, 'available_bytes':4*h.GIB, 'inode_used_pct':10}]
        await self.owner.execute('INSERT INTO data_node_health(checked_at,cpu_pct,mem_used_pct,load1,disks) VALUES($1,10,40,0.5,$2)',
                                 self.now,json.dumps(disks))
        async with self.console.transaction(isolation='repeatable_read',readonly=True):
            body=await targets.targets_view(self.console,self.now)
            monitor=await targets.monitor_view(self.console,self.now)
        card=next(t for t in body['targets'] if t['id']=='data-node')['system']
        self.assertEqual(card['capacity'],'critical')
        self.assertEqual([a for a in monitor['items'] if a['key'].startswith('data_')],h.alerts(card))
        await self.owner.execute('UPDATE data_node_health SET checked_at=$1',self.now-timedelta(minutes=11))
        old=await h.read(self.console,self.now)
        self.assertEqual((old['state'],old['capacity']),('stale','unknown'))
        self.assertNotIn('alert',[a['level'] for a in h.alerts(old)])

    async def test_denied_and_missing_table_do_not_abort_read_transaction(self):
        await self.owner.execute(f'REVOKE SELECT ON data_node_health FROM {self.role}')
        async with self.console.transaction(readonly=True):
            got=await h.read(self.console,self.now)
            self.assertEqual(got['state'],'no_privilege')
            self.assertEqual(await self.console.fetchval('SELECT 1'),1)
        await self.owner.execute('DROP TABLE data_node_health')
        try:
            async with self.console.transaction(readonly=True):
                got=await h.read(self.console,self.now)
                self.assertEqual(got['state'],'no_data')
                self.assertIn('미설치',got['problems'][0])
                self.assertEqual(await self.console.fetchval('SELECT 1'),1)
        finally:
            import re
            migration=(db.SCHEMA.parent/'migrations/20261003_data_node_health.sql').read_text()
            await self.owner.execute(re.sub(r'\bopsloop_console\b',self.role,migration))
