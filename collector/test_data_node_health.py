import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import data_node_health as h


class DataNodeHealthTests(unittest.TestCase):
    def test_shared_device_and_separate_device(self):
        stats = SimpleNamespace(f_blocks=100, f_bfree=40, f_bavail=30, f_frsize=4096, f_files=100, f_ffree=95)
        with patch.object(h.os, 'stat', side_effect=lambda p: SimpleNamespace(st_dev=1 if p != '/loki' else 2)), \
             patch.object(h.os, 'statvfs', return_value=stats) as vfs:
            rows = h.disk_stats({'root': '/', 'postgres': '/db', 'loki': '/loki'})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['labels'], ['루트', 'PostgreSQL'])
        self.assertEqual(rows[0]['used_pct'], 66.7)  # reserved blocks excluded, like df
        self.assertEqual(rows[0]['available_bytes'], 30*4096)
        self.assertEqual(vfs.call_count, 2)

    def test_missing_path_is_not_replaced_by_root(self):
        def stat(p):
            if p == '/missing': raise FileNotFoundError()
            return SimpleNamespace(st_dev=1)
        fs = SimpleNamespace(f_blocks=100, f_bfree=80, f_bavail=75, f_frsize=4096, f_files=0)
        with patch.object(h.os, 'stat', side_effect=stat), patch.object(h.os, 'statvfs', return_value=fs):
            rows = h.disk_stats({'root': '/', 'postgres': '/missing', 'loki': '/loki'})
        self.assertEqual(rows[0]['labels'], ['루트', 'Loki'])
        self.assertTrue(rows[1]['error'])
        self.assertIsNone(rows[1]['used_pct'])

    def test_cpu_excludes_guest_and_counts_iowait_idle(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'stat'; p.write_text('cpu 10 0 20 100 20 0 0 0 7 0\ncpu0 0\n')
            self.assertEqual(h.cpu_ticks(p), (150, 120))
        self.assertEqual(h.cpu_percent((150, 120), (250, 170)), 50)
        for after in [(150,120), (140,120), (200,180)]:
            with self.assertRaises(ValueError): h.cpu_percent((150,120),after)

    def test_memory_uses_available_not_free(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'mem'; p.write_text('MemTotal: 2000 kB\nMemFree: 50 kB\nMemAvailable: 800 kB\n')
            self.assertEqual(h.memory_percent(p), 60)

    def test_partial_sample_keeps_disks(self):
        with patch.object(h, 'cpu_ticks', side_effect=OSError()), patch.object(h, 'memory_percent', return_value=40), \
             patch.object(h.os, 'getloadavg', return_value=(0.5,0,0)), patch.object(h,'disk_stats',return_value=[{'labels':['루트']} ]):
            got=h.sample({})
        self.assertIsNone(got['cpu_pct'])
        self.assertEqual(got['mem_used_pct'],40)
        self.assertEqual(got['problems'],['CPU 측정 실패'])
        self.assertTrue(got['disks'])

    def test_paths_and_role_validation(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'env'; p.write_text('DATABASE_URL=postgresql://opsloop_ingest:unit-test@db/opsloop\n')
            self.assertIn('opsloop_ingest', h.database_url(p))
            p.write_text('DATABASE_URL=postgresql://opsloop:unit-test@db/opsloop\n')
            with self.assertRaises(ValueError): h.database_url(p)
            p.write_text(json.dumps({'root':'/','postgres':'/db','loki':'/loki'}))
            self.assertEqual(h.load_paths(p)['root'],'/')
            p.write_text(json.dumps({'root':'/','postgres':'relative','loki':'/loki'}))
            with self.assertRaises(ValueError): h.load_paths(p)

    def test_check_does_not_read_database_credentials(self):
        out=io.StringIO()
        with patch.object(h,'load_paths',return_value={}), patch.object(h,'sample',return_value={'disks':[]}), \
             patch.object(h,'database_url',side_effect=AssertionError('must not connect')), contextlib.redirect_stdout(out):
            self.assertEqual(h.main(['--check']),0)
        self.assertEqual(json.loads(out.getvalue()),{'disks':[]})

    def test_errors_do_not_print_secrets(self):
        out=io.StringIO()
        with patch.object(h,'load_paths',side_effect=ValueError('secret-canary')), contextlib.redirect_stderr(out):
            self.assertEqual(h.main([]),1)
        self.assertNotIn('secret-canary',out.getvalue())
        self.assertIn('ValueError',out.getvalue())
