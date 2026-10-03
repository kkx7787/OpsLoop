"""자원 부족/미측정/오래됨이 같은 기준으로 카드와 이상 띠에 표시되는지 검증."""
import copy
from datetime import datetime, timedelta, timezone
import json
import unittest

import data_health as h

NOW = datetime(2026, 10, 3, tzinfo=timezone.utc)


def row(**changes):
    value = {'checked_at': NOW, 'cpu_pct': 12, 'mem_used_pct': 45, 'load1': 0.2,
             'disks': [{'labels': ['루트', 'PostgreSQL', 'Loki'], 'used_pct': 60,
                        'available_bytes': 8 * h.GIB, 'inode_used_pct': 5}], 'problems': []}
    value.update(changes)
    return value


class DataHealthTests(unittest.TestCase):
    def test_healthy_and_serialized_json(self):
        r = row()
        r['disks'] = json.dumps(r['disks'])
        got = h.view(r, NOW)
        self.assertEqual((got['state'], got['capacity'], got['metrics']['disk_root_pct']), ('ok', 'ok', 60))
        self.assertEqual(h.alerts(got), [])
        self.assertEqual(len(got['disks']), 1)

    def test_thresholds_capacity_free_and_inodes(self):
        for field, value, expected in [('used_pct', 79.9, 'ok'), ('used_pct', 80, 'warning'),
            ('used_pct', 90, 'critical'), ('available_bytes', 2*h.GIB, 'warning'),
            ('available_bytes', h.GIB, 'critical'), ('inode_used_pct', 90, 'warning'), ('inode_used_pct', 95, 'critical')]:
            with self.subTest(field=field, value=value):
                r = row(); r['disks'][0][field] = value
                got = h.view(r, NOW)
                self.assertEqual(got['capacity'], expected)
                self.assertEqual(len(h.alerts(got)), int(expected != 'ok'))
                if expected != 'ok':
                    self.assertEqual(h.alerts(got)[0]['level'], 'alert')

    def test_stale_boundary_and_future(self):
        for age, expected in [(600, 'ok'), (601, 'stale'), (-300, 'ok'), (-301, 'stale')]:
            got = h.view(row(checked_at=NOW-timedelta(seconds=age)), NOW)
            self.assertEqual(got['state'], expected)
            if expected == 'stale':
                self.assertEqual(got['capacity'], 'unknown')
                self.assertEqual(h.alerts(got)[0]['level'], 'unknown')

    def test_missing_and_denied_never_healthy(self):
        for reason in ('missing', 'denied', 'ok'):
            got = h.view(None, NOW, reason)
            self.assertEqual(got['capacity'], 'unknown')
            self.assertTrue(got['problems'])
            self.assertEqual(h.alerts(got)[0]['level'], 'unknown')

    def test_partial_failure_does_not_hide_other_disk_alert(self):
        r = row()
        r['disks'] = [{'labels': ['루트'], 'used_pct': 60, 'available_bytes': 8*h.GIB},
                      {'labels': ['PostgreSQL'], 'error': True},
                      {'labels': ['Loki'], 'used_pct': 95, 'available_bytes': 9*h.GIB}]
        got = h.view(r, NOW)
        self.assertEqual(got['capacity'], 'critical')
        self.assertEqual([a['level'] for a in h.alerts(got)], ['unknown', 'alert'])
        self.assertIn('PostgreSQL', got['problems'][0])

    def test_missing_labels_and_invalid_values_are_unknown(self):
        for disks in ([], 'bad json', {}, [None], [{'labels': None}], [{'labels': ['Loki'], 'used_pct': 0, 'available_bytes': 10*h.GIB}],
                      [{'labels': ['루트', 'PostgreSQL', 'Loki'], 'used_pct': float('nan'), 'available_bytes': 10*h.GIB}]):
            with self.subTest(disks=disks):
                got = h.view(row(disks=copy.deepcopy(disks)), NOW)
                self.assertEqual(got['capacity'], 'unknown')
                self.assertTrue(h.alerts(got))

    def test_cpu_failure_not_green(self):
        got = h.view(row(cpu_pct=None), NOW)
        self.assertEqual(got['capacity'], 'unknown')
        self.assertTrue(got['problems'])
