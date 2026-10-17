import unittest
from unittest.mock import patch
import pull_loki as bridge


class LedgerIntegrityTests(unittest.TestCase):
    def test_budget_does_not_forget_unvisited_offsets(self):
        names = [f'collector-2026-10-{day:02d}.jsonl' for day in range(1, 5)]
        state = {'ledgers': {name: {'offset': 123} for name in names}}
        with patch.object(bridge.os, 'listdir', side_effect=[names, []]), \
                patch.object(bridge, 'LEDGER_BYTES', 1), \
                patch.object(bridge, 'read_ledger_file', return_value=({'lines': 0, 'new': 0, 'bad': 0, 'forged': 0}, 1)):
            bridge.read_ledgers(None, None, state, lambda: None)
        self.assertEqual(set(state['ledgers']), set(names))

    def test_unreadable_directory_does_not_erase_offsets(self):
        name = 'collector-2026-10-01.jsonl'
        state = {'ledgers': {name: {'offset': 123}}}
        with patch.object(bridge.os, 'listdir', side_effect=[PermissionError(), []]):
            self.assertFalse(bridge.read_ledgers(None, None, state, lambda: None))
        self.assertEqual(state['ledgers'][name]['offset'], 123)

    def test_confirmed_removed_file_is_pruned(self):
        state = {'ledgers': {'collector-2026-10-01.jsonl': {'offset': 123}}}
        with patch.object(bridge.os, 'listdir', return_value=[]):
            bridge.read_ledgers(None, None, state, lambda: None)
        self.assertEqual(state['ledgers'], {})
