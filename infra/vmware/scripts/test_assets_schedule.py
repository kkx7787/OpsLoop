"""실패 복귀·정기 경계·시계 오류·강제 종료 뒤 재시도. 실제 VM이나 사용자 상태는 쓰지 않는다."""
import importlib.util
import tempfile
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('assets_schedule', Path(__file__).with_name('assets-schedule.py'))
schedule = importlib.util.module_from_spec(spec)
spec.loader.exec_module(schedule)


class ScheduleTests(unittest.TestCase):
    def test_daily_boundary_and_recovery_intervals(self):
        at = schedule.datetime(2026, 10, 6, 5, 9, 59, tzinfo=schedule.KST).timestamp()
        self.assertFalse(schedule.due({'finished_at': at, 'exit_code': 0}, at))
        for code in (0, 1, 2):
            self.assertTrue(schedule.due({'finished_at': at, 'exit_code': code}, at + 1))
        at += 60  # 재시도 간격은 같은 일일 실행 구간 안에서 검사한다
        for code, delay in ((1, 14400), (2, 900)):
            self.assertFalse(schedule.due({'finished_at': at, 'exit_code': code}, at + delay - 1))
            self.assertTrue(schedule.due({'finished_at': at, 'exit_code': code}, at + delay))

    def test_missing_corrupt_future_and_nonfinite_state_cannot_hide_failure(self):
        now = time.time()
        for state in ({}, None, [], {'finished_at': 'bad', 'exit_code': 0},
                      {'finished_at': now + 1, 'exit_code': 0},
                      {'finished_at': float('nan'), 'exit_code': 0},
                      {'finished_at': float('inf'), 'exit_code': 0}):
            with self.subTest(state=state):
                self.assertTrue(schedule.due(state, now))

    def test_clock_waits_for_sync_and_measures_again(self):
        with patch.object(schedule.time, 'time', side_effect=[1000, 1000, 1010, 1010]), \
             patch.object(schedule.subprocess, 'run', side_effect=[
                 subprocess.CompletedProcess([], 0, '100\n'), subprocess.CompletedProcess([], 0),
                 subprocess.CompletedProcess([], 0, '1010\n')]) as run:
            self.assertTrue(schedule.clock_ready())
            self.assertIn('chronyc waitsync', run.call_args_list[1].args[0][-1])

    def test_invalid_or_unreachable_clock_blocks_collection(self):
        for response in (subprocess.CompletedProcess([], 0, 'garbage'), subprocess.CompletedProcess([], 1, '1000')):
            with patch.object(schedule.time, 'time', return_value=1000), \
                 patch.object(schedule.subprocess, 'run', return_value=response):
                self.assertFalse(schedule.clock_ready())

    def test_persisted_failure_retries_and_success_skips_until_next_daily_slot(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(schedule.Path, 'home', return_value=Path(tmp)), \
             patch.object(schedule.time, 'time', return_value=2000000000) as clock, \
             patch.object(schedule, 'clock_ready', return_value=False) as ready, \
             patch.object(schedule, 'run_bounded', return_value=0) as collect, \
             patch.object(schedule.subprocess, 'Popen'), patch.object(schedule, 'notify') as notify:
            self.assertEqual(schedule.main(['--scheduled']), 2)
            collect.assert_not_called()
            notify.assert_called_once()
            self.assertEqual(schedule.main(['--scheduled']), 0)
            ready.assert_called_once()
            clock.return_value += 900
            ready.return_value = True
            self.assertEqual(schedule.main(['--scheduled']), 0)
            collect.assert_called_once()
            self.assertEqual(json.loads((Path(tmp)/'opsloop-assets/schedule.json').read_text())['exit_code'], 0)
            clock.return_value += 900
            self.assertEqual(schedule.main(['--scheduled']), 0)
            collect.assert_called_once()

    def test_timeout_terminates_process_group(self):
        started = time.monotonic()
        code = schedule.run_bounded([sys.executable, '-c', 'import time; time.sleep(60)'], timeout=0.05)
        self.assertEqual(code, 2)
        self.assertLess(time.monotonic() - started, 8)


if __name__ == '__main__':
    unittest.main()
