"""#130: 실제 두 프로세스로 수집/적재의 공유 잠금과 비정상 종료를 확인한다."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from run_lock import Busy, run_lock

HERE = Path(__file__).resolve().parent


class RunLockTest(unittest.TestCase):
    def test_busy_rejects_both_entrypoints_before_external_work(self):
        with tempfile.TemporaryDirectory() as home, run_lock(home):
            env = dict(os.environ, OPSLOOP_HOME=home, OPSLOOP_APP=str(HERE.parent),
                       OPSLOOP_BUCKET='test-bucket', OPSLOOP_HOSTS='i-00000000000000000')
            env.pop('OPSLOOP_RUN_LOCK_FD', None)
            for entry in ('opsloop-ingest', 'pull.py'):
                p = subprocess.run([sys.executable, str(HERE/entry)], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(p.returncode, 75, p.stdout+p.stderr)
            self.assertEqual(os.listdir(home), ['.ingest.lock'])

    def test_inherited_lock_keeps_parent_protected_and_wrong_inode_rejected(self):
        code = 'from run_lock import run_lock; import sys;\nwith run_lock(sys.argv[1], sys.argv[2]): print("ok")'
        with tempfile.TemporaryDirectory() as home, run_lock(home) as fd:
            p = subprocess.run([sys.executable, '-c', code, home, str(fd)], cwd=HERE, pass_fds=(fd,),
                               capture_output=True, text=True, timeout=10)
            self.assertEqual((p.returncode, p.stdout.strip()), (0, 'ok'), p.stderr)
            # 하위 프로세스가 끝나도 부모 잠금은 남는다.
            with open(HERE/'pull.py') as other:
                with self.assertRaises(ValueError):
                    with run_lock(home, other.fileno()):
                        pass
            blocked = subprocess.run([sys.executable, str(HERE/'opsloop-ingest')],
                                     env=dict(os.environ, OPSLOOP_HOME=home), capture_output=True, timeout=10)
            self.assertEqual(blocked.returncode, 75)

    def test_child_holds_lock_after_parent_scope_ends(self):
        code = 'import os,sys,time;os.fstat(int(sys.argv[1]));print("ready",flush=True);time.sleep(60)'
        with tempfile.TemporaryDirectory() as home:
            with run_lock(home) as fd:
                p = subprocess.Popen([sys.executable,'-c',code,str(fd)], pass_fds=(fd,), stdout=subprocess.PIPE, text=True)
                self.assertEqual(p.stdout.readline().strip(), 'ready')
            try:
                with self.assertRaises(Busy):
                    with run_lock(home): pass
            finally:
                p.kill(); p.wait(timeout=5); p.stdout.close()
            with run_lock(home): pass

    def test_killed_holder_releases_lock_without_deleting_file(self):
        code = 'from run_lock import run_lock; import sys,time;\nwith run_lock(sys.argv[1]): print("ready",flush=True);time.sleep(60)'
        with tempfile.TemporaryDirectory() as home:
            p = subprocess.Popen([sys.executable,'-c',code,home], cwd=HERE, stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual(p.stdout.readline().strip(), 'ready')
                p.kill(); p.wait(timeout=5)
                with run_lock(home):
                    self.assertTrue(Path(home,'.ingest.lock').exists())
            finally:
                if p.poll() is None: p.kill(); p.wait()
                p.stdout.close()


if __name__ == '__main__': unittest.main()
