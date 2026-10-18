"""#130: 운영 명령은 가짜로 대체하고 비밀 전달·중복 백업·설치 사전 조건을 확인한다."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


def exe(path, text):
    path.write_text(text); path.chmod(0o755)


class SeedTest(unittest.TestCase):
    def test_password_and_hash_never_in_child_arguments_or_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            t=Path(tmp); bin=t/'bin'; bin.mkdir()
            exe(bin/'openssl', '''#!/usr/bin/env python3
import sys,hashlib,os,json
open(os.environ['ARGS'],'a').write(json.dumps(sys.argv)+'\\n')
assert sys.argv[1:]==['passwd','-6','-stdin']
print('$6$test$'+hashlib.sha256(sys.stdin.buffer.read()).hexdigest())
''')
            exe(bin/'hdiutil', '''#!/usr/bin/env python3
import sys,os,json,pathlib,shutil
open(os.environ['ARGS'],'a').write(json.dumps(sys.argv)+'\\n')
shutil.copyfile(pathlib.Path(sys.argv[-1])/'user-data', sys.argv[sys.argv.index('-o')+1])
''')
            key=t/'key.pub';key.write_text('ssh-ed25519 synthetic-key test')
            out=t/'seed.iso'; password='synthetic-password-130'
            env=dict(os.environ, PATH=str(bin)+os.pathsep+os.environ['PATH'], SSH_PUB=str(key), ARGS=str(t/'args'))
            p=subprocess.run(['bash','-x',str(ROOT/'infra/vmware/scripts/make-seed.sh'),str(out)], input=password+'\n'+password+'\n',
                             env=env, text=True,capture_output=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr)
            data=out.read_text(); args=(t/'args').read_text()
            self.assertNotIn(password,data+args+p.stdout+p.stderr)
            self.assertNotIn('$6$',args+p.stdout+p.stderr)
            self.assertIn('$6$test$',data)
            self.assertEqual(out.stat().st_mode & 0o777,0o600)


class GuardTest(unittest.TestCase):
    def test_backup_busy_different_destinations_no_remote_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            t=Path(tmp);bin=t/'bin';bin.mkdir()
            exe(bin/'ssh','#!/bin/sh\ntouch "$HOME/unexpected-ssh"\nexit 99\n')
            env=dict(os.environ, HOME=tmp,PATH=str(bin)+os.pathsep+os.environ['PATH'])
            with open(t/'.opsloop-backup.lock','w') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                for dest in ('a','b'):
                    p=subprocess.run(['bash',str(ROOT/'infra/vmware/scripts/backup-db.sh'),str(t/dest)],env=env,
                                     capture_output=True,text=True,timeout=10)
                    self.assertEqual(p.returncode,75,p.stdout+p.stderr)
                    self.assertFalse((t/dest).exists())
            self.assertFalse((t/'unexpected-ssh').exists())
            p=subprocess.run(['bash',str(ROOT/'infra/vmware/scripts/backup-db.sh'),str(t/'a')],env=env,
                             capture_output=True,text=True,timeout=10)
            self.assertNotEqual(p.returncode,75)
            self.assertTrue((t/'unexpected-ssh').exists())

    def test_cowrie_rejects_missing_or_mutable_image_before_sudo(self):
        with tempfile.TemporaryDirectory() as tmp:
            t=Path(tmp);exe(t/'sudo','#!/bin/sh\ntouch "$MARK"\nexit 99\n')
            for image in ('','cowrie/cowrie:latest','cowrie/cowrie:2.7','other/image@sha256:'+'a'*64):
                env=dict(os.environ,PATH=tmp+os.pathsep+os.environ['PATH'],OPSLOOP_COWRIE_IMAGE=image,MARK=str(t/'mark'))
                p=subprocess.run(['bash',str(ROOT/'scripts/run-cowrie.sh')],env=env,capture_output=True,timeout=10)
                self.assertNotEqual(p.returncode,0)
                self.assertFalse((t/'mark').exists())

    def test_installers_require_explicit_environment(self):
        for script in ('enforcer/install-enforcer.sh','recommend/install-recommend.sh'):
            env={k:v for k,v in os.environ.items() if not k.startswith('OPSLOOP_')}
            p=subprocess.run(['bash',str(ROOT/script),'test'],env=env,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(p.returncode,0)
            self.assertIn('현재 환경에 맞게 명시',p.stderr)


if __name__=='__main__':unittest.main()
