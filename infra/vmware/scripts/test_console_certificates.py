#!/usr/bin/env python3
"""실제 OpenSSL 발급·용도/신원/키 확인. 신뢰 저장소·원격 VM은 건드리지 않는다."""
import contextlib
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('certificates', Path(__file__).with_name('console-certificates.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class Certificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='opsloop-tls-test-')
        cls.addClassCleanup(cls.tmp.cleanup)
        root = Path(cls.tmp.name)
        cls.ca, cls.out = root/'authority', root/'issued'
        with contextlib.redirect_stdout(io.StringIO()):
            C.init(cls.ca)
            C.issue(cls.ca, cls.out)

    def test_front_ip_and_backend_names_have_verified_server_certificates(self):
        with contextlib.redirect_stdout(io.StringIO()):
            C.check(self.out, 21)
        for role, ip in [('console', '192.168.70.254'), ('console-a', '192.168.50.11'), ('console-b', '192.168.50.12')]:
            C.openssl('verify', '-CAfile', self.ca/'ca.crt', '-verify_ip', ip, self.out/role/'server.crt')
        with self.assertRaises(RuntimeError):
            C.openssl('verify', '-CAfile', self.ca/'ca.crt', '-verify_hostname', 'console-b.opsloop.internal', self.out/'console-a/server.crt')

    def test_ca_key_is_not_distributed_and_keys_are_private(self):
        self.assertFalse((self.out/'ca.key').exists())
        for key in [self.ca/'ca.key', *self.out.glob('*/server.key'), self.out/'console/console.pem']:
            self.assertEqual(key.stat().st_mode & 0o077, 0)
        self.assertNotEqual((self.out/'console-a/server.key').read_bytes(), (self.out/'console-b/server.key').read_bytes())

    def test_existing_authority_and_certificates_are_not_overwritten(self):
        before = (self.ca/'ca.crt').read_bytes()
        with self.assertRaises(FileExistsError):
            C.init(self.ca)
        with self.assertRaises(FileExistsError):
            C.issue(self.ca, self.out)
        self.assertEqual((self.ca/'ca.crt').read_bytes(), before)

    def test_mismatching_key_and_short_lifetime_are_rejected(self):
        copy = Path(self.tmp.name)/'bad'
        shutil.copytree(self.out, copy)
        shutil.copy(copy/'console-b/server.key', copy/'console-a/server.key')
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            C.check(copy, 21)
        with self.assertRaises(RuntimeError):
            C.openssl('x509', '-in', self.out/'console/server.crt', '-noout', '-checkend', str(91*86400))


if __name__ == '__main__':
    unittest.main()
