"""공유 로그인 제한의 HTTP 계약. 카운터 원자성/권한은 test_login_limits_db가 본다."""
import os
from unittest.mock import AsyncMock, patch

from test_web import Base, SAME, PASSWORD
import auth
import login_limits


class LoginLimitHTTP(Base):
    def post(self):
        return self.client.post('/login', data={'username': 'han', 'password': PASSWORD}, headers=SAME)

    def test_limit_does_not_hash_or_issue_cookie_and_keeps_destination(self):
        with patch.object(login_limits, 'take', AsyncMock(return_value=42)), patch.object(auth, 'authenticate', AsyncMock()) as check:
            result = self.client.post('/login', data={'username': 'han', 'password': PASSWORD, 'next': '/incidents'}, headers=SAME)
        self.assertEqual(result.status_code, 429)
        self.assertEqual(result.headers['retry-after'], '42')
        self.assertIn('42초 후', result.text)
        self.assertIn('value="/incidents"', result.text)
        self.assertNotIn(PASSWORD, result.text)
        self.assertNotIn('set-cookie', result.headers)
        check.assert_not_called()

    def test_limit_database_failure_is_closed(self):
        with patch.object(login_limits, 'take', AsyncMock(side_effect=OSError('secret'))), patch.object(auth, 'authenticate', AsyncMock()) as check:
            result = self.post()
        self.assertEqual(result.status_code, 503)
        self.assertNotIn('secret', result.text)
        check.assert_not_called()

    def test_https_cookie_and_logout_use_same_secure_attributes(self):
        with patch.dict(os.environ, {'OPSLOOP_HTTPS_ONLY': '1'}):
            result = self.client.post('/login', data={'username': 'han', 'password': PASSWORD}, headers={'Origin': 'https://testserver'})
            self.assertEqual(result.status_code, 302)
            self.assertIn('Secure', result.headers['set-cookie'])
            self.assertIn('HttpOnly', result.headers['set-cookie'])
            result = self.client.post('/logout', headers={'Origin': 'https://testserver'})
            self.assertIn('Secure', result.headers['set-cookie'])
            self.assertIn('Max-Age=0', result.headers['set-cookie'])

    def test_https_mode_rejects_plaintext_origin(self):
        with patch.dict(os.environ, {'OPSLOOP_HTTPS_ONLY': '1'}):
            self.assertEqual(self.post().status_code, 403)

    def test_ip_keys_ignore_forwarded_headers_and_normalize_mapped_ip(self):
        from types import SimpleNamespace
        def request(ip):
            return SimpleNamespace(client=SimpleNamespace(host=ip), headers={'X-Forwarded-For': '8.8.8.8'})
        a = login_limits.keys(request('192.0.2.1'), 'han')
        self.assertEqual(a, login_limits.keys(request('::ffff:192.0.2.1'), 'han'))
        b = login_limits.keys(request('192.0.2.2'), 'han')
        self.assertNotEqual(a[0], b[0])
        self.assertEqual(a[1], b[1])
        self.assertTrue(all(len(k) == 64 for k in a))
