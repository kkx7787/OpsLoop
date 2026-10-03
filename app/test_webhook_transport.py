"""DNS 차단·IP 고정·실제 TLS 호스트 검증·리다이렉트/프록시 거부. 외부로 보내지 않는다."""
import asyncio
import http.server
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import notifier
import webhook_transport as transport


def answer(ip):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    address = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', address


class Validation(unittest.TestCase):
    def test_all_dns_answers_must_be_public_before_any_socket_is_opened(self):
        for ip in ('127.0.0.1', '169.254.169.254', '192.168.50.11', '100.64.0.1', '::1',
                   '::ffff:127.0.0.1', 'fe80::1', '2001:db8::1', '224.0.0.1'):
            with self.subTest(ip=ip), patch.object(socket, 'getaddrinfo', return_value=[answer('8.8.8.8'), answer(ip)]), \
                    patch.object(socket, 'socket') as connect:
                with self.assertRaises(transport.UnsafeDestination):
                    transport.post('https://hook.example/path?token=secret', b'{}')
                connect.assert_not_called()

    def test_empty_dns_and_invalid_urls(self):
        with patch.object(socket, 'getaddrinfo', return_value=[]), self.assertRaises(transport.UnsafeDestination):
            transport.resolve_public('hook.example', 443)
        for url in ('https://host:0/', 'https://host:65536/', 'https://host:x/', 'https://u:p@host/',
                    'http://host/', 'https://host/#x', 'https://ho\nst/', 'https://host/ a', 'https://[fe80::1%eth0]/'):
            with self.subTest(url=url), self.assertRaises(transport.UnsafeDestination):
                transport.destination(url)

    def test_socket_connects_to_pinned_numeric_ip_and_preserves_tls_name(self):
        raw, wrapped, context = Mock(), Mock(), Mock()
        context.wrap_socket.return_value = wrapped
        with patch.object(ssl, 'create_default_context', return_value=context), patch.object(socket, 'socket', return_value=raw), \
                patch.object(socket, 'getaddrinfo', side_effect=AssertionError('second DNS')):
            connection = transport.PinnedHTTPSConnection('hook.example', 443, (socket.AF_INET, ('8.8.8.8', 443)),
                                                         deadline=time.monotonic()+15, timeout=10)
            connection.connect()
        raw.connect.assert_called_once_with(('8.8.8.8', 443))
        context.wrap_socket.assert_called_once_with(raw, server_hostname='hook.example', do_handshake_on_connect=False)
        wrapped.do_handshake.assert_called_once()

    def test_dns_past_deadline_never_starts_connection(self):
        def slow(*args):
            time.sleep(.03)
            return [(socket.AF_INET, ('8.8.8.8', 443))]
        with patch.object(transport, 'resolve_public', slow), patch.object(socket, 'socket') as connect:
            with self.assertRaises(TimeoutError):
                transport.post('https://hook.example/', b'{}', deadline_seconds=.01)
            connect.assert_not_called()

    def test_timeout_workers_are_bounded_until_they_really_finish(self):
        entered = []
        done = threading.Event()
        def blocked(*args):
            entered.append(1)
            done.wait(3)
            return 202, None
        async def exercise():
            with patch.object(notifier, '_HTTP_SLOTS', threading.BoundedSemaphore(4)), \
                    patch.object(notifier, 'HTTP_DEADLINE', .05), patch.object(notifier, 'post_json', blocked):
                result = await asyncio.gather(*(notifier.deliver('https://hook.example/', {}) for _ in range(12)))
                self.assertEqual(result.count((None, 'TimeoutError')), 4)
                self.assertEqual(result.count((None, 'SenderBusy')), 8)
                self.assertEqual(await notifier.deliver('https://hook.example/', {}), (None, 'SenderBusy'))
                done.set()
                for _ in range(100):
                    if notifier._HTTP_SLOTS._value == 4:
                        break
                    await asyncio.sleep(.01)
                self.assertEqual(notifier._HTTP_SLOTS._value, 4)
        try:
            asyncio.run(exercise())
        finally:
            done.set()
        self.assertEqual(len(entered), 4)


class RealTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='opsloop-webhook-test-')
        cls.addClassCleanup(cls.tmp.cleanup)
        root = Path(cls.tmp.name)
        cls.cert, cls.key = root/'cert.pem', root/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=hook.example', '-addext', 'subjectAltName=DNS:hook.example',
                        '-keyout', str(cls.key), '-out', str(cls.cert)], check=True, capture_output=True)

    def setUp(self):
        self.hits, self.names = [], []
        hits = self.hits
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append((self.path, self.headers['Host'], self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(302)
                self.send_header('Location', 'https://127.0.0.1/private')
                self.send_header('Content-Length', '0')
                self.end_headers()
            def log_message(self, *args):
                pass
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        ctx.set_servername_callback(lambda sock, name, context: self.names.append(name))
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        # 로컬 TLS 시험에서만 공인-IP 검사 다음 단계를 주입한다. 정책 자체는 Validation에서 검사한다.
        self.pin = patch.object(transport, 'resolve_public', return_value=[(socket.AF_INET, self.server.server_address)])
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def test_verified_tls_host_path_body_and_redirect_without_environment_proxy(self):
        ctx = ssl.create_default_context(cafile=str(self.cert))
        with patch.object(ssl, 'create_default_context', return_value=ctx), \
                patch.dict(os.environ, {'HTTPS_PROXY': 'http://127.0.0.1:1', 'ALL_PROXY': 'http://127.0.0.1:1'}):
            code = transport.post('https://hook.example/event?sig=fixture', b'{"ok":true}')
        self.assertEqual(code, 302)
        self.assertEqual(self.hits, [('/event?sig=fixture', 'hook.example', b'{"ok":true}')])
        self.assertEqual(self.names, ['hook.example'])

    def test_wrong_hostname_and_untrusted_cert_are_rejected(self):
        ctx = ssl.create_default_context(cafile=str(self.cert))
        with patch.object(ssl, 'create_default_context', return_value=ctx), self.assertRaises(ssl.SSLCertVerificationError):
            transport.post('https://different.example/', b'{}')
        with self.assertRaises(ssl.SSLCertVerificationError):
            transport.post('https://hook.example/', b'{}')
        self.assertEqual(self.hits, [])


if __name__ == '__main__':
    unittest.main()
