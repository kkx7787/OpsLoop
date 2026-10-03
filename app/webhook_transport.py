"""외부 웹훅 전송. DNS 답 전체 검사 → 고정 IP 연결 → 원래 이름으로 TLS 검증.

리다이렉트와 환경변수 프록시는 사용하지 않는다. URL · 응답 본문은 로그에 남기지 않는다.
DNS 호출은 OS 한계로 취소할 수 없으므로 호출자는 별도의 제한된 작업자에서 실행한다.
"""
import http.client
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit


class UnsafeDestination(ValueError):
    pass


def public_address(value):
    try:
        if "%" in value:
            raise ValueError()
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return (address.is_global and not any((address.is_private, address.is_loopback,
                address.is_link_local, address.is_multicast, address.is_reserved, address.is_unspecified)))
    except ValueError:
        return False


def destination(url):
    """파서가 제거하는 제어 문자도 사전에 거부한다. 오류에 URL을 넣지 않는다."""
    try:
        if not isinstance(url, str) or not url or len(url) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
            raise ValueError()
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.username is not None or parts.password is not None or parts.fragment:
            raise ValueError()
        host = (parts.hostname or "").rstrip(".").encode("idna").decode("ascii")
        if not host or "%" in host or "\\" in host:
            raise ValueError()
        port = 443 if parts.port is None else parts.port
        if not 1 <= port <= 65535:
            raise ValueError()
        return host, port, (parts.path or "/") + ("?" + parts.query if parts.query else "")
    except (ValueError, UnicodeError):
        raise UnsafeDestination("InvalidDestination") from None


def resolve_public(host, port):
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    # 일부만 공인이어도 거절한다. 이후 다른 주소로 재해석/우회하지 않는다.
    if not addresses or any(family not in (socket.AF_INET, socket.AF_INET6) or not public_address(addr[0])
                            for family, _, _, _, addr in addresses):
        raise UnsafeDestination("NonPublicDestination")
    return list(dict.fromkeys((family, addr) for family, _, _, _, addr in addresses))


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address, *, deadline, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address
        self.deadline = deadline
        self.limit = timeout

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError()
        return min(self.limit, left)

    def connect(self):
        family, address = self.address
        sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.sock = sock
        try:
            sock.settimeout(self.remaining())
            sock.connect(address)  # 숫자 sockaddr만 사용하며 이름을 다시 해석하지 않는다.
            sock.settimeout(self.remaining())
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host, do_handshake_on_connect=False)
            self.sock.do_handshake()
            self.sock.settimeout(self.remaining())
        except BaseException:
            sock.close()
            self.close()
            raise

    def abort(self):
        sock = self.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


def post(url, data, *, timeout=10, deadline_seconds=15):
    deadline = time.monotonic() + deadline_seconds
    host, port, path = destination(url)
    addresses = resolve_public(host, port)
    # 검증한 IP 중 하나로만 보낸다. 접속 뒤 재전송으로 알림이 중복되지 않게 이 회차에서는 재시도하지 않는다.
    connection = PinnedHTTPSConnection(host, port, addresses[0], deadline=deadline, timeout=timeout)
    timer = threading.Timer(max(0, deadline - time.monotonic()), connection.abort)
    timer.daemon = True
    try:
        connection.remaining()  # DNS가 기한보다 늦게 끝나면 접속·전송을 시작하지 않는다.
        timer.start()
        connection.request("POST", path, body=data, headers={
            "Content-Type": "application/json; charset=utf-8", "User-Agent": "OpsLoop",
            "Connection": "close",
        })
        connection.sock.settimeout(connection.remaining())
        response = connection.getresponse()
        return response.status  # 본문은 읽지 않고 리다이렉트도 따라가지 않는다.
    finally:
        timer.cancel()
        connection.close()
