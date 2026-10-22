"""Sockets, TLS wrapping, and bidirectional relay."""

from __future__ import annotations

import socket
import ssl
import threading
from typing import Callable

from proxy_chain.errors import ProxyChainError


class SocketIO:
    """A socket with a pushback buffer.

    Protocol parsers can read a few bytes too many. The extra bytes stay here
    so the next handshake, or the tunnel relay, still sees them.
    """

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._buf = bytearray()

    def settimeout(self, timeout: float | None) -> None:
        self.sock.settimeout(timeout)

    def sendall(self, data: bytes) -> None:
        self.sock.sendall(data)

    def pending(self) -> int:
        return len(self._buf)

    def recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(max(n - len(self._buf), 4096))
            if not chunk:
                raise ProxyChainError("connection closed")
            self._buf += chunk
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def recv_until_nul(self, limit: int = 1024) -> bytes:
        data = bytearray()
        while True:
            byte = self.recv_exact(1)
            if byte == b"\x00":
                return bytes(data)
            data += byte
            if len(data) > limit:
                raise ProxyChainError("field too long")

    def read_until(self, marker: bytes, limit: int) -> bytes:
        while marker not in self._buf:
            if len(self._buf) > limit:
                raise ProxyChainError("header too large")
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ProxyChainError("connection closed")
            self._buf += chunk
        index = self._buf.index(marker) + len(marker)
        out = bytes(self._buf[:index])
        del self._buf[:index]
        return out

    def drain(self) -> bytes:
        out = bytes(self._buf)
        self._buf.clear()
        return out

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class _TLSAdapter:
    """Socket-like TLS client backed by a memory BIO.

    A memory BIO lets us start TLS even when the previous hop already read
    bytes that belong to the handshake.
    """

    def __init__(self, sock: socket.socket, server_hostname: str, tls_verify: bool, pending: bytes):
        self._sock = sock
        context = ssl.create_default_context()
        if not tls_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        if pending:
            self._incoming.write(pending)
        self._ssl = context.wrap_bio(
            self._incoming,
            self._outgoing,
            server_hostname=server_hostname or None,
        )
        self._handshake()

    def _flush_out(self) -> None:
        while True:
            data = self._outgoing.read()
            if not data:
                return
            self._sock.sendall(data)

    def _pump_in(self) -> bool:
        data = self._sock.recv(16384)
        if not data:
            self._incoming.write_eof()
            self._flush_out()
            return False
        self._incoming.write(data)
        self._flush_out()
        return True

    def _handshake(self) -> None:
        while True:
            try:
                self._ssl.do_handshake()
                self._flush_out()
                return
            except ssl.SSLWantReadError:
                self._flush_out()
                if not self._pump_in():
                    raise ProxyChainError("tls handshake closed") from None
            except ssl.SSLWantWriteError:
                self._flush_out()
            except ssl.SSLError as exc:
                raise ProxyChainError(f"tls handshake failed: {exc}") from exc

    def recv(self, n: int) -> bytes:
        while True:
            try:
                return self._ssl.read(n) or b""
            except ssl.SSLWantReadError:
                if not self._pump_in():
                    return b""
            except ssl.SSLWantWriteError:
                self._flush_out()
            except ssl.SSLZeroReturnError:
                return b""
            except ssl.SSLError as exc:
                if "EOF" in str(exc):
                    return b""
                raise

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            try:
                sent = self._ssl.write(view)
            except ssl.SSLWantReadError:
                if not self._pump_in():
                    raise ProxyChainError("tls connection closed")
                continue
            except ssl.SSLWantWriteError:
                self._flush_out()
                continue
            if not sent:
                raise ProxyChainError("tls connection closed")
            view = view[sent:]
            self._flush_out()

    def settimeout(self, timeout: float | None) -> None:
        self._sock.settimeout(timeout)

    def shutdown(self, how: int) -> None:
        try:
            self._sock.shutdown(how)
        except OSError:
            pass

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def wrap_tls(io: SocketIO, server_hostname: str, tls_verify: bool) -> SocketIO:
    pending = io.drain()
    try:
        adapter = _TLSAdapter(io.sock, server_hostname, tls_verify, pending)
    except ProxyChainError:
        raise
    except OSError as exc:
        raise ProxyChainError(f"tls failed: {exc}") from exc
    return SocketIO(adapter)  # type: ignore[arg-type]


def tcp_connect(host: str, port: int, timeout: float) -> socket.socket:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ProxyChainError(f"dns failed for {host}: {exc}") from exc
    if not infos:
        raise ProxyChainError(f"no addresses for {host}")
    last: Exception | None = None
    for family, socktype, proto, _, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last = exc
            sock.close()
    raise ProxyChainError(f"connect {host}:{port} failed: {last}")


def listen_socket(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    if family is socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(128)
    return sock


def relay(
    left: SocketIO,
    right: SocketIO,
    idle_timeout: float,
    on_left: Callable[[int], None],
    on_right: Callable[[int], None],
) -> None:
    """Copy bytes both ways until one side closes or ``idle_timeout`` elapses.

    ``on_left`` counts bytes read from ``left``. ``on_right`` counts bytes
    read from ``right``. Counts are updated before the matching ``sendall``,
    so a reader that has the bytes can already observe the counter.
    """

    def pipe(src: SocketIO, dst: SocketIO, count: Callable[[int], None]) -> None:
        try:
            src.settimeout(idle_timeout)
            pending = src.drain()
            if pending:
                count(len(pending))
                dst.sendall(pending)
            while True:
                data = src.sock.recv(65536)
                if not data:
                    break
                count(len(data))
                dst.sendall(data)
        except (TimeoutError, OSError):
            return
        finally:
            try:
                dst.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    to_right = threading.Thread(target=pipe, args=(left, right, on_left), daemon=True)
    to_left = threading.Thread(target=pipe, args=(right, left, on_right), daemon=True)
    to_right.start()
    to_left.start()
    to_right.join()
    to_left.join()
