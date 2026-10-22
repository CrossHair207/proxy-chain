"""Local SOCKS4, SOCKS5, and HTTP proxy listener."""

from __future__ import annotations

import logging
import socket
import threading
from collections import deque

from proxy_chain.chain import ChainManager
from proxy_chain.errors import ProxyChainError
from proxy_chain.models import Settings
from proxy_chain.net import SocketIO, listen_socket, relay
from proxy_chain.protocols import (
    accept_socks4,
    accept_socks5,
    credentials_match,
    http_message,
    parse_basic_authorization,
    parse_http_request,
    rewrite_origin_request,
    socks4_reply,
    socks5_reply,
    socks_failure_code,
)

log = logging.getLogger("proxy_chain")


class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.accepted = 0
        self.succeeded = 0
        self.failed = 0
        self.bytes_to_remote = 0
        self.bytes_to_client = 0

    def add(self, **values: int) -> None:
        with self._lock:
            for key, value in values.items():
                setattr(self, key, getattr(self, key) + value)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "accepted": self.accepted,
                "succeeded": self.succeeded,
                "failed": self.failed,
                "bytes_to_remote": self.bytes_to_remote,
                "bytes_to_client": self.bytes_to_client,
            }


class ProxyServer:
    """Accepts local clients and tunnels each one through the chain."""

    def __init__(self, settings: Settings, chain: ChainManager, stats: Stats):
        self.settings = settings
        self.chain = chain
        self.stats = stats
        self.recent: deque[tuple[str, int]] = deque(maxlen=200)
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(settings.max_connections)
        self._stopped = threading.Event()
        self._active: set[SocketIO] = set()
        self._thread: threading.Thread | None = None
        self._listen = listen_socket(settings.listen_host, settings.listen_port)
        self.port = self._listen.getsockname()[1]

    def start(self) -> None:
        self._listen.settimeout(0.5)
        self._thread = threading.Thread(target=self._loop, name="proxy-listen", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stopped.set()
        try:
            self._listen.close()
        except OSError:
            pass
        with self._lock:
            active = list(self._active)
        for io in active:
            io.close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def recent_requests(self) -> list[tuple[str, int]]:
        with self._lock:
            return list(self.recent)

    def _remember(self, host: str, port: int) -> None:
        with self._lock:
            self.recent.append((host, port))

    def _track(self, io: SocketIO) -> None:
        with self._lock:
            self._active.add(io)

    def _untrack(self, io: SocketIO) -> None:
        with self._lock:
            self._active.discard(io)

    def _loop(self) -> None:
        while not self._stopped.is_set():
            try:
                conn, addr = self._listen.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                conn.close()
                self.stats.add(failed=1)
                log.warning("rejected %s: connection limit reached", addr)
                continue
            client = SocketIO(conn)
            self._track(client)
            threading.Thread(
                target=self._client,
                args=(client, addr),
                name="proxy-client",
                daemon=True,
            ).start()

    def _client(self, client: SocketIO, addr: tuple) -> None:
        conn = client.sock
        upstream: SocketIO | None = None
        self.stats.add(accepted=1)
        opened = False
        try:
            conn.settimeout(self.settings.handshake_timeout)
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            peeked = conn.recv(1, socket.MSG_PEEK)
            if not peeked:
                raise ProxyChainError("client closed")
            kind = peeked[0]
            if kind == 5:
                host, port = accept_socks5(client, self.settings.username, self.settings.password)
                upstream = self._tunnel(client, addr, host, port, socks5_reply)
            elif kind == 4:
                if self.settings.username is not None:
                    socks4_reply(client, False)
                    raise ProxyChainError("socks4 has no password authentication")
                host, port = accept_socks4(client)
                upstream = self._tunnel(client, addr, host, port, _socks4_ok)
            else:
                upstream = self._http(client, addr)
            opened = upstream is not None
            if upstream is not None:
                self.stats.add(succeeded=1)
                relay(
                    client,
                    upstream,
                    self.settings.idle_timeout,
                    lambda n: self.stats.add(bytes_to_remote=n),
                    lambda n: self.stats.add(bytes_to_client=n),
                )
        except (ProxyChainError, OSError) as exc:
            log.info("connection from %s failed: %s", addr[0], exc)
        except Exception:
            log.exception("connection from %s crashed", addr[0])
        finally:
            if not opened:
                self.stats.add(failed=1)
            if upstream is not None:
                self._untrack(upstream)
                upstream.close()
            self._untrack(client)
            client.close()
            self._slots.release()

    def _tunnel(self, client: SocketIO, addr: tuple, host: str, port: int, reply) -> SocketIO:
        self._remember(host, port)
        try:
            upstream, hops = self.chain.connect(host, port)
        except ProxyChainError as exc:
            reply(client, socks_failure_code(exc))
            raise
        self._track(upstream)
        reply(client, 0)
        self._log_open(addr, host, port, hops)
        return upstream

    def _http(self, client: SocketIO, addr: tuple) -> SocketIO | None:
        head = client.read_until(b"\r\n\r\n", 65536)
        request = parse_http_request(head)
        if not self._http_authorized(request):
            client.sendall(
                http_message(
                    407,
                    "Proxy Authentication Required",
                    "authentication required\n",
                    {"Proxy-Authenticate": 'Basic realm="proxy-chain"'},
                )
            )
            raise ProxyChainError("authentication failed")
        self._remember(request.dest_host, request.dest_port)
        try:
            upstream, hops = self.chain.connect(request.dest_host, request.dest_port)
        except ProxyChainError as exc:
            client.sendall(http_message(502, "Bad Gateway", f"{exc}\n"))
            raise
        self._track(upstream)
        try:
            self._log_open(addr, request.dest_host, request.dest_port, hops)
            if request.method == "CONNECT":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                return upstream
            payload = rewrite_origin_request(request) + client.drain()
            self.stats.add(bytes_to_remote=len(payload))
            upstream.sendall(payload)
            return upstream
        except Exception:
            self._untrack(upstream)
            upstream.close()
            raise

    def _http_authorized(self, request) -> bool:
        if self.settings.username is None:
            return True
        parsed = parse_basic_authorization(request.header("proxy-authorization"))
        if parsed is None:
            return False
        return credentials_match(self.settings.username, self.settings.password, parsed[0], parsed[1])

    def _log_open(self, addr: tuple, host: str, port: int, hops) -> None:
        path = " -> ".join(proxy.display for proxy in hops) if hops else "direct"
        log.info("%s connected to %s:%s via %s", addr[0], host, port, path)


def _socks4_ok(io: SocketIO, code: int) -> None:
    socks4_reply(io, code == 0)
