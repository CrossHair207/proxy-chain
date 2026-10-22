"""Proxy selection and hop-by-hop connection."""

from __future__ import annotations

import random
import threading

from proxy_chain.errors import ConfigError, HopError, ProxyChainError
from proxy_chain.health import HealthTracker
from proxy_chain.models import MODES, Proxy
from proxy_chain.net import SocketIO, tcp_connect, wrap_tls
from proxy_chain.protocols import http_connect_client, socks4_client, socks5_client


def _handshake_error(index: int, proxy: Proxy, host: str, port: int, exc: ProxyChainError, last_hop: bool) -> HopError:
    message = f"{proxy.display} -> {host}:{port}: {exc}"
    text = str(exc).lower()
    if "connect failed" in text and last_hop:
        return HopError(index, message, proxy_dead=False)
    network_failure = any(token in text for token in ("refused", "unreachable", "timed out", "timeout"))
    if "connect failed" in text and not last_hop and network_failure:
        return HopError(index + 1, message, proxy_dead=True)
    return HopError(index, message, proxy_dead=True)


def handshake(io: SocketIO, proxy: Proxy, host: str, port: int) -> None:
    if proxy.scheme == "socks5":
        socks5_client(io, host, port, proxy.username, proxy.password)
    elif proxy.scheme == "socks4":
        socks4_client(io, host, port, proxy.username)
    elif proxy.scheme in {"http", "https"}:
        http_connect_client(io, host, port, proxy.username, proxy.password)
    else:
        raise ProxyChainError(f"unsupported scheme {proxy.scheme}")


def open_chain(proxies: list[Proxy], dest_host: str, dest_port: int, timeout: float) -> SocketIO:
    """Connect to ``dest`` through ``proxies``, in order.

    Hostnames are sent to the exit proxy as names, so DNS happens there
    instead of on this machine. The first hop is the exception: this process
    has to open that TCP connection itself.
    """
    if not proxies:
        return SocketIO(tcp_connect(dest_host, dest_port, timeout))

    sock = None
    try:
        first = proxies[0]
        try:
            sock = tcp_connect(first.host, first.port, timeout)
        except ProxyChainError as exc:
            raise HopError(0, f"{first.display}: {exc}") from exc
        io = SocketIO(sock)
        if first.scheme == "https":
            try:
                io = wrap_tls(io, first.host, first.tls_verify)
            except ProxyChainError as exc:
                raise HopError(0, f"{first.display}: {exc}") from exc
        for index, proxy in enumerate(proxies):
            if index + 1 < len(proxies):
                nxt = proxies[index + 1]
                next_host, next_port = nxt.host, nxt.port
            else:
                next_host, next_port = dest_host, dest_port
            try:
                handshake(io, proxy, next_host, next_port)
            except ProxyChainError as exc:
                raise _handshake_error(
                    index,
                    proxy,
                    next_host,
                    next_port,
                    exc,
                    index + 1 == len(proxies),
                ) from exc
            if index + 1 < len(proxies) and proxies[index + 1].scheme == "https":
                nxt = proxies[index + 1]
                try:
                    io = wrap_tls(io, nxt.host, nxt.tls_verify)
                except ProxyChainError as exc:
                    raise HopError(index + 1, f"{nxt.display}: {exc}") from exc
        return io
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        raise


class ChainManager:
    """The proxy list, selection mode, and per-connection failover."""

    def __init__(
        self,
        proxies: list[Proxy],
        health: HealthTracker,
        mode: str = "dynamic",
        chain_length: int = 0,
        min_hops: int = 1,
        allow_direct: bool = False,
        connect_timeout: float = 10.0,
    ):
        self.health = health
        self._lock = threading.RLock()
        self._proxies = list(proxies)
        self.mode = mode
        self.chain_length = chain_length
        self.min_hops = min_hops
        self.allow_direct = allow_direct
        self.connect_timeout = connect_timeout
        self._rr = 0
        self._uses: dict[str, int] = {}
        self._random = random.Random()

    def proxies(self) -> list[Proxy]:
        with self._lock:
            return list(self._proxies)

    def connect(self, host: str, port: int) -> tuple[SocketIO, list[Proxy]]:
        with self._lock:
            mode = self.mode
            timeout = self.connect_timeout
            if mode == "round_robin":
                pool, start, length = self._round_robin_locked()
            else:
                pool = self._plan_locked()
                start = 0
                length = len(pool)
        if mode == "static":
            self._ensure(pool)
            try:
                io = open_chain(pool, host, port, timeout)
            except HopError as exc:
                if exc.proxy_dead and 0 <= exc.index < len(pool):
                    self.health.mark_down(pool[exc.index].id, hard=True)
                raise
            self._success(pool)
            return io, pool
        if mode == "round_robin":
            return self._connect_windows(host, port, timeout, pool, start, length)
        return self._connect_skipping(host, port, timeout, pool)

    def add(self, proxy: Proxy) -> None:
        with self._lock:
            if any(item.id == proxy.id for item in self._proxies):
                raise ProxyChainError(f"proxy id {proxy.id} already exists")
            self._proxies.append(proxy)

    def remove(self, proxy_id: str) -> Proxy:
        with self._lock:
            for index, proxy in enumerate(self._proxies):
                if proxy.id == proxy_id:
                    return self._proxies.pop(index)
            raise ProxyChainError(f"unknown proxy {proxy_id}")

    def set_enabled(self, proxy_id: str, enabled: bool) -> Proxy:
        with self._lock:
            for proxy in self._proxies:
                if proxy.id == proxy_id:
                    proxy.enabled = enabled
                    return proxy
            raise ProxyChainError(f"unknown proxy {proxy_id}")

    def reorder(self, ids: list[str]) -> None:
        with self._lock:
            by_id = {proxy.id: proxy for proxy in self._proxies}
            if set(ids) != set(by_id) or len(ids) != len(by_id):
                raise ProxyChainError("reorder must list every proxy id once")
            self._proxies = [by_id[proxy_id] for proxy_id in ids]

    def replace_proxies(self, proxies: list[Proxy]) -> None:
        with self._lock:
            self._proxies = list(proxies)

    def configure(
        self,
        *,
        mode: str | None = None,
        chain_length: int | None = None,
        min_hops: int | None = None,
        allow_direct: bool | None = None,
        connect_timeout: float | None = None,
    ) -> None:
        with self._lock:
            if mode is not None:
                if mode not in MODES:
                    raise ConfigError(f"unknown mode {mode}")
                self.mode = mode
            if chain_length is not None:
                if chain_length < 0:
                    raise ConfigError("chain_length must be >= 0")
                self.chain_length = chain_length
            if min_hops is not None:
                if min_hops < 0:
                    raise ConfigError("min_hops must be >= 0")
                self.min_hops = min_hops
            if allow_direct is not None:
                self.allow_direct = allow_direct
            if connect_timeout is not None:
                if connect_timeout <= 0:
                    raise ConfigError("connect_timeout must be > 0")
                self.connect_timeout = connect_timeout

    def snapshot(self) -> dict:
        with self._lock:
            proxies = []
            for proxy in self._proxies:
                item = proxy.public()
                item["uses"] = self._uses.get(proxy.id, 0)
                item.update(self.health.snapshot(proxy.id))
                proxies.append(item)
            return {
                "mode": self.mode,
                "chain_length": self.chain_length,
                "min_hops": self.min_hops,
                "allow_direct": self.allow_direct,
                "connect_timeout": self.connect_timeout,
                "proxies": proxies,
            }

    def _plan_locked(self) -> list[Proxy]:
        enabled = [proxy for proxy in self._proxies if proxy.enabled]
        if self.mode == "static":
            if self.chain_length > 0:
                return enabled[: self.chain_length]
            return enabled
        ready, cooling = self.health.partition(enabled)
        pool = ready or cooling
        if self.mode == "dynamic":
            return pool
        if self.mode == "random":
            if not pool:
                return []
            count = len(pool) if self.chain_length <= 0 else min(self.chain_length, len(pool))
            return self._random.sample(pool, count)
        raise ConfigError(f"unknown mode {self.mode}")

    def _round_robin_locked(self) -> tuple[list[Proxy], int, int]:
        enabled = [proxy for proxy in self._proxies if proxy.enabled]
        ready, cooling = self.health.partition(enabled)
        pool = ready or cooling
        if not pool:
            return [], 0, 0
        count = len(pool)
        length = count if self.chain_length <= 0 else min(self.chain_length, count)
        start = self._rr % count
        self._rr += 1
        return pool, start, length

    def _connect_skipping(
        self,
        host: str,
        port: int,
        timeout: float,
        pool: list[Proxy],
    ) -> tuple[SocketIO, list[Proxy]]:
        working = list(pool)
        last: Exception | None = None
        while True:
            with self._lock:
                limit = self.chain_length
            attempt = working if limit <= 0 else working[:limit]
            try:
                self._ensure(attempt)
            except ProxyChainError as exc:
                if last is not None:
                    raise ProxyChainError(f"{exc}: {last}") from last
                raise
            try:
                io = open_chain(attempt, host, port, timeout)
            except HopError as exc:
                last = exc
                if not 0 <= exc.index < len(attempt):
                    raise
                if exc.proxy_dead:
                    self.health.mark_down(attempt[exc.index].id, hard=True)
                del working[exc.index]
                continue
            self._success(attempt)
            return io, attempt

    def _connect_windows(
        self,
        host: str,
        port: int,
        timeout: float,
        pool: list[Proxy],
        start: int,
        length: int,
    ) -> tuple[SocketIO, list[Proxy]]:
        if not pool:
            self._ensure([])
            io = open_chain([], host, port, timeout)
            return io, []
        count = len(pool)
        attempts = count if length < count else 1
        last: Exception | None = None
        for attempt in range(attempts):
            window = [pool[(start + attempt + offset) % count] for offset in range(length)]
            try:
                self._ensure(window)
                io = open_chain(window, host, port, timeout)
            except HopError as exc:
                last = exc
                if exc.proxy_dead and 0 <= exc.index < len(window):
                    self.health.mark_down(window[exc.index].id, hard=True)
                continue
            except ProxyChainError as exc:
                if last is not None:
                    raise ProxyChainError(f"{exc}: {last}") from last
                raise
            self._success(window)
            return io, window
        if self.allow_direct and self.min_hops == 0:
            return open_chain([], host, port, timeout), []
        raise ProxyChainError(f"all proxies failed: {last}")

    def _ensure(self, proxies: list[Proxy]) -> None:
        with self._lock:
            min_hops = self.min_hops
            allow_direct = self.allow_direct
        if len(proxies) < min_hops:
            raise ProxyChainError(f"need at least {min_hops} working proxies, have {len(proxies)}")
        if not proxies and not allow_direct:
            raise ProxyChainError("direct connections are disabled")

    def _success(self, proxies: list[Proxy]) -> None:
        with self._lock:
            for proxy in proxies:
                self._uses[proxy.id] = self._uses.get(proxy.id, 0) + 1
                self.health.mark_up(proxy.id)
