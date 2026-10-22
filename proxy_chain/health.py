"""Background TCP health checks and per-proxy cooldown."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from proxy_chain.errors import ProxyChainError
from proxy_chain.models import Proxy
from proxy_chain.net import tcp_connect


@dataclass
class _State:
    fails: int = 0
    down_until: float = 0.0


class HealthTracker:
    """Tracks which proxies recently failed.

    A hard failure (a hop died during a client connection) cools the proxy
    down immediately. A probe failure counts toward ``threshold`` first.
    """

    def __init__(self, timeout: float, threshold: int = 2, cooldown: float = 30.0):
        self.timeout = timeout
        self.threshold = threshold
        self.cooldown = cooldown
        self.enabled = False
        self._lock = threading.Lock()
        self._states: dict[str, _State] = {}

    def partition(self, proxies: list[Proxy]) -> tuple[list[Proxy], list[Proxy]]:
        if not self.enabled:
            return list(proxies), []
        now = time.monotonic()
        ready: list[Proxy] = []
        cooling: list[Proxy] = []
        with self._lock:
            for proxy in proxies:
                state = self._states.get(proxy.id)
                if state is not None and state.down_until > now:
                    cooling.append(proxy)
                else:
                    ready.append(proxy)
        return ready, cooling

    def mark_up(self, proxy_id: str) -> None:
        with self._lock:
            self._states[proxy_id] = _State()

    def mark_down(self, proxy_id: str, *, hard: bool = False) -> None:
        with self._lock:
            state = self._states.setdefault(proxy_id, _State())
            state.fails += 1
            if hard or state.fails >= self.threshold:
                state.down_until = time.monotonic() + self.cooldown

    def snapshot(self, proxy_id: str) -> dict:
        with self._lock:
            state = self._states.get(proxy_id)
            if state is None:
                return {"healthy": True, "failures": 0}
            cooling = state.down_until > time.monotonic()
            return {"healthy": not cooling, "failures": state.fails}

    def probe(self, proxies: list[Proxy]) -> None:
        for proxy in proxies:
            if not proxy.enabled:
                continue
            try:
                sock = tcp_connect(proxy.host, proxy.port, self.timeout)
            except (ProxyChainError, OSError):
                self.mark_down(proxy.id, hard=False)
                continue
            sock.close()
            self.mark_up(proxy.id)
