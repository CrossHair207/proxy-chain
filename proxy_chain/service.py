"""Process lifetime: listener, control API, health probes, and config reload."""

from __future__ import annotations

import logging
import os
import threading

from proxy_chain import __version__
from proxy_chain.chain import ChainManager
from proxy_chain.config import load_proxy_list_file, load_settings, normalize
from proxy_chain.control import start_control
from proxy_chain.errors import ConfigError
from proxy_chain.health import HealthTracker
from proxy_chain.models import Settings
from proxy_chain.server import ProxyServer, Stats

log = logging.getLogger("proxy_chain")
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class Service:
    def __init__(self, settings: Settings):
        self.settings = normalize(settings)
        self.stats = Stats()
        self.health = HealthTracker(
            timeout=self.settings.health_timeout,
            cooldown=self.settings.health_cooldown,
        )
        self.health.enabled = self.settings.health_enabled
        self.chain = ChainManager(
            self.settings.proxies,
            self.health,
            mode=self.settings.mode,
            chain_length=self.settings.chain_length,
            min_hops=self.settings.min_hops or 0,
            allow_direct=bool(self.settings.allow_direct),
            connect_timeout=self.settings.connect_timeout,
        )
        self.server: ProxyServer | None = None
        self.control = None
        self._stop = threading.Event()
        self._health_thread: threading.Thread | None = None
        self._reload_thread: threading.Thread | None = None
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._warn_exposure()
        try:
            self.server = ProxyServer(self.settings, self.chain, self.stats)
            self.server.start()
            if self.settings.control_enabled:
                self.control = start_control(self)
            if self.settings.health_enabled:
                self._start_health()
            if self.settings.config_path or self.settings.proxy_list:
                self._start_reload()
        except Exception:
            self.stop()
            raise
        self._started = True
        assert self.server is not None
        log.info(
            "listening on %s:%s mode=%s proxies=%s",
            self.settings.listen_host,
            self.server.port,
            self.chain.mode,
            len(self.chain.proxies()),
        )
        if self.control is not None:
            log.info(
                "control on %s:%s",
                self.settings.control_host,
                self.control.server_address[1],
            )

    def serve_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(3600):
                continue
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()
        control = self.control
        self.control = None
        if control is not None:
            try:
                control.shutdown()
                control.server_close()
            except OSError:
                pass
        if self.server is not None:
            self.server.stop()
            self.server = None
        if self._health_thread is not None:
            self._health_thread.join(timeout=2)
            self._health_thread = None
        if self._reload_thread is not None:
            self._reload_thread.join(timeout=2)
            self._reload_thread = None
        self._started = False

    def reload(self) -> None:
        path = self.settings.config_path
        if path:
            fresh = normalize(load_settings(path))
            self.chain.replace_proxies(fresh.proxies)
            self.chain.configure(
                mode=fresh.mode,
                chain_length=fresh.chain_length,
                min_hops=fresh.min_hops,
                allow_direct=fresh.allow_direct,
                connect_timeout=fresh.connect_timeout,
            )
            self.settings.proxy_list = fresh.proxy_list
            self.settings.proxy_scheme = fresh.proxy_scheme
            self.settings.proxy_username = fresh.proxy_username
            self.settings.proxy_password = fresh.proxy_password
            self.settings.idle_timeout = fresh.idle_timeout
            self.settings.handshake_timeout = fresh.handshake_timeout
            self.settings.health_interval = fresh.health_interval
            self.settings.health_timeout = fresh.health_timeout
            self.settings.health_cooldown = fresh.health_cooldown
            self.settings.health_enabled = fresh.health_enabled
            self.health.timeout = fresh.health_timeout
            self.health.cooldown = fresh.health_cooldown
            self.health.enabled = fresh.health_enabled
            if fresh.health_enabled:
                self._start_health()
            log.info("reloaded %s (%s proxies, mode %s)", path, len(fresh.proxies), fresh.mode)
            return
        if self.settings.proxy_list:
            proxies = load_proxy_list_file(
                self.settings.proxy_list,
                self.settings.proxy_scheme,
                self.settings.proxy_username,
                self.settings.proxy_password,
            )
            self.chain.replace_proxies(proxies)
            log.info("reloaded %s (%s proxies)", self.settings.proxy_list, len(proxies))
            return
        raise ConfigError("no config file to reload")

    def probe_once(self) -> None:
        self.health.probe(self.chain.proxies())

    def status(self) -> dict:
        snapshot = self.chain.snapshot()
        recent = self.server.recent_requests()[-20:] if self.server is not None else []
        snapshot.update(
            {
                "version": __version__,
                "listen": {
                    "host": self.settings.listen_host,
                    "port": self.server.port if self.server is not None else self.settings.listen_port,
                },
                "stats": self.stats.snapshot(),
                "proxy_list": self.settings.proxy_list,
                "proxy_scheme": self.settings.proxy_scheme,
                "recent_requests": [{"host": host, "port": port} for host, port in recent],
            }
        )
        return snapshot

    def _warn_exposure(self) -> None:
        if self.settings.listen_host not in _LOOPBACK and not self.settings.username:
            log.warning("listening on %s without authentication", self.settings.listen_host)
        if (
            self.settings.control_enabled
            and self.settings.control_host not in _LOOPBACK
            and not self.settings.control_token
        ):
            log.warning("control API on %s has no token", self.settings.control_host)

    def _start_health(self) -> None:
        if self._health_thread is not None and self._health_thread.is_alive():
            return

        def run() -> None:
            while not self._stop.is_set():
                if self.health.enabled:
                    try:
                        self.probe_once()
                    except Exception:
                        log.exception("health probe failed")
                if self._stop.wait(self.settings.health_interval):
                    break

        self._health_thread = threading.Thread(target=run, name="proxy-health", daemon=True)
        self._health_thread.start()

    def _start_reload(self) -> None:
        if self._reload_thread is not None and self._reload_thread.is_alive():
            return
        if not self.settings.config_path and not self.settings.proxy_list:
            return

        def stamp() -> tuple:
            paths = [self.settings.config_path, self.settings.proxy_list]
            found = []
            for item in paths:
                if not item:
                    continue
                try:
                    found.append((item, os.path.getmtime(item)))
                except OSError:
                    found.append((item, None))
            return tuple(found)

        def run() -> None:
            last = stamp()
            while not self._stop.wait(1.0):
                current = stamp()
                if current == last:
                    continue
                last = current
                try:
                    self.reload()
                except (ConfigError, OSError, ValueError) as exc:
                    log.warning("config reload failed: %s", exc)

        self._reload_thread = threading.Thread(target=run, name="proxy-reload", daemon=True)
        self._reload_thread.start()
