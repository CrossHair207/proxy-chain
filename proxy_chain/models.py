"""Shared data types."""

from __future__ import annotations

from dataclasses import dataclass, field

MODES = ("dynamic", "static", "random", "round_robin")


@dataclass
class Proxy:
    """One upstream proxy hop."""

    id: str
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    enabled: bool = True
    tls_verify: bool = True

    @property
    def display(self) -> str:
        auth = f"{self.username}@" if self.username else ""
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    def public(self) -> dict:
        return {
            "id": self.id,
            "url": self.display,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "enabled": self.enabled,
            "has_auth": self.username is not None,
            "tls_verify": self.tls_verify,
        }


@dataclass
class Settings:
    """Runtime configuration. ``None`` optionals are filled in by ``normalize``."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 1080
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    mode: str = "dynamic"
    chain_length: int = 0
    min_hops: int | None = None
    allow_direct: bool | None = None
    connect_timeout: float = 10.0
    handshake_timeout: float = 20.0
    idle_timeout: float = 300.0
    max_connections: int = 512
    proxies: list[Proxy] = field(default_factory=list)
    proxy_list: str | None = None
    proxy_scheme: str = "http"
    proxy_username: str | None = None
    proxy_password: str | None = field(default=None, repr=False)
    control_enabled: bool = False
    control_host: str = "127.0.0.1"
    control_port: int = 1081
    control_token: str | None = None
    health_enabled: bool = False
    health_interval: float = 30.0
    health_timeout: float = 5.0
    health_cooldown: float = 30.0
    config_path: str | None = None
