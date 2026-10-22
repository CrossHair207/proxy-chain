"""JSON configuration and proxy URL parsing."""

from __future__ import annotations

import hashlib
import json
import os
import re
from urllib.parse import parse_qs, quote, unquote, urlsplit

from proxy_chain.errors import ConfigError
from proxy_chain.models import Proxy, Settings

_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_DEFAULT_PORTS = {"socks5": 1080, "socks4": 1080, "http": 8080, "https": 443}


_MODE_ALIASES = {
    "dynamic": "dynamic",
    "dynamic_chain": "dynamic",
    "static": "static",
    "strict": "static",
    "strict_chain": "static",
    "random": "random",
    "random_chain": "random",
    "round_robin": "round_robin",
}


def normalize_mode(value: str) -> str:
    key = str(value).strip().lower().replace("-", "_")
    canonical = _MODE_ALIASES.get(key)
    if canonical is None:
        names = "dynamic, static, random, round_robin"
        raise ConfigError(f"unknown mode {value!r}; expected one of {names}")
    return canonical


def parse_proxy(entry: str | dict, index: int = 0) -> Proxy:
    if isinstance(entry, str):
        data: dict = {"url": entry}
    elif isinstance(entry, dict):
        data = entry
    else:
        raise ConfigError(f"proxy #{index + 1} must be a url or an object")
    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        raise ConfigError(f"proxy #{index + 1} is missing a url")
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ConfigError(f"unsupported proxy scheme {scheme!r}")
    host = parts.hostname
    if not host:
        raise ConfigError("proxy url is missing a host")
    try:
        port = parts.port or int(data.get("port") or _DEFAULT_PORTS[scheme])
    except (TypeError, ValueError) as exc:
        raise ConfigError("bad proxy port") from exc
    if not 1 <= port <= 65535:
        raise ConfigError(f"bad proxy port {port}")

    if parts.username is not None:
        username: str | None = unquote(parts.username)
    else:
        raw_user = data.get("username")
        username = raw_user if isinstance(raw_user, str) and raw_user else None
    if parts.password is not None:
        password: str | None = unquote(parts.password)
    elif username is not None and "password" in data:
        password = data.get("password")
    else:
        password = None
    if username is not None and not isinstance(username, str):
        raise ConfigError("username must be a string")
    if password is not None and not isinstance(password, str):
        raise ConfigError("password must be a string")
    if username is None:
        password = None

    query = parse_qs(parts.query)
    if "tls_verify" in data:
        tls_verify = bool(data["tls_verify"])
    elif "tls_verify" in query:
        tls_verify = query["tls_verify"][-1].lower() not in {"0", "false", "no"}
    else:
        tls_verify = True

    proxy_id = data.get("id") or hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    if not isinstance(proxy_id, str) or not _ID.fullmatch(proxy_id):
        raise ConfigError(f"bad proxy id {proxy_id!r}")
    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError("enabled must be a boolean")
    return Proxy(
        id=proxy_id,
        scheme=scheme,
        host=host,
        port=port,
        username=username,
        password=password,
        enabled=enabled,
        tls_verify=tls_verify,
    )


def merge_proxies(*groups: list[Proxy]) -> list[Proxy]:
    merged: list[Proxy] = []
    seen: set[str] = set()
    for group in groups:
        for proxy in group:
            if proxy.id in seen:
                continue
            seen.add(proxy.id)
            merged.append(proxy)
    return merged


def _proxy_url(scheme: str, host: str, port: int, username: str | None, password: str | None) -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if username is None:
        return f"{scheme}://{host}:{port}"
    user = quote(username, safe="")
    secret = quote(password or "", safe="")
    return f"{scheme}://{user}:{secret}@{host}:{port}"


def load_proxy_list_file(
    path: str,
    scheme: str = "http",
    username: str | None = None,
    password: str | None = None,
) -> list[Proxy]:
    """Read a proxy list, including a Webshare ``ip:port:user:pass`` download."""
    scheme = scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ConfigError(f"unsupported proxy scheme {scheme!r}")
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError as exc:
        raise ConfigError(
            f"proxy list not found: {path}. Copy proxies.example.txt to proxies.txt and add your proxies."
        ) from exc
    except OSError as exc:
        raise ConfigError(f"could not read proxy list {path}: {exc}") from exc

    current_scheme = scheme
    proxies: list[Proxy] = []
    for index, raw_line in enumerate(lines, start=1):
        line = raw_line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith("scheme ") or lowered.startswith("protocol "):
            current_scheme = lowered.split(None, 1)[1].strip()
            if current_scheme not in _DEFAULT_PORTS:
                raise ConfigError(f"{path}:{index}: unsupported scheme {current_scheme!r}")
            continue
        proxies.append(_proxy_from_list_line(line, index, path, current_scheme, username, password))
    return merge_proxies(proxies)


def _proxy_from_list_line(
    line: str,
    index: int,
    path: str,
    scheme: str,
    username: str | None,
    password: str | None,
) -> Proxy:
    try:
        if "://" in line:
            return parse_proxy(line, index - 1)
        if "@" in line:
            auth, _, hostport = line.rpartition("@")
            user, sep, secret = auth.partition(":")
            if not sep or not user:
                raise ConfigError("expected user:password@host:port")
            host, port = split_list_host_port(hostport, _DEFAULT_PORTS[scheme])
            return parse_proxy(_proxy_url(scheme, host, port, user, secret), index - 1)
        parts = [part.strip() for part in line.split(":")]
        if len(parts) >= 4:
            host, port_text, user = parts[0], parts[1], parts[2]
            secret = ":".join(parts[3:])
            port = int(port_text)
            return parse_proxy(_proxy_url(scheme, host, port, user, secret), index - 1)
        if len(parts) == 2:
            host, port = parts[0], int(parts[1])
            return parse_proxy(_proxy_url(scheme, host, port, username, password), index - 1)
    except (ConfigError, ValueError) as exc:
        raise ConfigError(f"{path}:{index}: {exc}") from exc
    raise ConfigError(
        f"{path}:{index}: use ip:port:username:password, user:password@host:port, or a proxy URL"
    )


def split_list_host_port(target: str, default: int) -> tuple[str, int]:
    from proxy_chain.protocols import split_host_port

    return split_host_port(target, default)


def resolve_list_path(path: str, config_path: str | None) -> str:
    if os.path.isabs(path):
        return path
    base = os.path.dirname(os.path.abspath(config_path)) if config_path else os.getcwd()
    return os.path.normpath(os.path.join(base, path))


def parse_proxy_list(entries: list) -> list[Proxy]:
    if not isinstance(entries, list):
        raise ConfigError("proxies must be a list")
    proxies: list[Proxy] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        proxy = parse_proxy(entry, index)
        if proxy.id in seen:
            raise ConfigError(f"duplicate proxy id {proxy.id}")
        seen.add(proxy.id)
        proxies.append(proxy)
    return proxies


def normalize(settings: Settings) -> Settings:
    settings.mode = normalize_mode(settings.mode)
    if settings.username == "":
        settings.username = None
    if settings.username is None:
        settings.password = None
    elif settings.password is None:
        settings.password = ""
    if settings.control_token == "":
        settings.control_token = None
    if settings.min_hops is None:
        settings.min_hops = 1 if settings.proxies else 0
    if settings.allow_direct is None:
        settings.allow_direct = not bool(settings.proxies)
    if settings.min_hops < 0:
        raise ConfigError("min_hops must be >= 0")
    if settings.chain_length < 0:
        raise ConfigError("chain_length must be >= 0")
    if not 0 <= settings.listen_port <= 65535:
        raise ConfigError("bad listen port")
    if not 0 <= settings.control_port <= 65535:
        raise ConfigError("bad control port")
    if settings.max_connections < 1:
        raise ConfigError("max_connections must be >= 1")
    for name, value in (
        ("connect_timeout", settings.connect_timeout),
        ("handshake_timeout", settings.handshake_timeout),
        ("idle_timeout", settings.idle_timeout),
        ("health_interval", settings.health_interval),
        ("health_timeout", settings.health_timeout),
        ("health_cooldown", settings.health_cooldown),
    ):
        if value <= 0:
            raise ConfigError(f"{name} must be > 0")
    return settings


def _blank(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError("expected a string")
    stripped = value.strip()
    return stripped or None


def _object(raw: dict, key: str) -> dict:
    value = raw.get(key) or {}
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be an object")
    return value


def settings_from_dict(raw: dict, config_path: str | None = None) -> Settings:
    """Build settings without filling hop defaults.

    ``Service`` calls ``normalize`` after CLI overrides, so omitted
    ``min_hops`` and ``allow_direct`` follow the final proxy list.
    """
    if not isinstance(raw, dict):
        raise ConfigError("config root must be an object")
    listen = _object(raw, "listen")
    auth = _object(raw, "auth")
    settings = Settings(config_path=config_path)
    settings.listen_host = str(listen.get("host", settings.listen_host))
    settings.listen_port = int(listen.get("port", settings.listen_port))
    if "username" in auth:
        settings.username = _blank(auth.get("username"))
    if settings.username is not None:
        password = auth.get("password", "")
        if not isinstance(password, str):
            raise ConfigError("password must be a string")
        settings.password = password
    if "mode" in raw:
        settings.mode = normalize_mode(str(raw["mode"]))
    if "chain_length" in raw:
        settings.chain_length = int(raw["chain_length"])
    if "min_hops" in raw:
        settings.min_hops = int(raw["min_hops"])
    if "allow_direct" in raw:
        settings.allow_direct = bool(raw["allow_direct"])
    if "connect_timeout" in raw:
        settings.connect_timeout = float(raw["connect_timeout"])
    if "handshake_timeout" in raw:
        settings.handshake_timeout = float(raw["handshake_timeout"])
    if "idle_timeout" in raw:
        settings.idle_timeout = float(raw["idle_timeout"])
    if "max_connections" in raw:
        settings.max_connections = int(raw["max_connections"])
    settings.proxies = parse_proxy_list(list(raw.get("proxies") or []))
    if "proxy_scheme" in raw and raw.get("proxy_scheme"):
        settings.proxy_scheme = str(raw["proxy_scheme"]).strip().lower()
    if settings.proxy_scheme not in _DEFAULT_PORTS:
        raise ConfigError(f"unsupported proxy scheme {settings.proxy_scheme!r}")
    if "proxy_username" in raw:
        settings.proxy_username = _blank(raw.get("proxy_username"))
    if settings.proxy_username is not None:
        list_password = raw.get("proxy_password", "")
        if not isinstance(list_password, str):
            raise ConfigError("proxy_password must be a string")
        settings.proxy_password = list_password
    if raw.get("proxy_list"):
        if not isinstance(raw["proxy_list"], str):
            raise ConfigError("proxy_list must be a file path")
        settings.proxy_list = resolve_list_path(raw["proxy_list"], config_path)
        listed = load_proxy_list_file(
            settings.proxy_list,
            settings.proxy_scheme,
            settings.proxy_username,
            settings.proxy_password,
        )
        settings.proxies = merge_proxies(settings.proxies, listed)

    control = raw.get("control")
    if control is None:
        settings.control_enabled = True
    else:
        if not isinstance(control, dict):
            raise ConfigError("control must be an object")
        settings.control_enabled = bool(control.get("enabled", True))
        settings.control_host = str(control.get("host", settings.control_host))
        settings.control_port = int(control.get("port", settings.control_port))
        if "token" in control:
            settings.control_token = _blank(control.get("token"))

    health = raw.get("health")
    if health is None:
        settings.health_enabled = True
    else:
        if not isinstance(health, dict):
            raise ConfigError("health must be an object")
        settings.health_enabled = bool(health.get("enabled", True))
        settings.health_interval = float(health.get("interval", settings.health_interval))
        settings.health_timeout = float(health.get("timeout", settings.health_timeout))
        settings.health_cooldown = float(health.get("cooldown", settings.health_cooldown))
    return settings


def load_settings(path: str | None) -> Settings:
    if not path:
        return Settings(control_enabled=True, health_enabled=True)
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return settings_from_dict(raw, config_path=path)
