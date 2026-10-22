"""Local HTTP API for changing the chain without a restart."""

from __future__ import annotations

import hmac
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from proxy_chain.config import normalize_mode, parse_proxy
from proxy_chain.errors import ConfigError, ProxyChainError

log = logging.getLogger("proxy_chain.control")


class ControlHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler, service):
        self.service = service
        super().__init__(address, handler)


class ControlHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: ControlHTTPServer

    def log_message(self, fmt: str, *args) -> None:
        log.debug("%s - " + fmt, self.address_string(), *args)

    def do_GET(self) -> None:
        self._guard(self._get)

    def do_POST(self) -> None:
        self._guard(self._post)

    def do_PATCH(self) -> None:
        self._guard(self._patch)

    def do_DELETE(self) -> None:
        self._guard(self._delete)

    def _authorized(self) -> bool:
        token = self.server.service.settings.control_token
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme != "Bearer" or not presented:
            return False
        return hmac.compare_digest(presented, token)

    def _guard(self, method) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            method()
        except (ProxyChainError, ConfigError, json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            self._send(400, {"error": str(exc)})

    def _path(self) -> str:
        path = unquote(urlparse(self.path).path).rstrip("/")
        return path or "/"

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length < 0 or length > 1_000_000:
            raise ConfigError("body too large")
        if length == 0:
            return {}
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(data, dict):
            raise ConfigError("json object required")
        return data

    def _send(self, code: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            pass

    def _get(self) -> None:
        path = self._path()
        service = self.server.service
        if path == "/status":
            self._send(200, service.status())
            return
        if path == "/proxies":
            self._send(200, {"proxies": service.chain.snapshot()["proxies"]})
            return
        self._send(404, {"error": "not found"})

    def _post(self) -> None:
        path = self._path()
        service = self.server.service
        if path == "/proxies":
            proxy = parse_proxy(self._body())
            service.chain.add(proxy)
            self._send(201, proxy.public())
            return
        if path == "/mode":
            body = self._body()
            if not body:
                raise ConfigError("mode body is empty")
            mode = normalize_mode(body["mode"]) if "mode" in body else None
            service.chain.configure(
                mode=mode,
                chain_length=int(body["chain_length"]) if "chain_length" in body else None,
                min_hops=int(body["min_hops"]) if "min_hops" in body else None,
                allow_direct=bool(body["allow_direct"]) if "allow_direct" in body else None,
                connect_timeout=float(body["connect_timeout"]) if "connect_timeout" in body else None,
            )
            self._send(200, service.chain.snapshot())
            return
        if path == "/reorder":
            ids = self._body()["ids"]
            if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
                raise ConfigError("ids must be a list of strings")
            service.chain.reorder(ids)
            self._send(200, service.chain.snapshot())
            return
        if path == "/reload":
            service.reload()
            self._send(200, service.status())
            return
        if path == "/health/check":
            service.probe_once()
            self._send(200, {"proxies": service.chain.snapshot()["proxies"]})
            return
        self._send(404, {"error": "not found"})

    def _patch(self) -> None:
        proxy_id = self._proxy_id()
        body = self._body()
        if "enabled" not in body:
            raise ConfigError("enabled is required")
        proxy = self.server.service.chain.set_enabled(proxy_id, bool(body["enabled"]))
        self._send(200, proxy.public())

    def _delete(self) -> None:
        proxy = self.server.service.chain.remove(self._proxy_id())
        self._send(200, {"ok": True, "id": proxy.id})

    def _proxy_id(self) -> str:
        path = self._path()
        prefix = "/proxies/"
        if not path.startswith(prefix) or "/" in path[len(prefix) :]:
            raise ConfigError("not found")
        return path[len(prefix) :]


def start_control(service) -> ControlHTTPServer:
    host = service.settings.control_host
    port = service.settings.control_port
    try:
        httpd = ControlHTTPServer((host, port), ControlHandler, service)
    except OSError as exc:
        raise ConfigError(f"control bind {host}:{port} failed: {exc}") from exc
    thread = threading.Thread(target=httpd.serve_forever, name="proxy-control", daemon=True)
    thread.start()
    return httpd
