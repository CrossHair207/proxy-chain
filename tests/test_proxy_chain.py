"""Behavioral tests for the local proxy chain."""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import ssl
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from proxy_chain.cli import settings_from_args
from proxy_chain.config import (
    load_proxy_list_file,
    load_settings,
    normalize_mode,
    parse_proxy,
    parse_proxy_list,
)
from proxy_chain.errors import ConfigError, ProxyChainError
from proxy_chain.health import HealthTracker
from proxy_chain.models import Proxy, Settings
from proxy_chain.net import SocketIO
from proxy_chain.protocols import socks5_client
from proxy_chain.service import Service


def recvn(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


class Echo:
    def __init__(self) -> None:
        self.accepted = 0
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accepted += 1
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn: socket.socket) -> None:
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


def refused_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def connect_socks(port: int, host: str, dest_port: int, user: str | None = None, password: str | None = None):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    try:
        io = SocketIO(sock)
        socks5_client(io, host, dest_port, user, password)
        if io.pending():
            raise AssertionError(f"unexpected buffered bytes: {io.drain()!r}")
    except Exception:
        sock.close()
        raise
    return sock


def exchange(sock: socket.socket, payload: bytes) -> bytes:
    sock.sendall(payload)
    return recvn(sock, len(payload))


class ProxyCase(unittest.TestCase):
    def setUp(self) -> None:
        self._cleanup = []

    def tearDown(self) -> None:
        for obj in reversed(self._cleanup):
            stopper = getattr(obj, "stop", None) or obj.close
            stopper()

    def track(self, obj):
        self._cleanup.append(obj)
        return obj

    def service(self, **kwargs) -> Service:
        settings = Settings(
            listen_port=0,
            connect_timeout=2,
            handshake_timeout=5,
            idle_timeout=5,
            **kwargs,
        )
        service = Service(settings)
        service.start()
        return self.track(service)

    def echo(self) -> Echo:
        return self.track(Echo())

    def proxy_url(self, service: Service, scheme: str = "socks5", user: str | None = None, password: str | None = None) -> str:
        auth = ""
        if user is not None:
            secret = password or ""
            auth = f"{user}:{secret}@"
        return f"{scheme}://{auth}127.0.0.1:{service.server.port}"


class ChainTests(ProxyCase):
    def test_direct_socks5_echo(self) -> None:
        echo = self.echo()
        proxy = self.service()
        payload = b"ping-direct"
        sock = connect_socks(proxy.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, payload), payload)
        finally:
            sock.close()
        self.assertEqual(proxy.stats.snapshot()["succeeded"], 1)
        self.assertGreaterEqual(proxy.stats.snapshot()["bytes_to_remote"], len(payload))
        self.assertGreaterEqual(proxy.stats.snapshot()["bytes_to_client"], len(payload))

    def test_two_hop_strict_chain(self) -> None:
        echo = self.echo()
        exit_proxy = self.service()
        mid_proxy = self.service()
        chain = self.service(
            mode="strict",
            proxies=[
                parse_proxy(self.proxy_url(mid_proxy), 0),
                parse_proxy(self.proxy_url(exit_proxy), 1),
            ],
        )
        payload = b"through-two-hops"
        sock = connect_socks(chain.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, payload), payload)
        finally:
            sock.close()
        self.assertIn(("127.0.0.1", exit_proxy.server.port), mid_proxy.server.recent_requests())
        self.assertIn(("127.0.0.1", echo.port), exit_proxy.server.recent_requests())
        self.assertEqual(echo.accepted, 1)

    def test_dynamic_skips_dead_proxy_and_strict_does_not(self) -> None:
        echo = self.echo()
        exit_proxy = self.service()
        dead = f"socks5://127.0.0.1:{refused_port()}"
        live = self.proxy_url(exit_proxy)
        dynamic = self.service(mode="dynamic", proxies=parse_proxy_list([dead, live]))
        payload = b"skipped-dead"
        sock = connect_socks(dynamic.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, payload), payload)
        finally:
            sock.close()
        self.assertIn(("127.0.0.1", echo.port), exit_proxy.server.recent_requests())

        strict = self.service(mode="strict", proxies=parse_proxy_list([dead, live]))
        with self.assertRaises(ProxyChainError):
            connect_socks(strict.server.port, "127.0.0.1", echo.port)
        self.assertEqual(len(exit_proxy.server.recent_requests()), 1)

    def test_min_hops_blocks_direct_and_zero_allows_it(self) -> None:
        echo = self.echo()
        dead = parse_proxy(f"socks5://127.0.0.1:{refused_port()}")
        blocked = self.service(mode="dynamic", proxies=[dead], min_hops=1, allow_direct=True)
        with self.assertRaises(ProxyChainError):
            connect_socks(blocked.server.port, "127.0.0.1", echo.port)
        self.assertEqual(echo.accepted, 0)

        fallback = self.service(mode="dynamic", proxies=[dead], min_hops=0, allow_direct=True)
        payload = b"direct-fallback"
        sock = connect_socks(fallback.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, payload), payload)
        finally:
            sock.close()
        self.assertEqual(echo.accepted, 1)

    def test_target_refusal_does_not_retire_proxy(self) -> None:
        exit_proxy = self.service()
        chain = self.service(mode="dynamic", proxies=[parse_proxy(self.proxy_url(exit_proxy))])
        with self.assertRaises(ProxyChainError):
            connect_socks(chain.server.port, "127.0.0.1", refused_port())
        proxy = chain.chain.snapshot()["proxies"][0]
        self.assertTrue(proxy["healthy"])
        self.assertEqual(proxy["uses"], 0)
        self.assertEqual(proxy["failures"], 0)

    def test_dynamic_chain_length_uses_one_working_proxy(self) -> None:
        echo = self.echo()
        first = self.service()
        second = self.service()
        chain = self.service(
            mode="dynamic",
            chain_length=1,
            proxies=[
                parse_proxy(self.proxy_url(first), 0),
                parse_proxy(self.proxy_url(second), 1),
            ],
        )
        sock = connect_socks(chain.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, b"one-hop"), b"one-hop")
        finally:
            sock.close()
        self.assertIn(("127.0.0.1", echo.port), first.server.recent_requests())
        self.assertEqual(second.server.recent_requests(), [])

    def test_round_robin_rotates_single_hops(self) -> None:
        echo = self.echo()
        first = self.service()
        second = self.service()
        chain = self.service(
            mode="round_robin",
            chain_length=1,
            proxies=[
                parse_proxy(self.proxy_url(first), 0),
                parse_proxy(self.proxy_url(second), 1),
            ],
        )
        for _ in range(2):
            sock = connect_socks(chain.server.port, "127.0.0.1", echo.port)
            try:
                self.assertEqual(exchange(sock, b"rr"), b"rr")
            finally:
                sock.close()
        uses = [item["uses"] for item in chain.chain.snapshot()["proxies"]]
        self.assertEqual(uses, [1, 1])
        self.assertEqual(len(first.server.recent_requests()), 1)
        self.assertEqual(len(second.server.recent_requests()), 1)

    def test_random_uses_one_hop_when_length_is_one(self) -> None:
        echo = self.echo()
        first = self.service()
        second = self.service()
        chain = self.service(
            mode="random",
            chain_length=1,
            proxies=[
                parse_proxy(self.proxy_url(first), 0),
                parse_proxy(self.proxy_url(second), 1),
            ],
        )
        sock = connect_socks(chain.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, b"one"), b"one")
        finally:
            sock.close()
        seen = len(first.server.recent_requests()) + len(second.server.recent_requests())
        self.assertEqual(seen, 1)

    def test_disabled_proxy_is_not_used(self) -> None:
        echo = self.echo()
        live = self.service()
        dead = parse_proxy({"id": "dead", "url": f"socks5://127.0.0.1:{refused_port()}", "enabled": False})
        chain = self.service(mode="strict", proxies=[dead, parse_proxy(self.proxy_url(live))])
        sock = connect_socks(chain.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, b"enabled-only"), b"enabled-only")
        finally:
            sock.close()

    def test_upstream_auth_and_http_and_socks4_hops(self) -> None:
        echo = self.echo()
        secured = self.service(username="alice", password="secret")
        http_hop = self.service()
        socks4_hop = self.service()
        authed = self.service(proxies=[parse_proxy(self.proxy_url(secured, user="alice", password="secret"))])
        via_http = self.service(proxies=[parse_proxy(self.proxy_url(http_hop, scheme="http"))])
        via_socks4 = self.service(proxies=[parse_proxy(self.proxy_url(socks4_hop, scheme="socks4"))])
        payload = b"x" * 100_000
        for proxy in (authed, via_http, via_socks4):
            sock = connect_socks(proxy.server.port, "127.0.0.1", echo.port)
            try:
                self.assertEqual(exchange(sock, payload), payload)
            finally:
                sock.close()
        wrong = self.service(proxies=[parse_proxy(self.proxy_url(secured, user="alice", password="nope"))])
        with self.assertRaises(ProxyChainError):
            connect_socks(wrong.server.port, "127.0.0.1", echo.port)

    def test_local_socks_auth_and_socks4_client(self) -> None:
        echo = self.echo()
        proxy = self.service(username="alice", password="secret")
        with self.assertRaises(ProxyChainError):
            connect_socks(proxy.server.port, "127.0.0.1", echo.port)
        sock = connect_socks(proxy.server.port, "127.0.0.1", echo.port, "alice", "secret")
        try:
            self.assertEqual(exchange(sock, b"authed"), b"authed")
        finally:
            sock.close()

        open_proxy = self.service()
        raw = socket.create_connection(("127.0.0.1", open_proxy.server.port), timeout=5)
        raw.settimeout(5)
        try:
            ip = socket.inet_aton("127.0.0.1")
            raw.sendall(b"\x04\x01" + echo.port.to_bytes(2, "big") + ip + b"\x00")
            reply = recvn(raw, 8)
            self.assertEqual(reply[1], 0x5A)
            self.assertEqual(exchange(raw, b"socks4"), b"socks4")
        finally:
            raw.close()

    def test_hostname_is_forwarded_to_the_exit(self) -> None:
        exit_proxy = self.service()
        chain = self.service(proxies=[parse_proxy(self.proxy_url(exit_proxy))])
        with self.assertRaises((ProxyChainError, TimeoutError, OSError)):
            connect_socks(chain.server.port, "no-such-host.invalid", 9)
        self.assertIn(("no-such-host.invalid", 9), exit_proxy.server.recent_requests())

    def test_http_connect_and_rewritten_request(self) -> None:
        echo = self.echo()
        proxy = self.service(username="alice", password="secret")
        token = base64.b64encode(b"alice:secret").decode("ascii")
        denied = socket.create_connection(("127.0.0.1", proxy.server.port), timeout=5)
        denied.settimeout(5)
        try:
            denied.sendall(f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: 127.0.0.1:{echo.port}\r\n\r\n".encode())
            head = recvn(denied, 32)
            self.assertTrue(head.startswith(b"HTTP/1.1 407"))
        finally:
            denied.close()

        sock = socket.create_connection(("127.0.0.1", proxy.server.port), timeout=5)
        sock.settimeout(5)
        try:
            request = (
                f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{echo.port}\r\n"
                f"Proxy-Authorization: Basic {token}\r\n\r\n"
            ).encode()
            sock.sendall(request)
            buf = bytearray()
            while b"\r\n\r\n" not in buf:
                buf += sock.recv(4096)
            self.assertIn(b" 200 ", bytes(buf).split(b"\r\n", 1)[0])
            self.assertEqual(exchange(sock, b"tunneled"), b"tunneled")
        finally:
            sock.close()

        plain = self.service()
        client = socket.create_connection(("127.0.0.1", plain.server.port), timeout=5)
        client.settimeout(5)
        try:
            client.sendall(
                (
                    f"GET http://127.0.0.1:{echo.port}/hello?x=1 HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{echo.port}\r\n"
                    "Proxy-Authorization: Basic bm9wZQo=\r\n"
                    "\r\n"
                ).encode()
            )
            received = bytearray()
            while b"GET /hello?x=1 HTTP/1.1" not in received:
                chunk = client.recv(4096)
                if not chunk:
                    break
                received += chunk
            self.assertIn(b"GET /hello?x=1 HTTP/1.1", received)
            self.assertNotIn(b"GET http://", received)
            self.assertNotIn(b"Proxy-Authorization", received)
        finally:
            client.close()


class ControlTests(ProxyCase):
    def api(self, service: Service, method: str, path: str, body: dict | None = None, token: str | None = "tok"):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{service.control.server_address[1]}{path}",
            data=data,
            method=method,
        )
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if token is not None:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_runtime_updates_and_secret_redaction(self) -> None:
        echo = self.echo()
        exit_proxy = self.service(username="alice", password="super-secret-value")
        chain = self.service(
            control_enabled=True,
            control_port=0,
            control_token="tok",
            min_hops=1,
            allow_direct=False,
        )
        self.assertEqual(self.api(chain, "GET", "/status", token=None)[0], 401)
        status_code, status = self.api(chain, "GET", "/status")
        self.assertEqual(status_code, 200)
        self.assertEqual(status["proxies"], [])

        created_code, created = self.api(
            chain,
            "POST",
            "/proxies",
            {"url": self.proxy_url(exit_proxy, user="alice", password="super-secret-value")},
        )
        self.assertEqual(created_code, 201)
        self.assertNotIn("super-secret-value", json.dumps(created))
        proxy_id = created["id"]
        sock = connect_socks(chain.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, b"added"), b"added")
        finally:
            sock.close()
        self.assertNotIn("super-secret-value", json.dumps(chain.status()))

        self.api(chain, "PATCH", f"/proxies/{proxy_id}", {"enabled": False})
        with self.assertRaises(ProxyChainError):
            connect_socks(chain.server.port, "127.0.0.1", echo.port)
        self.api(chain, "PATCH", f"/proxies/{proxy_id}", {"enabled": True})
        sock = connect_socks(chain.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, b"enabled-again"), b"enabled-again")
        finally:
            sock.close()

        other = parse_proxy("socks5://127.0.0.1:1")
        self.api(chain, "POST", "/proxies", {"id": other.id, "url": "socks5://127.0.0.1:1"})
        code, body = self.api(chain, "POST", "/reorder", {"ids": [other.id, proxy_id]})
        self.assertEqual(code, 200)
        self.assertEqual([item["id"] for item in body["proxies"]], [other.id, proxy_id])
        mode_code, mode_body = self.api(chain, "POST", "/mode", {"mode": "strict_chain", "chain_length": 2})
        self.assertEqual(mode_code, 200)
        self.assertEqual(mode_body["mode"], "static")
        self.assertEqual(mode_body["chain_length"], 2)
        delete_code, _ = self.api(chain, "DELETE", f"/proxies/{other.id}")
        self.assertEqual(delete_code, 200)
        self.api(chain, "DELETE", f"/proxies/{proxy_id}")
        with self.assertRaises(ProxyChainError):
            connect_socks(chain.server.port, "127.0.0.1", echo.port)

    def test_reload_replaces_chain(self) -> None:
        directory = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        path = os.path.join(directory, "chain.json")
        document = {
            "listen": {"host": "127.0.0.1", "port": 0},
            "mode": "dynamic",
            "control": {"enabled": False},
            "health": {"enabled": False},
            "proxies": [{"id": "old", "url": "socks5://127.0.0.1:1"}],
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        service = Service(load_settings(path))
        service.start()
        self.track(service)
        document["mode"] = "static"
        document["proxies"] = [{"id": "new", "url": "http://127.0.0.1:9"}]
        replacement = path + ".next"
        with open(replacement, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        os.replace(replacement, path)
        service.reload()
        snapshot = service.chain.snapshot()
        self.assertEqual(snapshot["mode"], "static")
        self.assertEqual([item["id"] for item in snapshot["proxies"]], ["new"])


class ConfigTests(unittest.TestCase):
    def test_mode_aliases_match_proxychains_names(self) -> None:
        self.assertEqual(normalize_mode("dynamic_chain"), "dynamic")
        self.assertEqual(normalize_mode("strict_chain"), "static")
        self.assertEqual(normalize_mode("static"), "static")
        self.assertEqual(normalize_mode("random-chain"), "random")

    def test_webshare_proxy_list(self) -> None:
        directory = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        path = os.path.join(directory, "proxies.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "\n".join(
                    [
                        "# downloaded from webshare",
                        "scheme http",
                        "1.2.3.4:8080:alice:p:ass",
                        "bob:secret@5.6.7.8:9090",
                        "http://carol:pw@9.9.9.9:80",
                        "10.0.0.5:8000",
                        "10.0.0.5:8000",
                        "scheme socks5",
                        "11.0.0.8:1080:sam:socks-pass",
                    ]
                )
            )
        proxies = load_proxy_list_file(path, scheme="http", username="fallback", password="fb-pass")
        self.assertEqual(
            [(item.scheme, item.host, item.port, item.username, item.password) for item in proxies],
            [
                ("http", "1.2.3.4", 8080, "alice", "p:ass"),
                ("http", "5.6.7.8", 9090, "bob", "secret"),
                ("http", "9.9.9.9", 80, "carol", "pw"),
                ("http", "10.0.0.5", 8000, "fallback", "fb-pass"),
                ("socks5", "11.0.0.8", 1080, "sam", "socks-pass"),
            ],
        )
        self.assertNotIn("p:ass", proxies[0].display)
        self.assertNotIn("fb-pass", json.dumps(proxies[3].public()))
        with self.assertRaises(ConfigError):
            load_proxy_list_file(os.path.join(directory, "missing.txt"))

    def test_proxy_urls(self) -> None:
        password = parse_proxy("socks5://user:p%40ss@10.0.0.8:1080")
        self.assertEqual(password.username, "user")
        self.assertEqual(password.password, "p@ss")
        self.assertNotIn("p@ss", password.display)
        ipv6 = parse_proxy("socks5://[::1]:1080")
        self.assertEqual(ipv6.host, "::1")
        self.assertEqual(ipv6.port, 1080)
        defaults = parse_proxy("https://proxy.example?tls_verify=0")
        self.assertEqual(defaults.port, 443)
        self.assertFalse(defaults.tls_verify)
        with self.assertRaises(ConfigError):
            parse_proxy("ftp://127.0.0.1:1")
        with self.assertRaises(ConfigError):
            parse_proxy_list(["socks5://127.0.0.1:1", {"id": parse_proxy("socks5://127.0.0.1:1").id, "url": "socks5://127.0.0.1:1"}])

    def test_cli_defaults_do_not_leak_when_proxies_are_set(self) -> None:
        empty, _ = settings_from_args(["--control", "off", "--no-health"])
        self.assertEqual(empty.min_hops, 0)
        self.assertTrue(empty.allow_direct)
        chained, _ = settings_from_args(
            ["--proxy", "socks5://127.0.0.1:9050", "--mode", "round-robin", "--control", "off", "--no-health"]
        )
        self.assertEqual(chained.mode, "round_robin")
        self.assertEqual(chained.min_hops, 1)
        self.assertFalse(chained.allow_direct)
        self.assertFalse(chained.health_enabled)
        fallback, _ = settings_from_args(
            ["--proxy", "socks5://127.0.0.1:9050", "--allow-direct", "--control", "off", "--no-health"]
        )
        self.assertEqual(fallback.min_hops, 0)
        self.assertTrue(fallback.allow_direct)

    def test_health_cooldown_skips_a_proxy_until_it_is_marked_up(self) -> None:
        health = HealthTracker(timeout=0.2, cooldown=30)
        health.enabled = True
        proxy = Proxy(id="a", scheme="socks5", host="127.0.0.1", port=1)
        ready, cooling = health.partition([proxy])
        self.assertEqual(ready, [proxy])
        self.assertEqual(cooling, [])
        health.mark_down(proxy.id, hard=True)
        ready, cooling = health.partition([proxy])
        self.assertEqual(ready, [])
        self.assertEqual(cooling, [proxy])
        health.mark_up(proxy.id)
        ready, cooling = health.partition([proxy])
        self.assertEqual(ready, [proxy])


def _write_test_cert(directory: str) -> tuple[str, str] | None:
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_path = os.path.join(directory, "key.pem")
    cert_path = os.path.join(directory, "cert.pem")
    with open(key_path, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


class TlsHopTests(ProxyCase):
    def test_https_upstream(self) -> None:
        directory = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        material = _write_test_cert(directory)
        if material is None:
            self.skipTest("cryptography is not installed")
        cert, key = material
        echo = self.echo()
        hop = _TlsConnectProxy(cert, key)
        self.track(hop)
        chain = self.service(proxies=[parse_proxy(f"https://127.0.0.1:{hop.port}?tls_verify=0")])
        sock = connect_socks(chain.server.port, "127.0.0.1", echo.port)
        try:
            self.assertEqual(exchange(sock, b"tls-hop"), b"tls-hop")
        finally:
            sock.close()


class _TlsConnectProxy:
    """Minimal TLS HTTP CONNECT proxy used as an upstream hop."""

    def __init__(self, cert: str, key: str) -> None:
        self._raw = socket.socket()
        self._raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._raw.bind(("127.0.0.1", 0))
        self._raw.listen()
        self.port = self._raw.getsockname()[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self._context = context
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        self._raw.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._raw.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        upstream = None
        tls = None
        try:
            tls = self._context.wrap_socket(conn, server_side=True)
            buf = bytearray()
            while b"\r\n\r\n" not in buf:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                buf += chunk
            line = bytes(buf).split(b"\r\n", 1)[0].decode()
            target = line.split(" ")[1]
            host, port_text = target.rsplit(":", 1)
            upstream = socket.create_connection((host, int(port_text)), timeout=5)
            tls.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._relay(tls, upstream)
        except OSError:
            pass
        finally:
            if tls is not None:
                try:
                    tls.close()
                except OSError:
                    pass
            else:
                conn.close()
            if upstream is not None:
                upstream.close()

    @staticmethod
    def _relay(left: socket.socket, right: socket.socket) -> None:
        def pipe(src, dst) -> None:
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threads = [
            threading.Thread(target=pipe, args=(left, right), daemon=True),
            threading.Thread(target=pipe, args=(right, left), daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def close(self) -> None:
        self._stop.set()
        try:
            self._raw.close()
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
