"""SOCKS4, SOCKS5, and HTTP CONNECT client handshakes, plus request parsing."""

from __future__ import annotations

import base64
import hmac
import socket
from dataclasses import dataclass

from proxy_chain.errors import ProxyChainError
from proxy_chain.net import SocketIO

SOCKS5_REPLY = {
    0: "succeeded",
    1: "general failure",
    2: "connection not allowed",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "ttl expired",
    7: "command not supported",
    8: "address type not supported",
}


@dataclass
class HttpRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    dest_host: str
    dest_port: int

    def header(self, name: str) -> str | None:
        folded = name.lower()
        for key, value in self.headers:
            if key.lower() == folded:
                return value
        return None


def ascii_host(host: str) -> str:
    try:
        host.encode("ascii")
        return host
    except UnicodeEncodeError:
        return host.encode("idna").decode("ascii")


def split_host_port(target: str, default: int) -> tuple[str, int]:
    try:
        if target.startswith("["):
            host, _, rest = target[1:].partition("]")
            if not host:
                raise ProxyChainError(f"bad address {target}")
            if rest.startswith(":") and rest[1:]:
                port = int(rest[1:])
            elif rest in {"", ":"}:
                port = default
            else:
                raise ProxyChainError(f"bad address {target}")
        elif target.count(":") == 1:
            host, port_text = target.split(":")
            if not host:
                raise ProxyChainError(f"bad address {target}")
            port = int(port_text)
        elif ":" in target:
            raise ProxyChainError(f"bad address {target}")
        else:
            host, port = target, default
    except ValueError as exc:
        raise ProxyChainError(f"bad port in {target}") from exc
    if not host or not 1 <= port <= 65535:
        raise ProxyChainError(f"bad address {target}")
    return host, port


def encode_socks5_addr(host: str) -> tuple[int, bytes]:
    try:
        packed = socket.inet_aton(host)
        # inet_aton accepts shorthand such as "127". Only dotted quads are IPv4.
        if packed and host.count(".") == 3:
            socket.inet_pton(socket.AF_INET, host)
            return 0x01, packed
    except OSError:
        pass
    if ":" in host:
        try:
            return 0x04, socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            pass
    raw = ascii_host(host).encode("ascii")
    if not raw or len(raw) > 255:
        raise ProxyChainError("hostname too long")
    return 0x03, bytes([len(raw)]) + raw


def consume_socks5_addr(io: SocketIO, atyp: int) -> None:
    if atyp == 0x01:
        io.recv_exact(4)
    elif atyp == 0x04:
        io.recv_exact(16)
    elif atyp == 0x03:
        length = io.recv_exact(1)[0]
        io.recv_exact(length)
    else:
        raise ProxyChainError(f"bad address type {atyp}")
    io.recv_exact(2)


def read_socks5_addr(io: SocketIO, atyp: int) -> tuple[str, int]:
    if atyp == 0x01:
        host = socket.inet_ntoa(io.recv_exact(4))
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, io.recv_exact(16))
    elif atyp == 0x03:
        length = io.recv_exact(1)[0]
        host = io.recv_exact(length).decode("idna")
    else:
        raise ProxyChainError(f"bad address type {atyp}")
    port = int.from_bytes(io.recv_exact(2), "big")
    return host, port


def socks5_reply(io: SocketIO, code: int) -> None:
    try:
        io.sendall(bytes((5, code, 0, 1, 0, 0, 0, 0, 0, 0)))
    except OSError:
        pass


def socks4_reply(io: SocketIO, granted: bool) -> None:
    try:
        io.sendall(b"\x00" + (b"\x5a" if granted else b"\x5b") + b"\x00" * 6)
    except OSError:
        pass


def socks5_client(
    io: SocketIO,
    dest_host: str,
    dest_port: int,
    username: str | None,
    password: str | None,
) -> None:
    if username is not None:
        io.sendall(b"\x05\x02\x00\x02")
    else:
        io.sendall(b"\x05\x01\x00")
    version, method = io.recv_exact(2)
    if version != 5:
        raise ProxyChainError(f"socks5 bad version {version}")
    if method == 0xFF:
        raise ProxyChainError("socks5 rejected authentication methods")
    if method == 0x02:
        if username is None:
            raise ProxyChainError("socks5 server required authentication")
        user = username.encode("utf-8")
        secret = (password or "").encode("utf-8")
        if len(user) > 255 or len(secret) > 255:
            raise ProxyChainError("socks5 credentials too long")
        io.sendall(bytes((1, len(user))) + user + bytes((len(secret),)) + secret)
        status = io.recv_exact(2)[1]
        if status != 0:
            raise ProxyChainError("socks5 authentication failed")
    elif method != 0x00:
        raise ProxyChainError(f"socks5 unsupported method {method}")

    atyp, addr = encode_socks5_addr(dest_host)
    io.sendall(b"\x05\x01\x00" + bytes((atyp,)) + addr + dest_port.to_bytes(2, "big"))
    reply = io.recv_exact(4)
    if reply[0] != 5:
        raise ProxyChainError("socks5 bad reply")
    if reply[1] != 0:
        reason = SOCKS5_REPLY.get(reply[1], str(reply[1]))
        raise ProxyChainError(f"socks5 connect failed: {reason}")
    consume_socks5_addr(io, reply[3])


def socks4_client(
    io: SocketIO,
    dest_host: str,
    dest_port: int,
    username: str | None,
) -> None:
    user = (username or "").encode("utf-8") + b"\x00"
    try:
        if dest_host.count(".") != 3:
            raise OSError
        ip = socket.inet_pton(socket.AF_INET, dest_host)
        packet = b"\x04\x01" + dest_port.to_bytes(2, "big") + ip + user
    except OSError:
        packet = (
            b"\x04\x01"
            + dest_port.to_bytes(2, "big")
            + b"\x00\x00\x00\x01"
            + user
            + ascii_host(dest_host).encode("ascii")
            + b"\x00"
        )
    io.sendall(packet)
    reply = io.recv_exact(8)
    if reply[1] != 0x5A:
        raise ProxyChainError(f"socks4 connect failed: {reply[1]}")


def http_connect_client(
    io: SocketIO,
    dest_host: str,
    dest_port: int,
    username: str | None,
    password: str | None,
) -> None:
    host = ascii_host(dest_host)
    lines = [
        f"CONNECT {host}:{dest_port} HTTP/1.1",
        f"Host: {host}:{dest_port}",
        "Proxy-Connection: keep-alive",
        "User-Agent: proxy-chain",
    ]
    if username is not None:
        token = base64.b64encode(f"{username}:{password or ''}".encode()).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    io.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    raw = io.read_until(b"\r\n\r\n", 65536)
    status_line = raw.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProxyChainError(f"bad proxy response: {status_line}")
    if int(parts[1]) != 200:
        raise ProxyChainError(f"http connect failed: {status_line}")


def socks_failure_code(exc: BaseException) -> int:
    text = str(exc).lower()
    if "refused" in text:
        return 5
    if "unreachable" in text or "timed out" in text or "timeout" in text:
        return 4
    return 1


def parse_http_request(head: bytes) -> HttpRequest:
    try:
        text = head.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise ProxyChainError("bad http request") from exc
    if text.endswith("\r\n\r\n"):
        text = text[:-4]
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        raise ProxyChainError("empty http request")
    try:
        method, target, version = lines[0].split(" ")
    except ValueError as exc:
        raise ProxyChainError("bad http request line") from exc
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise ProxyChainError("bad http header")
        headers.append((name.strip(), value.strip()))
    request = HttpRequest(method.upper(), target, version, headers, "", 0)
    host, port = _destination(request)
    request.dest_host = host
    request.dest_port = port
    return request


def _destination(request: HttpRequest) -> tuple[str, int]:
    if request.method == "CONNECT":
        return split_host_port(request.target, 443)
    parsed_scheme = ""
    rest = request.target
    if "://" in request.target:
        parsed_scheme, _, rest = request.target.partition("://")
        parsed_scheme = parsed_scheme.lower()
    if parsed_scheme in {"http", "https"}:
        hostport, sep, path = rest.partition("/")
        if "@" in hostport:
            hostport = hostport.rsplit("@", 1)[1]
        default = 443 if parsed_scheme == "https" else 80
        return split_host_port(hostport, default)
    host_header = request.header("host")
    if not host_header:
        raise ProxyChainError("http request is missing a host")
    return split_host_port(host_header, 80)


def credentials_match(
    expected_user: str | None,
    expected_password: str | None,
    got_user: str | None,
    got_password: str | None,
) -> bool:
    if expected_user is None:
        return True
    if got_user is None:
        return False
    expected = f"{expected_user}\0{expected_password or ''}".encode()
    got = f"{got_user}\0{got_password or ''}".encode()
    return hmac.compare_digest(expected, got)


def parse_basic_authorization(value: str | None) -> tuple[str, str] | None:
    if not value or not value.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(value.split(None, 1)[1].strip(), validate=True)
        text = decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError, IndexError):
        return None
    user, sep, password = text.partition(":")
    if not sep:
        return None
    return user, password


def accept_socks5(io: SocketIO, username: str | None, password: str | None) -> tuple[str, int]:
    version, count = io.recv_exact(2)
    if version != 5:
        raise ProxyChainError("not a socks5 greeting")
    methods = set(io.recv_exact(count))
    if username is not None:
        if 0x02 not in methods:
            io.sendall(b"\x05\xff")
            raise ProxyChainError("client did not offer authentication")
        io.sendall(b"\x05\x02")
        auth_version = io.recv_exact(1)[0]
        if auth_version != 1:
            raise ProxyChainError("bad socks5 auth version")
        user = io.recv_exact(io.recv_exact(1)[0]).decode("utf-8", "replace")
        secret = io.recv_exact(io.recv_exact(1)[0]).decode("utf-8", "replace")
        if not credentials_match(username, password, user, secret):
            io.sendall(b"\x01\x01")
            raise ProxyChainError("authentication failed")
        io.sendall(b"\x01\x00")
    else:
        if 0x00 not in methods:
            io.sendall(b"\x05\xff")
            raise ProxyChainError("client required authentication")
        io.sendall(b"\x05\x00")

    request = io.recv_exact(4)
    if request[0] != 5:
        raise ProxyChainError("bad socks5 request")
    if request[1] != 1:
        socks5_reply(io, 7)
        raise ProxyChainError("only CONNECT is supported")
    try:
        host, port = read_socks5_addr(io, request[3])
    except ProxyChainError:
        socks5_reply(io, 8)
        raise
    return host, port


def accept_socks4(io: SocketIO) -> tuple[str, int]:
    head = io.recv_exact(8)
    if head[0] != 4:
        raise ProxyChainError("not a socks4 request")
    if head[1] != 1:
        socks4_reply(io, False)
        raise ProxyChainError("only CONNECT is supported")
    port = int.from_bytes(head[2:4], "big")
    ip = head[4:8]
    io.recv_until_nul()
    if ip[:3] == b"\x00\x00\x00" and ip[3] != 0:
        host = io.recv_until_nul().decode("idna", "replace")
    else:
        host = socket.inet_ntoa(ip)
    if not host or not 1 <= port <= 65535:
        socks4_reply(io, False)
        raise ProxyChainError("bad destination")
    return host, port


def http_message(code: int, reason: str, body: str = "", headers: dict[str, str] | None = None) -> bytes:
    payload = body.encode("utf-8")
    lines = [
        f"HTTP/1.1 {code} {reason}",
        "Connection: close",
        f"Content-Length: {len(payload)}",
        "Content-Type: text/plain; charset=utf-8",
    ]
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + payload


def rewrite_origin_request(request: HttpRequest) -> bytes:
    """Turn a proxy-form request into an origin-form request."""
    target = request.target
    if "://" in target:
        _, _, rest = target.partition("://")
        authority = rest.split("/", 1)[0]
        if "@" in authority:
            rest = rest.split("@", 1)[1]
        _, sep, path = rest.partition("/")
        path = f"/{path}" if sep else "/"
    else:
        path = target if target.startswith("/") else "/" + target
    lines = [f"{request.method} {path} {request.version}"]
    saw_host = False
    for name, value in request.headers:
        folded = name.lower()
        if folded in {"proxy-authorization", "proxy-connection", "connection"}:
            continue
        if folded == "host":
            saw_host = True
        lines.append(f"{name}: {value}")
    if not saw_host:
        host = ascii_host(request.dest_host)
        if request.dest_port not in {80, 443}:
            host = f"{host}:{request.dest_port}"
        lines.append(f"Host: {host}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")
