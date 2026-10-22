"""Command line entry point."""

from __future__ import annotations

import argparse
import logging
import sys

from proxy_chain.config import (
    load_proxy_list_file,
    load_settings,
    merge_proxies,
    normalize,
    normalize_mode,
    parse_proxy_list,
    resolve_list_path,
)
from proxy_chain.errors import ConfigError
from proxy_chain.protocols import split_host_port
from proxy_chain.service import Service


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxy-chain",
        description="Local dynamic TCP proxy chain (SOCKS4, SOCKS5, and HTTP CONNECT).",
        epilog=(
            "examples:\n"
            "  python -m proxy_chain --proxy-list proxies.txt --proxy-scheme http --mode dynamic\n"
            "  python -m proxy_chain -c config.json\n"
            "  curl --socks5-hostname 127.0.0.1:1080 https://example.com\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-c", "--config", help="JSON config file")
    parser.add_argument("--listen", help="local listen address, host:port (default 127.0.0.1:1080)")
    parser.add_argument("--proxy", action="append", default=[], help="upstream proxy URL; repeat to build a chain")
    parser.add_argument("--proxy-list", help="proxy file, including Webshare ip:port:username:password lines")
    parser.add_argument(
        "--proxy-scheme",
        choices=["http", "https", "socks5", "socks4"],
        help="scheme for list lines that do not name one (default http)",
    )
    parser.add_argument("--proxy-user", help="username for list lines that omit one")
    parser.add_argument("--proxy-password", help="password for list lines that omit one")
    parser.add_argument("--mode", help="dynamic, static, random, or round-robin")
    parser.add_argument("--chain-length", type=int, help="hops per connection for random and round-robin; 0 uses all")
    parser.add_argument("--min-hops", type=int, help="refuse a connection that would use fewer working proxies")
    parser.add_argument("--allow-direct", action="store_true", help="allow a direct connection when min-hops is 0")
    parser.add_argument("--no-direct", action="store_true", help="never connect directly")
    parser.add_argument("--control", help="control API host:port, or 'off'")
    parser.add_argument("--token", help="bearer token required by the control API")
    parser.add_argument("--user", help="username required of local clients")
    parser.add_argument("--password", help="password required of local clients")
    parser.add_argument("--no-health", action="store_true", help="disable background proxy probes")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser


def settings_from_args(argv: list[str] | None = None):
    args = build_parser().parse_args(argv)
    settings = load_settings(args.config)
    if args.listen:
        host, port = split_host_port(args.listen, settings.listen_port or 1080)
        settings.listen_host = host
        settings.listen_port = port
    if args.proxy_scheme:
        settings.proxy_scheme = args.proxy_scheme
    if args.proxy_user:
        settings.proxy_username = args.proxy_user
        settings.proxy_password = args.proxy_password or ""
    if args.proxy or args.proxy_list:
        inline = parse_proxy_list(args.proxy) if args.proxy else []
        listed = []
        if args.proxy_list:
            settings.proxy_list = resolve_list_path(args.proxy_list, None)
            listed = load_proxy_list_file(
                settings.proxy_list,
                settings.proxy_scheme,
                settings.proxy_username,
                settings.proxy_password,
            )
        settings.proxies = merge_proxies(inline, listed) if args.proxy_list else inline
        if args.min_hops is None and (not args.config or settings.min_hops is None):
            settings.min_hops = None
        if not args.allow_direct and not args.no_direct and (not args.config or settings.allow_direct is None):
            settings.allow_direct = None
    if args.mode:
        settings.mode = normalize_mode(args.mode)
    if args.chain_length is not None:
        settings.chain_length = args.chain_length
    if args.min_hops is not None:
        settings.min_hops = args.min_hops
    if args.allow_direct:
        settings.allow_direct = True
        if args.min_hops is None:
            settings.min_hops = 0
    if args.no_direct:
        settings.allow_direct = False
    if args.control == "off":
        settings.control_enabled = False
    elif args.control:
        host, port = split_host_port(args.control, 1081)
        settings.control_enabled = True
        settings.control_host = host
        settings.control_port = port
    if args.token is not None:
        settings.control_token = args.token
    if args.user:
        settings.username = args.user
        settings.password = args.password or ""
    if args.no_health:
        settings.health_enabled = False
    return normalize(settings), args.verbose


def main(argv: list[str] | None = None) -> int:
    try:
        settings, verbose = settings_from_args(argv)
    except (ConfigError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    service = Service(settings)
    try:
        service.serve_forever()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
