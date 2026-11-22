"""Локальный DNS-сервер AntiZapret для Windows 11 (служба).

Запуск: `python -m azwin.dnsd --mode split --listen 127.0.0.1 --port 5353`

Нужен, когда DNS AntiZapret недоступен: например, при «полном VPN» на
стороне Windows, когда заблокированные домены резолвятся локально через
fake-IP, а маршрут на fake-пул уходит в туннель.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

from . import lists, resolver
from .cli import Paths, configure_output_encoding, load_lists


def build_resolver(root: str, mode: str, listen: str, port: int,
                   fake_cidr: str, ipv6_mode: str, adblock: bool,
                   warp_dns: bool) -> resolver.AntiZapretResolver:
    """Собирает резолвер со списками из каталога root."""
    paths = Paths(root)
    paths.ensure()
    domains, ips = load_lists(paths)
    config = resolver.ResolverConfig(
        mode=mode,
        listen=listen,
        port=port,
        fake_cidr=fake_cidr,
        ipv6_mode=ipv6_mode,
        adblock=adblock,
        warp_dns=warp_dns,
    )
    return resolver.AntiZapretResolver(config, domains=domains, ips=ips)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="azwin-dnsd", description="Локальный DNS AntiZapret для Windows 11")
    parser.add_argument("--root", default=None,
                        help="каталог данных (по умолчанию C:\\ProgramData\\AntiZapret)")
    parser.add_argument("--mode", default="split", choices=["split", "full", "proxy"])
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353,
                        help="порт (5353 — не требует прав администратора)")
    parser.add_argument("--fake-cidr", default=resolver.FAKE_CIDR_DEFAULT)
    parser.add_argument("--ipv6-mode", default="a", choices=["a", "b", "c"])
    parser.add_argument("--adblock", action="store_true")
    parser.add_argument("--warp-dns", action="store_true")
    args = parser.parse_args(argv)

    from .cli import DEFAULT_ROOT

    configure_output_encoding()
    root = args.root or DEFAULT_ROOT
    res = build_resolver(root, args.mode, args.listen, args.port,
                         args.fake_cidr, args.ipv6_mode, args.adblock,
                         args.warp_dns)
    server = resolver.DnsServer(res, args.listen, args.port)
    try:
        server.start()
    except OSError as exc:
        print(f"Error: не удалось занять {args.listen}:{args.port} — {exc}",
              file=sys.stderr)
        print("       Порт 53 требует прав администратора; используйте 5353.",
              file=sys.stderr)
        return 1

    res.start()
    print(f"AntiZapret DNS слушает {args.listen}:{args.port} "
          f"(режим {args.mode}, fake-IP {args.fake_cidr})")

    stop = False

    def _handle(signum, frame):  # noqa: ARG001
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    try:
        while not stop:
            time.sleep(0.5)
    finally:
        server.stop()
        res.stop()
    print("Остановлено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
