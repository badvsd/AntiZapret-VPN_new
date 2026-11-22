"""CLI AntiZapret для Windows 11.

Заменяет набор Linux-скриптов upstream (`setup.sh`, `doall.sh`, `parse.sh`,
`client.sh`, `up.sh`, `down.sh`) одним инструментом под Windows 11.

Команды:
  setup      — первоначальная настройка (DNS, IPv6, маршруты, утечки)
  up/down    — включить/выключить split-маршрутизацию
  client     — создать/удалить/показать клиентские профили
  parse      — пересобрать списки и маршруты из config/ и download/
  update     — обновить автоматические списки (домены и IP)
  status     — текущее состояние: DNS, маршруты, туннель
  dns        — разовый DNS-запрос через локальный резолвер
  doctor     — диагностика типовых проблем
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass

from . import dnswire, lists, profiles, resolver, winnet
from .dnswire import TYPE_A, TYPE_AAAA

APP_NAME = "azwin"
DEFAULT_ROOT = r"C:\ProgramData\AntiZapret"
DEFAULT_LISTS_URLS = {
    "include-hosts.txt": [
        "https://raw.githubusercontent.com/bol-van/rulist/main/reestr_hostname.txt",
        "https://antifilter.download/list/domains.lst",
    ],
    "include-adblock-hosts.txt": [
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_small.txt",
    ],
}

# DNS AntiZapret на сервере upstream — клиент ходит к ним через туннель.
DNS_SERVERS = [
    "10.29.0.1",
    "10.29.4.1",
    "10.29.8.1",
]


@dataclass
class Paths:
    """Раскладка каталогов (аналог /root/antizapret в upstream)."""

    root: str = DEFAULT_ROOT

    @property
    def download(self) -> str:
        return os.path.join(self.root, "download")

    @property
    def config(self) -> str:
        return os.path.join(self.root, "config")

    @property
    def result(self) -> str:
        return os.path.join(self.root, "result")

    @property
    def client(self) -> str:
        return os.path.join(self.root, "client")

    @property
    def logs(self) -> str:
        return os.path.join(self.root, "logs")

    @property
    def setup_file(self) -> str:
        return os.path.join(self.root, "setup")

    def ensure(self) -> None:
        for path in (self.root, self.download, self.config, self.result,
                     self.client, self.logs):
            os.makedirs(path, exist_ok=True)

    def config_file(self, name: str) -> str:
        return os.path.join(self.config, name)


def read_setup(paths: Paths) -> dict[str, str]:
    """Читает файл настроек (формат KEY=VALUE, как upstream /root/antizapret/setup)."""
    settings: dict[str, str] = {}
    try:
        with open(paths.setup_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                settings[key.strip()] = value.strip()
    except OSError:
        pass
    return settings


def write_setup(paths: Paths, settings: dict[str, str]) -> None:
    paths.ensure()
    with open(paths.setup_file, "w", encoding="utf-8", newline="\n") as f:
        for key, value in settings.items():
            f.write(f"{key}={value}\n")


def load_lists(paths: Paths) -> tuple[lists.DomainLists, lists.IpLists]:
    """Собирает доменные и IP-списки из download/ и config/."""
    domains = lists.build_domain_lists(paths.download, paths.config)
    ips = lists.build_ip_lists(paths.download, paths.config)
    return domains, ips


def download_file(urls: list[str], destination: str) -> bool:
    """Скачивает файл, перебирая зеркала."""
    import urllib.request

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
            with open(destination, "wb") as f:
                f.write(data)
            return True
        except Exception as exc:  # noqa: BLE001 - зеркала падают по-разному
            print(f"Warning: {url} — {exc}")
    return False


def cmd_update(args: argparse.Namespace) -> int:
    """Обновляет автоматические списки (домены, адблок)."""
    paths = Paths(args.root)
    paths.ensure()
    ok = True
    for name, urls in DEFAULT_LISTS_URLS.items():
        target = os.path.join(paths.download, name)
        print(f"Обновляю {name} ...")
        if download_file(urls, target):
            size = os.path.getsize(target)
            print(f"  ok: {size} байт")
        else:
            print("  не удалось скачать, оставляю прежнюю версию")
            ok = False
    return 0 if ok else 1


def cmd_parse(args: argparse.Namespace) -> int:
    """Пересобирает итоговые списки и маршруты (аналог parse.sh)."""
    paths = Paths(args.root)
    paths.ensure()
    domains, ips = load_lists(paths)

    with open(os.path.join(paths.result, "route-ips.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        for net in ips.route:
            f.write(f"{net}\n")
    with open(os.path.join(paths.result, "route-ips6.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        for net in ips.route6:
            f.write(f"{net}\n")
    with open(os.path.join(paths.result, "allowed-ips.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        base = args.allowed_base or "10.29.8.0/24"
        f.write(profiles._route_ips_line([str(n) for n in ips.route], base) + "\n")
    with open(os.path.join(paths.result, "hosts.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        for domain in lists.sort_domains(domains.blocked):
            f.write(f"{domain}\n")

    print(f"Доменов в списке AntiZapret: {len(domains.blocked)}")
    print(f"Маршрутов IPv4: {len(ips.route)}, IPv6: {len(ips.route6)}")
    return 0


def _fake_cidr(settings: dict[str, str]) -> str:
    return settings.get("FAKE_IP_CIDR", resolver.FAKE_CIDR_DEFAULT)


def _tunnel_gateway(settings: dict[str, str]) -> str:
    """IP шлюза туннеля. По умолчанию — адрес DNS AntiZapret в туннеле."""
    return settings.get("TUNNEL_GATEWAY", "10.29.8.1")


def _tunnel_interface(settings: dict[str, str]) -> str | None:
    return settings.get("TUNNEL_INTERFACE") or None


def cmd_up(args: argparse.Namespace) -> int:
    """Включает split-маршрутизацию."""
    paths = Paths(args.root)
    settings = read_setup(paths)
    domains, ips = load_lists(paths)
    net = winnet.WindowsNetwork(
        gateway=_tunnel_gateway(settings),
        interface=_tunnel_interface(settings),
        dry_run=args.dry_run,
    )
    if not args.dry_run and not winnet.is_admin():
        print("Error: нужны права администратора для изменения маршрутов.",
              file=sys.stderr)
        return 1
    dns_ips = settings.get("DNS_IPS", "10.29.0.1,10.29.4.1,10.29.8.1").split(",")
    added = net.setup_split_routing(ips, _fake_cidr(settings), dns_ips)
    print(f"Добавлено маршрутов: {len(added)}")
    for cidr in added[:10]:
        print(f"  {cidr}")
    if len(added) > 10:
        print(f"  ... ещё {len(added) - 10}")
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    """Выключает split-маршрутизацию."""
    paths = Paths(args.root)
    settings = read_setup(paths)
    domains, ips = load_lists(paths)
    net = winnet.WindowsNetwork(
        gateway=_tunnel_gateway(settings),
        interface=_tunnel_interface(settings),
        dry_run=args.dry_run,
    )
    dns_ips = settings.get("DNS_IPS", "10.29.0.1,10.29.4.1,10.29.8.1").split(",")
    removed = net.cleanup_split_routing(ips, _fake_cidr(settings), dns_ips)
    print(f"Удалено маршрутов: {removed}")
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    """Первоначальная настройка Windows 11."""
    paths = Paths(args.root)
    paths.ensure()
    settings = read_setup(paths)
    if not settings:
        settings = {
            "FAKE_IP_CIDR": resolver.FAKE_CIDR_DEFAULT,
            "DNS_IPS": "10.29.0.1,10.29.4.1,10.29.8.1",
            "TUNNEL_GATEWAY": "10.29.8.1",
            "TUNNEL_INTERFACE": "",
            "IPV6_MODE": "a",
            "MODE": "split",
            "ADBLOCK": "n",
        }
        write_setup(paths, settings)

    print("AntiZapret VPN — настройка Windows 11\n")

    if not winnet.is_admin():
        print("Warning: скрипт запущен без прав администратора.")
        print("         Изменение маршрутов, DNS и IPv6 потребует прав.\n")

    print("[1/5] Отключаю IPv6 (иначе трафик уходит в обход туннеля)")
    if winnet.disable_ipv6_globally():
        print("      IPv6 отключён. Для полного эффекта нужна перезагрузка.")
    else:
        print("      не удалось отключить IPv6")

    print("[2/5] Выключаю Secure DNS (DoH) — иначе DNS AntiZapret игнорируется")
    winnet.disable_secure_dns()
    winnet.disable_nrdot()
    winnet.disable_wpad()

    print("[3/5] Готовлю каталоги списков")
    cmd_parse(args)

    print("[4/5] Проверяю список доменов")
    if not os.path.exists(os.path.join(paths.download, "include-hosts.txt")):
        print("      списка нет — запускаю обновление")
        cmd_update(args)

    print("[5/5] Статус")
    print(f"      корень: {paths.root}")
    print(f"      режим:  {settings.get('MODE', 'split')}")
    print(f"      fake-IP: {settings.get('FAKE_IP_CIDR', resolver.FAKE_CIDR_DEFAULT)}")
    print("\nГотово. Подключите туннель, затем выполните: azwin up")
    return 0


def _used_client_ips(paths: Paths) -> set[str]:
    """Собирает IPv4-адреса, уже занятые существующими клиентами."""
    used: set[str] = set()
    if not os.path.isdir(paths.client):
        return used
    for dirpath, _dirnames, filenames in os.walk(paths.client):
        for name in filenames:
            if not name.endswith(".conf"):
                continue
            try:
                with open(os.path.join(dirpath, name), encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("Address = "):
                            addr = line.split("=", 1)[1].strip().split(",")[0].strip()
                            ip = addr.split("/")[0].strip()
                            if ip.count(".") == 3:
                                used.add(ip)
            except OSError:
                continue
    return used


def cmd_client(args: argparse.Namespace) -> int:
    """Создаёт/удаляет/показывает клиентские профили (аналог client.sh)."""
    paths = Paths(args.root)
    paths.ensure()
    settings = read_setup(paths)
    server_host = settings.get("SERVER_HOST", "")
    if not server_host:
        print("Error: не задан SERVER_HOST в файле setup.", file=sys.stderr)
        print("       Укажите адрес или домен зарубежного сервера AntiZapret.",
              file=sys.stderr)
        return 1

    if args.action == "list":
        print("Клиенты:")
        for entry in sorted(os.listdir(paths.client)) if os.path.isdir(paths.client) else []:
            print(f"  {entry}")
        return 0

    if args.action == "delete":
        target = os.path.join(paths.client, profiles.sanitize_filename(args.name))
        if os.path.isdir(target):
            import shutil

            shutil.rmtree(target)
            print(f"Клиент '{args.name}' удалён")
        else:
            print(f"Клиент '{args.name}' не найден")
        return 0

    # create
    domains, ips = load_lists(paths)
    route_ips = [str(n) for n in ips.route]
    used_ips = _used_client_ips(paths)

    # У каждого семейства протоколов свои ключи и своя подсеть — как в
    # upstream, где на каждое семейство свой серверный интерфейс.
    server = profiles.ServerKeys(
        server_host=server_host,
        public_key=settings.get("SERVER_PUBLIC_KEY", ""),
    )
    created: list[profiles.ClientProfile] = []

    for layer in ("antizapret", "vpn"):
        for protocol in ("udp", "tcp", "both"):
            created.append(profiles.render_openvpn(
                args.name, server_host, settings.get("CA_CERT", ""),
                settings.get("CLIENT_CERT", ""), settings.get("CLIENT_KEY", ""),
                layer=layer, protocol=protocol, route_ips=route_ips))

    keys_by_group: dict[str, tuple[str, str, str]] = {}
    ip_by_group: dict[str, str] = {}
    for family in profiles.FAMILIES:
        group = family.key_group or f"{family.key}/{family.layer}"
        if group not in keys_by_group:
            private, public = profiles.generate_wg_keys()
            preshared = profiles.base64_key(32)
            keys_by_group[group] = (private, public, preshared)
            ip_by_group[group] = profiles.next_client_ip(used_ips, family.base_ipv4)
            used_ips.add(ip_by_group[group])
        private, public, preshared = keys_by_group[group]
        client_ip = ip_by_group[group]
        client_ipv6 = _ipv6_for(family, client_ip)
        subnet = profiles.LAYER_SUBNET[(family.key, family.layer)]
        server.preshared_key = preshared
        common = dict(server=server, client_private=private, client_public=public,
                      preshared=preshared, client_ip=client_ip, layer=family.layer,
                      route_ips=route_ips, client_ipv6=client_ipv6,
                      dns=family.dns, port=family.port, subnet=subnet)
        if family.key == "wireguard":
            created.append(profiles.render_wireguard(args.name, **common))
        elif family.key == "awg15":
            created.append(profiles.render_awg15(args.name, **common))
        elif family.key == "awg2":
            created.append(profiles.render_awg2(args.name, **common))
        elif family.key == "awg3":
            created.append(profiles.render_awg3(
                args.name, **common,
                header_protection_key=settings.get("AWG3_HEADER_KEY", "")))

    out_dir = os.path.join(paths.client, profiles.sanitize_filename(args.name))
    for profile in created:
        path = profile.save(out_dir)
        print(f"  {path}")
    print(f"Профили клиента '{args.name}' созданы в {out_dir}")
    print("Публичные ключи (их нужно внести на сервер):")
    for group, (_private, public, _psk) in keys_by_group.items():
        print(f"  {group}: {public}")
    # Ключи сохраняем в setup, чтобы при пересоздании профилей они не сменились.
    for group, (private, public, psk) in keys_by_group.items():
        suffix = group.replace("-", "_").upper()
        settings[f"PRIVATE_KEY_{suffix}"] = private
        settings[f"PUBLIC_KEY_{suffix}"] = public
        settings[f"PSK_{suffix}"] = psk
    write_setup(paths, settings)
    return 0


def _ipv6_for(family: "profiles.ProtocolFamily", client_ip: str) -> str:
    """IPv6-адрес клиента для семейства протоколов."""
    last = int(client_ip.split(".")[-1])
    prefix, suffix = family.base_ipv6.rsplit("::", 1)
    return f"{prefix}::{last:x}"


def cmd_status(args: argparse.Namespace) -> int:
    """Показывает состояние системы."""
    paths = Paths(args.root)
    settings = read_setup(paths)
    print("=== AntiZapret status ===\n")
    print(f"корень:      {paths.root}")
    print(f"режим:       {settings.get('MODE', 'split')}")
    print(f"fake-IP:     {settings.get('FAKE_IP_CIDR', resolver.FAKE_CIDR_DEFAULT)}")
    print(f"туннель:     {settings.get('TUNNEL_INTERFACE') or 'не задан'}")
    print(f"IPv6:        {'отключён' if winnet.WindowsNetwork.ipv6_disabled() else 'включён'}")
    print(f"права:       {'администратор' if winnet.is_admin() else 'обычный пользователь'}")

    print("\n--- Адаптеры ---")
    for name, status, desc in winnet.WindowsNetwork.list_adapters():
        marker = "*" if status == "Up" else " "
        print(f" {marker} {name} [{status}] {desc}")

    print("\n--- DNS ---")
    print(winnet.WindowsNetwork.list_dns()[:2000])

    if os.path.exists(os.path.join(paths.result, "route-ips.txt")):
        with open(os.path.join(paths.result, "route-ips.txt"), encoding="utf-8") as f:
            count = sum(1 for _ in f)
        print(f"\n--- Маршруты AntiZapret в списке: {count} ---")
    return 0


def cmd_dns(args: argparse.Namespace) -> int:
    """Разовый DNS-запрос через локальный резолвер."""
    server = args.server
    port = args.port
    qtype = TYPE_AAAA if args.type == "AAAA" else TYPE_A
    try:
        reply = resolver.UpstreamResolver(timeout=args.timeout).query(
            server, args.name, qtype, 0x1234)
    except resolver.UpstreamError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Запрос: {args.name} {args.type} @ {server}:{port}")
    for rec in reply.answers:
        value = rec.address or rec.target or rec.rdata.hex()
        print(f"  {rec.name} {rec.ttl} {rec.rtype} {value}")
    if not reply.answers:
        print(f"  (пустой ответ, rcode={reply.rcode})")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Диагностика типовых проблем (по FAQ upstream)."""
    paths = Paths(args.root)
    settings = read_setup(paths)
    problems: list[str] = []
    ok: list[str] = []

    if winnet.is_admin():
        ok.append("права администратора есть")
    else:
        problems.append("нет прав администратора — маршруты и DNS не изменяются")

    if winnet.WindowsNetwork.ipv6_disabled():
        ok.append("IPv6 отключён")
    else:
        problems.append("IPv6 включён — трафик может уходить мимо туннеля")

    domains, ips = load_lists(paths)
    if len(domains.blocked) > 1000:
        ok.append(f"список доменов загружен ({len(domains.blocked)})")
    else:
        problems.append(f"список доменов почти пуст ({len(domains.blocked)}) — "
                        "выполните azwin update")

    if ips.route:
        ok.append(f"маршруты загружены ({len(ips.route)})")
    else:
        problems.append("список маршрутов пуст — выполните azwin update")

    if not settings.get("TUNNEL_INTERFACE"):
        problems.append("не указан туннель (TUNNEL_INTERFACE в setup) — "
                        "маршруты некуда направить")

    print("=== Диагностика ===\n")
    for item in ok:
        print(f"  [ok]    {item}")
    for item in problems:
        print(f"  [пробл] {item}")
    return 0 if not problems else 1


def cmd_client_list(args: argparse.Namespace) -> int:
    return cmd_client(argparse.Namespace(root=args.root, action="list", name=""))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME, description="AntiZapret VPN для Windows 11")
    parser.add_argument("--root", default=DEFAULT_ROOT,
                        help=f"каталог данных (по умолчанию {DEFAULT_ROOT})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup", help="первоначальная настройка")
    p_setup.set_defaults(func=cmd_setup)

    p_up = sub.add_parser("up", help="включить split-маршрутизацию")
    p_up.add_argument("--dry-run", action="store_true", help="только показать команды")
    p_up.set_defaults(func=cmd_up)

    p_down = sub.add_parser("down", help="выключить split-маршрутизацию")
    p_down.add_argument("--dry-run", action="store_true")
    p_down.set_defaults(func=cmd_down)

    p_client = sub.add_parser("client", help="клиентские профили")
    p_client.add_argument("action", choices=["create", "delete", "list"])
    p_client.add_argument("name", nargs="?", default="")
    p_client.set_defaults(func=cmd_client)

    p_parse = sub.add_parser("parse", help="пересобрать списки и маршруты")
    p_parse.add_argument("--allowed-base", default=None)
    p_parse.set_defaults(func=cmd_parse)

    p_update = sub.add_parser("update", help="обновить автоматические списки")
    p_update.set_defaults(func=cmd_update)

    p_status = sub.add_parser("status", help="состояние системы")
    p_status.set_defaults(func=cmd_status)

    p_dns = sub.add_parser("dns", help="разовый DNS-запрос")
    p_dns.add_argument("name")
    p_dns.add_argument("--server", default="127.0.0.1")
    p_dns.add_argument("--port", type=int, default=53)
    p_dns.add_argument("--type", default="A", choices=["A", "AAAA"])
    p_dns.add_argument("--timeout", type=float, default=5.0)
    p_dns.set_defaults(func=cmd_dns)

    p_doctor = sub.add_parser("doctor", help="диагностика")
    p_doctor.set_defaults(func=cmd_doctor)

    return parser


def configure_output_encoding() -> None:
    """Переводит stdout/stderr в UTF-8 с заменой непечатаемых символов.

    В консоли Windows кодировка по умолчанию — cp1252/cp866, и кириллица
    в выводе падает с UnicodeEncodeError. На CI это проявлялось сразу:
    `python -m azwin.cli --help` завершался с ошибкой кодировки.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    configure_output_encoding()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nПрервано")
        return 130


if __name__ == "__main__":
    sys.exit(main())
