"""Списки доменов и IP: загрузка, объединение, исключения.

Портирует логику upstream `parse.sh` / `ip6list.py` / `proxy.py`:
  * автоматически обновляемые списки в `download/`
  * ручные надстройки в `config/` (include/exclude/remove/adblock/warp)
  * `include` минус `exclude` = итоговый `route-ips.txt`
  * `remove` вырезает домен и из включения, и из исключения

Формат файлов — обычный текст, одна запись на строку, `#` и `;` — комментарии.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from dataclasses import dataclass, field

DOMAIN_COMMENT_PREFIXES = ("#", ";")


def _strip_comment(line: str) -> str:
    """Убирает комментарий и лишние пробелы, как `sed -E 's/[\\r[:space:]]+//g'`."""
    text = line.strip()
    if not text or text[0] in DOMAIN_COMMENT_PREFIXES:
        return ""
    # Комментарий в конце строки (для IP-списков upstream так не делает, но
    # для доменов это привычно и безопасно).
    for prefix in DOMAIN_COMMENT_PREFIXES:
        idx = text.find(prefix)
        if idx > 0:
            text = text[:idx].strip()
    return " ".join(text.split())


def read_lines(path: str) -> list[str]:
    """Читает файл списка, игнорируя комментарии и пустые строки."""
    out: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                token = _strip_comment(line)
                if token:
                    out.append(token)
    except OSError:
        return []
    return out


def read_domains(paths: list[str]) -> set[str]:
    """Читает домены из списка файлов в нижний регистр, без точек."""
    domains: set[str] = set()
    for path in paths:
        for token in read_lines(path):
            name = token.lower().rstrip(".")
            if name and "/" not in name and " " not in name:
                domains.add(name)
    return domains


def read_networks(paths: list[str]) -> list[ipaddress._BaseNetwork]:
    """Читает IPv4/IPv6 подсети, пропуская мусор (как upstream awk-фильтр)."""
    nets: list[ipaddress._BaseNetwork] = []
    for path in paths:
        for token in read_lines(path):
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            nets.append(net)
    return nets


def ipv4_only(networks: list[ipaddress._BaseNetwork]) -> list[ipaddress.IPv4Network]:
    """Оставляет только IPv4-сети с префиксом /1../32 (фильтр upstream awk)."""
    out: list[ipaddress.IPv4Network] = []
    for net in networks:
        if isinstance(net, ipaddress.IPv4Network) and 1 <= net.prefixlen <= 32:
            out.append(net)
    return out


def subtract(nets: list[ipaddress._BaseNetwork],
             excludes: list[ipaddress._BaseNetwork]) -> list[ipaddress._BaseNetwork]:
    """Вычитает exclude-сети из include-сетей (портирует `ip6list.py`)."""
    result = list(nets)
    for ex in excludes:
        out: list[ipaddress._BaseNetwork] = []
        for net in result:
            if not net.overlaps(ex):
                out.append(net)
                continue
            if net.supernet_of(ex) and net != ex:
                out.extend(net.address_exclude(ex))
            elif ex.supernet_of(net) and net != ex:
                continue  # сеть целиком исключена
            else:
                out.append(net)
        result = out
    return result


def collapse(nets: list[ipaddress._BaseNetwork]) -> list[ipaddress._BaseNetwork]:
    """Схлопывает перекрывающиеся сети."""
    return sorted(ipaddress.collapse_addresses(nets))


def match_domain(domain: str, patterns: set[str]) -> bool:
    """Проверяет домен против набора точных имён и wildcard-паттернов.

    Wildcard-строка может быть `*.example.com` (совпадает и сам домен) или
    `example.com` (совпадает сам домен и все поддомены) — как в списках
    РКН, где запись домена покрывает и его поддомены.
    """
    name = domain.lower().rstrip(".")
    if not name:
        return False
    for pattern in patterns:
        pat = pattern.lower().rstrip(".")
        if not pat:
            continue
        if pat.startswith("*."):
            suffix = pat[2:]
            if name == suffix or name.endswith("." + suffix):
                return True
        elif pat.startswith("."):
            if name.endswith(pat):
                return True
        elif name == pat or name.endswith("." + pat):
            return True
        elif "*" in pat or "?" in pat:
            if fnmatch.fnmatchcase(name, pat):
                return True
    return False


def sort_domains(domains: set[str]) -> list[str]:
    return sorted(domains)


@dataclass
class DomainLists:
    """Итоговые доменные наборы после слияния download/ и config/."""

    blocked: set[str] = field(default_factory=set)
    excluded: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)
    adblock_blocked: set[str] = field(default_factory=set)
    adblock_excluded: set[str] = field(default_factory=set)
    warp: set[str] = field(default_factory=set)
    warp_excluded: set[str] = field(default_factory=set)

    def finalize(self) -> "DomainLists":
        """Применяет remove-hosts: домен вырезается отовсюду."""
        if self.removed:
            self.blocked -= self.removed
            self.excluded -= self.removed
            self.adblock_blocked -= self.removed
            self.adblock_excluded -= self.removed
            self.warp -= self.removed
            self.warp_excluded -= self.removed
        # Исключения выбивают домен из блокировки.
        self.blocked -= self.excluded
        self.adblock_blocked -= self.adblock_excluded
        self.warp -= self.warp_excluded
        return self


@dataclass
class IpLists:
    """Итоговые IP-наборы после слияния download/ и config/."""

    route: list[ipaddress.IPv4Network] = field(default_factory=list)
    route6: list[ipaddress.IPv6Network] = field(default_factory=list)
    excluded: list[ipaddress.IPv4Network] = field(default_factory=list)
    drop: list[ipaddress.IPv4Network] = field(default_factory=list)
    deny: list[ipaddress.IPv4Network] = field(default_factory=list)
    allow: list[ipaddress.IPv4Network] = field(default_factory=list)
    forward: list[ipaddress.IPv4Network] = field(default_factory=list)


def build_domain_lists(download_dir: str, config_dir: str) -> DomainLists:
    """Собирает доменные списки из `download/` и `config/`."""
    def paths(*names: str) -> list[str]:
        return [os.path.join(download_dir, n) for n in names if os.path.exists(os.path.join(download_dir, n))] + \
               [os.path.join(config_dir, n) for n in names if os.path.exists(os.path.join(config_dir, n))]

    lists = DomainLists()
    lists.blocked = read_domains(paths("include-hosts.txt"))
    lists.excluded = read_domains(paths("exclude-hosts.txt"))
    lists.removed = read_domains(paths("remove-hosts.txt"))
    lists.adblock_blocked = read_domains(paths("include-adblock-hosts.txt"))
    lists.adblock_excluded = read_domains(paths("exclude-adblock-hosts.txt"))
    lists.warp = read_domains(paths("include-warp-hosts.txt"))
    lists.warp_excluded = read_domains(paths("exclude-warp-hosts.txt"))
    return lists.finalize()


def build_ip_lists(download_dir: str, config_dir: str) -> IpLists:
    """Собирает IP-списки из `download/` и `config/` (портирует `parse.sh ip`)."""
    def paths(suffix: str) -> list[str]:
        out = []
        for d in (download_dir, config_dir):
            if not os.path.isdir(d):
                continue
            for name in sorted(os.listdir(d)):
                if name.endswith(suffix):
                    out.append(os.path.join(d, name))
        return out

    include = read_networks(paths("ips.txt") + paths("include-ips.txt"))
    exclude = read_networks(paths("exclude-ips.txt"))
    include6 = read_networks(paths("ips6.txt") + paths("include-ips6.txt"))
    exclude6 = read_networks(paths("exclude-ips6.txt"))

    route = collapse(ipv4_only(subtract(collapse(ipv4_only(include)), ipv4_only(exclude))))
    route6 = collapse([n for n in subtract(collapse(include6), collapse(exclude6))
                       if isinstance(n, ipaddress.IPv6Network)])
    forward = collapse(ipv4_only(subtract(collapse(ipv4_only(include)),
                                           ipv4_only(read_networks(paths("forward-ips.txt"))))))

    lists = IpLists(
        route=route,
        route6=route6,
        excluded=ipv4_only(collapse(exclude)),
        drop=ipv4_only(collapse(read_networks(paths("drop-ips.txt")))),
        deny=ipv4_only(collapse(read_networks(paths("deny-ips.txt")))),
        allow=ipv4_only(collapse(read_networks(paths("allow-ips.txt")))),
        forward=forward,
    )
    return lists


def cidr_to_netmask(prefixlen: int) -> str:
    """IPv4 CIDR -> маска подсети в dotted-quad (для `route add` в Windows)."""
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefixlen}").netmask)


def split_cidr(cidr: str) -> tuple[str, str]:
    """`1.2.3.0/24` -> (`1.2.3.0`, `255.255.255.0`)."""
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address), str(net.netmask)


def format_allowed_ips(nets: list[ipaddress._BaseNetwork], base: str) -> str:
    """Собирает строку AllowedIPs: базовая подсеть + список маршрутов."""
    parts = [base]
    parts.extend(str(n) for n in nets)
    return ", ".join(parts)


def is_russian_zone(name: str) -> bool:
    """`.ru`, `.su` и `.рф` (xn--p1ai) — российские зоны."""
    lowered = name.lower().rstrip(".")
    if lowered.endswith(".ru") or lowered == "ru":
        return True
    if lowered.endswith(".su") or lowered == "su":
        return True
    if lowered.endswith(".xn--p1ai") or lowered == "xn--p1ai":
        return True
    return False


RU_ZONES = ("ru", "su", "xn--p1ai")

# Домены, для которых AAAA всегда пустой (Meta/Instagram — их IPv6-кластеры
# с части узлов виснут или режутся через Proton).
META_NO_AAAA = ("instagram.com", "cdninstagram.com", "fbcdn.net", "facebook.com")

# 4pda: Cloudflare отдаёт 403-челлендж, нужен статический A.
PDA_DOMAINS = ("4pda.to", "4pda.ws")
PDA_STATIC_A = ("8.47.69.0", "8.6.112.0")

_WILDCARD_RE = re.compile(r"[*?\[]")


def has_wildcard(pattern: str) -> bool:
    return bool(_WILDCARD_RE.search(pattern))
