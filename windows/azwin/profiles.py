"""Генератор клиентских профилей для Windows 11.

Портирует `client.sh` upstream: те же шаблоны, те же подстановки, те же
протоколы (OpenVPN, WireGuard, AmneziaWG 1.5/2/3) и те же ограничения,
которые upstream отдельно оговаривает для Windows:

  * имя файла профиля — не длиннее 32 символов, без скобок;
  * AmneziaWG 2/3 не поддерживаются AmneziaVPN — нужен AmneziaWG;
  * для профилей IPv4 в OpenVPN добавляется `block-ipv6`;
  * MTU AmneziaWG 2 — 1280 (минимальный, гарантированно проходит).
"""

from __future__ import annotations

import base64
import ipaddress
import os
import secrets
from dataclasses import dataclass, field

# Порты upstream.
OPENVPN_ANTIZAPRET_UDP = 50443
OPENVPN_ANTIZAPRET_TCP = 50443
OPENVPN_VPN_UDP = 50080
OPENVPN_VPN_TCP = 50080

WG_ANTIZAPRET_PORT = 51443
WG_VPN_PORT = 51080
AWG2_ANTIZAPRET_PORT = 53443
AWG2_VPN_PORT = 53080
AWG3_PORT = 51821

# Резервные порты (обход блокировок).
OPENVPN_FALLBACK_PORTS = [504, 443]        # AntiZapret VPN
OPENVPN_FALLBACK_PORTS_VPN = [508, 80]     # полный VPN
WG_FALLBACK_PORTS = [540, 580]
AWG2_FALLBACK_PORTS = [544, 584]
AWG3_CLIENT_PORT_RANGE = range(51900, 52000)

FAKE_IP_POOL = "198.18.0.0/15"
FAKE_IP_POOL_ALT = "10.30.0.0/15"

DNS_ANTIZAPRET_UDP = "10.29.0.1"
DNS_ANTIZAPRET_TCP = "10.29.4.1"
DNS_ANTIZAPRET_WG = "10.29.8.1"
DNS_ANTIZAPRET_AWG2 = "10.29.9.1"
DNS_ANTIZAPRET_AWG3 = "10.9.0.1"

MTU_DEFAULT = 1420
MTU_AWG2 = 1280

# Имя файла профиля для Windows — максимум 32 символа, без скобок.
MAX_FILENAME_LEN = 32


def sanitize_filename(name: str) -> str:
    """Приводит имя клиента к безопасному имени файла профиля.

    Windows-ограничения из README: длина до 32 символов, без скобок.
    """
    cleaned = "".join(ch for ch in name if ch.isalnum() or ch in "-_")
    cleaned = cleaned.strip("-_") or "client"
    return cleaned[:MAX_FILENAME_LEN]


def base64_key(length: int = 32) -> str:
    """Ключ WireGuard-формата (base64 от 32 случайных байт)."""
    import base64

    return base64.b64encode(secrets.token_bytes(length)).decode("ascii")


def generate_wg_keys() -> tuple[str, str]:
    """Генерирует пару ключей X25519 (приватный/публичный).

    Используется `cryptography`, если он есть; иначе — чистый Python
    (X25519 через RFC 7748), чтобы не тянуть внешнюю зависимость.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat,
        )

        private = X25519PrivateKey.generate()
        public = private.public_key()
        priv_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = public.public_bytes(Encoding.Raw, PublicFormat.Raw)

        return (base64.b64encode(priv_bytes).decode("ascii"),
                base64.b64encode(pub_bytes).decode("ascii"))
    except ImportError:
        return _x25519_keygen_python()


def _x25519_keygen_python() -> tuple[str, str]:
    """X25519 без внешних зависимостей (RFC 7748)."""
    private_raw = bytearray(secrets.token_bytes(32))
    private_raw[0] &= 248
    private_raw[31] &= 127
    private_raw[31] |= 64
    public_raw = _x25519_scalar_mult(bytes(private_raw), _X25519_BASEPOINT)
    return (base64.b64encode(bytes(private_raw)).decode("ascii"),
            base64.b64encode(public_raw).decode("ascii"))


_X25519_BASEPOINT = (9).to_bytes(32, "little")
_P = 2 ** 255 - 19
_A24 = 121665


def _x25519_scalar_mult(k: bytes, u: bytes) -> bytes:
    """Скалярное умножение X25519 (RFC 7748)."""
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    u_int = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u_int, 1, 0, u_int, 1, 0
    for t in range(254, -1, -1):
        kt = (k_int >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = ((da + cb) ** 2) % _P
        z3 = (x1 * ((da - cb) ** 2)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * (aa + _A24 * e)) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = (x2 * pow(z2, _P - 2, _P)) % _P
    return result.to_bytes(32, "little")


@dataclass
class ServerKeys:
    """Ключи сервера для рендера клиентских профилей."""

    private_key: str = ""
    public_key: str = ""
    preshared_key: str = ""
    server_host: str = ""


@dataclass(frozen=True)
class ProtocolFamily:
    """Одно семейство протоколов: своя подсеть, свой DNS, свой порт.

    Портирует разделение upstream: у каждого семейства свой серверный
    интерфейс, своя подсеть адресов и свои ключи клиента.

    `key_group` — группы, которые делят ключ и адрес. В upstream AmneziaWG 1.5
    и обычный WireGuard — это один и тот же серверный интерфейс
    (`/etc/wireguard/antizapret.conf`), поэтому у клиента один ключ и один
    адрес, а различаются только порт и параметры обфускации.
    """

    key: str            # wireguard | awg15 | awg2 | awg3
    layer: str         # antizapret | vpn
    base_ipv4: str     # база подсети IPv4 клиентов
    base_ipv6: str     # база подсети IPv6 клиентов
    dns: str           # DNS в профиле
    port: int          # порт Endpoint
    key_group: str = ""  # группа ключей (по умолчанию key/layer)


# Семейства протоколов — подсети и порты как в upstream.
FAMILIES: tuple[ProtocolFamily, ...] = (
    ProtocolFamily("wireguard", "antizapret", "10.29.8.2", "fd29:8::",
                   DNS_ANTIZAPRET_WG, WG_ANTIZAPRET_PORT, "wg-antizapret"),
    ProtocolFamily("wireguard", "vpn", "10.28.8.2", "fd28:8::",
                   "1.1.1.1, 1.0.0.1", WG_VPN_PORT, "wg-vpn"),
    # AmneziaWG 1.5 делит ключ и адрес с WireGuard (тот же серверный интерфейс).
    ProtocolFamily("awg15", "antizapret", "10.29.8.2", "fd29:8::",
                   DNS_ANTIZAPRET_WG, 52443, "wg-antizapret"),
    ProtocolFamily("awg15", "vpn", "10.28.8.2", "fd28:8::",
                   "1.1.1.1, 1.0.0.1", 52080, "wg-vpn"),
    ProtocolFamily("awg2", "antizapret", "10.29.9.2", "fd29:9::",
                   DNS_ANTIZAPRET_AWG2, AWG2_ANTIZAPRET_PORT, "awg2-antizapret"),
    ProtocolFamily("awg2", "vpn", "10.28.9.2", "fd28:9::",
                   "1.1.1.1, 1.0.0.1", AWG2_VPN_PORT, "awg2-vpn"),
    ProtocolFamily("awg3", "antizapret", "10.9.0.2", "fd29:7::",
                   DNS_ANTIZAPRET_AWG3, AWG3_PORT, "awg3-antizapret"),
    ProtocolFamily("awg3", "vpn", "10.9.1.2", "fd28:7::",
                   "1.1.1.1, 1.0.0.1", AWG3_PORT, "awg3-vpn"),
)

# Подсеть, в которую уходит AllowedIPS-трафик слоя.
LAYER_SUBNET = {
    ("wireguard", "antizapret"): "10.29.8.0/24",
    ("wireguard", "vpn"): "10.28.8.0/24",
    ("awg15", "antizapret"): "10.29.8.0/24",
    ("awg15", "vpn"): "10.28.8.0/24",
    ("awg2", "antizapret"): "10.29.9.0/24",
    ("awg2", "vpn"): "10.28.9.0/24",
    ("awg3", "antizapret"): "10.9.0.0/24",
    ("awg3", "vpn"): "10.9.1.0/24",
}


@dataclass
class ClientProfile:
    """Готовый профиль одного клиента."""

    client_name: str
    protocol: str          # openvpn-udp | openvpn-tcp | openvpn | wireguard | awg15 | awg2 | awg3
    filename: str
    content: str
    layer: str = "antizapret"   # antizapret | vpn
    extra: dict = field(default_factory=dict)

    def save(self, directory: str) -> str:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, self.filename)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(self.content)
        return path


def _render(template: str, values: dict[str, str]) -> str:
    """Подставляет `${VAR}` как в upstream `render`."""
    out = template
    for key, value in values.items():
        out = out.replace("${" + key + "}", value)
    return out


def _route_ips_line(route_ips: list[str], base: str) -> str:
    """Собирает AllowedIPs: базовая подсеть + fake-пул + маршруты."""
    parts = [base, FAKE_IP_POOL]
    parts.extend(route_ips)
    return ", ".join(parts)


def render_openvpn(client_name: str, server_host: str, ca_cert: str,
                   client_cert: str, client_key: str, layer: str = "antizapret",
                   protocol: str = "udp", route_ips: list[str] | None = None,
                   block_ipv6: bool = True) -> ClientProfile:
    """Собирает .ovpn профиль.

    Порты и запасные порты — как в upstream-шаблонах: AntiZapret VPN
    использует 50443 + 504 + 443, полный VPN — 50080 + 508 + 80.
    `protocol` = `udp`, `tcp` или `both` (в upstream для `both` есть отдельный
    шаблон `antizapret.conf` / `vpn.conf`).

    `block-ipv6` добавляется для профилей IPv4 — на Windows OpenVPN
    иначе продолжит слать IPv6 в туннель и утекать мимо split-маршрутов.
    """
    is_vpn = layer == "vpn"
    if is_vpn:
        main_port, fallback_ports = OPENVPN_VPN_UDP, OPENVPN_FALLBACK_PORTS_VPN
    else:
        main_port, fallback_ports = OPENVPN_ANTIZAPRET_UDP, OPENVPN_FALLBACK_PORTS
    if protocol == "tcp":
        main_port = OPENVPN_VPN_TCP if is_vpn else OPENVPN_ANTIZAPRET_TCP

    def remotes_for(proto: str) -> list[str]:
        suffix = "tcp4" if proto == "tcp" else "udp4"
        ports = [main_port] + list(fallback_ports)
        return [f"remote {server_host} {port} {suffix}" for port in ports]

    protocols = ("udp", "tcp") if protocol == "both" else (protocol,)
    remotes: list[str] = []
    for proto in protocols:
        remotes.extend(remotes_for(proto))

    lines = [
        "client",
        "nobind",
        *remotes,
        "server-poll-timeout 10",
        "remote-cert-tls server",
        "dev tun",
        "cipher AES-128-GCM",
        "reneg-sec 0",
        "resolv-retry infinite",
        "persist-key",
        "persist-tun",
    ]
    if "udp" in protocols:
        lines.append("explicit-exit-notify 1")
    if block_ipv6:
        lines.append("block-ipv6")
    label = "VPN" if is_vpn else "AntiZapret"
    if protocol == "both":
        friendly = f"{label} {server_host} [{client_name}]"
    else:
        friendly = f"{label} {server_host} {protocol.upper()} [{client_name}]"
    lines.append(f'setenv FRIENDLY_NAME "{friendly}"')
    lines.extend([
        "",
        "<ca>",
        ca_cert.strip(),
        "</ca>",
        "",
        "<cert>",
        client_cert.strip(),
        "</cert>",
        "",
        "<key>",
        client_key.strip(),
        "</key>",
        "",
    ])
    suffix = "" if protocol == "both" else f"-{protocol}"
    filename = f"{sanitize_filename(client_name)}-{'vpn' if is_vpn else 'antizapret'}{suffix}.ovpn"
    return ClientProfile(
        client_name=client_name, protocol=f"openvpn-{protocol}", filename=filename,
        content="\n".join(lines), layer=layer,
    )


def render_wireguard(client_name: str, server: ServerKeys, client_private: str,
                     client_public: str, preshared: str, client_ip: str,
                     layer: str = "antizapret", route_ips: list[str] | None = None,
                     client_ipv6: str | None = None,
                     dns: str | None = None, port: int | None = None,
                     subnet: str | None = None) -> ClientProfile:
    """Собирает .conf профиль WireGuard."""
    is_vpn = layer == "vpn"
    dns = dns or ("1.1.1.1, 1.0.0.1" if is_vpn else DNS_ANTIZAPRET_WG)
    port = port or (WG_VPN_PORT if is_vpn else WG_ANTIZAPRET_PORT)
    subnet = subnet or LAYER_SUBNET[("wireguard", layer)]
    address = f"{client_ip}/32" + (f", {client_ipv6}/128" if client_ipv6 else "")
    allowed = ("0.0.0.0/0" if is_vpn
               else _route_ips_line(route_ips or [], subnet))
    if client_ipv6:
        allowed += ", fd00:30::/64"

    content = f"""[Interface]
PrivateKey = {client_private}
Address = {address}
DNS = {dns}

[Peer]
PublicKey = {server.public_key}
PresharedKey = {preshared}
Endpoint = {server.server_host}:{port}
AllowedIPs = {allowed}
PersistentKeepalive = 15
"""
    filename = f"{sanitize_filename(client_name)}-{'vpn' if is_vpn else 'antizapret'}.conf"
    return ClientProfile(
        client_name=client_name, protocol="wireguard", filename=filename,
        content=content, layer=layer,
    )


def render_awg15(client_name: str, server: ServerKeys, client_private: str,
                  client_public: str, preshared: str, client_ip: str,
                  layer: str = "antizapret", route_ips: list[str] | None = None,
                  client_ipv6: str | None = None,
                  dns: str | None = None, port: int | None = None,
                  subnet: str | None = None,
                  jc: int = 4, jmin: int = 40, jmax: int = 70,
                  s1: int = 0, s2: int = 0,
                  h1: int = 1, h2: int = 2, h3: int = 3, h4: int = 4,
                  i1: str | None = None) -> ClientProfile:
    """Собирает .conf профиль AmneziaWG 1.5 (обфускация WireGuard)."""
    is_vpn = layer == "vpn"
    dns = dns or ("1.1.1.1, 1.0.0.1" if is_vpn else DNS_ANTIZAPRET_WG)
    port = port or (52080 if is_vpn else 52443)
    subnet = subnet or LAYER_SUBNET[("awg15", layer)]
    address = f"{client_ip}/32" + (f", {client_ipv6}/128" if client_ipv6 else "")
    allowed = ("0.0.0.0/0" if is_vpn
               else _route_ips_line(route_ips or [], subnet))
    if client_ipv6:
        allowed += ", fd00:30::/64"

    i_lines = ""
    if i1:
        i_lines = f"I1 = {i1}\nI2 = \nI3 = \nI4 = \nI5 = \n"
    content = f"""[Interface]
PrivateKey = {client_private}
Address = {address}
DNS = {dns}
Jc = {jc}
Jmin = {jmin}
Jmax = {jmax}
S1 = {s1}
S2 = {s2}
H1 = {h1}
H2 = {h2}
H3 = {h3}
H4 = {h4}
{i_lines}
[Peer]
PublicKey = {server.public_key}
PresharedKey = {preshared}
Endpoint = {server.server_host}:{port}
AllowedIPs = {allowed}
PersistentKeepalive = 15
"""
    filename = f"{sanitize_filename(client_name)}-{'vpn' if is_vpn else 'antizapret'}-am.conf"
    return ClientProfile(
        client_name=client_name, protocol="awg15", filename=filename,
        content=content, layer=layer,
    )


def render_awg2(client_name: str, server: ServerKeys, client_private: str,
                client_public: str, preshared: str, client_ip: str,
                layer: str = "antizapret", route_ips: list[str] | None = None,
                client_ipv6: str | None = None,
                dns: str | None = None, port: int | None = None,
                subnet: str | None = None,
                jc: int = 5, jmin: int = 20, jmax: int = 50,
                s1: int = 88, s2: int = 121, s3: int = 41, s4: int = 8,
                h1: int = 305419896, h2: int = 892374510,
                h3: int = 1439827201, h4: int = 1985043762,
                i1: str | None = None, i2: str | None = None,
                masquerade: int = 1) -> ClientProfile:
    """Собирает .conf профиль AmneziaWG 2 (маскировка первого пакета).

    Тип маскировки выбирается один раз при установке: 1 — TLS ClientHello,
    2 — QUIC Initial, 3 — SIP INVITE.
    """
    is_vpn = layer == "vpn"
    dns = dns or ("1.1.1.1, 1.0.0.1" if is_vpn else DNS_ANTIZAPRET_AWG2)
    port = port or (AWG2_VPN_PORT if is_vpn else AWG2_ANTIZAPRET_PORT)
    subnet = subnet or LAYER_SUBNET[("awg2", layer)]
    address = f"{client_ip}/32" + (f", {client_ipv6}/128" if client_ipv6 else "")
    allowed = ("0.0.0.0/0" if is_vpn
               else _route_ips_line(route_ips or [], subnet))
    if client_ipv6:
        allowed += ", fd00:30::/64"

    i_lines = ""
    if i1:
        i_lines = f"I1 = {i1}\nI2 = {i2 or ''}\nI3 = \nI4 = \nI5 = \n"

    content = f"""[Interface]
PrivateKey = {client_private}
Address = {address}
DNS = {dns}
Jc = {jc}
Jmin = {jmin}
Jmax = {jmax}
S1 = {s1}
S2 = {s2}
S3 = {s3}
S4 = {s4}
H1 = {h1}
H2 = {h2}
H3 = {h3}
H4 = {h4}
{i_lines}
[Peer]
PublicKey = {server.public_key}
PresharedKey = {preshared}
Endpoint = {server.server_host}:{port}
AllowedIPs = {allowed}
PersistentKeepalive = 15
"""
    filename = f"{sanitize_filename(client_name)}-{'vpn' if is_vpn else 'antizapret'}-am2.conf"
    return ClientProfile(
        client_name=client_name, protocol="awg2", filename=filename,
        content=content, layer=layer,
        extra={"mtu": MTU_AWG2, "masquerade": masquerade},
    )


def render_awg3(client_name: str, server: ServerKeys, client_private: str,
                client_public: str, preshared: str, client_ip: str,
                layer: str = "antizapret", route_ips: list[str] | None = None,
                client_ipv6: str | None = None,
                client_port: int | None = None,
                header_protection_key: str | None = None,
                dns: str | None = None, port: int | None = None,
                subnet: str | None = None,
                jc: int = 5, jmin: int = 20, jmax: int = 50,
                s1: int = 88, s2: int = 121, s3: int = 41, s4: int = 8,
                h1: int = 305419896, h2: int = 892374510,
                h3: int = 1439827201, h4: int = 1985043762) -> ClientProfile:
    """Собирает .conf профиль AmneziaWG 3 (параметры обфускации 3.x).

    Требует AmneziaWG для Windows 3.1.0+ — старые версии такой конфиг
    не примут.
    """
    is_vpn = layer == "vpn"
    port = client_port or port or AWG3_PORT
    dns = dns or (DNS_ANTIZAPRET_AWG3 if not is_vpn else "1.1.1.1, 1.0.0.1")
    subnet = subnet or LAYER_SUBNET[("awg3", layer)]
    address = f"{client_ip}/32" + (f", {client_ipv6}/128" if client_ipv6 else "")
    if is_vpn:
        allowed = "0.0.0.0/0"
    else:
        allowed = _route_ips_line(route_ips or [], subnet)
    if client_ipv6:
        allowed += ", fd00:30::/64"

    header_line = f"HeaderProtectionKey = {header_protection_key}\n" if header_protection_key else ""
    content = f"""[Interface]
PrivateKey = {client_private}
Address = {address}
DNS = {dns}
Jc = {jc}
Jmin = {jmin}
Jmax = {jmax}
S1 = {s1}
S2 = {s2}
S3 = {s3}
S4 = {s4}
H1 = {h1}
H2 = {h2}
H3 = {h3}
H4 = {h4}
{header_line}
[Peer]
PublicKey = {server.public_key}
PresharedKey = {preshared}
Endpoint = {server.server_host}:{port}
AllowedIPs = {allowed}
PersistentKeepalive = 15
"""
    filename = f"{sanitize_filename(client_name)}-{'vpn' if is_vpn else 'antizapret'}-awg3.conf"
    return ClientProfile(
        client_name=client_name, protocol="awg3", filename=filename,
        content=content, layer=layer,
        extra={"client_port": port},
    )


def all_profiles(client_name: str, server_host: str, keys: ServerKeys,
                 route_ips: list[str] | None = None,
                 ca_cert: str = "", client_cert: str = "",
                 client_key: str = "") -> list[ClientProfile]:
    """Собирает полный набор профилей клиента (все протоколы, оба слоя)."""
    route_ips = route_ips or []
    profiles: list[ClientProfile] = []
    for layer in ("antizapret", "vpn"):
        for protocol in ("udp", "tcp"):
            profiles.append(render_openvpn(
                client_name, server_host, ca_cert, client_cert, client_key,
                layer=layer, protocol=protocol, route_ips=route_ips))
    profiles.append(render_openvpn(
        client_name, server_host, ca_cert, client_cert, client_key,
        layer="antizapret", protocol="udp", route_ips=route_ips))
    return profiles


def ipv6_from_client_ip(client_ip: str, family: str = "wg") -> str:
    """Вычисляет IPv6-адрес клиента из его IPv4 (как upstream client.sh).

    family: `wg` — WireGuard/AmneziaWG 1.5 (fd29:8::/fd28:8::),
            `awg2` — AmneziaWG 2 (fd29:9::/fd28:9::),
            `awg3` — AmneziaWG 3 (fd29:7::/fd28:7::).
    """
    last = int(client_ip.split(".")[-1])
    prefix = {"wg": "8", "awg2": "9", "awg3": "7"}.get(family, "8")
    return f"fd29:{prefix}::{last:x}"


def ipv6_from_client_ip_vpn(client_ip: str, family: str = "wg") -> str:
    """IPv6-адрес клиента для полного VPN (слой fd28)."""
    last = int(client_ip.split(".")[-1])
    prefix = {"wg": "8", "awg2": "9", "awg3": "7"}.get(family, "8")
    return f"fd28:{prefix}::{last:x}"


def next_client_ip(used: set[str], base: str) -> str:
    """Выбирает свободный адрес клиента в подсети (до 253 клиентов)."""
    octets = base.split(".")
    for i in range(2, 255):
        candidate = f"{octets[0]}.{octets[1]}.{octets[2]}.{i}"
        if candidate not in used:
            return candidate
    raise RuntimeError("подсеть заполнена: максимум 253 клиента")


def validate_profile(content: str) -> list[str]:
    """Проверяет профиль на очевидные ошибки. Возвращает список проблем."""
    problems: list[str] = []
    if "[Interface]" not in content:
        problems.append("нет секции [Interface]")
    if "[Peer]" not in content:
        problems.append("нет секции [Peer]")
    if "PrivateKey = " in content and "PrivateKey = \n" in content:
        problems.append("пустой PrivateKey")
    if "Endpoint = " in content and "Endpoint = \n" in content:
        problems.append("пустой Endpoint")
    for line in content.splitlines():
        if line.startswith("AllowedIPs = ") and not line.strip().endswith(("/", "0")):
            problems.append(f"некорректный AllowedIPs: {line}")
    return problems
