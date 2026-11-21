"""Сетевой слой Windows 11: маршруты, DNS, firewall, IPv6, утечки.

Портирует серверную часть upstream (`up.sh` / `down.sh`) на Windows:
  * split-маршрутизация — в туннель уходят только адреса из route-ips.txt
    и поддельный пул fake-IP;
  * DNS-утечки — запросы к DNS AntiZapret идут через туннель, а не мимо;
  * IPv6 — по умолчанию выключается (как на сервере), иначе трафик
    уходит в обход туннеля;
  * fake-IP подстановка — маршрут на fake-пул идёт в туннель, где
    настоящий адрес подставляет сам туннель/прокси.

Все команды вызываются через `netsh`/`route.exe`/`New-NetRoute`, потому что
на Windows это единственный путь менять таблицу маршрутизации из
непривилегированного скрипта (через netsh route).
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
import sys
from dataclasses import dataclass

from .lists import IpLists

# Windows: выключаем IPv6 на всех интерфейсах (обязательно для split-режима).
IPV6_STATE_REG = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
DISABLE_IPV6_VALUE = 0xFFFFFFFF


def is_admin() -> bool:
    """Проверяет права администратора (нужны для netsh route и реестра)."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - вне Windows или нет ctypes
        return False


def run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    """Запускает команду и возвращает результат. Текст — UTF-8."""
    return subprocess.run(cmd, capture_output=True, check=check,
                          shell=(os.name == "nt" and cmd[0].lower().endswith(".exe")
                                 and cmd[0].lower() in ("netsh", "route")))


@dataclass
class RouteEntry:
    """Одна запись в таблице маршрутизации."""

    destination: str      # CIDR
    gateway: str         # IP шлюза (VPN-интерфейс) или "net_gateway"
    mask: str            # dotted-quad маска
    interface: str | None = None
    metric: int = 0

    @property
    def prefix(self) -> str:
        net = ipaddress.ip_network(self.destination, strict=False)
        return net.prefixlen


class WindowsNetwork:
    """Управление маршрутами и DNS на Windows 11."""

    def __init__(self, gateway: str, interface: str | None = None,
                 metric: int = 0, dry_run: bool = False):
        self.gateway = gateway
        self.interface = interface
        self.metric = metric
        self.dry_run = dry_run
        self._added: list[RouteEntry] = []

    # --- маршруты ---------------------------------------------------------

    def add_route(self, destination: str, gateway: str | None = None,
                  mask: str | None = None) -> bool:
        """Добавляет маршрут. destination — CIDR."""
        net = ipaddress.ip_network(destination, strict=False)
        if isinstance(net, ipaddress.IPv6Network):
            return self._add_route_v6(net, gateway)
        mask = mask or str(net.netmask)
        cmd = ["netsh", "interface", "ipv4", "add", "route",
               destination, net.network_address.exploded, mask, gateway or self.gateway]
        if self.interface:
            cmd += ["interface=" + self.interface]
        if self.metric:
            cmd += ["metric=" + str(self.metric)]
        if self.dry_run:
            print("[dry-run] " + " ".join(cmd))
            self._added.append(RouteEntry(str(net), gateway or self.gateway, mask))
            return True
        result = run(cmd)
        ok = result.returncode == 0
        if ok:
            self._added.append(RouteEntry(str(net), gateway or self.gateway, mask))
        else:
            self._log_error("add route", result)
        return ok

    def _add_route_v6(self, net: ipaddress.IPv6Network, gateway: str | None) -> bool:
        cmd = ["netsh", "interface", "ipv6", "add", "route",
               str(net), str(net.network_address), gateway or self.gateway]
        if self.interface:
            cmd += ["interface=" + self.interface]
        if self.dry_run:
            print("[dry-run] " + " ".join(cmd))
            return True
        result = run(cmd)
        if result.returncode != 0:
            self._log_error("add route v6", result)
            return False
        return True

    def delete_route(self, destination: str, gateway: str | None = None,
                     mask: str | None = None) -> bool:
        """Удаляет маршрут (обратная операция add_route)."""
        net = ipaddress.ip_network(destination, strict=False)
        if isinstance(net, ipaddress.IPv6Network):
            cmd = ["netsh", "interface", "ipv6", "delete", "route",
                   str(net), str(net.network_address), gateway or self.gateway]
        else:
            mask = mask or str(net.netmask)
            cmd = ["netsh", "interface", "ipv4", "delete", "route",
                   destination, net.network_address.exploded, mask, gateway or self.gateway]
        if self.interface:
            cmd += ["interface=" + self.interface]
        if self.dry_run:
            print("[dry-run] " + " ".join(cmd))
            return True
        result = run(cmd)
        if result.returncode != 0:
            self._log_error("delete route", result)
            return False
        self._added = [r for r in self._added if r.destination != str(net)]
        return True

    def add_routes(self, cidrs: list[str]) -> int:
        """Добавляет список подсетей, возвращает число успешных."""
        added = 0
        for cidr in cidrs:
            if self.add_route(cidr):
                added += 1
        return added

    def delete_routes(self, cidrs: list[str]) -> int:
        deleted = 0
        for cidr in cidrs:
            if self.delete_route(cidr):
                deleted += 1
        return deleted

    def setup_split_routing(self, ips: IpLists, fake_cidr: str,
                            dns_ips: list[str]) -> list[str]:
        """Настраивает split-маршрутизацию как на сервере upstream.

        В туннель уходят:
          * поддельный пул fake-IP (весь трафик к нему идёт через туннель);
          * адреса из route-ips.txt (Discord, Telegram, Cloudflare и т.д.);
          * DNS-адреса AntiZapret (иначе DNS-утечка мимо туннеля).
        """
        added: list[str] = []
        for cidr in [fake_cidr] + list(ips.route):
            if self.add_route(cidr):
                added.append(cidr)
        for dns_ip in dns_ips:
            if self.add_route(f"{dns_ip}/32"):
                added.append(f"{dns_ip}/32")
        return added

    def cleanup_split_routing(self, ips: IpLists, fake_cidr: str,
                              dns_ips: list[str]) -> int:
        removed = 0
        for cidr in [fake_cidr] + [str(n) for n in ips.route] + [f"{d}/32" for d in dns_ips]:
            if self.delete_route(cidr):
                removed += 1
        return removed

    # --- DNS --------------------------------------------------------------

    def set_dns_servers(self, interface: str, servers: list[str]) -> bool:
        """Назначает DNS-серверы интерфейсу (через netsh, чтобы не трогать DHCP)."""
        cmd = ["netsh", "interface", "ipv4", "set", "dnsservers",
               f"name={interface}", "source=static"]
        if not servers:
            cmd.append("none")
        else:
            cmd.append("address=" + ",".join(servers))
        if self.dry_run:
            print("[dry-run] " + " ".join(cmd))
            return True
        result = run(cmd)
        if result.returncode != 0:
            self._log_error("set dns", result)
            return False
        return True

    def reset_dns_servers(self, interface: str) -> bool:
        """Возвращает DNS интерфейса к DHCP."""
        cmd = ["netsh", "interface", "ipv4", "set", "dnsservers",
               f"name={interface}", "source=dhcp"]
        if self.dry_run:
            print("[dry-run] " + " ".join(cmd))
            return True
        result = run(cmd)
        return result.returncode == 0

    # --- IPv6 -------------------------------------------------------------

    @staticmethod
    def disable_ipv6_globally() -> bool:
        """Отключает IPv6 на уровне системы (как upstream отключает IPv6 на сервере).

        Требует перезагрузки для полного эффекта.
        """
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IPV6_STATE_REG, 0,
                                winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "DisabledComponents", 0, winreg.DWORD,
                                  DISABLE_IPV6_VALUE)
            return True
        except (OSError, ImportError) as exc:
            print(f"Error: не удалось отключить IPv6: {exc}")
            return False

    @staticmethod
    def ipv6_disabled() -> bool:
        """Проверяет, выключен ли IPv6 глобально."""
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, IPV6_STATE_REG, 0,
                                winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "DisabledComponents")
                return value == DISABLE_IPV6_VALUE
        except (OSError, ImportError):
            return False

    @staticmethod
    def disable_ipv6_per_adapter(interface: str) -> bool:
        """Отключает IPv6 на конкретном адаптере (UncheckBindComponent)."""
        cmd = ["Disable-NetAdapterBinding", "-ComponentID", "ms_tcpip6",
               "-Name", interface, "-Confirm:$false"]
        result = run(["powershell", "-NoProfile", "-Command", " ".join(cmd)])
        return result.returncode == 0

    # --- утечки DNS -------------------------------------------------------

    @staticmethod
    def disable_secure_dns() -> bool:
        """Выключает системный DNS-over-HTTPS (Windows 11 Secure DNS).

        Включённый DoH обходит DNS AntiZapret и ломает split-режим —
        ровно то, о чём предупреждает README.
        """
        try:
            import winreg

            path = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSCache"
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                    winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "Enabled", 0, winreg.DWORD, 0)
            return True
        except (OSError, ImportError) as exc:
            print(f"Error: не удалось выключить Secure DNS: {exc}")
            return False

    @staticmethod
    def disable_nrdot() -> bool:
        """Отключает NRDOT (RFC 7817) — иначе Windows добавляет суффиксы .mDNS."""
        try:
            import winreg

            path = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSCache"
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                    winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "DisableNrDomainParam", 0, winreg.DWORD, 1)
            return True
        except (OSError, ImportError) as exc:
            print(f"Error: не удалось отключить NRDOT: {exc}")
            return False

    @staticmethod
    def disable_wpad() -> bool:
        """Отключает WPAD — автоопределение прокси может увести трафик мимо туннеля."""
        try:
            import winreg

            path = r"SOFTWARE\Policies\Microsoft\Windows\System\WinHttp"
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0,
                                    winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxySettingsPerUser", 0, winreg.DWORD, 0)
            return True
        except (OSError, ImportError) as exc:
            print(f"Error: не удалось отключить WPAD: {exc}")
            return False

    # --- firewall ---------------------------------------------------------

    @staticmethod
    def add_firewall_rule(name: str, remote_cidrs: list[str], port: int = 0,
                          protocol: str = "Any", action: str = "Block") -> bool:
        """Добавляет правило брандмауэра (block/allow по списку адресов).

        Используется для deny-ips (запрет подключаться к самому серверу) и
        drop-ips (запрет обращаться клиентам).
        """
        if not remote_cidrs:
            return True
        cmd = ["New-NetFirewallRule", "-Name", name, "-Direction", "Outbound",
               "-Action", action, "-Protocol", protocol]
        if port:
            cmd += ["-RemotePort", str(port)]
        cmd += ["-RemoteAddress", ",".join(remote_cidrs)]
        result = run(["powershell", "-NoProfile", "-Command", " ".join(cmd)])
        return result.returncode == 0

    @staticmethod
    def remove_firewall_rule(name: str) -> bool:
        result = run(["powershell", "-NoProfile", "-Command",
                      f"Remove-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue"])
        return result.returncode == 0

    # --- диагностика ------------------------------------------------------

    @staticmethod
    def list_routes(destination: str | None = None) -> str:
        """Показывает таблицу маршрутизации (для проверки split-режима)."""
        cmd = ["route", "print"]
        if destination:
            cmd.append(destination)
        result = run(cmd)
        return (result.stdout or b"").decode("utf-8", "replace")

    @staticmethod
    def list_dns() -> str:
        result = run(["netsh", "interface", "ipv4", "show", "dnsservers"])
        return (result.stdout or b"").decode("utf-8", "replace")

    @staticmethod
    def interface_index(interface: str) -> int | None:
        """Возвращает ifIndex интерфейса по имени (нужен для маршрутов)."""
        result = run(["powershell", "-NoProfile", "-Command",
                      f"(Get-NetAdapter -Name '{interface}' -ErrorAction SilentlyContinue"
                      " | Select-Object -ExpandProperty ifIndex)"])
        text = (result.stdout or b"").decode("utf-8", "replace").strip()
        try:
            return int(text)
        except ValueError:
            return None

    @staticmethod
    def list_adapters() -> list[tuple[str, str, str]]:
        """Список адаптеров: (имя, статус, описание)."""
        result = run(["powershell", "-NoProfile", "-Command",
                      "Get-NetAdapter | Select-Object Name,Status,InterfaceDescription"
                      " | ConvertTo-Csv -NoTypeInformation"])
        text = (result.stdout or b"").decode("utf-8", "replace")
        rows = [line for line in text.splitlines() if line.strip()]
        if len(rows) < 2:
            return []
        out: list[tuple[str, str, str]] = []
        for line in rows[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 3:
                out.append((parts[0], parts[1], parts[2]))
        return out

    @staticmethod
    def _log_error(action: str, result: subprocess.CompletedProcess) -> None:
        stderr = (result.stderr or b"").decode("utf-8", "replace").strip()
        stdout = (result.stdout or b"").decode("utf-8", "replace").strip()
        message = stderr or stdout or f"код {result.returncode}"
        print(f"Error: {action}: {message}", file=sys.stderr)
