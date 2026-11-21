"""Локальный DNS-резолвер AntiZapret для Windows 11.

Это порт серверной части upstream (`proxy.py` + `kresd.conf`) на Windows:
тот же fake-IP-механизм, те же правила выбора резолвера и те же списки.

Ключевая идея upstream: клиент спрашивает локальный DNS, тот для
заблокированных доменов выдаёт «поддельный» адрес из пула 198.18.0.0/15
(или 10.30.0.0/15). Трафик к поддельному адресу уходит в туннель, где
настоящий адрес подставляется через nftables-карту. На Windows подстановку
делает маршрутизация WFP/netsh, а ответы — локальный резолвер.

Режимы работы:
  * `split` — DNS AntiZapret VPN: российские домены через российские
    резолверы (с переспросом тоже по российским), заблокированные — через
    зарубежные. NSDI спрашивается только для .ru/.su/.рф.
  * `full`  — DNS полного VPN: всё через зарубежные резолверы.
  * `proxy` — DNS прокси (kresd@3): только заблокированные домены.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

from . import dnswire
from .dnswire import (
    CLASS_IN, RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL, TYPE_A, TYPE_AAAA,
    TYPE_CNAME, TYPE_HTTPS, TYPE_NS, TYPE_SVCB, TYPE_SOA,
)
from .lists import (
    META_NO_AAAA, PDA_DOMAINS, PDA_STATIC_A, DomainLists, IpLists, match_domain,
)

# Резолверы из upstream kresd.conf.
RU_RESOLVERS = [
    "195.208.4.1",   # MSK-IX
    "195.208.5.1",   # MSK-IX
    "77.88.8.8",     # Яндекс
    "77.88.8.1",     # Яндекс
    "217.150.34.129",  # ТрансТелеКом
    "217.150.35.129",  # ТрансТелеКом
    "62.76.76.62",   # MSK-IX
    "62.76.62.76",   # MSK-IX
    "185.191.32.7",  # BI.ZONE
    "185.191.32.8",  # BI.ZONE
]

RU_RESOLVERS_FALLBACK = [
    "195.208.4.1", "195.208.5.1", "77.88.8.8", "77.88.8.1",
    "217.150.34.129", "217.150.35.129",
]

FOREIGN_RESOLVERS = [
    "1.1.1.1", "1.0.0.1", "9.9.9.10", "149.112.112.10",
    "76.76.2.0", "76.76.10.0", "64.6.64.6", "64.6.65.6",
]

# Альтернативные зоны (upstream alternative_zones) — уходят к своим NS.
ALTERNATIVE_ZONE_RESOLVERS = [
    "91.190.185.43", "94.247.43.254", "95.216.99.249", "185.226.181.19",
]

# Зоны .ru/.su/.рф — российские.
RU_ZONE_SUFFIXES = ("ru", "su", "xn--p1ai")

MIN_TTL = 300
MAX_TTL = 86400
DEFAULT_DNS_TTL = 300
DEFAULT_EXPIRE = 3600

FAKE_CIDR_DEFAULT = "198.18.0.0/15"
FAKE_CIDR_ALTERNATIVE = "10.30.0.0/15"
FAKE6_CIDR = "fd00:30::/64"


@dataclass
class ResolverConfig:
    """Настройки локального резолвера."""

    mode: str = "split"          # split | full | proxy
    listen: str = "127.0.0.1"
    port: int = 53
    fake_cidr: str = FAKE_CIDR_DEFAULT
    fake6_cidr: str = FAKE6_CIDR
    dns_ttl: int = DEFAULT_DNS_TTL
    expire: int = DEFAULT_EXPIRE
    timeout: float = 5.0
    ipv6_mode: str = "a"         # a | b | c — как в upstream /etc/knot-resolver/ipv6-mode
    enable_fake6: bool = False
    use_ru_resolvers: bool = True
    warp_dns: bool = False        # ANTIZAPRET_WARP_DNS=y — зарубежные ответы через WARP/Proton
    adblock: bool = False
    nsdi_ru_only: bool = True

    @property
    def fake_pool(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.fake_cidr)

    @property
    def fake6_pool(self) -> ipaddress.IPv6Network:
        return ipaddress.ip_network(self.fake6_cidr)


class FakeIpPool:
    """Пул поддельных адресов и карта real_ip -> fake_ip.

    Порт `proxy.py`: адрес выдаётся из пула, привязка хранится с временем
    последнего использования, неактивные записи истекают.
    """

    def __init__(self, cidr: str, expire: int = DEFAULT_EXPIRE):
        self._net = ipaddress.ip_network(cidr)
        self._pool: set[str] = {str(x) for x in self._net.hosts()}
        self._map: dict[tuple[str, bool], dict] = {}
        self._expire = expire
        self._lock = threading.Lock()

    def allocate(self, real_ip: str, warp: bool = False) -> str | None:
        with self._lock:
            key = (real_ip, warp)
            entry = self._map.get(key)
            if entry is not None:
                entry["used"] = time.time()
                return entry["fake_ip"]
            if not self._pool:
                return None
            fake_ip = self._pool.pop()
            self._map[key] = {"fake_ip": fake_ip, "used": time.time()}
            return fake_ip

    def release(self, real_ip: str, warp: bool = False) -> None:
        with self._lock:
            entry = self._map.pop((real_ip, warp), None)
            if entry:
                self._pool.add(entry["fake_ip"])

    def expire_old(self) -> list[tuple[str, bool]]:
        """Возвращает список истёкших (real_ip, warp) и освобождает адреса."""
        now = time.time()
        expired: list[tuple[str, bool]] = []
        with self._lock:
            for key, entry in list(self._map.items()):
                if now - entry["used"] > self._expire:
                    expired.append(key)
                    self._pool.add(entry["fake_ip"])
                    del self._map[key]
        return expired

    def mapping(self) -> dict[str, str]:
        """Текущая карта fake_ip -> real_ip (для маршрутизации на Windows)."""
        with self._lock:
            return {entry["fake_ip"]: key[0] for key, entry in self._map.items()}

    def __len__(self) -> int:
        with self._lock:
            return len(self._map)

    @property
    def available(self) -> int:
        with self._lock:
            return len(self._pool)


def _is_ru_zone(name: str) -> bool:
    lowered = name.lower().rstrip(".")
    parts = lowered.split(".")
    return len(parts) >= 2 and parts[-1] in RU_ZONE_SUFFIXES


def _is_alternative_zone(name: str) -> bool:
    """Зоны onion/эфирные и прочие альтернативные — upstream alternative_zones."""
    lowered = name.lower().rstrip(".")
    parts = set(lowered.split("."))
    alt = {"bbs", "chan", "cyb", "dyn", "epic", "geek", "gopher", "indy", "libre",
           "neo", "null", "o", "oss", "oz", "parody", "pirate", "opennic.glue",
           "bazar", "coin", "emc", "lib", "fur", "ku", "te", "ti", "uu", "ko", "rm"}
    return bool(parts & alt)


def _meta_no_aaaa(name: str) -> bool:
    lowered = name.lower().rstrip(".")
    for base in META_NO_AAAA:
        if lowered == base or lowered.endswith("." + base):
            return True
    return False


def _pda_static(name: str) -> bool:
    lowered = name.lower().rstrip(".")
    for base in PDA_DOMAINS:
        if lowered == base or lowered.endswith("." + base):
            return True
    return False


def _valid_chars_only(name: str) -> bool:
    """Проверка имени допустимыми символами (upstream valid_chars_only)."""
    if not name:
        return False
    for ch in name:
        if not (ch.isalnum() or ch in "-._"):
            return False
    return True


class UpstreamError(Exception):
    """Не удалось получить ответ от вышестоящего резолвера."""


class UpstreamResolver:
    """Отправляет запросы вышестоящим резолверам (UDP, с TCP-фолбэком)."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._lock = threading.Lock()

    def query(self, server: str, qname: str, qtype: int, msg_id: int) -> dnswire.Message:
        packet = dnswire.make_query(qname, qtype, msg_id=msg_id)
        response = self._query_udp(server, packet)
        if response is None or response.truncated:
            tcp = self._query_tcp(server, packet)
            if tcp is not None:
                return tcp
            if response is None:
                raise UpstreamError(f"нет ответа от {server}")
        return response

    def _query_udp(self, server: str, packet: bytes) -> dnswire.Message | None:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.sendto(packet, (server, 53))
                data, _ = sock.recvfrom(65535)
            except (socket.timeout, OSError):
                return None
        try:
            return dnswire.parse_message(data)
        except dnswire.DnsFormatError:
            return None

    def _query_tcp(self, server: str, packet: bytes) -> dnswire.Message | None:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((server, 53))
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                header = self._recv_exact(sock, 2)
                if not header:
                    return None
                (length,) = struct.unpack("!H", header)
                body = self._recv_exact(sock, length)
                if not body:
                    return None
            return dnswire.parse_message(body)
        except (socket.timeout, OSError, dnswire.DnsFormatError):
            return None

    @staticmethod
    def _recv_exact(sock: socket.socket, count: int) -> bytes:
        buf = bytearray()
        while len(buf) < count:
            chunk = sock.recv(count - len(buf))
            if not chunk:
                return bytes()
            buf.extend(chunk)
        return bytes(buf)


@dataclass
class ResolverStats:
    queries: int = 0
    blocked_hits: int = 0
    ru_hits: int = 0
    foreign_hits: int = 0
    fake_allocated: int = 0
    errors: int = 0
    adblock_hits: int = 0


class AntiZapretResolver:
    """Резолвер с fake-IP и политикой выбора上游-резолвера.

    Портирует логику upstream:
      * `kresd@1` (split) — российские домены через российские резолверы,
        заблокированные через зарубежные, NSDI только для .ru/.su/.рф;
      * `kresd@2` (full) — всё через зарубежные;
      * `kresd@3` (proxy) — только заблокированные через зарубежные.
    """

    def __init__(self, config: ResolverConfig,
                 domains: DomainLists | None = None,
                 ips: IpLists | None = None,
                 upstream: UpstreamResolver | None = None):
        self.config = config
        self.domains = domains or DomainLists()
        self.ips = ips or IpLists()
        self.upstream = upstream or UpstreamResolver(config.timeout)
        self.pool = FakeIpPool(config.fake_cidr, config.expire)
        self.stats = ResolverStats()
        self._lock = threading.Lock()
        self._msg_id = 0
        self._cache: dict[tuple[str, int], tuple[float, dnswire.Message]] = {}
        self._running = False
        self._thread: threading.Thread | None = None

    # --- выбор резолвера -------------------------------------------------

    def is_blocked(self, name: str) -> bool:
        """Домен входит в список AntiZapret (после exclude/remove)."""
        return match_domain(name, self.domains.blocked)

    def is_adblocked(self, name: str) -> bool:
        if not self.config.adblock:
            return False
        return match_domain(name, self.domains.adblock_blocked)

    def is_warp(self, name: str) -> bool:
        return match_domain(name, self.domains.warp)

    def upstream_for(self, name: str) -> tuple[list[str], str]:
        """Возвращает (список резолверов, режим).

        Режим: `ru` — российские резолверы, `foreign` — зарубежные,
        `alt` — альтернативные зоны.
        """
        if _is_alternative_zone(name):
            return list(ALTERNATIVE_ZONE_RESOLVERS), "alt"
        if self.config.mode == "full":
            return list(FOREIGN_RESOLVERS), "foreign"
        if self.config.mode == "proxy":
            # kresd@3 отвечает только на заблокированные домены.
            if self.is_blocked(name):
                return list(FOREIGN_RESOLVERS), "foreign"
            return list(RU_RESOLVERS), "ru"
        # split
        if _is_ru_zone(name):
            return list(RU_RESOLVERS), "ru"
        if self.is_blocked(name):
            return list(FOREIGN_RESOLVERS), "foreign"
        return list(RU_RESOLVERS), "ru"

    def _ru_chain(self, name: str) -> list[str]:
        """Цепочка российских резолверов: при ошибке переспрашиваем тоже российские.

        Портирует замечание из README: «при ошибке или пустом ответе
        российского резолвера переспрашивает тоже российские (Яндекс,
        MSK-IX, ТрансТелеКом), а не Cloudflare».
        """
        primary = RU_RESOLVERS[:2] if RU_RESOLVERS_FALLBACK else RU_RESOLVERS
        chain = list(primary)
        for resolver in RU_RESOLVERS_FALLBACK:
            if resolver not in chain:
                chain.append(resolver)
        for resolver in RU_RESOLVERS:
            if resolver not in chain:
                chain.append(resolver)
        return chain

    # --- обработка запроса -----------------------------------------------

    def _next_id(self) -> int:
        with self._lock:
            self._msg_id = (self._msg_id + 1) & 0xFFFF
            return self._msg_id or 1

    def resolve_query(self, request: bytes) -> bytes:
        """Главная точка входа: принимает запрос, возвращает ответ."""
        try:
            msg = dnswire.parse_message(request)
        except dnswire.DnsFormatError:
            return dnswire.make_servfail(request)
        if not msg.questions:
            return dnswire.make_servfail(request)
        qname = msg.qname
        qtype = msg.qtype
        self.stats.queries += 1

        if not _valid_chars_only(qname):
            return dnswire.make_response(request, rcode=dnswire.RCODE_REFUSED)

        # Adblock: ответ 0.0.0.0 (как upstream deny.rpz -> zero_a_answer).
        if self.is_adblocked(qname):
            self.stats.adblock_hits += 1
            return self._zero_a(request, qtype)

        # 4pda: статический A, AAAA пусто.
        if _pda_static(qname):
            if qtype == TYPE_A:
                answers = [self._a_record(qname, ip) for ip in PDA_STATIC_A]
                return dnswire.make_response(request, answers=answers)
            if qtype == TYPE_AAAA:
                return dnswire.make_nodata(request)

        # Meta/Instagram: AAAA всегда пусто.
        if qtype == TYPE_AAAA and _meta_no_aaaa(qname):
            return dnswire.make_nodata(request)

        # HTTPS/SVCB — NODATA (upstream match_query_type).
        if qtype in (TYPE_HTTPS, TYPE_SVCB):
            return dnswire.make_nodata(request)

        # IPv6: режим a — AAAA пусто (кроме российских зон).
        if qtype == TYPE_AAAA and self.config.ipv6_mode == "a":
            if not (self.config.nsdi_ru_only and _is_ru_zone(qname)):
                return dnswire.make_nodata(request)

        blocked = self.is_blocked(qname)
        if blocked:
            self.stats.blocked_hits += 1
        elif _is_ru_zone(qname):
            self.stats.ru_hits += 1
        else:
            self.stats.foreign_hits += 1

        key = (qname.lower(), qtype)
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        try:
            response = self._query_upstream(qname, qtype)
        except UpstreamError:
            self.stats.errors += 1
            return dnswire.make_servfail(request)

        if response is None:
            self.stats.errors += 1
            return dnswire.make_servfail(request)

        payload = self._build_response(request, response, qname, qtype, blocked)
        self._cache_put(key, payload)
        return payload

    def _query_upstream(self, qname: str, qtype: int) -> dnswire.Message:
        """Опрашивает резолверы по цепочке, возвращает первый удачный ответ."""
        resolvers, kind = self.upstream_for(qname)
        if kind == "ru":
            chain = self._ru_chain(qname)
        else:
            chain = resolvers
        last_error: Exception | None = None
        for resolver in chain:
            try:
                reply = self.upstream.query(resolver, qname, qtype, self._next_id())
            except UpstreamError as exc:
                last_error = exc
                continue
            if reply.rcode == RCODE_NXDOMAIN:
                return reply
            if reply.answers:
                return reply
            # Пустой ответ — пробуем следующий в цепочке.
            last_error = UpstreamError(f"пустой ответ от {resolver}")
        if last_error:
            raise last_error
        raise UpstreamError(f"нет ответов для {qname}")

    def _build_response(self, request: bytes, reply: dnswire.Message,
                        qname: str, qtype: int, blocked: bool) -> bytes:
        """Собирает ответ клиенту, подменяя A-адреса на fake-IP для заблокированных."""
        answers: list[dnswire.Record] = []
        for rec in reply.answers:
            if rec.rtype == TYPE_A and rec.address and blocked:
                fake = self.pool.allocate(rec.address, warp=self.is_warp(qname))
                if fake is None:
                    return dnswire.make_servfail(request)
                self.stats.fake_allocated += 1
                answers.append(self._a_record(rec.name or qname, fake, rec.ttl))
                continue
            if rec.rtype == TYPE_AAAA:
                if self.config.ipv6_mode == "a" and not (
                        self.config.nsdi_ru_only and _is_ru_zone(qname)):
                    continue
                answers.append(rec)
                continue
            answers.append(rec)
        # CNAME-цепочка сохраняется, но её A-записи тоже подменяются.
        if not answers and reply.rcode == RCODE_NXDOMAIN:
            return dnswire.make_response(request, rcode=RCODE_NXDOMAIN)
        return dnswire.make_response(request, answers=answers)

    @staticmethod
    def _a_record(name: str, address: str, ttl: int = DEFAULT_DNS_TTL) -> dnswire.Record:
        rec = dnswire.Record(name=name, rtype=TYPE_A, rclass=CLASS_IN, ttl=ttl,
                             rdata=ipaddress.IPv4Address(address).packed)
        rec.address = address
        return rec

    @staticmethod
    def _zero_a(request: bytes, qtype: int) -> bytes:
        """Ответ adblock: 0.0.0.0 для A, пусто для прочих."""
        if qtype != TYPE_A:
            return dnswire.make_nodata(request)
        rec = dnswire.Record(name=".", rtype=TYPE_A, rclass=CLASS_IN, ttl=MAX_TTL,
                             rdata=ipaddress.IPv4Address("0.0.0.0").packed)
        rec.address = "0.0.0.0"
        return dnswire.make_response(request, answers=[rec])

    # --- кэш -------------------------------------------------------------

    def _cache_get(self, key: tuple[str, int]) -> bytes | None:
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            expires, payload = entry
            if expires < time.time():
                self._cache.pop(key, None)
                return None
            return payload

    def _cache_put(self, key: tuple[str, int], payload: bytes) -> None:
        with self._lock:
            if len(self._cache) > 4096:
                now = time.time()
                for k in [k for k, (exp, _) in self._cache.items() if exp < now]:
                    self._cache.pop(k, None)
            self._cache[key] = (time.time() + MIN_TTL, payload)

    # --- фоновые задачи --------------------------------------------------

    def _expiry_worker(self) -> None:
        while self._running:
            time.sleep(30)
            try:
                expired = self.pool.expire_old()
                if expired:
                    print(f"Expired: {len(expired)} fake IPs")
            except Exception as exc:  # noqa: BLE001 - фоновый поток не должен падать
                print(f"Error: expire fake IP mapping failed: {exc}")

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._expiry_worker, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)


class DnsServer:
    """UDP/TCP-сервер поверх резолвера."""

    def __init__(self, resolver: AntiZapretResolver, listen: str, port: int):
        self.resolver = resolver
        self.listen = listen
        self.port = port
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        family = socket.AF_INET6 if ":" in self.listen else socket.AF_INET
        self._udp = socket.socket(family, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((self.listen, self.port))
        self._tcp = socket.socket(family, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind((self.listen, self.port))
        self._tcp.listen(16)
        threading.Thread(target=self._udp_loop, daemon=True).start()
        threading.Thread(target=self._tcp_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._udp, self._tcp):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    def _udp_loop(self) -> None:
        assert self._udp is not None
        self._udp.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data, addr = self._udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                reply = self.resolver.resolve_query(data)
                self._udp.sendto(reply, addr)
            except Exception as exc:  # noqa: BLE001
                print(f"Error: UDP query failed: {exc}")

    def _tcp_loop(self) -> None:
        assert self._tcp is not None
        self._tcp.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, _ = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_tcp, args=(conn,), daemon=True).start()

    def _handle_tcp(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(self.resolver.config.timeout)
            header = conn.recv(2)
            if len(header) < 2:
                return
            (length,) = struct.unpack("!H", header)
            data = b""
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    return
                data += chunk
            reply = self.resolver.resolve_query(data)
            conn.sendall(struct.pack("!H", len(reply)) + reply)
        except Exception as exc:  # noqa: BLE001
            print(f"Error: TCP query failed: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
