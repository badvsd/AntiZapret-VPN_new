"""Тесты Windows-порта AntiZapret.

Запуск: `python -m unittest discover -s windows/tests -v`
"""

from __future__ import annotations

import ipaddress
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from azwin import dnswire, lists, profiles, resolver  # noqa: E402


class _BlockCryptography:
    """Имитирует отсутствие пакета `cryptography` (find_spec, а не find_module)."""

    def find_spec(self, name, path=None, target=None):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return None


class TestDnsWire(unittest.TestCase):
    """Кодек DNS: кодирование/разбор пакета."""

    def test_query_roundtrip(self):
        packet = dnswire.make_query("example.com", dnswire.TYPE_A, msg_id=0x4242)
        msg = dnswire.parse_message(packet)
        self.assertEqual(msg.id, 0x4242)
        self.assertEqual(msg.qname, "example.com")
        self.assertEqual(msg.qtype, dnswire.TYPE_A)
        self.assertFalse(msg.is_response)

    def test_response_with_answer(self):
        rec = dnswire.Record(name="example.com", rtype=dnswire.TYPE_A,
                             rclass=dnswire.CLASS_IN, ttl=300,
                             rdata=ipaddress.IPv4Address("93.184.216.34").packed)
        rec.address = "93.184.216.34"
        request = dnswire.make_query("example.com", dnswire.TYPE_A, msg_id=7)
        response = dnswire.make_response(request, answers=[rec])
        msg = dnswire.parse_message(response)
        self.assertTrue(msg.is_response)
        self.assertEqual(msg.id, 7)
        self.assertEqual(msg.qname, "example.com")
        self.assertEqual(len(msg.answers), 1)
        self.assertEqual(msg.answers[0].address, "93.184.216.34")
        self.assertEqual(msg.answers[0].ttl, 300)

    def test_nodata_has_soa(self):
        request = dnswire.make_query("example.com", dnswire.TYPE_AAAA, msg_id=9)
        response = dnswire.make_nodata(request)
        msg = dnswire.parse_message(response)
        self.assertEqual(msg.rcode, dnswire.RCODE_NOERROR)
        self.assertEqual(msg.answers, [])
        self.assertEqual(len(msg.authority), 1)
        self.assertEqual(msg.authority[0].rtype, dnswire.TYPE_SOA)

    def test_servfail(self):
        request = dnswire.make_query("example.com", dnswire.TYPE_A, msg_id=11)
        msg = dnswire.parse_message(dnswire.make_servfail(request))
        self.assertEqual(msg.rcode, dnswire.RCODE_SERVFAIL)

    def test_cname_parsing(self):
        rdata = dnswire.encode_name("target.example.org")
        rec = dnswire.Record(name="example.com", rtype=dnswire.TYPE_CNAME,
                             rclass=dnswire.CLASS_IN, ttl=60, rdata=rdata)
        rec.target = "target.example.org"
        request = dnswire.make_query("example.com", dnswire.TYPE_A, msg_id=13)
        msg = dnswire.parse_message(dnswire.make_response(request, answers=[rec]))
        self.assertEqual(msg.answers[0].target, "target.example.org")

    def test_ipv6_formatting(self):
        raw = ipaddress.IPv6Address("fd00:30::1").packed
        rec = dnswire.Record(name="x", rtype=dnswire.TYPE_AAAA,
                             rclass=dnswire.CLASS_IN, ttl=1, rdata=raw)
        msg = dnswire.parse_message(dnswire.make_response(
            dnswire.make_query("x", dnswire.TYPE_AAAA), answers=[rec]))
        self.assertEqual(msg.answers[0].address, "fd00:30::1")

    def test_malformed_packet(self):
        with self.assertRaises(dnswire.DnsFormatError):
            dnswire.parse_message(b"\x00\x01")


class TestLists(unittest.TestCase):
    """Списки доменов и IP: слияние, исключения, remove."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.download = os.path.join(self.tmp.name, "download")
        self.config = os.path.join(self.tmp.name, "config")
        os.makedirs(self.download)
        os.makedirs(self.config)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, directory, name, content):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as f:
            f.write(content)

    def test_include_minus_exclude(self):
        self._write(self.download, "include-hosts.txt", "blocked.com\nok.com\n")
        self._write(self.config, "exclude-hosts.txt", "ok.com\n")
        result = lists.build_domain_lists(self.download, self.config)
        self.assertIn("blocked.com", result.blocked)
        self.assertNotIn("ok.com", result.blocked)

    def test_remove_wins_over_everything(self):
        self._write(self.download, "include-hosts.txt", "a.com\nb.com\n")
        self._write(self.config, "exclude-hosts.txt", "b.com\n")
        self._write(self.config, "remove-hosts.txt", "b.com\n")
        result = lists.build_domain_lists(self.download, self.config)
        self.assertNotIn("b.com", result.blocked)
        self.assertNotIn("b.com", result.excluded)

    def test_comments_and_blank_lines_ignored(self):
        self._write(self.config, "include-hosts.txt",
                    "# комментарий\n\n; тоже комментарий\nreal.com\n")
        result = lists.build_domain_lists(self.download, self.config)
        self.assertEqual(result.blocked, {"real.com"})

    def test_subdomain_matching(self):
        self.assertTrue(lists.match_domain("www.youtube.com", {"youtube.com"}))
        self.assertTrue(lists.match_domain("youtube.com", {"youtube.com"}))
        self.assertFalse(lists.match_domain("notyoutube.com", {"youtube.com"}))

    def test_wildcard_matching(self):
        self.assertTrue(lists.match_domain("a.example.com", {"*.example.com"}))
        self.assertFalse(lists.match_domain("example.org", {"*.example.com"}))

    def test_ip_include_exclude(self):
        self._write(self.download, "include-ips.txt", "8.8.8.8/32\n1.1.1.0/24\n")
        self._write(self.config, "exclude-ips.txt", "1.1.1.128/25\n")
        result = lists.build_ip_lists(self.download, self.config)
        cidr_text = {str(n) for n in result.route}
        self.assertIn("8.8.8.8/32", cidr_text)
        self.assertNotIn("1.1.1.128/25", cidr_text)

    def test_invalid_ips_skipped(self):
        self._write(self.download, "include-ips.txt", "не ip\n999.999.0.0/24\n8.8.4.4/32\n")
        result = lists.build_ip_lists(self.download, self.config)
        cidr_text = {str(n) for n in result.route}
        self.assertEqual(cidr_text, {"8.8.4.4/32"})

    def test_ru_zone_detection(self):
        self.assertTrue(lists.is_russian_zone("yandex.ru"))
        self.assertTrue(lists.is_russian_zone("mail.ru"))
        self.assertTrue(lists.is_russian_zone("xn--p1ai"))
        self.assertFalse(lists.is_russian_zone("google.com"))

    def test_subtract_nets(self):
        """Вычитание /16 из /8 даёт 8 сетей — как в upstream ip6list.py."""
        nets = [ipaddress.ip_network("10.0.0.0/8")]
        ex = [ipaddress.ip_network("10.1.0.0/16")]
        result = lists.subtract(nets, ex)
        self.assertEqual(len(result), 8)
        self.assertIn(ipaddress.ip_network("10.0.0.0/16"), result)
        self.assertNotIn(ipaddress.ip_network("10.1.0.0/16"), result)
        # Покрытие сохраняется: 10.1.0.0/16 вырезан, остальное на месте.
        self.assertIn(ipaddress.ip_network("10.2.0.0/15"), result)

    def test_subtract_removes_fully_covered_net(self):
        nets = [ipaddress.ip_network("10.1.0.0/16")]
        ex = [ipaddress.ip_network("10.0.0.0/8")]
        self.assertEqual(lists.subtract(nets, ex), [])


class TestFakeIpPool(unittest.TestCase):
    """Пул поддельных адресов."""

    def test_allocate_is_stable(self):
        pool = resolver.FakeIpPool("198.18.0.0/15")
        first = pool.allocate("1.2.3.4")
        second = pool.allocate("1.2.3.4")
        self.assertIsNotNone(first)
        self.assertEqual(first, second)

    def test_different_ips_get_different_fakes(self):
        pool = resolver.FakeIpPool("198.18.0.0/15")
        a = pool.allocate("1.2.3.4")
        b = pool.allocate("5.6.7.8")
        self.assertNotEqual(a, b)

    def test_fake_is_inside_pool(self):
        pool = resolver.FakeIpPool("198.18.0.0/15")
        fake = pool.allocate("1.2.3.4")
        self.assertIn(ipaddress.ip_address(fake), ipaddress.ip_network("198.18.0.0/15"))

    def test_release_returns_to_pool(self):
        pool = resolver.FakeIpPool("198.18.0.0/15")
        before = pool.available
        fake = pool.allocate("1.2.3.4")
        pool.release("1.2.3.4")
        self.assertEqual(pool.available, before)
        self.assertIsNotNone(fake)

    def test_mapping_direction(self):
        pool = resolver.FakeIpPool("198.18.0.0/15")
        fake = pool.allocate("1.2.3.4")
        self.assertEqual(pool.mapping(), {fake: "1.2.3.4"})

    def test_expiry(self):
        """Запись истекает по истечении времени простоя."""
        pool = resolver.FakeIpPool("198.18.0.0/15", expire=0)
        pool.allocate("1.2.3.4")
        expired = pool.expire_old()
        self.assertEqual(len(expired), 1)
        self.assertEqual(len(pool), 0)

    def test_expiry_keeps_fresh_entries(self):
        """Свежая запись не истекает, пока не прошло достаточно времени."""
        pool = resolver.FakeIpPool("198.18.0.0/15", expire=3600)
        pool.allocate("1.2.3.4")
        self.assertEqual(pool.expire_old(), [])
        self.assertEqual(len(pool), 1)


class TestResolverPolicy(unittest.TestCase):
    """Политика выбора резолвера и обработки запросов."""

    def _resolver(self, mode="split", **kwargs):
        config = resolver.ResolverConfig(mode=mode, **kwargs)
        domains = lists.DomainLists()
        domains.blocked = {"blocked.com"}
        domains.finalize()
        return resolver.AntiZapretResolver(config, domains=domains)

    def test_ru_domain_uses_ru_resolvers(self):
        res = self._resolver()
        servers, kind = res.upstream_for("mail.ru")
        self.assertEqual(kind, "ru")
        self.assertNotIn("1.1.1.1", servers)

    def test_blocked_domain_uses_foreign_resolvers(self):
        res = self._resolver()
        servers, kind = res.upstream_for("blocked.com")
        self.assertEqual(kind, "foreign")
        self.assertIn("1.1.1.1", servers)

    def test_full_mode_uses_foreign_for_everything(self):
        res = self._resolver(mode="full")
        servers, kind = res.upstream_for("mail.ru")
        self.assertEqual(kind, "foreign")

    def test_proxy_mode_ru_domains_stay_ru(self):
        res = self._resolver(mode="proxy")
        servers, kind = res.upstream_for("mail.ru")
        self.assertEqual(kind, "ru")

    def test_ru_chain_has_no_foreign_resolvers(self):
        """При ошибке российского резолвера переспрашиваем тоже российские."""
        res = self._resolver()
        chain = res._ru_chain("mail.ru")
        self.assertTrue(chain)
        for foreign in ("1.1.1.1", "1.0.0.1", "9.9.9.10", "8.8.8.8"):
            self.assertNotIn(foreign, chain)

    def test_ru_chain_contains_yandex_mskix_tt(self):
        res = self._resolver()
        chain = res._ru_chain("mail.ru")
        self.assertIn("77.88.8.8", chain)        # Яндекс
        self.assertIn("195.208.4.1", chain)      # MSK-IX
        self.assertIn("217.150.34.129", chain)   # ТрансТелеКом

    def test_is_blocked_respects_exclude(self):
        config = resolver.ResolverConfig()
        domains = lists.DomainLists()
        domains.blocked = {"a.com"}
        domains.excluded = {"a.com"}
        domains.finalize()
        res = resolver.AntiZapretResolver(config, domains=domains)
        self.assertFalse(res.is_blocked("a.com"))

    def test_adblock_returns_zero(self):
        config = resolver.ResolverConfig(adblock=True)
        domains = lists.DomainLists()
        domains.adblock_blocked = {"ads.example"}
        domains.finalize()
        res = resolver.AntiZapretResolver(config, domains=domains)
        request = dnswire.make_query("ads.example", dnswire.TYPE_A, msg_id=5)
        reply = dnswire.parse_message(res.resolve_query(request))
        self.assertEqual(reply.answers[0].address, "0.0.0.0")

    def test_meta_no_aaaa(self):
        res = self._resolver()
        request = dnswire.make_query("instagram.com", dnswire.TYPE_AAAA, msg_id=6)
        reply = dnswire.parse_message(res.resolve_query(request))
        self.assertEqual(reply.answers, [])
        self.assertEqual(reply.rcode, dnswire.RCODE_NOERROR)

    def test_https_type_nodata(self):
        res = self._resolver()
        request = dnswire.make_query("example.com", dnswire.TYPE_HTTPS, msg_id=8)
        reply = dnswire.parse_message(res.resolve_query(request))
        self.assertEqual(reply.answers, [])

    def test_invalid_chars_refused(self):
        """Имя с недопустимым символом отклоняется (upstream valid_chars_only).

        Подчёркивание upstream разрешает (шаблон `[%w%-%._]`), поэтому
        проверяем именно запрещённый символ.
        """
        res = self._resolver()
        self.assertTrue(resolver._valid_chars_only("good-name.example"))
        self.assertFalse(resolver._valid_chars_only("bad name.example"))
        self.assertFalse(resolver._valid_chars_only("bad/name.example"))

        request = dnswire.make_query("bad_name.com", dnswire.TYPE_A, msg_id=10)
        # Подчёркивание допустимо -> запрос уходит дальше, а не отклоняется.
        reply = dnswire.parse_message(res.resolve_query(request))
        self.assertNotEqual(reply.rcode, dnswire.RCODE_REFUSED)

    def test_ipv6_mode_a_returns_nodata_for_aaaa(self):
        res = self._resolver(ipv6_mode="a")
        # Не блокированный, не российский домен — AAAA пусто.
        request = dnswire.make_query("example.com", dnswire.TYPE_AAAA, msg_id=12)
        reply = dnswire.parse_message(res.resolve_query(request))
        self.assertEqual(reply.answers, [])


class TestProfiles(unittest.TestCase):
    """Генерация клиентских профилей."""

    def test_filename_length_limit(self):
        name = "очень-длинное-имя-клиента-которое-не-влезет"
        safe = profiles.sanitize_filename(name)
        self.assertLessEqual(len(safe), profiles.MAX_FILENAME_LEN)

    def test_filename_has_no_brackets(self):
        safe = profiles.sanitize_filename("клиент(1)")
        self.assertNotIn("(", safe)
        self.assertNotIn(")", safe)

    def test_openvpn_contains_block_ipv6(self):
        profile = profiles.render_openvpn("test", "1.2.3.4", "CA", "CERT", "KEY")
        self.assertIn("block-ipv6", profile.content)
        self.assertTrue(profile.filename.endswith(".ovpn"))

    def test_openvpn_has_udp_and_tcp_ports(self):
        """UDP-профиль AntiZapret: 50443 + резервные 504/443 (как upstream)."""
        profile = profiles.render_openvpn("test", "1.2.3.4", "CA", "CERT", "KEY",
                                          protocol="udp")
        self.assertIn("remote 1.2.3.4 50443 udp4", profile.content)
        self.assertIn("remote 1.2.3.4 504 udp4", profile.content)
        self.assertIn("remote 1.2.3.4 443 udp4", profile.content)
        self.assertNotIn("tcp4", profile.content)

    def test_openvpn_both_protocols(self):
        """Профиль `both`: и UDP, и TCP — как upstream antizapret.conf."""
        profile = profiles.render_openvpn("test", "1.2.3.4", "CA", "CERT", "KEY",
                                          protocol="both")
        self.assertIn("remote 1.2.3.4 50443 udp4", profile.content)
        self.assertIn("remote 1.2.3.4 50443 tcp4", profile.content)

    def test_openvpn_vpn_layer_fallback_ports(self):
        """У полного VPN свои резервные порты: 508 и 80."""
        profile = profiles.render_openvpn("test", "1.2.3.4", "CA", "CERT", "KEY",
                                          layer="vpn", protocol="udp")
        self.assertIn("remote 1.2.3.4 50080 udp4", profile.content)
        self.assertIn("remote 1.2.3.4 508 udp4", profile.content)
        self.assertIn("remote 1.3.4.5 80 udp4".replace("1.3.4.5", "1.2.3.4"),
                      profile.content)

    def test_openvpn_vpn_layer_uses_full_port(self):
        profile = profiles.render_openvpn("test", "1.2.3.4", "CA", "CERT", "KEY",
                                          layer="vpn")
        self.assertIn("remote 1.2.3.4 50080 udp4", profile.content)

    def test_wireguard_allowed_ips_include_fake_pool(self):
        server = profiles.ServerKeys(public_key="PUB", server_host="1.2.3.4")
        profile = profiles.render_wireguard("test", server, "PRIV", "PUB", "PSK",
                                            "10.29.8.2", route_ips=["8.8.8.8/32"])
        self.assertIn("198.18.0.0/15", profile.content)
        self.assertIn("8.8.8.8/32", profile.content)
        self.assertIn("10.29.8.0/24", profile.content)

    def test_wireguard_vpn_layer_is_full_tunnel(self):
        server = profiles.ServerKeys(public_key="PUB", server_host="1.2.3.4")
        profile = profiles.render_wireguard("test", server, "PRIV", "PUB", "PSK",
                                            "10.28.8.2", layer="vpn")
        self.assertIn("AllowedIPs = 0.0.0.0/0", profile.content)
        self.assertIn("DNS = 1.1.1.1, 1.0.0.1", profile.content)

    def test_awg2_has_obfuscation_params(self):
        server = profiles.ServerKeys(public_key="PUB", server_host="1.2.3.4")
        profile = profiles.render_awg2("test", server, "PRIV", "PUB", "PSK",
                                       "10.29.9.2")
        for param in ("Jc = ", "Jmin = ", "Jmax = ", "S1 = ", "S4 = ", "H1 = "):
            self.assertIn(param, profile.content)
        self.assertTrue(profile.filename.endswith("-am2.conf"))

    def test_awg3_has_header_protection_key(self):
        server = profiles.ServerKeys(public_key="PUB", server_host="1.2.3.4")
        profile = profiles.render_awg3("test", server, "PRIV", "PUB", "PSK",
                                       "10.9.0.2", header_protection_key="KEY123")
        self.assertIn("HeaderProtectionKey = KEY123", profile.content)
        self.assertTrue(profile.filename.endswith("-awg3.conf"))

    def test_key_generation_is_valid_base64_32_bytes(self):
        import base64

        private, public = profiles.generate_wg_keys()
        self.assertEqual(len(base64.b64decode(private)), 32)
        self.assertEqual(len(base64.b64decode(public)), 32)
        self.assertNotEqual(private, public)

    def test_x25519_public_key_matches_private(self):
        """Публичный ключ должен выводиться из приватного (RFC 7748)."""
        import base64

        private, public = profiles.generate_wg_keys()
        priv_bytes = base64.b64decode(private)
        derived = profiles._x25519_scalar_mult(
            priv_bytes, profiles._X25519_BASEPOINT)
        self.assertEqual(base64.b64encode(derived).decode("ascii"), public)

    def test_x25519_rfc7748_vector(self):
        """Контрольный вектор RFC 7748 §6.1 для чистой реализации X25519."""
        k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        expected = bytes.fromhex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        self.assertEqual(profiles._x25519_scalar_mult(k, u), expected)

    def test_key_generation_without_cryptography(self):
        """Резервный путь без `cryptography` тоже должен работать.

        На машине без установленного `cryptography` (Codespace, минимальный
        Python) генерация ключей обязана оставаться рабочей.
        """
        import base64
        import importlib.abc

        blocker = _BlockCryptography()
        sys.meta_path.insert(0, blocker)
        try:
            private, public = profiles.generate_wg_keys()
        finally:
            sys.meta_path.remove(blocker)
        self.assertEqual(len(base64.b64decode(private)), 32)
        self.assertEqual(len(base64.b64decode(public)), 32)
        derived = profiles._x25519_scalar_mult(
            base64.b64decode(private), profiles._X25519_BASEPOINT)
        self.assertEqual(base64.b64encode(derived).decode("ascii"), public)

    def test_next_client_ip_skips_used(self):
        self.assertEqual(profiles.next_client_ip({"10.29.8.2"}, "10.29.8.2"), "10.29.8.3")

    def test_ipv6_from_client_ip(self):
        """IPv6-подсети клиентов: WG/AWG1.5 — fd29:8, AWG2 — fd29:9, AWG3 — fd29:7."""
        self.assertEqual(profiles.ipv6_from_client_ip("10.29.8.2", "wg"), "fd29:8::2")
        self.assertEqual(profiles.ipv6_from_client_ip("10.29.9.2", "awg2"), "fd29:9::2")
        self.assertEqual(profiles.ipv6_from_client_ip("10.9.0.2", "awg3"), "fd29:7::2")
        self.assertEqual(profiles.ipv6_from_client_ip_vpn("10.29.9.2", "awg2"),
                         "fd28:9::2")

    def test_validate_profile_detects_missing_sections(self):
        problems = profiles.validate_profile("[Interface]\nPrivateKey = \n")
        self.assertTrue(any("Peer" in p for p in problems))


class TestProtocolFamilies(unittest.TestCase):
    """Семейства протоколов: подсети, порты, общие ключи."""

    def test_awg15_shares_key_group_with_wireguard(self):
        """AWG 1.5 и WireGuard — один серверный интерфейс: общий ключ."""
        wg = next(f for f in profiles.FAMILIES
                  if f.key == "wireguard" and f.layer == "antizapret")
        awg = next(f for f in profiles.FAMILIES
                   if f.key == "awg15" and f.layer == "antizapret")
        self.assertEqual(wg.key_group, awg.key_group)
        self.assertEqual(wg.base_ipv4, awg.base_ipv4)
        self.assertNotEqual(wg.port, awg.port)

    def test_awg2_and_awg3_have_own_subnets(self):
        awg2 = next(f for f in profiles.FAMILIES if f.key == "awg2")
        awg3 = next(f for f in profiles.FAMILIES if f.key == "awg3")
        self.assertNotEqual(awg2.key_group, awg3.key_group)
        self.assertNotEqual(awg2.base_ipv4, awg3.base_ipv4)
        self.assertNotEqual(awg2.base_ipv6, awg3.base_ipv6)

    def test_awg3_uses_its_own_subnets(self):
        """AWG 3 — 10.9.0.0/24 (антизапрет) и 10.9.1.0/24 (полный VPN)."""
        antizapret = next(f for f in profiles.FAMILIES
                          if f.key == "awg3" and f.layer == "antizapret")
        vpn = next(f for f in profiles.FAMILIES if f.key == "awg3" and f.layer == "vpn")
        self.assertTrue(antizapret.base_ipv4.startswith("10.9.0."))
        self.assertTrue(vpn.base_ipv4.startswith("10.9.1."))
        self.assertEqual(profiles.LAYER_SUBNET[("awg3", "antizapret")],
                         "10.9.0.0/24")
        self.assertEqual(profiles.LAYER_SUBNET[("awg3", "vpn")], "10.9.1.0/24")

    def test_family_ports_match_upstream(self):
        ports = {(f.key, f.layer): f.port for f in profiles.FAMILIES}
        self.assertEqual(ports[("wireguard", "antizapret")], 51443)
        self.assertEqual(ports[("wireguard", "vpn")], 51080)
        self.assertEqual(ports[("awg15", "antizapret")], 52443)
        self.assertEqual(ports[("awg15", "vpn")], 52080)
        self.assertEqual(ports[("awg2", "antizapret")], 53443)
        self.assertEqual(ports[("awg2", "vpn")], 53080)
        self.assertEqual(ports[("awg3", "antizapret")], 51821)

    def test_family_dns_addresses(self):
        dns = {(f.key, f.layer): f.dns for f in profiles.FAMILIES}
        self.assertEqual(dns[("wireguard", "antizapret")], "10.29.8.1")
        self.assertEqual(dns[("awg2", "antizapret")], "10.29.9.1")
        self.assertEqual(dns[("awg3", "antizapret")], "10.9.0.1")
        self.assertEqual(dns[("wireguard", "vpn")], "1.1.1.1, 1.0.0.1")

    def test_awg3_profile_uses_awg3_subnet(self):
        server = profiles.ServerKeys(public_key="PUB", server_host="1.2.3.4")
        profile = profiles.render_awg3("test", server, "PRIV", "PUB", "PSK",
                                       "10.9.0.2", subnet="10.9.0.0/24")
        self.assertIn("10.9.0.0/24", profile.content)
        self.assertNotIn("10.29.9.0/24", profile.content)

    def test_layer_subnet_covers_all_families(self):
        for family in profiles.FAMILIES:
            self.assertIn((family.key, family.layer), profiles.LAYER_SUBNET)


if __name__ == "__main__":
    unittest.main()
