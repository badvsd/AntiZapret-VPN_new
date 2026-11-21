"""Минимальный DNS-кодек (RFC 1035) без внешних зависимостей.

Локальный резолвер AntiZapret для Windows 11 должен и сам отдавать ответы
клиенту, и разбирать ответы вышестоящих серверов. Тянуть dnspython/dnslib
нельзя: на Windows их установка — лишний шаг для пользователя. Поэтому
кодек написан на голой стандартной библиотеке.

Поддерживаются типы, нужные для политики AntiZapret: A, AAAA, CNAME, NS,
SOA, PTR, MX, TXT, SVCB, HTTPS. Неизвестные типы пробрасываются как
необработанные RDATA, чтобы ответ можно было переслать клиенту без потерь.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SVCB = 64
TYPE_HTTPS = 65

CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_RA = 0x0080

MAX_PACKET = 65535
_LABEL_MAX = 63
_NAME_MAX = 255


class DnsFormatError(ValueError):
    """Пакет не является корректным DNS-сообщением."""


@dataclass
class Question:
    name: str
    qtype: int
    qclass: int = CLASS_IN


@dataclass
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    # Разобранные представления для часто используемых типов.
    address: str | None = None
    target: str | None = None
    soa: tuple[str, str, int, int, int, int] | None = None
    ttl_seconds: int | None = None

    def __repr__(self) -> str:  # pragma: no cover - только для отладки
        return f"<Record {self.name} {self.rtype} ttl={self.ttl}>"


@dataclass
class Message:
    id: int = 0
    flags: int = 0
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_QR)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def truncated(self) -> bool:
        return bool(self.flags & FLAG_TC)

    @property
    def qname(self) -> str:
        return self.questions[0].name if self.questions else ""

    @property
    def qtype(self) -> int:
        return self.questions[0].qtype if self.questions else 0


def encode_name(name: str) -> bytes:
    """Кодирует доменное имя в формате DNS (без сжатия)."""
    out = bytearray()
    trimmed = name.rstrip(".")
    if trimmed:
        for label in trimmed.split("."):
            raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii", "ignore")
            if not raw:
                raise DnsFormatError(f"пустая метка в имени {name!r}")
            if len(raw) > _LABEL_MAX:
                raise DnsFormatError(f"метка длиннее {_LABEL_MAX} байт в имени {name!r}")
            out.append(len(raw))
            out.extend(raw)
    out.append(0)
    if len(out) > _NAME_MAX + 1:
        raise DnsFormatError(f"имя длиннее {_NAME_MAX} байт: {name!r}")
    return bytes(out)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Разбирает имя, начиная с offset. Возвращает (имя, новый offset)."""
    labels: list[bytes] = []
    pos = offset
    end = None
    hops = 0
    while True:
        if pos >= len(data):
            raise DnsFormatError("имя выходит за пределы пакета")
        length = data[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DnsFormatError("обрезанный указатель сжатия")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if end is None:
                end = pos + 2
            hops += 1
            if hops > 32:
                raise DnsFormatError("цикл указателей сжатия")
            if pointer >= len(data):
                raise DnsFormatError("указатель сжатия за пределами пакета")
            _, pos = decode_name(data, pointer)
            return (".".join(l.decode("ascii", "ignore") for l in labels), end)
        if length & 0xC0:
            raise DnsFormatError("недопустимая длина метки")
        pos += 1
        if length == 0:
            if end is None:
                end = pos
            break
        if pos + length > len(data):
            raise DnsFormatError("метка выходит за пределы пакета")
        labels.append(data[pos:pos + length])
        pos += length
    name = ".".join(l.decode("ascii", "ignore") for l in labels)
    return name, end


def _decode_rdata(rtype: int, rdata: bytes) -> dict:
    """Разбирает RDATA для известных типов. Остальные отдаются как есть."""
    out: dict = {}
    if rtype == TYPE_A and len(rdata) == 4:
        out["address"] = ".".join(str(b) for b in rdata)
    elif rtype == TYPE_AAAA and len(rdata) == 16:
        out["address"] = _format_ipv6(rdata)
    elif rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        try:
            target, _ = decode_name(rdata, 0)
            out["target"] = target
        except DnsFormatError:
            pass
    elif rtype == TYPE_SOA and len(rdata) >= 22:
        try:
            mname, pos = decode_name(rdata, 0)
            rname, pos = decode_name(rdata, pos)
            numbers = struct.unpack("!IIIII", rdata[pos:pos + 20])
            out["soa"] = (mname, rname, *numbers)
        except (DnsFormatError, struct.error):
            pass
    elif rtype == TYPE_TXT:
        texts: list[str] = []
        pos = 0
        while pos < len(rdata):
            size = rdata[pos]
            pos += 1
            texts.append(rdata[pos:pos + size].decode("utf-8", "replace"))
            pos += size
        out["txt"] = texts
    return out


def _format_ipv6(raw: bytes) -> str:
    """Форматирует 16 байт как IPv6-адрес в сжатом виде."""
    import ipaddress

    return ipaddress.IPv6Address(raw).compressed


def parse_message(data: bytes) -> Message:
    """Разбирает DNS-пакет."""
    if len(data) < 12:
        raise DnsFormatError("пакет короче заголовка")
    msg_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    msg = Message(id=msg_id, flags=flags)
    pos = 12
    for _ in range(qd):
        name, pos = decode_name(data, pos)
        if pos + 4 > len(data):
            raise DnsFormatError("обрезанный вопрос")
        qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        msg.questions.append(Question(name=name, qtype=qtype, qclass=qclass))
    for section, count in ((msg.answers, an), (msg.authority, ns), (msg.additional, ar)):
        for _ in range(count):
            if pos + 10 > len(data):
                raise DnsFormatError("обрезанная ресурсная запись")
            name, pos = decode_name(data, pos)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            if pos + rdlen > len(data):
                raise DnsFormatError("обрезанные RDATA")
            rdata = data[pos:pos + rdlen]
            pos += rdlen
            rec = Record(name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata)
            for key, value in _decode_rdata(rtype, rdata).items():
                setattr(rec, key, value)
            section.append(rec)
    return msg


def encode_record(rec: Record) -> bytes:
    """Кодирует ресурсную запись."""
    out = bytearray()
    out.extend(encode_name(rec.name))
    out.extend(struct.pack("!HHIH", rec.rtype, rec.rclass, rec.ttl, len(rec.rdata)))
    out.extend(rec.rdata)
    return bytes(out)


def encode_message(msg: Message) -> bytes:
    """Кодирует DNS-пакет."""
    out = bytearray()
    out.extend(struct.pack("!HHHHHH", msg.id, msg.flags, len(msg.questions),
                           len(msg.answers), len(msg.authority), len(msg.additional)))
    for q in msg.questions:
        out.extend(encode_name(q.name))
        out.extend(struct.pack("!HH", q.qtype, q.qclass))
    for section in (msg.answers, msg.authority, msg.additional):
        for rec in section:
            out.extend(encode_record(rec))
    return bytes(out)


def make_query(name: str, qtype: int, msg_id: int = 0x1234, rd: bool = True) -> bytes:
    """Собирает запрос к вышестоящему серверу."""
    flags = FLAG_RD if rd else 0
    msg = Message(id=msg_id, flags=flags)
    msg.questions.append(Question(name=name.rstrip("."), qtype=qtype))
    return encode_message(msg)


def make_response(request: bytes, answers: list[Record] | None = None,
                  authority: list[Record] | None = None,
                  rcode: int = RCODE_NOERROR, aa: bool = False,
                  tc: bool = False) -> bytes:
    """Собирает ответ на запрос `request` (копирует id и вопрос)."""
    try:
        req = parse_message(request)
    except DnsFormatError:
        req = Message(id=0)
    flags = FLAG_QR | (FLAG_AA if aa else 0) | (FLAG_TC if tc else 0) | FLAG_RA
    flags |= (req.flags & FLAG_RD)
    flags |= rcode & 0x000F
    msg = Message(id=req.id, flags=flags)
    msg.questions = list(req.questions)
    msg.answers = answers or []
    msg.authority = authority or []
    return encode_message(msg)


def make_nodata(request: bytes, soa_ttl: int = 300) -> bytes:
    """Ответ NODATA: NOERROR без A/AAAA, но с SOA в authority."""
    try:
        req = parse_message(request)
    except DnsFormatError:
        req = Message(id=0)
    qname = req.qname or "."
    soa_rdata = (encode_name(".") + encode_name(".")
                 + struct.pack("!IIIII", 1, 3600, 600, 86400, 300))
    soa = Record(name=".", rtype=TYPE_SOA, rclass=CLASS_IN, ttl=soa_ttl, rdata=soa_rdata)
    soa.soa = (".", ".", 1, 3600, 600, 86400, 300)
    return make_response(request, answers=[], authority=[soa], rcode=RCODE_NOERROR)


def make_servfail(request: bytes) -> bytes:
    return make_response(request, answers=[], authority=[], rcode=RCODE_SERVFAIL)
