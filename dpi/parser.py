"""
Ethernet / IPv4 / TCP / UDP header parsing. Ported from
include/packet_parser.h + src/packet_parser.cpp.

Deliberately hand-rolled with `struct` (no scapy/dpkt) so the byte-offset
arithmetic stays explicit -- that's the whole point of a DPI project.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .types import FiveTuple

ETH_HDR_LEN = 14
ETHERTYPE_IPV4 = 0x0800

PROTO_TCP = 6
PROTO_UDP = 17


@dataclass
class ParsedPacket:
    src_mac: str
    dest_mac: str
    ether_type: int

    has_ip: bool = False
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0

    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    tcp_flags: int = 0

    payload_offset: int = 0
    payload_length: int = 0

    @property
    def tuple(self) -> Optional[FiveTuple]:
        if not self.has_ip or not (self.has_tcp or self.has_udp):
            return None
        from .types import parse_ipv4
        return FiveTuple(
            parse_ipv4(self.src_ip), parse_ipv4(self.dest_ip),
            self.src_port, self.dest_port, self.protocol,
        )


def _mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_packet(data: bytes) -> Optional[ParsedPacket]:
    """Parse a raw Ethernet frame. Returns None if it's too short or not
    an IPv4 frame we understand -- mirrors PacketParser::parse's early-outs."""
    if len(data) < ETH_HDR_LEN:
        return None

    dest_mac = data[0:6]
    src_mac = data[6:12]
    ether_type = struct.unpack(">H", data[12:14])[0]

    pkt = ParsedPacket(src_mac=_mac_str(src_mac), dest_mac=_mac_str(dest_mac), ether_type=ether_type)

    if ether_type != ETHERTYPE_IPV4:
        return pkt  # not IPv4 (e.g. ARP) -- caller filters these out

    if len(data) < ETH_HDR_LEN + 20:
        return pkt

    ip = data[ETH_HDR_LEN:]
    version_ihl = ip[0]
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return pkt

    ttl = ip[8]
    protocol = ip[9]
    src_ip = ".".join(str(b) for b in ip[12:16])
    dest_ip = ".".join(str(b) for b in ip[16:20])

    pkt.has_ip = True
    pkt.src_ip = src_ip
    pkt.dest_ip = dest_ip
    pkt.protocol = protocol
    pkt.ttl = ttl

    payload_offset = ETH_HDR_LEN + ihl
    transport = ip[ihl:]

    if protocol == PROTO_TCP and len(transport) >= 20:
        src_port, dest_port = struct.unpack(">HH", transport[0:4])
        data_offset = (transport[12] >> 4) * 4
        flags = transport[13]
        pkt.has_tcp = True
        pkt.src_port = src_port
        pkt.dest_port = dest_port
        pkt.tcp_flags = flags
        payload_offset += max(data_offset, 20)

    elif protocol == PROTO_UDP and len(transport) >= 8:
        src_port, dest_port = struct.unpack(">HH", transport[0:4])
        pkt.has_udp = True
        pkt.src_port = src_port
        pkt.dest_port = dest_port
        payload_offset += 8

    else:
        return pkt  # ICMP or anything else -- not TCP/UDP, no five-tuple

    pkt.payload_offset = payload_offset
    pkt.payload_length = max(0, len(data) - payload_offset)
    return pkt
