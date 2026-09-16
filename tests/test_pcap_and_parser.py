import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dpi.parser import parse_packet
from dpi.pcap import PcapReader, PcapWriter


def _eth_ip_tcp_packet(payload: bytes = b"hello") -> bytes:
    eth = bytes.fromhex("aabbccddeeff" "001122334455") + struct.pack(">H", 0x0800)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + 20 + len(payload), 0, 0x4000, 64, 6, 0)
    ip += bytes([192, 168, 1, 100]) + bytes([93, 184, 216, 34])
    tcp = struct.pack(">HHIIBBHHH", 55555, 443, 1000, 0, 5 << 4, 0x18, 65535, 0, 0)
    return eth + ip + tcp + payload


def test_pcap_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        path = f"{d}/t.pcap"
        pkt1 = _eth_ip_tcp_packet(b"first")
        pkt2 = _eth_ip_tcp_packet(b"second")

        with PcapWriter(path) as w:
            w.write_packet(1700000000, 0, pkt1)
            w.write_packet(1700000001, 500, pkt2)

        with PcapReader(path) as r:
            packets = list(r)

        assert len(packets) == 2
        assert packets[0].data == pkt1
        assert packets[1].data == pkt2
        assert packets[1].ts_sec == 1700000001
        assert packets[1].ts_usec == 500


def test_parse_packet_extracts_five_tuple():
    raw = _eth_ip_tcp_packet(b"payload-bytes")
    parsed = parse_packet(raw)
    assert parsed is not None
    assert parsed.has_ip and parsed.has_tcp
    assert parsed.src_ip == "192.168.1.100"
    assert parsed.dest_ip == "93.184.216.34"
    assert parsed.dest_port == 443
    assert parsed.payload_length == len(b"payload-bytes")
    assert raw[parsed.payload_offset: parsed.payload_offset + parsed.payload_length] == b"payload-bytes"


def test_parse_packet_too_short_returns_none():
    assert parse_packet(b"\x00" * 5) is None


def test_parse_packet_non_ip_ethertype_is_tolerated():
    arp = bytes.fromhex("aabbccddeeff" "001122334455") + struct.pack(">H", 0x0806) + b"\x00" * 20
    parsed = parse_packet(arp)
    assert parsed is not None
    assert not parsed.has_ip
