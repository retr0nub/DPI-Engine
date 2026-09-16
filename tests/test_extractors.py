import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dpi.extractors import (
    extract_dns_query,
    extract_http_host,
    extract_sni,
    is_dns_query,
    is_http_request,
    is_tls_client_hello,
)


def _build_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode()
    sni_entry = struct.pack(">BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    extensions = sni_ext
    extensions_data = struct.pack(">H", len(extensions)) + extensions

    body = (
        struct.pack(">H", 0x0303)          # client version
        + bytes(32)                        # random
        + struct.pack("B", 0)              # session id len
        + struct.pack(">H", 2) + struct.pack(">H", 0x1301)  # cipher suites
        + struct.pack("BB", 1, 0)          # compression
        + extensions_data
    )
    handshake = struct.pack("B", 0x01) + struct.pack(">I", len(body))[1:] + body
    record = struct.pack("B", 0x16) + struct.pack(">H", 0x0301) + struct.pack(">H", len(handshake)) + handshake
    return record


def test_extract_sni_happy_path():
    payload = _build_client_hello("example.com")
    assert is_tls_client_hello(payload)
    assert extract_sni(payload) == "example.com"


def test_extract_sni_truncated_does_not_crash():
    payload = _build_client_hello("example.com")
    for cut in range(0, len(payload)):
        # Every truncation point must return None, never raise or over-read.
        assert extract_sni(payload[:cut]) in (None, "example.com")


def test_extract_sni_not_a_client_hello():
    assert extract_sni(b"\x17\x03\x01\x00\x05hello") is None  # content type 0x17 = app data
    assert extract_sni(b"") is None
    assert extract_sni(b"\x16\x03\x01") is None  # too short


def test_extract_sni_garbage_lengths_bounded():
    # Malformed record claiming a huge extensions_length -- must clamp, not overread.
    payload = _build_client_hello("x")
    corrupted = bytearray(payload)
    # Blow up the extensions_length field (best-effort corruption; just must not crash)
    for i in range(len(corrupted)):
        corrupted[i] = 0xFF
        extract_sni(bytes(corrupted))  # should never raise
        corrupted[i] = payload[i]


def test_http_host_extraction():
    req = b"GET /path HTTP/1.1\r\nHost: example.org:8080\r\nUser-Agent: test\r\n\r\n"
    assert is_http_request(req)
    assert extract_http_host(req) == "example.org"  # port stripped


def test_http_host_case_insensitive():
    req = b"GET / HTTP/1.1\r\nhost: lower.example.com\r\n\r\n"
    assert extract_http_host(req) == "lower.example.com"


def test_http_no_host_header():
    req = b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n"
    assert extract_http_host(req) is None


def test_not_http_request():
    assert extract_http_host(b"\x16\x03\x01not http") is None


def _build_dns_query(domain: str) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(struct.pack("B", len(label)) + label.encode() for label in domain.split(".")) + b"\x00"
    q += struct.pack(">HH", 1, 1)
    return header + q


def test_dns_query_extraction():
    payload = _build_dns_query("api.example.com")
    assert is_dns_query(payload)
    assert extract_dns_query(payload) == "api.example.com"


def test_dns_response_not_treated_as_query():
    payload = bytearray(_build_dns_query("example.com"))
    payload[2] |= 0x80  # set QR bit -> response
    assert not is_dns_query(bytes(payload))
    assert extract_dns_query(bytes(payload)) is None


def test_dns_truncated_does_not_crash():
    payload = _build_dns_query("a.b.c.example.com")
    for cut in range(12, len(payload)):
        extract_dns_query(payload[:cut])  # must not raise
