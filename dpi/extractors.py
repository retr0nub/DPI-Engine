"""
Payload-level extractors: pull a hostname out of a TLS ClientHello (SNI),
an HTTP request (Host header), or a DNS query -- the three things that let
us classify a flow before it's fully encrypted, or at all.

Ported from src/sni_extractor.cpp. Every offset is bounds-checked against
`length` before use, same discipline as the C++ version, since this is
parsing untrusted bytes off the wire.

Note vs. the original: `QUICSNIExtractor` isn't ported. The C++ version had
a pointer-underflow bug (`payload + i - 5` with `i` starting at 0) and its
QUIC parsing was already flagged in its own comments as a simplified,
unreliable heuristic. Proper QUIC SNI extraction needs to decrypt the
Initial packet's CRYPTO frame (RFC 9001 Initial secrets) -- worth a real
implementation later, not worth faking here.
"""
from __future__ import annotations

import struct
from typing import Optional

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def _u24(data: bytes, offset: int) -> int:
    b0, b1, b2 = data[offset], data[offset + 1], data[offset + 2]
    return (b0 << 16) | (b1 << 8) | b2


def is_tls_client_hello(payload: bytes) -> bool:
    length = len(payload)
    if length < 9:
        return False
    if payload[0] != CONTENT_TYPE_HANDSHAKE:
        return False

    version = _u16(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return False

    record_length = _u16(payload, 3)
    if record_length > length - 5:
        return False

    return payload[5] == HANDSHAKE_CLIENT_HELLO


def extract_sni(payload: bytes) -> Optional[str]:
    """Walk a TLS ClientHello: version, random, session ID, cipher suites,
    compression methods, then the extensions list looking for SNI (0x0000)."""
    if not is_tls_client_hello(payload):
        return None

    length = len(payload)
    offset = 5  # skip TLS record header

    # handshake header: type(1) + length(3)
    offset += 4

    offset += 2   # client version
    offset += 32  # random

    if offset >= length:
        return None
    session_id_length = payload[offset]
    offset += 1 + session_id_length

    if offset + 2 > length:
        return None
    cipher_suites_length = _u16(payload, offset)
    offset += 2 + cipher_suites_length

    if offset >= length:
        return None
    compression_methods_length = payload[offset]
    offset += 1 + compression_methods_length

    if offset + 2 > length:
        return None
    extensions_length = _u16(payload, offset)
    offset += 2

    extensions_end = min(offset + extensions_length, length)

    while offset + 4 <= extensions_end:
        extension_type = _u16(payload, offset)
        extension_length = _u16(payload, offset + 2)
        offset += 4

        if offset + extension_length > extensions_end:
            break

        if extension_type == EXTENSION_SNI:
            if extension_length < 5:
                break
            sni_list_length = _u16(payload, offset)
            if sni_list_length < 3:
                break
            sni_type = payload[offset + 2]
            sni_length = _u16(payload, offset + 3)

            if sni_type != SNI_TYPE_HOSTNAME:
                break
            if sni_length > extension_length - 5:
                break

            start = offset + 5
            return payload[start:start + sni_length].decode("ascii", errors="replace")

        offset += extension_length

    return None


_HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")


def is_http_request(payload: bytes) -> bool:
    return len(payload) >= 4 and payload[:4] in _HTTP_METHODS


def extract_http_host(payload: bytes) -> Optional[str]:
    if not is_http_request(payload):
        return None

    length = len(payload)
    lower = payload.lower()
    idx = lower.find(b"host:")
    if idx == -1 or idx + 5 >= length:
        return None

    start = idx + 5
    while start < length and payload[start:start + 1] in (b" ", b"\t"):
        start += 1

    end = start
    while end < length and payload[end:end + 1] not in (b"\r", b"\n"):
        end += 1

    if end <= start:
        return None

    host = payload[start:end].decode("ascii", errors="replace")
    return host.split(":", 1)[0]  # strip a trailing :port


def is_dns_query(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    flags = payload[2]
    if flags & 0x80:  # QR bit set -> response, not query
        return False
    qdcount = _u16(payload, 4)
    return qdcount > 0


def extract_dns_query(payload: bytes) -> Optional[str]:
    if not is_dns_query(payload):
        return None

    length = len(payload)
    offset = 12
    labels: list[str] = []

    while offset < length:
        label_length = payload[offset]
        if label_length == 0:
            break
        if label_length > 63:  # compression pointer or malformed -- bail out
            break
        offset += 1
        if offset + label_length > length:
            break
        labels.append(payload[offset:offset + label_length].decode("ascii", errors="replace"))
        offset += label_length

    return ".".join(labels) if labels else None
