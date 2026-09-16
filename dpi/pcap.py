"""
Minimal PCAP (libpcap classic format) reader/writer -- no external
dependency, just `struct`. Ported from src/pcap_reader.cpp.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC_NATIVE = 0xA1B2C3D4
MAGIC_SWAPPED = 0xD4C3B2A1

_GLOBAL_HDR_FMT_LE = "<IHHiIII"  # magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network
_GLOBAL_HDR_FMT_BE = ">IHHiIII"
_PKT_HDR_FMT_LE = "<IIII"        # ts_sec, ts_usec, incl_len, orig_len
_PKT_HDR_FMT_BE = ">IIII"

GLOBAL_HDR_SIZE = 24
PKT_HDR_SIZE = 16


@dataclass
class GlobalHeader:
    magic: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass
class RawPacket:
    ts_sec: int
    ts_usec: int
    data: bytes


class PcapFormatError(ValueError):
    pass


class PcapReader:
    """Streaming reader: open() then iterate with read_packet() until it
    returns None, or just `for pkt in reader:`."""

    def __init__(self, path: str):
        self._f = open(path, "rb")
        self.header = self._read_global_header(path)

    def _read_global_header(self, path: str) -> GlobalHeader:
        raw = self._f.read(GLOBAL_HDR_SIZE)
        if len(raw) < GLOBAL_HDR_SIZE:
            raise PcapFormatError(f"{path}: truncated pcap global header")

        magic = int.from_bytes(raw[:4], "little")
        if magic == MAGIC_NATIVE:
            self.endian = "<"
        elif magic == MAGIC_SWAPPED:
            self.endian = ">"
        else:
            raise PcapFormatError(f"{path}: bad magic number 0x{magic:08x}")

        fmt = _GLOBAL_HDR_FMT_LE if self.endian == "<" else _GLOBAL_HDR_FMT_BE
        magic, vmaj, vmin, tz, sigfigs, snaplen, network = struct.unpack(fmt, raw)
        return GlobalHeader(magic, vmaj, vmin, tz, sigfigs, snaplen, network)

    def read_packet(self) -> "RawPacket | None":
        fmt = _PKT_HDR_FMT_LE if self.endian == "<" else _PKT_HDR_FMT_BE
        hdr_raw = self._f.read(PKT_HDR_SIZE)
        if len(hdr_raw) < PKT_HDR_SIZE:
            return None  # clean EOF

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, hdr_raw)

        if incl_len > self.header.snaplen or incl_len > 65535:
            raise PcapFormatError(f"invalid captured packet length: {incl_len}")

        data = self._f.read(incl_len)
        if len(data) < incl_len:
            raise PcapFormatError("truncated packet data (file ends mid-packet)")

        return RawPacket(ts_sec, ts_usec, data)

    def __iter__(self):
        while True:
            pkt = self.read_packet()
            if pkt is None:
                return
            yield pkt

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class PcapWriter:
    def __init__(self, path: str, snaplen: int = 65535, network: int = 1):
        self._f = open(path, "wb")
        self._f.write(struct.pack(_GLOBAL_HDR_FMT_LE, MAGIC_NATIVE, 2, 4, 0, 0, snaplen, network))

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes):
        self._f.write(struct.pack(_PKT_HDR_FMT_LE, ts_sec, ts_usec, len(data), len(data)))
        self._f.write(data)

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
