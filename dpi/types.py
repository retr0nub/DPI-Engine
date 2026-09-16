"""
Core data types shared across the DPI engine: the five-tuple that identifies
a flow, the AppType classification enum, and the SNI -> AppType heuristic.

Ported from the original C++ (include/types.h, src/types.cpp).
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple, Optional


class AppType(str, Enum):
    UNKNOWN = "Unknown"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    QUIC = "QUIC"
    GOOGLE = "Google"
    FACEBOOK = "Facebook"
    YOUTUBE = "YouTube"
    TWITTER = "Twitter/X"
    INSTAGRAM = "Instagram"
    NETFLIX = "Netflix"
    AMAZON = "Amazon"
    MICROSOFT = "Microsoft"
    APPLE = "Apple"
    WHATSAPP = "WhatsApp"
    TELEGRAM = "Telegram"
    TIKTOK = "TikTok"
    SPOTIFY = "Spotify"
    ZOOM = "Zoom"
    DISCORD = "Discord"
    GITHUB = "GitHub"
    CLOUDFLARE = "Cloudflare"

    def __str__(self) -> str:  # pretty-print as the display name
        return self.value


# Ordered (pattern -> AppType) table. Order matters: more specific brands
# (YouTube, Instagram, WhatsApp) are checked before their parent company
# (Google, Facebook) would otherwise also match.
_SNI_PATTERNS: list[tuple[tuple[str, ...], AppType]] = [
    (("google", "gstatic", "googleapis", "ggpht", "gvt1"), AppType.GOOGLE),
    (("youtube", "ytimg", "youtu.be", "yt3.ggpht"), AppType.YOUTUBE),
    (("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"), AppType.FACEBOOK),
    (("instagram", "cdninstagram"), AppType.INSTAGRAM),
    (("whatsapp", "wa.me"), AppType.WHATSAPP),
    (("twitter", "twimg", "x.com", "t.co"), AppType.TWITTER),
    (("netflix", "nflxvideo", "nflximg"), AppType.NETFLIX),
    (("amazon", "amazonaws", "cloudfront", "aws"), AppType.AMAZON),
    (("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"), AppType.MICROSOFT),
    (("apple", "icloud", "mzstatic", "itunes"), AppType.APPLE),
    (("telegram", "t.me"), AppType.TELEGRAM),
    (("tiktok", "tiktokcdn", "musical.ly", "bytedance"), AppType.TIKTOK),
    (("spotify", "scdn.co"), AppType.SPOTIFY),
    (("zoom",), AppType.ZOOM),
    (("discord", "discordapp"), AppType.DISCORD),
    (("github", "githubusercontent"), AppType.GITHUB),
    (("cloudflare", "cf-"), AppType.CLOUDFLARE),
]


def _matches_at_boundary(haystack: str, needle: str) -> bool:
    """True if `needle` occurs in `haystack` starting at a label/word
    boundary (start of string, or preceded by a non-alphanumeric char).

    This is a deliberate fix over the original C++ version, which did a
    plain substring search. Some of its patterns are short enough to match
    accidentally *inside* an unrelated word -- e.g. the Twitter pattern
    "x.com" (short for the x.com rebrand) is a literal substring of
    "netfli-X.COM-", i.e. "netflix.com", and "t.co" is a substring of
    "microsof-T.CO-m", i.e. "microsoft.com". Both were silently
    misclassified as Twitter/X in the original engine. Requiring a
    boundary before the match keeps the intentional loose matches (e.g.
    "google" inside "googleapis.com") while rejecting mid-word collisions.
    """
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            return False
        if idx == 0 or not haystack[idx - 1].isalnum():
            return True
        start = idx + 1


def sni_to_app_type(sni: str) -> AppType:
    """Classify a hostname/SNI into a known application, else HTTPS/generic TLS."""
    if not sni:
        return AppType.UNKNOWN

    lower = sni.lower()
    for needles, app in _SNI_PATTERNS:
        if any(_matches_at_boundary(lower, n) for n in needles):
            return app

    # SNI present but not a recognized brand -> still classify as encrypted web traffic
    return AppType.HTTPS


def parse_ipv4(ip: str) -> int:
    """Dotted-quad string -> 32-bit int, stored little-endian-first-octet
    to match the C++ version's byte order (so formatting round-trips)."""
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def format_ipv4(ip: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", ip))


class FiveTuple(NamedTuple):
    """Uniquely identifies a connection/flow. Hashable -> used directly as a
    dict key for per-worker flow state and as the hash-partition key."""
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int  # 6 = TCP, 17 = UDP

    def reverse(self) -> "FiveTuple":
        return FiveTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)

    def __str__(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (f"{format_ipv4(self.src_ip)}:{self.src_port} -> "
                f"{format_ipv4(self.dst_ip)}:{self.dst_port} ({proto})")


@dataclass
class FlowState:
    """Per-flow bookkeeping, kept in the worker process that owns this flow
    (mirrors the per-FP-thread ConnectionTracker in the C++ version -- no
    cross-worker locking needed since a flow always hashes to one worker)."""
    tuple: Optional[FiveTuple] = None
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False
