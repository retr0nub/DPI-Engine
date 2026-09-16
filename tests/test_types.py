import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dpi.types import AppType, FiveTuple, format_ipv4, parse_ipv4, sni_to_app_type


def test_ip_roundtrip():
    for ip in ["192.168.1.1", "8.8.8.8", "0.0.0.0", "255.255.255.255"]:
        assert format_ipv4(parse_ipv4(ip)) == ip


def test_five_tuple_reverse():
    t = FiveTuple(parse_ipv4("1.1.1.1"), parse_ipv4("2.2.2.2"), 1234, 443, 6)
    r = t.reverse()
    assert r.src_ip == t.dst_ip and r.dst_ip == t.src_ip
    assert r.src_port == t.dst_port and r.dst_port == t.src_port
    assert r.reverse() == t


def test_brand_classification():
    cases = {
        "www.youtube.com": AppType.YOUTUBE,
        "www.google.com": AppType.GOOGLE,
        "googleapis.com": AppType.GOOGLE,
        "www.facebook.com": AppType.FACEBOOK,
        "www.instagram.com": AppType.INSTAGRAM,
        "twitter.com": AppType.TWITTER,
        "api.twitter.com": AppType.TWITTER,
        "www.netflix.com": AppType.NETFLIX,     # regression test for the x.com bug
        "www.microsoft.com": AppType.MICROSOFT,  # regression test for the t.co bug
        "github.com": AppType.GITHUB,
        "discord.com": AppType.DISCORD,
    }
    for domain, expected in cases.items():
        assert sni_to_app_type(domain) == expected, domain


def test_unrecognized_domain_falls_back_to_https():
    assert sni_to_app_type("some-random-startup.io") == AppType.HTTPS


def test_empty_sni_is_unknown():
    assert sni_to_app_type("") == AppType.UNKNOWN
