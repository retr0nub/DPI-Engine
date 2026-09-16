"""
Blocking rules: by source IP, by classified app, or by domain (substring
match against the detected SNI/Host). Ported from the `Rules` class actually
used by the engine in src/dpi_mt.cpp (the more elaborate RuleManager in
rule_manager.cpp/.h existed in the C++ repo but wasn't wired into the
multi-threaded engine -- dead code, not ported here).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .types import AppType, parse_ipv4


@dataclass
class Rules:
    blocked_ips: set[int] = field(default_factory=set)
    blocked_apps: set[AppType] = field(default_factory=set)
    blocked_domains: list[str] = field(default_factory=list)
    blocked_ports: set[int] = field(default_factory=set)

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(parse_ipv4(ip))

    def block_app(self, name: str) -> bool:
        """Match by display name, case-insensitively (e.g. 'youtube' -> AppType.YOUTUBE)."""
        for app in AppType:
            if app.value.lower() == name.lower():
                self.blocked_apps.add(app)
                return True
        return False

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain.lower())

    def block_port(self, port: int) -> None:
        self.blocked_ports.add(port)

    def is_blocked(self, src_ip: int, dst_port: int, app: AppType, sni: str) -> Optional[str]:
        """Returns a short reason string if blocked, else None."""
        if src_ip in self.blocked_ips:
            return "ip"
        if dst_port in self.blocked_ports:
            return "port"
        if app in self.blocked_apps:
            return "app"
        if sni:
            lower_sni = sni.lower()
            for dom in self.blocked_domains:
                if dom in lower_sni:
                    return "domain"
        return None
