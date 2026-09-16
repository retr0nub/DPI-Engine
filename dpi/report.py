"""Text report formatting, in the spirit of the original boxed console output."""
from __future__ import annotations

from .engine import EngineStats

_WIDTH = 66


def _line(text: str = "") -> str:
    return "║ " + text.ljust(_WIDTH - 4) + " ║"


def render_report(stats: EngineStats, num_workers: int) -> str:
    lines = []
    lines.append("╔" + "═" * (_WIDTH - 2) + "╗")
    lines.append(_line("PROCESSING REPORT"))
    lines.append("╠" + "═" * (_WIDTH - 2) + "╣")
    lines.append(_line(f"Total Packets:   {stats.total_packets}"))
    lines.append(_line(f"Total Bytes:     {stats.total_bytes}"))
    lines.append(_line(f"TCP Packets:     {stats.tcp_packets}"))
    lines.append(_line(f"UDP Packets:     {stats.udp_packets}"))
    lines.append("╠" + "═" * (_WIDTH - 2) + "╣")
    lines.append(_line(f"Forwarded:       {stats.forwarded}"))
    lines.append(_line(f"Dropped:         {stats.dropped}"))
    lines.append("╠" + "═" * (_WIDTH - 2) + "╣")
    lines.append(_line("WORKER STATISTICS"))
    for i in range(num_workers):
        count = stats.per_worker_processed.get(i, 0)
        lines.append(_line(f"  Worker{i} processed: {count}"))

    lines.append("╠" + "═" * (_WIDTH - 2) + "╣")
    lines.append(_line("APPLICATION BREAKDOWN"))
    lines.append("╠" + "═" * (_WIDTH - 2) + "╣")

    total = stats.total_packets or 1
    for app, count in sorted(stats.app_counts.items(), key=lambda kv: -kv[1]):
        pct = 100.0 * count / total
        bar = "#" * int(pct / 5)
        lines.append(_line(f"{str(app):<15}{count:>8}  {pct:5.1f}% {bar}"))

    lines.append("╚" + "═" * (_WIDTH - 2) + "╝")

    if stats.detected_snis:
        lines.append("")
        lines.append("[Detected Domains/SNIs]")
        for sni, app in stats.detected_snis.items():
            lines.append(f"  - {sni} -> {app}")

    return "\n".join(lines)
