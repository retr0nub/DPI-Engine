#!/usr/bin/env python3
"""
DPI Engine (Python port) -- CLI entry point.

Usage:
    python3 main.py <input.pcap> <output.pcap> [options]

Options:
    --block-ip IP           Block a source IP (repeatable)
    --block-app APP         Block an application by name, e.g. YouTube (repeatable)
    --block-domain DOMAIN   Block by substring match against detected SNI/Host (repeatable)
    --block-port PORT       Block a destination port (repeatable)
    --workers N             Number of worker processes (default: 4)

Example:
    python3 main.py capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import sys

from dpi.engine import DPIEngine
from dpi.report import render_report


def main() -> int:
    parser = argparse.ArgumentParser(description="DPI Engine (Python port)")
    parser.add_argument("input", help="Input pcap file")
    parser.add_argument("output", help="Output pcap file (forwarded packets only)")
    parser.add_argument("--block-ip", action="append", default=[], metavar="IP")
    parser.add_argument("--block-app", action="append", default=[], metavar="APP")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN")
    parser.add_argument("--block-port", action="append", type=int, default=[], metavar="PORT")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker processes")
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print(f"║  DPI ENGINE v2.0 (Python, multiprocessing, {args.workers} workers){' ' * max(0, 16 - len(str(args.workers)))}║")
    print("╚══════════════════════════════════════════════════════════════╝")

    engine = DPIEngine(num_workers=args.workers)
    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for domain in args.block_domain:
        engine.block_domain(domain)
    for port in args.block_port:
        engine.block_port(port)

    try:
        stats = engine.process(args.input, args.output)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(render_report(stats, args.workers))
    print(f"\nOutput written to: {args.output}")
    return 0


if __name__ == "__main__":
    mp.freeze_support()  # harmless on Linux/macOS, needed for a frozen Windows exe
    raise SystemExit(main())
