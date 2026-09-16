"""
The engine itself: reads a pcap, hash-partitions each flow to one of N
worker processes, each worker classifies + applies blocking rules against
its own private flow table, and results stream back to the main process
for writing + reporting.

Architecture note (why this differs from the C++ version):
The original C++ engine used two tiers of *threads* -- load balancers that
hash-dispatch to fast-path threads, each fast-path owning its own
lock-free ConnectionTracker. That two-tier split made sense there because
OS threads are cheap and share memory, so adding a tier costs almost
nothing.

Python's GIL means threads don't get real parallelism for this CPU-bound
parsing work, so this version uses `multiprocessing` instead -- but
processes are much more expensive to spin up than threads, and they don't
share memory. So the two tiers collapse into one: the main process itself
plays the role of dispatcher (hashing each five-tuple straight to a worker
process's queue), and each worker process plays the role the fast-path
threads did -- owning its own flow table, no locking needed, same reason
as before (a flow's five-tuple always hashes to the same worker, so no
two workers ever touch the same flow).
"""
from __future__ import annotations

import multiprocessing as mp
import time
from dataclasses import dataclass, field
from typing import Optional

from .extractors import extract_dns_query, extract_http_host, extract_sni
from .parser import parse_packet
from .pcap import PcapReader, PcapWriter
from .rules import Rules
from .types import AppType, FiveTuple, FlowState, sni_to_app_type

_GENERIC_APPS = frozenset({AppType.UNKNOWN, AppType.DNS, AppType.TLS, AppType.QUIC, AppType.HTTP, AppType.HTTPS})


@dataclass
class PacketJob:
    id: int
    tuple: FiveTuple
    data: bytes
    ts_sec: int
    ts_usec: int
    payload_offset: int
    payload_length: int


@dataclass
class PacketResult:
    id: int
    ts_sec: int
    ts_usec: int
    data: Optional[bytes]  # only present when forwarded
    app: AppType
    sni: str
    forwarded: bool
    worker_id: int


@dataclass
class WorkerDone:
    worker_id: int
    processed: int


@dataclass
class EngineStats:
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    forwarded: int = 0
    dropped: int = 0
    per_worker_processed: dict = field(default_factory=dict)
    app_counts: dict = field(default_factory=dict)
    detected_snis: dict = field(default_factory=dict)


def _classify(job: PacketJob, flow: FlowState) -> None:
    """Try, in order: TLS SNI (port 443) -> HTTP Host (port 80) -> DNS
    query name -> port-based fallback. Mirrors FastPath::classifyFlow."""
    payload = job.data[job.payload_offset: job.payload_offset + job.payload_length]

    if job.tuple.dst_port == 443 and len(payload) > 5:
        sni = extract_sni(payload)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
            flow.classified = True
            return

    if job.tuple.dst_port == 80 and len(payload) > 10:
        host = extract_http_host(payload)
        if host:
            flow.sni = host
            flow.app_type = sni_to_app_type(host)
            flow.classified = True
            return

    if job.tuple.dst_port == 53 or job.tuple.src_port == 53:
        query = extract_dns_query(payload) if payload else None
        if query:
            flow.sni = query
        flow.app_type = AppType.DNS
        flow.classified = True
        return

    # Port-based fallback -- not "classified" yet, might still get an SNI later
    if job.tuple.dst_port == 443:
        flow.app_type = AppType.HTTPS
    elif job.tuple.dst_port == 80:
        flow.app_type = AppType.HTTP


def _worker_main(worker_id: int, task_queue: mp.Queue, result_queue: mp.Queue, rules: Rules) -> None:
    flows: dict[FiveTuple, FlowState] = {}
    processed = 0

    while True:
        job = task_queue.get()
        if job is None:  # sentinel: no more work
            break
        processed += 1

        flow = flows.get(job.tuple)
        if flow is None:
            flow = FlowState(tuple=job.tuple)
            flows[job.tuple] = flow
        flow.packets += 1
        flow.bytes += len(job.data)

        if not flow.classified:
            _classify(job, flow)

        if not flow.blocked:
            reason = rules.is_blocked(job.tuple.src_ip, job.tuple.dst_port, flow.app_type, flow.sni)
            flow.blocked = reason is not None

        result_queue.put(PacketResult(
            id=job.id, ts_sec=job.ts_sec, ts_usec=job.ts_usec,
            data=None if flow.blocked else job.data,
            app=flow.app_type, sni=flow.sni,
            forwarded=not flow.blocked, worker_id=worker_id,
        ))

    result_queue.put(WorkerDone(worker_id=worker_id, processed=processed))


class DPIEngine:
    def __init__(self, num_workers: int = 4):
        self.num_workers = max(1, num_workers)
        self.rules = Rules()

    def block_ip(self, ip: str) -> None:
        self.rules.block_ip(ip)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, name: str) -> None:
        if self.rules.block_app(name):
            print(f"[Rules] Blocked app: {name}")
        else:
            print(f"[Rules] Unknown app: {name}")

    def block_domain(self, domain: str) -> None:
        self.rules.block_domain(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def block_port(self, port: int) -> None:
        self.rules.block_port(port)
        print(f"[Rules] Blocked port: {port}")

    def process(self, input_path: str, output_path: str) -> EngineStats:
        stats = EngineStats()

        task_queues = [mp.Queue() for _ in range(self.num_workers)]
        result_queue: mp.Queue = mp.Queue()

        workers = [
            mp.Process(target=_worker_main, args=(i, task_queues[i], result_queue, self.rules), daemon=True)
            for i in range(self.num_workers)
        ]
        for w in workers:
            w.start()

        print(f"[Reader] Processing packets with {self.num_workers} worker process(es)...")

        pkt_id = 0
        with PcapReader(input_path) as reader:
            for raw in reader:
                parsed = parse_packet(raw.data)
                if parsed is None or not parsed.has_ip or not (parsed.has_tcp or parsed.has_udp):
                    continue

                tup = parsed.tuple
                if tup is None:
                    continue

                stats.total_packets += 1
                stats.total_bytes += len(raw.data)
                if parsed.has_tcp:
                    stats.tcp_packets += 1
                else:
                    stats.udp_packets += 1

                job = PacketJob(
                    id=pkt_id, tuple=tup, data=raw.data,
                    ts_sec=raw.ts_sec, ts_usec=raw.ts_usec,
                    payload_offset=parsed.payload_offset, payload_length=parsed.payload_length,
                )
                pkt_id += 1

                worker_idx = hash(tup) % self.num_workers
                task_queues[worker_idx].put(job)

        print(f"[Reader] Done reading {pkt_id} packets")

        for q in task_queues:
            q.put(None)  # sentinel

        forwarded_packets: list[tuple[int, int, int, bytes]] = []
        done_count = 0
        while done_count < self.num_workers:
            msg = result_queue.get()
            if isinstance(msg, WorkerDone):
                stats.per_worker_processed[msg.worker_id] = msg.processed
                done_count += 1
                continue

            result: PacketResult = msg
            stats.app_counts[result.app] = stats.app_counts.get(result.app, 0) + 1
            if result.sni:
                existing = stats.detected_snis.get(result.sni)
                # A hostname can appear in more than one flow (e.g. a DNS
                # lookup and a TLS connection to the same domain). Don't let
                # a generic classification (DNS/HTTP/HTTPS/Unknown) clobber a
                # more specific one (a recognized brand) that arrived first.
                if existing is None or existing in _GENERIC_APPS or result.app not in _GENERIC_APPS:
                    stats.detected_snis[result.sni] = result.app

            if result.forwarded:
                stats.forwarded += 1
                forwarded_packets.append((result.id, result.ts_sec, result.ts_usec, result.data))
            else:
                stats.dropped += 1

        for w in workers:
            w.join()

        # Written in original packet order -- the C++ version wrote in whatever
        # order the async pipeline happened to finish in; sorting by id here
        # gives a deterministic, chronologically-ordered output file instead.
        forwarded_packets.sort(key=lambda t: t[0])
        with PcapWriter(output_path) as writer:
            for _id, ts_sec, ts_usec, data in forwarded_packets:
                writer.write_packet(ts_sec, ts_usec, data)

        return stats
