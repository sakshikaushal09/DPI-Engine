#!/usr/bin/env python3
"""
dpi_mt.py
Multi-threaded DPI engine.

Architecture:

    Reader Thread -> [LB queues] -> Load Balancer Threads
                                       -> [FP queues] -> Fast Path Threads
                                                            -> Output Queue
                                                                 -> Output Writer Thread

Packets belonging to the same connection (five-tuple) are always routed
to the same Load Balancer and the same Fast Path via consistent hashing
(hash(five_tuple) % N), so each Fast Path can safely keep its own
private flow table without locking.

Usage:
    python3 dpi_mt.py input.pcap output.pcap --lbs 2 --fps 2 \
        --block-app YouTube --block-ip 192.168.1.50 --block-domain tiktok
"""

import argparse
import sys
import threading
import queue
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from dpi.pcap_reader import PcapReader, PcapPacketHeader
from dpi.pcap_writer import PcapWriter
from dpi.packet_parser import PacketParser
from dpi.sni_extractor import SNIExtractor, HTTPHostExtractor
from dpi.rule_manager import RuleManager
from dpi.types import FiveTuple, Flow, AppType, sni_to_app_type


@dataclass
class Packet:
    header: PcapPacketHeader
    raw: bytes
    tuple: Optional[FiveTuple]
    src_ip: str = ""
    dst_port: int = 0
    payload: bytes = b""
    ip_proto: int = 0


class Stats:
    """Thread-safe counters, protected by a single lock (simple & correct)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total = 0
        self.total_bytes = 0
        self.tcp = 0
        self.udp = 0
        self.forwarded = 0
        self.dropped = 0
        self.app_stats = defaultdict(int)
        self.detected = {}
        self.lb_dispatched = defaultdict(int)
        self.fp_processed = defaultdict(int)

    def incr(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                setattr(self, k, getattr(self, k) + v)

    def note_app(self, app_name: str):
        with self._lock:
            self.app_stats[app_name] += 1

    def note_detected(self, sni: str, app_name: str):
        with self._lock:
            if sni not in self.detected:
                self.detected[sni] = app_name

    def note_lb(self, idx: int):
        with self._lock:
            self.lb_dispatched[idx] += 1

    def note_fp(self, idx: int):
        with self._lock:
            self.fp_processed[idx] += 1


def classify_flow(pkt: Packet, flow: Flow) -> None:
    if flow.sni:
        return
    if pkt.dst_port == 443 and len(pkt.payload) > 5:
        sni = SNIExtractor.extract(pkt.payload)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
            return
    if pkt.dst_port == 80 and len(pkt.payload) > 0:
        host = HTTPHostExtractor.extract(pkt.payload)
        if host:
            flow.sni = host
            flow.app_type = sni_to_app_type(host)
            return
    if pkt.ip_proto == 17 and pkt.dst_port == 53:
        flow.app_type = AppType.DNS


class FastPath(threading.Thread):
    """Owns a private flow table; does the actual DPI classification + rule check."""

    def __init__(self, idx: int, in_q: "queue.Queue", out_q: "queue.Queue",
                 rules: RuleManager, stats: Stats):
        super().__init__(name=f"FP{idx}", daemon=True)
        self.idx = idx
        self.in_q = in_q
        self.out_q = out_q
        self.rules = rules
        self.stats = stats
        self.flows = {}

    def run(self):
        while True:
            pkt = self.in_q.get()
            if pkt is None:  # poison pill = shutdown signal
                self.out_q.put(None)
                return

            self.stats.note_fp(self.idx)

            if pkt.tuple is None:
                self.stats.incr(forwarded=1)
                self.out_q.put(pkt)
                continue

            flow = self.flows.setdefault(pkt.tuple, Flow())
            flow.packet_count += 1
            classify_flow(pkt, flow)

            if flow.sni:
                self.stats.note_detected(flow.sni, str(flow.app_type))

            if not flow.blocked and self.rules.is_blocked(
                pkt.src_ip, flow.app_type, flow.sni
            ):
                flow.blocked = True

            self.stats.note_app(str(flow.app_type))

            if flow.blocked:
                self.stats.incr(dropped=1)
            else:
                self.stats.incr(forwarded=1)
                self.out_q.put(pkt)


class LoadBalancer(threading.Thread):
    """Hashes each packet's five-tuple to a Fast Path queue (consistent hashing)."""

    def __init__(self, idx: int, in_q: "queue.Queue", fast_paths, stats: Stats):
        super().__init__(name=f"LB{idx}", daemon=True)
        self.idx = idx
        self.in_q = in_q
        self.fast_paths = fast_paths
        self.stats = stats

    def run(self):
        while True:
            pkt = self.in_q.get()
            if pkt is None:
                for fp in self.fast_paths:
                    fp.in_q.put(None)
                return

            self.stats.note_lb(self.idx)
            fp_idx = 0 if pkt.tuple is None else hash(pkt.tuple) % len(self.fast_paths)
            self.fast_paths[fp_idx].in_q.put(pkt)


def output_writer(out_qs, writer: PcapWriter, num_producers: int):
    """Drains every Fast Path's output queue and writes packets to the output PCAP."""
    done = 0
    while done < num_producers:
        for q in out_qs:
            try:
                pkt = q.get(timeout=0.05)
            except queue.Empty:
                continue
            if pkt is None:
                done += 1
                continue
            writer.write_packet(pkt.header.ts_sec, pkt.header.ts_usec, pkt.raw)


def main():
    ap = argparse.ArgumentParser(description="Multi-threaded DPI engine")
    ap.add_argument("input_pcap")
    ap.add_argument("output_pcap")
    ap.add_argument("--block-app", action="append", default=[])
    ap.add_argument("--block-ip", action="append", default=[])
    ap.add_argument("--block-domain", action="append", default=[])
    ap.add_argument("--lbs", type=int, default=2, help="Number of Load Balancer threads")
    ap.add_argument("--fps", type=int, default=2, help="Number of Fast Path threads per LB")
    args = ap.parse_args()

    rules = RuleManager()
    for app_name in args.block_app:
        try:
            rules.block_app(AppType[app_name.upper()])
        except KeyError:
            print(f"[Warning] Unknown app type: {app_name}", file=sys.stderr)
    for ip in args.block_ip:
        rules.block_ip(ip)
    for domain in args.block_domain:
        rules.block_domain(domain)

    total_fps = args.lbs * args.fps
    print("=" * 66)
    print(" " * 15 + "DPI ENGINE (Python, multi-threaded)")
    print("=" * 66)
    print(f"Load Balancers: {args.lbs}   FPs per LB: {args.fps}   Total FPs: {total_fps}")
    summary = rules.summary()
    if summary:
        print(summary)

    stats = Stats()

    # One output queue per Fast Path, so the writer can count poison pills
    # and know when every producer is finished.
    fast_paths = []
    fp_out_qs = []
    for fp_id in range(total_fps):
        out_q: "queue.Queue" = queue.Queue()
        fast_paths.append(FastPath(fp_id, queue.Queue(), out_q, rules, stats))
        fp_out_qs.append(out_q)

    load_balancers = []
    for i in range(args.lbs):
        lb_fps = fast_paths[i * args.fps:(i + 1) * args.fps]
        load_balancers.append(LoadBalancer(i, queue.Queue(), lb_fps, stats))

    writer = PcapWriter()
    writer.open(args.output_pcap)

    writer_thread = threading.Thread(
        target=output_writer, args=(fp_out_qs, writer, total_fps), daemon=True
    )

    for fp in fast_paths:
        fp.start()
    for lb in load_balancers:
        lb.start()
    writer_thread.start()

    reader = PcapReader()
    reader.open(args.input_pcap)

    for header, raw in reader:
        parsed = PacketParser.parse(raw)
        stats.incr(total=1, total_bytes=header.incl_len)

        if parsed is None or (not parsed.has_tcp and not parsed.has_udp):
            pkt = Packet(header=header, raw=raw, tuple=None)
            lb_idx = 0
        else:
            stats.incr(**({"tcp": 1} if parsed.has_tcp else {"udp": 1}))
            tuple_ = FiveTuple(
                src_ip=parsed.src_ip, dst_ip=parsed.dst_ip,
                src_port=parsed.src_port, dst_port=parsed.dst_port,
                protocol=parsed.ip_proto,
            )
            pkt = Packet(
                header=header, raw=raw, tuple=tuple_,
                src_ip=parsed.src_ip_str(), dst_port=parsed.dst_port,
                payload=parsed.payload, ip_proto=parsed.ip_proto,
            )
            lb_idx = hash(tuple_) % len(load_balancers)

        load_balancers[lb_idx].in_q.put(pkt)

    reader.close()

    for lb in load_balancers:
        lb.in_q.put(None)  # signal shutdown down the whole pipeline

    writer_thread.join()
    writer.close()

    blocked_app_names = {str(a) for a in rules.blocked_apps}
    print()
    print("=" * 66)
    print(" " * 22 + "PROCESSING REPORT")
    print("=" * 66)
    print(f"Total Packets:  {stats.total}")
    print(f"Total Bytes:    {stats.total_bytes}")
    print(f"TCP Packets:    {stats.tcp}")
    print(f"UDP Packets:    {stats.udp}")
    print("-" * 66)
    print(f"Forwarded:      {stats.forwarded}")
    print(f"Dropped:        {stats.dropped}")
    print("-" * 66)
    print("THREAD STATISTICS")
    for i in sorted(stats.lb_dispatched):
        print(f"  LB{i} dispatched: {stats.lb_dispatched[i]}")
    for i in sorted(stats.fp_processed):
        print(f"  FP{i} processed:  {stats.fp_processed[i]}")
    print("-" * 66)
    print("APPLICATION BREAKDOWN")
    for app, count in sorted(stats.app_stats.items(), key=lambda kv: -kv[1]):
        pct = (count / stats.total * 100) if stats.total else 0
        tag = " (BLOCKED)" if app in blocked_app_names else ""
        print(f"{app:<12} {count:>5}  {pct:5.1f}%{tag}")
    print("=" * 66)

    if stats.detected:
        print("\n[Detected Domains/SNIs]")
        for sni, app in sorted(stats.detected.items()):
            print(f"  - {sni} -> {app}")


if __name__ == "__main__":
    main()
