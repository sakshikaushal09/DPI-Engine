#!/usr/bin/env python3
"""
live_sniffer.py
Optional live-capture mode for the DPI engine: sniffs packets straight
off a real network interface instead of reading a saved .pcap file,
using scapy for the actual capture, then reuses the exact same
dpi/packet_parser.py, dpi/sni_extractor.py, and dpi/rule_manager.py
logic as the rest of this project.

This is a separate script on purpose - main_simple.py and dpi_mt.py
stay untouched and keep working exactly as before, whether or not
scapy is installed.

Setup:
    pip install -r requirements-live.txt

    Linux/macOS: you'll need root/sudo to open a raw socket:
        sudo python3 live_sniffer.py --iface eth0

    Windows: install Npcap (https://npcap.com) first, then run the
        script from an Administrator terminal:
        python live_sniffer.py --iface "Wi-Fi"

Usage:
    python3 live_sniffer.py --iface eth0 \
        --block-app YouTube --block-domain tiktok --count 200

    (Omit --count to sniff until Ctrl+C.)
"""

import argparse
import sys
from collections import defaultdict

from dpi.packet_parser import PacketParser
from dpi.sni_extractor import SNIExtractor, HTTPHostExtractor
from dpi.rule_manager import RuleManager
from dpi.types import FiveTuple, Flow, AppType, sni_to_app_type

try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def classify_flow(pkt, flow: Flow) -> None:
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


class LiveEngine:
    """Holds flow state + counters across the whole capture session."""

    def __init__(self, rules: RuleManager):
        self.rules = rules
        self.flows = {}
        self.total = self.tcp = self.udp = self.forwarded = self.dropped = 0
        self.app_stats = defaultdict(int)
        self.detected = {}

    def handle_raw_frame(self, raw_bytes: bytes) -> None:
        self.total += 1
        pkt = PacketParser.parse(raw_bytes)
        if pkt is None or (not pkt.has_tcp and not pkt.has_udp):
            self.forwarded += 1
            return

        if pkt.has_tcp:
            self.tcp += 1
        else:
            self.udp += 1

        tuple_ = FiveTuple(
            src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
            src_port=pkt.src_port, dst_port=pkt.dst_port,
            protocol=pkt.ip_proto,
        )
        flow = self.flows.setdefault(tuple_, Flow())
        flow.packet_count += 1

        was_classified = bool(flow.sni)
        classify_flow(pkt, flow)

        if flow.sni and not was_classified:
            self.detected[flow.sni] = str(flow.app_type)
            print(f"[+] {pkt.src_ip_str():15s} -> {flow.sni:30s} ({flow.app_type})")

        if not flow.blocked and self.rules.is_blocked(
            pkt.src_ip_str(), flow.app_type, flow.sni
        ):
            flow.blocked = True
            print(f"[BLOCKED] {pkt.src_ip_str()} -> {flow.sni or pkt.dst_ip_str()} ({flow.app_type})")

        self.app_stats[str(flow.app_type)] += 1

        if flow.blocked:
            self.dropped += 1
        else:
            self.forwarded += 1

    def print_report(self, blocked_app_names):
        print()
        print("=" * 66)
        print(" " * 22 + "LIVE CAPTURE REPORT")
        print("=" * 66)
        print(f"Total Packets:  {self.total}")
        print(f"TCP / UDP:      {self.tcp} / {self.udp}")
        print(f"Forwarded:      {self.forwarded}")
        print(f"Dropped:        {self.dropped}")
        print("-" * 66)
        print("APPLICATION BREAKDOWN")
        for app, count in sorted(self.app_stats.items(), key=lambda kv: -kv[1]):
            pct = (count / self.total * 100) if self.total else 0
            tag = " (BLOCKED)" if app in blocked_app_names else ""
            print(f"{app:<12} {count:>5}  {pct:5.1f}%{tag}")
        print("=" * 66)
        if self.detected:
            print("\n[Detected Domains/SNIs]")
            for sni, app in sorted(self.detected.items()):
                print(f"  - {sni} -> {app}")


def main():
    ap = argparse.ArgumentParser(description="Live packet capture DPI (requires scapy)")
    ap.add_argument("--iface", required=True, help="Network interface to sniff, e.g. eth0 or 'Wi-Fi'")
    ap.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = run until Ctrl+C)")
    ap.add_argument("--block-app", action="append", default=[])
    ap.add_argument("--block-ip", action="append", default=[])
    ap.add_argument("--block-domain", action="append", default=[])
    args = ap.parse_args()

    if not SCAPY_AVAILABLE:
        print("[Error] scapy is not installed.", file=sys.stderr)
        print("        Install it with: pip install -r requirements-live.txt", file=sys.stderr)
        print("        On Windows you also need Npcap: https://npcap.com", file=sys.stderr)
        sys.exit(1)

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

    engine = LiveEngine(rules)
    blocked_app_names = {str(a) for a in rules.blocked_apps}

    print("=" * 66)
    print(" " * 18 + "DPI ENGINE - LIVE CAPTURE MODE")
    print("=" * 66)
    print(f"Interface: {args.iface}")
    summary = rules.summary()
    if summary:
        print(summary)
    print("Press Ctrl+C to stop and see the report.\n")

    def on_packet(scapy_pkt):
        try:
            engine.handle_raw_frame(bytes(scapy_pkt))
        except Exception as e:  # never let a single malformed frame kill the capture
            print(f"[Warning] failed to parse a frame: {e}", file=sys.stderr)

    try:
        sniff(
            iface=args.iface,
            prn=on_packet,
            store=False,
            count=args.count if args.count > 0 else 0,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(
            "\n[Error] Permission denied opening the interface.\n"
            "        Linux/macOS: re-run with sudo.\n"
            "        Windows: run from an Administrator terminal and make sure Npcap is installed.",
            file=sys.stderr,
        )
        sys.exit(1)

    engine.print_report(blocked_app_names)


if __name__ == "__main__":
    main()
