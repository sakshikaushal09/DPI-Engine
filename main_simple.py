#!/usr/bin/env python3
"""
main_simple.py
Single-threaded DPI engine - reads a PCAP, classifies flows by SNI/Host,
applies blocking rules, and writes the allowed packets to an output PCAP.

Usage:
    python3 main_simple.py input.pcap output.pcap \
        --block-app YouTube --block-app TikTok \
        --block-ip 192.168.1.50 --block-domain facebook
"""

import argparse
import sys
from collections import defaultdict

from dpi.pcap_reader import PcapReader
from dpi.pcap_writer import PcapWriter
from dpi.packet_parser import PacketParser, IP_PROTO_UDP
from dpi.sni_extractor import SNIExtractor, HTTPHostExtractor
from dpi.rule_manager import RuleManager
from dpi.types import FiveTuple, Flow, AppType, sni_to_app_type


def build_five_tuple(pkt) -> FiveTuple:
    return FiveTuple(
        src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
        src_port=pkt.src_port, dst_port=pkt.dst_port,
        protocol=pkt.ip_proto,
    )


def classify_flow(pkt, flow: Flow) -> None:
    """Attempts SNI (HTTPS) or Host header (HTTP) extraction on this packet."""
    if flow.sni:
        return  # already classified for this flow

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

    if pkt.ip_proto == IP_PROTO_UDP and pkt.dst_port == 53:
        flow.app_type = AppType.DNS


def print_report(total, total_bytes, tcp_count, udp_count,
                  forwarded, dropped, app_stats, blocked_apps, detected):
    def bar(pct):
        return "#" * int(pct / 5)

    print()
    print("=" * 66)
    print(" " * 22 + "PROCESSING REPORT")
    print("=" * 66)
    print(f"Total Packets:   {total}")
    print(f"Total Bytes:     {total_bytes}")
    print(f"TCP Packets:     {tcp_count}")
    print(f"UDP Packets:     {udp_count}")
    print("-" * 66)
    print(f"Forwarded:       {forwarded}")
    print(f"Dropped:         {dropped}")
    print("-" * 66)
    print(" " * 20 + "APPLICATION BREAKDOWN")
    print("-" * 66)
    for app, count in sorted(app_stats.items(), key=lambda kv: -kv[1]):
        pct = (count / total * 100) if total else 0
        tag = " (BLOCKED)" if app in blocked_apps else ""
        print(f"{app:<12} {count:>5}  {pct:5.1f}% {bar(pct)}{tag}")
    print("=" * 66)

    if detected:
        print("\n[Detected Domains/SNIs]")
        for sni, app in sorted(detected.items()):
            print(f"  - {sni} -> {app}")


def main():
    ap = argparse.ArgumentParser(description="Single-threaded DPI engine")
    ap.add_argument("input_pcap")
    ap.add_argument("output_pcap")
    ap.add_argument("--block-app", action="append", default=[],
                     help="App name to block, e.g. YouTube (repeatable)")
    ap.add_argument("--block-ip", action="append", default=[],
                     help="Source IP to block (repeatable)")
    ap.add_argument("--block-domain", action="append", default=[],
                     help="Domain substring to block, e.g. tiktok (repeatable)")
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

    print("=" * 66)
    print(" " * 15 + "DPI ENGINE (Python, single-threaded)")
    print("=" * 66)
    summary = rules.summary()
    if summary:
        print(summary)

    reader = PcapReader()
    reader.open(args.input_pcap)
    writer = PcapWriter()
    writer.open(args.output_pcap)

    flows = {}
    total = total_bytes = tcp_count = udp_count = forwarded = dropped = 0
    app_stats = defaultdict(int)
    detected = {}

    for header, raw in reader:
        total += 1
        total_bytes += header.incl_len

        pkt = PacketParser.parse(raw)
        if pkt is None or (not pkt.has_tcp and not pkt.has_udp):
            forwarded += 1
            writer.write_packet(header.ts_sec, header.ts_usec, raw)
            continue

        if pkt.has_tcp:
            tcp_count += 1
        else:
            udp_count += 1

        tuple_ = build_five_tuple(pkt)
        flow = flows.setdefault(tuple_, Flow())
        flow.packet_count += 1
        flow.byte_count += header.incl_len

        classify_flow(pkt, flow)

        if flow.sni and flow.sni not in detected:
            detected[flow.sni] = str(flow.app_type)

        if not flow.blocked and rules.is_blocked(
            pkt.src_ip_str(), flow.app_type, flow.sni
        ):
            flow.blocked = True

        app_stats[str(flow.app_type)] += 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            writer.write_packet(header.ts_sec, header.ts_usec, raw)

    reader.close()
    writer.close()

    blocked_app_names = {str(a) for a in rules.blocked_apps}
    print_report(total, total_bytes, tcp_count, udp_count,
                 forwarded, dropped, app_stats, blocked_app_names, detected)


if __name__ == "__main__":
    main()
