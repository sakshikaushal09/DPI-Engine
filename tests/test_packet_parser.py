"""
test_packet_parser.py
Unit tests for dpi/packet_parser.py - builds minimal raw Ethernet/IP/TCP
and Ethernet/IP/UDP frames in-memory and checks the parser extracts the
right fields.
"""

import os
import sys
import socket
import struct

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dpi.packet_parser import PacketParser

SRC_MAC = bytes.fromhex("001122334455")
DST_MAC = bytes.fromhex("aabbccddeeff")


def _ip_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _build_ip_header(src_ip, dst_ip, proto, payload_len):
    version_ihl = (4 << 4) | 5
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_len, 0, 0, 64, proto, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    checksum = _ip_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:]


def build_tcp_frame(src_ip, dst_ip, src_port, dst_port, payload=b"", flags=0x18):
    tcp_header = struct.pack(
        "!HHIIBBHHH", src_port, dst_port, 1000, 2000, 5 << 4, flags, 65535, 0, 0
    )
    tcp = tcp_header + payload
    ip = _build_ip_header(src_ip, dst_ip, 6, len(tcp))
    eth = DST_MAC + SRC_MAC + struct.pack("!H", 0x0800)
    return eth + ip + tcp


def build_udp_frame(src_ip, dst_ip, src_port, dst_port, payload=b""):
    udp_header = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    udp = udp_header + payload
    ip = _build_ip_header(src_ip, dst_ip, 17, len(udp))
    eth = DST_MAC + SRC_MAC + struct.pack("!H", 0x0800)
    return eth + ip + udp


class TestPacketParserTCP:
    def test_parses_src_and_dst_ip(self):
        raw = build_tcp_frame("192.168.1.100", "142.250.185.206", 54321, 443)
        pkt = PacketParser.parse(raw)
        assert pkt.src_ip_str() == "192.168.1.100"
        assert pkt.dst_ip_str() == "142.250.185.206"

    def test_parses_ports(self):
        raw = build_tcp_frame("10.0.0.1", "10.0.0.2", 12345, 443)
        pkt = PacketParser.parse(raw)
        assert pkt.src_port == 12345
        assert pkt.dst_port == 443

    def test_marks_has_tcp(self):
        raw = build_tcp_frame("10.0.0.1", "10.0.0.2", 12345, 443)
        pkt = PacketParser.parse(raw)
        assert pkt.has_tcp is True
        assert pkt.has_udp is False
        assert pkt.ip_proto == 6

    def test_payload_is_extracted(self):
        raw = build_tcp_frame("10.0.0.1", "10.0.0.2", 1234, 80, payload=b"hello world")
        pkt = PacketParser.parse(raw)
        assert pkt.payload == b"hello world"


class TestPacketParserUDP:
    def test_marks_has_udp(self):
        raw = build_udp_frame("192.168.1.5", "8.8.8.8", 51000, 53, payload=b"dnsquery")
        pkt = PacketParser.parse(raw)
        assert pkt.has_udp is True
        assert pkt.has_tcp is False
        assert pkt.ip_proto == 17
        assert pkt.dst_port == 53
        assert pkt.payload == b"dnsquery"


class TestPacketParserEdgeCases:
    def test_returns_none_for_too_short_frame(self):
        assert PacketParser.parse(b"\x00" * 5) is None

    def test_non_ipv4_ethertype_does_not_crash(self):
        # ARP frame (ethertype 0x0806), no IPv4 payload to parse
        raw = DST_MAC + SRC_MAC + struct.pack("!H", 0x0806) + b"\x00" * 20
        pkt = PacketParser.parse(raw)
        assert pkt is not None
        assert pkt.ethertype == 0x0806
