"""
packet_parser.py
Parses Ethernet / IPv4 / TCP / UDP headers from raw packet bytes.

A packet is like a set of Russian nesting dolls - headers wrapped inside
headers:

    Ethernet Header (14 bytes)
      IP Header (>= 20 bytes)
        TCP/UDP Header (>= 8-20 bytes)
          Payload (application data, e.g. TLS Client Hello)
"""

import struct
import socket
from dataclasses import dataclass
from typing import Optional

ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


@dataclass
class ParsedPacket:
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: int = 0

    src_ip: int = 0
    dst_ip: int = 0
    ip_proto: int = 0
    ttl: int = 0
    ip_header_len: int = 0

    src_port: int = 0
    dst_port: int = 0
    tcp_flags: int = 0
    has_tcp: bool = False
    has_udp: bool = False

    payload_offset: int = 0
    payload: bytes = b""

    def src_ip_str(self) -> str:
        return socket.inet_ntoa(struct.pack("!I", self.src_ip))

    def dst_ip_str(self) -> str:
        return socket.inet_ntoa(struct.pack("!I", self.dst_ip))


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


class PacketParser:
    """Stateless parser: raw bytes in, ParsedPacket out."""

    @staticmethod
    def parse(raw: bytes) -> Optional[ParsedPacket]:
        if len(raw) < ETH_HEADER_LEN:
            return None

        pkt = ParsedPacket()
        pkt.dst_mac = _format_mac(raw[0:6])
        pkt.src_mac = _format_mac(raw[6:12])
        pkt.ethertype = struct.unpack("!H", raw[12:14])[0]

        offset = ETH_HEADER_LEN

        if pkt.ethertype != ETHERTYPE_IPV4:
            return pkt  # Non-IPv4 (ARP, IPv6, ...) - caller decides what to do

        if len(raw) < offset + 20:
            return pkt

        PacketParser._parse_ipv4(raw, offset, pkt)
        ip_offset = offset + pkt.ip_header_len

        if pkt.ip_proto == IP_PROTO_TCP and len(raw) >= ip_offset + 20:
            PacketParser._parse_tcp(raw, ip_offset, pkt)
        elif pkt.ip_proto == IP_PROTO_UDP and len(raw) >= ip_offset + 8:
            PacketParser._parse_udp(raw, ip_offset, pkt)
        else:
            pkt.payload_offset = ip_offset
            pkt.payload = raw[ip_offset:]

        return pkt

    @staticmethod
    def _parse_ipv4(raw: bytes, offset: int, pkt: ParsedPacket) -> None:
        version_ihl = raw[offset]
        ihl = (version_ihl & 0x0F) * 4  # header length in bytes
        pkt.ip_header_len = ihl
        pkt.ttl = raw[offset + 8]
        pkt.ip_proto = raw[offset + 9]
        pkt.src_ip = struct.unpack("!I", raw[offset + 12:offset + 16])[0]
        pkt.dst_ip = struct.unpack("!I", raw[offset + 16:offset + 20])[0]

    @staticmethod
    def _parse_tcp(raw: bytes, offset: int, pkt: ParsedPacket) -> None:
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", raw[offset:offset + 4])
        data_offset_flags = struct.unpack("!H", raw[offset + 12:offset + 14])[0]
        tcp_header_len = ((data_offset_flags >> 12) & 0x0F) * 4
        pkt.tcp_flags = data_offset_flags & 0x3F
        pkt.has_tcp = True
        payload_offset = offset + max(tcp_header_len, 20)
        pkt.payload_offset = payload_offset
        pkt.payload = raw[payload_offset:]

    @staticmethod
    def _parse_udp(raw: bytes, offset: int, pkt: ParsedPacket) -> None:
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", raw[offset:offset + 4])
        pkt.has_udp = True
        payload_offset = offset + 8
        pkt.payload_offset = payload_offset
        pkt.payload = raw[payload_offset:]
