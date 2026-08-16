#!/usr/bin/env python3
"""
generate_test_pcap.py
Builds a synthetic test_dpi.pcap with Ethernet/IP/TCP/UDP frames: TLS
Client Hellos (carrying an SNI) to a handful of well-known domains, a
couple of plaintext HTTP requests, and a DNS query - so the DPI engine
can be exercised without needing a real network capture.
"""

import os
import random
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dpi.pcap_writer import PcapWriter

SRC_MAC = bytes.fromhex("001122334455")
DST_MAC = bytes.fromhex("aabbccddeeff")
CLIENT_IP = "192.168.1.100"

random.seed(42)  # reproducible test data


def rand_bytes(n: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(n))


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def build_eth_header(dst_mac=DST_MAC, src_mac=SRC_MAC, ethertype=0x0800) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype)


def ip_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def build_ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int,
                     ident: int = 0) -> bytes:
    version_ihl = (4 << 4) | 5
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_len, ident, 0, 64, proto, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
    )
    checksum = ip_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:]


def build_tcp_header(src_port: int, dst_port: int, seq: int, ack: int,
                      flags: int) -> bytes:
    offset_reserved = 5 << 4  # 20-byte header, no options
    # checksum left as 0 - our own reader doesn't validate it, only real
    # network stacks would care
    return struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, offset_reserved, flags,
        65535, 0, 0,
    )


def build_udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    length = 8 + payload_len
    return struct.pack("!HHHH", src_port, dst_port, length, 0)


def build_tls_client_hello(sni: str) -> bytes:
    """Builds a structurally-valid TLS 1.2 Client Hello record with an SNI extension."""
    server_name = sni.encode("ascii")

    sni_entry = bytes([0x00]) + struct.pack("!H", len(server_name)) + server_name
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    extensions = sni_ext
    extensions_len = struct.pack("!H", len(extensions))

    session_id = b""
    cipher_suites = struct.pack("!H", 2) + b"\x00\x2f"  # one cipher suite
    compression = b"\x01\x00"                            # one method: null

    client_hello_body = (
        b"\x03\x03"                       # client_version: TLS 1.2
        + rand_bytes(32)                  # random
        + bytes([len(session_id)]) + session_id
        + cipher_suites
        + compression
        + extensions_len + extensions
    )

    handshake_len = struct.pack("!I", len(client_hello_body))[1:]  # 3-byte length
    handshake = bytes([0x01]) + handshake_len + client_hello_body

    record = (
        bytes([0x16])                       # Content Type: Handshake
        + b"\x03\x01"                       # Record version: TLS 1.0
        + struct.pack("!H", len(handshake))  # Record length
        + handshake
    )
    return record


def build_dns_query(domain: str) -> bytes:
    header = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00" + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def build_http_get(host: str, path: str = "/") -> bytes:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: dpi-test-generator\r\n"
        f"Connection: close\r\n\r\n"
    )
    return request.encode("ascii")


def build_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags,
                      payload: bytes = b"") -> bytes:
    tcp = build_tcp_header(src_port, dst_port, seq, ack, flags) + payload
    ip = build_ip_header(src_ip, dst_ip, 6, len(tcp))
    return build_eth_header() + ip + tcp


def build_udp_packet(src_ip, dst_ip, src_port, dst_port,
                      payload: bytes = b"") -> bytes:
    udp = build_udp_header(src_port, dst_port, len(payload)) + payload
    ip = build_ip_header(src_ip, dst_ip, 17, len(udp))
    return build_eth_header() + ip + udp


TARGET_IPS = {
    "www.youtube.com": "142.250.185.206",
    "www.facebook.com": "31.13.71.36",
    "www.google.com": "142.250.72.14",
    "github.com": "140.82.121.3",
    "www.instagram.com": "157.240.22.174",
    "www.tiktok.com": "23.63.116.10",
    "www.netflix.com": "52.6.24.14",
    "api.whatsapp.com": "157.240.22.60",
}


def main():
    writer = PcapWriter()
    writer.open("test_dpi.pcap")

    ts = 1700000000
    src_port = 40000

    for domain, dst_ip in TARGET_IPS.items():
        src_port += 1
        seq = random.randint(1000, 100000)

        # 3-way TCP handshake (SYN, SYN-ACK, ACK)
        writer.write_packet(ts, 0, build_tcp_packet(
            CLIENT_IP, dst_ip, src_port, 443, seq, 0, 0x02))
        ts += 1
        writer.write_packet(ts, 0, build_tcp_packet(
            dst_ip, CLIENT_IP, 443, src_port, 5000, seq + 1, 0x12))
        ts += 1
        writer.write_packet(ts, 0, build_tcp_packet(
            CLIENT_IP, dst_ip, src_port, 443, seq + 1, 5001, 0x10))
        ts += 1

        # TLS Client Hello - this is where the SNI leaks in plaintext
        client_hello = build_tls_client_hello(domain)
        writer.write_packet(ts, 0, build_tcp_packet(
            CLIENT_IP, dst_ip, src_port, 443, seq + 1, 5001, 0x18, client_hello))
        ts += 1

        # A little "encrypted" application data afterward
        for _ in range(2):
            writer.write_packet(ts, 0, build_tcp_packet(
                CLIENT_IP, dst_ip, src_port, 443,
                seq + 1 + len(client_hello), 5001, 0x18, rand_bytes(64)))
            ts += 1

    # A couple of plaintext HTTP requests
    for domain in ["example.com", "neverssl.com"]:
        src_port += 1
        seq = random.randint(1000, 100000)
        request = build_http_get(domain)
        writer.write_packet(ts, 0, build_tcp_packet(
            CLIENT_IP, "93.184.216.34", src_port, 80, seq, 0, 0x18, request))
        ts += 1

    # A DNS query
    dns_payload = build_dns_query("www.youtube.com")
    writer.write_packet(ts, 0, build_udp_packet(
        CLIENT_IP, "8.8.8.8", 51000, 53, dns_payload))
    ts += 1

    writer.close()
    print("Wrote test_dpi.pcap")


if __name__ == "__main__":
    main()
