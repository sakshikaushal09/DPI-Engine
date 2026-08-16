"""
test_sni_extractor.py
Unit tests for dpi/sni_extractor.py - builds minimal but structurally
valid TLS Client Hello / HTTP request payloads in-memory and checks
that the extractor pulls the right hostname out of them.
"""

import os
import sys
import struct
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dpi.sni_extractor import SNIExtractor, HTTPHostExtractor


def _rand_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def build_tls_client_hello(sni: str) -> bytes:
    """Same construction used by generate_test_pcap.py, kept self-contained here
    so this test file has no dependency on the pcap-generation script."""
    server_name = sni.encode("ascii")

    sni_entry = bytes([0x00]) + struct.pack("!H", len(server_name)) + server_name
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    extensions = sni_ext
    extensions_len = struct.pack("!H", len(extensions))

    session_id = b""
    cipher_suites = struct.pack("!H", 2) + b"\x00\x2f"
    compression = b"\x01\x00"

    client_hello_body = (
        b"\x03\x03"
        + _rand_bytes(32)
        + bytes([len(session_id)]) + session_id
        + cipher_suites
        + compression
        + extensions_len + extensions
    )

    handshake_len = struct.pack("!I", len(client_hello_body))[1:]
    handshake = bytes([0x01]) + handshake_len + client_hello_body

    return (
        bytes([0x16]) + b"\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    )


class TestSNIExtractor:
    def test_extracts_youtube_sni(self):
        payload = build_tls_client_hello("www.youtube.com")
        assert SNIExtractor.extract(payload) == "www.youtube.com"

    def test_extracts_various_domains(self):
        for domain in ["github.com", "api.example.org", "a.b.c.tiktok.com"]:
            payload = build_tls_client_hello(domain)
            assert SNIExtractor.extract(payload) == domain

    def test_returns_none_for_non_tls_payload(self):
        assert SNIExtractor.extract(b"not a tls handshake at all") is None

    def test_returns_none_for_short_payload(self):
        assert SNIExtractor.extract(b"\x16\x03\x01") is None

    def test_returns_none_for_non_client_hello_handshake(self):
        # Content type is Handshake (0x16) but handshake type != Client Hello (0x01)
        payload = bytearray(build_tls_client_hello("example.com"))
        payload[5] = 0x02  # Server Hello instead of Client Hello
        assert SNIExtractor.extract(bytes(payload)) is None

    def test_does_not_crash_on_truncated_client_hello(self):
        payload = build_tls_client_hello("example.com")
        truncated = payload[:20]
        # Should return None, never raise
        assert SNIExtractor.extract(truncated) is None


class TestHTTPHostExtractor:
    def test_extracts_host_header(self):
        request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: test\r\n\r\n"
        )
        assert HTTPHostExtractor.extract(request) == "example.com"

    def test_extracts_host_with_post_method(self):
        request = b"POST /login HTTP/1.1\r\nHost: api.service.com\r\n\r\n"
        assert HTTPHostExtractor.extract(request) == "api.service.com"

    def test_returns_none_for_non_http_payload(self):
        assert HTTPHostExtractor.extract(b"\x16\x03\x01random binary") is None

    def test_returns_none_when_no_host_header(self):
        request = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"
        assert HTTPHostExtractor.extract(request) is None
