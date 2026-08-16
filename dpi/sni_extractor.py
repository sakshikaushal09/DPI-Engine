"""
sni_extractor.py
Extracts the destination hostname from:
  - TLS Client Hello (SNI extension)  - for HTTPS traffic
  - Plaintext HTTP requests (Host header) - for HTTP traffic

This works because the SNI field in a TLS handshake is sent in
plaintext, even though everything after the handshake is encrypted -
that plaintext leak is the whole basis for TLS-based DPI.
"""

import struct
from typing import Optional

TLS_CONTENT_TYPE_HANDSHAKE = 0x16
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
TLS_EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00


class SNIExtractor:
    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """Parses a TLS Client Hello and returns the SNI hostname, if present."""
        try:
            if len(payload) < 6:
                return None
            if payload[0] != TLS_CONTENT_TYPE_HANDSHAKE:
                return None
            if payload[5] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
                return None

            # Skip: record header(5) + handshake header(4) + version(2) + random(32)
            offset = 43

            # Session ID
            session_len = payload[offset]
            offset += 1 + session_len

            # Cipher Suites
            cipher_len = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2 + cipher_len

            # Compression Methods
            comp_len = payload[offset]
            offset += 1 + comp_len

            if offset + 2 > len(payload):
                return None

            # Extensions
            ext_total_len = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_total_len

            while offset + 4 <= min(ext_end, len(payload)):
                ext_type, ext_data_len = struct.unpack("!HH", payload[offset:offset + 4])
                offset += 4

                if ext_type == TLS_EXTENSION_SNI:
                    return SNIExtractor._parse_sni_extension(
                        payload[offset:offset + ext_data_len]
                    )

                offset += ext_data_len

            return None
        except (IndexError, struct.error):
            return None

    @staticmethod
    def _parse_sni_extension(data: bytes) -> Optional[str]:
        # server_name_list_len(2) + name_type(1) + name_len(2) + name
        if len(data) < 5:
            return None
        name_type = data[2]
        if name_type != SNI_TYPE_HOSTNAME:
            return None
        name_len = struct.unpack("!H", data[3:5])[0]
        hostname = data[5:5 + name_len]
        try:
            return hostname.decode("ascii")
        except UnicodeDecodeError:
            return None


class HTTPHostExtractor:
    _METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """Extracts the 'Host:' header value from a plaintext HTTP request."""
        if not any(payload.startswith(m) for m in HTTPHostExtractor._METHODS):
            return None

        idx = payload.find(b"Host:")
        if idx == -1:
            return None

        start = idx + len("Host:")
        end = payload.find(b"\r\n", start)
        if end == -1:
            end = payload.find(b"\n", start)
        if end == -1:
            return None

        host = payload[start:end].strip()
        try:
            return host.decode("ascii")
        except UnicodeDecodeError:
            return None
