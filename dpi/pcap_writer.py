"""
pcap_writer.py
Minimal PCAP file writer, format-compatible with pcap_reader.py (and
with Wireshark) - little-endian, Ethernet link-layer.
"""

import struct
from .pcap_reader import GLOBAL_HEADER_FMT, PACKET_HEADER_FMT, PCAP_MAGIC_LE


class PcapWriter:
    def __init__(self, snaplen: int = 65535, linktype: int = 1):
        self._file = None
        self.snaplen = snaplen
        self.linktype = linktype  # 1 = Ethernet

    def open(self, filename: str) -> None:
        self._file = open(filename, "wb")
        header = struct.pack(
            "<" + GLOBAL_HEADER_FMT,
            PCAP_MAGIC_LE, 2, 4, 0, 0, self.snaplen, self.linktype,
        )
        self._file.write(header)

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes) -> None:
        header = struct.pack(
            "<" + PACKET_HEADER_FMT, ts_sec, ts_usec, len(data), len(data)
        )
        self._file.write(header)
        self._file.write(data)

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
