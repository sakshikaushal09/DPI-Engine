"""
pcap_reader.py
Minimal PCAP (libpcap) file reader - no external dependencies.

PCAP file layout:
    [Global Header (24 bytes)]
    [Packet Header (16 bytes)][Packet Data]
    [Packet Header (16 bytes)][Packet Data]
    ...
"""

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1

# magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network
GLOBAL_HEADER_FMT = "IHHiIII"
GLOBAL_HEADER_LEN = struct.calcsize(GLOBAL_HEADER_FMT)

# ts_sec, ts_usec, incl_len, orig_len
PACKET_HEADER_FMT = "IIII"
PACKET_HEADER_LEN = struct.calcsize(PACKET_HEADER_FMT)


@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


class PcapReader:
    """Reads packets one at a time from a .pcap file."""

    def __init__(self):
        self._file = None
        self.byte_order = "<"  # '<' little-endian, '>' big-endian
        self.linktype = 1      # 1 = Ethernet

    def open(self, filename: str) -> None:
        self._file = open(filename, "rb")
        raw = self._file.read(GLOBAL_HEADER_LEN)
        if len(raw) < GLOBAL_HEADER_LEN:
            raise ValueError(f"{filename} is not a valid PCAP file (too short)")

        magic = struct.unpack("<I", raw[:4])[0]
        if magic == PCAP_MAGIC_LE:
            self.byte_order = "<"
        elif magic == PCAP_MAGIC_BE:
            self.byte_order = ">"
        else:
            raise ValueError(f"{filename}: bad magic number 0x{magic:08x}")

        fields = struct.unpack(self.byte_order + GLOBAL_HEADER_FMT, raw)
        self.linktype = fields[6]

    def read_next_packet(self) -> Optional[Tuple[PcapPacketHeader, bytes]]:
        """Returns (PcapPacketHeader, bytes) for the next packet, or None at EOF."""
        raw_header = self._file.read(PACKET_HEADER_LEN)
        if len(raw_header) < PACKET_HEADER_LEN:
            return None
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            self.byte_order + PACKET_HEADER_FMT, raw_header
        )
        data = self._file.read(incl_len)
        if len(data) < incl_len:
            return None
        header = PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len)
        return header, data

    def __iter__(self):
        while True:
            result = self.read_next_packet()
            if result is None:
                return
            yield result

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
