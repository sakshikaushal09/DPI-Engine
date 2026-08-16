"""
types.py
Core data structures for the DPI Engine: FiveTuple (connection identifier),
AppType (traffic classification), and Flow (per-connection state).
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional
import socket
import struct


class AppType(Enum):
    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    GOOGLE = auto()
    YOUTUBE = auto()
    FACEBOOK = auto()
    INSTAGRAM = auto()
    TIKTOK = auto()
    TWITTER = auto()
    NETFLIX = auto()
    AMAZON = auto()
    GITHUB = auto()
    WHATSAPP = auto()

    def __str__(self) -> str:
        return self.name.capitalize()


@dataclass(frozen=True)
class FiveTuple:
    """Uniquely identifies a network connection (flow): src/dst IP, src/dst port, protocol."""
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int  # 6 = TCP, 17 = UDP

    def __hash__(self) -> int:
        return hash((self.src_ip, self.dst_ip, self.src_port,
                     self.dst_port, self.protocol))

    def src_ip_str(self) -> str:
        return socket.inet_ntoa(struct.pack("!I", self.src_ip))

    def dst_ip_str(self) -> str:
        return socket.inet_ntoa(struct.pack("!I", self.dst_ip))


@dataclass
class Flow:
    """Per-connection state tracked across packets that share a FiveTuple."""
    sni: Optional[str] = None
    app_type: AppType = AppType.UNKNOWN
    blocked: bool = False
    packet_count: int = 0
    byte_count: int = 0


# Substring patterns used to map an SNI / HTTP Host header to a known app.
# Order matters: more specific patterns should come before generic ones
# (e.g. "youtube" before "google").
_SNI_APP_PATTERNS = [
    ("youtube", AppType.YOUTUBE),
    ("googlevideo", AppType.YOUTUBE),
    ("facebook", AppType.FACEBOOK),
    ("fbcdn", AppType.FACEBOOK),
    ("instagram", AppType.INSTAGRAM),
    ("tiktok", AppType.TIKTOK),
    ("twitter", AppType.TWITTER),
    ("netflix", AppType.NETFLIX),
    ("amazon", AppType.AMAZON),
    ("github", AppType.GITHUB),
    ("whatsapp", AppType.WHATSAPP),
    ("google", AppType.GOOGLE),
]


def sni_to_app_type(sni: str) -> AppType:
    """Maps a TLS SNI / HTTP Host string to a known AppType via substring match."""
    lowered = sni.lower()
    for pattern, app in _SNI_APP_PATTERNS:
        if pattern in lowered:
            return app
    return AppType.UNKNOWN
