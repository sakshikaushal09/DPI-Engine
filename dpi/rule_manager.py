"""
rule_manager.py
Holds and evaluates blocking rules: by source IP, by AppType, or by
domain substring match against the extracted SNI / Host header.
"""

from typing import Optional, Set, List
from .types import AppType


class RuleManager:
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.blocked_apps: Set[AppType] = set()
        self.blocked_domains: List[str] = []

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(ip)

    def block_app(self, app: AppType) -> None:
        self.blocked_apps.add(app)

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain.lower())

    def is_blocked(self, src_ip: str, app_type: AppType,
                    sni: Optional[str]) -> bool:
        if src_ip in self.blocked_ips:
            return True

        if app_type in self.blocked_apps:
            return True

        if sni:
            lowered = sni.lower()
            for domain in self.blocked_domains:
                if domain in lowered:
                    return True

        return False

    def summary(self) -> str:
        lines = []
        for ip in sorted(self.blocked_ips):
            lines.append(f"[Rules] Blocked IP: {ip}")
        for app in self.blocked_apps:
            lines.append(f"[Rules] Blocked app: {app}")
        for dom in self.blocked_domains:
            lines.append(f"[Rules] Blocked domain: {dom}")
        return "\n".join(lines)
