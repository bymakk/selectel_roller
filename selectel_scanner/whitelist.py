from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from .paths import DEFAULT_WHITELIST_PATH


def load_selectel_default_ranges(path: Path = DEFAULT_WHITELIST_PATH) -> list[str]:
    if not path.exists():
        return []

    entries: list[str] = []
    seen: set[str] = set()

    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            value = raw_line.strip()
            if not value or value.startswith("#"):
                continue

            try:
                normalized = str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue

            if normalized in seen:
                continue

            seen.add(normalized)
            entries.append(value)
    except OSError:
        return []

    return entries


@dataclass
class WhitelistSummary:
    total_entries: int = 0
    network_entries: int = 0
    single_ip_entries: int = 0


class WhitelistMatcher:
    def __init__(self, entries: list[str] | None = None):
        self._networks: list[ipaddress.IPv4Network] = []
        self._ips: set[str] = set()
        self._summary = WhitelistSummary()
        self._load_entries(entries or [])

    @classmethod
    def from_path(cls, path: Path | None = None) -> "WhitelistMatcher":
        source_path = path or DEFAULT_WHITELIST_PATH
        if source_path.exists():
            raw_entries = source_path.read_text(encoding="utf-8").splitlines()
        else:
            raw_entries = load_selectel_default_ranges()
        return cls([entry.strip() for entry in raw_entries])

    def _load_entries(self, entries: list[str]) -> None:
        seen: set[str] = set()
        for raw_entry in entries:
            entry = raw_entry.strip()
            if not entry or entry.startswith("#"):
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue

            normalized = str(network)
            if normalized in seen:
                continue
            seen.add(normalized)
            self._summary.total_entries += 1

            if network.prefixlen == network.max_prefixlen:
                self._ips.add(str(network.network_address))
                self._summary.single_ip_entries += 1
            else:
                self._networks.append(network)
                self._summary.network_entries += 1

    @property
    def summary(self) -> WhitelistSummary:
        return self._summary

    def contains(self, ip_address: str) -> bool:
        candidate = ip_address.strip()
        if candidate in self._ips:
            return True
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return any(address in network for network in self._networks)
