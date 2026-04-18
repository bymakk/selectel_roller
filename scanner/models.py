from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def _string_field(value: object, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


@dataclass
class ScannerSettings:
    username: str
    password: str
    account_id: str
    project_name: str
    project_id: str
    whitelist_path: Path
    state_path: Path
    regions: tuple[str, ...]
    # Секция внутри JSON при общем state-файле (dual: account-1 / account-2; см. MatchStore).
    state_section: str = "account-1"
    target_count: int = 1
    min_batch_size: int = 1
    max_batch_size: int = 1
    delete_concurrency: int = 8
    live_refresh_per_second: int = 6
    allocation_poll_attempts: int = 5
    allocation_poll_delay: float = 0.45
    cooldown_base: float = 1.2
    cooldown_max: float = 15.0
    cleanup_on_exit: bool = True
    cleanup_existing_non_matches: bool = True
    reconcile_interval: float = 7.0
    # 0 = без лимита. Скользящее окно 60 с на все регионы этого процесса (один аккаунт).
    max_floating_ips_per_minute: int = 30

    def __post_init__(self) -> None:
        self.target_count = max(1, int(self.target_count))
        self.min_batch_size = max(1, int(self.min_batch_size))
        self.max_batch_size = max(self.min_batch_size, int(self.max_batch_size))
        self.delete_concurrency = max(1, int(self.delete_concurrency))
        self.live_refresh_per_second = max(1, int(self.live_refresh_per_second))
        self.allocation_poll_attempts = max(1, int(self.allocation_poll_attempts))
        self.allocation_poll_delay = max(0.1, float(self.allocation_poll_delay))
        self.cooldown_base = max(0.0, float(self.cooldown_base))
        self.cooldown_max = max(self.cooldown_base, float(self.cooldown_max))
        self.cleanup_on_exit = bool(self.cleanup_on_exit)
        self.cleanup_existing_non_matches = bool(self.cleanup_existing_non_matches)
        self.reconcile_interval = max(0.0, float(self.reconcile_interval))
        self.max_floating_ips_per_minute = max(0, int(self.max_floating_ips_per_minute))
        self.state_section = (self.state_section or "account-1").strip() or "account-1"

    @property
    def min_seconds_per_floating_ip(self) -> float | None:
        """Минимальный средний интервал между выдачами IP при лимите (60 / cap)."""
        if self.max_floating_ips_per_minute <= 0:
            return None
        return 60.0 / float(self.max_floating_ips_per_minute)


@dataclass
class FloatingIPRecord:
    id: str
    address: str
    region: str
    project_id: str = ""
    status: str = ""
    fixed_ip_address: str = ""
    port_id: str = ""
    source: str = "api"

    @classmethod
    def from_payload(cls, payload: dict[str, object], source: str = "api") -> "FloatingIPRecord":
        return cls(
            id=_string_field(payload.get("id")),
            address=_string_field(payload.get("floating_ip_address")),
            region=_string_field(payload.get("region")),
            project_id=_string_field(payload.get("project_id")),
            status=_string_field(payload.get("status")),
            fixed_ip_address=_string_field(payload.get("fixed_ip_address")),
            port_id=_string_field(payload.get("port_id")),
            source=source,
        )

    def resource_ref(self) -> str:
        short_id = self.id[:8] if self.id else "unknown"
        if self.address:
            return f"{self.address} (id={short_id})"
        return f"id={short_id}"


@dataclass
class MatchRecord:
    id: str
    address: str
    region: str
    project_id: str = ""
    source: str = "allocated"
    discovered_at: str = ""

    @classmethod
    def from_floating_ip(
        cls,
        floating_ip: FloatingIPRecord,
        source: str = "allocated",
    ) -> "MatchRecord":
        return cls(
            id=floating_ip.id,
            address=floating_ip.address,
            region=floating_ip.region,
            project_id=floating_ip.project_id,
            source=source,
            discovered_at=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def from_payload(cls, payload: dict[str, object]) -> "MatchRecord":
        return cls(
            id=_string_field(payload.get("id")),
            address=_string_field(payload.get("address")),
            region=_string_field(payload.get("region")),
            project_id=_string_field(payload.get("project_id")),
            source=_string_field(payload.get("source"), "allocated") or "allocated",
            discovered_at=_string_field(payload.get("discovered_at")),
        )

    def to_payload(self) -> dict[str, str]:
        return {
            "id": self.id,
            "address": self.address,
            "region": self.region,
            "project_id": self.project_id,
            "source": self.source,
            "discovered_at": self.discovered_at,
        }

    def resource_ref(self) -> str:
        short_id = self.id[:8] if self.id else "unknown"
        return f"{self.address} (id={short_id}, {self.region})"


@dataclass
class EventRecord:
    level: str
    message: str
    created_at: datetime

    @classmethod
    def create(cls, level: str, message: str) -> "EventRecord":
        return cls(level=level, message=message, created_at=datetime.now(timezone.utc))

    def timestamp(self) -> str:
        return self.created_at.astimezone().strftime("%H:%M:%S")


@dataclass
class RegionRunState:
    region: str
    batch_size: int
    batches: int = 0
    allocations: int = 0
    matches: int = 0
    misses: int = 0
    duplicates: int = 0
    deleted: int = 0
    errors: int = 0
    inflight: int = 0
    cooldown_until: float = 0.0
    backoff_seconds: float = 0.0
    consecutive_matches: int = 0
    consecutive_misses: int = 0
    last_ip: str = ""
    last_result: str = "idle"
    last_error: str = ""

    def hit_rate(self) -> float:
        if self.allocations <= 0:
            return 0.0
        return (self.matches / self.allocations) * 100.0

    def cooldown_remaining(self, now: float) -> float:
        return max(0.0, self.cooldown_until - now)
