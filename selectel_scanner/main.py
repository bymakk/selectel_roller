from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from .client import SelectelScannerClient
from .config import ScannerConfig, load_scanner_config
from .dashboard import build_dashboard
from .models import EventRecord, FloatingIPRecord, MatchRecord, RegionRunState, ScannerSettings
from .paths import TEMP_DIR
from .state import MatchStore
from .strategy import apply_batch_result, apply_error
from .whitelist import DEFAULT_WHITELIST_PATH, WhitelistMatcher


class SelectelScannerApp:
    def __init__(
        self,
        settings: ScannerSettings,
        *,
        console: Console | None = None,
        interactive: bool | None = None,
        emit_console_output: bool = True,
        emit_summary: bool = True,
    ):
        self.settings = settings
        self.console = console or Console()
        detected_interactive = self.console.is_terminal and sys.stdout.isatty()
        self.interactive = detected_interactive if interactive is None else interactive
        self.emit_console_output = emit_console_output
        self.emit_summary = emit_summary
        self.matcher = WhitelistMatcher.from_path(settings.whitelist_path)
        self.client = SelectelScannerClient(
            username=settings.username,
            password=settings.password,
            account_id=settings.account_id,
            project_name=settings.project_name,
            project_id=settings.project_id,
            regions=settings.regions,
        )
        self.match_store = MatchStore(settings.state_path)
        self.persisted_matches = self.match_store.load()
        self.matches: dict[str, MatchRecord] = {}
        self.owned_unmatched: dict[str, FloatingIPRecord] = {}
        self.seen_non_match_ips: set[str] = set()
        self.region_states = {
            region: RegionRunState(region=region, batch_size=settings.min_batch_size)
            for region in settings.regions
        }
        self.events: deque[EventRecord] = deque(maxlen=16)
        self.delete_semaphore = asyncio.Semaphore(settings.delete_concurrency)
        self.reconcile_lock = asyncio.Lock()
        self.stop_event = asyncio.Event()
        self.started_at = time.monotonic()
        self.project_id = settings.project_id
        self.project_label = settings.project_name or settings.project_id or "project-scoped"
        # Статистика по выданным IP (каждое появление в батче считается отдельно)
        self._allocation_ip_counts: dict[str, int] = {}
        self._miss_ip_counts: dict[str, int] = {}
        self._rate_samples: deque[tuple[float, int]] = deque()
        # Успешные DELETE по промахам — уникальные адреса (глобально и по региону)
        self._deleted_miss_addresses: set[str] = set()
        self._alloc_addrs_by_region: dict[str, set[str]] = defaultdict(set)
        self._deleted_miss_addrs_by_region: dict[str, set[str]] = defaultdict(set)

    def unique_allocated_ip_count(self) -> int:
        return len(self._allocation_ip_counts)

    def total_allocation_events(self) -> int:
        return sum(self._allocation_ip_counts.values())

    def allocations_per_minute_recent(self) -> float:
        """Сколько раз выдали IP за последние ~60 с (скорость «перебора»)."""
        now = time.monotonic()
        while self._rate_samples and now - self._rate_samples[0][0] > 60.0:
            self._rate_samples.popleft()
        return float(sum(n for _, n in self._rate_samples))

    def miss_ip_counts_snapshot(self) -> dict[str, int]:
        return dict(self._miss_ip_counts)

    def distinct_allocated_ips(self) -> set[str]:
        return set(self._allocation_ip_counts.keys())

    def deleted_miss_address_set(self) -> set[str]:
        return set(self._deleted_miss_addresses)

    def unique_alloc_by_region(self, region: str) -> int:
        return len(self._alloc_addrs_by_region.get(region, ()))

    def unique_deleted_miss_by_region(self, region: str) -> int:
        return len(self._deleted_miss_addrs_by_region.get(region, ()))

    def _record_allocation_batch(self, records: list[FloatingIPRecord], region: str) -> None:
        now = time.monotonic()
        batch = 0
        for record in records:
            addr = record.address.strip()
            if not addr:
                continue
            self._allocation_ip_counts[addr] = self._allocation_ip_counts.get(addr, 0) + 1
            self._alloc_addrs_by_region[region].add(addr)
            batch += 1
        if batch:
            self._rate_samples.append((now, batch))
            while self._rate_samples and now - self._rate_samples[0][0] > 60.0:
                self._rate_samples.popleft()

    def _record_miss_hits(self, misses: list[FloatingIPRecord]) -> None:
        for record in misses:
            addr = record.address.strip()
            if not addr:
                continue
            self._miss_ip_counts[addr] = self._miss_ip_counts.get(addr, 0) + 1

    def log(self, level: str, message: str) -> None:
        self.events.append(EventRecord.create(level, message))
        if not self.interactive and self.emit_console_output:
            style = {
                "info": "white",
                "warning": "yellow",
                "error": "red",
                "success": "green",
            }.get(level, "white")
            self.console.print(f"[{style}]{level.upper()}[/{style}] {message}")

    async def run(self) -> int:
        try:
            if self.emit_console_output:
                with self.console.status("[bold cyan]Authenticating with Selectel..."):
                    await self.client.ensure_authenticated()
                    self.project_id = self.client.project_id
                    if self.project_id:
                        self.project_label = self.settings.project_name or self.project_id
            else:
                await self.client.ensure_authenticated()
                self.project_id = self.client.project_id
                if self.project_id:
                    self.project_label = self.settings.project_name or self.project_id

            self.log("success", "Authenticated with project-scoped Selectel token")
            self.log("info", f"Using project {self.project_label}")

            existing = await self.client.list_floating_ips(regions=set(self.settings.regions))
            existing = await self._cleanup_existing_non_matches(existing, reason="startup")
            await self._adopt_existing_inventory(existing)
            if len(self.matches) >= self.settings.target_count:
                self.log("success", "Target count already satisfied by existing floating IPs")
                return 0

            workers = [asyncio.create_task(self._region_worker(region)) for region in self.settings.regions]
            reconciler: asyncio.Task[None] | None = None
            if self.settings.reconcile_interval > 0:
                reconciler = asyncio.create_task(self._run_reconciler())
            try:
                if self.interactive:
                    with Live(
                        build_dashboard(
                            settings=self.settings,
                            whitelist_summary=self.matcher.summary,
                            regions=list(self.region_states.values()),
                            matches=self.matches,
                            events=self.events,
                            started_at=self.started_at,
                            project_label=self.project_label,
                            unique_ips=self.unique_allocated_ip_count(),
                            ips_per_minute=self.allocations_per_minute_recent(),
                            miss_ip_counts=self.miss_ip_counts_snapshot(),
                            delete_unique_addrs=len(self._deleted_miss_addresses),
                            region_alloc_unique={
                                r: self.unique_alloc_by_region(r) for r in self.region_states
                            },
                            region_del_unique={
                                r: self.unique_deleted_miss_by_region(r) for r in self.region_states
                            },
                        ),
                        console=self.console,
                        screen=True,
                        refresh_per_second=self.settings.live_refresh_per_second,
                    ) as live:
                        while not self.stop_event.is_set():
                            if len(self.matches) >= self.settings.target_count:
                                self.stop_event.set()
                                break
                            live.update(
                                build_dashboard(
                                    settings=self.settings,
                                    whitelist_summary=self.matcher.summary,
                                    regions=list(self.region_states.values()),
                                    matches=self.matches,
                                    events=self.events,
                                    started_at=self.started_at,
                                    project_label=self.project_label,
                                    unique_ips=self.unique_allocated_ip_count(),
                                    ips_per_minute=self.allocations_per_minute_recent(),
                                    miss_ip_counts=self.miss_ip_counts_snapshot(),
                                    delete_unique_addrs=len(self._deleted_miss_addresses),
                                    region_alloc_unique={
                                        r: self.unique_alloc_by_region(r) for r in self.region_states
                                    },
                                    region_del_unique={
                                        r: self.unique_deleted_miss_by_region(r) for r in self.region_states
                                    },
                                )
                            )
                            await asyncio.sleep(1.0 / self.settings.live_refresh_per_second)
                else:
                    while not self.stop_event.is_set():
                        if len(self.matches) >= self.settings.target_count:
                            self.stop_event.set()
                            break
                        await asyncio.sleep(1.0 / self.settings.live_refresh_per_second)
            finally:
                self.stop_event.set()
                tasks = [*workers]
                if reconciler is not None:
                    tasks.append(reconciler)
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

            return 0
        finally:
            await self._cleanup_owned_unmatched()
            self.match_store.save(self.matches)
            await self.client.close()
            if self.emit_summary:
                self._print_summary()

    async def _cleanup_existing_non_matches(
        self,
        existing_records: list[FloatingIPRecord],
        *,
        reason: str,
    ) -> list[FloatingIPRecord]:
        if not self.settings.cleanup_existing_non_matches:
            return existing_records

        cleanup_candidates = self._cleanup_candidates(existing_records)
        preserved_non_matches = [
            record
            for record in existing_records
            if not self.matcher.contains(record.address) and record not in cleanup_candidates
        ]

        if preserved_non_matches:
            self.log(
                "info",
                f"Preserving {len(preserved_non_matches)} existing bound non-match floating IP(s)",
            )

        if not cleanup_candidates:
            return existing_records

        self.log(
            "warning",
            f"Deleting {len(cleanup_candidates)} existing unbound non-match floating IP(s)",
        )
        deleted_count = await self._delete_records("startup", cleanup_candidates, reason=reason)
        self.log(
            "info",
            f"Startup cleanup removed {deleted_count}/{len(cleanup_candidates)} stale non-match floating IP(s)",
        )
        return await self.client.list_floating_ips(regions=set(self.settings.regions))

    def _is_existing_cleanup_candidate(self, record: FloatingIPRecord) -> bool:
        if self.matcher.contains(record.address):
            return False
        return not record.port_id and not record.fixed_ip_address

    def _cleanup_candidates(self, records: list[FloatingIPRecord]) -> list[FloatingIPRecord]:
        return [record for record in records if self._is_existing_cleanup_candidate(record)]

    async def _run_reconciler(self) -> None:
        while not self.stop_event.is_set():
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=self.settings.reconcile_interval)
                break
            except asyncio.TimeoutError:
                pass
            await self._reconcile_unbound_non_matches(reason="periodic")

    async def _reconcile_unbound_non_matches(
        self,
        *,
        reason: str,
        regions: set[str] | None = None,
    ) -> int:
        async with self.reconcile_lock:
            target_regions = regions or set(self.settings.regions)
            records = await self.client.list_floating_ips(regions=target_regions)
            cleanup_candidates = self._cleanup_candidates(records)
            if not cleanup_candidates:
                return 0

            region_list = ", ".join(sorted({record.region for record in cleanup_candidates}))
            self.log(
                "warning",
                f"[reconcile] deleting {len(cleanup_candidates)} stale non-match floating IP(s) in {region_list}",
            )
            deleted_count = await self._delete_records("reconcile", cleanup_candidates, reason=reason)
            self.log(
                "info",
                f"[reconcile] removed {deleted_count}/{len(cleanup_candidates)} stale non-match floating IP(s)",
            )
            return deleted_count

    async def _adopt_existing_inventory(self, existing_records: list[FloatingIPRecord]) -> None:
        current_records = {record.id: record for record in existing_records if record.id}
        for match_id, persisted in self.persisted_matches.items():
            current = current_records.get(match_id)
            if current is not None:
                self.matches[match_id] = MatchRecord.from_floating_ip(current, source=persisted.source)

        existing_matches = 0
        for record in existing_records:
            if self.matcher.contains(record.address):
                self.matches.setdefault(record.id, MatchRecord.from_floating_ip(record, source="existing"))
                existing_matches += 1
            else:
                self.seen_non_match_ips.add(record.address)

        self.match_store.save(self.matches)
        self.log(
            "info",
            f"Inventory: {len(existing_records)} existing floating IP(s), {existing_matches} already match whitelist",
        )

    async def _region_worker(self, region: str) -> None:
        state = self.region_states[region]
        while not self.stop_event.is_set():
            if len(self.matches) >= self.settings.target_count:
                self.stop_event.set()
                break

            remaining = state.cooldown_remaining(time.monotonic())
            if remaining > 0:
                await asyncio.sleep(min(remaining, 0.5))
                continue

            state.inflight = state.batch_size
            try:
                allocated = await self.client.allocate_floating_ips(
                    region,
                    state.batch_size,
                    poll_attempts=self.settings.allocation_poll_attempts,
                    poll_delay=self.settings.allocation_poll_delay,
                )
                state.inflight = 0
                if not allocated:
                    cooldown = apply_batch_result(
                        state,
                        created_count=0,
                        match_count=0,
                        miss_count=0,
                        duplicate_count=0,
                        deleted_count=0,
                        min_batch_size=self.settings.min_batch_size,
                        max_batch_size=self.settings.max_batch_size,
                        cooldown_base=self.settings.cooldown_base,
                        cooldown_max=self.settings.cooldown_max,
                    )
                    if cooldown > 0:
                        state.cooldown_until = time.monotonic() + cooldown
                    self.log("warning", f"[{region}] no floating IPs returned by API")
                    continue

                self._record_allocation_batch(allocated, region)

                for record in allocated:
                    self.owned_unmatched[record.id] = record
                    state.last_ip = record.address

                matched, misses, duplicates = self._classify_allocated(allocated)
                self._record_miss_hits(misses)
                deleted_count = await self._delete_records(region, misses, reason="miss")
                for record in matched:
                    self.owned_unmatched.pop(record.id, None)
                    self._register_match(record, source="allocated")

                cooldown = apply_batch_result(
                    state,
                    created_count=len(allocated),
                    match_count=len(matched),
                    miss_count=len(misses),
                    duplicate_count=duplicates,
                    deleted_count=deleted_count,
                    min_batch_size=self.settings.min_batch_size,
                    max_batch_size=self.settings.max_batch_size,
                    cooldown_base=self.settings.cooldown_base,
                    cooldown_max=self.settings.cooldown_max,
                )
                state.cooldown_until = time.monotonic() + cooldown if cooldown > 0 else 0.0
                self.log(
                    "info",
                    f"[{region}] batch: created={len(allocated)} matched={len(matched)} "
                    f"misses={len(misses)} duplicates={duplicates} deleted={deleted_count} "
                    f"next_batch={state.batch_size}",
                )

                if matched:
                    self.log(
                        "success",
                        f"[{region}] matched {len(matched)} IP(s): {', '.join(record.address for record in matched)}",
                    )
                elif duplicates:
                    self.log(
                        "warning",
                        f"[{region}] batch completed with {duplicates} duplicate/non-useful allocation(s)",
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                state.inflight = 0
                error_message = str(exc).strip() or type(exc).__name__
                cooldown = apply_error(
                    state,
                    error_message=error_message,
                    min_batch_size=self.settings.min_batch_size,
                    cooldown_base=self.settings.cooldown_base,
                    cooldown_max=self.settings.cooldown_max,
                )
                state.cooldown_until = time.monotonic() + cooldown if cooldown > 0 else 0.0
                self.log("error", f"[{region}] {error_message}")
                try:
                    await self._reconcile_unbound_non_matches(reason="error", regions={region})
                except Exception as reconcile_exc:
                    reconcile_message = str(reconcile_exc).strip() or type(reconcile_exc).__name__
                    self.log("error", f"[{region}] reconcile failed: {reconcile_message}")

    def _classify_allocated(
        self,
        records: list[FloatingIPRecord],
    ) -> tuple[list[FloatingIPRecord], list[FloatingIPRecord], int]:
        duplicates = 0
        matches: list[FloatingIPRecord] = []
        misses: list[FloatingIPRecord] = []
        existing_match_ips = {match.address for match in self.matches.values()}

        for record in records:
            if record.id in self.matches or record.address in existing_match_ips:
                duplicates += 1
                misses.append(record)
                continue

            if self.matcher.contains(record.address):
                matches.append(record)
                continue

            if record.address in self.seen_non_match_ips:
                duplicates += 1
            else:
                self.seen_non_match_ips.add(record.address)
            misses.append(record)

        return matches, misses, duplicates

    def _register_match(self, record: FloatingIPRecord, source: str) -> None:
        match = MatchRecord.from_floating_ip(record, source=source)
        self.matches[record.id] = match
        self.match_store.save(self.matches)

    async def _delete_records(
        self,
        region: str,
        records: list[FloatingIPRecord],
        *,
        reason: str,
    ) -> int:
        if not records:
            return 0

        async def _delete_one(record: FloatingIPRecord) -> bool:
            async with self.delete_semaphore:
                try:
                    deleted = await self.client.delete_floating_ip(record.id)
                except Exception as exc:
                    self.log("error", f"[{region}] failed to delete {record.resource_ref()}: {exc}")
                    return False
                if deleted:
                    self.owned_unmatched.pop(record.id, None)
                    if reason == "miss" and record.address.strip():
                        addr = record.address.strip()
                        self._deleted_miss_addresses.add(addr)
                        reg_bucket = (record.region or "").strip() or (
                            region if isinstance(region, str) and region not in ("startup", "reconcile", "cleanup") else ""
                        )
                        if reg_bucket:
                            self._deleted_miss_addrs_by_region[reg_bucket].add(addr)
                    return True
                self.log("warning", f"[{region}] delete returned false for {record.resource_ref()} ({reason})")
                return False

        results = await asyncio.gather(*(_delete_one(record) for record in records), return_exceptions=False)
        return sum(1 for deleted in results if deleted)

    async def _cleanup_owned_unmatched(self) -> None:
        if not self.settings.cleanup_on_exit or not self.owned_unmatched:
            return

        leftovers = list(self.owned_unmatched.values())
        self.log("warning", f"Cleaning up {len(leftovers)} scanner-owned non-match floating IP(s)")
        await self._delete_records("cleanup", leftovers, reason="shutdown")

    def _print_summary(self) -> None:
        summary = Table(title="Selectel Scanner Summary")
        summary.add_column("Metric")
        summary.add_column("Value")
        summary.add_row("Project", self.project_label)
        summary.add_row("Regions", ", ".join(self.settings.regions))
        summary.add_row("Matches kept", str(len(self.matches)))
        summary.add_row(
            "Whitelist entries",
            str(self.matcher.summary.total_entries),
        )
        summary.add_row(
            "Remaining owned misses",
            str(len(self.owned_unmatched)),
        )
        self.console.print(summary)

        if self.matches:
            matches_table = Table(title="Matched Floating IPs")
            matches_table.add_column("IP", style="bold green")
            matches_table.add_column("Region")
            matches_table.add_column("Source")
            for match in sorted(self.matches.values(), key=lambda item: item.address):
                matches_table.add_row(match.address, match.region, match.source)
            self.console.print(matches_table)
        else:
            self.console.print(Panel("No whitelist matches found.", border_style="yellow"))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="High-throughput Selectel floating IP scanner")
    parser.add_argument("--config", dest="config_path")
    parser.add_argument("--whitelist", dest="whitelist_path")
    parser.add_argument("--state", dest="state_path")
    parser.add_argument("--regions", nargs="+")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--account-id")
    parser.add_argument("--project-name")
    parser.add_argument("--project-id")
    parser.add_argument("--target-count", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-batch-size", type=int, default=32)
    parser.add_argument("--delete-concurrency", type=int, default=12)
    parser.add_argument("--refresh-per-second", type=int, default=4)
    parser.add_argument("--allocation-poll-attempts", type=int, default=6)
    parser.add_argument("--allocation-poll-delay", type=float, default=0.7)
    parser.add_argument("--cooldown-base", type=float, default=2.0)
    parser.add_argument("--cooldown-max", type=float, default=20.0)
    parser.add_argument("--reconcile-interval", type=float, default=10.0)
    parser.add_argument("--keep-owned-misses", action="store_true")
    parser.add_argument("--keep-existing-non-matches", action="store_true")
    parser.add_argument(
        "--rich",
        action="store_true",
        help="Force Rich full-screen Live dashboard (otherwise auto: TTY only)",
    )
    return parser.parse_args(argv)


def build_settings(args: argparse.Namespace) -> ScannerSettings:
    config = load_scanner_config(args.config_path)
    selectel_config = config.selectel.api

    username = _first_non_empty(args.username, os.getenv("SEL_USERNAME"), selectel_config.username)
    password = _first_non_empty(args.password, os.getenv("SEL_PASSWORD"), selectel_config.password)
    account_id = _first_non_empty(args.account_id, os.getenv("SEL_ACCOUNT_ID"), selectel_config.account_id)
    project_name = _first_non_empty(args.project_name, os.getenv("SEL_PROJECT_NAME"), selectel_config.project_name)
    project_id = _first_non_empty(args.project_id, os.getenv("SEL_PROJECT_ID"), selectel_config.project_id)

    if not username or not password or not account_id:
        raise ValueError("username, password and account_id are required for Selectel Scanner")
    if not project_name and not project_id:
        raise ValueError("project_name or project_id is required for Selectel Scanner")

    whitelist_path = Path(args.whitelist_path).expanduser() if args.whitelist_path else DEFAULT_WHITELIST_PATH
    state_path = (
        Path(args.state_path).expanduser()
        if args.state_path
        else TEMP_DIR / "selectel-scanner-matches.json"
    )
    regions = _resolve_regions(args, config)

    return ScannerSettings(
        username=username,
        password=password,
        account_id=account_id,
        project_name=project_name,
        project_id=project_id,
        whitelist_path=whitelist_path,
        state_path=state_path,
        regions=regions,
        target_count=args.target_count,
        min_batch_size=args.batch_size,
        max_batch_size=args.max_batch_size,
        delete_concurrency=args.delete_concurrency,
        live_refresh_per_second=args.refresh_per_second,
        allocation_poll_attempts=args.allocation_poll_attempts,
        allocation_poll_delay=args.allocation_poll_delay,
        cooldown_base=args.cooldown_base,
        cooldown_max=args.cooldown_max,
        reconcile_interval=args.reconcile_interval,
        cleanup_on_exit=not args.keep_owned_misses,
        cleanup_existing_non_matches=not args.keep_existing_non_matches,
    )


def _resolve_regions(args: argparse.Namespace, config: ScannerConfig) -> tuple[str, ...]:
    if args.regions:
        return _normalize_regions(args.regions)

    env_regions = os.getenv("SEL_SCANNER_REGIONS", "").strip()
    if env_regions:
        return _normalize_regions(env_regions.split(","))

    configured_regions: list[str] = []
    selectel_config = config.selectel.api
    if selectel_config.server_id_ru2:
        configured_regions.append("ru-2")
    if selectel_config.server_id_ru3:
        configured_regions.append("ru-3")
    if configured_regions:
        return tuple(configured_regions)
    return ("ru-2", "ru-3")


def _normalize_regions(values: list[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        region = value.strip()
        if not region or region in seen:
            continue
        seen.add(region)
        normalized.append(region)
    if not normalized:
        raise ValueError("At least one region is required for Selectel Scanner")
    return tuple(normalized)


def _first_non_empty(*values: str | None) -> str:
    for value in values:
        candidate = (value or "").strip()
        if candidate:
            return candidate
    return ""


async def run_async(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = build_settings(args)
    interactive = True if args.rich else None
    app = SelectelScannerApp(settings, interactive=interactive)
    return await app.run()


def main(argv: list[str] | None = None) -> int:
    try:
        return asyncio.run(run_async(argv))
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        console = Console(stderr=True)
        console.print(f"[bold red]Selectel Scanner failed:[/] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
