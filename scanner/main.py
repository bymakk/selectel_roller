from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import TextIO

from rich.console import Console

from .rich_ui import (
    DASHBOARD_PANEL_PADDING,
    DASHBOARD_TABLE_BOX,
    DASHBOARD_TABLE_PADDING,
    dashboard_console,
    dashboard_console_stderr,
)
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from .client import SelectelScannerClient
from .config import ScannerConfig, load_scanner_config
from .dashboard import build_dashboard
from .ip_frequency import MissChurnSnapshot, canonical_ip_address, ipv4_slash24_key
from .models import EventRecord, FloatingIPRecord, MatchRecord, RegionRunState, ScannerSettings
from .paths import TEMP_DIR
from .state import MatchStore
from .strategy import apply_batch_result, apply_error
from .whitelist import DEFAULT_WHITELIST_PATH, WhitelistMatcher


def _extract_http_status(exc: BaseException) -> int | None:
    """Пытается извлечь HTTP-статус из исключения httpx."""
    try:
        import httpx

        if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None:
            return int(exc.response.status_code)
    except Exception:
        pass
    # httpx иногда оборачивает статус в строку сообщения: "… '400 Bad Request' …"
    msg = str(exc)
    import re

    m = re.search(r"\b([1-5]\d{2})\b", msg)
    if m:
        return int(m.group(1))
    return None


def _ip_list(records: list[FloatingIPRecord], *, limit: int = 12) -> str:
    """Строка адресов для логов; при длинном списке обрезает хвост."""
    if not records:
        return "—"
    parts = [(r.address or "?").strip() for r in records[:limit]]
    tail = len(records) - limit
    s = ", ".join(parts)
    if tail > 0:
        s += f" (+ещё {tail})"
    return s


class SelectelScannerApp:
    def __init__(
        self,
        settings: ScannerSettings,
        *,
        console: Console | None = None,
        interactive: bool | None = None,
        emit_console_output: bool = True,
        emit_summary: bool = True,
        audit: bool = False,
        log_to_stderr: bool = False,
        log_file: str | Path | None = None,
        suppress_console_log: bool = False,
    ):
        self.settings = settings
        self.console = console or dashboard_console()
        detected_interactive = self.console.is_terminal and sys.stdout.isatty()
        self.interactive = detected_interactive if interactive is None else interactive
        self.emit_console_output = emit_console_output
        self.emit_summary = emit_summary
        self.audit = bool(audit)
        # При Rich dual: писать строки лога в stderr, чтобы не портить полноэкранный Live
        self.log_to_stderr = bool(log_to_stderr)
        # Dual + Rich + --log-file без --rich-logs: писать только в файл, не в stdout
        self.suppress_console_log = bool(suppress_console_log)
        self._log_file_handle: TextIO | None = None
        if log_file:
            lp = Path(log_file).expanduser()
            lp.parent.mkdir(parents=True, exist_ok=True)
            self._log_file_handle = lp.open("a", encoding="utf-8")
        # Аудит: полные канонические IP для сверки с подсчётами (вкл. только audit=True)
        self._audit_alloc_events: list[str] = []
        self._audit_unique_alloc: set[str] = set()
        self._audit_delete_miss_hits: list[str] = []
        # Каждый засчитанный Miss (+1 к /24 или other), в т.ч. повтор того же IP после DELETE
        self._audit_miss_increments: list[str] = []
        self.matcher = WhitelistMatcher.from_path(settings.whitelist_path)
        try:
            self._whitelist_mtime_ns: int | None = settings.whitelist_path.stat().st_mtime_ns
        except OSError:
            self._whitelist_mtime_ns = None
        self.client = SelectelScannerClient(
            username=settings.username,
            password=settings.password,
            account_id=settings.account_id,
            project_name=settings.project_name,
            project_id=settings.project_id,
            regions=settings.regions,
        )
        self.match_store = MatchStore(settings.state_path, section=settings.state_section)
        self.persisted_matches = self.match_store.load()
        self.matches: dict[str, MatchRecord] = {}
        self._matched_addresses: set[str] = set()
        self.owned_unmatched: dict[str, FloatingIPRecord] = {}
        self.seen_non_match_ips: set[str] = set()
        self.region_states = {
            region: RegionRunState(region=region, batch_size=settings.min_batch_size)
            for region in settings.regions
        }
        self.events: deque[EventRecord] = deque(maxlen=48)
        self.delete_semaphore = asyncio.Semaphore(settings.delete_concurrency)
        self.reconcile_lock = asyncio.Lock()
        self._allocation_rate_lock = asyncio.Lock()
        self._allocation_rate_times: deque[float] = deque()
        self.stop_event = asyncio.Event()
        self.started_at = time.monotonic()
        self.project_id = settings.project_id
        self.project_label = settings.project_name or settings.project_id or "project-scoped"
        # Статистика по выданным IP (каждое появление в батче считается отдельно)
        self._allocation_ip_counts: dict[str, int] = {}
        # Промахи: адрес вне whitelist учитывается один раз, пока не удалён; после успешного DELETE снова может дать +1 к /24
        self._miss_ips_counted: set[str] = set()
        self._miss_ipv4_by_net: dict[str, dict[str, str | int]] = defaultdict(
            lambda: {"events": 0, "first_ip": ""}
        )
        self._miss_other: defaultdict[str, int] = defaultdict(int)
        self._rate_samples: deque[tuple[float, int]] = deque()
        # Успешные DELETE по промахам: каждое удаление +1 (не дедуп по адресу)
        self._deleted_miss_ops: int = 0
        self._alloc_addrs_by_region: dict[str, set[str]] = defaultdict(set)
        self._deleted_miss_ops_by_region: dict[str, int] = defaultdict(int)
        # Засчитанные промахи по региону (повтор после удаления IP снова +1)
        self._whitelist_miss_events_by_region: dict[str, int] = defaultdict(int)

    def unique_allocated_ip_count(self) -> int:
        return len(self._allocation_ip_counts)

    def total_allocation_events(self) -> int:
        return sum(self._allocation_ip_counts.values())

    async def _allocation_rate_reserve(self, planned: int) -> None:
        """Резервирует слоты скользящего окна 60 с до вызова allocate (лимит на весь аккаунт, все регионы)."""
        cap = self.settings.max_floating_ips_per_minute
        if cap <= 0 or planned <= 0:
            return
        window = 60.0
        async with self._allocation_rate_lock:
            while True:
                now = time.monotonic()
                while self._allocation_rate_times and self._allocation_rate_times[0] <= now - window:
                    self._allocation_rate_times.popleft()
                if len(self._allocation_rate_times) + planned <= cap:
                    for _ in range(planned):
                        self._allocation_rate_times.append(now)
                    return
                wait = self._allocation_rate_times[0] + window - now
                await asyncio.sleep(max(wait, 0.001))

    async def _allocation_rate_finalize(self, planned: int, actual: int) -> None:
        """После allocate: убрать неиспользованный резерв или добавить слоты, если вернули больше planned."""
        cap = self.settings.max_floating_ips_per_minute
        if cap <= 0:
            return
        if actual < planned:
            async with self._allocation_rate_lock:
                for _ in range(planned - actual):
                    if self._allocation_rate_times:
                        self._allocation_rate_times.pop()
            return
        if actual <= planned:
            return
        extra = actual - planned
        window = 60.0
        async with self._allocation_rate_lock:
            while True:
                now = time.monotonic()
                while self._allocation_rate_times and self._allocation_rate_times[0] <= now - window:
                    self._allocation_rate_times.popleft()
                if len(self._allocation_rate_times) + extra <= cap:
                    for _ in range(extra):
                        self._allocation_rate_times.append(now)
                    return
                wait = self._allocation_rate_times[0] + window - now
                await asyncio.sleep(max(wait, 0.001))

    def allocations_per_minute_recent(self) -> float:
        """Сколько раз выдали IP за последние ~60 с (скорость «перебора»)."""
        now = time.monotonic()
        while self._rate_samples and now - self._rate_samples[0][0] > 60.0:
            self._rate_samples.popleft()
        return float(sum(n for _, n in self._rate_samples))

    def miss_churn_snapshot(self) -> MissChurnSnapshot:
        ipv4 = {
            k: (int(v["events"]), str(v["first_ip"]))
            for k, v in self._miss_ipv4_by_net.items()
            if int(v["events"]) > 0
        }
        return MissChurnSnapshot(ipv4=ipv4, other=dict(self._miss_other))

    def distinct_allocated_ips(self) -> set[str]:
        return set(self._allocation_ip_counts.keys())

    def deleted_miss_ops_total(self) -> int:
        return int(self._deleted_miss_ops)

    def unique_alloc_by_region(self, region: str) -> int:
        return len(self._alloc_addrs_by_region.get(region, ()))

    def deleted_miss_ops_in_region(self, region: str) -> int:
        return int(self._deleted_miss_ops_by_region.get(region, 0))

    def whitelist_miss_events_in_region(self, region: str) -> int:
        """Сумма засчитанных промахов по региону (колонка Miss; после DELETE тот же IP может снова добавиться)."""
        return int(self._whitelist_miss_events_by_region.get(region, 0))

    def audit_report_lines(self) -> list[str]:
        """Сводка для сравнения: реальные IP при выдаче/удалении vs счётчики Miss (только при audit=True)."""
        if not self.audit:
            return []
        snap = self.miss_churn_snapshot()
        sum_slash24 = sum(int(v["events"]) for v in self._miss_ipv4_by_net.values())
        sum_other = sum(snap.other.values())
        churn_sum = sum_slash24 + sum_other

        def _sort_ip(s: str) -> tuple:
            try:
                return (0, ipaddress.ip_address(s))
            except ValueError:
                return (1, s)

        lines = [
            "",
            "========== АУДИТ IP (канонический вид) ==========",
            f"Событий выдачи (строк в батчах, с повторами): {len(self._audit_alloc_events)}",
            f"Уникальных IP среди выдач: {len(self._audit_unique_alloc)}",
            "Уникальные выданные IP (полностью):",
        ]
        for ip in sorted(self._audit_unique_alloc, key=_sort_ip):
            lines.append(f"  {ip}")
        lines.append(
            f"Успешных DELETE по промаху (операций): {len(self._audit_delete_miss_hits)}; "
            f"уникальных адресов среди них: {len(set(self._audit_delete_miss_hits))}"
        )
        if self._audit_delete_miss_hits:
            lines.append("Каждое успешное удаление (miss), по порядку:")
            for ip in self._audit_delete_miss_hits:
                lines.append(f"  del {ip}")
        miss_unique = sorted(set(self._audit_miss_increments), key=_sort_ip)
        lines.extend(
            [
                "",
                "---------- Сверка с панелью Miss ----------",
                f"Засчитано инкрементов Miss (каждый +1): {len(self._audit_miss_increments)}",
                f"Уникальных IP среди инкрементов Miss: {len(miss_unique)}",
                f"Сумма Miss по /24 (events) + прочие: {churn_sum} (= {sum_slash24} + {sum_other})",
                "Совпадение len(инкременты) с суммой по панели: "
                + (
                    "да"
                    if len(self._audit_miss_increments) == churn_sum
                    else f"нет ({len(self._audit_miss_increments)} vs {churn_sum})"
                ),
            ]
        )
        lines.append("Уникальные IP, по которым был хотя бы один Miss:")
        for ip in miss_unique:
            lines.append(f"  {ip}")
        lines.append("==============================================")
        return lines

    def unique_match_count(self) -> int:
        return len(self._matched_addresses)

    def _record_allocation_batch(self, records: list[FloatingIPRecord], region: str) -> None:
        now = time.monotonic()
        batch = 0
        for record in records:
            addr = (record.address or "").strip()
            if not addr:
                continue
            self._allocation_ip_counts[addr] = self._allocation_ip_counts.get(addr, 0) + 1
            self._alloc_addrs_by_region[region].add(addr)
            if self.audit:
                ak = canonical_ip_address(addr) or addr
                self._audit_unique_alloc.add(ak)
                self._audit_alloc_events.append(ak)
            batch += 1
        if batch:
            self._rate_samples.append((now, batch))
            while self._rate_samples and now - self._rate_samples[0][0] > 60.0:
                self._rate_samples.popleft()

    @staticmethod
    def _miss_stat_key(addr: str) -> str | None:
        """Ключ учёта Miss: канонический IP или исходная строка, если не IP."""
        s = (addr or "").strip()
        if not s:
            return None
        c = canonical_ip_address(s)
        return c if c is not None else s

    def _is_true_whitelist_miss(self, record: FloatingIPRecord) -> bool:
        """Промах для панели «не whitelist»: не дубликат уже учтённого match и адрес вне whitelist."""
        if record.id in self.matches:
            return False
        addr = (record.address or "").strip()
        if addr in self._matched_addresses:
            return False
        return not self._ip_in_whitelist(record)

    def _record_miss_hits(
        self,
        misses: list[FloatingIPRecord],
        *,
        worker_region: str | None = None,
    ) -> None:
        wr = (worker_region or "").strip()
        seen_in_batch: set[str] = set()
        for record in misses:
            addr = (record.address or "").strip()
            key = self._miss_stat_key(addr)
            if not key:
                continue
            # Один и тот же адрес не должен учитываться дважды в одном вызове (дубликаты в списке)
            if key in seen_in_batch:
                continue
            seen_in_batch.add(key)
            if key in self._miss_ips_counted:
                continue
            self._miss_ips_counted.add(key)
            if self.audit:
                self._audit_miss_increments.append(key)
            reg_bucket = (record.region or "").strip() or wr
            if reg_bucket:
                self._whitelist_miss_events_by_region[reg_bucket] += 1
            display_addr = canonical_ip_address(addr) or addr
            net_s = ipv4_slash24_key(addr)
            if net_s is not None:
                st = self._miss_ipv4_by_net[net_s]
                if int(st["events"]) == 0:
                    st["first_ip"] = display_addr
                st["events"] = int(st["events"]) + 1
            else:
                self._miss_other[key] += 1

    def log(self, level: str, message: str) -> None:
        self.events.append(EventRecord.create(level, message))
        if not self.emit_console_output:
            return
        line = f"{level.upper()} {message}"
        if self._log_file_handle is not None:
            self._log_file_handle.write(line + "\n")
            self._log_file_handle.flush()
        if self.log_to_stderr:
            print(line, file=sys.stderr, flush=True)
            return
        if self.suppress_console_log:
            return
        if not self.interactive:
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

            self.log("success", f"Авторизация OK, проект: {self.project_label}")

            existing = await self.client.list_floating_ips(regions=set(self.settings.regions))
            existing = await self._cleanup_existing_non_matches(existing, reason="startup")
            await self._adopt_existing_inventory(existing)
            if self.unique_match_count() >= self.settings.target_count:
                self.log("success", "Цель по количеству совпадений уже достигнута существующими IP")
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
                            miss_churn=self.miss_churn_snapshot(),
                            delete_miss_ops=self._deleted_miss_ops,
                            region_alloc_unique={
                                r: self.unique_alloc_by_region(r) for r in self.region_states
                            },
                            region_del_ops={
                                r: self.deleted_miss_ops_in_region(r) for r in self.region_states
                            },
                        ),
                        console=self.console,
                        screen=True,
                        refresh_per_second=self.settings.live_refresh_per_second,
                    ) as live:
                        while not self.stop_event.is_set():
                            if self.unique_match_count() >= self.settings.target_count:
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
                                    miss_churn=self.miss_churn_snapshot(),
                                    delete_miss_ops=self._deleted_miss_ops,
                                    region_alloc_unique={
                                        r: self.unique_alloc_by_region(r) for r in self.region_states
                                    },
                                    region_del_ops={
                                        r: self.deleted_miss_ops_in_region(r) for r in self.region_states
                                    },
                                )
                            )
                            await asyncio.sleep(1.0 / self.settings.live_refresh_per_second)
                else:
                    while not self.stop_event.is_set():
                        if self.unique_match_count() >= self.settings.target_count:
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
            if self._log_file_handle is not None:
                self._log_file_handle.close()
                self._log_file_handle = None
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
            if not self._ip_in_whitelist(record) and record not in cleanup_candidates
        ]

        if preserved_non_matches:
            self.log(
                "info",
                f"Старт: оставляю {len(preserved_non_matches)} привязанных «мимо» whitelist IP (есть порт/фикс. адрес)",
            )

        if not cleanup_candidates:
            return existing_records

        self.log(
            "warning",
            f"Старт: удаляю {len(cleanup_candidates)} непривязанных IP вне whitelist: {_ip_list(cleanup_candidates)}",
        )
        deleted_count = await self._delete_records("startup", cleanup_candidates, reason=reason)
        self.log(
            "info",
            f"Старт: удалено {deleted_count} из {len(cleanup_candidates)} лишних floating IP",
        )
        return await self.client.list_floating_ips(regions=set(self.settings.regions))

    def _refresh_whitelist_if_changed(self) -> None:
        """Подхватывает правки whitelist.txt во время работы процесса."""
        path = self.settings.whitelist_path
        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError:
            return
        if self._whitelist_mtime_ns == mtime_ns:
            return
        self.matcher = WhitelistMatcher.from_path(path)
        self._whitelist_mtime_ns = mtime_ns
        self.log(
            "info",
            f"Whitelist обновлён: {self.matcher.summary.total_entries} записей",
        )

    def _ip_in_whitelist(self, record: FloatingIPRecord) -> bool:
        """True, если публичный адрес floating IP попадает под сеть/адрес из whitelist.txt."""
        self._refresh_whitelist_if_changed()
        addr = (record.address or "").strip()
        return bool(addr) and self.matcher.contains(addr)

    def _is_existing_cleanup_candidate(self, record: FloatingIPRecord) -> bool:
        # Плавающий IP из whitelist.txt никогда не считаем «мусором» на старте / reconcile.
        if self._ip_in_whitelist(record):
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
                f"Сверка: удаляю {len(cleanup_candidates)} непривязанных IP вне whitelist ({region_list}): "
                f"{_ip_list(cleanup_candidates)}",
            )
            deleted_count = await self._delete_records("reconcile", cleanup_candidates, reason=reason)
            self.log(
                "info",
                f"Сверка: удалено {deleted_count} из {len(cleanup_candidates)} лишних IP",
            )
            return deleted_count

    async def _adopt_existing_inventory(self, existing_records: list[FloatingIPRecord]) -> None:
        current_records = {record.id: record for record in existing_records if record.id}
        for match_id, persisted in self.persisted_matches.items():
            current = current_records.get(match_id)
            if current is not None:
                self._remember_match(current, source=persisted.source)

        existing_matches = 0
        for record in existing_records:
            if self._ip_in_whitelist(record):
                if self._remember_match(record, source="existing"):
                    existing_matches += 1
            else:
                addr = (record.address or "").strip()
                if addr:
                    self.seen_non_match_ips.add(addr)

        self.match_store.save(self.matches)
        self.log(
            "info",
            f"Инвентарь: всего {len(existing_records)} floating IP, из них в whitelist уже {existing_matches}",
        )

    async def _region_worker(self, region: str) -> None:
        state = self.region_states[region]
        while not self.stop_event.is_set():
            if self.unique_match_count() >= self.settings.target_count:
                self.stop_event.set()
                break

            remaining = state.cooldown_remaining(time.monotonic())
            if remaining > 0:
                await asyncio.sleep(min(remaining, 0.5))
                continue

            state.inflight = state.batch_size
            planned = state.batch_size
            allocated: list[FloatingIPRecord] = []
            await self._allocation_rate_reserve(planned)
            try:
                try:
                    allocated = await self.client.allocate_floating_ips(
                        region,
                        state.batch_size,
                        poll_attempts=self.settings.allocation_poll_attempts,
                        poll_delay=self.settings.allocation_poll_delay,
                    )
                finally:
                    await self._allocation_rate_finalize(planned, len(allocated))
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
                    self.log(
                        "warning",
                        f"[{region}] API не вернул floating IP (пустой ответ после выдачи)",
                    )
                    continue

                self._record_allocation_batch(allocated, region)

                for record in allocated:
                    self.owned_unmatched[record.id] = record
                    state.last_ip = record.address

                self.log("info", f"[{region}] Получено IP: {_ip_list(allocated)}")

                matched, misses, duplicates = self._classify_allocated(allocated)
                for record in matched:
                    self.owned_unmatched.pop(record.id, None)
                    self._register_match(record, source="allocated")
                if self.unique_match_count() >= self.settings.target_count:
                    self.stop_event.set()

                # В misses попадают и «дубликаты» уже существующих match — не в Miss /24, не в Del#, не в miss_count
                whitelist_misses = [r for r in misses if self._is_true_whitelist_miss(r)]
                self._record_miss_hits(whitelist_misses, worker_region=region)
                for r in whitelist_misses:
                    self.log(
                        "warning",
                        f"[{region}] Не в whitelist — удаляю {(r.address or '?').strip()}",
                    )
                dup_for_delete = [r for r in misses if r not in whitelist_misses]
                if dup_for_delete:
                    self.log(
                        "info",
                        f"[{region}] Удаляю служебные/дубликаты выдачи: {_ip_list(dup_for_delete)}",
                    )
                deleted_count = await self._delete_records(region, misses, reason="miss")

                cooldown = apply_batch_result(
                    state,
                    created_count=len(allocated),
                    match_count=len(matched),
                    miss_count=len(whitelist_misses),
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
                    f"[{region}] Итог батча: выдано {len(allocated)}, в whitelist {len(matched)}, "
                    f"мимо whitelist {len(whitelist_misses)}, удалено записей {deleted_count}, "
                    f"след. размер батча {state.batch_size}",
                )

                if matched:
                    self.log(
                        "success",
                        f"[{region}] Совпадение whitelist: {_ip_list(matched)}",
                    )
                elif duplicates:
                    self.log(
                        "warning",
                        f"[{region}] В батче только дубликаты/отбраковка ({duplicates} шт.)",
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                state.inflight = 0
                error_message = str(exc).strip() or type(exc).__name__
                http_status = _extract_http_status(exc)
                cooldown = apply_error(
                    state,
                    error_message=error_message,
                    min_batch_size=self.settings.min_batch_size,
                    cooldown_base=self.settings.cooldown_base,
                    cooldown_max=self.settings.cooldown_max,
                    http_status=http_status,
                )
                state.cooldown_until = time.monotonic() + cooldown if cooldown > 0 else 0.0
                status_hint = f" [HTTP {http_status}]" if http_status else ""
                self.log("error", f"[{region}] Ошибка{status_hint}: {error_message}")
                if http_status and 400 <= http_status < 500:
                    self.log(
                        "warning",
                        f"[{region}] HTTP {http_status} — кулдаун {cooldown:.0f}s "
                        f"(quota/rate-limit Selectel)",
                    )
                try:
                    await self._reconcile_unbound_non_matches(reason="error", regions={region})
                except Exception as reconcile_exc:
                    reconcile_message = str(reconcile_exc).strip() or type(reconcile_exc).__name__
                    self.log("error", f"[{region}] Сверка после ошибки не удалась: {reconcile_message}")

    def _classify_allocated(
        self,
        records: list[FloatingIPRecord],
    ) -> tuple[list[FloatingIPRecord], list[FloatingIPRecord], int]:
        duplicates = 0
        matches: list[FloatingIPRecord] = []
        misses: list[FloatingIPRecord] = []
        known_match_ips = set(self._matched_addresses)

        for record in records:
            addr = (record.address or "").strip()
            if record.id in self.matches or addr in known_match_ips:
                duplicates += 1
                misses.append(record)
                continue

            if self._ip_in_whitelist(record):
                matches.append(record)
                if addr:
                    known_match_ips.add(addr)
                continue

            if addr in self.seen_non_match_ips:
                duplicates += 1
            else:
                self.seen_non_match_ips.add(addr)
            misses.append(record)

        return matches, misses, duplicates

    def _remember_match(self, record: FloatingIPRecord, source: str) -> bool:
        addr = (record.address or "").strip()
        if not record.id or not addr or addr in self._matched_addresses:
            return False
        match = MatchRecord.from_floating_ip(record, source=source)
        self.matches[record.id] = match
        self._matched_addresses.add(addr)
        return True

    def _register_match(self, record: FloatingIPRecord, source: str) -> bool:
        stored = self._remember_match(record, source=source)
        if stored:
            self.match_store.save(self.matches)
        return stored

    async def _delete_records(
        self,
        region: str,
        records: list[FloatingIPRecord],
        *,
        reason: str,
    ) -> int:
        """Единственная точка вызова Neutron DELETE для floating IP. Не удаляет адреса из whitelist.txt."""
        if not records:
            return 0

        wl_skip = [r for r in records if self._ip_in_whitelist(r)]
        if wl_skip:
            self.log(
                "warning",
                f"[{region}] Защита: не удаляю {len(wl_skip)} IP из whitelist.txt: {_ip_list(wl_skip)}",
            )
        records = [r for r in records if not self._ip_in_whitelist(r)]
        if not records:
            return 0

        async def _delete_one(record: FloatingIPRecord) -> bool:
            # Двойная защита whitelist: первый слой — в _delete_records выше (сразу
            # отрезает сам список), второй слой — здесь, прямо перед HTTP-вызовом,
            # на случай, если список изменился между фильтрацией и этим моментом.
            if record.id in self.matches or self._ip_in_whitelist(record):
                return False
            addr = (record.address or "").strip()
            async with self.delete_semaphore:
                # Третий слой: после взятия семафора whitelist мог быть обновлён на диске —
                # дочитываем, чтобы свежие записи успели защитить запись от DELETE.
                if self._ip_in_whitelist(record):
                    self.log(
                        "info",
                        f"[{region}] Whitelist обновился — пропускаю DELETE для {addr}",
                    )
                    return False
                try:
                    deleted = await self.client.delete_floating_ip(record.id)
                except Exception as exc:
                    addr = (record.address or "?").strip()
                    self.log("error", f"[{region}] Не удалось удалить IP {addr}: {exc}")
                    return False
                if deleted:
                    self.owned_unmatched.pop(record.id, None)
                    addr_st = record.address.strip()
                    if (
                        reason == "miss"
                        and addr_st
                        and self._is_true_whitelist_miss(record)
                    ):
                        self._deleted_miss_ops += 1
                        reg_bucket = (record.region or "").strip() or (
                            region if isinstance(region, str) and region not in ("startup", "reconcile", "cleanup") else ""
                        )
                        if reg_bucket:
                            self._deleted_miss_ops_by_region[reg_bucket] += 1
                        # Снимаем с учёта: тот же IP из той же подсети после новой выдачи снова даст +1 Miss к /24
                        mk = self._miss_stat_key(record.address)
                        if mk:
                            self._miss_ips_counted.discard(mk)
                            if self.audit:
                                self._audit_delete_miss_hits.append(mk)
                    return True
                addr = (record.address or "?").strip()
                self.log(
                    "warning",
                    f"[{region}] DELETE не прошёл для {addr} ({reason}) — возможен повтор или уже снят",
                )
                return False

        results = await asyncio.gather(*(_delete_one(record) for record in records), return_exceptions=False)
        return sum(1 for deleted in results if deleted)

    async def _cleanup_owned_unmatched(self) -> None:
        if not self.settings.cleanup_on_exit or not self.owned_unmatched:
            return

        leftovers = list(self.owned_unmatched.values())
        self.log(
            "warning",
            f"Выход: удаляю оставшиеся «мимо» IP сканера ({len(leftovers)} шт.): {_ip_list(leftovers)}",
        )
        await self._delete_records("cleanup", leftovers, reason="shutdown")

    def _print_summary(self) -> None:
        summary = Table(
            title="Selectel Scanner Summary",
            box=DASHBOARD_TABLE_BOX,
            padding=DASHBOARD_TABLE_PADDING,
        )
        summary.add_column("Metric")
        summary.add_column("Value")
        summary.add_row("Project", self.project_label)
        summary.add_row("Regions", ", ".join(self.settings.regions))
        summary.add_row("Matches kept", str(self.unique_match_count()))
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
            matches_table = Table(
                title="Matched Floating IPs",
                box=DASHBOARD_TABLE_BOX,
                padding=DASHBOARD_TABLE_PADDING,
            )
            matches_table.add_column("IP", style="bold green")
            matches_table.add_column("Region")
            matches_table.add_column("Source")
            for match in sorted(self.matches.values(), key=lambda item: item.address):
                matches_table.add_row(match.address, match.region, match.source)
            self.console.print(matches_table)
        else:
            self.console.print(
                Panel(
                    "No whitelist matches found.",
                    border_style="yellow",
                    padding=DASHBOARD_PANEL_PADDING,
                )
            )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="High-throughput Selectel floating IP scanner")
    parser.add_argument("--config", dest="config_path")
    parser.add_argument("--whitelist", dest="whitelist_path")
    parser.add_argument("--state", dest="state_path", help="JSON с matches (по умолчанию temp/selectel-scanner-state.json)")
    parser.add_argument(
        "--state-section",
        dest="state_section",
        default="account-1",
        help="Ключ секции в JSON (account-1 / account-2 / smoke) при общем файле состояния",
    )
    parser.add_argument("--regions", nargs="+")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--account-id")
    parser.add_argument("--project-name")
    parser.add_argument("--project-id")
    parser.add_argument("--target-count", type=int, default=1)
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help="Минимальный размер батча выдачи (по умолчанию 1 IP за запрос)",
    )
    parser.add_argument(
        "--max-batch-size",
        type=int,
        default=1,
        help="Верхняя граница размера батча; при 1 всегда выдаётся по одному IP",
    )
    parser.add_argument("--delete-concurrency", type=int, default=8)
    parser.add_argument(
        "--refresh-per-second",
        type=int,
        default=6,
        help="Частота обновления Rich (при батче 1 IP удобнее 5–8)",
    )
    parser.add_argument(
        "--allocation-poll-attempts",
        type=int,
        default=5,
        help="Попытки дождаться появления IP в списке после create (батч 1 → меньше)",
    )
    parser.add_argument(
        "--allocation-poll-delay",
        type=float,
        default=0.45,
        help="Пауза между попытками reconcile-списка (сек)",
    )
    parser.add_argument(
        "--cooldown-base",
        type=float,
        default=2.0,
        help="Базовая пауза при пустом ответе (сек). HTTP 4xx всегда даёт минимум 30 с независимо от этого значения.",
    )
    parser.add_argument(
        "--cooldown-max",
        type=float,
        default=60.0,
        help="Максимальный кулдаун (сек). При HTTP 4xx/429 может временно превышать это значение.",
    )
    parser.add_argument(
        "--reconcile-interval",
        type=float,
        default=7.0,
        help="Интервал фоновой сверки «лишних» floating IP (сек)",
    )
    parser.add_argument(
        "--max-ips-per-minute",
        type=int,
        default=30,
        dest="max_ips_per_minute",
        help="Макс. выданных floating IP на этот аккаунт за скользящие 60 с (0 = без лимита). "
        "30 и батч 1 → средний интервал ≥ 2 с между выдачами (60/30).",
    )
    parser.add_argument("--keep-owned-misses", action="store_true")
    parser.add_argument("--keep-existing-non-matches", action="store_true")
    parser.add_argument(
        "--rich",
        action="store_true",
        help="Force Rich full-screen Live dashboard (otherwise auto: TTY only)",
    )
    parser.add_argument(
        "--rich-logs",
        action="store_true",
        dest="rich_logs",
        help="Вместе с Rich (dual): дублировать события в stderr, не отключая дашборд",
    )
    parser.add_argument(
        "--log-file",
        dest="log_file",
        metavar="PATH",
        help="Дописывать те же строки лога в файл (например temp/scanner.log в каталоге проекта)",
    )
    parser.add_argument(
        "--yes",
        "-y",
        dest="assume_yes",
        action="store_true",
        help="Пропустить подтверждение, если в проекте уже есть VM (иначе сканер остановится)",
    )
    parser.add_argument(
        "--no-auto-create-project",
        dest="auto_create_project",
        action="store_false",
        default=True,
        help="Не создавать новый проект автоматически, если его нет у аккаунта",
    )
    parser.add_argument(
        "--auto-project-name",
        dest="auto_project_name",
        default="ip-roller",
        help="Имя проекта для автосоздания, если у аккаунта ещё нет проектов (по умолчанию ip-roller)",
    )
    parser.add_argument(
        "--setup",
        dest="force_setup",
        action="store_true",
        help="Принудительно запустить мастер настройки и перезаписать учётные данные в .env",
    )
    return parser.parse_args(argv)


def _env_int(name: str, fallback: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return fallback
    try:
        return int(raw)
    except ValueError:
        return fallback


def _env_float(name: str, fallback: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return fallback
    try:
        return float(raw.replace(",", "."))
    except ValueError:
        return fallback


def build_settings(
    args: argparse.Namespace,
    *,
    allow_incomplete_primary: bool = False,
    require_project: bool = True,
) -> ScannerSettings:
    config = load_scanner_config(args.config_path)
    selectel_config = config.selectel.api

    username = _first_non_empty(args.username, os.getenv("SEL_USERNAME"), selectel_config.username)
    password = _first_non_empty(args.password, os.getenv("SEL_PASSWORD"), selectel_config.password)
    account_id = _first_non_empty(args.account_id, os.getenv("SEL_ACCOUNT_ID"), selectel_config.account_id)
    project_name = _first_non_empty(args.project_name, os.getenv("SEL_PROJECT_NAME"), selectel_config.project_name)
    project_id = _first_non_empty(args.project_id, os.getenv("SEL_PROJECT_ID"), selectel_config.project_id)

    if not allow_incomplete_primary:
        if not username or not password or not account_id:
            raise ValueError("username, password and account_id are required for Selectel Scanner")
        if require_project and not project_name and not project_id:
            raise ValueError("project_name or project_id is required for Selectel Scanner")

    whitelist_path = Path(args.whitelist_path).expanduser() if args.whitelist_path else DEFAULT_WHITELIST_PATH
    state_path = (
        Path(args.state_path).expanduser()
        if args.state_path
        else TEMP_DIR / "selectel-scanner-state.json"
    )
    regions = _resolve_regions(args, config)

    target_count = _env_int("SEL_TARGET_COUNT", args.target_count)
    min_batch = _env_int("SEL_BATCH_SIZE", args.batch_size)
    max_batch = _env_int("SEL_MAX_BATCH_SIZE", args.max_batch_size)
    delete_conc = _env_int("SEL_DELETE_CONCURRENCY", args.delete_concurrency)
    refresh_ps = _env_int("SEL_REFRESH_PER_SECOND", args.refresh_per_second)
    poll_attempts = _env_int("SEL_ALLOCATION_POLL_ATTEMPTS", args.allocation_poll_attempts)
    poll_delay = _env_float("SEL_ALLOCATION_POLL_DELAY", args.allocation_poll_delay)
    cooldown_base = _env_float("SEL_COOLDOWN_BASE", args.cooldown_base)
    cooldown_max = _env_float("SEL_COOLDOWN_MAX", args.cooldown_max)
    reconcile_iv = _env_float("SEL_RECONCILE_INTERVAL", args.reconcile_interval)
    max_ipm = _env_int("SEL_MAX_IPS_PER_MINUTE", args.max_ips_per_minute)

    return ScannerSettings(
        username=username,
        password=password,
        account_id=account_id,
        project_name=project_name,
        project_id=project_id,
        whitelist_path=whitelist_path,
        state_path=state_path,
        regions=regions,
        state_section=(args.state_section or "account-1").strip() or "account-1",
        target_count=target_count,
        min_batch_size=min_batch,
        max_batch_size=max_batch,
        delete_concurrency=delete_conc,
        live_refresh_per_second=refresh_ps,
        allocation_poll_attempts=poll_attempts,
        allocation_poll_delay=poll_delay,
        cooldown_base=cooldown_base,
        cooldown_max=cooldown_max,
        reconcile_interval=reconcile_iv,
        max_floating_ips_per_minute=max_ipm,
        cleanup_on_exit=not args.keep_owned_misses,
        cleanup_existing_non_matches=not args.keep_existing_non_matches,
    )


def _resolve_regions(args: argparse.Namespace, config: ScannerConfig) -> tuple[str, ...]:
    if args.regions:
        return _normalize_regions(args.regions)

    env1 = os.getenv("SEL1_SCANNER_REGIONS", "").strip()
    if env1:
        return _normalize_regions(env1.split(","))

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
        console = dashboard_console_stderr()
        console.print(f"[bold red]Selectel Scanner failed:[/] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
