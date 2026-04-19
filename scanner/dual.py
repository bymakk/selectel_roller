from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .client import SelectelScannerClient
from .config import ScannerConfig, load_scanner_config
from .dashboard import (
    MATCHES_PANEL_MIN_LINES,
    MISS_CHURN_TABLE_MAX_ROWS,
    format_uptime,
    region_result_style,
    regions_panel_layout_height,
    render_events,
)
from .ip_frequency import (
    MissChurnSnapshot,
    merge_miss_churn_snapshots,
    persist_miss_churn_text,
    render_miss_churn_table,
)
from .main import SelectelScannerApp, _normalize_regions, build_settings, parse_args
from .models import EventRecord, MatchRecord, RegionRunState, ScannerSettings
from .rich_ui import DASHBOARD_PANEL_PADDING, DASHBOARD_TABLE_BOX, DASHBOARD_TABLE_PADDING, dashboard_console, dashboard_console_stderr


ONLY_REGIONS = ("ru-1", "ru-2", "ru-3")


def _region_sort_key(region: str) -> tuple[str, int | str]:
    prefix, _, suffix = region.partition("-")
    try:
        return prefix, int(suffix)
    except ValueError:
        return prefix, suffix


def _select_regions(regions: tuple[str, ...]) -> tuple[str, ...]:
    available = set(regions)
    selected = tuple(region for region in ONLY_REGIONS if region in available)
    if not selected:
        raise RuntimeError(
            "None of ru-1, ru-2, ru-3 are available in the Selectel service catalog for this project"
        )
    return selected


def _regions_from_env_var(name: str) -> tuple[str, ...] | None:
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    return _normalize_regions(raw.split(","))


async def _resolve_available_regions(settings: ScannerSettings) -> tuple[str, ...]:
    client = SelectelScannerClient(
        username=settings.username,
        password=settings.password,
        account_id=settings.account_id,
        project_name=settings.project_name,
        project_id=settings.project_id,
        regions=(),
    )
    try:
        await client.ensure_authenticated()
        regions = _select_regions(tuple(sorted(client.available_regions(), key=_region_sort_key)))
    finally:
        await client.close()

    if not regions:
        raise RuntimeError("Selectel returned no available network regions for this account")
    return regions


def _secondary_env(key: str) -> str:
    return os.getenv(f"SEL2_{key}", "").strip()


def _pick_secondary_value(config_value: str, env_key: str, fallback: str = "") -> str:
    env_value = _secondary_env(env_key)
    if env_value:
        return env_value
    config_value = (config_value or "").strip()
    if config_value:
        return config_value
    return fallback


def _wants_primary(config: ScannerConfig) -> bool:
    if any(
        os.getenv(k, "").strip()
        for k in (
            "SEL_USERNAME",
            "SEL_PASSWORD",
            "SEL_ACCOUNT_ID",
            "SEL_PROJECT_NAME",
            "SEL_PROJECT_ID",
        )
    ):
        return True
    api = config.selectel.api
    return bool(
        (api.username or "").strip()
        or (api.password or "").strip()
        or (api.account_id or "").strip()
        or (api.project_name or "").strip()
        or (api.project_id or "").strip()
    )


def _wants_secondary(config: ScannerConfig) -> bool:
    if any(
        os.getenv(f"SEL2_{k}", "").strip()
        for k in ("USERNAME", "PASSWORD", "ACCOUNT_ID", "PROJECT_NAME", "PROJECT_ID")
    ):
        return True
    accs = config.selectel.additional_accounts
    if not accs:
        return False
    a = accs[0]
    return bool(
        (a.username or "").strip()
        or (a.password or "").strip()
        or (a.account_id or "").strip()
        or (a.project_name or "").strip()
        or (a.project_id or "").strip()
    )


def _primary_credentials(settings: ScannerSettings) -> dict[str, str]:
    return {
        "username": (settings.username or "").strip(),
        "password": (settings.password or "").strip(),
        "account_id": (settings.account_id or "").strip(),
        "project_name": (settings.project_name or "").strip(),
        "project_id": (settings.project_id or "").strip(),
    }


def _secondary_credentials(config_account: object | None, primary_settings: ScannerSettings) -> dict[str, str]:
    return {
        "username": _pick_secondary_value(getattr(config_account, "username", ""), "USERNAME"),
        "password": (os.getenv("SEL2_PASSWORD", "").strip() or (getattr(config_account, "password", "") or "").strip()),
        "account_id": _pick_secondary_value(getattr(config_account, "account_id", ""), "ACCOUNT_ID"),
        "project_name": _pick_secondary_value(
            getattr(config_account, "project_name", ""),
            "PROJECT_NAME",
            primary_settings.project_name,
        ),
        "project_id": _pick_secondary_value(
            getattr(config_account, "project_id", ""),
            "PROJECT_ID",
            primary_settings.project_id,
        ),
    }


def _validate_worker_credentials(
    worker_title: str,
    creds: dict[str, str],
    *,
    env_hint_primary: bool,
) -> str | None:
    """Возвращает текст ошибки для Recent Events или None, если всё ок."""
    missing: list[str] = []
    if not creds.get("username"):
        missing.append("логин (SEL_USERNAME / config)" if env_hint_primary else "логин (SEL2_USERNAME / config)")
    if not creds.get("password"):
        missing.append("пароль (SEL_PASSWORD / config)" if env_hint_primary else "пароль (SEL2_PASSWORD / config)")
    if not creds.get("account_id"):
        missing.append("SEL_ACCOUNT_ID" if env_hint_primary else "SEL2_ACCOUNT_ID")
    if missing:
        return f"{worker_title} не запущен: не задано — {', '.join(missing)}"
    if not creds.get("project_name") and not creds.get("project_id"):
        return (
            f"{worker_title} не запущен: нужен проект — "
            f"{'SEL_PROJECT_NAME или SEL_PROJECT_ID' if env_hint_primary else 'SEL2_PROJECT_NAME или SEL2_PROJECT_ID'}"
        )
    return None


def _error_events(message: str) -> deque[EventRecord]:
    return deque([EventRecord.create("error", message)], maxlen=48)


@dataclass
class WorkerSlot:
    """Один воркер в dual-дашборде: либо запущенный app, либо только событие об ошибке конфигурации."""

    label: str
    app: SelectelScannerApp | None
    events: deque[EventRecord]


def _slot_label(
    env_key: str,
    fallback: str,
    settings: ScannerSettings | None,
    *,
    err: str | None,
) -> str:
    explicit = os.getenv(env_key, "").strip()
    if explicit:
        return explicit
    if err is None and settings and (settings.username or "").strip():
        return f"{settings.username.strip()} / {(settings.account_id or '').strip()}".strip()
    return fallback


def _slot_events(app: SelectelScannerApp | None, err: str | None) -> deque[EventRecord]:
    if app is not None:
        return app.events
    assert err is not None
    return _error_events(err)


def _emit_log_flags(
    args: argparse.Namespace, console: Console, interactive_ui: bool
) -> tuple[bool, bool, bool, str | None]:
    rich_logs = bool(getattr(args, "rich_logs", False))
    log_file_arg = getattr(args, "log_file", None) or None
    emit_out = (not interactive_ui) or rich_logs or bool(log_file_arg)
    log_err = rich_logs and interactive_ui
    suppress_console = bool(interactive_ui and log_file_arg and not rich_logs)
    return emit_out, log_err, suppress_console, log_file_arg


async def _prepare_primary_regions(
    args: argparse.Namespace,
    primary_settings: ScannerSettings,
) -> tuple[str, ...]:
    available_primary = await _resolve_available_regions(primary_settings)
    sel1 = _regions_from_env_var("SEL1_SCANNER_REGIONS")

    if args.regions:
        primary_regions = primary_settings.regions
    elif sel1 is not None:
        primary_regions = tuple(r for r in sel1 if r in available_primary)
        if not primary_regions:
            primary_regions = available_primary
    else:
        primary_regions = available_primary

    primary_settings.regions = primary_regions
    primary_settings.state_section = "account-1"
    return primary_regions


async def _finalize_secondary_settings(
    args: argparse.Namespace,
    primary_settings: ScannerSettings,
    secondary_config: object | None,
    *,
    primary_regions: tuple[str, ...] | None,
) -> ScannerSettings:
    if primary_regions is None:
        secondary_seed = _build_secondary_settings(
            primary_settings,
            regions=(),
            config_account=secondary_config,
        )
    else:
        secondary_seed = _build_secondary_settings(
            primary_settings,
            regions=primary_regions if args.regions else (),
            config_account=secondary_config,
        )
    available_secondary = await _resolve_available_regions(secondary_seed)
    sel2 = _regions_from_env_var("SEL2_SCANNER_REGIONS")

    if args.regions:
        secondary_regions = secondary_seed.regions
    elif sel2 is not None:
        secondary_regions = tuple(r for r in sel2 if r in available_secondary)
        if not secondary_regions:
            secondary_regions = available_secondary
    else:
        secondary_regions = secondary_seed.regions or available_secondary

    return _build_secondary_settings(
        primary_settings,
        regions=secondary_regions,
        config_account=secondary_config,
    )


def _build_secondary_settings(
    primary_settings: ScannerSettings,
    *,
    regions: tuple[str, ...],
    config_account: object | None = None,
) -> ScannerSettings:
    username = _pick_secondary_value(getattr(config_account, "username", ""), "USERNAME")
    password = os.getenv("SEL2_PASSWORD", "") or getattr(config_account, "password", "")
    account_id = _pick_secondary_value(getattr(config_account, "account_id", ""), "ACCOUNT_ID")
    project_name = _pick_secondary_value(
        getattr(config_account, "project_name", ""),
        "PROJECT_NAME",
        primary_settings.project_name,
    )
    project_id = _pick_secondary_value(
        getattr(config_account, "project_id", ""),
        "PROJECT_ID",
        primary_settings.project_id,
    )

    if not username or not password or not account_id:
        raise ValueError(
            "Задайте второй аккаунт в .env (SEL2_*) или в config.json → selectel.additional_accounts[0]"
        )
    if not project_name and not project_id:
        raise ValueError("Second account requires project_name or project_id")

    return ScannerSettings(
        username=username,
        password=password,
        account_id=account_id,
        project_name=project_name,
        project_id=project_id,
        whitelist_path=primary_settings.whitelist_path,
        state_path=primary_settings.state_path,
        state_section="account-2",
        regions=regions,
        target_count=primary_settings.target_count,
        min_batch_size=primary_settings.min_batch_size,
        max_batch_size=primary_settings.max_batch_size,
        delete_concurrency=primary_settings.delete_concurrency,
        live_refresh_per_second=primary_settings.live_refresh_per_second,
        allocation_poll_attempts=primary_settings.allocation_poll_attempts,
        allocation_poll_delay=primary_settings.allocation_poll_delay,
        cooldown_base=primary_settings.cooldown_base,
        cooldown_max=primary_settings.cooldown_max,
        cleanup_on_exit=primary_settings.cleanup_on_exit,
        cleanup_existing_non_matches=primary_settings.cleanup_existing_non_matches,
        reconcile_interval=primary_settings.reconcile_interval,
        max_floating_ips_per_minute=primary_settings.max_floating_ips_per_minute,
    )


def _compact_label(label: str) -> str:
    primary = label.split(" / ", 1)[0].strip() or label.strip()
    if len(primary) <= 16:
        return primary
    return f"{primary[:13]}..."


def _disabled_worker_regions_panel(label: str) -> Panel:
    compact = _compact_label(label)
    return Panel(
        Text("Воркер не запущен — см. Recent Events ниже.", style="dim"),
        title=f"Region Workers | {compact}",
        subtitle="—",
        border_style="red",
        padding=DASHBOARD_PANEL_PADDING,
    )


def _render_compact_regions_table(app: SelectelScannerApp) -> Table:
    table = Table(expand=True, box=DASHBOARD_TABLE_BOX, padding=DASHBOARD_TABLE_PADDING)
    table.add_column("Rg", style="bold", no_wrap=True)
    table.add_column("B", justify="right")
    table.add_column("In", justify="right")
    table.add_column("A∪", justify="right")
    table.add_column("Miss", justify="right")
    table.add_column("Del#", justify="right")
    table.add_column("E", justify="right")
    table.add_column("Cd", justify="right")
    table.add_column("Last", overflow="fold")

    now = time.monotonic()
    for region in app.region_states.values():
        last_value = region.last_ip or region.last_error or "-"
        cooldown = f"{region.cooldown_remaining(now):.0f}s" if region.cooldown_until > now else "-"
        table.add_row(
            region.region,
            str(region.batch_size),
            str(region.inflight),
            str(app.unique_alloc_by_region(region.region)),
            str(app.whitelist_miss_events_in_region(region.region)),
            str(app.deleted_miss_ops_in_region(region.region)),
            str(region.errors),
            cooldown,
            f"[{region_result_style(region)}]{last_value}[/{region_result_style(region)}]",
        )
    return table


def _match_sort_key(match: MatchRecord) -> tuple[str, str, str]:
    return (match.discovered_at, match.region, match.address)


def _render_combined_matches_table(accounts: list[tuple[str, SelectelScannerApp]]) -> Table:
    table = Table(expand=True, box=DASHBOARD_TABLE_BOX, padding=DASHBOARD_TABLE_PADDING)
    table.add_column("Acct", style="bold")
    table.add_column("IP", style="bold green")
    table.add_column("Rg", no_wrap=True)
    table.add_column("When")

    rows: list[tuple[str, MatchRecord]] = []
    for label, app in accounts:
        compact_label = _compact_label(label)
        for match in app.matches.values():
            rows.append((compact_label, match))

    if not rows:
        table.add_row("-", "-", "-", "No matches yet")
        return table

    for compact_label, match in sorted(rows, key=lambda item: _match_sort_key(item[1]), reverse=True):
        discovered = match.discovered_at.replace("T", " ").split(".", 1)[0] if match.discovered_at else "-"
        table.add_row(compact_label, match.address, match.region, discovered)
    return table


def _merged_global_stats(
    accounts: list[tuple[str, SelectelScannerApp]],
) -> tuple[int, float, MissChurnSnapshot, int]:
    union: set[str] = set()
    del_ops_total = 0
    ips_pm = 0.0
    churn_snaps: list[MissChurnSnapshot] = []
    for _, app in accounts:
        union |= app.distinct_allocated_ips()
        del_ops_total += app.deleted_miss_ops_total()
        ips_pm += app.allocations_per_minute_recent()
        churn_snaps.append(app.miss_churn_snapshot())
    miss_merged = merge_miss_churn_snapshots(*churn_snaps)
    return len(union), ips_pm, miss_merged, del_ops_total


def _merged_region_alloc_delete_totals(accounts: list[tuple[str, SelectelScannerApp]]) -> tuple[int, int]:
    """Сумма счётчиков RegionRunState по всем регионам и аккаунтам (выдачи / удаления в воркерах)."""
    alloc = 0
    deleted = 0
    for _, app in accounts:
        for st in app.region_states.values():
            alloc += st.allocations
            deleted += st.deleted
    return alloc, deleted


def _build_dual_header(slots: list[WorkerSlot]) -> Panel:
    active = [s.app for s in slots if s.app is not None]
    if not active:
        line = "Нет активных воркеров — проверьте учётные данные в .env / config"
        return Panel(
            Text(line, style="bold yellow"),
            border_style="yellow",
            padding=DASHBOARD_PANEL_PADDING,
        )
    started_at = min(a.started_at for a in active)
    accounts = [(s.label, s.app) for s in slots if s.app is not None]
    _, ips_pm, _, _ = _merged_global_stats(accounts)
    total_alloc, total_deleted = _merged_region_alloc_delete_totals(accounts)
    line = (
        f"Время работы: {format_uptime(started_at)}    "
        f"IP/мин: {ips_pm:.1f}    "
        f"Всего IP: {total_alloc}    "
        f"Удалено IP: {total_deleted}"
    )
    return Panel(Text(line, style="bold cyan"), border_style="cyan", padding=DASHBOARD_PANEL_PADDING)


def _build_dual_dashboard(slots: list[WorkerSlot]) -> Layout:
    accounts = [(s.label, s.app) for s in slots if s.app is not None]
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(name="workers", ratio=3),
        Layout(name="right", ratio=2, minimum_size=40),
    )
    layout["workers"].split_column(
        Layout(name="account_1_workers"),
        Layout(name="account_2_workers"),
    )
    layout["header"].update(_build_dual_header(slots))

    for index, slot in enumerate(slots, start=1):
        compact_label = _compact_label(slot.label)
        region_h = (
            regions_panel_layout_height(len(slot.app.region_states))
            if slot.app is not None
            else 8
        )
        layout[f"account_{index}_workers"].split_column(
            Layout(name=f"account_{index}_regions", size=region_h),
            Layout(name=f"account_{index}_events", ratio=1),
        )
        if slot.app is not None:
            layout[f"account_{index}_regions"].update(
                Panel(
                    _render_compact_regions_table(slot.app),
                    title=f"Region Workers | {compact_label}",
                    subtitle=slot.app.project_label,
                    border_style="blue" if index == 1 else "cyan",
                    padding=DASHBOARD_PANEL_PADDING,
                )
            )
        else:
            layout[f"account_{index}_regions"].update(_disabled_worker_regions_panel(slot.label))
        layout[f"account_{index}_events"].update(
            Panel(
                render_events(slot.events),
                title=f"Recent Events | {compact_label}",
                border_style="magenta",
                padding=DASHBOARD_PANEL_PADDING,
            )
        )

    layout["right"].split_column(
        Layout(name="matches_pane", ratio=1, minimum_size=MATCHES_PANEL_MIN_LINES),
        Layout(name="miss_churn", ratio=1, minimum_size=12),
    )
    _, _, miss_merged, _ = _merged_global_stats(accounts)
    persist_miss_churn_text(miss_merged)
    layout["matches_pane"].update(
        Panel(
            _render_combined_matches_table(accounts),
            title="Matches",
            border_style="green",
        )
    )
    layout["miss_churn"].update(
        Panel(
            render_miss_churn_table(miss_merged, max_rows=MISS_CHURN_TABLE_MAX_ROWS),
            title="Выдачи вне белого списка",
            border_style="yellow",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )
    return layout


def _print_help() -> int:
    exit_code = 0
    try:
        parse_args(["--help"])
    except SystemExit as exc:
        exit_code = int(exc.code or 0)

    console = dashboard_console()
    console.print()
    console.print("Second account environment variables:", style="bold")
    console.print("  SEL2_USERNAME")
    console.print("  SEL2_PASSWORD")
    console.print("  SEL2_ACCOUNT_ID")
    console.print("  SEL2_PROJECT_NAME or SEL2_PROJECT_ID")
    console.print("Or set variables in .env (see .env.example) or selectel.additional_accounts[0] in config.json")
    console.print("Optional labels: SEL1_LABEL, SEL2_LABEL")
    console.print("  --rich-logs     — логи событий в stderr вместе с полноэкранным Rich")
    console.print("  --log-file PATH — тот же лог в файл внутри проекта, напр. temp/scanner.log")
    return exit_code


async def _run_single_scanner_from_dual(
    settings: ScannerSettings,
    *,
    console: Console,
    args: argparse.Namespace,
    interactive_ui: bool,
) -> int:
    emit_out, log_err, suppress_console, log_file_arg = _emit_log_flags(args, console, interactive_ui)
    app = SelectelScannerApp(
        settings,
        console=console,
        interactive=interactive_ui,
        emit_console_output=emit_out,
        emit_summary=not interactive_ui,
        log_to_stderr=log_err,
        log_file=log_file_arg,
        suppress_console_log=suppress_console,
    )
    return await app.run()


async def run_async(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if any(flag in args_list for flag in ("-h", "--help")):
        return _print_help()

    args = parse_args(args_list)
    config = load_scanner_config(args.config_path)
    config_accounts = config.selectel.additional_accounts
    secondary_config = config_accounts[0] if config_accounts else None

    wp = _wants_primary(config)
    ws = _wants_secondary(config)
    if not wp and not ws:
        raise ValueError(
            "Не задан ни первый аккаунт (SEL_* / config → selectel.api), "
            "ни второй (SEL2_* / additional_accounts[0])."
        )

    if wp and not ws:
        primary_settings = build_settings(args)
    else:
        primary_settings = build_settings(args, allow_incomplete_primary=True)

    primary_err: str | None = None
    if wp:
        primary_err = _validate_worker_credentials(
            "Аккаунт 1",
            _primary_credentials(primary_settings),
            env_hint_primary=True,
        )

    secondary_err: str | None = None
    if ws:
        secondary_err = _validate_worker_credentials(
            "Аккаунт 2",
            _secondary_credentials(secondary_config, primary_settings),
            env_hint_primary=False,
        )

    console = dashboard_console()
    interactive_ui = bool(args.rich) or (console.is_terminal and sys.stdout.isatty())

    # Один заданный аккаунт — один процесс сканера с обычным Rich-дашбордом.
    if wp and not ws:
        if primary_err:
            raise ValueError(primary_err)
        await _prepare_primary_regions(args, primary_settings)
        return await _run_single_scanner_from_dual(
            primary_settings,
            console=console,
            args=args,
            interactive_ui=interactive_ui,
        )

    if ws and not wp:
        if secondary_err:
            raise ValueError(secondary_err)
        secondary_settings = await _finalize_secondary_settings(
            args,
            primary_settings,
            secondary_config,
            primary_regions=None,
        )
        return await _run_single_scanner_from_dual(
            secondary_settings,
            console=console,
            args=args,
            interactive_ui=interactive_ui,
        )

    # Оба аккаунта задействованы — dual layout; при ошибке в .env воркер не стартует, причина в Recent Events.
    assert wp and ws
    primary_regions: tuple[str, ...] | None = None
    if not primary_err:
        primary_regions = await _prepare_primary_regions(args, primary_settings)

    secondary_settings: ScannerSettings | None = None
    if not secondary_err:
        secondary_settings = await _finalize_secondary_settings(
            args,
            primary_settings,
            secondary_config,
            primary_regions=primary_regions,
        )

    emit_out, log_err, suppress_console, log_file_arg = _emit_log_flags(args, console, interactive_ui)

    label1 = _slot_label("SEL1_LABEL", "Аккаунт 1", primary_settings, err=primary_err)
    label2 = _slot_label("SEL2_LABEL", "Аккаунт 2", secondary_settings, err=secondary_err)

    slot1_app: SelectelScannerApp | None = None
    if not primary_err:
        slot1_app = SelectelScannerApp(
            primary_settings,
            console=console,
            interactive=False,
            emit_console_output=emit_out,
            emit_summary=not interactive_ui,
            log_to_stderr=log_err,
            log_file=log_file_arg,
            suppress_console_log=suppress_console,
        )

    slot2_app: SelectelScannerApp | None = None
    if not secondary_err and secondary_settings is not None:
        slot2_app = SelectelScannerApp(
            secondary_settings,
            console=console,
            interactive=False,
            emit_console_output=emit_out,
            emit_summary=not interactive_ui,
            log_to_stderr=log_err,
            log_file=log_file_arg,
            suppress_console_log=suppress_console,
        )

    slots = [
        WorkerSlot(label=label1, app=slot1_app, events=_slot_events(slot1_app, primary_err)),
        WorkerSlot(label=label2, app=slot2_app, events=_slot_events(slot2_app, secondary_err)),
    ]

    active_apps = [s.app for s in slots if s.app is not None]
    refresh_per_second = max(
        (a.settings.live_refresh_per_second for a in active_apps),
        default=4,
    )
    tasks = [asyncio.create_task(app.run()) for app in active_apps]
    results: list[object] = []

    try:
        if interactive_ui:
            with Live(
                _build_dual_dashboard(slots),
                console=console,
                screen=True,
                refresh_per_second=refresh_per_second,
            ) as live:
                if tasks:
                    while not all(task.done() for task in tasks):
                        live.update(_build_dual_dashboard(slots))
                        await asyncio.sleep(1.0 / refresh_per_second)
                else:
                    try:
                        while True:
                            live.update(_build_dual_dashboard(slots))
                            await asyncio.sleep(1.0 / refresh_per_second)
                    except KeyboardInterrupt:
                        pass

            results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []
        else:
            results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []
    finally:
        for app in active_apps:
            app.stop_event.set()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    errors = [result for result in results if isinstance(result, Exception)]
    if interactive_ui:
        for slot in slots:
            if slot.app is not None:
                console.print(
                    Panel(
                        f"{slot.label} | {slot.app.project_label}",
                        border_style="cyan",
                        padding=DASHBOARD_PANEL_PADDING,
                    )
                )
                slot.app._print_summary()
    if errors:
        raise errors[0]
    if not tasks:
        return 1
    return 0 if all(result == 0 for result in results) else 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--rich" not in argv:
        argv = ["--rich", *argv]
    try:
        return asyncio.run(run_async(argv))
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        console = dashboard_console_stderr()
        console.print(f"[bold red]Dual Selectel Scanner failed:[/] {exc}")
        return 1
