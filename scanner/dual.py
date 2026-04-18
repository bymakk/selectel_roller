from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .client import SelectelScannerClient
from .config import load_scanner_config
from .dashboard import (
    format_uptime,
    region_result_style,
    render_events,
)
from .ip_frequency import MissChurnSnapshot, merge_miss_churn_snapshots, render_miss_churn_table
from .main import SelectelScannerApp, build_settings, parse_args
from .models import MatchRecord, RegionRunState, ScannerSettings


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


def _account_label(settings: ScannerSettings, *, env_key: str) -> str:
    explicit = os.getenv(env_key, "").strip()
    if explicit:
        return explicit
    return f"{settings.username} / {settings.account_id}"


def _compact_label(label: str) -> str:
    primary = label.split(" / ", 1)[0].strip() or label.strip()
    if len(primary) <= 16:
        return primary
    return f"{primary[:13]}..."


def _render_compact_regions_table(app: SelectelScannerApp) -> Table:
    table = Table(expand=True)
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
    table = Table(expand=True)
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


def _build_dual_header(accounts: list[tuple[str, SelectelScannerApp]]) -> Panel:
    started_at = min(app.started_at for _, app in accounts)
    _, ips_pm, _, _ = _merged_global_stats(accounts)
    total_alloc, total_deleted = _merged_region_alloc_delete_totals(accounts)
    line = (
        f"Время работы: {format_uptime(started_at)}    "
        f"IP/мин: {ips_pm:.1f}    "
        f"Всего IP: {total_alloc}    "
        f"Удалено IP: {total_deleted}"
    )
    return Panel(Text(line, style="bold cyan"), border_style="cyan")


def _build_dual_dashboard(accounts: list[tuple[str, SelectelScannerApp]]) -> Layout:
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
    layout["header"].update(_build_dual_header(accounts))

    for index, (label, app) in enumerate(accounts, start=1):
        compact_label = _compact_label(label)
        layout[f"account_{index}_workers"].split_column(
            Layout(name=f"account_{index}_regions"),
            Layout(name=f"account_{index}_events", size=9),
        )
        layout[f"account_{index}_regions"].update(
            Panel(
                _render_compact_regions_table(app),
                title=f"Region Workers | {compact_label}",
                subtitle=app.project_label,
                border_style="blue" if index == 1 else "cyan",
            )
        )
        layout[f"account_{index}_events"].update(
            Panel(
                render_events(app.events),
                title=f"Recent Events | {compact_label}",
                border_style="magenta",
            )
        )

    layout["right"].split_column(
        Layout(name="matches_pane"),
        Layout(name="miss_churn", size=28),
    )
    _, _, miss_merged, _ = _merged_global_stats(accounts)
    layout["matches_pane"].update(
        Panel(
            _render_combined_matches_table(accounts),
            title="Matches",
            border_style="green",
        )
    )
    layout["miss_churn"].update(
        Panel(
            render_miss_churn_table(miss_merged, max_rows=90),
            title="Промахи: Miss = выдачи вне whitelist по /24 (не DELETE)",
            border_style="yellow",
        )
    )
    return layout


def _print_help() -> int:
    exit_code = 0
    try:
        parse_args(["--help"])
    except SystemExit as exc:
        exit_code = int(exc.code or 0)

    console = Console()
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


async def run_async(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if any(flag in args_list for flag in ("-h", "--help")):
        return _print_help()

    args = parse_args(args_list)
    primary_settings = build_settings(args)
    config = load_scanner_config(args.config_path)
    config_accounts = config.selectel.additional_accounts
    secondary_config = config_accounts[0] if config_accounts else None

    if args.regions:
        primary_regions = primary_settings.regions
    else:
        primary_regions = await _resolve_available_regions(primary_settings)

    primary_settings.regions = primary_regions
    primary_settings.state_section = "account-1"

    secondary_seed = _build_secondary_settings(
        primary_settings,
        regions=primary_regions if args.regions else (),
        config_account=secondary_config,
    )
    secondary_regions = secondary_seed.regions or await _resolve_available_regions(secondary_seed)
    secondary_settings = _build_secondary_settings(
        primary_settings,
        regions=secondary_regions,
        config_account=secondary_config,
    )

    console = Console()
    interactive_ui = bool(args.rich) or (console.is_terminal and sys.stdout.isatty())
    rich_logs = bool(getattr(args, "rich_logs", False))
    log_file_arg = getattr(args, "log_file", None) or None
    emit_out = (not interactive_ui) or rich_logs or bool(log_file_arg)
    log_err = rich_logs and interactive_ui
    suppress_console = bool(interactive_ui and log_file_arg and not rich_logs)
    accounts = [
        (
            _account_label(primary_settings, env_key="SEL1_LABEL"),
            SelectelScannerApp(
                primary_settings,
                console=console,
                interactive=False,
                emit_console_output=emit_out,
                emit_summary=not interactive_ui,
                log_to_stderr=log_err,
                log_file=log_file_arg,
                suppress_console_log=suppress_console,
            ),
        ),
        (
            _account_label(secondary_settings, env_key="SEL2_LABEL"),
            SelectelScannerApp(
                secondary_settings,
                console=console,
                interactive=False,
                emit_console_output=emit_out,
                emit_summary=not interactive_ui,
                log_to_stderr=log_err,
                log_file=log_file_arg,
                suppress_console_log=suppress_console,
            ),
        ),
    ]
    refresh_per_second = max(account.settings.live_refresh_per_second for _, account in accounts)
    tasks = [asyncio.create_task(account.run()) for _, account in accounts]
    results: list[object] = []

    try:
        if interactive_ui:
            with Live(
                _build_dual_dashboard(accounts),
                console=console,
                screen=True,
                refresh_per_second=refresh_per_second,
            ) as live:
                while not all(task.done() for task in tasks):
                    live.update(_build_dual_dashboard(accounts))
                    await asyncio.sleep(1.0 / refresh_per_second)

        results = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for _, account in accounts:
            account.stop_event.set()
        await asyncio.gather(*tasks, return_exceptions=True)

    errors = [result for result in results if isinstance(result, Exception)]
    if interactive_ui:
        for label, account in accounts:
            console.print(Panel(f"{label} | {account.project_label}", border_style="cyan"))
            account._print_summary()
    if errors:
        raise errors[0]
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
        console = Console(stderr=True)
        console.print(f"[bold red]Dual Selectel Scanner failed:[/] {exc}")
        return 1
