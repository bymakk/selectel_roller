from __future__ import annotations

import time
from collections import deque
from typing import Any

from rich.console import Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .ip_frequency import MissChurnSnapshot, persist_miss_churn_text, render_miss_churn_table
from .models import EventRecord, MatchRecord, RegionRunState, ScannerSettings
from .rich_ui import DASHBOARD_PANEL_PADDING, DASHBOARD_TABLE_BOX, DASHBOARD_TABLE_PADDING
from .whitelist import WhitelistSummary

# Рамка + заголовок «Matches» + шапка таблицы + минимум 2–3 строки с IP.
MATCHES_PANEL_MIN_LINES = 14


def summarize_regions(regions: list[RegionRunState]) -> dict[str, int]:
    now = time.monotonic()
    return {
        "allocations": sum(region.allocations for region in regions),
        "matches": sum(region.matches for region in regions),
        "misses": sum(region.misses for region in regions),
        "duplicates": sum(region.duplicates for region in regions),
        "deleted": sum(region.deleted for region in regions),
        "errors": sum(region.errors for region in regions),
        "inflight": sum(region.inflight for region in regions),
        "cooldown_regions": sum(1 for region in regions if region.cooldown_until > now),
        "active_regions": sum(1 for region in regions if region.inflight > 0),
    }


def describe_project_status(
    regions: list[RegionRunState],
    *,
    match_count: int,
    target_count: int,
) -> str:
    if match_count >= target_count:
        return "target reached"
    if any(region.inflight > 0 for region in regions):
        return "allocating"
    if any(region.cooldown_until > time.monotonic() for region in regions):
        return "cooldown"
    if any(region.allocations > 0 or region.batches > 0 for region in regions):
        return "running"
    return "starting"


def regions_panel_layout_height(num_regions: int) -> int:
    """Высота панели Region Workers в строках Rich Layout (зависит от числа регионов ru-1 … ru-3)."""
    n = max(0, num_regions)
    return max(10, 7 + n)


def region_result_style(region: RegionRunState) -> str:
    return {
        "match": "green",
        "all-miss": "yellow",
        "duplicate-heavy": "magenta",
        "error": "red",
        "empty": "yellow",
        "mixed": "cyan",
    }.get(region.last_result, "white")


def build_dashboard(
    settings: ScannerSettings,
    whitelist_summary: WhitelistSummary,
    regions: list[RegionRunState],
    matches: dict[str, MatchRecord],
    events: deque[EventRecord],
    started_at: float,
    project_label: str,
    *,
    unique_ips: int = 0,
    ips_per_minute: float = 0.0,
    miss_churn: MissChurnSnapshot | None = None,
    delete_miss_ops: int = 0,
    region_alloc_unique: dict[str, int] | None = None,
    region_del_ops: dict[str, int] | None = None,
) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )
    region_h = regions_panel_layout_height(len(regions))
    layout["left"].split_column(
        Layout(name="regions", size=region_h),
        Layout(name="events", ratio=1),
    )
    layout["right"].split_column(
        Layout(name="matches_pane", ratio=1, minimum_size=MATCHES_PANEL_MIN_LINES),
        Layout(name="miss_churn", size=56),
    )

    totals = summarize_regions(regions)
    region_alloc_unique = region_alloc_unique or {}
    region_del_ops = region_del_ops or {}
    status_line = (
        f"Время работы: {format_uptime(started_at)}    "
        f"IP/мин: {ips_per_minute:.1f}    "
        f"Всего IP: {totals['allocations']}    "
        f"Удалено IP: {totals['deleted']}"
    )
    layout["header"].update(
        Panel(
            Text(status_line, style="bold cyan"),
            border_style="cyan",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )

    layout["regions"].update(
        Panel(
            render_regions_table(
                regions,
                region_alloc_unique=region_alloc_unique,
                region_del_ops=region_del_ops,
            ),
            title="Region Workers",
            border_style="blue",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )
    layout["events"].update(
        Panel(
            render_events(events),
            title="Recent Events",
            border_style="magenta",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )
    layout["matches_pane"].update(
        Panel(
            render_matches_table(matches),
            title="Matches",
            border_style="green",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )
    snap = miss_churn or MissChurnSnapshot(ipv4={}, other={})
    persist_miss_churn_text(snap)
    layout["miss_churn"].update(
        Panel(
            render_miss_churn_table(snap, max_rows=180),
            title="Выдачи вне белого списка",
            border_style="yellow",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )
    return layout


def render_regions_table(
    regions: list[RegionRunState],
    *,
    region_alloc_unique: dict[str, int] | None = None,
    region_del_ops: dict[str, int] | None = None,
) -> Table:
    alloc_u = region_alloc_unique or {}
    del_ops = region_del_ops or {}
    table = Table(expand=True, box=DASHBOARD_TABLE_BOX, padding=DASHBOARD_TABLE_PADDING)
    table.add_column("Region", style="bold")
    table.add_column("Batch", justify="right")
    table.add_column("In", justify="right")
    table.add_column("A∪", justify="right")
    table.add_column("Hits", justify="right")
    table.add_column("Miss", justify="right")
    table.add_column("Dup", justify="right")
    table.add_column("Del#", justify="right")
    table.add_column("Err", justify="right")
    table.add_column("Hit%", justify="right")
    table.add_column("Cooldown", justify="right")
    table.add_column("Last", overflow="fold")

    now = time.monotonic()
    for region in regions:
        result_style = region_result_style(region)
        last_value = region.last_ip or region.last_error or "-"
        rid = region.region
        a_show = str(alloc_u.get(rid, region.allocations))
        d_show = str(del_ops.get(rid, region.deleted))
        table.add_row(
            rid,
            str(region.batch_size),
            str(region.inflight),
            a_show,
            f"[green]{region.matches}[/green]",
            str(region.misses),
            str(region.duplicates),
            d_show,
            f"[red]{region.errors}[/red]" if region.errors else "0",
            f"{region.hit_rate():.1f}",
            f"{region.cooldown_remaining(now):.1f}s" if region.cooldown_until > now else "-",
            f"[{result_style}]{last_value}[/{result_style}]",
        )
    return table


def render_matches_table(matches: dict[str, MatchRecord]) -> Table:
    table = Table(expand=True, box=DASHBOARD_TABLE_BOX, padding=DASHBOARD_TABLE_PADDING)
    table.add_column("IP", style="bold green")
    table.add_column("Region")
    table.add_column("Source")
    table.add_column("Discovered")

    if not matches:
        table.add_row("-", "-", "-", "No matches yet")
        return table

    for match in sorted(matches.values(), key=lambda item: item.discovered_at):
        discovered = match.discovered_at.replace("T", " ").split(".", 1)[0] if match.discovered_at else "-"
        table.add_row(match.address, match.region, match.source, discovered)
    return table


def render_events(events: deque[EventRecord]) -> Group:
    if not events:
        return Group(Text("Ждём событий…", style="dim"))

    tag_style = {
        "info": ("INF", "cyan"),
        "warning": ("WRN", "yellow"),
        "error": ("ERR", "red"),
        "success": ("OK ", "green"),
    }
    lines = []
    for event in list(events):
        msg_style = {
            "info": "white",
            "warning": "yellow",
            "error": "red",
            "success": "green",
        }.get(event.level, "white")
        tag, tstyle = tag_style.get(event.level, ("LOG", "dim"))
        lines.append(
            Text.assemble(
                (event.timestamp(), "dim"),
                " ",
                (f"{tag}", f"bold {tstyle}"),
                " ",
                (event.message, msg_style),
            )
        )
    return Group(*lines)


def format_uptime(started_at: float) -> str:
    elapsed = max(0, int(time.monotonic() - started_at))
    minutes, seconds = divmod(elapsed, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"
