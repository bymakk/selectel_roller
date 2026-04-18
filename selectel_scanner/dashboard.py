from __future__ import annotations

import time
from collections import deque

from rich.console import Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .ip_frequency import render_miss_churn_table
from .models import EventRecord, MatchRecord, RegionRunState, ScannerSettings
from .whitelist import WhitelistSummary


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
    miss_ip_counts: dict[str, int] | None = None,
    delete_unique_addrs: int = 0,
    region_alloc_unique: dict[str, int] | None = None,
    region_del_unique: dict[str, int] | None = None,
) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )
    layout["left"].split_column(
        Layout(name="regions"),
        Layout(name="events", size=10),
    )
    layout["right"].split_column(
        Layout(name="matches_pane"),
        Layout(name="miss_churn", size=28),
    )

    totals = summarize_regions(regions)
    status = describe_project_status(
        regions,
        match_count=len(matches),
        target_count=settings.target_count,
    )
    miss_ip_counts = miss_ip_counts or {}
    region_alloc_unique = region_alloc_unique or {}
    region_del_unique = region_del_unique or {}
    layout["header"].update(
        Panel(
            Group(
                Text(
                    "  ".join(
                        [
                            f"Project: {project_label}",
                            f"Status: {status}",
                            f"Uptime: {format_uptime(started_at)}",
                            f"Progress: {len(matches)}/{settings.target_count}",
                            f"Alloc∪: {unique_ips}",
                            f"IP/min (~60s): {ips_per_minute:.1f}",
                            f"Del∪: {delete_unique_addrs}",
                        ]
                    ),
                    style="bold cyan",
                ),
                Text(
                    "  ".join(
                        [
                            f"Regions: {', '.join(settings.regions)}",
                            f"In-flight: {totals['inflight']}",
                            f"Cooldown: {totals['cooldown_regions']}",
                            f"Errors: {totals['errors']}",
                            f"Whitelist: {whitelist_summary.total_entries}",
                            f"CIDR: {whitelist_summary.network_entries}",
                            f"Single IP: {whitelist_summary.single_ip_entries}",
                            f"Batch range: {settings.min_batch_size}-{settings.max_batch_size}",
                            f"Alloc ops: {totals['allocations']} | Del ops: {totals['deleted']}",
                            "Alloc∪/Del∪ = уникальные адреса по проекту; ops = число операций API (может быть больше)",
                        ]
                    ),
                    style="dim",
                ),
            ),
            border_style="cyan",
        )
    )

    layout["regions"].update(
        Panel(
            render_regions_table(
                regions,
                region_alloc_unique=region_alloc_unique,
                region_del_unique=region_del_unique,
            ),
            title="Region Workers",
            border_style="blue",
        )
    )
    layout["events"].update(Panel(render_events(events), title="Recent Events", border_style="magenta"))
    layout["matches_pane"].update(Panel(render_matches_table(matches), title="Matches", border_style="green"))
    layout["miss_churn"].update(
        Panel(
            render_miss_churn_table(miss_ip_counts, max_rows=90),
            title="Промахи (не whitelist): частота по IP и /24",
            border_style="yellow",
        )
    )
    return layout


def render_regions_table(
    regions: list[RegionRunState],
    *,
    region_alloc_unique: dict[str, int] | None = None,
    region_del_unique: dict[str, int] | None = None,
) -> Table:
    alloc_u = region_alloc_unique or {}
    del_u = region_del_unique or {}
    table = Table(expand=True)
    table.add_column("Region", style="bold")
    table.add_column("Batch", justify="right")
    table.add_column("In", justify="right")
    table.add_column("A∪", justify="right")
    table.add_column("Hits", justify="right")
    table.add_column("Miss", justify="right")
    table.add_column("Dup", justify="right")
    table.add_column("D∪", justify="right")
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
        d_show = str(del_u.get(rid, region.deleted))
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
    table = Table(expand=True)
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
        return Group(Text("Waiting for activity...", style="dim"))

    lines = []
    for event in list(events):
        style = {
            "info": "white",
            "warning": "yellow",
            "error": "red",
            "success": "green",
        }.get(event.level, "white")
        lines.append(Text.assemble((event.timestamp(), "dim"), " ", (event.message, style)))
    return Group(*lines)


def format_uptime(started_at: float) -> str:
    elapsed = max(0, int(time.monotonic() - started_at))
    minutes, seconds = divmod(elapsed, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"
