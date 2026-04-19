from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from rich.table import Table

from .paths import MISS_CHURN_TXT_PATH
from .rich_ui import DASHBOARD_TABLE_BOX, DASHBOARD_TABLE_PADDING


@dataclass(frozen=True)
class MissChurnSnapshot:
    """IPv4: /24 → (число полученных промахов-событий, первый IP для строки при events==1)."""

    ipv4: Mapping[str, tuple[int, str]]
    other: Mapping[str, int]


def merge_miss_churn_snapshots(*snapshots: MissChurnSnapshot) -> MissChurnSnapshot:
    """Суммируем уникальные промахи по /24 и по не-IPv4 хостам между аккаунтами."""
    if not snapshots:
        return MissChurnSnapshot(ipv4={}, other={})
    ipv4_acc: dict[str, list[int | str]] = {}
    for snap in snapshots:
        for net, (ev, fi) in snap.ipv4.items():
            if net not in ipv4_acc:
                ipv4_acc[net] = [int(ev), str(fi or "")]
            else:
                cur = ipv4_acc[net]
                cur[0] = int(cur[0]) + int(ev)
                if not cur[1] and fi:
                    cur[1] = str(fi)
    ipv4_out: dict[str, tuple[int, str]] = {
        k: (int(v[0]), str(v[1] or "")) for k, v in ipv4_acc.items()
    }
    other_acc: dict[str, int] = {}
    for snap in snapshots:
        for ip, c in snap.other.items():
            other_acc[ip] = other_acc.get(ip, 0) + int(c)
    return MissChurnSnapshot(ipv4=ipv4_out, other=other_acc)


def _miss_churn_sorted_targets_and_counts(snapshot: MissChurnSnapshot | None) -> list[tuple[str, int]]:
    """Отсортированные (Target, число Miss) без процентов."""
    snap = snapshot or MissChurnSnapshot(ipv4={}, other={})
    rows: list[tuple[tuple[float, str], str, int]] = []

    for net_s, (events, first_ip) in snap.ipv4.items():
        ev = int(events)
        if ev <= 0:
            continue
        if ev == 1 and first_ip:
            target = first_ip
        else:
            net_obj = ipaddress.ip_network(net_s, strict=False)
            target = f"{net_obj.network_address}/24"
        rows.append(((-float(ev), target), target, ev))

    for ip, cnt in snap.other.items():
        c = int(cnt)
        if c <= 0:
            continue
        rows.append(((-float(c), ip), ip, c))

    rows.sort(key=lambda item: item[0])
    return [(left, cnt) for _, left, cnt in rows]


def _miss_pct_share(count: int, total: int) -> int:
    if total <= 0:
        return 0
    return int(round(100.0 * float(count) / float(total)))


def miss_churn_display_rows(snapshot: MissChurnSnapshot | None) -> list[tuple[str, str]]:
    """Строки как в UI: (Target, Miss с долей), например «48 (10%)». Доля — от суммы Miss по всем строкам."""
    counts = _miss_churn_sorted_targets_and_counts(snapshot)
    total = sum(c for _, c in counts)
    out: list[tuple[str, str]] = []
    for target, c in counts:
        pct = _miss_pct_share(c, total)
        out.append((target, f"{c} ({pct}%)"))
    return out


def format_miss_churn_plaintext(snapshot: MissChurnSnapshot | None) -> str:
    """Текст для копирования: Target слева, справа «число (N%)»."""
    pairs = miss_churn_display_rows(snapshot)
    if not pairs:
        return "—  0\n"
    tw = max(len(t) for t, _ in pairs)
    tw = max(tw, 12)
    rw = max(len(r) for _, r in pairs)
    lines = [f"{t.ljust(tw)}  {r:>{rw}}" for t, r in pairs]
    return "\n".join(lines) + "\n"


def persist_miss_churn_text(
    snapshot: MissChurnSnapshot | None,
    *,
    path: Path | None = None,
) -> None:
    """temp/miss-churn.txt — обновляется вместе с UI; удобно копировать список подсетей и счётчиков."""
    target = path or MISS_CHURN_TXT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(format_miss_churn_plaintext(snapshot), encoding="utf-8")


def render_miss_churn_table(snapshot: MissChurnSnapshot | None, *, max_rows: int = 90) -> Table:
    """Miss по /24: число засчитанных промахов (один IP в двух воркерах — один Miss; после DELETE тот же IP снова +1)."""
    table = Table(
        expand=True,
        show_header=True,
        header_style="bold",
        box=DASHBOARD_TABLE_BOX,
        padding=DASHBOARD_TABLE_PADDING,
    )
    table.add_column("Target", overflow="fold", style="yellow")
    table.add_column("Miss (%)", justify="right", style="dim")

    pairs = miss_churn_display_rows(snapshot)
    if not pairs:
        table.add_row("—", "0")
        return table

    for i, (left, right) in enumerate(pairs):
        if i >= max_rows:
            overflow = len(pairs) - max_rows
            if overflow > 0:
                table.add_row(f"... +{overflow} строк", "")
            break
        table.add_row(left, right)  # right: «48 (10%)»

    return table


def canonical_ip_address(addr: str) -> str | None:
    """Один канонический вид IPv4/IPv6 (str(ipaddress(...))) для сопоставления одного адреса в разных строках."""
    s = (addr or "").strip()
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def ipv4_slash24_key(addr: str) -> str | None:
    c = canonical_ip_address(addr)
    if c is None:
        return None
    try:
        a = ipaddress.ip_address(c)
    except ValueError:
        return None
    if not isinstance(a, ipaddress.IPv4Address):
        return None
    net = ipaddress.ip_network(f"{c}/24", strict=False)
    return str(net)
