from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from rich.table import Table

from .paths import MISS_CHURN_JSON_PATH


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


_last_miss_churn_payload_sig: str | None = None


def miss_churn_snapshot_to_payload(snapshot: MissChurnSnapshot) -> dict[str, object]:
    return {
        "ipv4": {k: [int(v[0]), str(v[1] or "")] for k, v in snapshot.ipv4.items()},
        "other": {k: int(v) for k, v in snapshot.other.items()},
    }


def persist_miss_churn_snapshot(
    snapshot: MissChurnSnapshot,
    *,
    path: Path | None = None,
    source: str = "scanner",
) -> None:
    """Пишет объединённый список промахов в JSON под temp/ (без лишних перезаписей при том же содержимом)."""
    global _last_miss_churn_payload_sig
    target = path or MISS_CHURN_JSON_PATH
    data = miss_churn_snapshot_to_payload(snapshot)
    sig = json.dumps(data, sort_keys=True, ensure_ascii=False)
    if sig == _last_miss_churn_payload_sig:
        return
    _last_miss_churn_payload_sig = sig
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "data": data,
    }
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def render_miss_churn_table(snapshot: MissChurnSnapshot | None, *, max_rows: int = 90) -> Table:
    """Miss по /24: число засчитанных промахов (один IP в двух воркерах — один Miss; после DELETE тот же IP снова +1)."""
    table = Table(expand=True, show_header=True, header_style="bold")
    table.add_column("Target", overflow="fold", style="yellow")
    table.add_column("Miss", justify="right", style="dim")

    snap = snapshot or MissChurnSnapshot(ipv4={}, other={})
    rows: list[tuple[tuple[float, str], str, str]] = []

    for net_s, (events, first_ip) in snap.ipv4.items():
        ev = int(events)
        if ev <= 0:
            continue
        if ev == 1 and first_ip:
            target = first_ip
        else:
            net_obj = ipaddress.ip_network(net_s, strict=False)
            target = f"{net_obj.network_address}/24"
        rows.append(((-float(ev), target), target, str(ev)))

    for ip, cnt in snap.other.items():
        c = int(cnt)
        if c <= 0:
            continue
        rows.append(((-float(c), ip), ip, str(c)))

    if not rows:
        table.add_row("—", "0")
        return table

    rows.sort(key=lambda item: item[0])

    for i, (_, left, right) in enumerate(rows):
        if i >= max_rows:
            overflow = len(rows) - max_rows
            if overflow > 0:
                table.add_row(f"... +{overflow} строк", "")
            break
        table.add_row(left, right)

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
