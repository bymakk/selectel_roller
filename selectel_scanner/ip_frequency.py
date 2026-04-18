from __future__ import annotations

import ipaddress
from collections import defaultdict

from rich.table import Table


def render_miss_churn_table(miss_ip_counts: dict[str, int], *, max_rows: int = 90) -> Table:
    """Промахи: IPv4 — одна строка на /24 (Target = подсеть), Hits = сколько раз любой IP из неё попал в промах (сумма, растёт). Иначе — хост и его счётчик."""
    table = Table(expand=True, show_header=True, header_style="bold")
    table.add_column("Target", overflow="fold", style="yellow")
    table.add_column("Hits", justify="right", style="dim")

    if not miss_ip_counts:
        table.add_row("—", "0")
        return table

    rows: list[tuple[tuple[float, str], str, str]] = []

    # IPv4: группируем по /24
    by_net: dict[str, dict[str, int]] = defaultdict(dict)
    rest: list[tuple[str, int]] = []

    for raw, cnt in miss_ip_counts.items():
        ip = raw.strip()
        if not ip or cnt <= 0:
            continue
        net_s = _ipv4_slash24_key(ip)
        if net_s is None:
            rest.append((ip, cnt))
        else:
            by_net[net_s][ip] = by_net[net_s].get(ip, 0) + cnt

    for net_s, hosts in by_net.items():
        total = sum(hosts.values())
        net_obj = ipaddress.ip_network(net_s, strict=False)
        left = f"{net_obj.network_address}/24"
        rows.append(((-float(total), left), left, str(total)))

    for ip, cnt in rest:
        rows.append(((-float(cnt), ip), ip, str(cnt)))

    rows.sort(key=lambda item: item[0])

    for i, (_, left, right) in enumerate(rows):
        if i >= max_rows:
            overflow = len(rows) - max_rows
            if overflow > 0:
                table.add_row(f"... +{overflow} строк", "")
            break
        table.add_row(left, right)

    return table


def _ipv4_slash24_key(addr: str) -> str | None:
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return None
    if not isinstance(a, ipaddress.IPv4Address):
        return None
    net = ipaddress.ip_network(f"{addr}/24", strict=False)
    return str(net)
