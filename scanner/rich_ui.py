from __future__ import annotations

import sys
from typing import TextIO

from rich.box import SIMPLE
from rich.console import Console
from rich.theme import Theme

# Плотный вид: тонкие границы таблиц и минимальные отступы — в том же окне терминала помещается больше строк.
DASHBOARD_TABLE_BOX = SIMPLE
DASHBOARD_PANEL_PADDING = (0, 1)
DASHBOARD_TABLE_PADDING = (0, 0)

_DASHBOARD_THEME = Theme(
    {
        "table.header": "bold",
    }
)


def dashboard_console(*, file: TextIO | None = None) -> Console:
    """Console для Rich-дашборда: общая тема; размер шрифта — настройка терминала."""
    return Console(file=file, theme=_DASHBOARD_THEME)


def dashboard_console_stderr() -> Console:
    return Console(file=sys.stderr, theme=_DASHBOARD_THEME)
