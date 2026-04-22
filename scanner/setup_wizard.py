from __future__ import annotations

"""Setup Wizard — при первом запуске спрашивает у пользователя минимум данных.

Цель — сделать запуск максимально простым даже для человека, который никогда
не работал с Selectel API. Вопросы формулируются подробно, с указанием, где
именно в панели Selectel искать нужное значение.

После успешного прохождения мастер сам запишет значения в `.env` — следующий
запуск уже не будет ничего спрашивать.
"""

import os
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.panel import Panel

from .paths import DOTENV_PATH
from .prompts import (
    PromptAborted,
    ask_password,
    ask_text,
    can_prompt,
    confirm_yes_no,
)
from .rich_ui import DASHBOARD_PANEL_PADDING


REQUIRED_PRIMARY = ("SEL_USERNAME", "SEL_PASSWORD", "SEL_ACCOUNT_ID")
REQUIRED_SECONDARY = ("SEL2_USERNAME", "SEL2_PASSWORD", "SEL2_ACCOUNT_ID")


def needs_setup() -> bool:
    """True, если не задан ни один аккаунт — значит, пользователь ещё не проходил настройку."""
    primary_ok = all(_env(key) for key in REQUIRED_PRIMARY)
    secondary_ok = all(_env(key) for key in REQUIRED_SECONDARY)
    return not (primary_ok or secondary_ok)


def run_setup_wizard(console: Console) -> None:
    """Запускает интерактивный опрос и пишет результат в `.env`.

    Бросает RuntimeError, если нет TTY (без интерактива wizard не имеет смысла),
    или если пользователь прервал ввод.
    """
    if not can_prompt():
        raise RuntimeError(
            "Запустите программу в обычном терминале — нужен интерактивный ввод "
            "или заранее заполните .env (см. .env.example)."
        )

    _render_welcome(console)

    primary = _ask_account(
        console,
        account_label="Первый аккаунт",
        env_prefix="SEL_",
        required=True,
    )

    values: dict[str, str] = dict(primary)

    try:
        add_second = confirm_yes_no(
            "Есть второй аккаунт Selectel? (можно запустить перебор на двух параллельно)",
            default=False,
            instruction="если нет — просто нажмите Enter",
        )
    except PromptAborted:
        add_second = False

    if add_second:
        secondary = _ask_account(
            console,
            account_label="Второй аккаунт",
            env_prefix="SEL2_",
            required=True,
        )
        values.update(secondary)

    _persist_env_values(values)
    _apply_to_process(values)

    console.print(
        Panel(
            "[bold green]Готово![/bold green] Значения сохранены в [cyan].env[/cyan]. "
            "Программа продолжит запуск автоматически.\n"
            "В следующий раз этого шага не будет — всё уже настроено.",
            border_style="green",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )


def _render_welcome(console: Console) -> None:
    text = (
        "[bold]Первый запуск — давайте настроим доступ к Selectel.[/bold]\n\n"
        "Это займёт 1–2 минуты. Нужно указать:\n"
        "  • логин и пароль сервисного пользователя Selectel;\n"
        "  • номер аккаунта (он же «ID аккаунта»).\n\n"
        "Где это взять в панели Selectel:\n"
        "  1. Откройте [cyan]https://my.selectel.ru[/cyan].\n"
        "  2. Правый верхний угол — под email'ом будет [bold]ID аккаунта[/bold] "
        "(число вида 123456).\n"
        "  3. Раздел [bold]IAM → Сервисные пользователи[/bold] — создайте или "
        "возьмите существующего; там же его логин и пароль.\n\n"
        "Секреты сохранятся в локальный файл [cyan].env[/cyan] "
        "(в git не попадёт, если не трогать [cyan].gitignore[/cyan])."
    )
    console.print(
        Panel(
            text,
            title="ip-roller — первичная настройка",
            border_style="cyan",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )


def _ask_account(
    console: Console,
    *,
    account_label: str,
    env_prefix: str,
    required: bool,
) -> dict[str, str]:
    """Спрашивает у пользователя логин/пароль/аккаунт для одного аккаунта Selectel."""
    console.print(
        Panel(
            f"[bold]{account_label}[/bold] — заполните три поля.",
            border_style="blue",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )
    try:
        username = ask_text(
            f"{account_label}: логин сервисного пользователя",
            instruction=(
                "Selectel → IAM → Сервисные пользователи → имя пользователя "
                "(обычно короткое: например, «api» или «roller»)"
            ),
        )
        password = ask_password(
            f"{account_label}: пароль этого пользователя",
            instruction=(
                "пароль создаётся при создании пользователя; если забыли — "
                "сгенерируйте новый в панели и введите его сюда"
            ),
        )
        account_id = ask_text(
            f"{account_label}: ID аккаунта Selectel",
            instruction=(
                "число, видно в правом верхнем углу панели под email'ом "
                "(пример: 575493)"
            ),
        )
    except PromptAborted as exc:
        raise RuntimeError(
            f"Настройка отменена пользователем ({account_label}). "
            "Запустите снова, когда будете готовы ввести данные."
        ) from exc

    return {
        f"{env_prefix}USERNAME": username,
        f"{env_prefix}PASSWORD": password,
        f"{env_prefix}ACCOUNT_ID": account_id,
    }


def _env(key: str) -> str:
    return (os.getenv(key) or "").strip()


def _apply_to_process(values: dict[str, str]) -> None:
    for key, value in values.items():
        if value:
            os.environ[key] = value


def _persist_env_values(values: dict[str, str]) -> None:
    """Аккуратно обновляет `.env`, сохраняя существующее форматирование.

    Если файла нет — создаёт из шаблона `.env.example` (если он есть).
    """
    path: Path = DOTENV_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    if not path.exists():
        example = path.parent / ".env.example"
        if example.exists():
            path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            path.write_text("", encoding="utf-8")

    existing = path.read_text(encoding="utf-8")
    updated = _rewrite_env_lines(existing.splitlines(), values)
    path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def _rewrite_env_lines(lines: Iterable[str], values: dict[str, str]) -> list[str]:
    pending = {k: v for k, v in values.items() if v}
    out: list[str] = []
    written: set[str] = set()

    for raw in lines:
        stripped = raw.lstrip()
        # комментарии и пустые строки переносим как есть
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out.append(raw)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in pending and key not in written:
            out.append(f"{key}={_quote_if_needed(pending[key])}")
            written.add(key)
        else:
            out.append(raw)

    missing = [(k, v) for k, v in pending.items() if k not in written]
    if missing:
        if out and out[-1].strip():
            out.append("")
        out.append("# Заполнено при первичной настройке ip-roller:")
        for key, value in missing:
            out.append(f"{key}={_quote_if_needed(value)}")
    return out


def _quote_if_needed(value: str) -> str:
    """Оборачивает значение в двойные кавычки, если в нём есть пробелы или спецсимволы.

    Для `.env` это нужно, чтобы `python-dotenv` правильно его распарсил.
    """
    if value == "":
        return '""'
    unsafe = set(" \t\"'#`$()|&;<>")
    if any(ch in unsafe for ch in value):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value
