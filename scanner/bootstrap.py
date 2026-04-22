from __future__ import annotations

"""Автоподготовка облака Selectel перед запуском сканера.

Задачи:
- если проект не задан в .env — найти через VPC Resell API `/v2/projects`.
  Если проектов 0 — создать «ip-roller». Если 1 — взять его. Если >1 — выбрать по
  имени (SEL_PROJECT_NAME) / SEL2_PROJECT_NAME или показать список и попросить y/n.
- сохранить полученный project_id обратно в .env (через `python-dotenv`),
  чтобы следующий запуск уже не дергал Resell лишний раз.
- перед стартом удалений убедиться, что в проекте нет «рабочих» виртуальных машин:
  если есть — остановиться и показать список, пока пользователь не подтвердит (--yes).

Безопасность whitelist.txt:
- существующую защиту в `scanner/main.py::_delete_records` трогать не нужно,
  она гарантирует, что whitelist-адреса не попадут в DELETE ни на старте, ни во время работы.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .client import SelectelScannerClient
from .models import ScannerSettings
from .paths import DOTENV_PATH
from .prompts import PromptAborted, SelectChoice, can_prompt, confirm_yes_no, select_option
from .resell import ResellProject, SelectelResellClient
from .rich_ui import DASHBOARD_PANEL_PADDING, DASHBOARD_TABLE_BOX, DASHBOARD_TABLE_PADDING
from .whitelist import WhitelistMatcher, WhitelistSummary


DEFAULT_PROJECT_NAME = "ip-roller"


def render_whitelist_banner(console: Console, path: Path) -> WhitelistSummary:
    """Показывает, что именно защищено whitelist.txt и сколько записей загружено.

    Нужен, чтобы пользователь видел: эти адреса НЕ будут удалены ни при каких
    условиях — ни во время перебора, ни при старте, ни после перезапуска.
    """
    matcher = WhitelistMatcher.from_path(path)
    summary = matcher.summary
    entries = _preview_whitelist_entries(path, limit=5)
    preview = "\n".join(f"  • [green]{entry}[/green]" for entry in entries) or "  [dim]пусто[/dim]"
    text = (
        f"[bold]Защита Whitelist[/bold] — загружено [cyan]{summary.total_entries}[/cyan] "
        f"записей из [cyan]{path}[/cyan]\n"
        f"подсетей: {summary.network_entries}, одиночных IP: {summary.single_ip_entries}\n\n"
        f"Примеры того, что НЕ будет удаляться:\n{preview}\n\n"
        "[dim]Любой floating IP, попадающий в whitelist, пропускается во всех ветках удаления —\n"
        "стартовой чистке, фоновой сверке, батч-удалении и cleanup после перезапуска.[/dim]"
    )
    console.print(
        Panel(
            text,
            title="whitelist.txt",
            border_style="green",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )
    return summary


def _preview_whitelist_entries(path: Path, *, limit: int = 5) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            out.append(entry)
            if len(out) >= limit:
                break
    except OSError:
        return []
    return out


@dataclass
class BootstrapOutcome:
    project_id: str
    project_name: str
    created: bool
    resolved_from: str  # "env", "resell-single", "resell-by-name", "resell-first", "created"


async def ensure_project_resolved(
    settings: ScannerSettings,
    *,
    console: Console,
    account_label: str,
    dotenv_env_prefix: str,
    desired_name: str = DEFAULT_PROJECT_NAME,
    auto_create: bool = True,
    interactive: bool = True,
) -> BootstrapOutcome:
    """Гарантирует, что у settings задан project_id (или project_name) под аккаунт.

    Изменяет `settings` inplace и возвращает сводку. Если project_id уже есть в env — ничего не меняет.
    """
    # Источник истины для bootstrap — env с нужным префиксом. В dual значения
    # могут прийти как фоллбэк с другого аккаунта, поэтому settings.* игнорируем.
    project_id = os.getenv(f"{dotenv_env_prefix}PROJECT_ID", "").strip()
    project_name = os.getenv(f"{dotenv_env_prefix}PROJECT_NAME", "").strip()

    # Перезаписать settings значениями из env, чтобы последующий код не использовал
    # «чужой» project из фоллбэка.
    settings.project_id = project_id
    settings.project_name = project_name

    if project_id:
        return BootstrapOutcome(
            project_id=project_id,
            project_name=project_name,
            created=False,
            resolved_from="env",
        )

    resell = SelectelResellClient(
        username=settings.username,
        password=settings.password,
        account_id=settings.account_id,
    )
    try:
        projects = await resell.list_projects()
        chosen, reason, created = _resolve_project(
            projects,
            desired_by_user=project_name,
            fallback_name=desired_name,
            auto_create=auto_create,
            account_label=account_label,
            env_prefix=dotenv_env_prefix,
            console=console,
            interactive=interactive,
        )
        if reason == "to-create":
            name_for_create = project_name or desired_name
            console.print(
                Panel(
                    f"[{account_label}] Создаю проект «{name_for_create}»…",
                    border_style="yellow",
                    padding=DASHBOARD_PANEL_PADDING,
                )
            )
            chosen = await resell.create_project(
                name_for_create, description="Auto-created by ip-roller"
            )
            reason = "created"
            created = True
    finally:
        await resell.close()

    settings.project_id = chosen.id
    if chosen.name and not settings.project_name:
        settings.project_name = chosen.name

    _persist_env(
        {
            f"{dotenv_env_prefix}PROJECT_ID": chosen.id,
            f"{dotenv_env_prefix}PROJECT_NAME": chosen.name,
        }
    )

    console.print(
        Panel(
            f"[{account_label}] Проект: [bold]{chosen.name}[/bold]  "
            f"id=[cyan]{chosen.id}[/cyan]  источник: {reason}",
            border_style="green",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )
    return BootstrapOutcome(
        project_id=chosen.id,
        project_name=chosen.name,
        created=created,
        resolved_from=reason,
    )


async def confirm_no_active_vms(
    settings: ScannerSettings,
    *,
    console: Console,
    account_label: str,
    regions: Iterable[str] | None = None,
    assume_yes: bool = False,
    interactive: bool = True,
) -> None:
    """Проверяет, что в проекте нет рабочих VM; если есть — требует подтверждения.

    Выбрасывает RuntimeError, если подтверждения не получено (в non-TTY без --yes).
    Это защита от ситуации «указали не тот проект» — IP на рабочих серверах не удалятся,
    но сам факт наличия VM означает, что запускать айпи-перебор тут рискованно.
    """
    client = SelectelScannerClient(
        username=settings.username,
        password=settings.password,
        account_id=settings.account_id,
        project_name=settings.project_name,
        project_id=settings.project_id,
        regions=tuple(regions) if regions else tuple(settings.regions),
    )
    try:
        await client.ensure_authenticated()
        target_regions = set(regions) if regions else set(settings.regions) or set(client.compute_regions())
        servers = await client.list_servers(regions=target_regions) if target_regions else []
    finally:
        await client.close()

    if not servers:
        return

    active = [s for s in servers if s.get("status", "").upper() in {"ACTIVE", "BUILD", "BUILDING"}]
    table = Table(
        title=f"[{account_label}] Найдены виртуальные машины в проекте",
        box=DASHBOARD_TABLE_BOX,
        padding=DASHBOARD_TABLE_PADDING,
    )
    table.add_column("Имя", style="bold")
    table.add_column("Регион", no_wrap=True)
    table.add_column("Статус")
    table.add_column("ID", overflow="fold")
    for s in servers:
        table.add_row(s.get("name") or "-", s.get("region") or "-", s.get("status") or "-", s.get("id") or "-")
    console.print(table)

    console.print(
        Panel(
            "Айпи-перебор создаёт и удаляет floating IP в этом проекте.\n"
            "Floating IP с привязкой к порту (к VM) и адреса из whitelist.txt НЕ удаляются.\n"
            "Но убедитесь, что этот проект — действительно тот, где вы хотите запускать перебор.",
            title=f"{len(servers)} VM (в т.ч. активных: {len(active)}) — требуется подтверждение",
            border_style="yellow",
            padding=DASHBOARD_PANEL_PADDING,
        )
    )

    if assume_yes:
        console.print(f"[{account_label}] Флаг --yes: продолжаю несмотря на наличие VM.", style="yellow")
        return

    if not interactive or not can_prompt():
        raise RuntimeError(
            f"[{account_label}] В проекте есть VM — остановка. Запустите с --yes, "
            "если действительно хотите продолжить."
        )

    try:
        answer = confirm_yes_no(
            f"[{account_label}] Продолжить айпи-перебор в этом проекте?",
            default=False,
            instruction="floating IP с привязкой к VM и whitelist-адреса удаляться не будут",
        )
    except PromptAborted as exc:
        raise RuntimeError(
            f"[{account_label}] Отмена: подтверждение не получено."
        ) from exc
    if not answer:
        raise RuntimeError(f"[{account_label}] Отмена: не подтверждено пользователем.")


def _resolve_project(
    projects: list[ResellProject],
    *,
    desired_by_user: str,
    fallback_name: str,
    auto_create: bool,
    account_label: str,
    env_prefix: str,
    console: Console,
    interactive: bool = True,
) -> tuple[ResellProject | None, str, bool]:
    """Выбирает проект: по умолчанию — отдельный `ip-roller` (не трогая другие).

    Возвращает `(project, reason, already_created)`. `reason == "to-create"` —
    сигнал вызывающему коду, что нужно сделать `POST /projects` с именем
    `desired_by_user or fallback_name`.

    Логика:
    - Если пользователь явно задал SEL_PROJECT_NAME / SEL_PROJECT_ID — уважаем его выбор:
      ищем этот проект; если нет и включено автосоздание — создаём с указанным именем.
    - Иначе ищем специальный проект `ip-roller` (или что задано в --auto-project-name):
      если уже есть — используем, если нет — создаём. Другие проекты пользователя
      не трогаем.
    - В интерактивном TTY при множестве проектов пользователь может выбрать вручную
      (на случай, если захочет переиспользовать конкретный проект).
    """
    if desired_by_user:
        by_name = _pick_by_name(projects, desired_by_user)
        if by_name is not None:
            return by_name, "resell-by-name", False
        if not auto_create:
            raise RuntimeError(
                f"[{account_label}] Проект «{desired_by_user}» не найден, автосоздание выключено."
            )
        return None, "to-create", False

    # Нет явного указания — стремимся иметь отдельный проект под роллер.
    dedicated = _pick_by_name(projects, fallback_name)
    if dedicated is not None:
        return dedicated, "resell-dedicated", False

    if not auto_create:
        if projects and interactive and can_prompt():
            return _prompt_project_from_list(projects, account_label=account_label, console=console)
        raise RuntimeError(
            f"[{account_label}] В аккаунте нет проекта «{fallback_name}», "
            "а автосоздание выключено. Снимите --no-auto-create-project или "
            f"задайте {env_prefix}PROJECT_NAME вручную."
        )

    # auto_create=True → создаём dedicated project, не трогая остальные
    return None, "to-create", False


def _prompt_project_from_list(
    projects: list[ResellProject],
    *,
    account_label: str,
    console: Console,
) -> tuple[ResellProject, str, bool]:
    """Показывает интерактивный выбор проекта (на случай, когда автосоздание запрещено)."""
    _render_projects_list(
        console,
        projects,
        title=f"[{account_label}] Выберите проект для айпи-перебора",
    )
    choices = [
        SelectChoice(
            label=f"{project.name}    id={project.id}",
            value=project.id,
        )
        for project in projects
    ]
    try:
        selected_value = select_option(
            f"[{account_label}] Какой проект использовать?",
            choices,
        )
    except PromptAborted as exc:
        raise RuntimeError(
            f"[{account_label}] Выбор проекта отменён пользователем."
        ) from exc
    for project in projects:
        if project.id == selected_value:
            return project, "user-selected", False
    raise RuntimeError(
        f"[{account_label}] Внутренняя ошибка: выбранный id {selected_value} не найден."
    )


def _pick_by_name(projects: list[ResellProject], name: str) -> ResellProject | None:
    target = (name or "").strip().casefold()
    if not target:
        return None
    for project in projects:
        if project.name.casefold() == target:
            return project
    return None


def _render_projects_list(console: Console, projects: list[ResellProject], *, title: str) -> None:
    table = Table(title=title, box=DASHBOARD_TABLE_BOX, padding=DASHBOARD_TABLE_PADDING)
    table.add_column("Название", style="bold")
    table.add_column("ID", overflow="fold")
    for project in projects:
        table.add_row(project.name or "-", project.id)
    console.print(table)


def _persist_env(values: dict[str, str]) -> None:
    """Аккуратно записывает/обновляет переменные в `.env` проекта.

    Используется без зависимостей от python-dotenv.set_key, чтобы случайно не повредить
    существующее форматирование файла (нестандартные кавычки и т. п.).
    """
    path: Path = DOTENV_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
    except OSError:
        return

    lines = existing.splitlines()
    updated: dict[str, bool] = {key: False for key in values}
    out: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#") or "=" not in stripped:
            out.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in values and not updated[key]:
            out.append(f"{key}={values[key]}")
            updated[key] = True
        else:
            out.append(line)

    extra: list[str] = []
    for key, flag in updated.items():
        if not flag and values.get(key):
            extra.append(f"{key}={values[key]}")

    if extra:
        if out and out[-1].strip():
            out.append("")
        out.append("# Автоматически записано ip-roller:")
        out.extend(extra)

    try:
        path.write_text("\n".join(out) + ("\n" if out and not out[-1].endswith("\n") else ""), encoding="utf-8")
        os.environ.update({k: v for k, v in values.items() if v})
    except OSError:
        return
