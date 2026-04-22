from __future__ import annotations

"""Интерактивные диалоги для сканера: y/n и выбор из списка.

Каскад fallback-ов:
1. `questionary` (prompt_toolkit) — красивый TUI со стрелками и поддержкой мыши,
   если терминал её понимает (iTerm, modern terminals).
2. `rich.prompt.Confirm` / `rich.prompt.Prompt` — стилизованный ввод с клавиатуры.
3. `input()` — самый базовый запасной вариант.

Функции возвращают результат либо бросают `PromptAborted`, если пользователь отменил
диалог (Ctrl-C / ESC) и вызывающему коду нужно корректно обработать это.

В non-TTY/бэкграунд режимах (`sys.stdin.isatty() is False`) диалоги нельзя показывать —
вызывающий код должен заранее проверить `can_prompt()` и использовать флаги вроде `--yes`.
"""

import sys
from dataclasses import dataclass
from typing import Iterable, Sequence


class PromptAborted(RuntimeError):
    """Пользователь прервал ввод (Ctrl-C / ESC / EOF)."""


@dataclass
class SelectChoice:
    label: str
    value: str


def can_prompt() -> bool:
    """True, если у нас настоящий TTY и можно безопасно показать диалог."""
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        return False


def ask_text(
    question: str,
    *,
    default: str = "",
    instruction: str | None = None,
    validate_nonempty: bool = True,
) -> str:
    """Текстовый ввод. Разрешает default при пустом. Бросает PromptAborted при отмене."""
    if not can_prompt():
        raise PromptAborted("non-interactive session")

    try:
        import questionary

        style = _default_style()

        def _validator(value: str) -> bool | str:
            if validate_nonempty and not (value or default).strip():
                return "Поле не может быть пустым"
            return True

        tip = instruction or ("Enter — подтвердить, Esc — отмена")
        result = questionary.text(
            question,
            default=default or "",
            instruction=tip,
            style=style,
            validate=_validator,
        ).ask()
        if result is None:
            raise PromptAborted("user aborted")
        return str(result).strip() or default
    except PromptAborted:
        raise
    except Exception:
        pass

    try:
        from rich.prompt import Prompt

        result = Prompt.ask(question, default=default or None, show_default=bool(default))
        value = (result or "").strip()
        if validate_nonempty and not value:
            raise PromptAborted("empty value")
        return value
    except (KeyboardInterrupt, EOFError) as exc:
        raise PromptAborted(str(exc)) from exc
    except Exception:
        pass

    try:
        suffix = f" [{default}]: " if default else ": "
        raw = input(question + suffix).strip()
    except (KeyboardInterrupt, EOFError) as exc:
        raise PromptAborted(str(exc)) from exc
    value = raw or default
    if validate_nonempty and not value.strip():
        raise PromptAborted("empty value")
    return value.strip()


def ask_password(
    question: str,
    *,
    instruction: str | None = None,
) -> str:
    """Ввод пароля (маскированный). Бросает PromptAborted при отмене."""
    if not can_prompt():
        raise PromptAborted("non-interactive session")

    try:
        import questionary

        style = _default_style()
        tip = instruction or ("символы скрыты; Enter — подтвердить, Esc — отмена")
        result = questionary.password(
            question,
            instruction=tip,
            style=style,
            validate=lambda v: True if (v or "").strip() else "Пароль не может быть пустым",
        ).ask()
        if result is None:
            raise PromptAborted("user aborted")
        return str(result)
    except PromptAborted:
        raise
    except Exception:
        pass

    try:
        from rich.prompt import Prompt

        result = Prompt.ask(question, password=True)
        value = (result or "").strip()
        if not value:
            raise PromptAborted("empty password")
        return value
    except (KeyboardInterrupt, EOFError) as exc:
        raise PromptAborted(str(exc)) from exc
    except Exception:
        pass

    import getpass

    try:
        raw = getpass.getpass(question + ": ")
    except (KeyboardInterrupt, EOFError) as exc:
        raise PromptAborted(str(exc)) from exc
    if not raw.strip():
        raise PromptAborted("empty password")
    return raw


def _default_style():
    from questionary import Style

    return Style(
        [
            ("qmark", "fg:#00afff bold"),
            ("question", "bold"),
            ("answer", "fg:#00d787 bold"),
            ("pointer", "fg:#ffaf00 bold"),
            ("highlighted", "fg:#ffaf00 bold"),
            ("selected", "fg:#00d787"),
            ("instruction", "fg:#808080 italic"),
        ]
    )


def confirm_yes_no(
    question: str,
    *,
    default: bool = False,
    instruction: str | None = None,
) -> bool:
    """Y/N-диалог. Возвращает True/False. Бросает PromptAborted при отмене.

    Пытается использовать questionary (стрелки/мышь), затем rich, затем input().
    """
    if not can_prompt():
        raise PromptAborted("non-interactive session")

    try:
        import questionary

        style = _default_style()
        full = question if not instruction else f"{question}\n  {instruction}"
        result = questionary.confirm(
            full,
            default=default,
            style=style,
            auto_enter=False,
            # questionary проксирует подходящие kwargs в prompt_toolkit.Application,
            # поэтому mouse_support=True добавляет реакцию на клик мышкой в терминале.
            mouse_support=True,
        ).ask()
        if result is None:
            raise PromptAborted("user aborted")
        return bool(result)
    except PromptAborted:
        raise
    except Exception:
        # Падение questionary (например, странный терминал) — fallback на rich
        pass

    try:
        from rich.prompt import Confirm

        return bool(Confirm.ask(question, default=default))
    except (KeyboardInterrupt, EOFError) as exc:
        raise PromptAborted(str(exc)) from exc
    except Exception:
        pass

    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        raw = input(question + suffix).strip().lower()
    except (KeyboardInterrupt, EOFError) as exc:
        raise PromptAborted(str(exc)) from exc
    if not raw:
        return default
    return raw in ("y", "yes", "д", "да")


def select_option(
    question: str,
    choices: Sequence[SelectChoice] | Iterable[tuple[str, str]],
    *,
    default_value: str | None = None,
    instruction: str | None = None,
) -> str:
    """Выбор одного значения из списка. Возвращает `value` выбранного варианта.

    choices: либо список SelectChoice, либо итерируемое кортежей (label, value).
    """
    if not can_prompt():
        raise PromptAborted("non-interactive session")

    normalized: list[SelectChoice] = []
    for item in choices:
        if isinstance(item, SelectChoice):
            normalized.append(item)
        else:
            label, value = item
            normalized.append(SelectChoice(label=str(label), value=str(value)))
    if not normalized:
        raise ValueError("select_option requires at least one choice")

    try:
        import questionary
        from questionary import Choice

        style = _default_style()
        q_choices = [Choice(title=c.label, value=c.value) for c in normalized]
        default = default_value if default_value in {c.value for c in normalized} else None
        tip = instruction or "↑/↓ стрелки или мышь, Enter — выбрать, Ctrl-C — отмена"
        result = questionary.select(
            question,
            choices=q_choices,
            default=default,
            use_shortcuts=False,
            use_arrow_keys=True,
            instruction=tip,
            style=style,
            # Включает клики мышью (поддерживается в iTerm, Terminal.app, VSCode и т.п.).
            mouse_support=True,
        ).ask()
        if result is None:
            raise PromptAborted("user aborted")
        return str(result)
    except PromptAborted:
        raise
    except Exception:
        pass

    # Fallback: rich.prompt.Prompt с нумерованным списком
    try:
        from rich.console import Console
        from rich.prompt import IntPrompt

        console = Console()
        console.print(question)
        for index, choice in enumerate(normalized, start=1):
            marker = " (default)" if default_value == choice.value else ""
            console.print(f"  [{index}] {choice.label}{marker}")
        default_index = 1
        for index, choice in enumerate(normalized, start=1):
            if default_value == choice.value:
                default_index = index
                break
        raw = IntPrompt.ask(
            "Введите номер",
            default=default_index,
            show_default=True,
            choices=[str(i) for i in range(1, len(normalized) + 1)],
        )
        return normalized[int(raw) - 1].value
    except (KeyboardInterrupt, EOFError) as exc:
        raise PromptAborted(str(exc)) from exc
    except Exception:
        pass

    # Финальный fallback: print + input
    print(question)
    for index, choice in enumerate(normalized, start=1):
        marker = " (default)" if default_value == choice.value else ""
        print(f"  [{index}] {choice.label}{marker}")
    default_index = 1
    for index, choice in enumerate(normalized, start=1):
        if default_value == choice.value:
            default_index = index
            break
    try:
        raw = input(f"Введите номер [{default_index}]: ").strip()
    except (KeyboardInterrupt, EOFError) as exc:
        raise PromptAborted(str(exc)) from exc
    if not raw:
        return normalized[default_index - 1].value
    try:
        idx = int(raw)
    except ValueError as exc:
        raise PromptAborted("invalid input") from exc
    if not 1 <= idx <= len(normalized):
        raise PromptAborted("out of range")
    return normalized[idx - 1].value
