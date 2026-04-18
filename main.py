from __future__ import annotations

"""Точка входа: два аккаунта Selectel + Rich dashboard. Перед импортом пакетов поднимается .venv."""

import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_REQUIREMENTS = _ROOT / "requirements.txt"


def _venv_python() -> Path:
    if sys.platform == "win32":
        return _ROOT / ".venv" / "Scripts" / "python.exe"
    return _ROOT / ".venv" / "bin" / "python"


def _running_in_project_venv() -> bool:
    exe = _venv_python()
    if not exe.is_file():
        return False
    try:
        return Path(sys.executable).resolve() == exe.resolve()
    except OSError:
        return False


def _ensure_venv() -> None:
    """Создаёт .venv при отсутствии, ставит зависимости; при запуске не из venv — exec в .venv/python."""
    venv_dir = _ROOT / ".venv"
    py = _venv_python()
    fresh = not venv_dir.is_dir()
    if fresh:
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            cwd=str(_ROOT),
            check=True,
        )
    if not py.is_file():
        raise RuntimeError(f"Ожидался интерпретатор venv: {py}")
    if fresh:
        subprocess.run(
            [str(py), "-m", "pip", "install", "-q", "--upgrade", "pip"],
            cwd=str(_ROOT),
            check=True,
        )
    # Всегда синхронизируем venv с requirements.txt (новые пакеты подтягиваются и в старом .venv).
    subprocess.run(
        [str(py), "-m", "pip", "install", "-q", "-r", str(_REQUIREMENTS)],
        cwd=str(_ROOT),
        check=True,
    )
    if not _running_in_project_venv():
        script = str(Path(__file__).resolve())
        os.execv(str(py), [str(py), script, *sys.argv[1:]])


_ensure_venv()

from scanner.dual import main


if __name__ == "__main__":
    raise SystemExit(main())
