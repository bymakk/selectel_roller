#!/usr/bin/env bash
# run.sh — запуск Selectel IP Roller на macOS и Linux.
# Автоматически устанавливает Python 3, создаёт .venv и ставит зависимости.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# ── 1. Найти или установить Python 3.10+ ─────────────────────────────────────
_find_python() {
  for cmd in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$cmd" &>/dev/null; then
      local ver
      ver="$("$cmd" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null || echo "(0, 0)")"
      if "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null; then
        echo "$cmd"
        return 0
      fi
    fi
  done
  return 1
}

_install_python_macos() {
  echo ""
  echo "Python 3.10+ не найден. Устанавливаю через Homebrew..."
  if ! command -v brew &>/dev/null; then
    echo "Homebrew не найден — устанавливаю Homebrew (это может занять несколько минут)..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # homebrew может добавиться в PATH только в новом шелле — попробуем вручную
    for p in "/opt/homebrew/bin" "/usr/local/bin"; do
      [[ -f "$p/brew" ]] && export PATH="$p:$PATH" && break
    done
  fi
  brew install python3
}

_install_python_linux() {
  echo ""
  echo "Python 3.10+ не найден. Пытаюсь установить через пакетный менеджер..."
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y python3 python3-venv python3-pip
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y python3
  elif command -v yum &>/dev/null; then
    sudo yum install -y python3
  elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm python
  elif command -v zypper &>/dev/null; then
    sudo zypper install -y python3
  else
    echo ""
    echo "Не удалось определить пакетный менеджер."
    echo "Установите Python 3.10+ вручную: https://www.python.org/downloads/"
    exit 1
  fi
}

PYTHON3=""
if ! PYTHON3="$(_find_python)"; then
  OS="$(uname -s)"
  if [[ "$OS" == "Darwin" ]]; then
    _install_python_macos
  else
    _install_python_linux
  fi
  # повторная попытка после установки
  if ! PYTHON3="$(_find_python)"; then
    echo ""
    echo "Python 3.10+ всё ещё не найден после установки."
    echo "Перезапустите терминал или установите вручную: https://www.python.org/downloads/"
    exit 1
  fi
fi

echo "Используем Python: $PYTHON3 ($("$PYTHON3" --version))"

# ── 2. Создать .venv и установить зависимости ────────────────────────────────
PY="${ROOT}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "Создаю виртуальное окружение .venv..."
  "$PYTHON3" -m venv "${ROOT}/.venv"
  echo "Устанавливаю зависимости (занимает ~30 секунд при первом запуске)..."
  "${ROOT}/.venv/bin/python" -m pip install -q --upgrade pip
  "${ROOT}/.venv/bin/python" -m pip install -q -r "${ROOT}/requirements.txt"
else
  # Обновляем пакеты при изменении requirements.txt
  "${ROOT}/.venv/bin/python" -m pip install -q -r "${ROOT}/requirements.txt"
fi

# ── 3. Запустить программу ───────────────────────────────────────────────────
exec "$PY" "${ROOT}/main.py" "$@"
