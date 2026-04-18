#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PY="${ROOT}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 1; }
  python3 -m venv .venv
  "${ROOT}/.venv/bin/python" -m pip install -q --upgrade pip
  "${ROOT}/.venv/bin/python" -m pip install -q -r "${ROOT}/requirements.txt"
fi
exec "$PY" "${ROOT}/main.py" "$@"
