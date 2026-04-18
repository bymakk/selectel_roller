from __future__ import annotations

from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
CONFIG_PATH = PROJECT_ROOT / "config.json"
DOTENV_PATH = PROJECT_ROOT / ".env"
TEMP_DIR = PROJECT_ROOT / "temp"
MISS_CHURN_TXT_PATH = TEMP_DIR / "miss-churn.txt"
DEFAULT_WHITELIST_PATH = PROJECT_ROOT / "whitelist.txt"


def resolve_config_path(config_path: str | Path | None = None) -> Path:
    if config_path is None:
        return CONFIG_PATH

    path = Path(config_path).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path
