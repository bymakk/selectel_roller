from __future__ import annotations

from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
CONFIG_PATH = PROJECT_ROOT / "config.json"
TEMP_DIR = PROJECT_ROOT / "temp"
SELECTEL_RESOURCES_DIR = PROJECT_ROOT / "resources" / "selectel"
DEFAULT_WHITELIST_PATH = SELECTEL_RESOURCES_DIR / "whitelist.txt"


def resolve_config_path(config_path: str | Path | None = None) -> Path:
    if config_path is None:
        return CONFIG_PATH

    path = Path(config_path).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path
