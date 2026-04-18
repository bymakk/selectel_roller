from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from .paths import DOTENV_PATH, resolve_config_path


def _string_value(value: object, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    items: list[str] = []
    for item in value:
        candidate = _string_value(item)
        if candidate:
            items.append(candidate)
    return items


def _int_value(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class SelectelApiConfig:
    username: str = ""
    password: str = ""
    account_id: str = ""
    project_name: str = ""
    project_id: str = ""
    server_id_ru2: str = ""
    server_id_ru3: str = ""
    server_ids: list[str] = field(default_factory=list)
    ip_limit: int = 2
    target_match_count: int = 1


@dataclass
class SelectelServiceConfig:
    api: SelectelApiConfig = field(default_factory=SelectelApiConfig)
    additional_accounts: list[SelectelApiConfig] = field(default_factory=list)


@dataclass
class ScannerConfig:
    selectel: SelectelServiceConfig = field(default_factory=SelectelServiceConfig)


def _build_api_config(payload: object) -> SelectelApiConfig:
    if not isinstance(payload, dict):
        return SelectelApiConfig()

    return SelectelApiConfig(
        username=_string_value(payload.get("username")),
        password=_string_value(payload.get("password")),
        account_id=_string_value(payload.get("account_id")),
        project_name=_string_value(payload.get("project_name")),
        project_id=_string_value(payload.get("project_id")),
        server_id_ru2=_string_value(payload.get("server_id_ru2")),
        server_id_ru3=_string_value(payload.get("server_id_ru3")),
        server_ids=_string_list(payload.get("server_ids")),
        ip_limit=_int_value(payload.get("ip_limit", 2), 2),
        target_match_count=_int_value(payload.get("target_match_count", 1), 1),
    )


def _build_service_config(payload: object) -> SelectelServiceConfig:
    if not isinstance(payload, dict):
        return SelectelServiceConfig()

    raw_accounts = payload.get("additional_accounts")
    accounts = [
        _build_api_config(item)
        for item in raw_accounts
        if isinstance(raw_accounts, list)
    ]

    return SelectelServiceConfig(
        api=_build_api_config(payload.get("api")),
        additional_accounts=accounts,
    )


def _parse_csv_env(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _apply_env_to_api(api: SelectelApiConfig, *, secondary: bool) -> None:
    """Подставляет секреты и идентификаторы из окружения (в т.ч. из .env)."""
    if secondary:
        mapping = (
            ("username", "SEL2_USERNAME"),
            ("password", "SEL2_PASSWORD"),
            ("account_id", "SEL2_ACCOUNT_ID"),
            ("project_name", "SEL2_PROJECT_NAME"),
            ("project_id", "SEL2_PROJECT_ID"),
        )
    else:
        mapping = (
            ("username", "SEL_USERNAME"),
            ("password", "SEL_PASSWORD"),
            ("account_id", "SEL_ACCOUNT_ID"),
            ("project_name", "SEL_PROJECT_NAME"),
            ("project_id", "SEL_PROJECT_ID"),
        )
    for field_name, env_key in mapping:
        raw = os.getenv(env_key, "").strip()
        if raw:
            setattr(api, field_name, raw)
    if secondary:
        ru2 = os.getenv("SEL2_SERVER_ID_RU2", "").strip()
        ru3 = os.getenv("SEL2_SERVER_ID_RU3", "").strip()
        if ru2:
            api.server_id_ru2 = ru2
        if ru3:
            api.server_id_ru3 = ru3
        ids = _parse_csv_env(os.getenv("SEL2_SERVER_IDS", ""))
        if ids:
            api.server_ids = ids
    else:
        ru2 = os.getenv("SEL_SERVER_ID_RU2", "").strip()
        ru3 = os.getenv("SEL_SERVER_ID_RU3", "").strip()
        if ru2:
            api.server_id_ru2 = ru2
        if ru3:
            api.server_id_ru3 = ru3


def _overlay_selectel_env(svc: SelectelServiceConfig) -> None:
    _apply_env_to_api(svc.api, secondary=False)
    for index, account in enumerate(svc.additional_accounts):
        if index == 0:
            _apply_env_to_api(account, secondary=True)


def load_scanner_config(config_path: str | Path | None = None) -> ScannerConfig:
    load_dotenv(DOTENV_PATH, override=False)
    path = resolve_config_path(config_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return ScannerConfig()
    except (OSError, ValueError, TypeError):
        return ScannerConfig()

    if not isinstance(payload, dict):
        return ScannerConfig()

    cfg = ScannerConfig(selectel=_build_service_config(payload.get("selectel")))
    _overlay_selectel_env(cfg.selectel)
    return cfg
