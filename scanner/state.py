from __future__ import annotations

import json
from pathlib import Path

from .models import MatchRecord


class MatchStore:
    """Хранит matches в JSON: одна секция на аккаунт (см. state_section) или весь файл — только matches (legacy)."""

    def __init__(self, path: Path, *, section: str | None = None):
        self.path = path
        self.section = (section or "").strip() or None

    def _read_raw_payload(self) -> dict[str, object]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, TypeError):
            return {}
        return raw if isinstance(raw, dict) else {}

    def load(self) -> dict[str, MatchRecord]:
        payload = self._read_raw_payload()
        matches: list[object]

        if self.section is None:
            block = payload.get("matches", [])
            matches = block if isinstance(block, list) else []
        else:
            block = payload.get(self.section)
            if isinstance(block, dict):
                m = block.get("matches", [])
                matches = m if isinstance(m, list) else []
            elif self.section == "account-1" and "matches" in payload and isinstance(payload["matches"], list):
                # legacy: один файл {"matches": [...]} → относим к account-1
                matches = payload["matches"]
            else:
                matches = []

        loaded: dict[str, MatchRecord] = {}
        for raw_match in matches:
            if not isinstance(raw_match, dict):
                continue
            match = MatchRecord.from_payload(raw_match)
            if match.id:
                loaded[match.id] = match
        return loaded

    def save(self, matches: dict[str, MatchRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        match_list = [matches[match_id].to_payload() for match_id in sorted(matches)]

        if self.section is None:
            out: dict[str, object] = {"matches": match_list}
            self.path.write_text(
                json.dumps(out, indent=4, ensure_ascii=False),
                encoding="utf-8",
            )
            return

        payload = self._read_raw_payload()
        for key in ("account-1", "account-2", "smoke"):
            if key not in payload or not isinstance(payload[key], dict):
                payload[key] = {"matches": []}
        if self.section not in payload or not isinstance(payload[self.section], dict):
            payload[self.section] = {"matches": []}
        payload[self.section] = {"matches": match_list}
        payload.pop("matches", None)

        self.path.write_text(
            json.dumps(payload, indent=4, ensure_ascii=False),
            encoding="utf-8",
        )
