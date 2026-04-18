from __future__ import annotations

import json
from pathlib import Path

from .models import MatchRecord


class MatchStore:
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> dict[str, MatchRecord]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, TypeError):
            return {}

        matches = payload.get("matches", [])
        if not isinstance(matches, list):
            return {}

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
        payload = {
            "matches": [matches[match_id].to_payload() for match_id in sorted(matches)],
        }
        self.path.write_text(
            json.dumps(payload, indent=4, ensure_ascii=False),
            encoding="utf-8",
        )
