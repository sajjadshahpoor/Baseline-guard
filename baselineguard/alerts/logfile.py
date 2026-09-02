"""Log-file alert channel: appends newline-delimited JSON.

JSON Lines keeps every scan's alerts machine-readable and easy to tail,
grep, or ship into a log aggregator without needing a schema migration
every time a new field is added.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import Alert


class LogFileAlertChannel:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def send(self, alerts: list[Alert]) -> None:
        if not alerts:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
