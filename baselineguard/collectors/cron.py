"""Scheduled-task collector: system crontabs, cron.d, and per-user crontabs.

Cron is a favorite persistence mechanism precisely because it's easy to
forget about — a single added line in ``/etc/cron.d`` blends in with
dozens of legitimate entries. This collector hashes each *entry* (not
just each file) so additions/removals are reported at line granularity.
"""

from __future__ import annotations

from pathlib import Path

from ..hashing import hash_bytes


class CronCollector:
    name = "cron"

    def __init__(
        self,
        system_crontab: str = "/etc/crontab",
        cron_d_dir: str = "/etc/cron.d",
        user_crontab_dir: str = "/var/spool/cron/crontabs",
    ):
        self.system_crontab = Path(system_crontab)
        self.cron_d_dir = Path(cron_d_dir)
        self.user_crontab_dir = Path(user_crontab_dir)

    def collect(self) -> dict[str, dict]:
        records: dict[str, dict] = {}

        if self.system_crontab.is_file():
            records.update(self._entries_from_file("system", self.system_crontab))

        for entry in self._safe_iterdir(self.cron_d_dir):
            if entry.is_file():
                records.update(self._entries_from_file(f"cron.d/{entry.name}", entry))

        for entry in self._safe_iterdir(self.user_crontab_dir):
            if entry.is_file():
                records.update(self._entries_from_file(f"user/{entry.name}", entry))

        return records

    @staticmethod
    def _safe_iterdir(directory: Path) -> list[Path]:
        if not directory.is_dir():
            return []
        try:
            return sorted(directory.iterdir())
        except OSError:
            return []

    @staticmethod
    def _entries_from_file(source: str, path: Path) -> dict[str, dict]:
        entries: dict[str, dict] = {}
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return entries

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            digest = hash_bytes(stripped.encode("utf-8"))[:16]
            item_id = f"{source}:{lineno}:{digest}"
            entries[item_id] = {"source": source, "line": stripped}
        return entries
