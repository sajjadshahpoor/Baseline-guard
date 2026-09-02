"""Diff engine: compares a fresh snapshot against the signed baseline.

Each collector produces a flat ``{item_id: record}`` mapping. Diffing is
therefore collector-agnostic — the interesting part is *severity*, which
is deliberately not a single fixed value per collector. A modified log
rotation config and a modified ``/etc/shadow`` are both "a file changed",
but they are not the same event, so ``classify_severity`` inspects the
records themselves for a handful of well-known red flags (new SUID bits,
new UID-0 accounts, keys added to root's authorized_keys, ...) before
falling back to a per-collector default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[name.upper()]


_DEFAULT_SEVERITY = {
    "files": Severity.MEDIUM,
    "users": Severity.HIGH,
    "ssh_keys": Severity.HIGH,
    "cron": Severity.HIGH,
}

ADDED = "added"
REMOVED = "removed"
MODIFIED = "modified"


@dataclass
class Change:
    collector: str
    item_id: str
    change_type: str
    old: dict | None
    new: dict | None
    changed_fields: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM

    def summary(self) -> str:
        if self.change_type == ADDED:
            return f"[{self.collector}] new: {self.item_id}"
        if self.change_type == REMOVED:
            return f"[{self.collector}] removed: {self.item_id}"
        fields = ", ".join(self.changed_fields)
        return f"[{self.collector}] changed ({fields}): {self.item_id}"


def diff_snapshots(collector: str, old: dict[str, dict], new: dict[str, dict]) -> list[Change]:
    changes: list[Change] = []

    for item_id in new.keys() - old.keys():
        record = new[item_id]
        changes.append(
            Change(
                collector=collector,
                item_id=item_id,
                change_type=ADDED,
                old=None,
                new=record,
                severity=classify_severity(collector, ADDED, None, record),
            )
        )

    for item_id in old.keys() - new.keys():
        record = old[item_id]
        changes.append(
            Change(
                collector=collector,
                item_id=item_id,
                change_type=REMOVED,
                old=record,
                new=None,
                severity=classify_severity(collector, REMOVED, record, None),
            )
        )

    for item_id in old.keys() & new.keys():
        old_record, new_record = old[item_id], new[item_id]
        changed_fields = sorted(
            key
            for key in set(old_record) | set(new_record)
            if old_record.get(key) != new_record.get(key)
        )
        if not changed_fields:
            continue
        changes.append(
            Change(
                collector=collector,
                item_id=item_id,
                change_type=MODIFIED,
                old=old_record,
                new=new_record,
                changed_fields=changed_fields,
                severity=classify_severity(collector, MODIFIED, old_record, new_record),
            )
        )

    return changes


def classify_severity(
    collector: str, change_type: str, old: dict | None, new: dict | None
) -> Severity:
    default = _DEFAULT_SEVERITY.get(collector, Severity.MEDIUM)

    if collector == "files":
        record = new or old or {}
        if change_type == MODIFIED and old and new and old.get("hash") != new.get("hash"):
            default = Severity.HIGH
        if record.get("suid") or record.get("sgid"):
            return Severity.CRITICAL
        if record.get("path", "").startswith(("/etc/passwd", "/etc/shadow", "/etc/sudoers")):
            return Severity.CRITICAL

    if collector == "users":
        record = new or old or {}
        if change_type == ADDED and record.get("uid") == 0:
            return Severity.CRITICAL
        if change_type == MODIFIED and old and new and old.get("uid") != new.get("uid"):
            return Severity.CRITICAL

    if collector == "ssh_keys":
        record = new or old or {}
        if change_type == ADDED and record.get("user") == "root":
            return Severity.CRITICAL

    return default
