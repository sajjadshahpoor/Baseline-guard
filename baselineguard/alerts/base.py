"""Shared alert representation and channel interface."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol

from ..diff import Change, Severity
from ..collectors.base import Finding


@dataclass
class Alert:
    severity: Severity
    collector: str
    title: str
    detail: str
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def from_change(cls, change: Change) -> "Alert":
        return cls(
            severity=change.severity,
            collector=change.collector,
            title=change.summary(),
            detail=f"old={change.old!r} new={change.new!r}",
        )

    @classmethod
    def from_finding(cls, finding: Finding) -> "Alert":
        return cls(
            severity=finding.severity,
            collector=finding.collector,
            title=finding.title,
            detail=finding.detail,
        )

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.name,
            "collector": self.collector,
            "title": self.title,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


class AlertChannel(Protocol):
    """Something that can deliver a batch of alerts."""

    def send(self, alerts: list[Alert]) -> None: ...
