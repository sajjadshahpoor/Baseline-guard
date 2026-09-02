"""Shared interfaces for collectors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..diff import Severity


class Collector(Protocol):
    """A baseline collector: snapshot of state that should stay stable."""

    name: str

    def collect(self) -> dict[str, dict]:
        """Return ``{item_id: record}`` for the current system state."""
        ...


@dataclass
class Finding:
    """A single suspicious condition surfaced by a heuristic collector."""

    collector: str
    item_id: str
    title: str
    detail: str
    severity: Severity
