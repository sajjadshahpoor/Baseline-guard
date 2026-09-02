"""Console alert channel: colored, human-readable output.

Uses raw ANSI escapes instead of a coloring library so the tool keeps
zero mandatory third-party dependencies. Color is skipped automatically
when stdout isn't a TTY (e.g. when output is piped into a log file).
"""

from __future__ import annotations

import sys

from ..diff import Severity
from .base import Alert

_COLORS = {
    Severity.INFO: "\033[36m",  # cyan
    Severity.LOW: "\033[32m",  # green
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.HIGH: "\033[31m",  # red
    Severity.CRITICAL: "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


class ConsoleAlertChannel:
    def __init__(self, stream=None, use_color: bool | None = None):
        self.stream = stream or sys.stdout
        self.use_color = use_color if use_color is not None else self.stream.isatty()

    def send(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            print(self._format(alert), file=self.stream)

    def _format(self, alert: Alert) -> str:
        label = f"[{alert.severity.name:<8}] {alert.collector}: {alert.title}"
        if not self.use_color:
            return label
        color = _COLORS.get(alert.severity, "")
        return f"{color}{label}{_RESET}"
