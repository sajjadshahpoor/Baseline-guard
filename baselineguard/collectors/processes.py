"""Heuristic process collector.

Unlike the baseline collectors, this one doesn't diff against a stored
snapshot — PIDs and short-lived processes churn constantly, so a strict
diff would be almost pure noise. Instead it inspects the *currently
running* process table on every scan and flags patterns that are rarely
legitimate:

* a process executing from a world-writable scratch directory
  (``/tmp``, ``/dev/shm``, ...) — a common spot for a dropped payload;
* a process whose backing binary has been deleted from disk while still
  running (``exe -> /path (deleted)``) — a classic way to hide a binary
  from a filesystem scan while it keeps executing in memory.

Requires a Linux-style ``/proc``.
"""

from __future__ import annotations

from pathlib import Path

from ..diff import Severity
from .base import Finding


class ProcessCollector:
    name = "processes"

    def __init__(
        self,
        suspicious_dirs: list[str] | None = None,
        flag_deleted_running_binaries: bool = True,
        proc_dir: str = "/proc",
    ):
        self.suspicious_dirs = suspicious_dirs or ["/tmp", "/var/tmp", "/dev/shm"]
        self.flag_deleted_running_binaries = flag_deleted_running_binaries
        self.proc_dir = Path(proc_dir)

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.proc_dir.is_dir():
            return findings

        try:
            entries = list(self.proc_dir.iterdir())
        except OSError:
            return findings

        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = entry.name
            exe_target = self._read_exe(entry)
            cmdline = self._read_cmdline(entry)

            if exe_target is None:
                continue

            deleted = exe_target.endswith(" (deleted)")
            real_path = exe_target[: -len(" (deleted)")] if deleted else exe_target

            if deleted and self.flag_deleted_running_binaries:
                findings.append(
                    Finding(
                        collector=self.name,
                        item_id=f"pid:{pid}",
                        title="Process running from a deleted binary",
                        detail=f"pid={pid} exe={real_path} cmdline={cmdline!r}",
                        severity=Severity.CRITICAL,
                    )
                )
                continue

            if any(real_path.startswith(d) for d in self.suspicious_dirs):
                findings.append(
                    Finding(
                        collector=self.name,
                        item_id=f"pid:{pid}",
                        title="Process executing from a writable scratch directory",
                        detail=f"pid={pid} exe={real_path} cmdline={cmdline!r}",
                        severity=Severity.HIGH,
                    )
                )

        return findings

    def _read_exe(self, proc_entry: Path) -> str | None:
        try:
            return str((proc_entry / "exe").readlink())
        except (OSError, RuntimeError):
            return None

    def _read_cmdline(self, proc_entry: Path) -> str:
        try:
            raw = (proc_entry / "cmdline").read_bytes()
        except OSError:
            return ""
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
