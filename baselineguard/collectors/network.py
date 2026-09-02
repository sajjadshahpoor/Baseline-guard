"""Heuristic network collector: flags unexpected listening sockets.

Reads ``/proc/net/tcp`` and ``/proc/net/tcp6`` directly rather than
shelling out to ``ss``/``netstat``, so it has no external command
dependency. Like the process collector, this runs fresh on every scan
and compares against a configured allowlist rather than a stored
baseline, since which ports happen to be listening is a policy question
("should this port be open"), not a drift question ("did this change").
"""

from __future__ import annotations

from pathlib import Path

from ..diff import Severity
from .base import Finding

_TCP_LISTEN_STATE = "0A"


class NetworkCollector:
    name = "network"

    def __init__(
        self,
        allowed_ports: list[int] | None = None,
        proc_net_dir: str = "/proc/net",
    ):
        self.allowed_ports = set(allowed_ports or [])
        self.proc_net_dir = Path(proc_net_dir)

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        seen_ports: set[int] = set()

        for source, family in (("tcp", "IPv4"), ("tcp6", "IPv6")):
            path = self.proc_net_dir / source
            for port in self._listening_ports(path):
                if port in seen_ports:
                    continue
                seen_ports.add(port)
                if port not in self.allowed_ports:
                    findings.append(
                        Finding(
                            collector=self.name,
                            item_id=f"tcp:{port}",
                            title="Listening port outside the configured allowlist",
                            detail=f"port={port} family={family}",
                            severity=Severity.MEDIUM,
                        )
                    )

        return findings

    @staticmethod
    def _listening_ports(path: Path) -> list[int]:
        if not path.is_file():
            return []
        ports: list[int] = []
        try:
            lines = path.read_text().splitlines()[1:]
        except OSError:
            return []
        for line in lines:
            fields = line.split()
            if len(fields) < 4:
                continue
            local_address, state = fields[1], fields[3]
            if state.upper() != _TCP_LISTEN_STATE:
                continue
            try:
                port = int(local_address.split(":")[1], 16)
            except (IndexError, ValueError):
                continue
            ports.append(port)
        return ports
