"""Wires collectors, storage, diffing, and alerting into a single engine.

This is the one place that knows about every moving part; ``cli.py``
should stay a thin argument-parsing layer on top of it so the whole
tool is also usable as a library (e.g. from a test suite or a notebook)
without going through the command line at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .alerts.base import Alert
from .alerts.console import ConsoleAlertChannel
from .alerts.email_alert import EmailAlertChannel
from .alerts.logfile import LogFileAlertChannel
from .alerts.webhook import WebhookAlertChannel
from .collectors.base import Finding
from .collectors.cron import CronCollector
from .collectors.files import FileCollector
from .collectors.network import NetworkCollector
from .collectors.processes import ProcessCollector
from .collectors.ssh_keys import SshKeyCollector
from .collectors.users import UserCollector
from .config import Config
from .diff import Change, Severity, diff_snapshots
from .storage import BaselineStore

BASELINE_COLLECTOR_NAMES = ("files", "users", "ssh_keys", "cron")


@dataclass
class ScanResult:
    changes: list[Change] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def alerts(self) -> list[Alert]:
        return [Alert.from_change(c) for c in self.changes] + [
            Alert.from_finding(f) for f in self.findings
        ]

    @property
    def highest_severity(self) -> Severity:
        levels = [a.severity for a in self.alerts]
        return max(levels) if levels else Severity.INFO

    def is_clean(self) -> bool:
        return not self.changes and not self.findings


class BaselineGuard:
    def __init__(self, config: Config):
        self.config = config
        self.store = BaselineStore(config.baseline_file, config.key_file)

    def _baseline_collectors(self) -> dict[str, object]:
        f = self.config.files
        return {
            "files": FileCollector(
                paths=f.paths,
                excludes=f.excludes,
                algorithm=f.algorithm,
                max_file_size_mb=f.max_file_size_mb,
                follow_symlinks=f.follow_symlinks,
            ),
            "users": UserCollector(),
            "ssh_keys": SshKeyCollector(),
            "cron": CronCollector(),
        }

    def collect_current_state(self) -> dict[str, dict[str, dict]]:
        return {name: c.collect() for name, c in self._baseline_collectors().items()}

    def create_baseline(self) -> int:
        """Snapshot current state and persist it as the new signed baseline.

        Returns the total number of items captured across all collectors.
        """
        snapshot = self.collect_current_state()
        self.store.save(snapshot)
        return sum(len(records) for records in snapshot.values())

    def scan(self) -> ScanResult:
        baseline = self.store.load()
        current = self.collect_current_state()

        changes: list[Change] = []
        for name in BASELINE_COLLECTOR_NAMES:
            old = baseline.collectors.get(name, {})
            new = current.get(name, {})
            changes.extend(diff_snapshots(name, old, new))

        findings: list[Finding] = []
        findings.extend(
            ProcessCollector(
                suspicious_dirs=self.config.heuristics.suspicious_process_dirs,
                flag_deleted_running_binaries=self.config.heuristics.flag_deleted_running_binaries,
            ).scan()
        )
        findings.extend(
            NetworkCollector(allowed_ports=self.config.heuristics.allowed_listen_ports).scan()
        )

        return ScanResult(changes=changes, findings=findings)

    def alert_channels(self) -> list:
        channels = []
        a = self.config.alerts

        if a.console:
            channels.append(ConsoleAlertChannel())
        if a.log_file:
            channels.append(LogFileAlertChannel(a.log_file))
        if a.email.enabled:
            channels.append(
                EmailAlertChannel(
                    smtp_host=a.email.smtp_host,
                    smtp_port=a.email.smtp_port,
                    from_addr=a.email.from_addr,
                    to_addrs=a.email.to_addrs,
                    username=a.email.username,
                    password_env_var=a.email.password_env_var,
                    use_tls=a.email.use_tls,
                    min_severity=Severity.from_name(a.email.min_severity),
                )
            )
        if a.webhook.enabled:
            channels.append(
                WebhookAlertChannel(
                    url=a.webhook.url,
                    min_severity=Severity.from_name(a.webhook.min_severity),
                )
            )
        return channels

    def dispatch(self, result: ScanResult) -> None:
        alerts = result.alerts
        for channel in self.alert_channels():
            channel.send(alerts)
