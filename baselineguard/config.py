"""Configuration loading for Baseline Guard.

Configuration lives in a TOML file (parsed with the stdlib ``tomllib``, so
no third-party dependency is needed just to boot). Every field has a safe
default, so ``Config.default()`` alone is enough to run the tool.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_STATE_DIR = Path("/var/lib/baseline-guard")
DEFAULT_CONFIG_PATHS = (
    Path("/etc/baseline-guard/baseline-guard.toml"),
    Path.home() / ".config" / "baseline-guard" / "baseline-guard.toml",
)


@dataclass
class FilesConfig:
    paths: list[str] = field(
        default_factory=lambda: ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"]
    )
    excludes: list[str] = field(default_factory=lambda: ["*.log", "*/tmp/*", "*/cache/*"])
    algorithm: str = "sha256"
    max_file_size_mb: int = 200
    follow_symlinks: bool = False


@dataclass
class HeuristicsConfig:
    suspicious_process_dirs: list[str] = field(
        default_factory=lambda: ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"]
    )
    allowed_listen_ports: list[int] = field(default_factory=lambda: [22, 80, 443])
    flag_deleted_running_binaries: bool = True


@dataclass
class EmailAlertConfig:
    enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 587
    use_tls: bool = True
    username: str = ""
    password_env_var: str = "BASELINE_GUARD_SMTP_PASSWORD"
    from_addr: str = "baseline-guard@localhost"
    to_addrs: list[str] = field(default_factory=list)
    min_severity: str = "high"


@dataclass
class WebhookAlertConfig:
    enabled: bool = False
    url: str = ""
    min_severity: str = "medium"


@dataclass
class AlertsConfig:
    console: bool = True
    log_file: str = ""
    email: EmailAlertConfig = field(default_factory=EmailAlertConfig)
    webhook: WebhookAlertConfig = field(default_factory=WebhookAlertConfig)


@dataclass
class Config:
    state_dir: Path = DEFAULT_STATE_DIR
    files: FilesConfig = field(default_factory=FilesConfig)
    heuristics: HeuristicsConfig = field(default_factory=HeuristicsConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    watch_interval_seconds: int = 300

    @property
    def baseline_file(self) -> Path:
        return self.state_dir / "baseline.json"

    @property
    def key_file(self) -> Path:
        return self.state_dir / "signing.key"

    @property
    def history_file(self) -> Path:
        return self.state_dir / "scan-history.jsonl"

    @classmethod
    def default(cls) -> "Config":
        return cls()

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        """Load config from *path*, or the first existing default location.

        Falls back to built-in defaults if no file is found, so the tool
        is usable out of the box without any setup step.
        """
        candidates = [path] if path else list(DEFAULT_CONFIG_PATHS)
        for candidate in candidates:
            if candidate and candidate.is_file():
                return cls._from_toml(candidate)
        return cls.default()

    @classmethod
    def _from_toml(cls, path: Path) -> "Config":
        with open(path, "rb") as handle:
            raw = tomllib.load(handle)

        cfg = cls.default()
        if "state_dir" in raw:
            cfg.state_dir = Path(raw["state_dir"])
        if "watch_interval_seconds" in raw:
            cfg.watch_interval_seconds = int(raw["watch_interval_seconds"])

        files_raw = raw.get("files", {})
        cfg.files = FilesConfig(
            paths=files_raw.get("paths", cfg.files.paths),
            excludes=files_raw.get("excludes", cfg.files.excludes),
            algorithm=files_raw.get("algorithm", cfg.files.algorithm),
            max_file_size_mb=files_raw.get("max_file_size_mb", cfg.files.max_file_size_mb),
            follow_symlinks=files_raw.get("follow_symlinks", cfg.files.follow_symlinks),
        )

        heur_raw = raw.get("heuristics", {})
        cfg.heuristics = HeuristicsConfig(
            suspicious_process_dirs=heur_raw.get(
                "suspicious_process_dirs", cfg.heuristics.suspicious_process_dirs
            ),
            allowed_listen_ports=heur_raw.get(
                "allowed_listen_ports", cfg.heuristics.allowed_listen_ports
            ),
            flag_deleted_running_binaries=heur_raw.get(
                "flag_deleted_running_binaries", cfg.heuristics.flag_deleted_running_binaries
            ),
        )

        alerts_raw = raw.get("alerts", {})
        email_raw = alerts_raw.get("email", {})
        webhook_raw = alerts_raw.get("webhook", {})
        cfg.alerts = AlertsConfig(
            console=alerts_raw.get("console", cfg.alerts.console),
            log_file=alerts_raw.get("log_file", cfg.alerts.log_file),
            email=EmailAlertConfig(
                enabled=email_raw.get("enabled", False),
                smtp_host=email_raw.get("smtp_host", "localhost"),
                smtp_port=email_raw.get("smtp_port", 587),
                use_tls=email_raw.get("use_tls", True),
                username=email_raw.get("username", ""),
                password_env_var=email_raw.get(
                    "password_env_var", "BASELINE_GUARD_SMTP_PASSWORD"
                ),
                from_addr=email_raw.get("from_addr", "baseline-guard@localhost"),
                to_addrs=email_raw.get("to_addrs", []),
                min_severity=email_raw.get("min_severity", "high"),
            ),
            webhook=WebhookAlertConfig(
                enabled=webhook_raw.get("enabled", False),
                url=webhook_raw.get("url", ""),
                min_severity=webhook_raw.get("min_severity", "medium"),
            ),
        )
        return cfg
