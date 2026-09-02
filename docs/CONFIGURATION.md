# Configuration reference

Baseline Guard reads a TOML file (parsed with the stdlib `tomllib` —
no PyYAML dependency needed). Every field has a built-in default, so
any field you omit falls back to it; you never need to restate the
whole file just to change one setting.

Config is loaded, in order, from:

1. `--config /path/to/file.toml` (or `-c`), if passed
2. `/etc/baseline-guard/baseline-guard.toml`
3. `~/.config/baseline-guard/baseline-guard.toml`
4. built-in defaults, if none of the above exist

A fully-commented starting point lives at
[`config/baseline-guard.example.toml`](../config/baseline-guard.example.toml).

## Top level

| Key | Default | Meaning |
|---|---|---|
| `state_dir` | `/var/lib/baseline-guard` | Where the signed baseline, signing key, and scan history live. |
| `watch_interval_seconds` | `300` | Default loop interval for `baseline-guard watch` when `--interval` isn't passed. |

## `[files]`

| Key | Default | Meaning |
|---|---|---|
| `paths` | `["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"]` | Directories (or individual files) to hash. |
| `excludes` | `["*.log", "*/tmp/*", "*/cache/*"]` | `fnmatch`-style glob patterns; matching paths are skipped entirely. |
| `algorithm` | `"sha256"` | Any digest name `hashlib.new()` accepts. |
| `max_file_size_mb` | `200` | Files larger than this are recorded (size/mode/owner) but not hashed, to bound scan time. |
| `follow_symlinks` | `false` | If false, symlinks are recorded as symlinks (target, mode, owner) rather than followed and hashed. |

## `[heuristics]`

| Key | Default | Meaning |
|---|---|---|
| `suspicious_process_dirs` | `["/tmp", "/var/tmp", "/dev/shm", "/run/shm"]` | A running process whose executable resolves under any of these is flagged `HIGH`. |
| `allowed_listen_ports` | `[22, 80, 443]` | Any TCP port found in `LISTEN` state outside this list is flagged `MEDIUM`. |
| `flag_deleted_running_binaries` | `true` | Flag (as `CRITICAL`) a process still running from a binary deleted off disk. |

## `[alerts]`

| Key | Default | Meaning |
|---|---|---|
| `console` | `true` | Print alerts to stdout, ANSI-colored when attached to a TTY. |
| `log_file` | `""` (disabled) | Path to append newline-delimited JSON alerts to. |

### `[alerts.email]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `smtp_host` / `smtp_port` | `localhost` / `587` | |
| `use_tls` | `true` | Calls `STARTTLS` before sending. |
| `username` | `""` | SMTP auth username. |
| `password_env_var` | `"BASELINE_GUARD_SMTP_PASSWORD"` | **Name** of the environment variable holding the SMTP password — the password itself never goes in this file. |
| `from_addr` | `"baseline-guard@localhost"` | |
| `to_addrs` | `[]` | No email is sent if empty. |
| `min_severity` | `"high"` | One of `info`, `low`, `medium`, `high`, `critical`. |

### `[alerts.webhook]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | |
| `url` | `""` | Any HTTPS endpoint accepting a JSON POST body — this includes Slack/Discord incoming webhooks as-is. |
| `min_severity` | `"medium"` | |

## Example: routing only critical findings to Slack

```toml
[alerts]
console = true
log_file = "/var/lib/baseline-guard/scan-history.jsonl"

[alerts.webhook]
enabled = true
url = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX"
min_severity = "critical"
```

## Example: monitoring only a specific application directory

```toml
state_dir = "/var/lib/baseline-guard"

[files]
paths = ["/opt/myapp"]
excludes = ["*/myapp/logs/*", "*/myapp/tmp/*"]

[heuristics]
allowed_listen_ports = [8443]
```
