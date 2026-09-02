# Baseline Guard

[![CI](https://github.com/sajjadshahpoor/Baseline-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/sajjadshahpoor/Baseline-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

A lightweight, dependency-free **host-based intrusion detection system
(HIDS)** built around a single idea: take a cryptographically signed
snapshot of the state that shouldn't casually change on your system —
file integrity, local accounts, SSH keys, cron jobs — and alert loudly
the moment it does. Layered on top, a set of live heuristics catch the
things a static baseline can't: a process running from `/tmp`, a
binary that's still executing after being deleted from disk, a port
that's suddenly listening outside your allowlist.

```
$ sudo baseline-guard scan
[HIGH    ] files: [files] changed (hash, mtime, size): /etc/passwd
[CRITICAL] files: [files] changed (mode): /usr/bin/find
[HIGH    ] processes: Process executing from a writable scratch directory
[MEDIUM  ] network: Listening port outside the configured allowlist
scan complete: 2 baseline change(s), 2 heuristic finding(s), highest severity = CRITICAL
```

## Why this exists

Most beginner HIDS projects are a pile of shell scripts that hash a
few files and email you a diff. Baseline Guard is built the way a
security tool that has to be *trusted* should be:

- **The baseline itself is tamper-evident.** Every snapshot is wrapped
  in an HMAC-SHA256 envelope, keyed by a locally generated, 0600-permission
  secret. An attacker who edits the stored baseline to hide their tracks
  gets caught by the next `scan`, not silently believed. See
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#signed-storage).
- **Severity isn't a flat per-file-type setting.** A new SUID binary, a
  new UID-0 account, or a modified `/etc/shadow` is always `CRITICAL`,
  regardless of collector defaults — see `classify_severity()` in
  [`baselineguard/diff.py`](baselineguard/diff.py).
- **Static baselines and live heuristics are treated as genuinely
  different problems**, not forced into one model. Files, accounts,
  SSH keys, and cron entries get diffed against a signed snapshot.
  Processes and listening ports — which churn by design — get evaluated
  against policy on every run instead. See
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#two-kinds-of-collector).
- **Zero mandatory runtime dependencies.** Hashing, TOML config parsing,
  email, and webhook delivery all use only the Python standard library.
  Fewer dependencies means a smaller supply-chain surface for a tool
  whose entire job is telling you what to trust.
- **The threat model is written down, including the limits.**
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) is explicit about what
  signed baselines do *not* guarantee — most importantly, that they
  don't protect against an attacker with privilege equal to or greater
  than Baseline Guard's own process.

## What it monitors

| Collector | Kind | Catches |
|---|---|---|
| `files` | baseline | Content, permission, ownership changes; explicit SUID/SGID tracking |
| `users` | baseline | New/changed accounts in `/etc/passwd`, UID changes |
| `ssh_keys` | baseline | Keys added to any user's `authorized_keys`, at line granularity |
| `cron` | baseline | New/changed entries in system crontab, `cron.d`, and per-user crontabs |
| `processes` | heuristic | Processes running from writable scratch dirs, or from a deleted binary |
| `network` | heuristic | TCP sockets listening outside a configured port allowlist |

## Quickstart

```bash
git clone https://github.com/sajjadshahpoor/Baseline-guard.git
cd Baseline-guard
pip install .

sudo baseline-guard init      # generates signing key + first baseline
sudo baseline-guard scan      # compare current state to the baseline
sudo baseline-guard report    # show the last scan's summary
```

Runs equally well without installing:

```bash
python -m baselineguard init
```

For continuous monitoring via a systemd timer, container deployment,
and every config option (alert routing, custom paths, port allowlists,
etc.), see [`docs/INSTALL.md`](docs/INSTALL.md) and
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

## Alerting

Four channels, any combination of which can be enabled in config:
console (color-coded), a JSON-lines log file, email (stdlib `smtplib`),
and a generic JSON webhook (works as-is with Slack/Discord incoming
webhooks). Email and webhook each take their own `min_severity`, so
low-noise channels don't get flooded while a dedicated critical-only
Slack channel stays quiet until it matters.

## Project layout

```
baselineguard/
  hashing.py          chunked SHA-256 + canonical JSON for signing
  config.py           TOML config with defaults for every field
  storage.py          HMAC-signed baseline persistence
  diff.py             snapshot diffing + severity classification
  engine.py           wires collectors + storage + diff + alerts
  cli.py              init / baseline / scan / watch / report
  collectors/         files, users, ssh_keys, cron, processes, network
  alerts/             console, logfile, email, webhook
tests/                 85 unit/integration tests, stdlib unittest only
docs/                  architecture, threat model, install, config reference
deploy/                systemd service+timer, Dockerfile
```

## Testing

```bash
python -m unittest discover -s tests -v
```

No `pip install` required — the test suite, like the tool itself, only
needs the standard library.

## License

[MIT](LICENSE) © Sajjad Shahpoor
