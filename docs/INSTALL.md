# Installation

## Requirements

- Linux (the process/network heuristics read `/proc` directly)
- Python 3.11+
- No third-party runtime dependencies

## From source

```bash
git clone https://github.com/sajjadshahpoor/Baseline-guard.git
cd Baseline-guard
pip install .
```

This installs the `baseline-guard` command via the `console_scripts`
entry point defined in `pyproject.toml`. Without installing, the tool
also runs directly from a checkout:

```bash
python -m baselineguard --help
```

## First run

```bash
sudo baseline-guard init
```

This generates the HMAC signing key at `/var/lib/baseline-guard/signing.key`
(`0600` permissions) and takes the first baseline snapshot. Monitoring
system paths like `/etc` and `/usr/sbin` generally requires root, since
the file collector needs read access to everything it hashes.

To scope monitoring to paths a non-root user can already read, or to
use a different state directory, write a config file first — see
[`CONFIGURATION.md`](CONFIGURATION.md) — before running `init`.

## Running scans

One-off:

```bash
sudo baseline-guard scan
```

Exits `0` if nothing at or above `--fail-on` (default: `high`) was
found, `1` if it was, `2` if no baseline exists yet, and `3` if the
stored baseline failed its signature check (treat this as its own
incident — see [`THREAT_MODEL.md`](THREAT_MODEL.md)).

## Continuous monitoring

Two supported options, both in `deploy/`:

- **systemd timer** (recommended): runs `scan` on a schedule, so a
  crashed or hung scan doesn't leave monitoring silently stopped the
  way a long-lived `watch` process could. See
  `deploy/systemd/baseline-guard.service` and
  `deploy/systemd/baseline-guard.timer`.
- **Long-running `watch`**: `baseline-guard watch --interval 300` loops
  `scan` in the foreground. Useful under a process supervisor, or for
  quick manual monitoring in a terminal.

```bash
sudo cp deploy/systemd/baseline-guard.* /etc/systemd/system/
sudo cp config/baseline-guard.example.toml /etc/baseline-guard/baseline-guard.toml
sudo systemctl daemon-reload
sudo systemctl enable --now baseline-guard.timer
```

## Container use

`deploy/Dockerfile` builds a minimal image. Note that a container can
only meaningfully monitor paths mounted into it — it has no visibility
into the host's real `/etc`, process table, or listening sockets unless
you explicitly bind-mount or pass `--pid=host` / `--net=host`, which
has its own security tradeoffs worth thinking through before using it
this way in production.
