"""Command-line entry point: ``baseline-guard <command> ...``."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__
from .config import Config
from .diff import Severity
from .engine import BASELINE_COLLECTOR_NAMES, BaselineGuard
from .storage import BaselineNotFound, TamperDetected


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="baseline-guard",
        description="A signed-baseline host intrusion detection system.",
    )
    parser.add_argument("-c", "--config", type=Path, default=None, help="Path to a TOML config file")
    parser.add_argument("-V", "--version", action="version", version=f"baseline-guard {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Generate signing key and take the first baseline")

    baseline_parser = subparsers.add_parser("baseline", help="(Re)compute and save the baseline")
    baseline_parser.add_argument(
        "--force", action="store_true", help="Overwrite an existing baseline without prompting"
    )

    scan_parser = subparsers.add_parser("scan", help="Compare current state against the baseline")
    scan_parser.add_argument(
        "--fail-on",
        choices=[s.name.lower() for s in Severity if s != Severity.INFO],
        default="high",
        help="Exit with a non-zero status if any alert reaches this severity or higher",
    )

    watch_parser = subparsers.add_parser("watch", help="Run 'scan' on a loop")
    watch_parser.add_argument(
        "--interval", type=int, default=None, help="Seconds between scans (default: from config)"
    )

    subparsers.add_parser("report", help="Show the most recent scan's summary")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = Config.load(args.config)

    if args.command == "init":
        return _cmd_init(config)
    if args.command == "baseline":
        return _cmd_baseline(config, force=args.force)
    if args.command == "scan":
        return _cmd_scan(config, fail_on=Severity.from_name(args.fail_on))
    if args.command == "watch":
        return _cmd_watch(config, interval=args.interval)
    if args.command == "report":
        return _cmd_report(config)

    parser.error(f"Unknown command: {args.command}")
    return 2


def _cmd_init(config: Config) -> int:
    guard = BaselineGuard(config)
    if guard.store.exists():
        print(f"Baseline already exists at {config.baseline_file}. Use 'baseline --force' to redo it.")
        return 0
    count = guard.create_baseline()
    print(f"Initialized. Captured {count} items into {config.baseline_file}")
    print(f"Signing key stored at {config.key_file} (keep this safe — see docs/THREAT_MODEL.md)")
    return 0


def _cmd_baseline(config: Config, force: bool) -> int:
    guard = BaselineGuard(config)
    if guard.store.exists() and not force:
        print(f"Baseline already exists at {config.baseline_file}. Pass --force to overwrite.")
        return 1
    count = guard.create_baseline()
    print(f"Baseline saved: {count} items across {len(BASELINE_COLLECTOR_NAMES)} collectors.")
    return 0


def _cmd_scan(config: Config, fail_on: Severity) -> int:
    guard = BaselineGuard(config)
    try:
        result = guard.scan()
    except BaselineNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except TamperDetected as exc:
        print(f"SECURITY ALERT: {exc}", file=sys.stderr)
        return 3

    guard.dispatch(result)
    _record_history(config, result)

    print(
        f"scan complete: {len(result.changes)} baseline change(s), "
        f"{len(result.findings)} heuristic finding(s), "
        f"highest severity = {result.highest_severity.name}"
    )

    if result.highest_severity >= fail_on:
        return 1
    return 0


def _cmd_watch(config: Config, interval: int | None) -> int:
    seconds = interval or config.watch_interval_seconds
    print(f"Watching every {seconds}s. Press Ctrl+C to stop.")
    try:
        while True:
            _cmd_scan(config, fail_on=Severity.CRITICAL)
            time.sleep(seconds)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def _cmd_report(config: Config) -> int:
    if not config.history_file.is_file():
        print("No scan history yet. Run 'scan' first.")
        return 0
    lines = config.history_file.read_text().splitlines()
    if not lines:
        print("No scan history yet. Run 'scan' first.")
        return 0
    last = json.loads(lines[-1])
    print(json.dumps(last, indent=2, sort_keys=True))
    return 0


def _record_history(config: Config, result) -> None:
    config.history_file.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.time(),
        "changes": len(result.changes),
        "findings": len(result.findings),
        "highest_severity": result.highest_severity.name,
        "alerts": [a.to_dict() for a in result.alerts],
    }
    with open(config.history_file, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


if __name__ == "__main__":
    sys.exit(main())
