"""Collectors turn live system state into flat, diffable snapshots.

Two kinds live in this package:

* **Baseline collectors** (``files``, ``users``, ``ssh_keys``, ``cron``)
  produce state that is expected to stay stable between scans. Their
  output is signed, stored, and diffed against future scans.
* **Heuristic collectors** (``processes``, ``network``) produce state
  that is expected to *change constantly* (PIDs, ephemeral ports), so
  diffing them against a fixed baseline would be mostly noise. Instead
  they flag suspicious conditions directly on every scan (a process
  running from ``/tmp``, a listening port outside the allowlist, a
  binary that's been deleted from disk while still running, ...).
"""

from .base import Collector, Finding

__all__ = ["Collector", "Finding"]
