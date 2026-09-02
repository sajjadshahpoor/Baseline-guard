# Threat Model

Being explicit about what Baseline Guard does and does not protect
against matters more for a security tool than for most software — a
false sense of coverage is worse than no coverage at all.

## What it defends against

Baseline Guard is aimed at **post-compromise persistence and tampering
on a single host**, detected after the fact rather than blocked in real
time:

- A file under a monitored path (default: `/etc`, `/bin`, `/sbin`,
  `/usr/bin`, `/usr/sbin`) is modified, has its permissions changed
  (including gaining SUID/SGID), or is replaced.
- A new local account is created, especially one reusing UID 0.
- An existing account's UID is changed (a classic way to grant an
  unprivileged-looking account root).
- A new SSH key is appended to any user's `authorized_keys`.
- A new or modified cron entry, in `/etc/crontab`, `/etc/cron.d/*`, or
  a per-user crontab.
- A process currently running from a world-writable scratch directory
  (`/tmp`, `/var/tmp`, `/dev/shm` by default).
- A process still running from a binary that has been deleted from
  disk (`exe -> ... (deleted)`), a common technique for hiding a
  payload from a filesystem scan while it keeps executing.
- A TCP socket listening on a port outside a configured allowlist.

## What it does not defend against

- **It is not real-time.** Detection happens on the cadence you run
  `scan`/`watch` at. An attacker who compromises a host, does damage,
  and cleans up before the next scan will not be caught. Baseline Guard
  is a detection control, not a prevention control — pair it with
  configuration hardening (least privilege, disabled root SSH login,
  etc.), not as a substitute for it.
- **It does not protect its own baseline from a sufficiently privileged
  attacker.** If an attacker gains the same or higher privilege as the
  Baseline Guard process itself, they can, in principle, read the
  signing key and forge a new, self-consistent signed baseline that
  hides their changes. The HMAC envelope protects against *accidental*
  or *lower-privilege* tampering, and against a baseline being edited
  by something other than Baseline Guard itself — it is not a substitute
  for keeping the signing key (`state_dir/signing.key`) on a trust
  boundary the attacker doesn't also control. For real assurance, copy
  `signing.key` (or the whole `state_dir`) to a separate, read-only-from-
  the-monitored-host location — e.g. push baselines to a remote log
  sink, or mount `state_dir` read-only after the initial `init`.
- **It does not detect in-memory-only attacks** that never touch a
  monitored path, create an account, add a cron entry, or open a
  listening socket the tool checks. A memory-resident implant that
  makes outbound connections only, for example, is outside the network
  collector's scope (which only inspects *listening* sockets).
- **It is not a replacement for kernel-level or eBPF-based EDR.**
  Baseline Guard reads `/proc` and the filesystem from userspace; a
  sufficiently privileged rootkit that hooks the same interfaces it
  reads from can lie to it, the same way it can lie to `ps`/`ls`/`netstat`.
- **File hashing has a TOCTOU boundary.** Between "collect" and "diff",
  nothing prevents a file from being read, hashed as legitimate, and
  then hosting future malicious content — the hash reflects the file's
  state *at scan time*, nothing between scans.

## Recommended deployment posture

- Run scans on a schedule short enough to matter for your environment
  (systemd timer, cron, or `watch` under a process supervisor — see
  `docs/INSTALL.md`).
- Ship `scan-history.jsonl` and alert output to a log destination the
  monitored host cannot itself modify after the fact.
- Treat `TamperDetected` (exit code `3`) as a security incident in its
  own right, separate from an ordinary `scan` finding — it means either
  the baseline file or the signing key was altered outside of Baseline
  Guard.
- Keep `state_dir` out of the set of paths that `files` itself monitors,
  to avoid the baseline's own storage becoming a source of self-referential
  noise.
