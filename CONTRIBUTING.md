# Contributing

Bug reports and pull requests are welcome.

## Development setup

```bash
git clone https://github.com/sajjadshahpoor/Baseline-guard.git
cd Baseline-guard
```

No dependency installation is required to run the test suite — it uses
only the standard library:

```bash
python -m unittest discover -s tests -v
```

If you have `ruff` available (`pip install ruff`), lint before sending
a PR:

```bash
ruff check baselineguard tests
```

## Guidelines

- **Keep the runtime dependency-free.** `baselineguard/` itself should
  never need anything beyond the standard library — see
  `docs/ARCHITECTURE.md` for why. `ruff` (dev-only, lint) is the one
  exception, and it's not imported by the package.
- **New collectors** implement either the `Collector` protocol
  (`name`, `collect() -> dict[str, dict]`) for state that should be
  baselined, or expose a `scan() -> list[Finding]` method for state
  that should be evaluated live against policy instead — see
  `baselineguard/collectors/base.py` and the "Two kinds of collector"
  section of `docs/ARCHITECTURE.md` for which one fits.
- **New alert channels** implement `AlertChannel.send(alerts)` in
  `baselineguard/alerts/` and must not raise on a delivery failure — a
  broken channel should never be able to crash a scan (see how
  `webhook.py` swallows `URLError`).
- **Tests accompany behavior changes.** The suite runs in well under a
  second, so there's little reason not to add a case alongside a fix.
