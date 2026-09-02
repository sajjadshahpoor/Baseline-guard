"""Signed on-disk storage for baselines.

A baseline is only useful as a security control if an attacker who has
compromised the host cannot silently edit it to hide their own changes.
We can't stop a root-level attacker from *deleting* the baseline, but we
can make undetected *tampering* hard: every baseline file is wrapped in
an HMAC-SHA256 envelope keyed by a locally generated secret stored with
restrictive permissions. ``BaselineStore.load`` refuses to return data
whose signature doesn't match, and treats that as a security event
rather than a normal I/O error.
"""

from __future__ import annotations

import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .hashing import canonical_json_bytes

SIGNATURE_ALGORITHM = "sha256"
KEY_SIZE_BYTES = 32


class TamperDetected(Exception):
    """Raised when a baseline's HMAC signature does not match its content."""


class BaselineNotFound(Exception):
    """Raised when no baseline has been created yet."""


@dataclass
class Baseline:
    generated_at: float
    collectors: dict[str, dict[str, dict]]

    def to_dict(self) -> dict:
        return {"generated_at": self.generated_at, "collectors": self.collectors}


def _ensure_dir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except PermissionError:
        pass  # best-effort on systems where we don't own the directory


def load_or_create_key(key_file: Path) -> bytes:
    """Return the HMAC signing key, generating one on first use.

    The key file is created with 0600 permissions. Losing this key (or an
    attacker reading it) means baseline tampering can no longer be
    detected, so it should live on a different trust boundary than the
    monitored host where possible (see docs/THREAT_MODEL.md).
    """
    if key_file.is_file():
        return key_file.read_bytes()

    _ensure_dir(key_file.parent)
    key = os.urandom(KEY_SIZE_BYTES)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


class BaselineStore:
    """Reads and writes HMAC-signed baseline snapshots."""

    def __init__(self, baseline_file: Path, key_file: Path):
        self.baseline_file = baseline_file
        self.key_file = key_file

    def save(self, collectors: dict[str, dict[str, dict]]) -> Baseline:
        baseline = Baseline(generated_at=time.time(), collectors=collectors)
        key = load_or_create_key(self.key_file)
        payload = baseline.to_dict()
        signature = hmac.new(
            key, canonical_json_bytes(payload), SIGNATURE_ALGORITHM
        ).hexdigest()
        envelope = {"payload": payload, "signature": signature, "algorithm": SIGNATURE_ALGORITHM}

        _ensure_dir(self.baseline_file.parent)
        tmp_path = self.baseline_file.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(envelope, indent=2, sort_keys=True))
        os.chmod(tmp_path, 0o600)
        tmp_path.replace(self.baseline_file)
        return baseline

    def load(self) -> Baseline:
        if not self.baseline_file.is_file():
            raise BaselineNotFound(f"No baseline at {self.baseline_file}. Run 'baseline' first.")

        envelope = json.loads(self.baseline_file.read_text())
        payload = envelope["payload"]
        signature = envelope["signature"]
        algorithm = envelope.get("algorithm", SIGNATURE_ALGORITHM)

        key = load_or_create_key(self.key_file)
        expected = hmac.new(key, canonical_json_bytes(payload), algorithm).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise TamperDetected(
                f"Signature mismatch on {self.baseline_file} — the baseline file has been "
                "modified outside of Baseline Guard, or the signing key changed."
            )

        return Baseline(generated_at=payload["generated_at"], collectors=payload["collectors"])

    def exists(self) -> bool:
        return self.baseline_file.is_file()
