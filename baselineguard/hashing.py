"""File hashing helpers used by collectors and the integrity store."""

from __future__ import annotations

import hashlib
from pathlib import Path

DEFAULT_ALGORITHM = "sha256"
_CHUNK_SIZE = 1024 * 1024


def hash_file(path: Path, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return the hex digest of *path*'s contents.

    Reads in fixed-size chunks so multi-gigabyte files never get pulled
    fully into memory.
    """
    digest = hashlib.new(algorithm)
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_bytes(data: bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return the hex digest of an in-memory blob (used for e.g. SSH keys)."""
    return hashlib.new(algorithm, data).hexdigest()


def canonical_json_bytes(obj) -> bytes:
    """Serialize *obj* deterministically so hashing/signing is stable.

    Keys are sorted and separators are tight, so semantically identical
    dicts always produce byte-identical output regardless of insertion
    order — this is what makes HMAC signatures over JSON reproducible.
    """
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
