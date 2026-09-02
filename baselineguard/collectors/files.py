"""File integrity collector.

Walks a configured set of directories and hashes every regular file it
finds, recording enough metadata (mode, owner, size, mtime, and the
SUID/SGID bits specifically) to catch not just content changes but
permission and ownership changes too — a file whose *contents* never
change but which suddenly gains the setuid bit is a classic privilege
escalation technique that a pure content-hash approach would miss.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from pathlib import Path

from ..hashing import hash_file

_SUID_BIT = stat.S_ISUID
_SGID_BIT = stat.S_ISGID


class FileCollector:
    name = "files"

    def __init__(
        self,
        paths: list[str],
        excludes: list[str] | None = None,
        algorithm: str = "sha256",
        max_file_size_mb: int = 200,
        follow_symlinks: bool = False,
    ):
        self.paths = paths
        self.excludes = excludes or []
        self.algorithm = algorithm
        self.max_file_bytes = max_file_size_mb * 1024 * 1024
        self.follow_symlinks = follow_symlinks

    def collect(self) -> dict[str, dict]:
        records: dict[str, dict] = {}
        for root_path in self.paths:
            root = Path(root_path)
            if not root.exists():
                continue
            for file_path in self._walk(root):
                str_path = str(file_path)
                if self._is_excluded(str_path):
                    continue
                record = self._record_for(file_path)
                if record is not None:
                    records[str_path] = record
        return records

    def _walk(self, root: Path):
        if root.is_file():
            yield root
            return
        for dirpath, dirnames, filenames in os.walk(root, followlinks=self.follow_symlinks):
            for filename in filenames:
                yield Path(dirpath) / filename

    def _is_excluded(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.excludes)

    def _record_for(self, path: Path) -> dict | None:
        try:
            st = path.lstat()
        except OSError:
            return None

        if stat.S_ISLNK(st.st_mode) and not self.follow_symlinks:
            return {
                "type": "symlink",
                "target": self._safe_readlink(path),
                "mode": stat.S_IMODE(st.st_mode),
                "uid": st.st_uid,
                "gid": st.st_gid,
            }

        if not stat.S_ISREG(st.st_mode):
            return None

        if st.st_size > self.max_file_bytes:
            return {
                "type": "file",
                "hash": None,
                "note": "skipped: exceeds max_file_size_mb",
                "size": st.st_size,
                "mode": stat.S_IMODE(st.st_mode),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mtime": st.st_mtime,
            }

        try:
            file_hash = hash_file(path, self.algorithm)
        except OSError:
            return None

        return {
            "type": "file",
            "path": str(path),
            "hash": file_hash,
            "size": st.st_size,
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mtime": st.st_mtime,
            "suid": bool(st.st_mode & _SUID_BIT),
            "sgid": bool(st.st_mode & _SGID_BIT),
        }

    @staticmethod
    def _safe_readlink(path: Path) -> str | None:
        try:
            return os.readlink(path)
        except OSError:
            return None
