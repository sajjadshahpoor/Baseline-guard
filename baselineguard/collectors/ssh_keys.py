"""SSH authorized_keys collector.

A new line silently appended to any user's ``~/.ssh/authorized_keys`` is
one of the most common persistence mechanisms after an initial
compromise. We hash each key line individually (rather than hashing the
whole file) so a diff reports exactly which key was added or removed,
not just "the file changed".
"""

from __future__ import annotations

from pathlib import Path

from ..hashing import hash_bytes
from .users import UserCollector


class SshKeyCollector:
    name = "ssh_keys"

    def __init__(self, passwd_path: str = "/etc/passwd"):
        self._user_collector = UserCollector(passwd_path=passwd_path)

    def collect(self) -> dict[str, dict]:
        records: dict[str, dict] = {}
        for username, user in self._user_collector.collect().items():
            home = Path(user["home"])
            for rel in ("authorized_keys", "authorized_keys2"):
                key_file = home / ".ssh" / rel
                try:
                    if not key_file.is_file():
                        continue
                    lines = key_file.read_text().splitlines()
                except OSError:
                    # Unreadable (permission denied, broken symlink, home
                    # dir on unmounted storage, ...) -- skip this user
                    # rather than aborting the whole scan.
                    continue
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    fingerprint = hash_bytes(line.encode("utf-8"))
                    item_id = f"{username}:{rel}:{fingerprint[:16]}"
                    records[item_id] = {
                        "user": username,
                        "file": str(key_file),
                        "fingerprint": fingerprint,
                        "comment": line.split()[-1] if " " in line else "",
                        "key_type": line.split()[0] if line else "",
                    }
        return records
