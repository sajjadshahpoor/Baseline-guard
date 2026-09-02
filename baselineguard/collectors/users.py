"""Local account collector.

Parses ``/etc/passwd`` and ``/etc/group``. We deliberately do not read
``/etc/shadow`` password hashes into the baseline — the file itself is
already covered by the file-integrity collector, and there is no reason
to duplicate sensitive hash material into a second store.
"""

from __future__ import annotations

from pathlib import Path

PASSWD_FIELDS = ("username", "password_x", "uid", "gid", "gecos", "home", "shell")


class UserCollector:
    name = "users"

    def __init__(self, passwd_path: str = "/etc/passwd", group_path: str = "/etc/group"):
        self.passwd_path = Path(passwd_path)
        self.group_path = Path(group_path)

    def collect(self) -> dict[str, dict]:
        records: dict[str, dict] = {}
        groups_by_gid = self._parse_groups()

        if not self.passwd_path.is_file():
            return records

        for line in self.passwd_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) != 7:
                continue
            username, _pw, uid, gid, gecos, home, shell = parts
            records[username] = {
                "uid": int(uid),
                "gid": int(gid),
                "group": groups_by_gid.get(gid, gid),
                "gecos": gecos,
                "home": home,
                "shell": shell,
                "login_enabled": shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"),
            }
        return records

    def _parse_groups(self) -> dict[str, str]:
        mapping: dict[str, str] = {}
        if not self.group_path.is_file():
            return mapping
        for line in self.group_path.read_text().splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 3:
                name, _pw, gid = parts[0], parts[1], parts[2]
                mapping[gid] = name
        return mapping
