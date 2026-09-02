import tempfile
import unittest
from pathlib import Path

from baselineguard.collectors.users import UserCollector


class UserCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _write(self, passwd: str, group: str = "") -> UserCollector:
        passwd_path = self.root / "passwd"
        group_path = self.root / "group"
        passwd_path.write_text(passwd)
        group_path.write_text(group)
        return UserCollector(passwd_path=str(passwd_path), group_path=str(group_path))

    def test_parses_standard_line(self):
        collector = self._write("root:x:0:0:root:/root:/bin/bash\n")
        records = collector.collect()
        self.assertIn("root", records)
        self.assertEqual(records["root"]["uid"], 0)
        self.assertEqual(records["root"]["home"], "/root")

    def test_resolves_group_name_from_gid(self):
        collector = self._write(
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
            "alice:x:1000:\n",
        )
        records = collector.collect()
        self.assertEqual(records["alice"]["group"], "alice")

    def test_nologin_shell_marks_login_disabled(self):
        collector = self._write("svc:x:900:900:Service:/nonexistent:/usr/sbin/nologin\n")
        records = collector.collect()
        self.assertFalse(records["svc"]["login_enabled"])

    def test_comments_and_blank_lines_are_skipped(self):
        collector = self._write("# comment\n\nroot:x:0:0:root:/root:/bin/bash\n")
        records = collector.collect()
        self.assertEqual(len(records), 1)

    def test_missing_passwd_file_returns_empty(self):
        collector = UserCollector(
            passwd_path=str(self.root / "nope"), group_path=str(self.root / "nope-group")
        )
        self.assertEqual(collector.collect(), {})


if __name__ == "__main__":
    unittest.main()
