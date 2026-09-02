import tempfile
import unittest
from pathlib import Path

from baselineguard.collectors.ssh_keys import SshKeyCollector


class SshKeyCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home" / "alice"
        (self.home / ".ssh").mkdir(parents=True)

        self.passwd_path = self.root / "passwd"
        self.passwd_path.write_text(f"alice:x:1000:1000:Alice:{self.home}:/bin/bash\n")

    def test_reads_authorized_keys(self):
        (self.home / ".ssh" / "authorized_keys").write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA alice@laptop\n"
        )
        records = SshKeyCollector(passwd_path=str(self.passwd_path)).collect()
        self.assertEqual(len(records), 1)
        record = next(iter(records.values()))
        self.assertEqual(record["user"], "alice")
        self.assertEqual(record["comment"], "alice@laptop")

    def test_no_ssh_dir_produces_no_records(self):
        records = SshKeyCollector(passwd_path=str(self.passwd_path)).collect()
        self.assertEqual(records, {})

    def test_each_key_line_gets_its_own_entry(self):
        (self.home / ".ssh" / "authorized_keys").write_text(
            "ssh-ed25519 AAAA1 a@x\nssh-rsa AAAA2 b@y\n"
        )
        records = SshKeyCollector(passwd_path=str(self.passwd_path)).collect()
        self.assertEqual(len(records), 2)

    def test_added_key_is_detectable_as_a_new_record(self):
        key_file = self.home / ".ssh" / "authorized_keys"
        key_file.write_text("ssh-ed25519 AAAA1 a@x\n")
        before = SshKeyCollector(passwd_path=str(self.passwd_path)).collect()

        with open(key_file, "a") as handle:
            handle.write("ssh-ed25519 AAAA2 attacker@evil\n")
        after = SshKeyCollector(passwd_path=str(self.passwd_path)).collect()

        self.assertEqual(len(after) - len(before), 1)


if __name__ == "__main__":
    unittest.main()
