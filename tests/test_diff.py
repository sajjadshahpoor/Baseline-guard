import unittest

from baselineguard.diff import ADDED, MODIFIED, REMOVED, Severity, diff_snapshots


class DiffSnapshotsTests(unittest.TestCase):
    def test_added_item(self):
        changes = diff_snapshots("files", {}, {"/a": {"hash": "1"}})
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change_type, ADDED)
        self.assertEqual(changes[0].item_id, "/a")

    def test_removed_item(self):
        changes = diff_snapshots("files", {"/a": {"hash": "1"}}, {})
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change_type, REMOVED)

    def test_modified_item_lists_changed_fields(self):
        old = {"/a": {"hash": "1", "size": 10, "mode": 420}}
        new = {"/a": {"hash": "2", "size": 20, "mode": 420}}
        changes = diff_snapshots("files", old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change_type, MODIFIED)
        self.assertEqual(changes[0].changed_fields, ["hash", "size"])

    def test_unchanged_item_produces_no_diff(self):
        record = {"/a": {"hash": "1"}}
        changes = diff_snapshots("files", record, dict(record))
        self.assertEqual(changes, [])

    def test_mixed_changes(self):
        old = {"/a": {"hash": "1"}, "/b": {"hash": "2"}}
        new = {"/a": {"hash": "1"}, "/c": {"hash": "3"}}
        changes = diff_snapshots("files", old, new)
        types = sorted(c.change_type for c in changes)
        self.assertEqual(types, [ADDED, REMOVED])


class SeverityClassificationTests(unittest.TestCase):
    def test_new_suid_file_is_critical(self):
        changes = diff_snapshots("files", {}, {"/x": {"hash": "1", "suid": True}})
        self.assertEqual(changes[0].severity, Severity.CRITICAL)

    def test_plain_new_file_is_default_medium(self):
        changes = diff_snapshots("files", {}, {"/x": {"hash": "1", "suid": False}})
        self.assertEqual(changes[0].severity, Severity.MEDIUM)

    def test_content_change_bumps_to_high(self):
        old = {"/x": {"hash": "1", "suid": False}}
        new = {"/x": {"hash": "2", "suid": False}}
        changes = diff_snapshots("files", old, new)
        self.assertEqual(changes[0].severity, Severity.HIGH)

    def test_new_root_account_is_critical(self):
        changes = diff_snapshots("users", {}, {"backdoor": {"uid": 0}})
        self.assertEqual(changes[0].severity, Severity.CRITICAL)

    def test_new_regular_account_is_high_default(self):
        changes = diff_snapshots("users", {}, {"alice": {"uid": 1001}})
        self.assertEqual(changes[0].severity, Severity.HIGH)

    def test_uid_change_on_existing_account_is_critical(self):
        old = {"alice": {"uid": 1001}}
        new = {"alice": {"uid": 0}}
        changes = diff_snapshots("users", old, new)
        self.assertEqual(changes[0].severity, Severity.CRITICAL)

    def test_new_root_ssh_key_is_critical(self):
        changes = diff_snapshots("ssh_keys", {}, {"k1": {"user": "root"}})
        self.assertEqual(changes[0].severity, Severity.CRITICAL)

    def test_new_non_root_ssh_key_is_default_high(self):
        changes = diff_snapshots("ssh_keys", {}, {"k1": {"user": "alice"}})
        self.assertEqual(changes[0].severity, Severity.HIGH)


class SeverityOrderingTests(unittest.TestCase):
    def test_severities_are_orderable(self):
        self.assertLess(Severity.INFO, Severity.LOW)
        self.assertLess(Severity.HIGH, Severity.CRITICAL)
        self.assertGreater(Severity.CRITICAL, Severity.MEDIUM)

    def test_from_name_is_case_insensitive(self):
        self.assertEqual(Severity.from_name("high"), Severity.HIGH)
        self.assertEqual(Severity.from_name("CRITICAL"), Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
