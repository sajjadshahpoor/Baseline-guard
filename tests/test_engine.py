import tempfile
import unittest
from pathlib import Path

from baselineguard.config import Config, FilesConfig
from baselineguard.engine import BaselineGuard
from baselineguard.storage import BaselineNotFound


class BaselineGuardEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.monitored = self.root / "monitored"
        self.monitored.mkdir()

        self.cfg = Config.default()
        self.cfg.state_dir = self.root / "state"
        self.cfg.files = FilesConfig(paths=[str(self.monitored)], excludes=[])
        self.guard = BaselineGuard(self.cfg)

    def test_scan_without_baseline_raises(self):
        with self.assertRaises(BaselineNotFound):
            self.guard.scan()

    def test_clean_scan_reports_no_file_changes(self):
        (self.monitored / "a.txt").write_text("stable")
        self.guard.create_baseline()
        result = self.guard.scan()
        self.assertEqual(result.changes, [])

    def test_modified_file_is_detected_on_scan(self):
        target = self.monitored / "a.txt"
        target.write_text("original")
        self.guard.create_baseline()

        target.write_text("modified content, different length")
        result = self.guard.scan()

        self.assertEqual(len(result.changes), 1)
        self.assertEqual(result.changes[0].collector, "files")
        self.assertFalse(result.is_clean())

    def test_new_file_is_detected_as_added(self):
        self.guard.create_baseline()
        (self.monitored / "new.txt").write_text("surprise")
        result = self.guard.scan()
        self.assertEqual(len(result.changes), 1)
        self.assertEqual(result.changes[0].change_type, "added")

    def test_deleted_file_is_detected_as_removed(self):
        target = self.monitored / "gone.txt"
        target.write_text("temporary")
        self.guard.create_baseline()
        target.unlink()
        result = self.guard.scan()
        self.assertEqual(len(result.changes), 1)
        self.assertEqual(result.changes[0].change_type, "removed")

    def test_create_baseline_returns_item_count(self):
        (self.monitored / "a.txt").write_text("x")
        (self.monitored / "b.txt").write_text("y")
        count = self.guard.create_baseline()
        self.assertGreaterEqual(count, 2)

    def test_alerts_property_merges_changes_and_findings(self):
        self.guard.create_baseline()
        (self.monitored / "new.txt").write_text("data")
        result = self.guard.scan()
        # every change should surface as an alert too
        self.assertGreaterEqual(len(result.alerts), len(result.changes))


if __name__ == "__main__":
    unittest.main()
