import json
import stat
import tempfile
import unittest
from pathlib import Path

from baselineguard.storage import BaselineNotFound, BaselineStore, TamperDetected


class BaselineStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.store = BaselineStore(base / "baseline.json", base / "signing.key")

    def test_load_without_baseline_raises(self):
        with self.assertRaises(BaselineNotFound):
            self.store.load()

    def test_save_then_load_round_trips(self):
        self.store.save({"files": {"/a": {"hash": "1"}}})
        baseline = self.store.load()
        self.assertEqual(baseline.collectors, {"files": {"/a": {"hash": "1"}}})

    def test_key_file_is_created_with_restrictive_permissions(self):
        self.store.save({"files": {}})
        mode = stat.S_IMODE(self.store.key_file.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_key_is_reused_across_saves(self):
        self.store.save({"files": {}})
        key_first = self.store.key_file.read_bytes()
        self.store.save({"files": {"/a": {}}})
        key_second = self.store.key_file.read_bytes()
        self.assertEqual(key_first, key_second)

    def test_tampering_with_payload_is_detected(self):
        self.store.save({"files": {"/a": {"hash": "1"}}})
        envelope = json.loads(self.store.baseline_file.read_text())
        envelope["payload"]["collectors"]["files"]["/a"]["hash"] = "attacker-controlled"
        self.store.baseline_file.write_text(json.dumps(envelope))

        with self.assertRaises(TamperDetected):
            self.store.load()

    def test_wrong_signing_key_is_detected(self):
        self.store.save({"files": {}})
        self.store.key_file.write_bytes(b"0" * 32)
        with self.assertRaises(TamperDetected):
            self.store.load()

    def test_exists_reflects_baseline_presence(self):
        self.assertFalse(self.store.exists())
        self.store.save({"files": {}})
        self.assertTrue(self.store.exists())


if __name__ == "__main__":
    unittest.main()
