import os
import tempfile
import unittest
from pathlib import Path

from baselineguard.collectors.files import FileCollector


class FileCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_collects_regular_files_with_hash(self):
        (self.root / "a.txt").write_text("hello")
        records = FileCollector([str(self.root)]).collect()
        self.assertEqual(len(records), 1)
        record = next(iter(records.values()))
        self.assertEqual(record["type"], "file")
        self.assertIsNotNone(record["hash"])

    def test_excludes_matching_glob(self):
        (self.root / "keep.txt").write_text("a")
        (self.root / "skip.log").write_text("b")
        records = FileCollector([str(self.root)], excludes=["*.log"]).collect()
        names = {Path(p).name for p in records}
        self.assertEqual(names, {"keep.txt"})

    def test_nested_directories_are_walked(self):
        nested = self.root / "sub" / "dir"
        nested.mkdir(parents=True)
        (nested / "deep.txt").write_text("x")
        records = FileCollector([str(self.root)]).collect()
        self.assertTrue(any("deep.txt" in p for p in records))

    def test_setuid_bit_is_recorded(self):
        target = self.root / "suid_bin"
        target.write_text("binary")
        os.chmod(target, 0o4755)
        records = FileCollector([str(self.root)]).collect()
        record = next(iter(records.values()))
        self.assertTrue(record["suid"])

    def test_content_change_changes_hash(self):
        target = self.root / "a.txt"
        target.write_text("version1")
        before = FileCollector([str(self.root)]).collect()
        target.write_text("version2 - different length")
        after = FileCollector([str(self.root)]).collect()
        key = str(target)
        self.assertNotEqual(before[key]["hash"], after[key]["hash"])

    def test_missing_root_path_is_ignored(self):
        records = FileCollector(["/definitely/does/not/exist"]).collect()
        self.assertEqual(records, {})

    def test_oversized_file_is_skipped_but_recorded(self):
        target = self.root / "big.bin"
        target.write_bytes(b"x" * 1024)
        records = FileCollector([str(self.root)], max_file_size_mb=0).collect()
        record = next(iter(records.values()))
        self.assertIsNone(record["hash"])
        self.assertIn("skipped", record["note"])


if __name__ == "__main__":
    unittest.main()
