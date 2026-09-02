import tempfile
import unittest
from pathlib import Path

from baselineguard.collectors.cron import CronCollector


class CronCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "cron.d").mkdir()
        (self.root / "crontabs").mkdir()

    def _collector(self) -> CronCollector:
        return CronCollector(
            system_crontab=str(self.root / "crontab"),
            cron_d_dir=str(self.root / "cron.d"),
            user_crontab_dir=str(self.root / "crontabs"),
        )

    def test_reads_system_crontab_entries(self):
        (self.root / "crontab").write_text("0 * * * * root /usr/bin/true\n")
        records = self._collector().collect()
        self.assertEqual(len(records), 1)
        entry = next(iter(records.values()))
        self.assertIn("/usr/bin/true", entry["line"])

    def test_reads_cron_d_files(self):
        (self.root / "cron.d" / "backups").write_text("*/5 * * * * root /opt/backup.sh\n")
        records = self._collector().collect()
        self.assertTrue(any("backup.sh" in r["line"] for r in records.values()))

    def test_comments_and_blanks_ignored(self):
        (self.root / "cron.d" / "job").write_text("# a comment\n\n* * * * * root /bin/true\n")
        records = self._collector().collect()
        self.assertEqual(len(records), 1)

    def test_missing_directories_are_tolerated(self):
        collector = CronCollector(
            system_crontab=str(self.root / "nope"),
            cron_d_dir=str(self.root / "also-nope"),
            user_crontab_dir=str(self.root / "still-nope"),
        )
        self.assertEqual(collector.collect(), {})

    def test_two_identical_lines_in_different_files_do_not_collide(self):
        (self.root / "cron.d" / "one").write_text("* * * * * root /bin/true\n")
        (self.root / "cron.d" / "two").write_text("* * * * * root /bin/true\n")
        records = self._collector().collect()
        self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
