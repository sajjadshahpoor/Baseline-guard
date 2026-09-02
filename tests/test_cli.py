import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from baselineguard.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.monitored = self.root / "monitored"
        self.monitored.mkdir()
        (self.monitored / "a.txt").write_text("hello")

        self.config_path = self.root / "config.toml"
        self.config_path.write_text(
            f"""
            state_dir = "{self.root / "state"}"

            [files]
            paths = ["{self.monitored}"]
            excludes = []

            [alerts]
            console = false
            """
        )

    def _run(self, *args: str) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["-c", str(self.config_path), *args])
        return code, buf.getvalue()

    def test_init_creates_baseline(self):
        code, output = self._run("init")
        self.assertEqual(code, 0)
        self.assertTrue((self.root / "state" / "baseline.json").is_file())
        self.assertIn("Initialized", output)

    def test_init_twice_does_not_overwrite(self):
        self._run("init")
        code, output = self._run("init")
        self.assertEqual(code, 0)
        self.assertIn("already exists", output)

    def test_baseline_requires_force_to_overwrite(self):
        self._run("init")
        code, output = self._run("baseline")
        self.assertEqual(code, 1)
        self.assertIn("--force", output)

    def test_scan_without_baseline_errors(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            code = main(["-c", str(self.config_path), "scan"])
        self.assertEqual(code, 2)

    def test_clean_scan_exits_zero(self):
        self._run("init")
        code, _ = self._run("scan")
        self.assertEqual(code, 0)

    def test_scan_detects_change_and_exits_nonzero(self):
        self._run("init")
        (self.monitored / "a.txt").write_text("modified content here")
        code, output = self._run("scan")
        self.assertEqual(code, 1)
        self.assertIn("1 baseline change", output)

    def test_report_after_scan_shows_history(self):
        self._run("init")
        self._run("scan")
        code, output = self._run("report")
        self.assertEqual(code, 0)
        self.assertIn("highest_severity", output)

    def test_report_before_any_scan(self):
        self._run("init")
        code, output = self._run("report")
        self.assertEqual(code, 0)
        self.assertIn("No scan history", output)


if __name__ == "__main__":
    unittest.main()
