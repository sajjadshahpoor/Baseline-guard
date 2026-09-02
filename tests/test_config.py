import tempfile
import unittest
from pathlib import Path

from baselineguard.config import Config


class DefaultConfigTests(unittest.TestCase):
    def test_default_has_sane_paths(self):
        cfg = Config.default()
        self.assertIn("/etc", cfg.files.paths)
        self.assertEqual(cfg.files.algorithm, "sha256")

    def test_derived_paths_live_under_state_dir(self):
        cfg = Config.default()
        self.assertEqual(cfg.baseline_file.parent, cfg.state_dir)
        self.assertEqual(cfg.key_file.parent, cfg.state_dir)


class TomlConfigTests(unittest.TestCase):
    def test_partial_override_keeps_other_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(
                """
                state_dir = "/custom/state"

                [files]
                paths = ["/opt/app"]

                [alerts.email]
                enabled = true
                to_addrs = ["ops@example.com"]
                """
            )
            cfg = Config.load(path)
            self.assertEqual(str(cfg.state_dir), "/custom/state")
            self.assertEqual(cfg.files.paths, ["/opt/app"])
            # Untouched defaults should survive the partial override.
            self.assertEqual(cfg.files.algorithm, "sha256")
            self.assertTrue(cfg.alerts.email.enabled)
            self.assertEqual(cfg.alerts.email.to_addrs, ["ops@example.com"])
            self.assertFalse(cfg.alerts.webhook.enabled)

    def test_missing_file_falls_back_to_defaults(self):
        cfg = Config.load(Path("/nonexistent/path/config.toml"))
        self.assertIn("/etc", cfg.files.paths)


if __name__ == "__main__":
    unittest.main()
