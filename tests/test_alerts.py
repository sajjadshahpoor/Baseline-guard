import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from baselineguard.alerts.base import Alert
from baselineguard.alerts.console import ConsoleAlertChannel
from baselineguard.alerts.logfile import LogFileAlertChannel
from baselineguard.alerts.webhook import WebhookAlertChannel
from baselineguard.diff import Severity


def _alert(severity=Severity.HIGH, title="Something changed"):
    return Alert(severity=severity, collector="files", title=title, detail="detail here")


class ConsoleAlertChannelTests(unittest.TestCase):
    def test_prints_one_line_per_alert(self):
        stream = io.StringIO()
        channel = ConsoleAlertChannel(stream=stream, use_color=False)
        channel.send([_alert(), _alert(title="Another one")])
        output = stream.getvalue().splitlines()
        self.assertEqual(len(output), 2)
        self.assertIn("HIGH", output[0])
        self.assertIn("Something changed", output[0])

    def test_color_codes_present_when_enabled(self):
        stream = io.StringIO()
        channel = ConsoleAlertChannel(stream=stream, use_color=True)
        channel.send([_alert(severity=Severity.CRITICAL)])
        self.assertIn("\033[", stream.getvalue())


class LogFileAlertChannelTests(unittest.TestCase):
    def test_appends_json_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "alerts.jsonl"
            channel = LogFileAlertChannel(path)
            channel.send([_alert()])
            channel.send([_alert(title="Second scan")])

            lines = path.read_text().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["title"], "Something changed")

    def test_empty_alert_list_does_not_create_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.jsonl"
            LogFileAlertChannel(path).send([])
            self.assertFalse(path.exists())


class WebhookAlertChannelTests(unittest.TestCase):
    def test_below_threshold_alerts_are_not_sent(self):
        with patch("baselineguard.alerts.webhook.urllib.request.urlopen") as mock_open:
            channel = WebhookAlertChannel(url="https://example.com/hook", min_severity=Severity.HIGH)
            channel.send([_alert(severity=Severity.LOW)])
            mock_open.assert_not_called()

    def test_at_or_above_threshold_is_posted(self):
        with patch("baselineguard.alerts.webhook.urllib.request.urlopen") as mock_open:
            channel = WebhookAlertChannel(url="https://example.com/hook", min_severity=Severity.MEDIUM)
            channel.send([_alert(severity=Severity.CRITICAL)])
            mock_open.assert_called_once()

    def test_network_error_does_not_raise(self):
        import urllib.error

        with patch(
            "baselineguard.alerts.webhook.urllib.request.urlopen",
            side_effect=urllib.error.URLError("boom"),
        ):
            channel = WebhookAlertChannel(url="https://example.com/hook", min_severity=Severity.LOW)
            channel.send([_alert(severity=Severity.HIGH)])  # should not raise

    def test_no_url_configured_skips_send(self):
        with patch("baselineguard.alerts.webhook.urllib.request.urlopen") as mock_open:
            WebhookAlertChannel(url="", min_severity=Severity.LOW).send([_alert()])
            mock_open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
