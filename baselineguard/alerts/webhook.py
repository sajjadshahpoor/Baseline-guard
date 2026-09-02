"""Generic webhook alert channel (stdlib ``urllib`` only).

Posts a JSON payload to any HTTP endpoint, which covers Slack/Discord
incoming webhooks, custom SIEM ingest endpoints, or anything else that
accepts a POST body — without pulling in an HTTP client dependency.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from ..diff import Severity
from .base import Alert


class WebhookAlertChannel:
    def __init__(self, url: str, min_severity: Severity = Severity.MEDIUM, timeout: int = 10):
        self.url = url
        self.min_severity = min_severity
        self.timeout = timeout

    def send(self, alerts: list[Alert]) -> None:
        relevant = [a for a in alerts if a.severity >= self.min_severity]
        if not relevant or not self.url:
            return

        payload = json.dumps(
            {
                "text": f"baseline-guard: {len(relevant)} alert(s) detected",
                "alerts": [a.to_dict() for a in relevant],
            }
        ).encode("utf-8")

        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout):
                pass
        except urllib.error.URLError:
            pass  # a broken alert channel must never crash the scan itself
