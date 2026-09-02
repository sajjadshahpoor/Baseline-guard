"""Email alert channel (stdlib ``smtplib`` only, no third-party mail SDK).

The SMTP password is never read from the config file itself — only the
*name* of an environment variable to read it from
(``password_env_var``). This keeps credentials out of a file that might
end up committed, backed up, or copied around with the rest of the
config.
"""

from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage

from ..diff import Severity
from .base import Alert


class EmailAlertChannel:
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        from_addr: str,
        to_addrs: list[str],
        username: str = "",
        password_env_var: str = "",
        use_tls: bool = True,
        min_severity: Severity = Severity.HIGH,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.username = username
        self.password_env_var = password_env_var
        self.use_tls = use_tls
        self.min_severity = min_severity

    def send(self, alerts: list[Alert]) -> None:
        relevant = [a for a in alerts if a.severity >= self.min_severity]
        if not relevant or not self.to_addrs:
            return

        message = EmailMessage()
        message["Subject"] = f"[baseline-guard] {len(relevant)} alert(s) detected"
        message["From"] = self.from_addr
        message["To"] = ", ".join(self.to_addrs)
        message.set_content(self._body(relevant))

        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as smtp:
            if self.use_tls:
                smtp.starttls()
            password = os.environ.get(self.password_env_var, "") if self.password_env_var else ""
            if self.username and password:
                smtp.login(self.username, password)
            smtp.send_message(message)

    @staticmethod
    def _body(alerts: list[Alert]) -> str:
        lines = [f"{a.severity.name:<8} {a.collector:<10} {a.title}\n  {a.detail}" for a in alerts]
        return "\n\n".join(lines)
