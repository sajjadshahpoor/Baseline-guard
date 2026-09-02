import os
import tempfile
import unittest
from pathlib import Path

from baselineguard.diff import Severity
from baselineguard.collectors.network import NetworkCollector
from baselineguard.collectors.processes import ProcessCollector


class ProcessCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proc = Path(self.tmp.name)

    def _make_fake_process(self, pid: str, exe_target: str, cmdline: str = "cmd"):
        pid_dir = self.proc / pid
        pid_dir.mkdir()
        (pid_dir / "cmdline").write_bytes(cmdline.encode() + b"\x00")
        os.symlink(exe_target, pid_dir / "exe")

    def test_process_in_suspicious_dir_is_flagged(self):
        self._make_fake_process("100", "/tmp/payload")
        findings = ProcessCollector(suspicious_dirs=["/tmp"], proc_dir=str(self.proc)).scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_process_in_normal_dir_is_not_flagged(self):
        self._make_fake_process("101", "/usr/bin/bash")
        findings = ProcessCollector(suspicious_dirs=["/tmp"], proc_dir=str(self.proc)).scan()
        self.assertEqual(findings, [])

    def test_deleted_running_binary_is_critical(self):
        self._make_fake_process("102", "/usr/bin/bash (deleted)")
        findings = ProcessCollector(proc_dir=str(self.proc)).scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_non_numeric_entries_are_ignored(self):
        (self.proc / "self").mkdir()
        findings = ProcessCollector(proc_dir=str(self.proc)).scan()
        self.assertEqual(findings, [])

    def test_missing_proc_dir_returns_no_findings(self):
        findings = ProcessCollector(proc_dir="/definitely/not/real").scan()
        self.assertEqual(findings, [])


class NetworkCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proc_net = Path(self.tmp.name)

    def _write_tcp_table(self, entries: list[tuple[str, str]]):
        header = "  sl  local_address rem_address   st ...\n"
        lines = [
            f"   {i}: {addr} 00000000:0000 {state} ..."
            for i, (addr, state) in enumerate(entries)
        ]
        (self.proc_net / "tcp").write_text(header + "\n".join(lines) + "\n")
        (self.proc_net / "tcp6").write_text(header)

    def test_listening_port_outside_allowlist_is_flagged(self):
        # 0x1F90 = 8080, state 0A = LISTEN
        self._write_tcp_table([("00000000:1F90", "0A")])
        findings = NetworkCollector(allowed_ports=[22], proc_net_dir=str(self.proc_net)).scan()
        self.assertEqual(len(findings), 1)
        self.assertIn("8080", findings[0].detail)

    def test_allowed_port_is_not_flagged(self):
        # 0x0016 = 22
        self._write_tcp_table([("00000000:0016", "0A")])
        findings = NetworkCollector(allowed_ports=[22], proc_net_dir=str(self.proc_net)).scan()
        self.assertEqual(findings, [])

    def test_non_listening_state_is_ignored(self):
        # state 01 = ESTABLISHED, not LISTEN
        self._write_tcp_table([("00000000:1F90", "01")])
        findings = NetworkCollector(allowed_ports=[], proc_net_dir=str(self.proc_net)).scan()
        self.assertEqual(findings, [])

    def test_missing_proc_net_returns_no_findings(self):
        findings = NetworkCollector(proc_net_dir="/definitely/not/real").scan()
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
