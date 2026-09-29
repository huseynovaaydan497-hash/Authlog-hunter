import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from helpers import SAMPLE

from authlog_hunter.cli import main


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(args))
        except SystemExit as exc:  # argparse errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_text_report(self):
        code, out, _ = run_cli(str(SAMPLE), "--year", "2026")
        self.assertEqual(code, 0)
        self.assertIn("[CRITICAL] AH-003", out)
        self.assertIn("ATTACK CHAIN 1", out)
        self.assertNotIn("\033[", out)  # no colours when not a TTY

    def test_json_report_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.json"
            code, _, err = run_cli(str(SAMPLE), "--year", "2026", "-f", "json", "-o", str(target))
            data = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertIn("report written", err)
        self.assertEqual(data["tool"], "authlog-hunter")
        first = data["findings"][0]
        self.assertEqual((first["rule_id"], first["severity"]), ("AH-003", "CRITICAL"))
        self.assertEqual(first["techniques"][0]["url"], "https://attack.mitre.org/techniques/T1110/001/")
        self.assertEqual(data["attack_chains"][0]["src_ip"], "192.0.2.77")

    def test_markdown_report(self):
        code, out, _ = run_cli(str(SAMPLE), "--year", "2026", "-f", "markdown")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("# authlog-hunter report"))
        self.assertIn("## Attack chains", out)

    def test_min_severity_and_allowlist(self):
        code, out, _ = run_cli(str(SAMPLE), "--year", "2026", "-f", "json", "--min-severity", "medium",
                               "--allowlist", "10.10.0.0/16")
        data = json.loads(out)
        self.assertNotIn("LOW", {f["severity"] for f in data["findings"]})
        self.assertNotIn("AH-004", {f["rule_id"] for f in data["findings"]})  # Ansible root login allowlisted
        self.assertEqual(data["summary"]["findings_by_severity"]["LOW"], 0)

    def test_fail_on_exit_code(self):
        self.assertEqual(run_cli(str(SAMPLE), "--fail-on", "critical", "-f", "json")[0], 1)
        with tempfile.TemporaryDirectory() as tmp:
            clean = Path(tmp) / "clean.log"
            clean.write_text("Sep 28 10:00:00 web sshd[1]: Accepted publickey for alice from 10.0.0.2 port 1 ssh2\n")
            self.assertEqual(run_cli(str(clean), "--fail-on", "low")[0], 0)

    def test_errors(self):
        self.assertEqual(run_cli("does-not-exist.log")[0], 2)
        self.assertEqual(run_cli(str(SAMPLE), "--allowlist", "not-an-ip")[0], 2)
        self.assertEqual(run_cli(str(SAMPLE), "--min-severity", "urgent")[0], 2)

    def test_list_rules(self):
        code, out, _ = run_cli("--list-rules")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 19)


if __name__ == "__main__":
    unittest.main()
