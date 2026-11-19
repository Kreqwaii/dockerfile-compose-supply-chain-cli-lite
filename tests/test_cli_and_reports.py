import io
import json
import os
import unittest
from contextlib import redirect_stdout
from docker_supply_lite.cli import main
from docker_supply_lite.reporter import format_json, format_markdown, format_text
from docker_supply_lite.rules import Finding


class TestCliAndReports(unittest.TestCase):
    def setUp(self):
        self.base = os.path.dirname(os.path.dirname(__file__))
        self.risky_df = os.path.join(self.base, "samples", "Dockerfile.risky")
        self.hardened_df = os.path.join(self.base, "samples", "Dockerfile.hardened")
        self.risky_dc = os.path.join(self.base, "samples", "docker-compose.risky.yml")

    def test_cli_hardened_returns_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([self.hardened_df])
        self.assertEqual(rc, 0)
        self.assertIn("PASS", buf.getvalue())

    def test_cli_risky_fail_on_high_returns_one(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([self.risky_df, "--fail-on", "high"])
        self.assertEqual(rc, 1)

    def test_cli_risky_fail_on_none_returns_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([self.risky_df, "--fail-on", "none"])
        self.assertEqual(rc, 0)

    def test_cli_json_output_valid(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([self.risky_df, self.risky_dc, "--format", "json", "--fail-on", "none"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("summary", data)
        self.assertGreater(data["summary"]["total"], 5)

    def test_cli_markdown_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([self.risky_df, "--format", "markdown", "--fail-on", "none"])
        self.assertEqual(rc, 0)
        self.assertIn("# Docker & Compose Supply-Chain Audit Report", buf.getvalue())

    def test_cli_missing_file_returns_two(self):
        rc = main(["nonexistent_file_12345.yml"])
        self.assertEqual(rc, 2)

    def test_format_text_empty(self):
        self.assertIn("PASS", format_text([]))

    def test_format_markdown_empty(self):
        self.assertIn("No security or supply-chain issues detected", format_markdown([]))

    def test_format_json_structure(self):
        f = Finding("DF001", "high", "Dockerfile", 1, "msg", "fix", "python:latest")
        parsed = json.loads(format_json([f]))
        self.assertEqual(parsed["summary"]["high"], 1)
        self.assertEqual(parsed["findings"][0]["rule_id"], "DF001")


if __name__ == "__main__":
    unittest.main()
