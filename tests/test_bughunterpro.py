#!/usr/bin/env python3
"""Unit tests for BugHunterPro core script."""

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import BugHunterPro as bhp
from BugHunterPro import BugHunterPro


class TestBugHunterPro(unittest.TestCase):
    def test_hunt_output_schema(self):
        result = BugHunterPro("example.com", mode="normal").hunt()
        self.assertIn("subdomains", result)
        self.assertIn("vulnerabilities", result)
        self.assertIsInstance(result["subdomains"], list)
        self.assertIsInstance(result["vulnerabilities"], list)

    def test_cli_runs_with_target(self):
        script = Path(__file__).parent.parent / "BugHunterPro.py"
        proc = subprocess.run(
            [sys.executable, str(script), "--target", "example.com", "--no-report"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Hunting en example.com", proc.stdout)


class TestSensitivePortFindings(unittest.TestCase):
    def test_flags_known_sensitive_port(self):
        findings = bhp.sensitive_port_findings("host", [3389, 80])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "open_sensitive_port")
        self.assertIn("3389", findings[0]["evidence"])

    def test_no_findings_for_non_sensitive_ports(self):
        self.assertEqual(bhp.sensitive_port_findings("host", [80, 443]), [])


class TestIdorCandidateRegex(unittest.TestCase):
    def test_matches_numeric_id_link(self):
        html = '<a href="/invoice?id=1024">View</a>'
        self.assertTrue(bhp.IDOR_CANDIDATE_RE.search(html))

    def test_ignores_non_numeric_id(self):
        html = '<a href="/profile?id=abc">View</a>'
        self.assertFalse(bhp.IDOR_CANDIDATE_RE.search(html))


class TestSqliSignatures(unittest.TestCase):
    def test_detects_mysql_signature(self):
        body = "You have an error in your SQL syntax; check the manual for your MySQL server version"
        matched = any(p.search(body) for _, p in bhp.SQLI_ERROR_SIGNATURES)
        self.assertTrue(matched)

    def test_clean_body_has_no_match(self):
        body = "<html><body>Welcome</body></html>"
        matched = any(p.search(body) for _, p in bhp.SQLI_ERROR_SIGNATURES)
        self.assertFalse(matched)


class TestBuildReportAndMarkdown(unittest.TestCase):
    def test_build_report_sorts_findings_by_severity(self):
        findings = [bhp._finding("missing_hsts", "t"), bhp._finding("sqli_error_based", "t")]
        report = bhp.build_report("t", "normal", [], [], findings, "2024-01-01T00:00:00+00:00")
        self.assertEqual(report["findings"][0]["type"], "sqli_error_based")
        self.assertEqual(report["summary"]["findings_by_severity"]["High"], 1)

    def test_render_markdown_includes_target_and_sections(self):
        report = bhp.build_report("t.example", "normal", [], [], [], "2024-01-01T00:00:00+00:00")
        md = bhp.render_markdown(report)
        self.assertIn("t.example", md)
        self.assertIn("## Findings", md)
        self.assertIn("## Recommendations", md)


if __name__ == "__main__":
    unittest.main()
