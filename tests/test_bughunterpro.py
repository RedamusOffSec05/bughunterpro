#!/usr/bin/env python3
"""Unit tests for BugHunterPro core script."""

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

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
            [sys.executable, str(script), "--target", "example.com"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Hunting en example.com", proc.stdout)


if __name__ == "__main__":
    unittest.main()
