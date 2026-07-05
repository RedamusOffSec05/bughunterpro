#!/usr/bin/env python3
"""Unit tests for red_offensive_team_05 utility functions."""

import hashlib
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import red_offensive_team_05 as rot05


class TestExtractPorts(unittest.TestCase):
    def test_tcp_ports_parsed(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".nmap", delete=False) as f:
            f.write("443/tcp  open  https\n88/tcp  open  kerberos\n")
            tmp = Path(f.name)
        try:
            ports = rot05.extract_ports(tmp)
            self.assertIn("443", ports)
            self.assertIn("88", ports)
        finally:
            tmp.unlink()

    def test_udp_lines_excluded(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".nmap", delete=False) as f:
            f.write("53/udp  open  domain\n")
            tmp = Path(f.name)
        try:
            ports = rot05.extract_ports(tmp)
            self.assertEqual(ports, "")
        finally:
            tmp.unlink()

    def test_missing_file_returns_empty(self):
        self.assertEqual(rot05.extract_ports(Path("/nonexistent/file.nmap")), "")


class TestRedact(unittest.TestCase):
    def test_short_password_flag_redacted(self):
        cmd = ["ldapsearch", "-w", "supersecret", "-b", "dc=test,dc=local"]
        result = rot05._redact(cmd)
        self.assertNotIn("supersecret", result)
        self.assertIn("***", result)

    def test_long_password_flag_redacted(self):
        cmd = ["tool", "--password", "hunter2"]
        result = rot05._redact(cmd)
        self.assertNotIn("hunter2", result)

    def test_non_sensitive_flags_unchanged(self):
        cmd = ["nmap", "-Pn", "--open", "10.10.10.10"]
        result = rot05._redact(cmd)
        self.assertIn("nmap", result)
        self.assertNotIn("***", result)

    def test_multiple_password_flags(self):
        cmd = ["tool", "-p", "pass1", "--password", "pass2"]
        result = rot05._redact(cmd)
        self.assertEqual(result.count("***"), 2)


class TestCalculateFileHash(unittest.TestCase):
    def test_known_content(self):
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"hello world")
            tmp = Path(f.name)
        try:
            expected = hashlib.sha256(b"hello world").hexdigest()
            self.assertEqual(rot05.calculate_file_hash(tmp), expected)
        finally:
            tmp.unlink()

    def test_missing_file_returns_empty(self):
        self.assertEqual(rot05.calculate_file_hash(Path("/nonexistent")), "")


class TestRateLimiter(unittest.TestCase):
    def test_enforces_min_delay(self):
        limiter = rot05.RateLimiter(min_delay=0.05)
        limiter.wait()
        start = time.time()
        limiter.wait()
        elapsed = time.time() - start
        self.assertGreaterEqual(elapsed, 0.04)

    def test_no_extra_delay_after_pause(self):
        limiter = rot05.RateLimiter(min_delay=0.05)
        limiter.wait()
        time.sleep(0.1)
        start = time.time()
        limiter.wait()
        elapsed = time.time() - start
        self.assertLess(elapsed, 0.04)


class TestCheckpointManager(unittest.TestCase):
    def test_phase_lifecycle(self):
        with tempfile.TemporaryDirectory() as td:
            mgr = rot05.CheckpointManager(Path(td))
            self.assertFalse(mgr.is_done("phase1"))
            mgr.update("phase1", rot05.PhaseStatus.COMPLETED)
            self.assertTrue(mgr.is_done("phase1"))

    def test_should_skip_respects_force(self):
        with tempfile.TemporaryDirectory() as td:
            mgr = rot05.CheckpointManager(Path(td))
            mgr.update("phase1", rot05.PhaseStatus.COMPLETED)
            self.assertTrue(mgr.should_skip("phase1", force=False))
            self.assertFalse(mgr.should_skip("phase1", force=True))

    def test_persistence_across_instances(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            mgr1 = rot05.CheckpointManager(p)
            mgr1.update("phase_x", rot05.PhaseStatus.COMPLETED)
            mgr2 = rot05.CheckpointManager(p)
            self.assertTrue(mgr2.is_done("phase_x"))


class TestComplianceChecker(unittest.TestCase):
    def test_always_in_window(self):
        checker = rot05.ComplianceChecker(start_hour=0, end_hour=23)
        ok, _ = checker.check()
        self.assertTrue(ok)

    def test_never_in_window(self):
        checker = rot05.ComplianceChecker(start_hour=0, end_hour=0)
        ok, _ = checker.check()
        self.assertFalse(ok)


class TestTargetConfig(unittest.TestCase):
    def test_has_creds_with_password(self):
        cfg = rot05.TargetConfig(username="admin", password="pass")
        self.assertTrue(cfg.has_creds())

    def test_has_creds_with_hash(self):
        cfg = rot05.TargetConfig(username="admin", ntlm_hash="aad3b435b51404ee")
        self.assertTrue(cfg.has_creds())

    def test_no_creds(self):
        self.assertFalse(rot05.TargetConfig().has_creds())

    def test_no_username(self):
        self.assertFalse(rot05.TargetConfig(password="pass").has_creds())

    def test_cred_str_password(self):
        cfg = rot05.TargetConfig(ip="10.0.0.1", domain="lab.local",
                                  username="user", password="pass")
        s = cfg.cred_str()
        self.assertIn("lab.local/user:pass@10.0.0.1", s)

    def test_cred_str_hash(self):
        cfg = rot05.TargetConfig(ip="10.0.0.1", domain="lab.local",
                                  username="user", ntlm_hash="aad3")
        s = cfg.cred_str()
        self.assertIn("-hashes :aad3", s)


class TestConfigFile(unittest.TestCase):
    def test_safe_keys_only_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cfg.json"
            cfg = rot05.TargetConfig(
                ip="10.0.0.1", domain="lab.local", username="admin",
                password="secret", ntlm_hash="deadbeef",
            )
            rot05.ConfigFile(path).save(cfg)
            import json
            data = json.loads(path.read_text())
            self.assertIn("ip", data)
            self.assertNotIn("password", data)
            self.assertNotIn("ntlm_hash", data)

    def test_apply_populates_config(self):
        with tempfile.TemporaryDirectory() as td:
            import json
            path = Path(td) / "cfg.json"
            path.write_text(json.dumps({"domain": "test.local", "username": "bob"}))
            target = rot05.TargetConfig()
            rot05.ConfigFile(path).apply(target)
            self.assertEqual(target.domain, "test.local")
            self.assertEqual(target.username, "bob")

    def test_missing_file_applies_nothing(self):
        target = rot05.TargetConfig(domain="original.local")
        rot05.ConfigFile(Path("/nonexistent/cfg.json")).apply(target)
        self.assertEqual(target.domain, "original.local")


if __name__ == "__main__":
    unittest.main()
