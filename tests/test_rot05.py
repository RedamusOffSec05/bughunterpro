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


def _encrypt_gpp_cpassword(plaintext: str) -> str:
    """Test-only helper: encode `plaintext` the same way GPP does, so we can
    round-trip through rot05.decrypt_gpp_cpassword without needing a
    hand-copied real-world ciphertext."""
    import base64
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    data = plaintext.encode("utf-16-le")
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    encryptor = Cipher(algorithms.AES(rot05.GPP_AES_KEY), modes.CBC(b"\x00" * 16)).encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(encrypted).decode().rstrip("=").replace("+", "-").replace("/", "_")


class TestDecryptGppCpassword(unittest.TestCase):
    def test_key_is_32_bytes_for_aes_256(self):
        self.assertEqual(len(rot05.GPP_AES_KEY), 32)

    def test_round_trip_recovers_plaintext(self):
        cpassword = _encrypt_gpp_cpassword("P@ssw0rd123!")
        self.assertEqual(rot05.decrypt_gpp_cpassword(cpassword), "P@ssw0rd123!")

    def test_known_real_world_vector(self):
        # Sample ciphertext taken verbatim from the `encrypted_data` literal in
        # BustedSec/gpp-decrypt's gpp-decrypt.rb (github.com/BustedSec/gpp-decrypt).
        # Confirms the key against an independent, real tool's test fixture,
        # not just a round-trip through our own encode/decode.
        cpassword = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
        self.assertEqual(rot05.decrypt_gpp_cpassword(cpassword), "Local*P4ssword!")

    def test_round_trip_with_url_safe_characters(self):
        # Pick a plaintext whose encrypted form is likely to need '-'/'_' swapped back.
        for candidate in ("abc", "a longer password with spaces", "unicode-é-ü"):
            cpassword = _encrypt_gpp_cpassword(candidate)
            self.assertEqual(rot05.decrypt_gpp_cpassword(cpassword), candidate)

    def test_empty_input_returns_empty_string(self):
        self.assertEqual(rot05.decrypt_gpp_cpassword(""), "")

    def test_garbage_input_does_not_raise(self):
        self.assertEqual(rot05.decrypt_gpp_cpassword("not-valid-base64!!"), "")

    def test_wrong_block_size_does_not_raise(self):
        # Valid base64, but not a multiple of the AES block size once decoded.
        self.assertEqual(rot05.decrypt_gpp_cpassword("YQ"), "")


class TestExtractGppCredentials(unittest.TestCase):
    def test_extracts_username_and_decrypted_password(self):
        cpassword = _encrypt_gpp_cpassword("hunter2")
        xml = (
            f'<Properties action="U" userName="localadmin" cpassword="{cpassword}" '
            f'newName="" fullName="" description="" />'
        )
        creds = rot05.extract_gpp_credentials(xml)
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["username"], "localadmin")
        self.assertEqual(creds[0]["password"], "hunter2")

    def test_multiple_entries_in_one_document(self):
        cpw1 = _encrypt_gpp_cpassword("first")
        cpw2 = _encrypt_gpp_cpassword("second")
        xml = (
            f'<Properties userName="svc1" cpassword="{cpw1}" />'
            f'<Properties runAs="svc2" cpassword="{cpw2}" />'
        )
        creds = rot05.extract_gpp_credentials(xml)
        self.assertEqual([c["password"] for c in creds], ["first", "second"])
        self.assertEqual([c["username"] for c in creds], ["svc1", "svc2"])

    def test_no_cpassword_attribute_yields_no_credentials(self):
        xml = '<Properties action="U" userName="localadmin" newName="" />'
        self.assertEqual(rot05.extract_gpp_credentials(xml), [])

    def test_empty_cpassword_attribute_is_skipped(self):
        xml = '<Properties userName="localadmin" cpassword="" />'
        self.assertEqual(rot05.extract_gpp_credentials(xml), [])


if __name__ == "__main__":
    unittest.main()
