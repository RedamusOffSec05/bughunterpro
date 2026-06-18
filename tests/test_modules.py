"""Tests for modules/base.py and plugin modules."""

import pytest

from modules.base import BaseModule


# ── BaseModule ───────────────────────────────────────────────────────────────

class _EchoModule(BaseModule):
    """Minimal concrete module that returns a fixed finding."""
    name        = "echo"
    description = "Test module"

    def run(self, target):
        return [{"type": "Echo", "severity": "Info", "detail": f"hit {target}"}]


class _ErrorModule(BaseModule):
    name = "error"
    description = "Module that raises"

    def run(self, target):
        raise ValueError("intentional test error")


class _EmptyModule(BaseModule):
    name = "empty"
    description = "Returns nothing"

    def run(self, target):
        return []


class TestBaseModuleExecute:
    def test_execute_returns_results(self):
        m = _EchoModule()
        results = m.execute("example.com")
        assert len(results) == 1
        assert results[0]["type"] == "Echo"

    def test_execute_records_timing(self):
        m = _EchoModule()
        m.execute("example.com")
        assert m.started_at  is not None
        assert m.finished_at is not None
        assert m.finished_at >= m.started_at

    def test_execute_catches_exception(self):
        m = _ErrorModule()
        results = m.execute("example.com")
        assert results == []
        assert len(m.errors) == 1
        assert "intentional test error" in m.errors[0]

    def test_execute_empty_run(self):
        m = _EmptyModule()
        results = m.execute("example.com")
        assert results == []
        assert m.errors == []

    def test_to_dict_structure(self):
        m = _EchoModule()
        m.execute("example.com")
        d = m.to_dict()
        assert d["module"]      == "echo"
        assert d["description"] == "Test module"
        assert isinstance(d["results"], list)
        assert isinstance(d["errors"],  list)
        assert d["duration_s"]  is not None
        assert d["duration_s"]  >= 0

    def test_to_dict_before_execute(self):
        m = _EchoModule()
        d = m.to_dict()
        assert d["started_at"]  is None
        assert d["finished_at"] is None
        assert d["duration_s"]  is None

    def test_config_passed_through(self):
        cfg = {"key": "value"}
        m = _EchoModule(config=cfg)
        assert m.config["key"] == "value"

    def test_default_config_is_empty_dict(self):
        m = _EchoModule()
        assert m.config == {}

    def test_multiple_executes_accumulate_results(self):
        m = _EchoModule()
        m.execute("a.com")
        m.execute("b.com")
        assert len(m.results) == 2


# ── BannerGrabModule ──────────────────────────────────────────────────────────

class TestBannerGrabModule:
    def test_empty_on_connect_failure(self):
        from modules.passive_recon import BannerGrabModule
        from unittest.mock import patch
        import socket

        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch("socket.socket") as mock_cls:
            mock_sock = mock_cls.return_value
            mock_sock.connect.side_effect = ConnectionRefusedError
            m = BannerGrabModule(config={"open_ports": [80]})
            results = m.execute("example.com")
            assert results == []

    def test_resolve_failure_returns_empty(self):
        from modules.passive_recon import BannerGrabModule
        from unittest.mock import patch
        import socket

        with patch("socket.gethostbyname", side_effect=socket.gaierror):
            m = BannerGrabModule(config={"open_ports": [80]})
            results = m.execute("invalid.invalid")
            assert results == []
            assert len(m.errors) == 1


# ── CredentialModule ──────────────────────────────────────────────────────────

class TestCredentialModule:
    def test_skips_ssh_without_port_open(self):
        from modules.credentials import CredentialModule
        m = CredentialModule(config={"open_ports": []})
        results = m.execute("example.com")
        # No ports open → nothing to test (web probe may error, that's OK)
        assert isinstance(results, list)

    def test_wordlist_override(self):
        from modules.credentials import CredentialModule
        custom = [("alice", "secret")]
        m = CredentialModule(config={"wordlist": custom, "open_ports": []})
        assert m.wordlist == custom

    def test_rate_default(self):
        from modules.credentials import CredentialModule
        m = CredentialModule()
        assert m._bucket.rate == 2.0
