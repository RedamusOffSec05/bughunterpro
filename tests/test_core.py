"""Tests for BugHunterPro core functions."""

import json
import os
import socket
import tempfile
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

import BugHunterPro as bhp


# ── Helpers ──────────────────────────────────────────────────────────────────

class TestUrlParams:
    def test_single_param(self):
        assert bhp._url_params("http://x.com/p?id=1") == {"id": "1"}

    def test_multiple_params(self):
        result = bhp._url_params("http://x.com?a=1&b=2")
        assert result == {"a": "1", "b": "2"}

    def test_no_params(self):
        assert bhp._url_params("http://x.com/page") == {}

    def test_encoded_param(self):
        result = bhp._url_params("http://x.com?q=hello+world")
        assert "q" in result


class TestSqliHit:
    def test_detects_mysql_error(self):
        assert bhp._sqli_hit("you have an error in your sql syntax")

    def test_detects_oracle_error(self):
        assert bhp._sqli_hit("ORA-00933: SQL command")

    def test_detects_generic_sql(self):
        assert bhp._sqli_hit("SQLState: 42000 sqlstate error")

    def test_normal_page_is_clean(self):
        assert not bhp._sqli_hit("<html><body>Welcome</body></html>")

    def test_case_insensitive(self):
        assert bhp._sqli_hit("SQL SYNTAX Error detected")


# ── BugHunterPro class ───────────────────────────────────────────────────────

class TestBugHunterProInit:
    def test_strips_http_prefix(self):
        h = bhp.BugHunterPro("http://example.com")
        assert h.target == "example.com"

    def test_strips_https_prefix(self):
        h = bhp.BugHunterPro("https://example.com/")
        assert h.target == "example.com"

    def test_lowercase(self):
        h = bhp.BugHunterPro("Example.COM")
        assert h.target == "example.com"

    def test_normal_mode(self):
        h = bhp.BugHunterPro("example.com")
        assert not h.aggressive

    def test_aggressive_mode(self):
        h = bhp.BugHunterPro("example.com", mode="aggressive")
        assert h.aggressive

    def test_default_report_formats(self):
        h = bhp.BugHunterPro("example.com")
        assert "json" in h.report_formats
        assert "markdown" in h.report_formats

    def test_usb_defaults(self):
        h = bhp.BugHunterPro("example.com")
        assert h.usb_host is None
        assert h.usb_port == 8080


# ── Subdomain enumeration (mocked DNS) ───────────────────────────────────────

class TestEnumerateSubdomains:
    @patch("BugHunterPro._make_resolver")
    def test_finds_valid_subdomain(self, mock_make):
        mock_resolver = MagicMock()
        mock_answer   = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([MagicMock(__str__=lambda s: "1.2.3.4")]))
        mock_resolver.resolve.return_value = [MagicMock(__str__=lambda s: "1.2.3.4")]
        mock_make.return_value = mock_resolver

        found = bhp.enumerate_subdomains("example.com", aggressive=False)
        assert isinstance(found, list)

    @patch("BugHunterPro._make_resolver")
    def test_ignores_nxdomain(self, mock_make):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN
        mock_make.return_value = mock_resolver

        found = bhp.enumerate_subdomains("example.com")
        assert found == []

    @patch("BugHunterPro._make_resolver")
    def test_retries_on_timeout(self, mock_make):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.exception.Timeout
        mock_make.return_value = mock_resolver

        # Should not raise; just return empty
        found = bhp.enumerate_subdomains("example.com")
        assert found == []

    def test_aggressive_uses_larger_wordlist(self):
        assert len(bhp._SUBS_EXTRA) > len(bhp._SUBS_COMMON)


# ── Port scanning (mocked socket) ────────────────────────────────────────────

class TestScanPorts:
    @patch("socket.gethostbyname", return_value="127.0.0.1")
    @patch("socket.socket")
    def test_detects_open_port(self, mock_socket_cls, mock_resolve):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0   # port open
        mock_socket_cls.return_value = mock_sock

        results = bhp.scan_ports("example.com", aggressive=False)
        assert any(r["state"] == "open" for r in results)

    @patch("socket.gethostbyname", return_value="127.0.0.1")
    @patch("socket.socket")
    def test_ignores_closed_port(self, mock_socket_cls, mock_resolve):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1   # port closed
        mock_socket_cls.return_value = mock_sock

        results = bhp.scan_ports("example.com", aggressive=False)
        assert results == []

    @patch("socket.gethostbyname", side_effect=socket.gaierror("no such host"))
    def test_returns_empty_on_resolve_failure(self, mock_resolve):
        results = bhp.scan_ports("nonexistent.invalid")
        assert results == []

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    @patch("socket.socket")
    def test_known_service_name(self, mock_socket_cls, mock_resolve):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        results = bhp.scan_ports("example.com", aggressive=False)
        port_nums = {r["port"] for r in results}
        for r in results:
            if r["port"] == 22:
                assert r["service"] == "SSH"
            if r["port"] == 80:
                assert r["service"] == "HTTP"

    def test_aggressive_port_list_larger(self):
        assert len(bhp._PORTS_AGGRESSIVE) > len(bhp._PORTS_COMMON)


# ── Security headers ─────────────────────────────────────────────────────────

class TestCheckSecurityHeaders:
    @patch("requests.get")
    def test_flags_missing_headers(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {}   # no headers at all
        mock_get.return_value = mock_resp

        issues = bhp.check_security_headers("http://example.com")
        assert len(issues) == len(bhp._SEC_HEADERS)
        assert all(i["severity"] == "Medium" for i in issues)

    @patch("requests.get")
    def test_no_issues_when_all_present(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {h: "value" for h in bhp._SEC_HEADERS}
        mock_get.return_value = mock_resp

        issues = bhp.check_security_headers("http://example.com")
        assert issues == []

    @patch("requests.get")
    def test_partial_headers(self, mock_get):
        mock_resp = MagicMock()
        present = list(bhp._SEC_HEADERS.keys())[:3]
        mock_resp.headers = {h: "x" for h in present}
        mock_get.return_value = mock_resp

        issues = bhp.check_security_headers("http://example.com")
        assert len(issues) == len(bhp._SEC_HEADERS) - 3


# ── Report generation ─────────────────────────────────────────────────────────

class TestGenerateReports:
    def _sample_report_args(self):
        return dict(
            target="example.com",
            subdomains=[{"host": "www.example.com", "ips": ["1.2.3.4"]}],
            ports=[{"port": 80, "service": "HTTP", "state": "open"}],
            vulns=[{
                "type": "SQL Injection", "severity": "Critical",
                "url": "http://example.com", "parameter": "id",
                "payload": "'", "cvss": 9.8,
            }],
            header_issues=[{
                "header": "X-Frame-Options",
                "severity": "Medium",
                "description": "Missing",
            }],
        )

    def test_creates_json_file(self, tmp_path):
        args = self._sample_report_args()
        report = bhp.generate_reports(**args, output_dir=str(tmp_path))
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 1
        data = json.loads(json_files[0].read_text())
        assert data["meta"]["target"] == "example.com"

    def test_creates_markdown_file(self, tmp_path):
        args = self._sample_report_args()
        bhp.generate_reports(**args, output_dir=str(tmp_path))
        md_files = list(tmp_path.glob("*.md"))
        assert len(md_files) == 1
        text = md_files[0].read_text()
        assert "example.com" in text
        assert "SQL Injection" in text

    def test_summary_counts(self, tmp_path):
        args = self._sample_report_args()
        report = bhp.generate_reports(**args, output_dir=str(tmp_path))
        s = report["summary"]
        assert s["subdomains_found"] == 1
        assert s["open_ports"] == 1
        assert s["vulnerabilities"] == 1
        assert s["critical"] == 1

    def test_html_report_generated(self, tmp_path):
        args = self._sample_report_args()
        bhp.generate_reports(**args, formats=["json", "markdown", "html"],
                             output_dir=str(tmp_path))
        html_files = list(tmp_path.glob("*.html"))
        assert len(html_files) == 1
        assert "example.com" in html_files[0].read_text()

    def test_usb_results_included(self, tmp_path):
        args = self._sample_report_args()
        usb = {"device": {"chipModel": "ESP32", "version": "v1"}, "findings": []}
        report = bhp.generate_reports(**args, usb_results=usb,
                                      output_dir=str(tmp_path))
        assert report["usb_attack"]["device"]["chipModel"] == "ESP32"
