#!/usr/bin/env python3
"""Unit tests for h1_recon_scanner. Network access is limited to 127.0.0.1."""

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))

import h1_recon_scanner as h1

SCRIPT = Path(__file__).parent.parent / "h1_recon_scanner.py"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.server.catch_all:
            status, ctype, body = 200, "text/html", b"<html>anything</html>"
        elif self.path == "/":
            status, ctype, body = 200, "text/html", b"<html>home</html>"
        elif self.path == "/.env":
            status, ctype, body = 200, "text/plain", b"DB_PASSWORD=hunter2\n"
        else:
            status, ctype, body = 404, "text/plain", b"not found"
        self.send_response(status)
        self.send_header("content-type", ctype)
        # Lowercase on purpose: HTTP/2 servers send lowercase header names.
        self.send_header("strict-transport-security", "max-age=31536000")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _start_server(catch_all=False):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.catch_all = catch_all
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class TestArgs(unittest.TestCase):
    def test_threads_parsed(self):
        args = h1.build_parser().parse_args(["-s", "s.txt", "-t", "3"])
        self.assertEqual(args.threads, 3)

    def test_threads_default(self):
        args = h1.build_parser().parse_args(["-s", "s.txt"])
        self.assertEqual(args.threads, 5)

    def test_threads_rejects_zero(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            h1.build_parser().parse_args(["-s", "s.txt", "-t", "0"])

    def test_source_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            h1.build_parser().parse_args(["-d", "example.com"])

    def test_scope_and_program_are_mutually_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            h1.build_parser().parse_args(["-s", "s.txt", "-p", "prog"])

    def test_negative_delay_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            h1.build_parser().parse_args(["-s", "s.txt", "--delay", "-1"])


class TestScopeParsing(unittest.TestCase):
    def test_hostname_wildcard_and_url_forms(self):
        self.assertEqual(h1.parse_scope_identifier("Example.com"), ("example.com", False))
        self.assertEqual(h1.parse_scope_identifier("*.example.com"), ("example.com", True))
        self.assertEqual(h1.parse_scope_identifier("https://app.example.com/login"), ("app.example.com", False))
        self.assertEqual(h1.parse_scope_identifier("api.example.com:8443"), ("api.example.com", False))

    def test_ip_cidr_and_junk_are_not_hostnames(self):
        for bad in ["10.0.0.1", "10.0.0.0/8", "2001:db8::1", "", "# comment", "*example.com", "a b"]:
            self.assertIsNone(h1.parse_scope_identifier(bad), bad)

    def test_parse_identifiers_reports_skipped(self):
        entries, skipped = h1.parse_scope_identifiers(["a.example.com", "10.0.0.0/8", "a.example.com"])
        self.assertEqual(entries, [("a.example.com", False)])
        self.assertEqual(skipped, [{"asset": "10.0.0.0/8", "reason": "not a hostname"}])


class TestScopeFile(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _write(self, text, encoding="utf-8"):
        path = Path(self._tmp.name) / "scope.txt"
        path.write_text(text, encoding=encoding)
        return str(path)

    def test_comments_blank_lines_and_bom(self):
        path = self._write("﻿# program scope\n\nexample.com\n  *.Example.org  \n")
        entries, skipped = h1.load_scope(path)
        self.assertEqual(entries, [("example.com", False), ("example.org", True)])
        self.assertEqual(skipped, [])

    def test_indented_comment_is_ignored(self):
        entries, _ = h1.load_scope(self._write("   # indented comment\nexample.com\n"))
        self.assertEqual(entries, [("example.com", False)])

    def test_missing_file_raises(self):
        with self.assertRaises(h1.ScopeError):
            h1.load_scope(str(Path(self._tmp.name) / "does-not-exist.txt"))


class TestScopeGuard(unittest.TestCase):
    def test_exact_entry_matches_only_that_host(self):
        guard = h1.ScopeGuard([("example.com", False)])
        self.assertTrue(guard.is_in_scope("https://example.com/path"))
        self.assertTrue(guard.is_in_scope("HTTPS://EXAMPLE.COM"))
        self.assertFalse(guard.is_in_scope("https://api.example.com"))
        self.assertFalse(guard.is_in_scope("https://evilexample.com"))

    def test_wildcard_entry_matches_subdomains_but_not_apex(self):
        guard = h1.ScopeGuard([("example.com", True)])
        self.assertTrue(guard.is_in_scope("https://api.example.com"))
        self.assertTrue(guard.is_in_scope("https://a.b.example.com"))
        self.assertFalse(guard.is_in_scope("https://example.com"))
        self.assertFalse(guard.is_in_scope("https://example.com.attacker.net"))
        self.assertFalse(guard.is_in_scope("https://evilexample.com"))

    def test_domains_property_formats_entries(self):
        guard = h1.ScopeGuard([("a.com", False), ("b.com", True)])
        self.assertEqual(guard.domains, ["a.com", "*.b.com"])

    def test_empty_scope_rejected(self):
        with self.assertRaises(h1.ScopeError):
            h1.ScopeGuard([])


class TestRateLimiter(unittest.TestCase):
    def test_zero_interval_does_not_sleep(self):
        limiter = h1.RateLimiter(0)
        start = time.monotonic()
        for _ in range(5):
            limiter.wait()
        self.assertLess(time.monotonic() - start, 0.05)

    def test_interval_spaces_calls_across_threads(self):
        limiter = h1.RateLimiter(0.05)
        stamps = []
        lock = threading.Lock()

        def worker():
            limiter.wait()
            with lock:
                stamps.append(time.monotonic())

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        stamps.sort()
        self.assertGreaterEqual(stamps[-1] - stamps[0], 0.09)


class TestAnalyzeEndpoint(unittest.TestCase):
    def setUp(self):
        self.limiter = h1.RateLimiter(0)

    def _analyze(self, headers):
        ep = {"url": "https://example.com", "headers": headers}
        return h1.analyze_endpoint(ep, self.limiter, skip_sensitive=True)

    def test_lowercase_hsts_header_is_recognised(self):
        findings = self._analyze({
            "strict-transport-security": "max-age=1",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
        })
        self.assertEqual(findings, [])

    def test_missing_headers_are_reported(self):
        details = [f["detail"] for f in self._analyze({})]
        self.assertIn("HSTS Header not enforced", details)
        self.assertIn("Content-Security-Policy (CSP) missing", details)
        self.assertIn("X-Frame-Options missing (Clickjacking vector)", details)

    def test_wildcard_cors_with_credentials_is_high(self):
        findings = self._analyze({
            "strict-transport-security": "max-age=1",
            "content-security-policy": "x",
            "x-frame-options": "DENY",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        })
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "High")


class TestLocalServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base = _start_server()
        cls.catch_all_server, cls.catch_all_base = _start_server(catch_all=True)
        cls.limiter = h1.RateLimiter(0)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.catch_all_server.shutdown()

    def test_probe_returns_lowercase_headers_and_body(self):
        res = h1.probe_url(self.base + "/", self.limiter)
        self.assertEqual(res["status"], 200)
        self.assertEqual(res["headers"]["strict-transport-security"], "max-age=31536000")
        self.assertIn("home", res["body_sample"])

    def test_probe_unreachable_host_reports_no_status(self):
        res = h1.probe_url("http://127.0.0.1:1/", self.limiter)
        self.assertIsNone(res["status"])
        self.assertIn("error", res)

    def test_sensitive_file_is_detected(self):
        ep = h1.probe_url(self.base + "/", self.limiter)
        findings = h1.analyze_endpoint(ep, self.limiter, log=lambda *_: None)
        disclosed = [f["detail"] for f in findings if f["type"] == "Sensitive File Disclosure"]
        self.assertEqual(disclosed, [f"Accessible sensitive resource: {self.base}/.env"])

    def test_catch_all_host_produces_no_sensitive_findings(self):
        ep = h1.probe_url(self.catch_all_base + "/", self.limiter)
        findings = h1.analyze_endpoint(ep, self.limiter, log=lambda *_: None)
        self.assertFalse([f for f in findings if f["type"] == "Sensitive File Disclosure"])


class TestCandidateHosts(unittest.TestCase):
    def setUp(self):
        self.resolved = []
        patcher = mock.patch.object(h1, "resolve_host", side_effect=self._resolve)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _resolve(self, host):
        self.resolved.append(host)
        return "203.0.113.7" if host == "api.example.com" else None

    def test_exact_entries_are_probed_without_dns(self):
        scope = h1.ScopeGuard([("app.example.com", False)])
        hosts = h1._candidate_hosts(scope, None, True, lambda *_: None)
        self.assertEqual(hosts, ["app.example.com"])
        self.assertEqual(self.resolved, [])

    def test_wildcard_base_guesses_only_resolving_subdomains(self):
        scope = h1.ScopeGuard([("example.com", True)])
        hosts = h1._candidate_hosts(scope, None, True, lambda *_: None)
        self.assertEqual(hosts, ["api.example.com"])
        self.assertNotIn("example.com", hosts)

    def test_no_subdomains_flag_disables_guessing(self):
        scope = h1.ScopeGuard([("example.com", True)])
        hosts = h1._candidate_hosts(scope, None, False, lambda *_: None)
        self.assertEqual(hosts, [])
        self.assertEqual(self.resolved, [])

    def test_domain_outside_scope_is_refused(self):
        scope = h1.ScopeGuard([("example.com", False)])
        with self.assertRaises(h1.ScopeError):
            h1._candidate_hosts(scope, "example.org", True, lambda *_: None)

    def test_wildcard_scope_refuses_apex_as_domain(self):
        scope = h1.ScopeGuard([("example.com", True)])
        with self.assertRaises(h1.ScopeError):
            h1._candidate_hosts(scope, "example.com", False, lambda *_: None)


class TestScanAndReport(unittest.TestCase):
    def test_scan_refuses_domain_outside_scope_without_network(self):
        scope = h1.ScopeGuard([("example.com", False)])
        with mock.patch.object(h1, "probe_url") as probe:
            with self.assertRaises(h1.ScopeError):
                h1.scan(scope, domain="example.org", subdomains=False, log=lambda *_: None)
        probe.assert_not_called()

    def test_markdown_lists_findings_and_scope(self):
        report = {
            "target": "example.com",
            "timestamp": "2024-01-01T00:00:00",
            "scope_domains": ["example.com", "*.example.com"],
            "total_live_endpoints": 1,
            "total_findings": 1,
            "endpoints": [{
                "url": "https://example.com", "status": 200, "server": "nginx",
                "vulnerabilities": [{"type": "Sensitive File Disclosure", "severity": "High",
                                     "detail": "Accessible sensitive resource: https://example.com/.env"}],
            }],
        }
        md = h1.render_markdown(report)
        self.assertIn("**[High] Sensitive File Disclosure**", md)
        self.assertIn("- `*.example.com`", md)
        self.assertIn("| https://example.com | 200 | nginx |", md)
        self.assertIn("Verify every finding manually", md)


class TestCli(unittest.TestCase):
    def test_cli_requires_source(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "-d", "example.com"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--program", proc.stderr)

    def test_cli_rejects_missing_scope_file(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "-s", "/nonexistent/scope.txt"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("cannot read scope file", proc.stderr)

    def test_program_mode_without_credentials_fails_closed(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            rc = h1.main(["-p", "example-program"])
        self.assertEqual(rc, 2)
        self.assertIn("H1_API_USERNAME", err.getvalue())

    def test_program_mode_uses_api_scope_and_writes_reports(self):
        from h1_api import HackerOneClient
        items = [
            {"attributes": {"asset_identifier": "*.example.com", "asset_type": "WILDCARD",
                            "eligible_for_submission": True}},
            {"attributes": {"asset_identifier": "10.0.0.0/8", "asset_type": "CIDR",
                            "eligible_for_submission": True}},
        ]
        captured = {}

        def fake_scan(scope, **kwargs):
            captured["domains"] = scope.domains
            captured.update(kwargs)
            return {"target": "example-program", "program": "example-program",
                    "timestamp": "t", "scope_domains": scope.domains, "skipped_scope_items": [],
                    "delay_seconds": 0, "total_live_endpoints": 0, "total_findings": 0,
                    "endpoints": []}

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.json")
            fake_client = mock.Mock()
            fake_client.get_structured_scopes.return_value = items
            with mock.patch.object(HackerOneClient, "from_env", return_value=fake_client), \
                    mock.patch.object(h1, "scan", side_effect=fake_scan), \
                    contextlib.redirect_stdout(io.StringIO()):
                rc = h1.main(["-p", "example-program", "-o", out])
            self.assertEqual(rc, 0)
            self.assertEqual(captured["domains"], ["*.example.com"])
            self.assertEqual(captured["program"], "example-program")
            self.assertTrue(os.path.exists(out))
            self.assertTrue(os.path.exists(os.path.join(tmp, "report.md")))


if __name__ == "__main__":
    unittest.main()
