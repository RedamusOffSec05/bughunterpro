#!/usr/bin/env python3
"""Unit tests for h1_recon_scanner. Network access is limited to 127.0.0.1."""

import contextlib
import io
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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
        args = h1.build_parser().parse_args(["-d", "x.com", "-s", "s.txt", "-t", "3"])
        self.assertEqual(args.threads, 3)

    def test_threads_default(self):
        args = h1.build_parser().parse_args(["-d", "x.com", "-s", "s.txt"])
        self.assertEqual(args.threads, 5)

    def test_threads_rejects_zero(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            h1.build_parser().parse_args(["-d", "x.com", "-s", "s.txt", "-t", "0"])

    def test_scope_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            h1.build_parser().parse_args(["-d", "x.com"])

    def test_negative_delay_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            h1.build_parser().parse_args(["-d", "x.com", "-s", "s.txt", "--delay", "-1"])


class TestScope(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _write(self, text, encoding="utf-8"):
        path = Path(self._tmp.name) / "scope.txt"
        path.write_text(text, encoding=encoding)
        return str(path)

    def test_load_scope_handles_comments_wildcards_and_bom(self):
        path = self._write("﻿# program scope\n\nexample.com\n  *.Example.org  \n")
        self.assertEqual(h1.load_scope(path), ["example.com", "example.org"])

    def test_load_scope_indented_comment_is_ignored(self):
        path = self._write("   # indented comment\nexample.com\n")
        self.assertEqual(h1.load_scope(path), ["example.com"])

    def test_load_scope_empty_file_raises(self):
        with self.assertRaises(h1.ScopeError):
            h1.load_scope(self._write("# nothing here\n\n"))

    def test_load_scope_missing_file_raises(self):
        with self.assertRaises(h1.ScopeError):
            h1.load_scope(str(Path(self._tmp.name) / "does-not-exist.txt"))

    def test_scope_guard_matches_exact_and_subdomains_only(self):
        guard = h1.ScopeGuard(["example.com"])
        self.assertTrue(guard.is_in_scope("https://example.com/path"))
        self.assertTrue(guard.is_in_scope("https://api.example.com"))
        self.assertTrue(guard.is_in_scope("HTTPS://API.EXAMPLE.COM"))
        self.assertFalse(guard.is_in_scope("https://evilexample.com"))
        self.assertFalse(guard.is_in_scope("https://example.com.attacker.net"))
        self.assertFalse(guard.is_in_scope("https://other.org"))

    def test_scope_guard_rejects_empty_scope(self):
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


class TestScanGuard(unittest.TestCase):
    def test_scan_refuses_root_domain_outside_scope(self):
        guard = h1.ScopeGuard(["example.com"])
        with self.assertRaises(h1.ScopeError):
            h1.scan("example.org", guard, subdomains=False, log=lambda *_: None)

    def test_cli_requires_scope_argument(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "-d", "example.com"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--scope", proc.stderr)

    def test_cli_rejects_missing_scope_file(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "-d", "example.com", "-s", "/nonexistent/scope.txt"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("cannot read scope file", proc.stderr)


if __name__ == "__main__":
    unittest.main()
