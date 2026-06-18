"""Tests for reporter.py HTML report generation."""

import pytest

from reporter import generate_html


def _make_report(**overrides):
    base = {
        "meta": {
            "tool": "BugHunterPro",
            "version": "1.3.0",
            "target": "example.com",
            "theme": "miasma",
        },
        "summary": {
            "subdomains_found": 2,
            "open_ports": 3,
            "vulnerabilities": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "usb_findings": 0,
        },
        "subdomains": [
            {"host": "www.example.com",  "ips": ["1.2.3.4"]},
            {"host": "mail.example.com", "ips": ["1.2.3.5"]},
        ],
        "open_ports": [
            {"port": 22,  "service": "SSH",   "state": "open"},
            {"port": 80,  "service": "HTTP",  "state": "open"},
            {"port": 443, "service": "HTTPS", "state": "open"},
        ],
        "vulnerabilities": [{
            "type": "SQL Injection", "severity": "Critical",
            "url": "http://example.com", "parameter": "id",
            "payload": "'", "cvss": 9.8,
        }],
        "header_issues": [
            {"header": "Content-Security-Policy", "severity": "Medium",
             "description": "CSP missing"},
        ],
        "usb_attack": {},
    }
    base.update(overrides)
    return base


class TestGenerateHtml:
    def test_creates_html_file(self, tmp_path):
        path = generate_html(_make_report(), output_dir=str(tmp_path))
        assert path.endswith(".html")
        from pathlib import Path
        assert Path(path).exists()

    def test_contains_target(self, tmp_path):
        path = generate_html(_make_report(), output_dir=str(tmp_path))
        from pathlib import Path
        html = Path(path).read_text()
        assert "example.com" in html

    def test_contains_severity_badge(self, tmp_path):
        path = generate_html(_make_report(), output_dir=str(tmp_path))
        from pathlib import Path
        html = Path(path).read_text()
        assert "Critical" in html

    def test_contains_subdomain(self, tmp_path):
        path = generate_html(_make_report(), output_dir=str(tmp_path))
        from pathlib import Path
        html = Path(path).read_text()
        assert "www.example.com" in html

    def test_contains_open_port(self, tmp_path):
        path = generate_html(_make_report(), output_dir=str(tmp_path))
        from pathlib import Path
        html = Path(path).read_text()
        assert "22/tcp" in html or "22" in html

    def test_missing_header_shown(self, tmp_path):
        path = generate_html(_make_report(), output_dir=str(tmp_path))
        from pathlib import Path
        html = Path(path).read_text()
        assert "missing" in html.lower()

    def test_usb_section_present_when_device(self, tmp_path):
        report = _make_report(usb_attack={
            "device": {
                "chipModel": "ESP32-S3", "version": "v1.1.5",
                "USBmode": "HID", "agentConnected": True,
                "machineName": "VICTIM-PC", "capabilities": ["HID", "WIFI"],
            },
            "findings": [],
            "wifi_aps": [],
            "payloads_run": ["recon_windows"],
        })
        path = generate_html(report, output_dir=str(tmp_path))
        from pathlib import Path
        html = Path(path).read_text()
        assert "ESP32-S3" in html
        assert "recon_windows" in html

    def test_empty_report_does_not_raise(self, tmp_path):
        minimal = {
            "meta": {"tool": "BugHunterPro", "version": "?",
                     "target": "test.com", "theme": "miasma"},
            "summary": {},
            "subdomains": [], "open_ports": [],
            "vulnerabilities": [], "header_issues": [], "usb_attack": {},
        }
        path = generate_html(minimal, output_dir=str(tmp_path))
        assert path.endswith(".html")

    def test_chart_js_included(self, tmp_path):
        path = generate_html(_make_report(), output_dir=str(tmp_path))
        from pathlib import Path
        html = Path(path).read_text()
        assert "chart.js" in html.lower()

    def test_miasma_css_colors_present(self, tmp_path):
        path = generate_html(_make_report(), output_dir=str(tmp_path))
        from pathlib import Path
        html = Path(path).read_text()
        assert "#d7c483" in html    # miasma foreground
        assert "#5f875f" in html    # miasma green
