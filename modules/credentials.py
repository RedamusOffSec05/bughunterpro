#!/usr/bin/env python3
"""
Credential testing module for BugHunterPro.

Tests common credentials against SSH (via paramiko), FTP (ftplib),
and HTTP Basic Auth / web login forms.  All attempts are rate-limited
by a TokenBucket to avoid account lockout and detection.

paramiko is optional — SSH testing degrades gracefully without it.
"""

import ftplib

import requests
import urllib3

from modules.base import BaseModule
from BugHunterPro import M, info, success, warn, error, section, vuln
from ratelimit import TokenBucket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import paramiko
    _PARAMIKO_OK = True
except ImportError:
    _PARAMIKO_OK = False

# Built-in credential wordlist (extend via config["wordlist"])
_DEFAULT_CREDS = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "admin123"),
    ("admin",         ""),
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "password"),
    ("root",          ""),
    ("user",          "user"),
    ("user",          "password"),
    ("guest",         "guest"),
    ("test",          "test"),
    ("administrator", "administrator"),
    ("admin",         "1234"),
    ("admin",         "12345"),
    ("pi",            "raspberry"),
    ("ubuntu",        "ubuntu"),
    ("postgres",      "postgres"),
    ("mysql",         "mysql"),
    ("oracle",        "oracle"),
]


class CredentialModule(BaseModule):
    name        = "credentials"
    description = "Tests common credentials against SSH, FTP, and web login forms"

    def __init__(self, config=None):
        super().__init__(config)
        self.wordlist = self.config.get("wordlist") or _DEFAULT_CREDS
        rate          = float(self.config.get("rate", 2.0))
        self._bucket  = TokenBucket(rate=rate, capacity=rate * 3)

    def run(self, target: str) -> list:
        findings = []
        open_ports = {p["port"] for p in self.config.get("open_ports", [])}

        section(f"Credential Testing — {target}")

        if 22 in open_ports:
            findings += self._ssh(target)

        if 21 in open_ports:
            findings += self._ftp(target)

        findings += self._http_basic(target, open_ports)

        return findings

    # ── SSH ──────────────────────────────────────────────────────────────────
    def _ssh(self, host, port=22):
        if not _PARAMIKO_OK:
            warn("SSH check skipped — pip install paramiko")
            return []

        section(f"SSH Credentials — {host}:{port}")
        findings = []

        for username, password in self.wordlist:
            self._bucket.acquire()
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(host, port=port, username=username, password=password,
                          timeout=5, look_for_keys=False, allow_agent=False)
                c.close()
                findings.append({
                    "type":     "SSH Valid Credential",
                    "severity": "Critical",
                    "detail":   f"Valid SSH login {username}:{password} at {host}:{port}",
                    "host": host, "port": port,
                    "username": username, "password": password,
                    "cvss": 9.8,
                })
                vuln(f"SSH valid: {username}:{password} @ {host}:{port}")
            except paramiko.AuthenticationException:
                pass
            except Exception as exc:
                self.errors.append(f"SSH connect error {host}: {exc}")
                break  # service unreachable; stop trying

        if not findings:
            success(f"No valid SSH credentials found on {host}:{port}")
        return findings

    # ── FTP ──────────────────────────────────────────────────────────────────
    def _ftp(self, host, port=21):
        section(f"FTP Credentials — {host}:{port}")
        findings = []

        # Check anonymous first
        self._bucket.acquire()
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login()
            files = ftp.nlst()[:10]
            ftp.quit()
            findings.append({
                "type":     "Anonymous FTP Access",
                "severity": "High",
                "detail":   f"Anonymous FTP login allowed on {host}:{port}",
                "host": host, "port": port,
                "files": files, "cvss": 7.5,
            })
            vuln(f"Anonymous FTP allowed @ {host}:{port}  files: {files[:3]}")
        except ftplib.error_perm:
            pass
        except Exception as exc:
            self.errors.append(f"FTP connect {host}: {exc}")
            return findings

        for username, password in self.wordlist[:15]:
            self._bucket.acquire()
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=5)
                ftp.login(username, password)
                ftp.quit()
                findings.append({
                    "type":     "FTP Valid Credential",
                    "severity": "High",
                    "detail":   f"Valid FTP login {username}:{password} at {host}:{port}",
                    "host": host, "port": port,
                    "username": username, "password": password, "cvss": 7.5,
                })
                vuln(f"FTP valid: {username}:{password} @ {host}:{port}")
            except ftplib.error_perm:
                pass
            except Exception:
                break

        if not findings:
            success(f"No valid FTP credentials found on {host}:{port}")
        return findings

    # ── HTTP Basic Auth ───────────────────────────────────────────────────────
    def _http_basic(self, target, open_ports):
        findings = []
        proto = "https" if 443 in open_ports else "http"
        port  = 443 if 443 in open_ports else 80
        url   = f"{proto}://{target}"

        section(f"HTTP Basic Auth — {url}")

        # Only attempt if the server actually returns 401
        try:
            probe = requests.get(url, timeout=5, verify=False)
            if probe.status_code != 401:
                info("Server does not use HTTP Basic Auth — skipping")
                return findings
        except requests.RequestException as exc:
            self.errors.append(f"HTTP probe failed: {exc}")
            return findings

        for username, password in self.wordlist:
            self._bucket.acquire()
            try:
                resp = requests.get(url, auth=(username, password),
                                    timeout=5, verify=False)
                if resp.status_code == 200:
                    findings.append({
                        "type":     "HTTP Basic Auth Valid Credential",
                        "severity": "Critical",
                        "detail":   f"Valid Basic Auth {username}:{password} at {url}",
                        "url":      url,
                        "username": username, "password": password,
                        "cvss":     9.0,
                    })
                    vuln(f"HTTP Basic Auth valid: {username}:{password} @ {url}")
                    break
            except requests.RequestException as exc:
                self.errors.append(f"HTTP auth attempt error: {exc}")
                break

        if not findings:
            success(f"No valid HTTP Basic Auth credentials found for {url}")
        return findings
