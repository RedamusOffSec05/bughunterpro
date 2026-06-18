#!/usr/bin/env python3
"""
Passive and active reconnaissance module for BugHunterPro.

Capabilities
------------
PassiveReconModule
  - Full DNS record set  (A, AAAA, MX, TXT, NS, SOA, CNAME)
  - DNS zone transfer attempt against every nameserver
  - WHOIS lookup (requires python-whois; degrades gracefully)
  - Reverse DNS (PTR)

BannerGrabModule
  - TCP banner grabbing from a supplied port list
  - Version disclosure detection in FTP, SSH, HTTP banners
"""

import socket

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from modules.base import BaseModule
from BugHunterPro import M, info, success, warn, error, section

try:
    import whois as _whois
    _WHOIS_OK = True
except ImportError:
    _WHOIS_OK = False

_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]


class PassiveReconModule(BaseModule):
    name        = "passive_recon"
    description = "DNS records, zone transfer, WHOIS, reverse DNS"

    def run(self, target: str) -> list:
        findings = []
        section("Passive Reconnaissance")
        findings += self._dns_records(target)
        findings += self._zone_transfer(target)
        findings += self._whois(target)
        findings += self._reverse_dns(target)
        return findings

    # ── DNS records ──────────────────────────────────────────────────────────
    def _dns_records(self, domain):
        findings = []
        section(f"DNS Records — {domain}")
        resolver          = dns.resolver.Resolver()
        resolver.lifetime = 5.0

        for rtype in _DNS_RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                records = [str(r) for r in answers]
                success(f"{rtype:<6} {', '.join(records)}")
                findings.append({
                    "type":     f"DNS Record ({rtype})",
                    "severity": "Info",
                    "detail":   f"{domain} {rtype}: {', '.join(records)}",
                    "records":  records,
                })
                if rtype == "TXT":
                    for rec in records:
                        if "v=spf1" in rec.lower():
                            info(f"  → SPF policy: {rec[:80]}")
                        if "v=dmarc1" in rec.lower():
                            info(f"  → DMARC policy found")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except dns.exception.Timeout:
                self.errors.append(f"DNS {rtype} timeout for {domain}")
            except Exception as exc:
                self.errors.append(f"DNS {rtype} error: {exc}")

        return findings

    # ── Zone transfer ─────────────────────────────────────────────────────────
    def _zone_transfer(self, domain):
        findings = []
        section(f"Zone Transfer — {domain}")

        try:
            ns_answers = dns.resolver.resolve(domain, "NS")
            nameservers = [str(r).rstrip(".") for r in ns_answers]
        except Exception as exc:
            self.errors.append(f"NS lookup failed: {exc}")
            return findings

        for ns in nameservers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                records = sorted(str(n) for n in zone.nodes)
                findings.append({
                    "type":        "DNS Zone Transfer Allowed",
                    "severity":    "Critical",
                    "detail":      f"AXFR succeeded from {ns} — {len(records)} records exposed",
                    "nameserver":  ns,
                    "records":     records,
                    "cvss":        7.5,
                })
                warn(f"Zone transfer allowed by {ns} ({len(records)} records)")
                for r in records[:15]:
                    info(f"  {M.GRAY}{r}")
                return findings
            except Exception:
                success(f"Zone transfer refused by {ns}")

        return findings

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    def _whois(self, domain):
        findings = []
        if not _WHOIS_OK:
            warn("WHOIS skipped — install python-whois (pip install python-whois)")
            return findings

        section(f"WHOIS — {domain}")
        try:
            w = _whois.whois(domain)
            info(f"Registrar : {w.registrar or 'unknown'}")
            info(f"Created   : {w.creation_date}")
            info(f"Expires   : {w.expiration_date}")
            info(f"Org       : {w.org or w.registrant_name or 'redacted'}")
            findings.append({
                "type":      "WHOIS",
                "severity":  "Info",
                "detail":    f"Registered via {w.registrar}",
                "registrar": str(w.registrar),
                "created":   str(w.creation_date),
                "expires":   str(w.expiration_date),
                "org":       str(w.org or w.registrant_name or "redacted"),
            })
        except Exception as exc:
            self.errors.append(f"WHOIS error: {exc}")

        return findings

    # ── Reverse DNS ───────────────────────────────────────────────────────────
    def _reverse_dns(self, domain):
        findings = []
        section(f"Reverse DNS — {domain}")
        try:
            ip       = socket.gethostbyname(domain)
            hostname = socket.gethostbyaddr(ip)[0]
            info(f"{domain} → {ip} → {hostname}")
            findings.append({
                "type":     "Reverse DNS",
                "severity": "Info",
                "detail":   f"{ip} reverse resolves to {hostname}",
                "ip":       ip,
                "reverse":  hostname,
            })
        except Exception as exc:
            self.errors.append(f"Reverse DNS error: {exc}")

        return findings


# ── Banner grabbing ───────────────────────────────────────────────────────────
_PROBES = {
    21:   b"",
    22:   b"",
    25:   b"EHLO bhp\r\n",
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:  b"",
    143:  b"",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
}

_VERSION_PATTERNS = {
    "Apache":  ("apache/", "Web Server Version Disclosed", "Medium"),
    "nginx":   ("nginx/",  "Web Server Version Disclosed", "Medium"),
    "IIS":     ("iis/",    "Web Server Version Disclosed", "Medium"),
    "OpenSSH": ("openssh", "SSH Version Disclosed",        "Low"),
    "ProFTPD": ("proftpd", "FTP Server Version Disclosed", "Low"),
    "vsftpd":  ("vsftpd",  "FTP Server Version Disclosed", "Low"),
}


class BannerGrabModule(BaseModule):
    name        = "banner_grab"
    description = "Service banner grabbing and version disclosure detection"

    def run(self, target: str) -> list:
        findings = []
        section(f"Banner Grabbing — {target}")

        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror as exc:
            self.errors.append(f"Cannot resolve {target}: {exc}")
            return findings

        ports = self.config.get("open_ports", list(_PROBES.keys()))

        for port in ports:
            banner = self._grab(target_ip, port)
            if not banner:
                continue

            info(f"Port {port:5d}: {banner[:80]}")
            findings.append({
                "type":     "Service Banner",
                "severity": "Info",
                "detail":   f"Port {port}: {banner[:200]}",
                "port":     port,
                "banner":   banner,
            })

            low = banner.lower()
            for label, (pattern, ftype, sev) in _VERSION_PATTERNS.items():
                if pattern in low:
                    findings.append({
                        "type":     ftype,
                        "severity": sev,
                        "detail":   f"{label} version in banner on port {port}: {banner[:100]}",
                        "port":     port,
                        "banner":   banner,
                    })
                    warn(f"{ftype}: {banner[:80]}")
                    break

        return findings

    def _grab(self, host, port, timeout=3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            probe = _PROBES.get(port, b"")
            if probe:
                s.sendall(probe)
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            s.close()
            return banner
        except Exception:
            return ""
