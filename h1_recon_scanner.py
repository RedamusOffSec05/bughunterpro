#!/usr/bin/env python3
"""
Bug Hunter Pro - HackerOne-scoped recon and misconfiguration checker.

Safety properties:
  * Requires a scope file and fails closed: a root domain outside the scope
    aborts the run, and out-of-scope subdomains are never requested.
  * Every request goes through one shared RateLimiter, so --delay is the
    minimum spacing between requests across all threads.
  * Read-only: GET requests only, no payloads, no exploitation.
"""

import argparse
import concurrent.futures
import json
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from urllib.parse import urljoin, urlparse

USER_AGENT = "Mozilla/5.0 (BugHunterPro-H1Research/2.0; Bug Bounty Security Assessment)"
REQUEST_TIMEOUT = 6
BODY_SAMPLE_BYTES = 2048

SUBDOMAIN_PREFIXES = [
    "www", "api", "admin", "test", "staging", "dev", "auth", "login",
    "portal", "dashboard", "shop", "blog", "app", "git", "status",
    "support", "help", "docs", "internal", "vpn", "mail", "smtp",
]

# (path, severity, predicate on the response body). The predicate stops a
# generic 200 page from being reported as a leaked file.
SENSITIVE_PATHS = [
    (".git/config", "High", lambda body: "[core]" in body),
    (".env", "High", lambda body: "=" in body and "<html" not in body.lower()),
    ("backup.zip", "High", lambda body: body.startswith("PK")),
    ("config.json", "High", lambda body: body.lstrip().startswith(("{", "["))),
    ("swagger.json", "Medium", lambda body: '"swagger"' in body or '"openapi"' in body),
    ("api/v1/docs", "Low", lambda body: bool(body.strip())),
]


class ScopeError(Exception):
    """Raised when the scope file is unusable or a target is out of scope."""


class RateLimiter:
    """Spaces requests at least `interval` seconds apart across all threads."""

    def __init__(self, interval):
        self.interval = interval
        self._lock = threading.Lock()
        self._next_slot = 0.0

    def wait(self):
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self.interval
        if slot > now:
            time.sleep(slot - now)


def load_scope(path):
    """Return the in-scope domains from a scope file.

    Accepts one domain per line, '#' comments, blank lines, a UTF-8 BOM and
    '*.example.com' wildcards. Raises ScopeError if the file is unreadable or
    contains no domains.
    """
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            lines = f.readlines()
    except OSError as e:
        raise ScopeError(f"cannot read scope file {path!r}: {e}") from e

    domains = []
    for raw in lines:
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*."):
            line = line[2:]
        domains.append(line)

    if not domains:
        raise ScopeError(f"scope file {path!r} contains no domains")
    return domains


class ScopeGuard:
    def __init__(self, domains):
        if not domains:
            raise ScopeError("no scope domains provided")
        self.domains = list(domains)

    def is_in_scope(self, target):
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        return any(host == d or host.endswith("." + d) for d in self.domains)


def enumerate_subdomains(domain):
    found = []
    for prefix in SUBDOMAIN_PREFIXES:
        sub = f"{prefix}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
        except socket.gaierror:
            continue
        found.append({"subdomain": sub, "ip": ip})
    return found


def _lower_headers(headers):
    # HTTP/2 servers send lowercase names, so normalise once for every lookup.
    return {k.lower(): v for k, v in headers.items()}


def _build_request(url, limiter):
    limiter.wait()
    return urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")


def probe_url(url, limiter):
    if not url.startswith("http"):
        url = f"https://{url}"
    req = _build_request(url, limiter)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            body = resp.read(BODY_SAMPLE_BYTES).decode("utf-8", errors="ignore")
            return {
                "url": url,
                "status": resp.status,
                "server": resp.headers.get("Server", "Unknown"),
                "content_type": resp.headers.get("Content-Type", "Unknown"),
                "latency": round(time.monotonic() - start, 3),
                "headers": _lower_headers(resp.headers),
                "body_sample": body,
            }
    except urllib.error.HTTPError as e:
        return {
            "url": url,
            "status": e.code,
            "server": e.headers.get("Server", "Unknown"),
            "headers": _lower_headers(e.headers),
            "error": str(e),
        }
    except Exception as e:
        return {"url": url, "status": None, "error": str(e)}


def _fetch_status_body(url, limiter):
    req = _build_request(url, limiter)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.status, resp.read(BODY_SAMPLE_BYTES).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""


def check_sensitive_paths(base_origin, limiter, log=print):
    # Hosts that answer 200 to everything would flag every path, so probe a
    # random path first and skip the host if it looks like a catch-all.
    baseline_url = urljoin(base_origin + "/", f"bhp-{secrets.token_hex(8)}")
    baseline_status, _ = _fetch_status_body(baseline_url, limiter)
    if baseline_status == 200:
        log(f"    [-] {base_origin} answers 200 to random paths; skipping sensitive-file checks")
        return []

    findings = []
    for path, severity, looks_real in SENSITIVE_PATHS:
        test_url = urljoin(base_origin + "/", path)
        status, body = _fetch_status_body(test_url, limiter)
        if status == 200 and looks_real(body):
            findings.append({
                "type": "Sensitive File Disclosure",
                "severity": severity,
                "detail": f"Accessible sensitive resource: {test_url}",
            })
    return findings


def analyze_endpoint(endpoint, limiter, skip_sensitive=False, log=print):
    findings = []
    hdrs = endpoint.get("headers", {})  # keys are lowercase, see _lower_headers

    # 1. Security headers
    if "strict-transport-security" not in hdrs:
        findings.append({"type": "Missing Security Header", "severity": "Low",
                         "detail": "HSTS Header not enforced"})
    if "content-security-policy" not in hdrs:
        findings.append({"type": "Missing Security Header", "severity": "Medium",
                         "detail": "Content-Security-Policy (CSP) missing"})
    if "x-frame-options" not in hdrs:
        findings.append({"type": "Missing Security Header", "severity": "Low",
                         "detail": "X-Frame-Options missing (Clickjacking vector)"})

    # 2. CORS
    acao = hdrs.get("access-control-allow-origin", "").strip()
    acac = hdrs.get("access-control-allow-credentials", "").strip().lower()
    if acao == "*" and acac == "true":
        findings.append({"type": "CORS Misconfiguration", "severity": "High",
                         "detail": "Wildcard ACAO with Credentials enabled"})
    elif acao == "*":
        findings.append({"type": "CORS Misconfiguration", "severity": "Low",
                         "detail": "Wildcard Access-Control-Allow-Origin"})

    # 3. Sensitive files, relative to the endpoint's origin
    if not skip_sensitive:
        parsed = urlparse(endpoint["url"])
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        findings.extend(check_sensitive_paths(base_origin, limiter, log=log))

    return findings


def scan(domain, scope, threads=5, delay=0.2, skip_sensitive=False,
         subdomains=True, log=print):
    if not scope.is_in_scope(f"https://{domain}"):
        raise ScopeError(f"root domain {domain!r} is not covered by the scope file")

    limiter = RateLimiter(delay)

    hosts = [domain]
    if subdomains:
        log(f"[*] Subdomain recon for {domain} ({len(SUBDOMAIN_PREFIXES)} prefixes)")
        for item in enumerate_subdomains(domain):
            log(f"    [+] Discovered subdomain: {item['subdomain']} -> {item['ip']}")
            hosts.append(item["subdomain"])

    targets = []
    for host in hosts:
        url = f"https://{host}"
        if scope.is_in_scope(url):
            targets.append(url)
        else:
            log(f"    [-] Out of scope, skipped: {host}")
    log(f"[*] Scope check passed: {len(targets)}/{len(hosts)} hosts in scope")

    log(f"[*] Probing {len(targets)} endpoints (threads={threads}, delay={delay}s)")
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(probe_url, t, limiter) for t in targets]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res.get("status"):
                live.append(res)
                log(f"    [+] LIVE: {res['url']} [Status: {res['status']}] [Server: {res['server']}]")

    log("[*] Analyzing live endpoints for security misconfigurations & exposures...")
    total_findings = 0
    report_endpoints = []
    for ep in sorted(live, key=lambda e: e["url"]):
        vulns = analyze_endpoint(ep, limiter, skip_sensitive=skip_sensitive, log=log)
        ep.pop("body_sample", None)
        ep["vulnerabilities"] = vulns
        report_endpoints.append(ep)
        if vulns:
            total_findings += len(vulns)
            log(f"    [!] {len(vulns)} finding(s) on {ep['url']}")
            for v in vulns:
                log(f"        -> [{v['severity']}] {v['type']}: {v['detail']}")

    return {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "scope_domains": scope.domains,
        "delay_seconds": delay,
        "total_live_endpoints": len(live),
        "total_findings": total_findings,
        "endpoints": report_endpoints,
    }


def positive_int(value):
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def non_negative_float(value):
    x = float(value)
    if x < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return x


def build_parser():
    parser = argparse.ArgumentParser(description="Bug Hunter Pro - HackerOne Compliant Automation Suite")
    parser.add_argument("-d", "--domain", required=True,
                        help="Target root domain (e.g., target-program.com)")
    parser.add_argument("-s", "--scope", required=True,
                        help="HackerOne scope file, one domain per line ('#' comments and "
                             "'*.example.com' allowed). Required: the scan refuses to run without it.")
    parser.add_argument("-o", "--output", default="h1_bug_report.json",
                        help="Output JSON report filename")
    parser.add_argument("-t", "--threads", type=positive_int, default=5,
                        help="Concurrent probe threads (default: 5)")
    parser.add_argument("--delay", type=non_negative_float, default=0.2,
                        help="Minimum seconds between requests, shared across all threads (default: 0.2)")
    parser.add_argument("--no-subdomains", action="store_true",
                        help="Skip subdomain guessing and scan only the root domain")
    parser.add_argument("--skip-sensitive", action="store_true",
                        help="Skip the sensitive file/path probes")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    print("=" * 70)
    print("       Bug Hunter Pro - HackerOne Authorized Automation Suite       ")
    print("       Safe Harbor Compliant Recon & Vulnerability Scanner         ")
    print("=" * 70)

    try:
        scope = ScopeGuard(load_scope(args.scope))
        report = scan(
            args.domain,
            scope,
            threads=args.threads,
            delay=args.delay,
            skip_sensitive=args.skip_sensitive,
            subdomains=not args.no_subdomains,
        )
    except ScopeError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print("=" * 70)
    print("[*] Scan Completed Successfully!")
    print(f"[*] Total Live Endpoints: {report['total_live_endpoints']}")
    print(f"[*] Total Security Findings: {report['total_findings']}")
    print(f"[*] Full JSON Report Saved To: {args.output}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
