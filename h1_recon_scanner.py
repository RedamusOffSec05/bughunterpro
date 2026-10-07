#!/usr/bin/env python3
"""
Bug Hunter Pro - HackerOne-scoped recon and misconfiguration checker.

Scope comes from one of two places:
  * --program HANDLE  pulls the structured scope from the HackerOne Hacker API
                      (credentials from H1_API_USERNAME / H1_API_TOKEN)
  * --scope FILE      reads a local list of hostnames

Scope matching follows HackerOne semantics: "*.example.com" covers subdomains
only, and "example.com" covers that exact host.

Safety properties:
  * Fails closed: no usable scope means no scan, and a root domain outside the
    scope aborts the run. Out-of-scope hosts are never requested.
  * Every target request goes through one RateLimiter, so --delay is the
    minimum spacing between requests across all threads.
  * Read-only: GET requests only, no payloads, no exploitation.
  * Nothing is submitted to HackerOne. Findings are written to a report for
    manual verification first.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from urllib.parse import urljoin, urlparse

from h1_api import TOKEN_ENV, USERNAME_ENV, HackerOneClient, HackerOneError, scope_identifiers

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

SEVERITY_ORDER = ("High", "Medium", "Low", "Info")


class ScopeError(Exception):
    """Raised when the scope is unusable or a target is out of scope."""


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


def parse_scope_identifier(identifier):
    """Turn one scope identifier into (hostname, is_wildcard).

    Accepts hostnames, "*.hostname" wildcards and URLs. Returns None for
    anything that is not a hostname, such as IP addresses and CIDR ranges,
    because this tool only probes by name.
    """
    text = (identifier or "").strip().lower()
    if not text or text.startswith("#"):
        return None
    if "://" in text:
        host = urlparse(text).hostname or ""
    else:
        if _is_ip_literal(text.split("/", 1)[0].strip("[]")):
            return None
        host = text.split("/", 1)[0].split(":", 1)[0]
    host = host.rstrip(".")
    wildcard = host.startswith("*.")
    if wildcard:
        host = host[2:]
    if not host or "*" in host or " " in host or _is_ip_literal(host):
        return None
    return host, wildcard


def _is_ip_literal(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def parse_scope_identifiers(identifiers):
    """Return (entries, skipped_identifiers) for a list of scope identifiers."""
    entries = []
    skipped = []
    for ident in identifiers:
        entry = parse_scope_identifier(ident)
        if entry is None:
            skipped.append({"asset": ident, "reason": "not a hostname"})
        elif entry not in entries:
            entries.append(entry)
    return entries, skipped


def format_entry(entry):
    host, wildcard = entry
    return f"*.{host}" if wildcard else host


def load_scope(path):
    """Read a scope file. Returns (entries, skipped).

    One entry per line. '#' starts a comment, and a UTF-8 BOM is accepted.
    """
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except OSError as e:
        raise ScopeError(f"cannot read scope file {path!r}: {e}") from e
    return parse_scope_identifiers(lines)


def _host_of(target):
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return (parsed.hostname or "").lower().rstrip(".")


class ScopeGuard:
    def __init__(self, entries):
        entries = list(entries)
        if not entries:
            raise ScopeError("the scope contains no hostnames to test")
        self.entries = entries

    @property
    def domains(self):
        return [format_entry(e) for e in self.entries]

    def is_in_scope(self, target):
        host = _host_of(target)
        if not host:
            return False
        for base, wildcard in self.entries:
            if wildcard and host.endswith("." + base):
                return True
            if not wildcard and host == base:
                return True
        return False


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


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


def _candidate_hosts(scope, domain, subdomains, log):
    """Return the hostnames to probe, in scope and in a stable order."""
    candidates = []

    def add(host):
        if host not in candidates:
            candidates.append(host)

    if domain:
        if not scope.is_in_scope(domain):
            raise ScopeError(f"root domain {domain!r} is not covered by the scope")
        add(domain)

    # Exact hostnames in scope are authorised as-is.
    for base, wildcard in scope.entries:
        if not wildcard:
            add(base)

    if subdomains:
        bases = [base for base, wildcard in scope.entries if wildcard]
        if domain and domain not in bases:
            bases.append(domain)
        guessed = []
        for base in bases:
            for prefix in SUBDOMAIN_PREFIXES:
                guess = f"{prefix}.{base}"
                # Guesses are filtered silently: most will be out of scope for an exact-only base.
                if scope.is_in_scope(guess) and guess not in guessed:
                    guessed.append(guess)
        log(f"[*] Resolving {len(guessed)} subdomain guesses across {len(bases)} base domain(s)")
        for guess in guessed:
            ip = resolve_host(guess)
            if ip:
                log(f"    [+] Discovered in-scope subdomain: {guess} -> {ip}")
                add(guess)

    return candidates


def scan(scope, *, domain=None, program=None, threads=5, delay=0.2,
         skip_sensitive=False, subdomains=True, skipped_scope=None, log=print):
    limiter = RateLimiter(delay)

    hosts = _candidate_hosts(scope, domain, subdomains, log)
    targets = [f"https://{h}" for h in hosts if scope.is_in_scope(h)]
    log(f"[*] Scope check passed: {len(targets)} in-scope host(s) to probe")

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
        "target": program or domain or ", ".join(scope.domains),
        "program": program,
        "timestamp": datetime.now().isoformat(),
        "scope_domains": scope.domains,
        "skipped_scope_items": skipped_scope or [],
        "delay_seconds": delay,
        "total_live_endpoints": len(live),
        "total_findings": total_findings,
        "endpoints": report_endpoints,
    }


def render_markdown(report):
    """Summary suitable as a starting point for a HackerOne report draft."""
    rows = [(ep["url"], v) for ep in report["endpoints"] for v in ep["vulnerabilities"]]
    lines = [
        f"# Automated recon report: {report['target']}",
        "",
        f"- Generated: {report['timestamp']}",
        f"- Live endpoints: {report['total_live_endpoints']}",
        f"- Findings: {report['total_findings']}",
        "",
        "## Findings",
        "",
    ]
    if not rows:
        lines.append("No findings.")
    for severity in SEVERITY_ORDER:
        for url, v in rows:
            if v["severity"] == severity:
                lines.append(f"- **[{severity}] {v['type']}** on `{url}`: {v['detail']}")
    lines += ["", "## Live endpoints", "", "| URL | Status | Server |", "|---|---|---|"]
    for ep in report["endpoints"]:
        lines.append(f"| {ep['url']} | {ep['status']} | {ep['server']} |")
    lines += [
        "",
        "## In-scope entries",
        "",
    ]
    lines += [f"- `{d}`" for d in report["scope_domains"]]
    lines += [
        "",
        "_Automated checks only. Verify every finding manually before submitting to HackerOne._",
        "",
    ]
    return "\n".join(lines)


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
    parser.add_argument("-d", "--domain",
                        help="Root domain to scan. Must be in scope. Optional; without it, "
                             "the scope's own hostnames and wildcard bases are used.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-p", "--program",
                        help="HackerOne program handle. Scope is fetched from the Hacker API using "
                             f"the {USERNAME_ENV} and {TOKEN_ENV} environment variables.")
    source.add_argument("-s", "--scope",
                        help="Local scope file, one hostname per line. '*.example.com' covers "
                             "subdomains only; 'example.com' covers that exact host.")
    parser.add_argument("-o", "--output", default="h1_bug_report.json",
                        help="JSON report path. A Markdown summary is written next to it.")
    parser.add_argument("-t", "--threads", type=positive_int, default=5,
                        help="Concurrent probe threads (default: 5)")
    parser.add_argument("--delay", type=non_negative_float, default=0.2,
                        help="Minimum seconds between requests, shared across all threads (default: 0.2)")
    parser.add_argument("--no-subdomains", action="store_true",
                        help="Skip subdomain guessing; scan only the scope's explicit hosts")
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
        if args.program:
            print(f"[*] Fetching structured scope for HackerOne program: {args.program}")
            raw_items = HackerOneClient.from_env().get_structured_scopes(args.program)
            identifiers, skipped = scope_identifiers(raw_items)
            entries, not_hosts = parse_scope_identifiers(identifiers)
            skipped += not_hosts
            print(f"[*] Structured scope: {len(raw_items)} asset(s), {len(entries)} hostname(s) usable")
        else:
            entries, skipped = load_scope(args.scope)
            print(f"[*] Loaded {len(entries)} hostname(s) from {args.scope}")

        for item in skipped:
            print(f"    [-] Skipped {item['asset'] or '(empty)'}: {item['reason']}")

        domain = None
        if args.domain:
            parsed_domain = parse_scope_identifier(args.domain)
            if parsed_domain is None:
                raise ScopeError(f"not a valid hostname: {args.domain!r}")
            domain = parsed_domain[0]

        scope = ScopeGuard(entries)
        report = scan(
            scope,
            domain=domain,
            program=args.program,
            threads=args.threads,
            delay=args.delay,
            skip_sensitive=args.skip_sensitive,
            subdomains=not args.no_subdomains,
            skipped_scope=skipped,
        )
    except (ScopeError, HackerOneError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    md_path = os.path.splitext(args.output)[0] + ".md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report))

    print("=" * 70)
    print("[*] Scan Completed Successfully!")
    print(f"[*] Total Live Endpoints: {report['total_live_endpoints']}")
    print(f"[*] Total Security Findings: {report['total_findings']}")
    print(f"[*] JSON report: {args.output}")
    print(f"[*] Markdown summary: {md_path}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
