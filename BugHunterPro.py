#!/usr/bin/env python3
"""
BugHunterPro — automated bug-bounty recon & light vulnerability triage.

Scope by mode:
  normal     — passive / light-active recon only: subdomain enumeration,
               port scanning, security-header audit. No payloads sent.
  aggressive — everything in `normal`, PLUS light active probes (reflected
               request-param echo check, error-based SQL error detection).
               These probes send a single harmless marker string per check;
               they never exploit, exfiltrate data, or modify target state.
               They only run if authorization is confirmed (--authorized),
               consistent with the Legal Notice in README.md.

Only scan targets you are explicitly authorized to test.
"""

import argparse
import json
import re
import socket
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    G, Y, R, B, RST = Fore.GREEN, Fore.YELLOW, Fore.RED, Fore.CYAN, Style.RESET_ALL
except ImportError:
    G = Y = R = B = RST = ""


def info(msg):    print(f"{G}[+]{RST} {msg}")
def warn(msg):    print(f"{Y}[!]{RST} {msg}")
def err(msg):     print(f"{R}[-]{RST} {msg}")
def step(msg):    print(f"{B}[*]{RST} {msg}")


# ──────────────────────────────────────────────────────────────────────────
# Severity rubric
# ──────────────────────────────────────────────────────────────────────────
# Each entry is (severity_label, cvss_like_score, description). Scores are
# either a well-known published CVSS base score for the named issue class,
# or a fixed, documented internal-rubric score for generic finding types.
# These are triage signals, not a replacement for manual verification.
SEVERITY_RUBRIC = {
    "missing_hsts":        ("Low",    3.1, "Missing Strict-Transport-Security header"),
    "missing_csp":         ("Low",    3.1, "Missing Content-Security-Policy header"),
    "missing_xfo":         ("Low",    4.3, "Missing X-Frame-Options header (clickjacking exposure)"),
    "missing_xcto":        ("Low",    3.1, "Missing X-Content-Type-Options header"),
    "server_banner_leak":  ("Info",   0.0, "Server/X-Powered-By header discloses software or version"),
    "open_sensitive_port": ("Medium", 5.3, "Sensitive service port reachable"),
    "reflected_marker":    ("Medium", 6.1, "Request parameter reflected unescaped in the response body"),
    "sqli_error_based":    ("High",   8.6, "Database error signature returned for a malformed parameter"),
    "potential_idor":      ("Info",   0.0, "Numeric-ID style endpoint found — needs manual authZ/IDOR review"),
    "active_checks_skipped": ("Info", 0.0, "Aggressive active checks skipped — authorization not confirmed"),
}

DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "portal",
    "vpn", "remote", "webmail", "ns1", "ns2", "smtp", "pop", "imap", "cpanel",
    "autodiscover", "cdn", "static", "media", "img", "assets", "app", "apps",
    "secure", "shop", "store", "blog", "support", "help", "docs", "status",
    "internal", "intranet", "git", "gitlab", "jenkins", "jira", "confluence",
]
AGGRESSIVE_EXTRA_WORDLIST = [
    "backup", "old", "beta", "demo", "sandbox", "preview", "uat", "qa",
    "monitor", "grafana", "kibana", "elastic", "db", "database", "sql",
    "mysql", "redis", "mongo", "s3", "storage", "files", "upload",
    "download", "api-dev", "api-staging", "auth", "sso", "login", "oauth",
    "payment", "pay", "billing", "crm", "erp", "vpn2", "mx", "mx1", "mx2",
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993,
                995, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888, 9200, 27017]
SENSITIVE_PORT_NOTES = {
    21: "FTP", 23: "Telnet (cleartext)", 445: "SMB", 3389: "RDP",
    6379: "Redis", 27017: "MongoDB", 5432: "PostgreSQL", 3306: "MySQL",
    9200: "Elasticsearch",
}

SQLI_ERROR_SIGNATURES = [
    ("MySQL",      re.compile(r"SQL syntax.*MySQL|Warning.*mysql_", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*ERROR|pg_query\(\)", re.I)),
    ("MSSQL",      re.compile(r"Microsoft SQL Server|Unclosed quotation mark", re.I)),
    ("Oracle",     re.compile(r"ORA-\d{5}", re.I)),
    ("SQLite",     re.compile(r"SQLite3?::|sqlite3\.OperationalError", re.I)),
]

IDOR_CANDIDATE_RE = re.compile(
    r'href=["\'][^"\']*[?&](?:id|uid|user_id|account|order|invoice|doc|file)=\d+[^"\']*["\']',
    re.I,
)


# ──────────────────────────────────────────────────────────────────────────
# Recon primitives — each one is bounded by an explicit timeout so a run
# never hangs waiting on an unresponsive host.
# ──────────────────────────────────────────────────────────────────────────

def _resolve(host: str, timeout: float = 2.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(host)
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def enumerate_subdomains(domain: str, mode: str = "normal",
                          max_workers: int = 20, batch_timeout: float = 15.0) -> List[Dict[str, str]]:
    wordlist = list(DEFAULT_SUBDOMAIN_WORDLIST)
    if mode == "aggressive":
        wordlist += AGGRESSIVE_EXTRA_WORDLIST
    found: List[Dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_resolve, f"{sub}.{domain}"): sub for sub in wordlist}
        try:
            for fut in as_completed(futures, timeout=batch_timeout):
                sub = futures[fut]
                ip = fut.result()
                if ip:
                    found.append({"host": f"{sub}.{domain}", "ip": ip})
        except FutureTimeoutError:
            warn("Subdomain enumeration batch timed out — returning partial results.")
    return sorted(found, key=lambda d: d["host"])


def _probe_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def scan_ports(host: str, ports: Optional[List[int]] = None,
                max_workers: int = 30, batch_timeout: float = 15.0) -> List[int]:
    ports = ports or COMMON_PORTS
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_port, host, p): p for p in ports}
        try:
            for fut in as_completed(futures, timeout=batch_timeout):
                p = futures[fut]
                if fut.result():
                    open_ports.append(p)
        except FutureTimeoutError:
            warn("Port scan batch timed out — returning partial results.")
    return sorted(open_ports)


def _fetch(url: str, params: Optional[Dict[str, str]] = None, timeout: float = 6.0):
    if not HAS_REQUESTS:
        return None
    try:
        return requests.get(url, params=params, timeout=timeout,
                             headers={"User-Agent": "BugHunterPro/1.0 (+authorized-scan)"})
    except Exception:
        return None


def audit_security_headers(resp) -> List[Dict]:
    findings = []
    headers = resp.headers
    if resp.url.startswith("https://") and "strict-transport-security" not in {h.lower() for h in headers}:
        findings.append(_finding("missing_hsts", resp.url))
    if "content-security-policy" not in {h.lower() for h in headers}:
        findings.append(_finding("missing_csp", resp.url))
    if "x-frame-options" not in {h.lower() for h in headers}:
        findings.append(_finding("missing_xfo", resp.url))
    if "x-content-type-options" not in {h.lower() for h in headers}:
        findings.append(_finding("missing_xcto", resp.url))
    server = headers.get("Server") or headers.get("X-Powered-By")
    if server and any(c.isdigit() for c in server):
        findings.append(_finding("server_banner_leak", resp.url, evidence=server))
    return findings


def probe_reflected_marker(base_url: str, timeout: float = 6.0) -> List[Dict]:
    marker = f"bhp{uuid.uuid4().hex[:8]}"
    resp = _fetch(base_url, params={"q": marker}, timeout=timeout)
    if resp is not None and marker in resp.text:
        return [_finding("reflected_marker", base_url, evidence=f"param 'q' echoed marker {marker} unescaped")]
    return []


def probe_sqli_error_based(base_url: str, timeout: float = 6.0) -> List[Dict]:
    resp = _fetch(base_url, params={"id": "1'\""}, timeout=timeout)
    if resp is None:
        return []
    findings = []
    for engine, pattern in SQLI_ERROR_SIGNATURES:
        if pattern.search(resp.text):
            findings.append(_finding("sqli_error_based", base_url, evidence=f"{engine} error signature on param 'id'"))
            break
    return findings


def heuristic_idor_candidates(resp, base_url: str) -> List[Dict]:
    if resp is None:
        return []
    matches = IDOR_CANDIDATE_RE.findall(resp.text)
    if matches:
        return [_finding("potential_idor", base_url, evidence=f"{len(matches)} numeric-ID link(s) found")]
    return []


def sensitive_port_findings(host: str, open_ports: List[int]) -> List[Dict]:
    findings = []
    for p in open_ports:
        if p in SENSITIVE_PORT_NOTES:
            findings.append(_finding("open_sensitive_port", host, evidence=f"port {p}/tcp ({SENSITIVE_PORT_NOTES[p]})"))
    return findings


def _finding(ftype: str, target: str, evidence: str = "") -> Dict:
    severity, score, desc = SEVERITY_RUBRIC[ftype]
    return {
        "type": ftype,
        "severity": severity,
        "cvss_like_score": score,
        "description": desc,
        "target": target,
        "evidence": evidence,
    }


# ──────────────────────────────────────────────────────────────────────────
# Report building
# ──────────────────────────────────────────────────────────────────────────

def build_report(target: str, mode: str, subdomains: List[Dict], open_ports: List[int],
                  findings: List[Dict], started_at: str) -> Dict:
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f["severity"], 9))
    return {
        "tool": "BugHunterPro",
        "target": target,
        "mode": mode,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "subdomains": subdomains,
        "open_ports": open_ports,
        "findings": findings_sorted,
        "summary": {
            "subdomains_found": len(subdomains),
            "open_ports_found": len(open_ports),
            "findings_by_severity": {
                sev: sum(1 for f in findings_sorted if f["severity"] == sev)
                for sev in ("High", "Medium", "Low", "Info")
            },
        },
    }


def render_markdown(report: Dict) -> str:
    lines = [
        f"# BugHunterPro Report — {report['target']}",
        "",
        f"- Mode: `{report['mode']}`",
        f"- Started: {report['started_at']}",
        f"- Finished: {report['finished_at']}",
        "",
        "## Subdomains",
        "",
    ]
    if report["subdomains"]:
        for s in report["subdomains"]:
            lines.append(f"- {s['host']} → {s['ip']}")
    else:
        lines.append("_None found._")

    lines += ["", "## Open Ports", ""]
    lines.append(", ".join(str(p) for p in report["open_ports"]) if report["open_ports"] else "_None found._")

    lines += ["", "## Findings", ""]
    if report["findings"]:
        for f in report["findings"]:
            lines.append(f"### [{f['severity']}] {f['description']} (score: {f['cvss_like_score']})")
            lines.append(f"- Target: {f['target']}")
            if f["evidence"]:
                lines.append(f"- Evidence: {f['evidence']}")
            lines.append("")
    else:
        lines.append("_None found._")

    lines += [
        "",
        "## Recommendations",
        "",
        "- Verify every finding manually before reporting it to a bug bounty program.",
        "- Apply missing security headers via your web server/CDN configuration.",
        "- Treat `reflected_marker` and `sqli_error_based` findings as leads, not proof — "
        "confirm impact with a proxy tool before disclosure.",
        "",
    ]
    return "\n".join(lines)


def save_report(report: Dict, output_dir: Path) -> (Path, Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = re.sub(r"[^A-Za-z0-9.-]", "_", report["target"])
    json_path = output_dir / f"BugHunterPro_Report_{safe_target}_{stamp}.json"
    md_path = output_dir / f"BugHunterPro_Report_{safe_target}_{stamp}.md"
    json_path.write_text(json.dumps(report, indent=2))
    md_path.write_text(render_markdown(report))
    return json_path, md_path


# ──────────────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────────────

class BugHunterPro:
    def __init__(self, target: str, mode: str = "normal", authorized: bool = False):
        self.target = target
        self.mode = mode
        self.authorized = authorized

    def hunt(self) -> Dict:
        print(f"[+] Hunting en {self.target}")
        started_at = datetime.now(timezone.utc).isoformat()

        step("Enumerating subdomains...")
        subdomains = enumerate_subdomains(self.target, self.mode)
        info(f"Found {len(subdomains)} subdomain(s).")

        step("Scanning common ports...")
        open_ports = scan_ports(self.target)
        info(f"Found {len(open_ports)} open port(s): {open_ports}")

        findings: List[Dict] = []
        findings += sensitive_port_findings(self.target, open_ports)

        base_url = f"https://{self.target}/"
        resp = _fetch(base_url)
        if resp is None:
            base_url = f"http://{self.target}/"
            resp = _fetch(base_url)

        if resp is not None:
            step("Auditing security headers...")
            findings += audit_security_headers(resp)
            findings += heuristic_idor_candidates(resp, base_url)
        else:
            warn("Could not reach target over HTTP(S) — skipping header/IDOR checks.")

        if self.mode == "aggressive":
            if self.authorized:
                step("Running active checks (reflected marker, error-based SQLi)...")
                findings += probe_reflected_marker(base_url)
                findings += probe_sqli_error_based(base_url)
            else:
                warn("Aggressive mode requested but --authorized was not set — "
                     "skipping active probes. Only run these against targets you are "
                     "explicitly authorized to test.")
                findings.append(_finding("active_checks_skipped", self.target))

        report = build_report(self.target, self.mode, subdomains, open_ports, findings, started_at)
        return {
            "subdomains": [s["host"] for s in subdomains],
            "vulnerabilities": findings,
            "open_ports": open_ports,
            "report": report,
        }


def main():
    parser = argparse.ArgumentParser(description="BugHunterPro — automated bug bounty recon")
    parser.add_argument("--target", "-t", required=True, help="Target domain (must be in-scope/authorized)")
    parser.add_argument("--mode", "-m", default="normal", choices=["normal", "aggressive"])
    parser.add_argument("--authorized", action="store_true",
                         help="Confirm you have explicit written authorization to actively test this target "
                              "(required for --mode aggressive's active probes)")
    parser.add_argument("--output-dir", "-o", default="bughunterpro_reports",
                         help="Directory to write JSON/Markdown reports into")
    parser.add_argument("--no-report", action="store_true", help="Don't write report files to disk")
    args = parser.parse_args()

    hunter = BugHunterPro(args.target, mode=args.mode, authorized=args.authorized)
    result = hunter.hunt()

    if not args.no_report:
        json_path, md_path = save_report(result["report"], Path(args.output_dir))
        info(f"Report saved → {json_path}")
        info(f"Report saved → {md_path}")

    sev_counts = result["report"]["summary"]["findings_by_severity"]
    info(f"Done. {len(result['subdomains'])} subdomain(s), {len(result['open_ports'])} open port(s), "
         f"findings: {sev_counts}")


if __name__ == "__main__":
    main()
