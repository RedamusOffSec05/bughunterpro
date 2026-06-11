#!/usr/bin/env python3
"""BugHunterPro — Automated Bug Bounty Hunting Framework (miasma edition)"""

import argparse
import json
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs

import dns.resolver
import requests
import urllib3
from bs4 import BeautifulSoup
import colorama

colorama.init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Miasma color palette (ANSI 256-color) ───────────────────────────────────
class M:
    RST  = "\033[0m"
    FG   = "\033[38;5;186m"   # #d7c483  main text
    GRN  = "\033[38;5;65m"    # #5f875f  success / found
    GOLD = "\033[38;5;179m"   # #c9a554  info / label
    RUST = "\033[38;5;137m"   # #b36d43  error
    ORG  = "\033[38;5;214m"   # #fd9720  warning / vuln
    GRAY = "\033[38;5;242m"   # #666666  dim / timestamp
    PALE = "\033[38;5;229m"   # #fbec9f  banner / header
    BOLD = "\033[1m"


# ── Output helpers ───────────────────────────────────────────────────────────
def _fmt(sym, color, msg):
    ts = f"{M.GRAY}{datetime.now().strftime('%H:%M:%S')}{M.RST}"
    return f"  {ts} {color}{sym}{M.RST} {M.FG}{msg}{M.RST}"

def info(msg):    print(_fmt("·", M.GOLD, msg))
def success(msg): print(_fmt("✓", M.GRN,  msg))
def warn(msg):    print(_fmt("!", M.ORG,  msg))
def error(msg):   print(_fmt("✗", M.RUST, msg))
def vuln(msg):    print(_fmt("⚡", M.ORG, f"{M.BOLD}{msg}{M.RST}"))
def section(msg): print(f"\n{M.GOLD}{M.BOLD}  ══ {msg} ══{M.RST}")


def banner():
    print(f"""{M.PALE}{M.BOLD}
  ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
  {M.GOLD}                           P R O  {M.GRAY}// miasma edition
{M.GRAY}  Automated Bug Bounty Hunting Framework  ·  Use on authorized targets only
{M.RST}""")


# ── Subdomain enumeration ────────────────────────────────────────────────────
_SUBS_COMMON = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "cpanel", "whm",
    "autodiscover", "m", "imap", "test", "ns", "blog", "pop3", "dev", "www2",
    "admin", "forum", "news", "vpn", "ns2", "mail2", "new", "mysql", "old",
    "support", "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure",
    "demo", "cp", "wiki", "web", "media", "email", "images", "img", "intranet",
    "portal", "video", "api", "cdn", "stats", "search", "staging", "server",
    "mx1", "chat", "my", "svn", "sites", "proxy", "host", "crm", "cms", "backup",
    "apps", "download", "remote", "db", "forums", "store", "files", "app",
    "live", "owa", "helpdesk", "web1", "home", "monitor", "login", "service",
    "cloud", "hub", "auth", "sso", "oauth",
]

_SUBS_EXTRA = _SUBS_COMMON + [
    "git", "gitlab", "github", "jenkins", "jira", "confluence", "sonar",
    "nexus", "artifactory", "k8s", "kubernetes", "docker", "registry",
    "vault", "consul", "grafana", "kibana", "elastic", "prometheus",
    "traefik", "nginx", "lb", "loadbalancer", "gateway", "internal",
    "uat", "qa", "sit", "prod", "preprod", "sandbox", "lab", "labs",
    "test2", "testing", "dev2", "development", "stage", "stg", "build",
    "ci", "cd", "deploy", "services", "api2", "v2", "v1",
    "accounts", "billing", "payment", "pay", "checkout", "cart", "order",
    "partner", "affiliate", "hr", "careers", "erp", "finance",
]


_DNS_SEMAPHORE = threading.Semaphore(15)   # cap concurrent DNS queries
_DNS_RETRIES   = 2                          # retry on transient timeout


def _make_resolver():
    r = dns.resolver.Resolver()
    r.timeout  = 1.5   # per-attempt timeout
    r.lifetime = 4.0   # total time across all attempts
    return r


def enumerate_subdomains(domain, aggressive=False):
    section("Subdomain Enumeration")
    wordlist = _SUBS_EXTRA if aggressive else _SUBS_COMMON
    found    = []

    def check(sub):
        host = f"{sub}.{domain}"
        for attempt in range(_DNS_RETRIES):
            with _DNS_SEMAPHORE:
                try:
                    answers = _make_resolver().resolve(host, "A")
                    return host, [str(r) for r in answers]
                except dns.resolver.NXDOMAIN:
                    return None                           # definitive miss
                except dns.resolver.NoAnswer:
                    return None
                except dns.exception.Timeout:
                    if attempt < _DNS_RETRIES - 1:
                        time.sleep(0.4 * (attempt + 1))  # back off before retry
                except Exception:
                    return None
        return None

    info(f"Checking {len(wordlist)} subdomains against {domain}")
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(check, s): s for s in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                host, ips = result
                found.append({"host": host, "ips": ips})
                success(f"Found: {host}  {M.GRAY}→ {', '.join(ips)}")

    if not found:
        warn("No subdomains discovered")
    else:
        info(f"Total: {len(found)} subdomain(s)")
    return found


# ── Port scanning ────────────────────────────────────────────────────────────
_PORTS_COMMON = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

_PORTS_AGGRESSIVE = _PORTS_COMMON + [
    20, 69, 88, 111, 135, 139, 161, 389, 465, 500, 514, 587, 636, 873,
    993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2082, 2083, 2222,
    2375, 2376, 3000, 4848, 5000, 5432, 5900, 5984, 6379, 6443, 7001,
    7474, 8000, 8008, 8081, 8086, 8088, 8888, 8983, 9000, 9090, 9200,
    9300, 9418, 10000, 10250, 27017, 27018, 50000,
]

_PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB", 2375: "Docker", 2376: "Docker-TLS", 6443: "K8s-API",
}


def scan_ports(host, aggressive=False):
    section(f"Port Scanning — {host}")
    ports = _PORTS_AGGRESSIVE if aggressive else _PORTS_COMMON
    open_ports = []

    # Resolve hostname once; avoids repeated per-socket DNS lookups
    try:
        target_ip = socket.gethostbyname(host)
        if target_ip != host:
            info(f"Resolved: {host} → {target_ip}")
    except socket.gaierror as exc:
        error(f"Cannot resolve '{host}': {exc}")
        return []

    def check(port):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            if s.connect_ex((target_ip, port)) == 0:
                return {"port": port, "service": _PORT_SERVICES.get(port, "Unknown"), "state": "open"}
        except OSError:
            pass
        finally:
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        return None

    info(f"Scanning {len(ports)} ports on {target_ip}")
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(check, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                success(f"Open: {result['port']}/tcp  {M.GRAY}({result['service']})")

    if not open_ports:
        warn("No open ports found")
    return sorted(open_ports, key=lambda x: x["port"])


# ── Security headers ─────────────────────────────────────────────────────────
_SEC_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — susceptible to protocol downgrade",
    "X-Frame-Options":           "Clickjacking protection missing",
    "X-Content-Type-Options":    "MIME-sniffing protection missing",
    "Content-Security-Policy":   "CSP missing — XSS risk elevated",
    "X-XSS-Protection":          "Browser XSS filter not explicitly enabled",
    "Referrer-Policy":           "Referrer information may leak",
    "Permissions-Policy":        "Feature access policy not defined",
}


def check_security_headers(url):
    section("Security Headers")
    issues = []
    try:
        resp = requests.get(url, timeout=10, verify=False,
                            headers={"User-Agent": "BugHunterPro/1.0"})
        present = {h.lower() for h in resp.headers}
        for header, desc in _SEC_HEADERS.items():
            if header.lower() not in present:
                issues.append({"header": header, "severity": "Medium", "description": desc})
                vuln(f"Missing: {header}  {M.GRAY}— {desc}")
            else:
                success(f"Present: {header}")
    except requests.RequestException as exc:
        error(f"Header check failed: {exc}")
    if not issues:
        success("All security headers present")
    return issues


# ── Vulnerability detection ──────────────────────────────────────────────────
_SQLI_PAYLOADS = [
    "'", "''", "\"", "`", ";", "' or '1'='1", "' or 1=1--",
    "\" or 1=1--", "or 1=1--", "' OR '1'='1'--",
    "1 UNION SELECT null--", "' AND 1=2 UNION SELECT 1,2,3--",
]

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

_SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite_",
    "sqlstate", "syntax error", "unclosed quotation",
    "microsoft ole db", "odbc sql", "warning: mysql",
    "you have an error in your sql syntax", "supplied argument is not a valid mysql",
]


def _get_forms(url, session):
    try:
        resp = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action", url))
            method = form.get("method", "get").lower()
            inputs = {
                inp.get("name"): inp.get("value", "test")
                for inp in form.find_all(["input", "textarea", "select"])
                if inp.get("name")
            }
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms
    except Exception:
        return []


def _url_params(url):
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def _sqli_hit(text):
    t = text.lower()
    return any(e in t for e in _SQLI_ERRORS)


def test_sqli(url, session, aggressive):
    vulns = []
    payloads = _SQLI_PAYLOADS if aggressive else _SQLI_PAYLOADS[:5]
    params = _url_params(url)
    base = url.split("?")[0]

    for param in params:
        for payload in payloads:
            try:
                test = dict(params, **{param: payload})
                resp = session.get(base, params=test, timeout=10, verify=False)
                if _sqli_hit(resp.text):
                    vulns.append({
                        "type": "SQL Injection", "severity": "Critical",
                        "url": url, "parameter": param, "payload": payload, "cvss": 9.8,
                    })
                    vuln(f"SQLi in '{param}' at {url}")
                    break
            except Exception:
                pass

    for form in _get_forms(url, session):
        for param in form["inputs"]:
            for payload in payloads[:3]:
                try:
                    data = dict(form["inputs"], **{param: payload})
                    fn = session.post if form["method"] == "post" else session.get
                    key = "data" if form["method"] == "post" else "params"
                    resp = fn(form["action"], **{key: data}, timeout=10, verify=False)
                    if _sqli_hit(resp.text):
                        vulns.append({
                            "type": "SQL Injection", "severity": "Critical",
                            "url": form["action"], "parameter": param,
                            "payload": payload, "cvss": 9.8,
                        })
                        vuln(f"SQLi (form) in '{param}' at {form['action']}")
                        break
                except Exception:
                    pass

    return vulns


def test_xss(url, session, aggressive):
    vulns = []
    payloads = _XSS_PAYLOADS if aggressive else _XSS_PAYLOADS[:3]
    params = _url_params(url)
    base = url.split("?")[0]

    for param in params:
        for payload in payloads:
            try:
                test = dict(params, **{param: payload})
                resp = session.get(base, params=test, timeout=10, verify=False)
                if payload in resp.text:
                    vulns.append({
                        "type": "Cross-Site Scripting (XSS)", "severity": "High",
                        "url": url, "parameter": param, "payload": payload, "cvss": 7.5,
                    })
                    vuln(f"XSS in '{param}' at {url}")
                    break
            except Exception:
                pass

    for form in _get_forms(url, session):
        for param in form["inputs"]:
            for payload in payloads[:2]:
                try:
                    data = dict(form["inputs"], **{param: payload})
                    fn = session.post if form["method"] == "post" else session.get
                    key = "data" if form["method"] == "post" else "params"
                    resp = fn(form["action"], **{key: data}, timeout=10, verify=False)
                    if payload in resp.text:
                        vulns.append({
                            "type": "Cross-Site Scripting (XSS)", "severity": "High",
                            "url": form["action"], "parameter": param,
                            "payload": payload, "cvss": 7.5,
                        })
                        vuln(f"XSS (form) in '{param}' at {form['action']}")
                        break
                except Exception:
                    pass

    return vulns


def test_idor(url, session):
    vulns = []
    params = _url_params(url)
    id_params = [p for p in params if re.search(r"(id|user|account|profile|doc|file|order|item)", p, re.I)]
    base = url.split("?")[0]

    for param in id_params:
        try:
            base_val = int(params[param])
        except (ValueError, TypeError):
            continue
        try:
            orig = session.get(base, params=params, timeout=10, verify=False)
            for delta in (-1, 1, 2, 100):
                test = dict(params, **{param: str(base_val + delta)})
                resp = session.get(base, params=test, timeout=10, verify=False)
                if resp.status_code == 200 and len(resp.text) > 100 and resp.text != orig.text:
                    vulns.append({
                        "type": "Insecure Direct Object Reference (IDOR)", "severity": "High",
                        "url": url, "parameter": param,
                        "payload": str(base_val + delta), "cvss": 7.5,
                    })
                    vuln(f"IDOR in '{param}' at {url}")
                    break
        except Exception:
            pass

    return vulns


def detect_vulnerabilities(target, subdomains, aggressive):
    section("Vulnerability Detection")
    session = requests.Session()
    session.headers["User-Agent"] = "BugHunterPro/1.0"

    all_vulns = []
    scan_urls = [f"http://{target}", f"https://{target}"]
    for sd in subdomains[:5]:
        scan_urls.append(f"http://{sd['host']}")

    for url in scan_urls:
        info(f"Scanning {url}")
        all_vulns += test_sqli(url, session, aggressive)
        all_vulns += test_xss(url, session, aggressive)
        all_vulns += test_idor(url, session)

    seen, unique = set(), []
    for v in all_vulns:
        key = (v["type"], v["url"], v["parameter"], v["payload"])
        if key not in seen:
            seen.add(key)
            unique.append(v)

    if not unique:
        success("No vulnerabilities detected")
    else:
        warn(f"{len(unique)} finding(s) — review carefully")
    return unique


# ── Report generation ────────────────────────────────────────────────────────
def generate_reports(target, subdomains, ports, vulns, header_issues, usb_results=None):
    section("Generating Reports")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"BugHunterPro_Report_{target}_{ts}"

    _sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    vulns_sorted = sorted(vulns, key=lambda v: _sev_order.get(v.get("severity", "Info"), 4))

    summary = {
        "subdomains_found": len(subdomains),
        "open_ports": len(ports),
        "vulnerabilities": len(vulns),
        "critical": sum(1 for v in vulns if v.get("severity") == "Critical"),
        "high":     sum(1 for v in vulns if v.get("severity") == "High"),
        "medium":   sum(1 for v in vulns if v.get("severity") == "Medium"),
    }

    usb_findings = (usb_results or {}).get("findings", [])
    usb_critical = sum(1 for f in usb_findings if f.get("severity") == "Critical")
    summary["usb_findings"] = len(usb_findings)
    summary["usb_critical"] = usb_critical

    report = {
        "meta": {
            "tool": "BugHunterPro", "version": "1.2.0",
            "target": target, "timestamp": datetime.now().isoformat(), "theme": "miasma",
        },
        "summary": summary,
        "subdomains": subdomains,
        "open_ports": ports,
        "vulnerabilities": vulns_sorted,
        "header_issues": header_issues,
        "usb_attack": usb_results or {},
    }

    json_path = f"{base}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    success(f"JSON  → {json_path}")

    md = [
        f"# BugHunterPro Report — {target}",
        f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Theme: miasma\n",
        "## Summary",
        "| Metric | Count |", "|--------|-------|",
        f"| Subdomains found | {summary['subdomains_found']} |",
        f"| Open ports       | {summary['open_ports']} |",
        f"| Vulnerabilities  | {summary['vulnerabilities']} |",
        f"| Critical         | {summary['critical']} |",
        f"| High             | {summary['high']} |",
        f"| Medium           | {summary['medium']} |",
        f"| USB findings     | {summary.get('usb_findings', 0)} |",
        "", "## Subdomains",
    ]
    if subdomains:
        md += ["| Host | IP Addresses |", "|------|-------------|"]
        md += [f"| {sd['host']} | {', '.join(sd['ips'])} |" for sd in subdomains]
    else:
        md.append("_No subdomains discovered._")

    md += ["", "## Open Ports"]
    if ports:
        md += ["| Port | Service |", "|------|---------|"]
        md += [f"| {p['port']} | {p['service']} |" for p in ports]
    else:
        md.append("_No open ports found._")

    md += ["", "## Vulnerabilities"]
    if vulns_sorted:
        for v in vulns_sorted:
            md += [
                f"### [{v['severity']}] {v['type']}",
                f"- **URL:** `{v['url']}`",
                f"- **Parameter:** `{v['parameter']}`",
                f"- **Payload:** `{v['payload']}`",
                f"- **CVSS Score:** {v.get('cvss', 'N/A')}",
                "",
            ]
    else:
        md.append("_No vulnerabilities detected._")

    if header_issues:
        md += ["", "## Missing Security Headers"]
        md += [f"- **{h['header']}** ({h['severity']}): {h['description']}" for h in header_issues]

    if usb_results and usb_results.get("device"):
        d = usb_results["device"]
        md += [
            "", "## USB Attack Module (USBArmyKnife)",
            f"- **Device:** {d.get('chipModel','?')} fw `{d.get('version','?')}`",
            f"- **USB mode:** {d.get('USBmode','?')}  |  Agent connected: {d.get('agentConnected','?')}",
            f"- **Capabilities:** {', '.join(d.get('capabilities', []))}",
        ]
        if usb_results.get("payloads_run"):
            md.append(f"- **Payloads executed:** {', '.join(usb_results['payloads_run'])}")
        if usb_findings:
            md += ["", "### USB Findings"]
            for f in usb_findings:
                md += [
                    f"#### [{f['severity']}] {f['type']}",
                    f"- {f['detail']}",
                    "",
                ]
        if usb_results.get("wifi_aps"):
            md += ["", "### Nearby WiFi APs (Marauder)"]
            md += [f"- `{ap}`" for ap in usb_results["wifi_aps"][:20]]

    md += ["", "---", "> Only use BugHunterPro on authorized targets."]

    md_path = f"{base}.md"
    with open(md_path, "w") as f:
        f.write("\n".join(md))
    success(f"Markdown → {md_path}")

    return report


# ── Public API ───────────────────────────────────────────────────────────────
class BugHunterPro:
    def __init__(self, target, mode="normal", verbose=False,
                 usb_host=None, usb_port=8080,
                 usb_payloads=None, usb_wifi=False, usb_agent=False):
        t = target.lower().strip()
        for prefix in ("https://", "http://"):
            if t.startswith(prefix):
                t = t[len(prefix):]
                break
        self.target = t.rstrip("/")
        self.mode = mode
        self.aggressive = mode == "aggressive"
        self.usb_host = usb_host
        self.usb_port = usb_port
        self.usb_payloads = usb_payloads or []
        self.usb_wifi = usb_wifi
        self.usb_agent = usb_agent
        logging.basicConfig(
            format=f"{M.GRAY}%(asctime)s %(levelname)s %(message)s{M.RST}",
            datefmt="%H:%M:%S",
            level=logging.DEBUG if verbose else logging.WARNING,
        )

    def hunt(self):
        banner()
        info(f"Target: {M.PALE}{self.target}{M.RST}  Mode: {M.GOLD}{self.mode}")
        if self.usb_host:
            info(f"USB device: {M.GOLD}{self.usb_host}:{self.usb_port}")
        info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        subdomains    = enumerate_subdomains(self.target, self.aggressive)
        ports         = scan_ports(self.target, self.aggressive)
        open_port_nos = {p["port"] for p in ports}
        base_url      = f"https://{self.target}" if 443 in open_port_nos else f"http://{self.target}"
        header_issues = check_security_headers(base_url)
        vulns         = detect_vulnerabilities(self.target, subdomains, self.aggressive)

        usb_results = None
        if self.usb_host:
            try:
                from usb_attack import USBAttackModule
                mod = USBAttackModule(self.usb_host, self.usb_port)
                usb_results = mod.run_full(
                    payloads=self.usb_payloads,
                    wifi_recon=self.usb_wifi,
                    agent_recon=self.usb_agent,
                    authorized=True,
                )
            except ImportError:
                warn("usb_attack.py not found — USB module skipped")
            except Exception as exc:
                error(f"USB module error: {exc}")

        report = generate_reports(
            self.target, subdomains, ports, vulns, header_issues, usb_results
        )

        section("Hunt Complete")
        s = report["summary"]
        info(f"Subdomains : {M.GRN}{s['subdomains_found']}")
        info(f"Open ports : {M.GRN}{s['open_ports']}")
        info(f"Findings   : {M.ORG if s['vulnerabilities'] else M.GRN}{s['vulnerabilities']}")
        if s.get("usb_findings"):
            info(f"USB hits   : {M.ORG}{s['usb_findings']}")
        if s["critical"]:
            warn(f"Critical   : {s['critical']} — prioritise immediately")

        return {
            "subdomains":      {sd["host"] for sd in subdomains},
            "vulnerabilities": vulns,
            "usb":             usb_results,
            "report":          report,
        }


# ── CLI entry point ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="BugHunterPro — Automated Bug Bounty Hunting Framework",
        epilog="Only use on authorized targets.",
    )
    parser.add_argument("--target",   "-t", required=True, help="Target domain")
    parser.add_argument("--mode",     "-m", default="normal",
                        choices=["normal", "aggressive"], help="Scan intensity")
    parser.add_argument("--verbose",  "-v", action="store_true", help="Verbose logging")

    usb = parser.add_argument_group("USB attack (USBArmyKnife)")
    usb.add_argument("--usb-host",    default=None,
                     help="USBArmyKnife device IP (e.g. 4.3.2.1 or 192.168.4.1)")
    usb.add_argument("--usb-port",    default=8080, type=int,
                     help="Device HTTP port (default: 8080)")
    usb.add_argument("--usb-payload", nargs="*", default=[], dest="usb_payloads",
                     metavar="NAME",
                     help="Payload name(s) from built-in library "
                          "(recon_windows, recon_linux, wifi_creds_windows, …)")
    usb.add_argument("--usb-wifi",    action="store_true",
                     help="Run Marauder WiFi AP scan")
    usb.add_argument("--usb-agent",   action="store_true",
                     help="Run recon commands via connected agent")

    args = parser.parse_args()

    BugHunterPro(
        args.target, args.mode, args.verbose,
        usb_host=args.usb_host,
        usb_port=args.usb_port,
        usb_payloads=args.usb_payloads,
        usb_wifi=args.usb_wifi,
        usb_agent=args.usb_agent,
    ).hunt()


if __name__ == "__main__":
    main()
