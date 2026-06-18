#!/usr/bin/env python3
"""
HTML report generator for BugHunterPro (miasma edition).

Produces a self-contained HTML file with:
  - Summary stats cards
  - Severity donut chart  (Chart.js via CDN)
  - Open ports bar chart  (Chart.js via CDN)
  - Subdomain table
  - Vulnerability finding cards (colour-coded by severity)
  - Security header status table
  - USB attack findings section
"""

import json
from datetime import datetime
from pathlib import Path

_CSS = """
:root{
  --bg:#222;--bg2:#1c1c1c;--fg:#d7c483;--green:#5f875f;
  --gold:#c9a554;--rust:#b36d43;--orange:#fd9720;
  --gray:#666;--pale:#fbec9f;--card:#2a2a2a;--border:#3a3a3a;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:'Courier New',monospace;
     padding:2rem;line-height:1.6;font-size:14px}
h1{color:var(--pale);font-size:1.6rem;border-bottom:2px solid var(--gold);
   padding-bottom:.5rem;margin-bottom:1.5rem}
h2{color:var(--gold);font-size:1.1rem;margin:2rem 0 .75rem;
   border-left:3px solid var(--gold);padding-left:.6rem}
h3{color:var(--fg);margin:.75rem 0 .4rem}
.meta{color:var(--gray);font-size:.8rem;margin-bottom:1.5rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
      gap:.75rem;margin-bottom:1.5rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:4px;
      padding:.9rem;text-align:center}
.card .num{font-size:2rem;font-weight:bold;color:var(--pale)}
.card .lbl{color:var(--gray);font-size:.75rem;text-transform:uppercase}
.card.c .num{color:var(--rust)}
.card.h .num{color:var(--orange)}
.card.m .num{color:var(--gold)}
.card.g .num{color:var(--green)}
table{width:100%;border-collapse:collapse;margin-bottom:1rem;font-size:.88rem}
th{background:var(--bg2);color:var(--gold);text-align:left;
   padding:.4rem .6rem;border-bottom:2px solid var(--border)}
td{padding:.35rem .6rem;border-bottom:1px solid var(--border)}
tr:hover td{background:var(--card)}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:3px;
       font-size:.72rem;font-weight:bold}
.Critical{background:var(--rust);color:#fff}
.High{background:var(--orange);color:#111}
.Medium{background:var(--gold);color:#111}
.Low{background:var(--green);color:#fff}
.Info{background:var(--gray);color:#fff}
.finding{background:var(--card);border:1px solid var(--border);
         border-radius:4px;padding:.75rem;margin-bottom:.6rem}
.ftitle{font-weight:bold;color:var(--pale);margin-bottom:.3rem}
.fmeta{color:var(--gray);font-size:.8rem}
code{background:var(--bg2);padding:.05rem .3rem;border-radius:2px;
     font-size:.82rem;color:var(--pale)}
.ok{color:var(--green)}.err{color:var(--rust)}
.chart-box{background:var(--card);border:1px solid var(--border);
           border-radius:4px;padding:1rem;margin-bottom:1rem;max-width:680px}
footer{margin-top:2.5rem;color:var(--gray);font-size:.78rem;
       border-top:1px solid var(--border);padding-top:.75rem}
"""

_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
_ALL_HEADERS = [
    "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options",
    "Content-Security-Policy", "X-XSS-Protection", "Referrer-Policy",
    "Permissions-Policy",
]


def _badge(sev: str) -> str:
    return f'<span class="badge {sev}">{sev}</span>'


def _status(present: bool) -> str:
    return ('<span class="ok">✓ present</span>' if present
            else '<span class="err">✗ missing</span>')


def _js(v) -> str:
    return json.dumps(v)


def generate_html(report: dict, output_dir: str = ".") -> str:
    """
    Write a self-contained HTML report and return the file path.

    report    : the dict returned by BugHunterPro.generate_reports()
    output_dir: directory to write the .html file into
    """
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    target  = report["meta"]["target"]
    version = report["meta"].get("version", "?")
    out     = Path(output_dir) / f"BugHunterPro_Report_{target}_{ts}.html"

    s     = report.get("summary", {})
    vulns = sorted(report.get("vulnerabilities", []),
                   key=lambda v: _SEV_ORDER.get(v.get("severity", "Info"), 4))
    subs  = report.get("subdomains", [])
    ports = report.get("open_ports", [])
    hdrs  = {h["header"] for h in report.get("header_issues", [])}
    usb   = report.get("usb_attack", {})

    # ── Summary cards ──────────────────────────────────────────────────────
    def card(cls, num, lbl):
        return f'<div class="card {cls}"><div class="num">{num}</div><div class="lbl">{lbl}</div></div>'

    nc = "c" if s.get("critical", 0) else "g"
    nh = "h" if s.get("high",     0) else "g"
    nm = "m" if s.get("medium",   0) else "g"
    cards = "".join([
        card("g",  s.get("subdomains_found", 0), "Subdomains"),
        card("g",  s.get("open_ports",       0), "Open Ports"),
        card(nc,   s.get("critical",          0), "Critical"),
        card(nh,   s.get("high",              0), "High"),
        card(nm,   s.get("medium",            0), "Medium"),
        card("g",  s.get("usb_findings",      0), "USB Findings"),
    ])

    # ── Subdomain rows ─────────────────────────────────────────────────────
    sd_rows = "".join(
        f"<tr><td><code>{sd['host']}</code></td><td>{', '.join(sd['ips'])}</td></tr>"
        for sd in subs
    ) or "<tr><td colspan='2'>No subdomains discovered.</td></tr>"

    # ── Port rows ──────────────────────────────────────────────────────────
    port_rows = "".join(
        f"<tr><td>{p['port']}/tcp</td><td>{p['service']}</td></tr>"
        for p in ports
    ) or "<tr><td colspan='2'>No open ports found.</td></tr>"

    # ── Vulnerability cards ────────────────────────────────────────────────
    vuln_cards = "".join(f"""
    <div class="finding">
      <div class="ftitle">{_badge(v['severity'])} {v['type']}</div>
      <div class="fmeta">
        URL <code>{v.get('url','')}</code> &nbsp;·&nbsp;
        Param <code>{v.get('parameter','')}</code> &nbsp;·&nbsp;
        Payload <code>{v.get('payload','')}</code> &nbsp;·&nbsp;
        CVSS&nbsp;{v.get('cvss','N/A')}
      </div>
    </div>""" for v in vulns) or "<p>No vulnerabilities detected.</p>"

    # ── Header table ───────────────────────────────────────────────────────
    hdr_rows = "".join(
        f"<tr><td>{h}</td><td>{_status(h not in hdrs)}</td></tr>"
        for h in _ALL_HEADERS
    )

    # ── Charts ─────────────────────────────────────────────────────────────
    port_chart = ""
    if ports:
        plabels = _js([str(p["port"]) for p in ports[:20]])
        pdata   = _js([1] * min(len(ports), 20))
        port_chart = f"""
        <div class="chart-box">
          <h3>Open Ports</h3>
          <canvas id="portChart" height="100"></canvas>
        </div>
        <script>
        new Chart(document.getElementById('portChart'),{{
          type:'bar',
          data:{{labels:{plabels},datasets:[{{label:'open',data:{pdata},
            backgroundColor:'#5f875f',borderColor:'#c9a554',borderWidth:1}}]}},
          options:{{plugins:{{legend:{{display:false}}}},
            scales:{{x:{{ticks:{{color:'#d7c483'}},grid:{{color:'#3a3a3a'}}}},
                     y:{{display:false}}}}}}
        }});
        </script>"""

    sev_chart = ""
    sev_vals = [s.get("critical",0), s.get("high",0), s.get("medium",0),
                sum(1 for v in vulns if v.get("severity") == "Low")]
    if any(sev_vals):
        sev_chart = f"""
        <div class="chart-box" style="max-width:340px">
          <h3>Findings by Severity</h3>
          <canvas id="sevChart" height="220"></canvas>
        </div>
        <script>
        new Chart(document.getElementById('sevChart'),{{
          type:'doughnut',
          data:{{labels:{_js(["Critical","High","Medium","Low"])},
                datasets:[{{data:{_js(sev_vals)},
                  backgroundColor:['#b36d43','#fd9720','#c9a554','#5f875f']}}]}},
          options:{{plugins:{{legend:{{labels:{{color:'#d7c483'}}}}}}}}
        }});
        </script>"""

    # ── USB section ────────────────────────────────────────────────────────
    usb_html = ""
    if usb and usb.get("device"):
        d = usb["device"]
        caps = ", ".join(d.get("capabilities", [])) or "none"
        usb_html = f"""
        <h2>USB Attack Module (USBArmyKnife)</h2>
        <table>
          <tr><th>Property</th><th>Value</th></tr>
          <tr><td>Device</td><td>{d.get('chipModel','?')} — fw {d.get('version','?')}</td></tr>
          <tr><td>USB mode</td><td>{d.get('USBmode','?')}</td></tr>
          <tr><td>Agent connected</td><td>{'yes' if d.get('agentConnected') else 'no'}</td></tr>
          <tr><td>Machine name</td><td>{d.get('machineName','—')}</td></tr>
          <tr><td>Capabilities</td><td>{caps}</td></tr>
          <tr><td>Payloads run</td><td>{', '.join(usb.get('payloads_run',[])) or 'none'}</td></tr>
        </table>"""

        for f in usb.get("findings", []):
            usb_html += f"""
            <div class="finding">
              <div class="ftitle">{_badge(f['severity'])} {f['type']}</div>
              <div class="fmeta">{f['detail']}</div>
            </div>"""

        aps = usb.get("wifi_aps", [])
        if aps:
            usb_html += f"<h3>Nearby WiFi APs ({len(aps)})</h3><table><tr><th>AP</th></tr>"
            for ap in aps[:20]:
                usb_html += f"<tr><td><code>{ap}</code></td></tr>"
            usb_html += "</table>"

    # ── Assemble ───────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>BugHunterPro — {target}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
  <style>{_CSS}</style>
</head>
<body>
<h1>BugHunterPro Report</h1>
<div class="meta">
  Target: <strong>{target}</strong> &nbsp;·&nbsp;
  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;·&nbsp;
  Version {version} &nbsp;·&nbsp; theme: miasma
</div>

<h2>Summary</h2>
<div class="grid">{cards}</div>
{sev_chart}

<h2>Subdomains ({len(subs)})</h2>
<table><tr><th>Host</th><th>IP Addresses</th></tr>{sd_rows}</table>

<h2>Open Ports ({len(ports)})</h2>
{port_chart}
<table><tr><th>Port</th><th>Service</th></tr>{port_rows}</table>

<h2>Vulnerabilities ({len(vulns)})</h2>
{vuln_cards}

<h2>Security Headers</h2>
<table><tr><th>Header</th><th>Status</th></tr>{hdr_rows}</table>

{usb_html}

<footer>
  BugHunterPro · miasma edition · Only use on systems you are authorized to test
</footer>
</body>
</html>"""

    out.write_text(html, encoding="utf-8")
    return str(out)
