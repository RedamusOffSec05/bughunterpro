# BugHunterPro

Automated Bug Bounty Hunting Framework

## Features

- Subdomain enumeration
- Port scanning
- Vulnerability detection (SQL Injection, XSS, IDOR)
- Automated reporting (JSON + Markdown)
- Multiple scanning modes (Normal / Aggressive)
- Detailed logging

## Requirements

- Python 3.8+
- nmap
- pip

## Installation

```bash
git clone https://github.com/RedamusOffSec05/bughunterpro.git
cd bughunterpro
pip install -r requirements.txt
```

## Usage

Basic scan:
```bash
python BugHunterPro.py --target example.com
```

Aggressive scan:
```bash
python BugHunterPro.py --target example.com --mode aggressive
```

## HackerOne Scoped Scanner (`h1_recon_scanner.py`)

Scope comes from HackerOne's Hacker API (`--program`) or a local file (`--scope`).
Exactly one is required. The scan refuses to run with no usable scope, and refuses a
root domain (`-d`) that the scope does not cover.

**Scope semantics** (matching HackerOne):
- `*.example.com` covers subdomains only, not `example.com` itself
- `example.com` covers that exact host only

### Against a HackerOne program

Create an API token under your HackerOne API settings, then:

```bash
export H1_API_USERNAME="your-api-token-identifier"
export H1_API_TOKEN="your-api-token"
python h1_recon_scanner.py -p program-handle
```

Credentials are read only from the environment, so they stay out of shell history
and process listings. Eligible URL, WILDCARD and DOMAIN assets are scanned. Ineligible
assets and other types (CIDR, API, Android, ...) are listed as skipped in the report.

### Against a local scope file

```bash
python h1_recon_scanner.py -s scope.txt
python h1_recon_scanner.py -s scope.txt -d api.target-program.com -t 3 --delay 1.0 --no-subdomains
```

| Option | Default | Meaning |
|---|---|---|
| `-p/--program` | | HackerOne program handle (needs `H1_API_USERNAME` / `H1_API_TOKEN`) |
| `-s/--scope` | | Local scope file, one hostname per line |
| `-d/--domain` | | Root domain to scan; must be in scope |
| `-t/--threads` | 5 | Concurrent probe threads |
| `--delay` | 0.2 | Minimum seconds between requests, shared across threads |
| `--no-subdomains` | off | Scan only the scope's explicit hosts |
| `--skip-sensitive` | off | Skip sensitive file probes |
| `-o/--output` | `h1_bug_report.json` | JSON report; a Markdown summary is written beside it |

Nothing is submitted to HackerOne automatically. Verify every finding manually, then
write the report yourself.

Run the tests with `python3 -m unittest tests.test_h1_api tests.test_h1_recon_scanner -v`.

## Reports

Generates automatic reports in JSON and Markdown format with:
- List of discovered subdomains
- Detected vulnerabilities
- CVSS scores
- Recommendations

## Legal Notice

IMPORTANT: Only use on authorized targets

- Respect bug bounty program terms
- Verify scope before scanning
- Use responsibly and ethically

## Supported Bug Bounty Platforms

- HackerOne (https://www.hackerone.com)
- Bugcrowd (https://www.bugcrowd.com)
- Intigriti (https://www.intigriti.com)
- YesWeHack (https://www.yeswehack.com)

## Contributing

Contributions are welcome. Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - See LICENSE file for details

## Author

Steven (RedOffSec05)
- Security Researcher
- Bug Bounty Hunter
- Cybersecurity Consultant

Happy Hunting!