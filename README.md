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

Requires a scope file (one domain per line; `#` comments and `*.example.com` allowed).
The scan refuses to run without one, and refuses a root domain the scope does not cover.

```bash
python h1_recon_scanner.py -d target-program.com -s scope.txt
python h1_recon_scanner.py -d target-program.com -s scope.txt -t 3 --delay 1.0 --no-subdomains
```

| Option | Default | Meaning |
|---|---|---|
| `-s/--scope` | required | Scope file |
| `-t/--threads` | 5 | Concurrent probe threads |
| `--delay` | 0.2 | Minimum seconds between requests, shared across threads |
| `--no-subdomains` | off | Scan only the root domain |
| `--skip-sensitive` | off | Skip sensitive file probes |
| `-o/--output` | `h1_bug_report.json` | JSON report path |

Run the tests with `python3 -m unittest tests.test_h1_recon_scanner -v`.

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