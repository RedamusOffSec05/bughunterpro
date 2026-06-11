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

\\\ash
git clone https://github.com/RedamusOffSec05/bughunterpro.git
cd bughunterpro
pip install -r requirements.txt
\\\

## Usage

Basic scan:
\\\ash
python BugHunterPro.py --target example.com
\\\

Aggressive scan:
\\\ash
python BugHunterPro.py --target example.com --mode aggressive
\\\

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