# BugHunterPro - Quick Start Guide

Get started with BugHunterPro in 5 minutes.

## Step 1: Installation (2 minutes)

\\\ash
git clone https://github.com/RedamusOffSec05/bughunterpro.git
cd bughunterpro
pip install -r requirements.txt
\\\

## Step 2: First Scan (2 minutes)

\\\ash
python BugHunterPro.py --target example.com
\\\

What happens:
1. Enumerates subdomains
2. Scans for open ports
3. Checks security headers
4. Generates reports (JSON + Markdown)

## Step 3: Review Reports (1 minute)

\\\ash
# View JSON report
cat BugHunterPro_Report_*.json

# View Markdown report
cat BugHunterPro_Report_*.md
\\\

## Step 4: Next Steps

### Practice on Safe Environments
- DVWA (local)
- HackTheBox labs
- TryHackMe

### Join Bug Bounty Programs
1. Register on HackerOne or Bugcrowd
2. Find program with public scope
3. Read program rules carefully
4. Run BugHunterPro on in-scope domains
5. Investigate findings
6. Report valid vulnerabilities
7. Get paid!

## Common Commands

\\\ash
# Normal scan
python BugHunterPro.py --target example.com

# Aggressive scan
python BugHunterPro.py --target example.com --mode aggressive

# Verbose output
python BugHunterPro.py --target example.com --verbose

# Help
python BugHunterPro.py -h
\\\

## Important: Ethics and Legality

ONLY scan targets you have explicit permission to test:
- Authorized by the target owner
- Part of an official bug bounty program
- Your own systems for learning

Unauthorized scanning is illegal.

Happy Hunting!
