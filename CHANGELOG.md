# Changelog

All notable changes to BugHunterPro will be documented in this file.

## [1.0.0] - 2024-06-10

### Added
- Initial release
- Subdomain enumeration module
- Port scanning integration
- Vulnerability detection (SQL Injection, XSS, IDOR)
- Security headers checking
- JSON and Markdown report generation
- Normal and Aggressive scanning modes
- Comprehensive logging

### Features
- DNS-based subdomain discovery
- Common subdomain wordlist
- Security header validation
- Automated reporting

## [1.1.0] - 2026-06-11

### Added
- Full implementation of all v1.0.0 planned features
- Miasma color theme applied to all terminal output (ANSI 256-color)
- Threaded subdomain enumeration (30 workers, 65+ common / 110+ aggressive wordlist)
- Threaded TCP port scanner (50 workers, service name resolution)
- Security headers check (HSTS, CSP, X-Frame-Options, and 4 more)
- SQLi detection: URL params + form inputs, error-pattern matching
- XSS detection: reflected payload check for URL params + form inputs
- IDOR detection: sequential ID fuzzing on numeric parameters
- JSON + Markdown reports with severity-sorted findings table
- `--verbose` flag for debug-level logging
- Deduplicated finding output across scan targets

### Changed
- BugHunterPro.hunt() now returns `{"subdomains", "vulnerabilities", "report"}`

## [Unreleased]

### Planned
- Machine learning-based detection
- Web dashboard
- API integration (HackerOne, Bugcrowd)
- Business logic vulnerability detection
