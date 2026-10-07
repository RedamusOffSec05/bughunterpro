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

## [Unreleased]

### Added
- `h1_recon_scanner.py`: HackerOne-scoped recon and misconfiguration checker
  (scope file required, global request rate limiting, sensitive-file probes
  with catch-all detection)
- `tests/test_h1_recon_scanner.py` covering scope, rate limiting, header
  analysis, a local HTTP server, and CLI guards

### Fixed
- Syntax error in the threads argument (`type=int, int`) from the original
  scanner draft
- Security header checks now match case-insensitively (HTTP/2 sends lowercase)
- `--delay` now applies to every request, including sensitive-file probes

### Planned
- Machine learning-based detection
- Web dashboard
- Multi-threading optimization
- API integration (HackerOne, Bugcrowd)
- Advanced IDOR detection
- Business logic vulnerability detection
