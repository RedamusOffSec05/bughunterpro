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
  (global request rate limiting, sensitive-file probes with catch-all detection,
  JSON and Markdown reports)
- `--program` mode: pulls the structured scope from the HackerOne Hacker API
  using `H1_API_USERNAME` / `H1_API_TOKEN`
- `h1_api.py`: HackerOne API client (Basic auth, pagination, 429 backoff,
  refuses to send credentials to any host other than api.hackerone.com)
- `tests/test_h1_recon_scanner.py` and `tests/test_h1_api.py` (mocked transport)

### Changed
- Scope matching follows HackerOne semantics: `*.example.com` covers subdomains
  only, and `example.com` covers that exact host. Previously `example.com`
  matched all of its subdomains.

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
