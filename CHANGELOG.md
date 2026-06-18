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

## [1.3.0] - 2026-06-12

### Added — Infrastructure
- `ratelimit.py` — thread-safe `TokenBucket` (token bucket algorithm)
- `config.py` — YAML/JSON config file loader with deep-merge over defaults;
  auto-discovers `bhp.yaml / bhp.yml / bhp.json` in cwd
- `modules/base.py` — `BaseModule` ABC with `execute()` timing wrapper,
  per-module `errors` list, and `to_dict()` for report serialisation

### Added — Modules
- `modules/passive_recon.py` — `PassiveReconModule` (full DNS record set,
  zone transfer attempt against every NS, WHOIS, reverse PTR) and
  `BannerGrabModule` (TCP banner grab with version disclosure detection
  for Apache, nginx, IIS, OpenSSH, ProFTPD, vsftpd)
- `modules/credentials.py` — `CredentialModule` (SSH via paramiko, FTP
  anonymous + wordlist, HTTP Basic Auth; all rate-limited by TokenBucket)

### Added — Reporting
- `reporter.py` — self-contained HTML report with miasma CSS palette,
  Chart.js severity donut + open-ports bar chart, subdomain table,
  colour-coded vulnerability cards, header status table, USB findings

### Added — CLI
- Subcommands: `scan` (default), `recon`, `creds`
  - `scan`  — existing full-scan flow; adds `--html` and `--output-dir`
  - `recon` — runs PassiveReconModule and/or BannerGrabModule
  - `creds` — runs CredentialModule with optional `--wordlist` and `--rate`
- `--config / -c` flag accepted by all subcommands
- Progress bars via `tqdm` (graceful degradation if not installed)
- Audit log written to `bhp_audit.jsonl` (hunt_start, hunt_complete, etc.)

### Changed
- `generate_reports()` accepts `formats` list and `output_dir`
- Optional dependencies documented in `requirements.txt` comments

## [1.2.0] - 2026-06-11

### Added
- `usb_attack.py` — USBArmyKnife hardware attack integration module
  - `USBArmyKnifeClient`: low-level HTTP client for all device endpoints
    (`/data.json`, `/runfile`, `/rawinput`, `/runagentcmd`, `/marauder`,
    `/uploadFile`, `/downloadFile`, `/delete`, `/set`, `/mic`, `/clearlogs`)
  - `USBAttackModule`: high-level orchestrator — device fingerprint, WiFi recon
    via Marauder, HID payload delivery, agent command execution, SD card dump
  - Built-in DuckyScript payload library: `recon_windows`, `recon_linux`,
    `wifi_creds_windows`, `lock_screen`, `mouse_jiggle`, `open_terminal_linux`
  - Standalone CLI: `python usb_attack.py --host 4.3.2.1 --payload recon_windows --wifi`
- BugHunterPro now accepts `--usb-host`, `--usb-port`, `--usb-payload`,
  `--usb-wifi`, `--usb-agent` flags to chain USB attack into a full scan
- USB findings merged into JSON and Markdown reports (device fingerprint,
  WiFi APs, agent output, payload list, severity-tagged findings)

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
