---
name: tool-self-review
description: Run a checklist-driven security/correctness review of this toolkit's own code (credential handling, subprocess usage, encryption, config allowlisting, compliance gating, README-vs-code drift). Use after changes to BugHunterPro.py or red_offensive_team_05.py, or when asked to audit this repo's own code rather than a target.
---

Review this repo's own source — not the targets it scans — against the risk areas below. Go file by file with Grep/Read, don't rely on memory of what the code "probably" does.

Checklist:
1. **Credential leakage** — `grep -n "_redact\|logger\.\|print(" red_offensive_team_05.py` and check every place a password/hash/ticket could reach a log file, stdout, `.checkpoints.json`, or a report. `_redact()` only strips `-w`/`-p`/`--password`/`-P`/`--pass` from logged commands — look for another flag spelling it misses, or credentials written directly to `logger`/stdout bypassing `_redact()`.
2. **Subprocess safety** — `grep -n "subprocess\." red_offensive_team_05.py`. Every external call should route through `run()`/`run_s()` with `shell=False` and a list of args. Flag any `shell=True` or f-string-built shell command, especially one built from a `--target`/domain/username argument.
3. **Encryption correctness** — read `ResultEncryptor`. Confirm the passphrase is never logged, the `.salt` file write isn't world-readable by default on a shared host, and `encrypt_dir()`'s suffix filter (`.txt`/`.json`, skip-already-`.enc`) still matches any new sensitive file types introduced since this check was last run.
4. **Config allowlisting** — read `ConfigFile._SAFE_KEYS` and `TargetConfig`. Confirm every field in `TargetConfig` that should be settable from `config.json` is deliberately listed in `_SAFE_KEYS`, and that `ConfigFile.apply()` can't set attributes outside that allowlist.
5. **Compliance gating** — read `ComplianceChecker.flag_intrusive()`. Confirm every intrusive phase in the codebase (credential harvesting, poisoning/relay, active exploitation) has its name in that intrusive set; `grep` for phase names used in `_phase(...)` calls and cross-check.
6. **Docs-vs-code drift** — compare README.md / CHANGELOG.md claims against actual code (e.g. does `BugHunterPro.py.hunt()` really enumerate subdomains and detect vulnerabilities, or is it still a stub returning empty lists?). Flag drift as a finding instead of silently treating the docs as accurate.
7. Run `python -m unittest discover -s tests` to confirm existing tests still pass before/after any fix.

Report findings most-severe-first with file:line and a concrete failure scenario, same bar as `/code-review` — skip stylistic nits.
