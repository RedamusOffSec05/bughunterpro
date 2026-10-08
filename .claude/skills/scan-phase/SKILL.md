---
name: scan-phase
description: Scaffold a new recon/scanning phase (subdomain enum, port scan, service probe, etc.) for BugHunterPro.py or red_offensive_team_05.py, following the existing checkpoint/run/redaction pattern. Use when asked to "add a scan for X", "add a new recon phase", or to fix a phase that silently produces no output.
---

Scaffold or fix a recon/scanning phase in this repo, matching the pattern already used by `ADEnum.nmap` / `ADEnum._nmap_impl` in `red_offensive_team_05.py`.

Steps:
1. Read `red_offensive_team_05.py` around the `ADEnum` class and the `_phase`, `run`/`run_s`, `require_tool`, `ensure_dir`, and `CheckpointManager` definitions to confirm the current pattern before writing anything.
2. Add the new phase as a `@staticmethod` on the relevant module class:
   - A thin public method that calls `_phase("<phase-name>", lambda: Cls._impl(...), ckpt, force)`.
   - A `_impl` method that does the actual work: `require_tool(...)` guard if it shells out, `ensure_dir("<phase-name>")` for output, `run()`/`run_s()` for every external command (never raw `subprocess`), and a `tqdm` progress block if the phase has multiple sub-steps.
3. If the phase is intrusive (credential harvesting, relay, active exploitation — not passive enumeration), confirm it's covered by `ComplianceChecker.flag_intrusive()`'s set and gated behind the CLI's authorization confirmation. If it isn't, add it rather than letting it run ungated.
4. If this phase is meant to replace part of `BugHunterPro.py`'s stubbed `hunt()` (which currently always returns empty `subdomains`/`vulnerabilities` lists), wire the real result into that return value — don't leave the stub in place next to new dead code.
5. Add a unit test in `tests/test_rot05.py` (or `tests/test_bughunterpro.py`) for any pure-function parsing/logic you added (e.g. an output parser), following the existing tempfile-based style — no live network/tool calls in tests.
6. Run `python -m unittest discover -s tests` and fix failures before considering the phase done.
7. If the phase closes a gap between what README.md claims and what the code does, update README.md to match — otherwise leave documentation alone.
