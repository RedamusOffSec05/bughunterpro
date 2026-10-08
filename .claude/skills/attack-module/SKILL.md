---
name: attack-module
description: Scaffold a new AD/enterprise attack technique module (Kerberos, AD CS, Exchange, SQL Server, GPO, DPAPI, etc.) in red_offensive_team_05.py with the correct checkpointing, redaction, tool-availability, and compliance/authorization gating. Use when asked to add a new attack technique (e.g. a new ESC check, a new lateral-movement path) to the toolkit.
---

Scaffold a new offensive technique module in `red_offensive_team_05.py`. This tool is explicitly scoped to AUTHORIZED penetration testing / CTF use (see its own module docstring) — you are writing code, not running it against a target, and no live execution should proceed without the user confirming explicit written authorization for the target in question.

Steps:
1. Read the nearest existing module for the same category (the AD CS/Kerberos/Exchange/SQL/GPO/DPAPI phases in `red_offensive_team_05.py`, with `ADEnum` as the most complete example) and model the new module on it structurally — same class/staticmethod shape, same helper usage.
2. Implement the new phase as `Cls.<technique>()` → `_phase("<technique>", lambda: Cls._<technique>_impl(...), ckpt, force)` → `_<technique>_impl()` doing the real work:
   - `require_tool(...)` for any external binary (impacket/certipy/responder/etc.), degrading with a warning rather than crashing if absent.
   - All shell-outs via `run()`/`run_s()` — never raw `subprocess` calls — so rate limiting, `DRY_RUN`, timeouts, and `_redact()` apply.
   - Output written under `ensure_dir("<technique>")`.
3. Decide whether the technique is intrusive (credential harvesting, active exploitation, poisoning/relay) vs. passive enumeration:
   - If intrusive, confirm its phase name is covered by `ComplianceChecker.flag_intrusive()`'s set (add it if missing) and that it's reachable only through whatever authorization-confirmation flow gates other intrusive phases in the CLI.
   - If it produces credential material (hashes, tickets, secrets, DPAPI blobs), confirm its output directory name is in `ResultEncryptor.SENSITIVE_DIRS` (add it if missing) so `encrypt_sensitive()` actually covers it post-engagement.
4. Wire the module into the CLI argument parsing / phase sequencing alongside its siblings, and make any dependency on a prior phase's output explicit (read from that phase's `ensure_dir` path, don't assume shared in-memory state).
5. Add it to `requirements.txt` as a commented optional dependency if it needs a new external package, matching the existing `# impacket>=0.11.0`-style entries.
6. Note in your summary which existing phase you modeled this on and explicitly confirm the compliance/encryption gating checks from step 3 — don't skip stating this even if the answer is "already covered."
