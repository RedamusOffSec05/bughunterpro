---
name: build-report
description: Build or fix the JSON+Markdown reporting pipeline that aggregates scan/attack phase output into findings with severity scoring, as promised by README.md. Use when asked to "generate a report", "add CVSS scoring", or implement the reporting step that BugHunterPro currently stubs out.
---

Build (or fix) the report pipeline that turns phase output into the JSON + Markdown reports README.md advertises.

Steps:
1. Check what already exists before writing anything new: `grep -rn "report\|json.dump\|markdown" --include=*.py .`. Treat `BugHunterPro.py`'s `hunt()` (currently returns hardcoded empty `subdomains`/`vulnerabilities` lists) as the gap to close, not a working baseline.
2. Design one findings data structure first — e.g. a list of `{target, type, severity, cvss, evidence_path, recommendation}` dicts — built by walking `OUTPUT_DIR`'s per-phase subdirectories (`ensure_dir(subdir)` output) and `CheckpointManager`'s `.checkpoints.json`. Don't re-run scans to build the report; it's a pure reducer over existing output.
3. Render that one structure twice:
   - JSON: direct `json.dumps(findings, indent=2)` of the structure (machine-readable, matches README's "JSON" report format).
   - Markdown: a human-readable summary — grouped by severity, with subdomains/vulnerabilities/recommendations sections matching what README.md describes.
4. Score severity deliberately, not arbitrarily: use known CVSS base scores for named CVEs/techniques where applicable, or a short documented internal rubric for generic finding types (e.g. open sensitive port, missing header). Note the methodology inline in the report output.
5. Redact secrets in the Markdown output the same way `_redact()` redacts logged commands (`-w`/`-p`/`--password`/`-P`/`--pass` patterns) — a report is exactly the kind of file that gets shared outside the tool.
6. Add tests under `tests/` that feed synthetic phase output (tempdirs, no live scan) into the aggregator and assert on the resulting JSON/Markdown structure, including that redaction actually strips secrets.
7. Run `python -m unittest discover -s tests` and fix failures before calling it done.
