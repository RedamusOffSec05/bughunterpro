#!/usr/bin/env bash
# entrypoint.sh — configure auth at runtime, then exec the requested command
set -euo pipefail

# ── Claude Code Router config ─────────────────────────────────────────────────
CCR_CONFIG="$HOME/.claude-code-router/config.json"
CCR_TEMPLATE="/app/scripts/ccr-config-template.json"

if [[ ! -f "$CCR_CONFIG" && -f "$CCR_TEMPLATE" ]]; then
    cp "$CCR_TEMPLATE" "$CCR_CONFIG"
fi

# Inject OPENROUTER_API_KEY into CCR config if provided
if [[ -n "${OPENROUTER_API_KEY:-}" && -f "$CCR_CONFIG" ]]; then
    tmp=$(mktemp)
    jq --arg key "$OPENROUTER_API_KEY" \
       '.providers[] |= if .name == "openrouter" then .apiKey = $key else . end' \
       "$CCR_CONFIG" > "$tmp" && mv "$tmp" "$CCR_CONFIG"
fi

# ── API key validation ────────────────────────────────────────────────────────
if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${OPENROUTER_API_KEY:-}" ]]; then
    echo "[!] WARNING: Neither ANTHROPIC_API_KEY nor OPENROUTER_API_KEY is set."
    echo "    Set one via -e ANTHROPIC_API_KEY=sk-... when running the container."
fi

# ── Announce available tools ──────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     PentestGPT + ROT05 — AD Pentesting Container         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  rot05 --help                 AD pentesting toolkit"
echo "  rot05 -t <IP> --enum         enumerate a target"
echo "  rot05 -t <IP> --full         full attack chain"
echo "  rot05 --dry-run -t <IP> --enum   preview commands"
echo ""
echo "  Output saved to: /workspace/<run>/"
echo ""

exec "$@"
