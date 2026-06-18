#!/usr/bin/env python3
"""
Configuration file support for BugHunterPro.

Supports YAML (requires pyyaml) and JSON.
Auto-detects bhp.yaml / bhp.yml / bhp.json in the current directory.
Loaded values are deep-merged over the built-in defaults.

Example bhp.yaml::

    mode: aggressive
    modules:
      passive_recon: true
      banner_grab: true
      credentials: true
    threads:
      dns: 20
      ports: 60
    output:
      formats: [json, markdown, html]
    credentials:
      rate: 1.5
"""

import json
from pathlib import Path

try:
    import yaml as _yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

DEFAULTS: dict = {
    "mode":    "normal",
    "verbose": False,
    "threads": {
        "dns":   15,
        "ports": 50,
    },
    "rate_limit": {
        "dns_semaphore": 15,
        "request_rate":  10.0,
        "request_burst": 20,
    },
    "output": {
        "formats": ["json", "markdown"],
        "dir":     ".",
    },
    "modules": {
        "subdomain_enum":  True,
        "port_scan":       True,
        "security_headers": True,
        "vuln_detect":     True,
        "passive_recon":   False,
        "banner_grab":     False,
        "credentials":     False,
    },
    "dns": {
        "retries":  2,
        "timeout":  1.5,
        "lifetime": 4.0,
    },
    "credentials": {
        "rate":     2.0,
        "wordlist": None,
    },
    "usb": {
        "host":       None,
        "port":       8080,
        "payloads":   [],
        "wifi_recon": False,
        "agent_recon": False,
    },
}


def load(path=None) -> dict:
    """
    Load config from a YAML or JSON file and merge over DEFAULTS.

    path=None auto-discovers bhp.yaml / bhp.yml / bhp.json in cwd.
    Raises FileNotFoundError if an explicit path is given and missing.
    """
    config = _deep_copy(DEFAULTS)

    if path is None:
        for candidate in ("bhp.yaml", "bhp.yml", "bhp.json"):
            if Path(candidate).exists():
                path = candidate
                break

    if path is None:
        return config

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = p.read_text(encoding="utf-8")

    if p.suffix in (".yaml", ".yml"):
        if not _YAML_OK:
            raise ImportError("pyyaml required for YAML config — pip install pyyaml")
        loaded = _yaml.safe_load(raw) or {}
    else:
        loaded = json.loads(raw)

    _deep_merge(config, loaded)
    return config


def _deep_copy(obj):
    """Minimal deep copy for plain dicts/lists."""
    if isinstance(obj, dict):
        return {k: _deep_copy(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_copy(v) for v in obj]
    return obj


def _deep_merge(base: dict, override: dict):
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
