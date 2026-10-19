
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

Enhanced with:
  • Authorization confirmation for legal compliance
  • Safe mode for reconnaissance-only operations
  • Execution profiles (stealth/standard/aggressive/CTF)
  • Progress tracking with tqdm
  • Enhanced reporting (HTML/JSON/Markdown)
  • Docker support
  • Audit logging

Intended for AUTHORIZED penetration testing and CTF use only.
USE WITH EXPLICIT WRITTEN AUTHORIZATION.
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
from typing import Dict, List, Optional, Tuple, Any

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

# ──────────────────────────────────────────────────────────────────────────────
# PROGRESS BAR (optional)
# ──────────────────────────────────────────────────────────────────────────────

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    # Simple fallback
    class tqdm:
        def __init__(self, *args, **kwargs): 
            self.desc = kwargs.get('desc', '')
        def __enter__(self): 
            return self
        def __exit__(self, *args): 
            pass
        def update(self, *args): 
            pass
        def close(self): 
            pass
        def set_description(self, desc): 
            self.desc = desc

# ──────────────────────────────────────────────────────────────────────────────
# DISPLAY FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

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
# EXIT CODES
# ──────────────────────────────────────────────────────────────────────────────

class ExitCode(IntEnum):
    SUCCESS          = 0
    GENERAL_ERROR    = 1
    COMPLIANCE_FAIL  = 2
    MISSING_TARGET   = 3
    CONFIG_ERROR     = 4
    ENCRYPT_ERROR    = 5

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("rot05")

def setup_logging(output_dir: Path) -> None:
    log_file = output_dir / "rot05.log"
    output_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_file)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

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
# CONFIG FILE
# ──────────────────────────────────────────────────────────────────────────────

class ConfigFile:
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
        for k, v in self._load_raw().items():
            if k in self._SAFE_KEYS and hasattr(cfg, k):
                setattr(cfg, k, v)

    def save(self, cfg: "TargetConfig") -> None:
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
# RESULT ENCRYPTOR
# ──────────────────────────────────────────────────────────────────────────────

class ResultEncryptor:
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
# RATE LIMITER
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
# COMPLIANCE CHECKER
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
# GLOBALS
# ──────────────────────────────────────────────────────────────────────────────

OUTPUT_DIR: Path = Path("rot05_output")
DRY_RUN:    bool = False

# ──────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

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
    if is_port_open(ip, 443):
        out, _ = run(["curl", "-k", "-s", "-I", f"https://{ip}/owa/", "--max-time", "5"])
        svcs["Exchange"] = any(h in out for h in ("X-OWA-Version", "X-FEServer"))
    else:
        svcs["Exchange"] = False
    return svcs

# ──────────────────────────────────────────────────────────────────────────────
# PHASE WRAPPER
# ──────────────────────────────────────────────────────────────────────────────

def _phase(name: str, fn, ckpt: Optional[CheckpointManager], force: bool):
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
    def nmap(ip: str, ckpt: Optional[CheckpointManager] = None, force: bool = False):
        _phase("nmap", lambda: ADEnum._nmap_impl(ip), ckpt, force)
    
    @staticmethod
    def _nmap_impl(ip: str):
        title("Phase – NMAP Enumeration")
        if not require_tool("nmap"):
            return
        out = ensure_dir("nmap")

        with tqdm(total=3, desc="NMAP Scanning") as pbar:
            pbar.set_description("Full port scan")
            run(["nmap", "-Pn", "-p-", ip, "-vv", "-oA", str(out / "all-ports"),
                 "--min-rate", "2000"], outfile=out / "all-ports.log", timeout=600)
            pbar.update(1)

            ports = extract_ports(out / "all-ports.nmap")
            if not ports:
                warn("Port parse failed; using common DC ports.")
                ports = "53,88,135,139,389,445,464,593,636,3268,3269,3389"
            info(f"Open ports: {ports}")

 