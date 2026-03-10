"""
Output utilities for PrivEsc Tool
Color-coded by severity: CRITICAL (red) > WARN (yellow) > INFO (blue) > FOUND (green)
"""

import subprocess
import json
import os
from datetime import datetime

# Try colorama, fallback to plain
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = YELLOW = GREEN = CYAN = BLUE = MAGENTA = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = ""


def print_banner():
    banner = f"""
{Fore.RED}{Style.BRIGHT}
 ██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗
 ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝
 ██████╔╝██████╔╝██║██║   ██║█████╗  ███████╗██║
 ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ╚════██║██║
 ██║     ██║  ██║██║ ╚████╔╝ ███████╗███████║╚██████╗
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝
{Fore.YELLOW}         🔓 Linux Privilege Escalation Tool v1.0
{Fore.RED}         ⚠️  For authorized lab/CTF use ONLY
{Style.RESET_ALL}"""
    print(banner)


def print_info(msg: str):
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

def print_found(msg: str):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def print_warn(msg: str):
    print(f"{Fore.YELLOW}[-]{Style.RESET_ALL} {msg}")

def print_error(msg: str):
    print(f"{Fore.RED}[!]{Style.RESET_ALL} {msg}")

def print_critical(msg: str):
    """Red bold for HIGH IMPACT findings."""
    print(f"{Fore.RED}{Style.BRIGHT}[!!!]{Style.RESET_ALL} {msg}")

def print_section(title: str):
    print(f"\n{Fore.RED}{'═' * 65}")
    print(f"  {title}")
    print(f"{'═' * 65}{Style.RESET_ALL}\n")


def run_cmd(cmd: str, timeout: int = 15) -> str:
    """
    Execute a shell command safely and return output.
    Returns empty string on failure — never crashes the tool.
    """
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return (result.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def print_summary(results: dict):
    """Print color-coded summary of all findings by severity."""
    print_section("🏆 PRIVILEGE ESCALATION SUMMARY")

    critical = []
    warnings = []

    # Collect all critical findings
    users = results.get("users", {})

    # Sudo NOPASSWD
    nopasswd = users.get("sudo", {}).get("nopasswd", [])
    for entry in nopasswd:
        critical.append(f"SUDO NOPASSWD: {entry}")

    # SUID exploitable
    suid = results.get("suid", {})
    for s in suid.get("suid_sgid", []):
        if s.get("exploitable"):
            critical.append(f"SUID EXPLOITABLE: {s['path']} → {s['exploit'][:60]}")

    # Capabilities
    for cap in suid.get("capabilities", []):
        if cap.get("dangerous"):
            critical.append(f"DANGEROUS CAPABILITY: {cap['binary']} = {cap['capabilities']}")

    # Cron writable
    cron = results.get("cron", {})
    for c in cron.get("cron", []):
        if c.get("type") == "writable_cron_script":
            critical.append(f"WRITABLE CRON: {c.get('script')}")

    # Writable critical files
    for f in cron.get("writable_files", []):
        critical.append(f"WRITABLE: {f['path']}")

    # Kernel exploits
    kernel = results.get("kernel", {})
    for k in kernel.get("kernel_exploits", []):
        critical.append(f"KERNEL EXPLOIT: {k['name']} ({k['cve']})")

    # SSH keys
    for key in users.get("ssh_keys", []):
        critical.append(f"SSH PRIVATE KEY: {key['path']}")

    # Containers
    misc = results.get("misc", {})
    container = misc.get("containers", {})
    for escape in container.get("escapes", []):
        critical.append(f"CONTAINER ESCAPE: {escape}")

    # Shadow readable
    shadow = users.get("passwd", {}).get("shadow", "")
    if shadow and "Permission denied" not in shadow and shadow:
        critical.append("SHADOW FILE READABLE — extract and crack hashes!")

    # PATH hijacking
    for p in cron.get("path_hijack", []):
        warnings.append(f"WRITABLE PATH DIR: {p}")

    # Print results
    print(f"\n  {Fore.RED}{Style.BRIGHT}🔥 CRITICAL FINDINGS ({len(critical)}):{Style.RESET_ALL}")
    if critical:
        for i, finding in enumerate(critical, 1):
            print(f"  {Fore.RED}  [{i:02d}] {finding}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}  No critical findings.{Style.RESET_ALL}")

    print(f"\n  {Fore.YELLOW}⚠️  WARNINGS ({len(warnings)}):{Style.RESET_ALL}")
    if warnings:
        for w in warnings:
            print(f"  {Fore.YELLOW}  → {w}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}  None.{Style.RESET_ALL}")

    # Quick wins
    print(f"\n  {Fore.CYAN}🎯 QUICK WIN CHECKLIST:{Style.RESET_ALL}")
    checklist = [
        ("sudo -l", "Check sudo permissions"),
        ("find / -perm -4000 2>/dev/null", "Find SUID binaries"),
        ("getcap -r / 2>/dev/null", "Check capabilities"),
        ("cat /etc/crontab", "Check cron jobs"),
        ("cat /etc/passwd", "Check for UID=0 accounts"),
        ("ls -la /etc/shadow", "Check shadow permissions"),
        ("env", "Check environment variables"),
        ("ls -la ~/.ssh/", "Check SSH keys"),
    ]
    for cmd, desc in checklist:
        print(f"  {Fore.CYAN}  $ {cmd}{Style.RESET_ALL}  ← {desc}")


def save_results(results: dict, output_dir: str = "results") -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"{output_dir}/privesc_{ts}.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print_found(f"Results saved: {path}")
    return path