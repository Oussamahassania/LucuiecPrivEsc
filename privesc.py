#!/usr/bin/env python3
"""
PrivEsc — Linux Privilege Escalation Tool v1.0
Fast, comprehensive, with exploit suggestions.
For use on authorized VMs, CTF, TryHackMe, HackTheBox.

CHECKS:
  1. System Info      — OS, kernel, arch, network, env variables
  2. Users & Creds    — sudo -l, passwd/shadow, SSH keys, history, cred files
  3. SUID/SGID/Caps   — GTFOBins matching + exploit commands
  4. Cron & Writable  — Writable cron scripts, /etc/passwd, PATH hijack, services
  5. Kernel Exploits  — DirtyPipe, DirtyCow, PwnKit, Baron Samedit + more
  6. Misc             — Containers, NFS no_root_squash, interesting files, LD_PRELOAD

USAGE:
  Full scan:          python privesc.py
  Quick (fast):       python privesc.py --quick
  Single module:      python privesc.py --suid
  With output:        python privesc.py --all -o /tmp/results
"""

import argparse
import sys
import os
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))

from LD_PRELOAD.utils.output import (
    print_banner, print_info, print_error, print_warn,
    print_section, print_summary, print_critical, save_results
)

import modules.sysinfo        as sysinfo_module
import modules.users_creds    as users_module
import envfiles.suid_caps      as suid_module
import capabilities.cron_writable  as cron_module
import hijack.kernel_exploits as kernel_module
import Samedit.misc_checks    as misc_module


def parse_args():
    parser = argparse.ArgumentParser(
        description="PrivEsc — Linux Privilege Escalation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mods = parser.add_argument_group("Modules")
    mods.add_argument("--all",    action="store_true", help="Run all checks (default)")
    mods.add_argument("--quick",  action="store_true", help="Quick scan — highest impact checks only")
    mods.add_argument("--sysinfo",action="store_true", help="System information")
    mods.add_argument("--users",  action="store_true", help="Users, sudo, credentials, history")
    mods.add_argument("--suid",   action="store_true", help="SUID/SGID binaries + capabilities")
    mods.add_argument("--cron",   action="store_true", help="Cron jobs + writable files")
    mods.add_argument("--kernel", action="store_true", help="Kernel exploits + vulnerable software")
    mods.add_argument("--misc",   action="store_true", help="Containers, NFS, processes, files")

    opts = parser.add_argument_group("Options")
    opts.add_argument("-o", "--output",   default="results", help="Output directory")
    opts.add_argument("--no-save",        action="store_true", help="Don't save results")
    opts.add_argument("--no-color",       action="store_true", help="Disable colors")
    opts.add_argument("--parallel",       action="store_true", help="Run modules in parallel (faster)")
    opts.add_argument("--critical-only",  action="store_true", help="Only show CRITICAL findings")

    return parser.parse_args()


def run_module(name: str, func, *args) -> tuple:
    """Run a module and return (name, result) — catches all errors."""
    try:
        result = func(*args)
        return name, result
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print_error(f"Module {name} error: {e}")
        return name, {}


def spinner(stop_event, message):
    """Simple spinner for long-running operations."""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    while not stop_event.is_set():
        print(f"\r  {chars[i % len(chars)]} {message}...", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print("\r" + " " * (len(message) + 10) + "\r", end="")


def main():
    print_banner()
    args = parse_args()

    # Default to --all if nothing selected
    if not any([args.all, args.quick, args.sysinfo, args.users,
                args.suid, args.cron, args.kernel, args.misc]):
        args.all = True

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    whoami = os.popen("whoami").read().strip()
    hostname = os.popen("hostname").read().strip()

    print_info(f"Started  : {timestamp}")
    print_info(f"Running as: {whoami}@{hostname}")
    print_warn("Ensure you have permission to run this on this system!\n")

    results = {
        "timestamp": timestamp,
        "user":      whoami,
        "hostname":  hostname,
    }

    # ── QUICK MODE — highest impact checks only ───────────────────────────
    if args.quick:
        print_section("⚡ QUICK SCAN — HIGH IMPACT CHECKS")
        from LD_PRELOAD.utils.output import run_cmd

        print_info("1. Sudo permissions:")
        print(run_cmd("sudo -l 2>/dev/null") or "  (nothing)")

        print_info("\n2. SUID binaries (known exploitable):")
        suid_out = run_cmd("find / -perm -4000 2>/dev/null | grep -v proc")
        gtfo = ["vim","vi","bash","find","python","python3","perl","ruby","php",
                "awk","less","more","man","cp","mv","env","tee","dd","curl","wget",
                "nmap","nc","netcat","pkexec","node","docker"]
        for line in suid_out.split("\n"):
            if any(g in line for g in gtfo):
                print_critical(f"  SUID: {line.strip()}")

        print_info("\n3. Capabilities:")
        print(run_cmd("getcap -r / 2>/dev/null") or "  (none)")

        print_info("\n4. Writable /etc/passwd:")
        print(run_cmd("ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null"))

        print_info("\n5. Interesting cron jobs:")
        print(run_cmd("cat /etc/crontab 2>/dev/null") or "  (empty)")

        print_info("\n6. Kernel version:")
        print(run_cmd("uname -a"))

        print_info("\n7. Writable files in /etc:")
        print(run_cmd("find /etc -writable 2>/dev/null | head -10") or "  (none)")

        print_info("\n8. SSH keys:")
        print(run_cmd("find / -name 'id_rsa' -readable 2>/dev/null | head -5") or "  (none)")
        return

    # ── FULL SCAN ─────────────────────────────────────────────────────────
    modules_to_run = []

    if args.all or args.sysinfo:
        modules_to_run.append(("sysinfo", sysinfo_module.run))
    if args.all or args.users:
        modules_to_run.append(("users", users_module.run))
    if args.all or args.suid:
        modules_to_run.append(("suid", suid_module.run))
    if args.all or args.cron:
        modules_to_run.append(("cron", cron_module.run))
    if args.all or args.kernel:
        modules_to_run.append(("kernel", kernel_module.run))
    if args.all or args.misc:
        modules_to_run.append(("misc", misc_module.run))

    if args.parallel and not args.critical_only:
        # ── Parallel execution ──
        print_info(f"Running {len(modules_to_run)} modules in parallel...")
        module_map = {
            "sysinfo": "🖥️  MODULE 1: SYSTEM INFORMATION",
            "users":   "👤 MODULE 2: USERS & CREDENTIALS",
            "suid":    "🔑 MODULE 3: SUID/SGID & CAPABILITIES",
            "cron":    "⏰ MODULE 4: CRON JOBS & WRITABLE FILES",
            "kernel":  "💣 MODULE 5: KERNEL EXPLOITS",
            "misc":    "🔍 MODULE 6: MISC CHECKS",
        }
        with ThreadPoolExecutor(max_workers=len(modules_to_run)) as executor:
            futures = {
                executor.submit(run_module, name, func): name
                for name, func in modules_to_run
            }
            for future in as_completed(futures):
                name, result = future.result()
                results[name] = result
    else:
        # ── Sequential execution ──
        module_titles = {
            "sysinfo": "🖥️  MODULE 1: SYSTEM INFORMATION",
            "users":   "👤 MODULE 2: USERS & CREDENTIALS",
            "suid":    "🔑 MODULE 3: SUID/SGID & CAPABILITIES",
            "cron":    "⏰ MODULE 4: CRON JOBS & WRITABLE FILES",
            "kernel":  "💣 MODULE 5: KERNEL EXPLOITS",
            "misc":    "🔍 MODULE 6: MISC CHECKS",
        }
        for name, func in modules_to_run:
            title = module_titles.get(name, name.upper())
            print_section(title)
            _, result = run_module(name, func)
            results[name] = result

    # ── Summary ───────────────────────────────────────────────────────────
    print_summary(results)

    if not args.no_save:
        save_results(results, output_dir=args.output)

    print_info("PrivEsc scan complete! 🎯")


if __name__ == "__main__":
    main()