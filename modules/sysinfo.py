"""
System Information Module
Collects deep OS, kernel, hardware, and environment info.
"""

import subprocess
import os
import platform
from LD_PRELOAD.utils.output import print_found, print_info, print_warn, run_cmd


def get_os_info() -> dict:
    info = {}

    info["hostname"]    = run_cmd("hostname")
    info["kernel"]      = run_cmd("uname -r")
    info["arch"]        = run_cmd("uname -m")
    info["os_release"]  = run_cmd("cat /etc/os-release")
    info["uname_full"]  = run_cmd("uname -a")
    info["uptime"]      = run_cmd("uptime")
    info["date"]        = run_cmd("date")
    info["cpu"]         = run_cmd("lscpu | grep 'Model name'")
    info["memory"]      = run_cmd("free -h")
    info["disk"]        = run_cmd("df -h")

    print_found(f"[OS]     {info['uname_full']}")
    print_found(f"[HOST]   {info['hostname']}")
    print_found(f"[KERNEL] {info['kernel']}")
    print_found(f"[ARCH]   {info['arch']}")

    return info


def get_env_variables() -> dict:
    """Dump environment variables — may contain passwords, tokens, paths."""
    env = dict(os.environ)
    sensitive_keys = ["pass", "secret", "token", "key", "pwd", "api", "auth",
                      "aws", "azure", "database", "db_", "credential"]

    juicy = {}
    for k, v in env.items():
        if any(s in k.lower() for s in sensitive_keys):
            juicy[k] = v
            print_found(f"[ENV] 🔑 {k}={v}")

    if not juicy:
        print_info("No sensitive env variables found.")

    return {"all": env, "sensitive": juicy}


def get_mounts_and_drives() -> list:
    """Check mounted filesystems — NFS, CIFS mounts may be exploitable."""
    results = []
    output = run_cmd("mount")
    for line in output.split("\n"):
        if any(x in line for x in ["nfs", "cifs", "smb", "fuse", "tmpfs", "rw"]):
            results.append(line.strip())
            if any(x in line for x in ["nfs", "cifs", "smb"]):
                print_found(f"[MOUNT] ⚠️  Network mount: {line.strip()}")
            else:
                print_info(f"[MOUNT] {line.strip()}")
    return results


def get_network_info() -> dict:
    """Collect network interfaces, routes, open connections."""
    info = {}
    info["interfaces"] = run_cmd("ip a 2>/dev/null || ifconfig 2>/dev/null")
    info["routes"]     = run_cmd("ip route 2>/dev/null || route -n 2>/dev/null")
    info["hosts"]      = run_cmd("cat /etc/hosts")
    info["dns"]        = run_cmd("cat /etc/resolv.conf")
    info["netstat"]    = run_cmd("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")
    info["arp"]        = run_cmd("arp -a 2>/dev/null")

    # Look for listening services on unusual ports
    for line in info["netstat"].split("\n"):
        if "LISTEN" in line:
            print_info(f"[NET] {line.strip()}")

    return info


def run() -> dict:
    print_info("Collecting system information...")
    return {
        "os":      get_os_info(),
        "env":     get_env_variables(),
        "mounts":  get_mounts_and_drives(),
        "network": get_network_info(),
    }