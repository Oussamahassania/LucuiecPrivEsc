"""
Users & Credentials Module
Checks:
- Current user privileges
- All users on system
- Sudo permissions
- Password hashes in /etc/shadow
- SSH keys
- Bash history (passwords typed in commands)
- Credential files (.netrc, .pgpass, etc.)
"""

import os
import re
from LD_PRELOAD.utils.output import print_found, print_info, print_warn, print_critical, run_cmd


def get_current_user() -> dict:
    """Who are we? What groups do we belong to?"""
    info = {}
    info["whoami"]  = run_cmd("whoami")
    info["id"]      = run_cmd("id")
    info["groups"]  = run_cmd("groups")
    info["home"]    = os.path.expanduser("~")

    print_found(f"[USER] {info['id']}")

    # Check for interesting group memberships
    dangerous_groups = ["sudo", "wheel", "docker", "lxd", "disk", "adm",
                        "shadow", "root", "dba", "video", "input", "kvm"]
    for grp in dangerous_groups:
        if grp in info["id"]:
            print_critical(f"[GROUP] 🚨 Member of '{grp}' group — potential privesc vector!")

    return info


def check_sudo() -> dict:
    """
    Check sudo permissions — the most common privesc path.
    sudo -l shows what commands we can run as root.
    """
    results = {}
    output = run_cmd("sudo -l 2>/dev/null")
    results["raw"] = output
    results["nopasswd"] = []
    results["all_entries"] = []

    if not output or "Sorry" in output or "not allowed" in output:
        print_info("No sudo privileges found.")
        return results

    print_found(f"[SUDO] Sudo entries found!")

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        results["all_entries"].append(line)

        # NOPASSWD = can run as root without password = easy win
        if "NOPASSWD" in line:
            results["nopasswd"].append(line)
            print_critical(f"[SUDO] 🚨 NOPASSWD: {line}")
            # Check GTFOBins-known binaries
            gtfo_bins = [
                "vim", "vi", "nano", "less", "more", "man", "awk", "perl",
                "python", "python3", "ruby", "lua", "php", "bash", "sh",
                "find", "nmap", "nc", "netcat", "curl", "wget", "tar",
                "zip", "unzip", "env", "cp", "mv", "chmod", "chown",
                "tee", "dd", "git", "make", "strace", "ltrace", "gdb",
                "docker", "kubectl", "mysql", "psql", "sqlite3",
                "node", "nodejs", "npm", "socat", "rlwrap",
                "cat", "head", "tail", "cut", "sort", "base64",
                "openssl", "ssh", "scp", "rsync", "ftp",
            ]
            for binary in gtfo_bins:
                if binary in line.lower():
                    print_critical(
                        f"[GTFO] 🔥 {binary} is NOPASSWD sudo → check GTFOBins: "
                        f"https://gtfobins.github.io/gtfobins/{binary}/"
                    )
        elif line.startswith("("):
            print_found(f"[SUDO] {line}")

    if "(ALL : ALL) ALL" in output or "(ALL) ALL" in output:
        print_critical("[SUDO] 🚨 Full sudo access! Just run: sudo su")

    return results


def read_passwd_shadow() -> dict:
    """Read /etc/passwd and /etc/shadow for user enumeration and hash cracking."""
    results = {}

    passwd = run_cmd("cat /etc/passwd")
    results["passwd"] = passwd
    results["users"] = []

    for line in passwd.split("\n"):
        parts = line.split(":")
        if len(parts) >= 7:
            username, pw, uid, gid, _, home, shell = parts[:7]
            uid = int(uid) if uid.isdigit() else -1

            # Root UID or shell users
            if uid == 0 and username != "root":
                print_critical(f"[PASSWD] 🚨 Hidden root account: {username} (UID=0)!")
            if shell not in ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin", ""]:
                results["users"].append({
                    "username": username, "uid": uid,
                    "home": home, "shell": shell
                })
                if uid >= 1000:
                    print_found(f"[USER] {username} (uid={uid}) shell={shell} home={home}")

    # Try to read shadow (requires root or shadow group)
    shadow = run_cmd("cat /etc/shadow 2>/dev/null")
    results["shadow"] = shadow
    if shadow and "Permission denied" not in shadow:
        print_critical("[SHADOW] 🚨 /etc/shadow is readable!")
        hashes = []
        for line in shadow.split("\n"):
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] not in ["*", "!", "", "x"]:
                hashes.append({"user": parts[0], "hash": parts[1]})
                print_critical(f"[HASH] {parts[0]}:{parts[1][:30]}... → crack with hashcat/john!")
        results["hashes"] = hashes

    return results


def check_ssh_keys() -> list:
    """Find SSH private keys — can be used for lateral movement or privesc."""
    keys_found = []

    search_paths = [
        os.path.expanduser("~/.ssh/"),
        "/root/.ssh/",
        "/home/*/.ssh/",
        "/etc/ssh/",
        "/tmp/",
        "/var/tmp/",
    ]

    # Search for private key files
    output = run_cmd(
        "find / -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' "
        "-o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' "
        "2>/dev/null | grep -v proc | head -30"
    )
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Check if readable
        content = run_cmd(f"cat '{line}' 2>/dev/null")
        if "PRIVATE KEY" in content:
            keys_found.append({"path": line, "content": content[:200]})
            print_critical(f"[SSH] 🚨 Private key found and readable: {line}")

    # Check authorized_keys
    auth_keys = run_cmd(
        "find / -name 'authorized_keys' 2>/dev/null | grep -v proc | head -10"
    )
    for line in auth_keys.split("\n"):
        if line.strip():
            content = run_cmd(f"cat '{line.strip()}' 2>/dev/null")
            print_found(f"[SSH] authorized_keys: {line.strip()}")

    return keys_found


def check_bash_history() -> list:
    """
    Read bash/shell history — users often type passwords in commands.
    e.g. mysql -u root -pPassword123
    """
    findings = []
    history_files = [
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.zsh_history"),
        os.path.expanduser("~/.sh_history"),
        "/root/.bash_history",
    ]

    # Also find other users' history
    other = run_cmd("find /home -name '.*history' 2>/dev/null")
    for line in other.split("\n"):
        if line.strip():
            history_files.append(line.strip())

    sensitive_patterns = [
        r'-p\s*\S+',           # -pPassword
        r'password[=:\s]\S+',  # password=xxx
        r'passwd\s+\S+',       # passwd newpass
        r'--password[=\s]\S+', # --password=xxx
        r'mysql.*-p\S+',       # mysql with password
        r'sshpass\s+-p\s*\S+', # sshpass -p password
        r'curl.*(-u|-H).*:\S+',# curl with credentials
    ]

    for hfile in history_files:
        content = run_cmd(f"cat '{hfile}' 2>/dev/null")
        if not content or "No such file" in content:
            continue

        print_info(f"[HIST] Reading: {hfile}")
        for i, line in enumerate(content.split("\n")):
            for pattern in sensitive_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({"file": hfile, "line": i+1, "content": line.strip()})
                    print_critical(f"[HIST] 🚨 Possible credential in {hfile} line {i+1}: {line.strip()}")
                    break

    return findings


def check_credential_files() -> list:
    """Check common credential storage files."""
    findings = []
    cred_files = [
        "~/.netrc",           # FTP/HTTP credentials
        "~/.pgpass",          # PostgreSQL passwords
        "~/.my.cnf",          # MySQL credentials
        "~/.ssh/config",      # SSH config (may have passwords)
        "/etc/fstab",         # May have credentials for network mounts
        "~/.aws/credentials", # AWS keys
        "~/.config/gcloud/",  # GCP credentials
        "~/.kube/config",     # Kubernetes config
        "/var/www/html/wp-config.php",     # WordPress DB creds
        "/var/www/html/config.php",
        "/var/www/html/.env",
        "/opt/*/config*",
        "/etc/apache2/.htpasswd",
        "/etc/nginx/.htpasswd",
    ]

    for path in cred_files:
        expanded = os.path.expanduser(path)
        content = run_cmd(f"cat '{expanded}' 2>/dev/null")
        if content and "No such file" not in content and "Permission denied" not in content:
            findings.append({"path": expanded, "content": content[:500]})
            print_critical(f"[CREDS] 🚨 Credential file readable: {expanded}")
            # Show juicy lines
            for line in content.split("\n")[:5]:
                if line.strip():
                    print(f"         → {line.strip()}")

    return findings


def run() -> dict:
    print_info("Enumerating users and credentials...")
    return {
        "current_user": get_current_user(),
        "sudo":         check_sudo(),
        "passwd":       read_passwd_shadow(),
        "ssh_keys":     check_ssh_keys(),
        "history":      check_bash_history(),
        "cred_files":   check_credential_files(),
    }