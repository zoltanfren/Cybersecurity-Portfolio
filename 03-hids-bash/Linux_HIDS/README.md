# Host Intrusion Detection System

A modular, bash-based Host Intrusion Detection System (HIDS) for Linux. It monitors system health, user activity, running processes, network connections, and critical file integrity. Results are logged to a structured JSONL event log and optionally run on a recurring schedule via systemd.

> **Requirements:** Linux with systemd · `bash` 4.0+ · Root / sudo access · `ss`, `journalctl`, `sha256sum`, `find`, `last`

---

## Table of Contents

1. [What is a HIDS?](#1-what-is-a-hids)
2. [Project Structure](#2-project-structure)
3. [Module Overview](#3-module-overview)
4. [Configuration](#4-configuration)
5. [Installation & Systemd Setup](#5-installation--systemd-setup)
6. [Running Manually](#6-running-manually)
7. [Generating the File Integrity Baseline](#7-generating-the-file-integrity-baseline)
8. [Expected Output](#8-expected-output)
9. [Event Log Format](#9-event-log-format)
10. [Whitelist Configuration](#10-whitelist-configuration)
11. [Troubleshooting](#11-troubleshooting)
12. [Uninstallation](#12-uninstallation)
13. [Limitations & Known Issues](#13-limitations--known-issues)

---

## 1. What is a HIDS?

A **Host Intrusion Detection System** monitors a single machine for signs of compromise or policy violations. Unlike a network IDS (which inspects traffic between machines), a HIDS runs *on* the host itself and watches for things like:

- Unexpected changes to system files (`/etc/passwd`, SSH config, etc.)
- Logins at unusual hours or from unusual IP addresses
- Processes running from suspicious locations (`/tmp`, `/dev/shm`)
- High resource usage that may indicate cryptominers or denial-of-service
- New SUID binaries that could be used for privilege escalation

This tool is **detection-only** — it alerts and logs, but does not automatically block or remediate. That is by design: automated blocking can cause unintended service disruption and should only be added once the detection logic is well-tuned for your environment.

---

## 2. Project Structure

```
Project 4 - HIDS/
├── README.md                  ← You are here
├── research.md                ← Background research and references
├── run_hids.sh                ← Main orchestrator — run this
├── install.sh                 ← Installs systemd service and timer
├── generate_baseline.sh       ← Creates the file integrity baseline
├── config/
│   ├── hids.conf              ← All thresholds and settings
│   └── whitelist.conf         ← Trusted users and processes
├── logs/
│   └── alerts.log             ← Human-readable alert log
├── data/
│   └── file_baseline.db       ← SHA-256 baseline (generated at first run)
├── modules/
│   ├── alerting.sh            ← Shared logging/output functions
│   ├── system_health.sh       ← Module 1
│   ├── user_activity.sh       ← Module 2
│   ├── process_network.sh     ← Module 3
│   └── file_integrity.sh      ← Module 4
└── lib/
    ├── common.sh              ← Shared utilities
    └── helpers.sh             ← Helper functions
```

**Key principle:** `run_hids.sh` is the only entry point you need. It sources `alerting.sh`, checks for a baseline, presents the module selection menu, and calls each module in order. Modules are independent — they can also be run directly for testing.

---

## 3. Module Overview

### Module 1 — System Health (`system_health.sh`)

Reads live metrics from `/proc` and compares them against configurable thresholds with three severity levels (INFO / WARNING / CRITICAL).

| Check | What it detects |
|---|---|
| CPU usage | Sustained high CPU — possible cryptominer or brute-force script |
| Memory usage | High memory pressure — possible buffer overflow exploit or memory leak |
| Swap usage | Swap exhaustion — precursor to resource exhaustion attack |
| Disk usage | Disk full — attackers may flood logs to disable logging |
| Load average | Task queue overload relative to CPU core count |
| Zombie processes | Dead processes not yet reaped — can exhaust the PID table |
| I/O pressure | High disk wait — a signature pattern of ransomware encrypting files |

### Module 2 — User Activity (`user_activity.sh`)

Inspects login history and system journal for suspicious account behaviour.

| Check | What it detects |
|---|---|
| Off-hours logins | Logins outside configured business hours (default: 07:00–20:00) |
| New user accounts | Unexpected increase in UID ≥ 1000 accounts in `/etc/passwd` |
| Sudo escalation | High volume of `sudo` invocations in the last hour |
| Unusual source IPs | SSH logins from IPs outside the configured allowed subnet |

### Module 3 — Process & Network (`process_network.sh`)

Iterates over every running process in `/proc` and scores it based on risk heuristics.

| Signal | Score added | Why it matters |
|---|---|---|
| Executable in `/tmp`, `/dev/shm`, etc. | +3 | Attackers drop payloads in writable directories |
| Not in trusted system path | +1 | Legitimate OS binaries live in `/bin`, `/usr/bin` etc. |
| Binary has been deleted on disk | +5 | Classic fileless malware technique |
| Root process from untrusted path | +4 | High-privilege process with no business being there |
| Suspicious command-line pattern | +2 | Inline execution (`bash -c`, `python -c`), `nc`, `base64`, etc. |
| Network connections from untrusted binary | +3 | Possible C2 or data exfiltration |
| More than 8 simultaneous connections | +2 | Possible beaconing or port scanning |
| Untrusted binary listening on a port | +2 | Possible backdoor or reverse shell listener |

Processes with a **score ≥ 7** are CRITICAL, **≥ 4** are WARNING, others are INFO.

### Module 4 — File Integrity (`file_integrity.sh`)

Compares a snapshot of critical system files (taken at baseline time) against their current state.

| Check | What it detects |
|---|---|
| SHA-256 hash mismatch | File content has been modified |
| File missing | Critical file has been deleted since baseline |
| Permission change | e.g., `/etc/shadow` becoming world-readable |
| Owner change | Root-owned file reassigned to another user |
| New SUID binaries | Attacker-planted setuid binary for persistent root access |
| World-writable files in sensitive dirs | `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/root` |
| Recently modified `/etc` files | Files changed in the last 24 hours not in baseline |

---

## 4. Configuration

All settings live in `config/hids.conf`. You should review and adjust these before your first run.

### Threshold levels

Every metric has three thresholds:

- **INFO** — worth logging, probably fine
- **WARN** — investigate when you have time
- **CRIT** — investigate immediately

```bash
# Example: CPU thresholds
CPU_INFO=50   CPU_WARN=70   CPU_CRIT=90   # percentages
```

---

## 5. Installation & Systemd Setup

`install.sh` creates a **systemd service** (`hids.service`) and a **systemd timer** (`hids.timer`) that runs the HIDS automatically every 5 minutes.

### Step 1 — Clone or copy the project

```bash
git clone <your-repo-url> ~/Project 4 - HIDS
cd ~/Project 4 - HIDS
```

### Step 2 — Make scripts executable

```bash
chmod +x run_hids.sh install.sh generate_baseline.sh
chmod +x modules/*.sh
```

### Step 3 — Generate the file integrity baseline

This must be done **before** installing the service, so Module 4 has something to compare against. Root is required because some files (e.g. `/etc/shadow`) are only readable by root.

```bash
sudo bash generate_baseline.sh
```

The baseline is saved to `data/file_baseline.db`. Keep this file safe — if an attacker can modify the baseline, they can hide their changes.

### Step 4 — Run install.sh

```bash
sudo bash install.sh
```

`install.sh` does the following automatically:

1. Creates `/etc/systemd/system/hids.service` pointing to your project directory
2. Creates `/etc/systemd/system/hids.timer` set to fire 1 minute after boot, then every 5 minutes
3. Runs `systemctl daemon-reload` to register the new units
4. Enables the timer so it starts automatically on boot
5. Starts the timer immediately
6. Runs the service once right away so you can see initial output

### Step 5 — Verify the installation

```bash
# Check the timer is active and scheduled
sudo systemctl status hids.timer

# Check the last service run
sudo systemctl status hids.service

# View recent logs from the service
sudo journalctl -u hids.service -n 50
```

### Changing the run interval

Edit `/etc/systemd/system/hids.timer` and change `OnUnitActiveSec`:

```ini
[Timer]
OnBootSec=1min
OnUnitActiveSec=15min   # change this value
```

Then reload:

```bash
sudo systemctl daemon-reload
sudo systemctl restart hids.timer
```

---

## 6. Running Manually

You can run the HIDS at any time without the systemd timer:

```bash
# Run all modules interactively (you will be prompted)
sudo bash run_hids.sh

# Run a single module directly (useful for testing)
sudo bash modules/system_health.sh
sudo bash modules/user_activity.sh
sudo bash modules/process_network.sh
sudo bash modules/file_integrity.sh
```

When you run `run_hids.sh`, it presents a menu:

```
==========================================
  HIDS Module Selection
==========================================
  [1] System Health
  [2] User Activity
  [3] Process & Network
  [4] File Integrity

  [0] Run ALL modules
  Or enter numbers separated by spaces (e.g., 1 2 4)
```

---

## 7. Generating the File Integrity Baseline

The baseline records the SHA-256 hash, permissions, and owner of each monitored file. Module 4 compares the live state of these files against the baseline on every run.

```bash
sudo bash generate_baseline.sh
```

**When to regenerate the baseline:**

- After intentional system updates that modify files in `/etc` or system binaries
- After applying OS patches (`apt upgrade`, etc.)
- After making deliberate configuration changes (e.g., editing `sshd_config`)

**To regenerate and overwrite an existing baseline:**

```bash
# The script will ask for confirmation before overwriting
sudo bash generate_baseline.sh
```

> ⚠️ **Security note:** Only regenerate the baseline when you are confident the system is in a known-good state. Regenerating after a compromise would hide the attacker's changes.

---

## 8. Expected Output

Each module prints a header, its findings, and a summary block. Below are examples of what normal and alert output look like.

### Normal (clean) run

```
==========================================
  Module 1 — System Health Module
  2026-04-14T10:00:00
==========================================

[*] Checking CPU, Memory, Swap, Disk, Load Average, Zombies, I/O Pressure...

==========================================
  System Health Check Complete — 2026-04-14 10:00:01
  Status : CLEAN — no issues detected
  Log    : /home/user/Project 4 - HIDS/logs/alerts.log
==========================================
```

### Alert output

```
[CRITICAL] File missing — was present at baseline: /etc/sudoers
[CRITICAL] Hash mismatch detected: /etc/passwd
[CRITICAL]   Expected : a3f1...
[CRITICAL]   Current  : 9b2c...
[WARNING]  Permissions changed on /etc/shadow (was: 640, now: 644)
```

---

## 9. Event Log Format

All alerts are written to `config/events.jsonl` in newline-delimited JSON (one object per line):

```json
{"timestamp":"2026-04-14T14:52:32Z","level":"WARNING","message":"User \"alice\" login from 10.0.0.5 at Mon Apr 14 02:31:00 UTC (outside 7:00-20:00)"}
{"timestamp":"2026-04-14T14:56:38Z","level":"INFO","message":"PID=1010 USER=kali SCORE=1 REASONS=untrusted_path EXE=/usr/libexec/gvfsd"}
{"timestamp":"2026-04-14T15:00:01Z","level":"CRITICAL","message":"Hash mismatch detected: /etc/passwd"}
```

**Level values:** `INFO` · `WARNING` · `CRITICAL`

You can filter the log using standard tools:

```bash
# Show only CRITICAL events
grep '"level":"CRITICAL"' config/events.jsonl

# Show events from the last hour (requires jq)
jq 'select(.timestamp > "2026-04-14T14:00:00Z")' config/events.jsonl

# Count events by level
grep -o '"level":"[^"]*"' config/events.jsonl | sort | uniq -c
```

---

## 10. Whitelist Configuration

Two types of whitelisting are supported.

### Whitelisted users (`config/whitelist.conf`)

Users listed here are exempt from user activity alerts (off-hours login checks, etc.). Add system service accounts that legitimately log in at unusual hours:

```bash
WHITELISTED_USERS="lightdm postgres wtmpdb"
```

### Whitelisted processes (`config/whitelist.conf`)

Add full executable paths to suppress process alerts for known-good binaries. One path per line, comments with `#`:

```
# Monitoring agents
/usr/bin/prometheus-node-exporter
/opt/company/agent/daemon
```

### Adjusting trusted paths (`config/hids.conf`)

Rather than whitelisting individual binaries, you can add a trusted path prefix. Any executable under this path will be considered trusted:

```bash
TRUSTED_PATHS=(
  "/bin/"
  "/usr/bin/"
  "/usr/sbin/"
  "/usr/local/bin/"
  "/usr/libexec/"    # add this to stop flagging gnome/desktop daemons
)
```

---

## 11. Troubleshooting

### "alerting.sh not found"

`run_hids.sh` expects `modules/alerting.sh` to exist relative to the project root. Make sure you are running from inside the `Project 4 - HIDS/` directory, or that the script is finding its own path correctly:

```bash
cd ~/Project 4 - HIDS
sudo bash run_hids.sh
```

### "No baseline found" / Module 4 skipped

You need to generate the baseline before Module 4 can run:

```bash
sudo bash generate_baseline.sh
```

If the baseline file exists but is empty or corrupt, choose option **[2]** from the `run_hids.sh` menu to overwrite it, or delete it manually and re-run `generate_baseline.sh`.

### "Must be run as root"

Several checks require root access: reading `/etc/shadow` for hashing, scanning all of `/proc`, finding SUID binaries across the filesystem. Always run with `sudo`:

```bash
sudo bash run_hids.sh
```

### The systemd service exits immediately

The service is `Type=oneshot` — it runs once and exits, which is normal. Check that it completed successfully:

```bash
sudo systemctl status hids.service
sudo journalctl -u hids.service -n 100
```

If `ExecStart` fails to find the script, make sure the `WorkingDirectory` in `/etc/systemd/system/hids.service` still points to where the project lives. If you moved the folder after installing, re-run `install.sh`.

### Too many false positives from Module 3

On a desktop system (e.g., Kali with a GUI), you will see many INFO-level alerts for binaries in `/usr/libexec`. These are legitimate. To suppress them, either:

- Add `/usr/libexec/` to `TRUSTED_PATHS` in `hids.conf`
- Add specific paths to `whitelist.conf`

### Module 2 flags every login as off-hours

Adjust `BUSINESS_HOURS_START` and `BUSINESS_HOURS_END` in `hids.conf` to match your actual usage pattern. For a home lab running 24/7, you can set `BUSINESS_HOURS_START=0` and `BUSINESS_HOURS_END=24` to effectively disable this check.

### Log file not being written

Check that the directory exists and is writable:

```bash
ls -la config/
# If missing:
mkdir -p config logs data
touch config/events.jsonl
```

Also confirm `LOG_FILE` in `hids.conf` is set to `config/events.jsonl` (relative path from the project root).

### `journalctl` returns no SSH data

On some systems, SSH logs may go to `/var/log/auth.log` instead of the systemd journal. The `ip_check()` function in `user_activity.sh` uses `journalctl`; if your distro writes SSH logs elsewhere, you may need to adjust that function to read from the correct log file (`AUTH_LOG` is configurable in `hids.conf`).

---

## 12. Uninstallation

To fully remove the HIDS and its systemd units:

```bash
# Stop the timer and service
sudo systemctl stop hids.timer
sudo systemctl stop hids.service

# Disable so they don't start on next boot
sudo systemctl disable hids.timer
sudo systemctl disable hids.service

# Remove the unit files
sudo rm /etc/systemd/system/hids.service
sudo rm /etc/systemd/system/hids.timer

# Reload systemd to deregister the units
sudo systemctl daemon-reload
sudo systemctl reset-failed

# (Optional) Remove the project directory and all logs
rm -rf ~/Project 4 - HIDS
```

After uninstallation, confirm the units are gone:

```bash
sudo systemctl status hids.timer   # should say "could not be found"
```

---

## 13. Limitations & Known Issues

- **Detection only.** The HIDS alerts but does not block, quarantine, or remediate. Act on alerts manually.
- **Timestamp tampering.** The recently-modified file check in Module 4 uses `mtime`. A root attacker can fake `mtime` with `touch -t`. SHA-256 hashes (Part 1 of Module 4) are not affected by this.
- **Baseline integrity.** If the baseline file itself is modified by an attacker, Module 4 will not detect their changes. Store a copy of the baseline offline or on a read-only mount.
- **No alerting integrations.** Alerts are written to a local log file only. For a real deployment you would want to ship logs to a remote SIEM (Splunk, Elastic, etc.) so an attacker who owns the host cannot tamper with the log.
- **Module 3 false positives.** The process scoring heuristics produce many INFO-level hits on desktop environments. Tune the whitelist and trusted paths before relying on Module 3 in production.
- **Single-host only.** This is a HIDS, not a NIDS. It has no visibility into network traffic between machines.
- **No integrity protection of HIDS itself.** A sufficiently privileged attacker could modify the HIDS scripts to suppress their own activity. For stronger assurance, store the scripts on a read-only filesystem or verify their hashes out-of-band.