# Project 3 — Linux HIDS (Host Intrusion Detection System)

> **Modular host-based intrusion detection system written in Bash**  
> Team challenge | Duration: 7 days | Linux (systemd) | Bash 5+

---

## Overview

A host-based intrusion detection system (HIDS) built entirely in Bash for Linux systems. It runs four independent detection modules — system health, user activity, process/network analysis, and file integrity — and logs all findings as structured JSONL events that can be ingested by a SIEM.

The system operates in two modes: an interactive terminal mode where the user selects modules and baseline options, and an automatic mode when triggered by systemd, where all modules run silently without prompts. Installation deploys a systemd timer that runs the HIDS every 60 minutes.

---

## Repository Contents

```
03-hids-bash/
├── run_hids.sh                 # Orchestrator — dual mode (interactive / automatic)
├── generate_baseline.sh        # Creates the file integrity baseline (SHA-256)
├── install.sh                  # systemd service + timer installer
├── config/
│   ├── hids.conf               # All thresholds and configuration variables
│   └── whitelist.conf          # Whitelisted users and processes
├── modules/
│   ├── alerting.sh             # Shared logging engine (JSON output, color output)
│   ├── system_health.sh        # Module 1 — CPU, memory, disk, load, zombies, I/O
│   ├── user_activity.sh        # Module 2 — logins, new users, sudo, source IPs
│   ├── process_network.sh      # Module 3 — suspicious processes and connections
│   └── file_integrity.sh       # Module 4 — hash comparison, SUID, world-writable
├── data/
│   └── file_baseline.db        # Generated baseline (SHA-256 + permissions + owner)
├── logs/
│   └── events.jsonl            # Structured JSON log output
└── research.md                 # Research notes and design rationale
```

---

## Detection Modules

### Module 1 — System Health (`system_health.sh`)
Monitors key system metrics by reading directly from `/proc`. Each metric has three configurable thresholds: INFO, WARNING, and CRITICAL.

| Metric | Detection rationale |
|--------|-------------------|
| CPU usage | Sustained high CPU can indicate cryptominers or brute-force scripts |
| Memory usage | High usage may indicate buffer overflow exploitation or memory-hungry payloads |
| Swap usage | Resource exhaustion before the system hangs |
| Disk usage | Prevents log-flooding attacks where attackers fill disk to crash services |
| Load average | Task queue depth — high load signals abnormal concurrent activity |
| Zombie processes | Dead processes awaiting parent signal; can exhaust the PID table |
| I/O pressure | % of CPU time waiting on disk — a key ransomware encryption signature |

### Module 2 — User Activity (`user_activity.sh`)
Monitors login events and access patterns for anomalies.

- **Impossible timestamps** — flags logins outside configured business hours (default: 07:00–20:00), with exemptions for whitelisted system accounts
- **New resident users** — compares current UID ≥ 1000 account count against the expected baseline; alerts if a new account has been created
- **Privilege escalation** — counts `sudo` events via `journalctl` over the last hour; warns or triggers critical above configurable thresholds
- **Unusual source IPs** — parses SSH accepted/failed events and flags logins from outside the configured allowed subnet

### Module 3 — Process & Network (`process_network.sh`)
Reads process information from `/proc` without executing any inspected binary. Applies three layers of heuristics:

- **Filesystem location** — flags processes running from writable/ephemeral directories (`/tmp`, `/dev/shm`, `/run/user`, etc.)
- **Command-line patterns** — detects interpreter abuse and inline execution (`bash -c`, `python -c`, `base64`, `/dev/tcp/`, `curl`, `wget`, `nc`)
- **Network behavior** — flags processes with listening sockets, high outbound connection counts, or connections on suspicious ports (4444, 1337, 5555, 8081)

Kernel threads are skipped. Exact-path whitelisting is supported via `whitelist.conf`.

### Module 4 — File Integrity (`file_integrity.sh`)
Compares the current state of critical system files against a SHA-256 baseline.

- **Hash comparison** — detects any modification to monitored files since baseline was taken
- **Permission changes** — catches dangerous permission drift (e.g. `/etc/shadow` becoming world-readable)
- **Owner changes** — flags root-owned files being reassigned
- **New SUID binaries** — scans the full filesystem and alerts on any SUID binary not present at baseline time (attacker persistence technique)
- **World-writable files** — scans sensitive directories (`/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/root`) for world-writable files
- **Recent modifications** — catches changes to `/etc` files within the last 24 hours, including files not in the monitored baseline

Monitored files include `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/crontab`, PAM configs, and SSH authorized keys.

---

## Alerting & Logging (`alerting.sh`)

All modules share a central alerting engine that provides:

- **Color-coded console output** — INFO (blue), WARNING (orange), CRITICAL (red)
- **Structured JSONL logging** — every alert is written as a single JSON object to `logs/events.jsonl`
- **Automatic field extraction** — `KEY=value` pairs in alert messages are parsed into individual JSON fields for SIEM ingestion
- **Automatic module detection** — the source module name is captured from the call stack and included in every log entry

Example log entry:
```json
{
  "timestamp": "2026-03-01T14:22:03Z",
  "level": "CRITICAL",
  "module": "file_integrity",
  "message": "Hash mismatch detected: /etc/passwd",
  "value": "/etc/passwd"
}
```

---

## Configuration

All thresholds are centralized in `config/hids.conf` — no hardcoded values in modules.

```bash
# System health thresholds (INFO / WARN / CRIT)
CPU_INFO=50   CPU_WARN=70   CPU_CRIT=90
MEM_INFO=60   MEM_WARN=75   MEM_CRIT=90
DISK_INFO=60  DISK_WARN=75  DISK_CRIT=90

# User activity
BUSINESS_HOURS_START=7
BUSINESS_HOURS_END=20
EXPECTED_USER_COUNT=1
ALLOWED_IP_RANGE="192.168.1."

# Process & network
SUSPICIOUS_PATHS=("/tmp/" "/dev/shm/" "/var/tmp/" ...)
SUSPICIOUS_CMD_PATTERNS=("bash -c" "python -c" "base64" ...)
SUSPICIOUS_PORTS=("4444" "1337" "5555" "8081")
ESTABLISHED_CONN_THRESHOLD=8
```

System accounts and known processes that would otherwise trigger false positives are exempted in `config/whitelist.conf`.

---

## Installation

```bash
sudo bash install.sh
```

The installer:
1. Creates `data/` and `logs/` directories
2. Generates the file integrity baseline if one does not exist
3. Creates a systemd service unit (`hids.service`)
4. Creates a systemd timer that runs the service every 60 minutes, starting 1 minute after boot
5. Enables and starts the timer

To run manually:
```bash
sudo bash run_hids.sh
```

To regenerate the file integrity baseline:
```bash
sudo bash generate_baseline.sh
```

---

## Dual-Mode Operation

`run_hids.sh` detects whether it is running in an interactive terminal (`-t 0 && -t 1`) or non-interactively (systemd/cron):

- **Interactive** — prompts for baseline handling and module selection
- **Automatic** — generates baseline if missing, runs all four modules without prompts

---

## Skills Demonstrated

- Bash scripting: functions, arrays, argument parsing, strict error handling (`set -euo pipefail`)
- Linux internals: reading `/proc/stat`, `/proc/meminfo`, `/proc/pressure/io`, `/proc/<pid>/status`
- File integrity monitoring: SHA-256 baseline comparison, SUID detection, permission tracking
- Log analysis: `journalctl`, `last`, `/etc/passwd` parsing
- Structured logging: JSONL output with dynamic field extraction for SIEM compatibility
- systemd: service and timer unit creation via installer
- Security concepts: defense-in-depth, false positive reduction via whitelisting, attacker TTP mapping
