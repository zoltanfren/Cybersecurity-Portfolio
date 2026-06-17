# HIDS Research Document

# Linux Host-Based Intrusion Detection System — Technical Reference

---

## Section 1 — System Health Monitoring

### What aspects of a running Linux system indicate health or stress?

A healthy Linux system maintains balance across four core resources: CPU, memory, disk I/O, and network. Stress manifests as sustained high utilization, queuing, or resource exhaustion.

**Key indicators of system stress:**

| Indicator | What it measures | Warning sign |
|---|---|---|
| Load average | Number of processes waiting for CPU or I/O | Sustained value above (core count × 1.5) |
| CPU utilization | Percentage of CPU cycles in use | Sustained > 85% for 5+ minutes |
| Memory pressure | RAM availability vs. demand | Swap usage > 10% of total |
| Disk usage | Filesystem capacity consumption | Any partition > 90% full |
| I/O wait | Time processes spend waiting for disk | Consistently high wa in top |

Commands for manual inspection: `ss -tulnp` (network sockets), `htop`/`top` (processes), `df -h` (disk free), `uptime` (load average).

### Where does Linux expose this information?

Linux exposes live system metrics through two primary interfaces:

**Commands:**

- `uptime` — displays load averages for 1, 5, and 15 minutes
- `free -h` — human-readable memory statistics
- `df -h` — filesystem disk space usage
- `top`/`htop` — dynamic process and resource viewer
- `iostat` — CPU and I/O statistics (requires `sysstat` package)

**The `/proc` virtual filesystem:**

| File | Contents |
|---|---|
| /proc/loadavg | 1, 5, and 15-minute load averages; runnable/total processes; last PID |
| /proc/meminfo | Detailed memory statistics (MemTotal, MemFree, MemAvailable, SwapTotal, SwapFree) |
| /proc/stat | Raw CPU tick counters (user, system, idle, iowait) — calculate percentages from deltas |
| /proc/net/dev | Network interface packet and byte counters |
| /proc/[PID]/status | Per-process state: name, UID, memory usage (VmRSS), parent PID |

The `/proc` filesystem is kernel-generated and exists only in memory. Reading it requires no special privileges for most metrics, making it ideal for HIDS monitoring scripts.

### What thresholds indicate a problem worth alerting on?

Alert fatigue is the primary enemy of effective monitoring. Thresholds must distinguish between normal spikes and genuine problems:

| Metric | Threshold | Rationale |
|---|---|---|
| CPU usage | > 85% sustained for 5 minutes | Short spikes are normal (program startup); sustained high usage suggests runaway processes, brute-force attacks, or cryptominers |
| Load average | > (CPU cores × 1.5) | Load of 3.0 on a 2-core system means processes are queuing; the system cannot keep up with demand |
| Disk usage | > 90% | At 100%, services crash (self-inflicted DoS). 90% provides reaction time. |
| Swap usage | > 10% | Heavy swap usage destroys performance; often the first sign of a memory leak in a compromised application |
| I/O wait | > 40% sustained | Indicates storage bottleneck or failing hardware |

> **Design decision:** Thresholds are configurable in `config/hids.conf` rather than hardcoded. A development VM and a production database server have different "normal" baselines.

---

## Section 2 — User Activity & Authentication Monitoring

### How does Linux record login activity?

Linux maintains three layers of login records, each serving a different investigative purpose:

| Record type | Storage | Command to read | What it shows |
|---|---|---|---|
| Current sessions | /run/utmp (binary) | who, w | Users currently logged in, their TTY, login time, and origin IP |
| Session history | /var/log/wtmp (binary) | last | Complete history of login/logout events with timestamps and source IPs |
| Failed attempts | /var/log/btmp (binary) | lastb | Every failed login attempt with username tried and source IP |

**Important:** `wtmp`, `btmp`, and `utmp` are binary files. They cannot be read with `cat` or `grep`. Use the dedicated commands (`last`, `lastb`, `who`) which parse the binary format correctly.

Text-based logs in `/var/log/` provide additional detail:

- `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS): Every authentication event including SSH connections, sudo usage, su attempts, and PAM operations

### What user activity is suspicious on a production server?

Production servers exhibit predictable patterns. Deviation from baseline is the indicator, not absolute values:

| Suspicious indicator | What to check | Investigation approach |
|---|---|---|
| Impossible travel | Same user logged in from geographically distant IPs within impossible timeframes | Correlate last output with IP geolocation |
| Off-hours access | Logins outside business hours for interactive users | Compare login times against user role expectations |
| New user accounts | Sudden appearance of accounts not in baseline | Monitor /etc/passwd for additions; cross-reference with change tickets |
| Privilege escalation | sudo or su usage by non-admin users | Review /var/log/auth.log for sudo commands and authentication failures |
| Brute force patterns | High volume of failed attempts followed by success | lastb showing 50+ attempts for same username, then last showing successful login |
| Unusual source IPs | Connections from unexpected networks or countries | Filter last output by IP ranges; flag external IPs for internal-only servers |
| Root direct login | SSH as root instead of via sudo | Check last root — should be rare or never on properly configured systems |

> **Design decision:** Module 2 reads `/var/log/auth.log` and correlates with `/var/log/btmp` data. A single failed login is `INFO`; 5+ failures in 10 minutes from one IP is `WARNING`; successful login after brute force pattern is `CRITICAL`.

---

## Section 3 — Process Monitoring

### How do you get a full picture of running processes?

Complete process visibility requires both command-line tools and direct `/proc` inspection:

**Commands:**

- `ps aux` — snapshot of all processes with resource usage
- `top`/`htop` — dynamic, sortable process viewer
- `pstree` — hierarchical view showing parent-child relationships
- `pgrep` — find PIDs by name or attributes

**The `/proc/[PID]/` directories:**

Each running process has a directory named after its PID. Key files:

| File | Contents |
|---|---|
| /proc/[PID]/status | Human-readable state: Name, Uid, Gid, VmRSS (memory), State (R/S/Z), PPid |
| /proc/[PID]/cmdline | Full command line that started the process (null-separated) |
| /proc/[PID]/exe | Symbolic link to the actual executable file |
| /proc/[PID]/cwd | Symbolic link to current working directory |
| /proc/[PID]/fd/ | Directory of open file descriptors |

### What makes a process suspicious?

Process name alone is unreliable — attackers rename malware to `systemd` or `crond`. Behavioral indicators are more trustworthy:

| Suspicious characteristic | Why it matters | Detection method |
|---|---|---|
| Execution from /tmp/ or /dev/shm/ | Temporary directories are world-writable and often used to drop malicious payloads | Check cwd and exe symlinks in /proc/[PID]/ |
| No associated binary (deleted executable) | Malware often deletes itself from disk after loading to evade file-based detection | exe symlink shows (deleted) |
| Running as root but started by non-root user | Indicates privilege escalation | Check Uid: line in status file against session ownership |
| Unusual parent-child relationships | bash spawning from httpd suggests web shell; nc (netcat) as child of apache suggests reverse shell | Trace PPid chain through /proc/[PID]/status |
| High resource consumption without known purpose | Cryptominers consume CPU; exfiltration consumes bandwidth | Monitor CPU% and network counters in /proc/[PID]/stat |
| Open network connections from unexpected processes | Database server process connecting to external IP is unusual | Correlate /proc/[PID]/fd/ with ss -tulnp output |

> **Design decision:** Process monitoring focuses on execution path and parentage, not names. A binary running from `/tmp` with a deleted executable and an outbound connection triggers `CRITICAL` regardless of what it calls itself.

---

## Section 4 — Network Monitoring

### How do you inspect listening ports and active connections?

Modern Linux provides `ss` (socket statistics) as the replacement for the deprecated `netstat`:

| Command | Purpose |
|---|---|
| ss -tulnp | All TCP/UDP listening sockets, with process name and PID |
| ss -tunap | All connections (established, listening, time-wait), with process association |
| lsof -i | List open files (including network sockets) with process details |
| ss -s | Socket summary statistics |

**The `/proc/net/` files:**

| File | Contents |
|---|---|
| /proc/net/tcp | All TCP sockets: local/remote addresses, state, inode (linkable to process via /proc/[PID]/fd/) |
| /proc/net/udp | All UDP sockets |
| /proc/net/dev | Per-interface packet and byte counters |

### What network activity is a red flag?

| Suspicious activity | Indicators | Severity |
|---|---|---|
| Unexpected listening port | Port not in baseline suddenly open | WARNING or CRITICAL depending on port (22 vs 4444) |
| Reverse shell | Process like bash or sh with established outbound connection to external IP | CRITICAL |
| Data exfiltration | Large outbound transfer from unexpected process | WARNING (requires threshold tuning) |
| Connection to known-bad IPs | Matches threat intelligence feeds | CRITICAL |
| High connection count from single source | Potential DDoS or scanning | WARNING |
| Process in /tmp with network activity | Malware staging or command-and-control | CRITICAL |

Common attack ports to flag immediately:

- 4444 (Metasploit default)
- 1234, 1337 (common attacker choices)
- Any high port (>10000) with a shell process attached

> **Design decision:** Network monitoring baselines expected ports on first run. New listening ports trigger alerts. Established connections are logged but only alerted on if they match suspicious process patterns (e.g., shell processes with outbound connections).

---

## Section 5 — File Integrity Monitoring

### Which files are critical enough that any unexpected change should trigger an alert?

Critical files fall into four categories:

**Identity & Authentication**

| File | Contents |
|---|---|
| /proc/loadavg | 1, 5, and 15-minute load averages; runnable/total processes; last PID |
| /proc/meminfo | Detailed memory statistics (MemTotal, MemFree, MemAvailable, SwapTotal, SwapFree) |
| /proc/stat | Raw CPU tick counters (user, system, idle, iowait) — calculate percentages from deltas |
| /proc/net/dev | Network interface packet and byte counters |
| /proc/[PID]/status | Per-process state: name, UID, memory usage (VmRSS), parent PID |0

`/etc/passwd` is intentionally world-readable, as many system utilities need it to resolve user IDs to names. The actual password hashes were separated into `/etc/shadow` specifically to keep sensitive credential data away from unprivileged users. Any modification to either file — especially `/etc/sudoers` — is a high-priority indicator of compromise.

**Boot & Startup (persistence vectors)**

| File | Contents |
|---|---|
| /proc/loadavg | 1, 5, and 15-minute load averages; runnable/total processes; last PID |
| /proc/meminfo | Detailed memory statistics (MemTotal, MemFree, MemAvailable, SwapTotal, SwapFree) |
| /proc/stat | Raw CPU tick counters (user, system, idle, iowait) — calculate percentages from deltas |
| /proc/net/dev | Network interface packet and byte counters |
| /proc/[PID]/status | Per-process state: name, UID, memory usage (VmRSS), parent PID |1

Attackers frequently plant entries in cron or systemd to maintain persistence after the initial compromise. Any unexpected addition to these locations warrants immediate investigation.

**Authentication Behaviour**

| File | Contents |
|---|---|
| /proc/loadavg | 1, 5, and 15-minute load averages; runnable/total processes; last PID |
| /proc/meminfo | Detailed memory statistics (MemTotal, MemFree, MemAvailable, SwapTotal, SwapFree) |
| /proc/stat | Raw CPU tick counters (user, system, idle, iowait) — calculate percentages from deltas |
| /proc/net/dev | Network interface packet and byte counters |
| /proc/[PID]/status | Per-process state: name, UID, memory usage (VmRSS), parent PID |2

**System Binaries**

| File | Contents |
|---|---|
| /proc/loadavg | 1, 5, and 15-minute load averages; runnable/total processes; last PID |
| /proc/meminfo | Detailed memory statistics (MemTotal, MemFree, MemAvailable, SwapTotal, SwapFree) |
| /proc/stat | Raw CPU tick counters (user, system, idle, iowait) — calculate percentages from deltas |
| /proc/net/dev | Network interface packet and byte counters |
| /proc/[PID]/status | Per-process state: name, UID, memory usage (VmRSS), parent PID |3

> **Design decision:** We baseline-hash all files in the four categories above on first run and compare on every subsequent run. Any hash mismatch triggers a `CRITICAL` alert.

### What file attributes or permissions settings are known to be dangerous if misconfigured?

**SUID bit (`u+s`)**

When a file has the SUID bit set, it executes with the *owner's* privileges rather than the caller's. A root-owned SUID binary that can be exploited allows any user to escalate to root. For example, `/usr/bin/passwd` has the SUID bit set specifically so regular users can update their own password in `/etc/shadow` without needing root access directly — but the same mechanism, applied to arbitrary binaries, becomes a privilege escalation vector.

Detection command:

```bash
find / -perm -4000 -type f 2>/dev/null
```

**World-writable files (`o+w`)**

Any user on the system can modify a world-writable file. If such a file is executed by a privileged process (e.g. a startup script owned by root), an attacker can inject malicious code without needing elevated access themselves.

Detection command:

```bash
find / -perm -002 -type f 2>/dev/null
```

**Incorrect permissions on sensitive files**

- `/etc/passwd` should be `644` (world-readable, root-writable only)
- `/etc/shadow` should be `640` or `000` (readable only by root or the shadow group)
- Any deviation from these expected values — particularly `/etc/shadow` becoming world-readable — is a critical misconfiguration that exposes password hashes to offline cracking attacks

> **Design decision:** Module 4 scans for SUID binaries and world-writable files on each run. On first run, we record the known-good SUID list as a baseline. On subsequent runs, any new SUID binary not in the baseline triggers a `CRITICAL` alert.

### How do you detect whether a file was modified recently?

There are three main approaches, with different trade-offs:

**1. `find` by modification time**

```bash
# Files modified in the last 24 hours
find /etc -mtime -1

# Files modified more recently than a reference timestamp
find /etc -newer /tmp/hids_last_run
```

Fast and simple, but relies on filesystem metadata. An attacker with root access can manipulate timestamps using `touch -t`, making this a supporting signal rather than a primary detection method.

**2. `ls -lt` — sort by modification time**

```bash
ls -lt /etc/ | head -20
```

Useful for quick manual inspection during incident response, but not suitable for automated scripted detection.

**3. Cryptographic hashing — the correct HIDS approach**

On first run, record the SHA-256 hash of each critical file:

```bash
sha256sum /etc/passwd /etc/shadow /etc/sudoers > /var/lib/hids/baseline_hashes.txt
```

On each subsequent run, recompute and compare:

```bash
sha256sum --check /var/lib/hids/baseline_hashes.txt
```

If even a single byte has changed, the hash will be completely different. This approach cannot be defeated by timestamp manipulation — the hash is derived from the file's actual content, not its metadata. This is the approach used by professional tools such as Tripwire and OSSEC/Wazuh.

> **Design decision:** We use `sha256sum` for baseline comparison. The baseline is generated on first run and stored in `data/file_baseline.db`. Any hash mismatch triggers a `CRITICAL` alert, alongside the filename and both the expected and current hash values.

---

## Section 6 — Logging & Alerting

### Where do Linux systems store their logs by default?

All default log files live under `/var/log/`. The exact filenames differ slightly between distributions:

| File | Contents |
|---|---|
| /proc/loadavg | 1, 5, and 15-minute load averages; runnable/total processes; last PID |
| /proc/meminfo | Detailed memory statistics (MemTotal, MemFree, MemAvailable, SwapTotal, SwapFree) |
| /proc/stat | Raw CPU tick counters (user, system, idle, iowait) — calculate percentages from deltas |
| /proc/net/dev | Network interface packet and byte counters |
| /proc/[PID]/status | Per-process state: name, UID, memory usage (VmRSS), parent PID |4

`wtmp`, `btmp`, and `utmp` are binary files and cannot be read with `cat` or `grep`. The correct commands are `last`, `lastb`, and `who` respectively.

> **For our HIDS:** `/var/log/auth.log` is the highest-value log file for security monitoring. It captures every SSH connection attempt, every `sudo` invocation, and every `su` attempt. Module 2 (User Activity) reads this file directly to surface suspicious login patterns.

### What format do professional security tools use for structured alerts, and why does format matter?

Professional tools such as Wazuh and OSSEC output alerts in JSON format by default, stored in files like `/var/ossec/logs/alerts/alerts.json`. This is not accidental — structured format is a deliberate design decision that has concrete operational benefits.

Example of a structured JSON alert (based on Wazuh's output format):

```json
{
  "timestamp": "2026-04-13T14:32:01Z",
  "severity": "CRITICAL",
  "module": "file_integrity",
  "message": "Hash mismatch detected on critical file",
  "file": "/etc/passwd",
  "expected_hash": "a3f1c9e2...",
  "actual_hash": "99bd2f71..."
}
```

**Why format matters:**

- **Parsability** — a structured format can be ingested by SIEM tools (Splunk, Elastic Stack) or filtered with `jq` without any preprocessing. An unstructured `echo "something changed"` cannot.
- **Timestamp** — every alert must carry a precise timestamp so analysts can reconstruct a timeline of events during incident response.
- **Severity levels** — without severity, an operator cannot triage. Not everything is equally urgent.
- **Consistency** — if every module writes alerts in the same format, the entire log can be searched with a single `grep` or `awk` command regardless of which module generated the alert.
- **Human readability under pressure** — during an incident, analysts read logs at 2am. Clear, consistent formatting reduces the chance of misreading a critical entry.

> **Design decision for our HIDS:** All alerts are written in a consistent pipe-delimited format:
>
> ```
> TIMESTAMP | SEVERITY | MODULE | MESSAGE
> ```
>
> Example: `2026-04-13T14:32:01 | CRITICAL | file_integrity | Hash mismatch: /etc/passwd` This format is parseable by standard shell tools (`grep`, `awk`, `cut`) while remaining human-readable under pressure. JSON output is listed as a nice-to-have for a future iteration.

### What is the difference between a tool that floods you with alerts and one you can actually trust?

This is the signal-to-noise problem — arguably the most important design challenge in any detection system.

A tool that alerts on everything gets ignored. A tool that gets ignored provides zero security value — which is arguably worse than having no tool at all, because it creates false confidence.

**Key principles that separate trustworthy tools from noisy ones:**

**Thresholds, not absolutes** Do not alert every time CPU usage is above 0%. Alert when CPU stays above 90% for more than 60 seconds. The threshold should reflect what is genuinely abnormal for this specific system.

**Baselining** Record the normal state of the system on first run. Alert on deviation from that baseline, not on absolute values. If port 22 is always open, do not alert on it on every run — alert only when a port appears that was not open at baseline time. This is the approach taken by tools like Wazuh, which compares file states against a known-good snapshot rather than alerting on every file it sees.

**Whitelisting known-good** Maintain a list of expected processes, ports, and SUID binaries. Alert only on entries that are new or unexpected relative to that list. This directly reduces false positives without reducing detection coverage.

**Severity levels** Use at minimum three levels:

- `INFO` — logged for reference, no action required
- `WARNING` — worth investigating, not immediately urgent
- `CRITICAL` — requires immediate action

**One alert per event per run** If the same condition is detected on every run, the tool should alert once per execution — not repeatedly within a single run. Repeating the same alert every few seconds trains operators to ignore it.

> **Design decision for our HIDS:** We implement three severity levels (`INFO` / `WARNING` / `CRITICAL`). For file integrity, we alert once per changed file per run. For network ports, we compare against a baseline and only alert on new ports. For CPU and memory, we use configurable thresholds defined in `config/hids.conf` so they can be tuned per environment without modifying the scripts.

---

## Sources

### System Health & /proc Filesystem

- Last9 — *The Ultimate Guide to Ubuntu Performance Monitoring* (loadavg, CPU thresholds): [https://last9.io/blog/ubuntu-performance-monitoring/](https://last9.io/blog/ubuntu-performance-monitoring/)
- OneUptime — *How to Explore the /proc Filesystem for Process Diagnostics on RHEL*: [https://oneuptime.com/blog/post/2026-03-04-explore-the-proc-filesystem-for-process-diagnostics-rhel-9/view](https://oneuptime.com/blog/post/2026-03-04-explore-the-proc-filesystem-for-process-diagnostics-rhel-9/view)
- Oracle Linux Blog — *memstate: Going beyond /proc/meminfo*: [https://blogs.oracle.com/linux/oled-memstate](https://blogs.oracle.com/linux/oled-memstate)

### User Activity & Authentication

- Cyberciti — *When a user logs in what files are updated in UNIX / Linux* (utmp/wtmp/btmp): [https://www.cyberciti.biz/tips/linux-unix-wtmp-utmp-login-records-file.html](https://www.cyberciti.biz/tips/linux-unix-wtmp-utmp-login-records-file.html)
- Linuxize — *last Command in Linux: Check Login History*: [https://linuxize.com/post/last-command-in-linux/](https://linuxize.com/post/last-command-in-linux/)
- Netsurion — *Top 5 Linux log file groups in /var/log*: [https://www.netsurion.com/articles/top-5-linux-log-file-groups-in-var-log](https://www.netsurion.com/articles/top-5-linux-log-file-groups-in-var-log)
- Matt Bromiley (SANS) — *Torvalds Tuesday: Logon History in the *tmp Files*: [https://bromiley.medium.com/torvalds-tuesday-logon-history-in-the-tmp-files-83530b2acc28](https://bromiley.medium.com/torvalds-tuesday-logon-history-in-the-tmp-files-83530b2acc28)

### Process Monitoring

- Datadog Security Labs — *How to detect security threats in Linux processes* (environment variables, command-line arguments): [https://www.datadoghq.com/blog/linux-security-threat-detection-datadog/](https://www.datadoghq.com/blog/linux-security-threat-detection-datadog/)
- Dev Genius — *How Does Process Monitoring Work in Linux?* (/proc/[pid]/stat parsing): [https://blog.devgenius.io/how-does-process-monitoring-work-in-linux-a4f325f709b2](https://blog.devgenius.io/how-does-process-monitoring-work-in-linux-a4f325f709b2)
- Elastic Security Labs — *Hooked on Linux: Rootkit Detection Engineering* (io_uring, process behavior): [https://www.elastic.co/security-labs/linux-rootkits-2-caught-in-the-act](https://www.elastic.co/security-labs/linux-rootkits-2-caught-in-the-act)
- Luke Wago (Medium) — *Linux Investigation And Process Analysis 101* (parent-child relationships, cronjobs): [https://medium.com/@lukewago/linux-investigation-and-process-analysis-101-d39f4a6af257](https://medium.com/@lukewago/linux-investigation-and-process-analysis-101-d39f4a6af257)

### Network Monitoring

- OneUptime — *How to Use the ss Command to Monitor Socket Connections on RHEL 9*: [https://oneuptime.com/blog/post/2026-03-04-ss-command-monitor-socket-connections-rhel-9/view](https://oneuptime.com/blog/post/2026-03-04-ss-command-monitor-socket-connections-rhel-9/view)
- SANS Institute — *Linux Incident Response - Using ss for Network Analysis*: [https://www.sans.org/blog/linux-incident-response-using-ss-for-network-analysis](https://www.sans.org/blog/linux-incident-response-using-ss-for-network-analysis)
- ServerAvatar — *How to Use netstat, ss, and lsof for Linux Network Debugging*: [https://serveravatar.com/netstat-ss-and-lsof/](https://serveravatar.com/netstat-ss-and-lsof/)
- Bornaly (Medium) — *How I Use netstat and ss to Catch Suspicious Connections on Linux*: [https://medium.com/@bornaly/how-i-use-netstat-and-ss-to-catch-suspicious-connections-on-linux-ee69f93a57c2](https://medium.com/@bornaly/how-i-use-netstat-and-ss-to-catch-suspicious-connections-on-linux-ee69f93a57c2)
- Network World — *Using the Linux ss command to examine network and socket connections*: [https://www.networkworld.com/article/966784/using-the-linux-ss-command-to-examine-network-and-socket-connections.html](https://www.networkworld.com/article/966784/using-the-linux-ss-command-to-examine-network-and-socket-connections.html)

### File Integrity & Logging

- Linux Audit — *File permissions of the /etc/shadow password file*: [https://linux-audit.com/file-permissions-of-the-etc-shadow-password-file/](https://linux-audit.com/file-permissions-of-the-etc-shadow-password-file/)
- Linux Audit — *Password security with the /etc/shadow file*: [https://linux-audit.com/authentication/password-security-with-linux-etc-shadow-file/](https://linux-audit.com/authentication/password-security-with-linux-etc-shadow-file/)
- NOC.org — *Basic Linux Security Checklist* (SUID detection, permission hardening): [https://noc.org/learn/linux-security-checklist](https://noc.org/learn/linux-security-checklist)
- OneUptime — *How to Understand the /etc/passwd and /etc/shadow Files on Ubuntu*: [https://oneuptime.com/blog/post/2026-03-02-how-to-understand-the-etc-passwd-and-etc-shadow-files-on-ubuntu/view](https://oneuptime.com/blog/post/2026-03-02-how-to-understand-the-etc-passwd-and-etc-shadow-files-on-ubuntu/view)
- CrowdStrike — *Linux Logging Guide: The Basics*: [https://www.crowdstrike.com/en-us/guides/linux-logging/](https://www.crowdstrike.com/en-us/guides/linux-logging/)
- Ubuntu Community Help Wiki — *LinuxLogFiles*: [https://help.ubuntu.com/community/LinuxLogFiles](https://help.ubuntu.com/community/LinuxLogFiles)
- Wazuh Documentation — *Alert Management*: [https://documentation.wazuh.com/current/user-manual/manager/alert-management.html](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)
- OSSEC Documentation — *Storing alerts as JSON*: [https://www.ossec.net/docs/manual/output/json-alert-log-output.html](https://www.ossec.net/docs/manual/output/json-alert-log-output.html)