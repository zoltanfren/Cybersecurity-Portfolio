# NEXACORP SOC — INCIDENT REPORT — INC-2026-002 — CONFIDENTIAL

## SECURITY INCIDENT REPORT

INC-2026-002 | bru-app-01 | Root-Level Compromise

| **Field** | **Value** |
|---|---|
| Incident ID | INC-2026-002 |
| Classification | CRITICAL — Root-level compromise, data exfiltration risk |
| Target host | bru-app-01 (NexaCorp Brussels internal API server) — 10.10.10.42 |
| Attack timestamp | 2026-05-16 17:43 – 19:50 UTC+2 (local) |
| Reported by | NexaCorp CISO / Wazuh SIEM alert |
| Investigated by | Zoltàn Frenyo - SOC Analyst at BeCorp |
| Report date | 2026-05-21 |
| Status | ACTIVE — attacker persistence remains on host |

---

## 1. Executive Summary

During the night of 16 May 2026, a threat actor who had previously compromised NexaCorp's Liège server (INC-2026-001) moved laterally to bru-app-01, the Brussels internal API server. The attacker used an SSH private key stolen from the Liège host to authenticate as the `svc_api` service account, then exploited a misconfigured SUID permission on `/usr/bin/find` to escalate to root. Over the following minutes they read the system password file, created a backdoor user account, harvested SSH private keys, and installed a cron-based persistence mechanism that continues to execute every 10 minutes.

The attacker may still have active access to the server. Immediate containment action is required.

---

## 2. How Did the Attacker Get In?

### 2.1 Reconnaissance — SSH Brute-Force Probing (17:45–19:41)

Starting at **17:45 UTC+2**, auth.log records a wave of SSH login failures against bru-app-01 from multiple external IP addresses. A total of 39 failed attempts targeted usernames including admin, root, backup, deploy, and svc_api, originating from at least 20 distinct IPs across the 162.247.74.x, 185.220.101.x, 45.142.212.x, 89.248.167.x, and 193.32.162.x ranges — consistent with Tor exit nodes used to obscure origin.

This brute-force phase lasted approximately two hours. No single IP made more than two attempts, suggesting automated tooling that rotates source IPs to evade rate-limiting.

### 2.2 Initial Access — Stolen SSH Key

Overlapping the failed attempts, auth.log shows **successful SSH logins as `svc_api`** beginning at **17:43 UTC+2** from IPs in the 185.220.101.x range, using the RSA key fingerprint `SHA256:3Qx7kY9pLmNvWz2Hj8bFcA`. These logins repeat every ~3 minutes from different IPs within the same subnet — a connection pattern consistent with a C2-driven automated operator, not a human.

The use of a valid SSH private key — rather than a password — is the critical finding here. This key was almost certainly **harvested from the Liège server during INC-2026-001**. bru-app-01 had svc_api's public key in its `authorized_keys` file, creating a direct lateral movement path from the compromised Liège host.

**Log source:** `auth.log` — `Accepted publickey for svc_api from 185.220.101.67 port 59084 ssh2: RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA (19:42:37)`

---

## 3. What Did the Attacker Do? — Attack Chain with Timeline

### 3.1 Privilege Escalation via SUID find (19:43 UTC+2)

At **~19:43 UTC+2**, audit.log records the first privilege escalation event. The attacker executed `/usr/bin/find` with the SUID bit set on that binary, causing it to run with **euid=0 (root)** despite being launched by uid=1000 (svc_api). The audit rule tag `suid_escalation` confirms this was flagged by auditd.

**Key audit fields:** `uid=1000 gid=1000 euid=0 — UID="svc_api" EUID="root" — exe="/usr/bin/find" key="suid_escalation"`

The SUID bit on `find` allows any user to invoke it with root effective privileges. The standard exploitation technique is `find / -exec /bin/sh \;`, which spawns a root shell. This is a well-known misconfiguration catalogued on GTFOBins.

### 3.2 Credential Dumping — /etc/shadow (19:43–19:44 UTC+2)

Immediately after escalating, the attacker used `cat /etc/shadow` to read the system's password hash file. audit.log records this access (`key=shadow_access`). While the first attempt logged `success=no` (before escalation was stable), subsequent attempts via the SUID find shell succeeded. The shadow file contains hashed passwords for every local account on the server.

**Log source:** `audit.log` — `type=PATH name="/etc/shadow" — key="shadow_access"`

### 3.3 Backdoor Account Creation — it_support (19:47 UTC+2)

At **19:47:07 UTC+2**, auth.log records the creation of a new local user account: `it_support` (UID=1002, GID=1002, shell=/bin/bash). The account name is deliberately chosen to appear legitimate — an IT helpdesk account. Its password was set immediately via `chpasswd`.

**Log source:** `auth.log` — `useradd[12909]: new user: name=it_support, UID=1002 — chpasswd: password changed for it_support`

### 3.4 SSH Key Harvest — Lateral Movement Preparation (19:43–19:44 UTC+2)

audit.log records the attacker running `find /home -name id_rsa` (`EXECVE argc=4 a0="find" a1="/home" a2="-name" a3="id_rsa"`) with root effective privileges (`key=ssh_key_access`). This is a systematic search for SSH private keys across all user home directories. The goal is to collect credentials enabling further lateral movement to other NexaCorp systems.

**Log source:** `audit.log` — `EXECVE: find /home -name id_rsa — key="ssh_key_access" — EUID="root"`

### 3.5 Cron Persistence — /etc/cron.d/svc-updater (installed ~19:47–19:50 UTC+2)

Starting at **19:50:01 UTC+2**, cron.log shows a new scheduled task firing every 10 minutes: `(root) CMD (/bin/bash /tmp/.svc_updater 2>/dev/null)`. This task runs as root, executes a hidden script in `/tmp`, and suppresses all output. The task continues to fire through the end of the log collection period (23:40+), confirming it was still active hours after the initial compromise.

**Log source:** `cron.log` — `CRON[13164]: (root) CMD (/bin/bash /tmp/.svc_updater 2>/dev/null)` — repeating every 10 min

---

## 4. Incident Timeline

| **Timestamp (UTC+2)** | **Log Source** | **Event** |
|---|---|---|
| 17:43:43 | auth.log | First successful SSH login as svc_api from 185.220.101.68 using stolen RSA key SHA256:3Qx7kY... |
| 17:45–19:41 | auth.log | 39 SSH brute-force failures from ~20 rotating IPs (Tor nodes) — reconnaissance phase |
| 19:42:37 | auth.log | Final successful login as svc_api; attacker prepares to execute attack chain |
| ~19:43 | audit.log | SUID find exploitation — uid=1000 (svc_api) obtains euid=0 (root). Key: suid_escalation |
| ~19:43–19:44 | audit.log | `cat /etc/shadow` — password hash dump attempted and succeeded via SUID shell. Key: shadow_access |
| ~19:43–19:44 | audit.log | `find /home -name id_rsa` — SSH private key harvest with root privileges. Key: ssh_key_access |
| 19:47:07 | auth.log | `useradd it_support` (UID=1002) — backdoor account created; password set immediately |
| ~19:47–19:50 | audit.log | Cron persistence file written to `/etc/cron.d/svc-updater` |
| 19:50:01 onwards | cron.log | `/bin/bash /tmp/.svc_updater` fires every 10 min as root — still running at log collection time |

---

## 5. How Far Did the Attacker Get?

The attacker achieved **full root control of bru-app-01** for at least several minutes. The confirmed impact is:

- Password hashes for all local accounts on bru-app-01 were read from `/etc/shadow`. These hashes may be cracked offline. Every local account's credentials should be considered compromised.

- A backdoor account (`it_support`) with a known password exists on the system. If not removed, the attacker can log in directly without needing a key.

- SSH private keys from `/home/*` were collected. Any service or server reachable by those keys is potentially at risk of lateral movement. This is how bru-app-01 itself was compromised from the Liège host.

- A root-level cron job (`/etc/cron.d/svc-updater`) executing `/tmp/.svc_updater` every 10 minutes remains active. The payload script's contents are unknown but runs with full system privileges.

**The attacker is likely still present** via the cron persistence and potentially the `it_support` account. Containment must happen before any password resets or other remediation steps, or the attacker will observe the response and adapt.

---

## 6. MITRE ATT&CK Mapping

| **Technique ID** | **Name** | **Evidence** |
|---|---|---|
| T1078.002 | Valid Accounts: Domain Accounts | Stolen svc_api SSH key used for initial access |
| T1548.001 | Abuse Elevation: Setuid/Setgid | SUID bit on `/usr/bin/find` exploited for root (key=suid_escalation) |
| T1059.004 | Command: Unix Shell | `/bin/sh` shell spawned via `find -exec` |
| T1003.008 | Credential Dump: /etc/shadow | `cat /etc/shadow` — key=shadow_access in audit.log |
| T1136.001 | Create Account: Local Account | `useradd it_support` (UID=1002) at 19:47:07 |
| T1552.004 | Unsecured Creds: Private Keys | `find /home -name id_rsa` with root — key=ssh_key_access |
| T1053.003 | Scheduled Task: Cron | `/etc/cron.d/svc-updater` — root cron firing every 10 min |
| T1087.001 | Account Discovery: Local | `id`, `whoami`, `cat /etc/passwd` executed post-escalation |

---

## 7. Indicators of Compromise (IOCs)

| **Type** | **Value** | **Context** |
|---|---|---|
| SSH Key Fingerprint | SHA256:3Qx7kY9pLmNvWz2Hj8bFcA | Attacker key used for all svc_api logins — block immediately |
| IP Range (C2) | 185.220.101.0/24 | All successful attacker logins — Tor exit node range |
| IP Ranges (probe) | 162.247.74.x, 45.142.212.x, 89.248.167.x, 193.32.162.x | Brute-force scanning IPs — all Tor-related |
| Username | it_support | Backdoor account — UID=1002 — not created by NexaCorp IT |
| File | /etc/cron.d/svc-updater | Malicious cron file — runs root payload every 10 min |
| File | /tmp/.svc_updater | Hidden payload script — executed by cron — contents unknown |
| Binary (abused) | /usr/bin/find | SUID bit set — must be removed immediately |

---

## 8. Remediation — Immediate Actions Required

### 8.1 Containment (Do First — Within the Hour)

- Isolate bru-app-01 from the network. Do not shut it down — a live forensic image should be taken first. Block inbound/outbound at the firewall level.

- Remove `/etc/cron.d/svc-updater` and `/tmp/.svc_updater` immediately. Examine the script contents for further C2 indicators before deletion.

- Delete the `it_support` account: `userdel -r it_support`.

- Remove the attacker's SSH key from all `authorized_keys` files on the host.

### 8.2 Eradication

- Remove the SUID bit from `/usr/bin/find`: `chmod u-s /usr/bin/find`. Audit all SUID binaries on the host:

```bash
find / -perm -4000 -type f 2>/dev/null
```

- Reset credentials for all local accounts on bru-app-01 — the `/etc/shadow` file was read and hashes may be cracked offline.

- Identify and rotate all SSH private keys discovered on bru-app-01, and audit every system those keys could access. Any of those systems may now be compromised.

- Review the `svc_api` `authorized_keys` file — it accepted a key stolen from the Liège host. Rotate the `svc_api` keypair entirely.

### 8.3 Recovery and Hardening

- Audit all NexaCorp servers that share SSH trust relationships with bru-app-01 or the Liège host. The attacker is collecting keys for further movement.

- Implement SSH key management policy: private keys should not be stored on servers that accept inbound SSH connections from other servers. Use short-lived certificates (e.g., Vault SSH CA) instead of static keys.

- Remove or strictly audit all SUID binaries. Standard servers should have no SUID bits on admin tools like `find`, `vim`, or `nmap`.

- Block inbound SSH from Tor exit node ranges at the perimeter firewall as a baseline measure.

- Confirm Wazuh SIEM coverage on all NexaCorp servers — the attacker has now compromised two hosts. Further lateral movement may already have occurred.

---

## 9. Phase 2 — Live Detection (Wazuh SIEM)

### 9.1 Alerts Observed During Live Attack Replay

| **Attack Stage** | **Wazuh Alert / Rule** | **Key Fields** |
|---|---|---|
| Privilege escalation | SUID execution alert (rule.level: high) | `data.audit.exe=/usr/bin/find`, `data.audit.uid=1000`, `data.audit.euid=0`, `data.audit.key=suid_escalation` |
| Credential dump | Sensitive file access (rule.level: high) | `data.audit.exe=/usr/bin/cat`, `PATH name=/etc/shadow`, `key=shadow_access` |
| SSH key harvest | SSH key search alert | `data.audit.command=find /home -name id_rsa`, `data.audit.euid=0`, `key=ssh_key_access` |
| Backdoor account | New user creation (rule.level: high) | `useradd it_support` — auth.log PAM event ingested by Wazuh |
| Cron persistence | Cron job execution (root) | `cron.log: (root) CMD /bin/bash /tmp/.svc_updater` — repeating every 10 min |

### 9.2 Detection Gaps

The **initial SSH key reuse** — multiple logins from different IPs with the same key fingerprint — generated no high-severity Wazuh alert, because each individual login was a valid authentication event. A custom rule correlating repeated successful logins from the same key fingerprint across different source IPs within a short window would have caught this.

The **contents of `/tmp/.svc_updater`** are not visible from any log source. The script executes with full output suppression. Without file integrity monitoring or process network monitoring, the payload's C2 behavior cannot be determined from these logs alone.

### 9.3 Proposed New Detection Rule

**Rule: Detect repeated SSH logins from the same key fingerprint across rotating source IPs**

Logic: If the same RSA key fingerprint appears in more than 3 successful SSH logins within a 10-minute window from 3 or more distinct source IPs, fire a high-severity alert — "SSH key reuse across multiple IPs — possible stolen credential or C2 rotation". Wazuh implementation: custom active-response rule on the `sshd` decoder, correlating on `data.srcuser` and key fingerprint across a time window.

---

*Prepared by: BeCode Corp SOC Team | Report date: 2026-05-21 | INC-2026-002*
