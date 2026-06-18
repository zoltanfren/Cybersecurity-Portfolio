# 05 — Incident Response Labs (NexaCorp SOC)

## Overview

A series of SOC analyst exercises conducted in a simulated corporate environment (NexaCorp). Each lab starts from raw evidence — PCAP files, system logs, and SIEM exports — and follows a two-phase structure: forensic investigation first, then detection engineering. The labs cover a three-week attack campaign in which a single threat actor progressively compromised multiple internal servers by building on what they gained each week.

A separate Month 1 Assessment consolidates incidents 001 through 003 into a management-level report covering the full kill chain.

---

## Incidents

| Report | Scenario | Key Techniques |
|---|---|---|
| [INC-2026-001](./NexaCorp-INC-2026-001-Report_Zoltan_Frenyo.md) | vsFTPd 2.3.4 backdoor exploit on Liège services server | CVE-2011-2523, PCAP forensics, Suricata rule engineering |
| [INC-2026-002](./NexaCorp-INC-2026-002_Report_Zoltan_Frenyot.md) | Root-level compromise of Brussels API server via stolen SSH key | SUID privesc, credential dumping, cron persistence, Wazuh SIEM |
| [INC-2026-004](./NexaCorp-INC-2026-004_Report_Zoltan_Frenyo.md) | SQL injection and credential reuse on employee web portal | Error-based and UNION SQLi, hash cracking, SSH lateral movement |
| [Month 1 Assessment](./NexaCorp-Month1_Assessment_Report_Zoltan_Frenyo.md) | Full kill chain reconstruction across INC-001, 002, and 003 | Multi-incident correlation, sudo misconfiguration, C2 beacon analysis |

---

## What I Did

- Reconstructed attack timelines from PCAP files, auth.log, audit.log, cron.log, and Wazuh SIEM exports
- Identified how each incident connected to the next — stolen SSH keys reused across three servers over three weeks
- Wrote Suricata detection rules for each attack stage and validated them by replaying evidence PCAPs, tuning thresholds to match actual attacker behaviour
- Performed false positive analysis and documented evasion paths for every rule
- Mapped all attacker actions to MITRE ATT&CK techniques
- Produced both technical reports (evidence-level detail, IOC tables, log citations) and a management-level assessment summarising the full campaign

---

## Skills Practiced

- Network forensics with Wireshark and PCAP analysis
- Linux log analysis: auth.log, audit.log (EXECVE records), cron.log, syslog
- Wazuh SIEM alert review and detection gap identification
- Suricata rule writing, testing, and tuning (IDS → IPS mode logic)
- MITRE ATT&CK mapping
- SQL injection: error-based, UNION-based, blind boolean enumeration
- Privilege escalation: SUID abuse, sudo misconfiguration (NOPASSWD interpreter)
- Persistence mechanisms: cron jobs, backdoor accounts, SSH key planting
- Technical and executive report writing

---

## Tools

- Wireshark / tshark
- Suricata (IDS mode, PCAP replay)
- Wazuh SIEM
- auditd / ausearch
- Linux CLI (grep, awk, netstat, ss, find)

---

## Lab Environment

All exercises were conducted in the BeCode Corp SOC lab environment (NexaCorp simulation). Hosts referenced in reports are isolated lab machines — no real infrastructure was involved.
