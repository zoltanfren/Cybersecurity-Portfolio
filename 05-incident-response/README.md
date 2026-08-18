# 05 — Incident Response Labs (NexaCorp SOC)

## Overview

A series of SOC analyst exercises conducted in a simulated corporate environment (NexaCorp). Each lab starts from raw evidence — PCAP files, system logs, and SIEM exports — and follows a two-phase structure: forensic investigation first, then detection engineering.

The labs cover two attack campaigns. The first is a three-week campaign (INC-2026-001 to 003) in which a single threat actor progressively compromised multiple internal Linux servers, building on what they gained each week — consolidated in a **Month 1 Assessment**. The second is a four-week web-application campaign (INC-2026-004 to 007) against NexaCorp's employee portal, escalating from SQL injection to a planted backdoor account and ending in the exfiltration of 47 employee records — consolidated in a **Month 2 Assessment**, which also covers the GDPR breach-notification analysis. INC-2026-008 is a standalone incident investigating a Kerberoasting attack against NexaCorp's Active Directory.

---

## Incidents

| Report | Scenario | Key Techniques |
|---|---|---|
| [INC-2026-001](./NexaCorp-INC-2026-001-Report_Zoltan_Frenyo.md) | vsFTPd 2.3.4 backdoor exploit on Liège services server | CVE-2011-2523, PCAP forensics, Suricata rule engineering |
| [INC-2026-002](./NexaCorp-INC-2026-002_Report_Zoltan_Frenyo.md) | Root-level compromise of Brussels API server via stolen SSH key | SUID privesc, credential dumping, cron persistence, Wazuh SIEM |
| [Month 1 Assessment](./NexaCorp-INC-2026-003-Month1_Assessment_Report_Zoltan_Frenyo.md) | Full kill chain reconstruction across INC-001, 002, and 003 | Multi-incident correlation, sudo misconfiguration, C2 beacon analysis |
| [INC-2026-004](./NexaCorp-INC-2026-004_Report_Zoltan_Frenyo.md) | SQL injection on the employee portal, credential theft and SSH reuse | Error-based and UNION SQLi, MD5 hash cracking, SSH lateral movement |
| [INC-2026-005](./NexaCorp-INC-2026-005_Report_Zoltan_Frenyo.md) | OS command injection and web shell planted on the employee portal | Command injection, web shell deployment, failed LFI attempts |
| [INC-2026-006](./NexaCorp-INC-2026-006_Report_Zoltan_Frenyo.md) | Stored XSS on the feedback form used to hijack an employee session | Stored XSS, session cookie theft, session reuse |
| [Month 2 Assessment](./NexaCorp-INC-2026-007-Month2_Assessment_Report_Zoltan_Frenyo.md) | Full campaign reconstruction across INC-004–007, including the IDOR/broken-access-control export of 47 employee records | Multi-incident correlation, IDOR, broken access control, GDPR breach assessment |
| [INC-2026-008](./NexaCorp-INC-2026-008_Report_Zoltan_Frenyo.md) | Kerberoasting attack against NexaCorp's Active Directory | AD enumeration (SharpHound), Kerberoasting, Wazuh custom rule authoring |

---

## What I Did

- Reconstructed attack timelines from PCAP files, auth.log, audit.log, cron.log, web server logs, and Wazuh SIEM exports
- Identified how each incident connected to the next — stolen SSH keys reused across three Linux servers, and later a planted backdoor account reused across three web-app incidents
- Wrote Suricata detection rules for each attack stage and validated them by replaying evidence PCAPs, tuning thresholds to match actual attacker behaviour
- Authored a custom Wazuh XML detection rule for Kerberoasting (weak-cipher service ticket requests) that fires only on the malicious pattern, not routine domain traffic
- Performed false positive analysis and documented evasion paths for every rule
- Mapped all attacker actions to MITRE ATT&CK techniques
- Assessed a confirmed personal-data breach (47 employee records) against GDPR notification requirements
- Produced both technical reports (evidence-level detail, IOC tables, log citations) and management-level assessments summarising each campaign

---

## Skills Practiced

- Network forensics with Wireshark and PCAP analysis
- Linux log analysis: auth.log, audit.log (EXECVE records), cron.log, syslog, web access logs
- Wazuh SIEM alert review, detection gap identification, and custom rule authoring (XML)
- Suricata rule writing, testing, and tuning (IDS → IPS mode logic)
- MITRE ATT&CK mapping
- Web application attacks: SQL injection (error-based, UNION-based, blind boolean), OS command injection, web shells, stored XSS, session hijacking, IDOR, broken access control
- Active Directory attacks: enumeration (SharpHound), Kerberoasting, weak-cipher ticket detection
- Privilege escalation: SUID abuse, sudo misconfiguration (NOPASSWD interpreter)
- Persistence mechanisms: cron jobs, backdoor accounts, SSH key planting
- Data breach impact assessment and GDPR notification analysis
- Technical and executive report writing

---

## Tools

- Wireshark / tshark
- Suricata (IDS mode, PCAP replay)
- Wazuh SIEM (alert review and custom rule authoring)
- auditd / ausearch
- Linux CLI (grep, awk, netstat, ss, find)
- Windows Event Logs / Kerberos ticket analysis

---

## Lab Environment

All exercises were conducted in the BeCode Corp SOC lab environment (NexaCorp simulation). Hosts referenced in reports are isolated lab machines — no real infrastructure was involved.
