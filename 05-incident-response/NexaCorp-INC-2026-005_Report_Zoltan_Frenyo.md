# NexaCorp Industries — Incident Report

**INC-2026-005 — OS Command Injection and Local File Inclusion**

| Field | Detail |
|---|---|
| Prepared by | Zoltan Frenyo, SOC Analyst — BeCode Corp |
| Client | NexaCorp Industries |
| Target system | bru-web-01 (employee portal, 192.168.10.20) |
| Date of incident | 5 June 2026 |
| Submission date | 9 June 2026 |
| Classification | Confidential — NexaCorp management |

---

## Executive Summary

On Friday 5 June 2026, the attacker returned to NexaCorp's employee portal and moved to a different part of it: the built-in diagnostic tools. A ping utility on the portal passed user input straight to the operating system, which let the attacker run their own commands on the server. Using this, the attacker read the full list of system accounts, mapped the web directory, and planted a web shell — a small file that lets them run further commands through the browser at any time. They then logged in over SSH using a legitimate employee account.

The attacker also tried to abuse a separate file-viewer tool to read system files (a local file inclusion attack), but every one of those attempts failed. The command injection alone was enough to seriously compromise the server. At the end of the incident the server is backdoored and the attacker has everything they need to come back.

This incident follows directly from INC-2026-004, where the attacker stole and cracked the `j.martin` credentials that they reuse here.

---

## Timeline

All times are local server time (CEST, UTC+2).

| Time | What happened |
|---|---|
| 08:00:02 | Attacker signs in to the portal and sets the security level to "low" |
| 11:53:30 | First command injection — `; id` confirms code runs as `www-data` |
| 13:35:17 | `; cat /etc/passwd` returns the full system account list |
| 14:15:47 | `; ls -la /var/www/html/` maps the web directory |
| 15:34:04 | Web shell written to `/var/www/html/shell.php` |
| 15:35:40 | Web shell tested and confirmed working |
| 15:47:15 | Attacker logs in over SSH as `j.martin` |

The local file inclusion attempts (at 12:57, 13:49, 14:25, and 15:13) all failed.

---

## Technical Analysis

**The environment.** The target is `bru-web-01`, a Debian 12 server running Apache and DVWA — the same server hit in INC-2026-004. The web application runs as the `www-data` account. The attacker came from `172.16.50.10`, the same IP as the SQL injection incident.

**Reconnaissance.** The attacker's first requests all arrive at 08:00:02 and go straight to the portal login, then set the security level to "low." That setting disables the application's input filtering and is what made the command injection possible. There is then a three-hour gap before the first attack, which points to a manual, deliberate approach rather than an automated scan.

**Command injection.** The ping utility at `/dvwa/vulnerabilities/exec/` takes an IP address and passes it to the OS. Adding a semicolon followed by a command causes that command to run as well. The attacker used this to run `id` and `whoami` (confirming they were running as `www-data`), `cat /etc/passwd` (returning all 29 system accounts, including `j.martin`), `ls -la /var/www/html/` (which showed the web directory was world-writable), and `uname -a` (OS and kernel details). Finally they used it to write a web shell into the web directory.

**Web shell.** Because the web directory was world-writable, the `www-data` account could write a file into it even without owning it. The attacker wrote a small PHP file that runs any command passed to it, then tested it through the browser and confirmed it returned `www-data` access. This gives the attacker a reliable way back in that does not depend on the ping utility.

**Failed LFI.** The attacker made four attempts to read system files through the portal's file viewer using path traversal (`../../../../etc/passwd` and similar). The file viewer rejected all of them and returned its default page. This attack path did not work.

**SSH access.** At 15:47 the attacker logged in over SSH as `j.martin`, using the credentials cracked in INC-2026-004. Several short sessions followed.

---

## Impact

The server is compromised at the operating-system level. The attacker has:

- The full list of system accounts from `/etc/passwd`.
- A working web shell (`shell.php`) that gives command execution through the browser.
- Valid SSH access as `j.martin`.

The web shell and the SSH access together mean the attacker can return whenever they want, even if one path is closed. This foothold is what the attacker uses to plant the backdoor account that appears in the later incidents.

---

## Detection Gap

The command injection and web shell activity would be visible to web-application monitoring, but none was in place. Suricata rules were written and validated against the captured traffic to detect the command injection, the web shell being written, and the web shell being used. These are included in the appendix.

---

## Remediation Recommendations

### Immediate

- Remove the web shell at `/var/www/html/shell.php`.
- Revoke the attacker's SSH access and reset the `j.martin` password.
- Block `172.16.50.10` at the firewall.

### Medium-term

- Fix the command injection by validating the ping input against a strict IP-address pattern and never passing user input directly to the operating system.
- Fix the directory permissions so the web directory is not world-writable.
- Restrict SSH to NexaCorp's internal network.

### Strategic / Detection

- Enable the Suricata rules from this investigation in blocking mode.
- Scan the web root for any other files written during the attack window.

---

## Appendix

### A — MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Command and Scripting Interpreter | T1059 |
| Server Software Component: Web Shell | T1505.003 |
| Valid Accounts (SSH reuse) | T1078 |

### B — Suricata Detection Rules

Written and validated against the incident capture.

```suricata
alert http any any -> $HTTP_SERVERS any (msg:"OS Command Injection - system file path in POST body"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/dvwa/vulnerabilities/exec/"; http.request_body; content:"%2Fetc"; nocase; classtype:web-application-attack; sid:9000010; rev:1;)

alert http any any -> $HTTP_SERVERS any (msg:"Web Shell Write - PHP code injected via command injection"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/dvwa/vulnerabilities/exec/"; http.request_body; content:"%3C%3Fphp"; nocase; classtype:web-application-attack; sid:9000011; rev:1;)

alert http any any -> $HTTP_SERVERS any (msg:"Web Shell Execution - cmd parameter on shell.php"; flow:established,to_server; http.uri; content:"/shell.php"; http.uri; content:"cmd="; nocase; classtype:web-application-attack; sid:9000012; rev:1;)
```

### C — Key Evidence

| Item | Value |
|---|---|
| Attacker IP | 172.16.50.10 |
| Target host | bru-web-01 (192.168.10.20) |
| Command injection endpoint | /dvwa/vulnerabilities/exec/ |
| Web shell | /var/www/html/shell.php |
| Compromised account | j.martin |
| Web shell planted | 5 June 2026 15:34:04 +0200 |
| SSH intrusion | 5 June 2026 15:47:15 +0200 |

---

*Prepared by Zoltan Frenyo, SOC Analyst, BeCode Corp — 9 June 2026*
