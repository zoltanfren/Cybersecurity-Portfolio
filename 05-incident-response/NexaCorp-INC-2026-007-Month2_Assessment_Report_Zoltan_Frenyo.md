# NexaCorp Industries — Month 2 Assessment Report

**INC-2026-004 · INC-2026-005 · INC-2026-006 · INC-2026-007**

| Field | Detail |
|---|---|
| Prepared by | Zoltan Frenyo, SOC Analyst — BeCode Corp |
| Reviewed by | Sarah Chen, Senior SOC Analyst |
| Client | NexaCorp Industries |
| Report period | 30 May 2026 – 19 June 2026 |
| Submission date | 30 June 2026 |
| Classification | Confidential — NexaCorp management and legal |

---

## Executive Summary

Over four weeks in June 2026, one attacker worked their way through NexaCorp's web applications, going a little further each time and finishing by stealing the personal data of 47 employees. This was not four unrelated incidents. It was one campaign, and each step was made possible by something left unresolved from the step before.

It started with a SQL injection attack on the employee portal that stole login details (INC-2026-004). The attacker used those details to get onto the server, then planted a hidden account inside NexaPortal under a name chosen to look legitimate (INC-2026-005). They used that account to steal an employee's login session the following week (INC-2026-006). NexaCorp responded correctly to that incident: the fixes we recommended went live on 18 June and they work. But the hidden account planted three weeks earlier was never removed.

On 19 June the attacker simply logged in through that hidden account and, over about fifteen minutes, read the entire employee directory one record at a time, walked into an admin page that had no access control on it, and downloaded a full export of every employee's details (INC-2026-007). No new vulnerability was needed. They used a valid login that should have been deleted.

**The root cause of the final incident is not the flaw in the application. It is the failure to remove the attacker's account after INC-2026-005.** The session-theft fix worked, but it did not matter, because the attacker no longer needed to steal sessions — they had a working login.

### Key numbers

| Metric | Value |
|---|---|
| Incidents this period | 4 |
| Accounts compromised | 2 (j.martin, and the m.renard backdoor) |
| Sessions stolen | 1 (p.dumont) |
| Employee records stolen | 47 |

### Is GDPR notification required?

Yes. The export taken on 19 June contains the names, work emails, departments, roles, phone numbers, and salary bands of 47 employees. This is personal data, and its loss is a personal data breach. Under GDPR, NexaCorp must notify the supervisory authority within 72 hours of becoming aware of it. NexaCorp's legal team should confirm that deadline and decide whether the affected employees also need to be told directly.

### Immediate actions

1. Delete the `m.renard` account from NexaPortal now.
2. Notify the supervisory authority within 72 hours.
3. Add access control to the admin pages so ordinary logins cannot reach them.
4. Check every portal account against the authorised list and remove any that do not belong.
5. Reset the `j.martin` password everywhere it may have been reused.

---

## The Four Incidents

### Finding 04 — SQL Injection (30 May) — Critical

The attacker exploited a SQL injection flaw in the employee portal to steal every account's username and password hash. One hash (`j.martin`) was weak and cracked in seconds, and the attacker reused that password to log in over SSH. This gave them a foothold on the server and the credentials they reuse in the next incident.

### Finding 05 — Command Injection and Web Shell (5 June) — Critical

Using the `j.martin` access, the attacker moved to the portal's diagnostic tools, where a ping utility passed input straight to the operating system. They ran commands as the web server, read the full system account list, and planted a web shell for reliable access. Most importantly, they used this access to insert a hidden account, `m.renard`, into the NexaPortal database — a login that looks like a normal staff account. Attempts to read files through a separate tool (LFI) all failed.

### Finding 06 — Stored XSS and Session Hijacking (18 June) — High

The attacker logged in with the `m.renard` backdoor and planted a script in the portal's feedback form. When employee `p.dumont` opened the page, the script sent their session cookie to the attacker, who used it to browse the portal as `p.dumont`. NexaCorp patched this correctly (HttpOnly and CSP, live 18 June), closing the session-theft method — but the backdoor account remained.

### Finding 07 — IDOR and Broken Access Control (19 June) — Critical

The `m.renard` account logged in again and stepped through 47 employee records in order by changing a number in the web address (an IDOR flaw), then opened an admin page that returned data to a non-admin login (broken access control), and finally downloaded a full export of the employee directory. No new vulnerability was used. The record for `j.martin`, the account compromised back in Finding 04, is in the export, tying the start and end of the campaign together.

---

## How the Incidents Connect

```
INC-004  SQL injection steals j.martin credentials
   |
INC-005  j.martin access used to run commands and plant the m.renard backdoor
   |
INC-006  m.renard logs in, steals p.dumont's session via XSS
   |   [NexaCorp patches the XSS method on 18 June — but does not remove m.renard]
   |
INC-007  m.renard logs in again, reads 47 records, exports the directory
```

The thread running through all four is the `m.renard` account. It was created in INC-005, used in INC-006, and still active for INC-007. Removing it after INC-005 would have prevented the last two incidents entirely. The attacker even named it to match a real employee (`p.renard`) so it would blend into the user list.

---

## Risk Summary

| Finding | Likelihood | Impact | Rating |
|---|---|---|---|
| 04 — SQL Injection | High | Credentials stolen, server access | Critical |
| 05 — Command Injection | High | Server access, backdoor planted | Critical |
| 06 — XSS / Session Theft | Medium | One session stolen | High |
| 07 — IDOR / Access Control | High | 47 records stolen, GDPR breach | Critical |

---

## Recommendations

### Immediate

- Delete the `m.renard` account and audit all portal accounts against the authorised list.
- Notify the supervisory authority of the breach within 72 hours.
- Add server-side access control to all admin pages so they return "forbidden" to non-admin logins.
- Add access checks to the employee profile pages so a user cannot read other people's records by changing the ID.
- Reset the `j.martin` password everywhere.

### Medium-term

- Remove the web shell from `bru-web-01` and scan for any other files left behind.
- Fix the command injection with strict input validation.
- Replace MD5 password hashing with bcrypt or argon2id.
- Serve all portals over HTTPS.

### Strategic / Detection

- Add rate limiting and alerting on rapid, sequential record access (which would have caught the IDOR enumeration).
- Review every authenticated page in NexaPortal to confirm access checks are applied consistently.
- Remove development artefacts (such as the debug token found in the admin page) from production.

---

## Appendix

### A — MITRE ATT&CK Mapping

| Incident | Technique | ID |
|---|---|---|
| 04 | Exploit Public-Facing Application | T1190 |
| 04, 05 | Valid Accounts | T1078 |
| 05 | Web Shell | T1505.003 |
| 06 | Steal Web Session Cookie | T1539 |
| 07 | Valid Accounts (backdoor reuse) | T1078 |

### B — GDPR Notification Position

A personal data breach affecting 47 employees has occurred. The exported data includes names, work emails, departments, roles, phone numbers, and salary bands. Notification to the supervisory authority is required within 72 hours of awareness. NexaCorp's legal team should confirm the deadline and assess whether the affected individuals must also be notified directly given the inclusion of salary information.

### C — Indicators of Compromise

| Item | Value | Incident |
|---|---|---|
| Attacker IP | 172[.]16[.]50[.]10 | 004, 005, 007 |
| Attacker IP | 91[.]92[.]100[.]45 | 006 |
| Compromised account | j.martin | 004, 005 |
| Backdoor account | m.renard | 005, 006, 007 |
| Victim account | p.dumont | 006 |
| Web shell | /var/www/html/shell.php | 005 |
| Records exported | 47 | 007 |

---

*Prepared by Zoltan Frenyo, SOC Analyst, BeCode Corp — Reviewed by Sarah Chen, Senior SOC Analyst — 30 June 2026*
