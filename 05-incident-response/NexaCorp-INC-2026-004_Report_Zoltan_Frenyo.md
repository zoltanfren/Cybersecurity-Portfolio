# NexaCorp Industries — Incident Report

**INC-2026-004 — SQL Injection on the Employee Portal**

| Field | Detail |
|---|---|
| Prepared by | Zoltan Frenyo, SOC Analyst — BeCode Corp |
| Client | NexaCorp Industries |
| Target system | bru-web-01 (employee portal, 192.168.10.20) |
| Date of incident | 30 May 2026 |
| Submission date | 4 June 2026 |
| Classification | Confidential — NexaCorp management |

---

## Executive Summary

On 30 May 2026, an attacker exploited a SQL injection flaw in NexaCorp's employee self-service portal and used it to steal the login details of every account in the application's database. The attacker sent specially crafted input to the account lookup form, which the application passed straight to its database without checking it. This let the attacker read the full list of usernames and password hashes.

One of those hashes belonged to employee `j.martin`, and it was weak enough to be cracked into a plain-text password in seconds. The attacker then reused that password to log in to the same server over SSH, getting a real foothold on the machine at 14:48, about half an hour after stealing the data.

The most urgent actions are to reset the affected passwords, block the attacker's IP, and fix the injection flaw so it cannot be used again. This successful SSH login is the starting point for the next incident, INC-2026-005.

---

## Timeline

All times are local server time (CEST, UTC+2).

| Time | What happened |
|---|---|
| 09:34:03 | Attacker loads the login page and signs in to the portal |
| 09:35:02 | First injection probe — a single quote breaks the query and confirms the flaw |
| 09:37:24 | Attacker works out the query has 2 columns |
| 09:39:58 | Full user table stolen — all usernames and password hashes |
| 14:48:06 | Attacker logs in over SSH as `j.martin` using the cracked password |

The authoritative time of the data theft, from the web server log, is 30 May 2026 09:39:58 +0200.

---

## Technical Analysis

**The vulnerable page.** The injection was in the `id` parameter of `/dvwa/vulnerabilities/sqli/` on `bru-web-01`. The application was running at its "low" security setting, which disables input filtering, and used a MySQL backend.

**How the attack worked.** The attacker followed the standard SQL injection sequence:

1. **Confirm the flaw** — sending a single quote (`'`) caused a database error, proving the input was not being handled safely.
2. **Map the query** — using `ORDER BY`, the attacker found the query returned two columns.
3. **Extract the data** — using `UNION SELECT`, the attacker pulled the database version, the database name (`dvwa`), the table structure, and finally the full `users` table with `UNION SELECT user,password FROM users`.
4. **Blind enumeration** — the attacker also tested character-by-character extraction using `SUBSTRING`, `ASCII`, and `LENGTH`, confirming the hashes were 32-character MD5 values.

**The source.** The attacker came from `172.16.50.10`, outside NexaCorp's internal range, using `curl` and Firefox user agents.

---

## What Was Exposed

The attacker stole all seven accounts from the `users` table. Because the passwords were stored as unsalted MD5 hashes (a hashing method that is not safe for passwords), most cracked instantly against a standard wordlist:

| Username | Cracked password |
|---|---|
| admin | password |
| gordonb | abc123 |
| 1337 | charley |
| pablo | letmein |
| smithy | password |
| j.martin | (cracked via rockyou.txt) |

The `j.martin` hash was the one that mattered, because that account also exists on the server's operating system.

---

## Impact

After cracking `j.martin`'s password, the attacker reused it against SSH on the same server and logged in successfully at 14:48:06. This gives the attacker an authenticated shell on `bru-web-01`. Follow-up attempts for `admin` and `gordonb` failed, meaning those accounts do not have OS-level logins.

The consequence is that a web-application flaw has turned into a foothold on the server itself. That foothold is what the attacker uses in INC-2026-005.

---

## Detection Gap

The attack was noisy and would be caught by web-application monitoring, but NexaCorp had none in place at the time. Suricata rules were written and validated against the captured traffic to detect the three stages of the attack: the error-based probe, the UNION-based extraction, and the blind boolean enumeration. These are included in the appendix.

One tuning note: a rule that fires on any single quote in a request will also fire on legitimate input such as apostrophes in names, so in production it needs to be anchored to the vulnerable parameter or combined with a threshold.

---

## Remediation Recommendations

### Immediate

- Reset the passwords for all affected accounts (`j.martin`, `admin`, `gordonb`, `pablo`, `smithy`) on the portal and anywhere else they may be reused. Revoke the attacker's active SSH session for `j.martin`.
- Block `172.16.50.10` at the firewall.
- Take the vulnerable page offline until it is fixed.

### Medium-term

- Fix the injection by using parameterised queries (prepared statements) everywhere, so user input is never concatenated into SQL.
- Replace MD5 password hashing with a modern, salted algorithm such as bcrypt or argon2id.
- Restrict SSH so it only accepts connections from NexaCorp's internal network.

### Strategic / Detection

- Deploy a web application firewall with SQL injection signatures in blocking mode.
- Enable the Suricata rules from this investigation in blocking (IPS) mode on the web server.

---

## Appendix

### A — MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Exploit Public-Facing Application | T1190 |
| Valid Accounts (credential reuse over SSH) | T1078 |

### B — Suricata Detection Rules

Written and validated against the incident capture. Alert counts on replay: error-based 39, UNION-based 16, blind boolean 24.

```suricata
alert http any any -> $HTTP_SERVERS any (msg:"SQL Injection Probe - Error Based Single Quote"; flow:to_server,established; http.uri; content:"'"; classtype:web-application-attack; sid:9000001; rev:1;)

alert http any any -> $HTTP_SERVERS any (msg:"SQL Injection - UNION Based Query"; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:1; classtype:web-application-attack; sid:9000002; rev:1;)

alert http any any -> $HTTP_SERVERS any (msg:"SQL Injection - Blind Boolean Enumeration"; http.uri; content:"AND"; nocase; pcre:"/AND\s+(SUBSTRING|ASCII|LENGTH|\d+=\d+)/Ui"; classtype:web-application-attack; sid:9000003; rev:1;)
```

### C — Key Evidence

| Item | Value |
|---|---|
| Attacker IP | 172.16.50.10 |
| Target host | bru-web-01 (192.168.10.20) |
| Vulnerable page | /dvwa/vulnerabilities/sqli/ (parameter: id) |
| Compromised account | j.martin |
| Data theft time | 30 May 2026 09:39:58 +0200 |
| SSH intrusion time | 30 May 2026 14:48:06 +0200 |

---

*Prepared by Zoltan Frenyo, SOC Analyst, BeCode Corp — 4 June 2026*
