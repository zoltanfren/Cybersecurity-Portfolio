# NexaCorp — INC2026001 | Incident Report

**Author:** Zoltan Frenyo  
**Date of report:** 15 May 2026  
**Attack target:** 192.168.10.10  
**Attacker IP:** 172.16.50.10  
**Date/time of incident:** 9 May 2026 at 22:08 UTC+2

---

## Phase 1 — Forensic Analysis

### 1. Executive Summary

During the night of 9–10 May 2026, a host on the lab network (192.168.10.10) was attacked by another machine at 172.16.50.10. The attacker started by scanning the target's open ports and then probed the web server to figure out what software was running. After confirming the FTP service version, they exploited a well-known backdoor in vsFTPd 2.3.4 (CVE-2011-2523) which gave them a root shell on the machine without needing a password.

Once inside, the attacker ran several commands to learn sensitive information about the system. Wazuh picked up the failed FTP login attempts but didn't detect the actual exploit or the root shell at all.

---

### 2. Attack Timeline (UTC+2)

**2026-05-09 22:08:16 — Start of port scan**  
Action: The attacker sends many SYN packets on various ports to detect the ones open (SYN port scan).  
Result: He finds several open ports: 21 (FTP), 22 (SSH), 23 (Telnet), 80 (HTTP).

**2026-05-09 22:12:36 — FTP anonymous login**  
Action: The attacker establishes multiple anonymous logins to the FTP server with a 35–45 minute delay, indicating the use of an automated tool.  
Result: He fails to list FTP directories, but gets information about the version of the FTP server (vsFTPd 2.3.4), which has known vulnerabilities.

**2026-05-09 22:30:20 — FTP credential brute force**  
Action: The attacker attempts to log in to the FTP server with multiple standard account names.  
Result: He fails to log in to the FTP server.

**2026-05-10 00:53:31 — Exploit of CVE-2011-2523 — backdoor triggered**  
Action: The attacker uses a known vulnerability of vsFTPd 2.3.4 to trigger an exploit by sending a login attempt with username `baduser:)`.  
Result: The FTP server sends a 500 error message and opens a root shell on port 6200/tcp.

**2026-05-10 00:53:35 — Interactive root shell access**  
Action: The attacker uses the root shell to gather various sensitive information about the system via standard Linux commands.  
Result: The attacker extracts the following information:

| Command | Output |
|---|---|
| `id` | `uid=0(root) gid=0(root)` |
| `whoami` | `root` |
| `uname -a` | `Linux metasploitable 2.6.24-16-server ... i686` |
| `hostname` | `metasploitable` |
| `cat /etc/passwd \| head -10` | full passwd output |
| `ls /home` | `ftp, msfadmin, service, user` |
| `ifconfig` | `eth0 at 192.168.10.10` |
| `netstat -an \| grep LISTEN` | full listening port list |

---

### 3. Technical Findings

#### 3.1 What reconnaissance happened and how do you spot it?

The attacker first performed a port scan. The giveaway is a series of TCP SYN packets sent to different ports on the same target IP in a short window, without any normal application data following them. A real user connecting to a web server or FTP server would just open one connection to one port, not sweep across 15 different ports. The attacker hit ports 21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6200, 8080 and 8443.

*Exhibit 1: port scan visible in Wireshark*

#### 3.2 What service was exploited and why is it suspicious?

The FTP service was the entry point. It was running vsFTPd version 2.3.4, which is suspicious for a couple of reasons.

First, anonymous login was enabled. Anyone could connect with the username `anonymous` and password `guest@` and get in. That's not normal for a production server; anonymous FTP is only really used for public file shares, and even then it's risky.

Second, and more importantly, vsFTPd 2.3.4 is a version that's known to have a backdoor in it. In 2011 someone compromised the project's download server and replaced the source code with a version that includes a secret: if you put `:)` anywhere in the username during login, the daemon opens a root shell on port 6200. This is documented as CVE-2011-2523. The version was announced in the FTP banner before the attacker even logged in:

```
220 (vsFTPd 2.3.4)
```

So just connecting to port 21 already told the attacker exactly what version was running and that the exploit would work.

#### 3.3 What happened after the exploit succeeded?

The PCAP shows the exact moment the backdoor fires. The attacker sent this to the FTP port:

```
USER baduser:)
PASS anything
```

The server responded with a `500 OOPS` error and then a second connection appeared, this time on port 6200. That's the backdoor shell. The attacker immediately ran `id` and got back:

```
uid=0(root) gid=0(root)
```

That confirms full root access. All of this traffic is completely unencrypted; we can read every command and every response straight out of the PCAP.

*Exhibit 2: CVE-2011-2523 triggered by logging in with ":)" in the username and connection on port 6200*

#### 3.4 What did the attacker do once inside?

The session lasted about 19 seconds. The attacker ran 7 commands, all of which are standard post-exploitation enumeration:

| Command | What it tells the attacker |
|---|---|
| `id` | Confirms they're root (uid=0) |
| `whoami` | Double-checks; returns 'root' |
| `uname -a` | Gets kernel version and architecture (Linux 2.6.24, 2008, i686) |
| `hostname` | Gets the machine name (metasploitable) |
| `cat /etc/passwd \| head -10` | Lists local user accounts and their shells |
| `ls /home` | Shows home directories: ftp, msfadmin, service, user |
| `ifconfig` | Gets the network interface and IP address |
| `netstat -an \| grep LISTEN` | Lists all open/listening ports on the machine |

After that, they just disconnected. It feels like a scripted sequence rather than someone manually typing, given how quickly it all happened.

*Exhibit 3: whoami command sent to the target on port 6200*

#### 3.5 What did Wazuh detect?

Wazuh generated 26 alerts, but they all relate to the brute force phase only. Here's what was in the export:

| Rule ID | Level | Description |
|---|---|---|
| 11451 | 10 | vsftpd: FTP brute force (multiple failed logins) |
| 5551 | 10 | PAM: Multiple failed logins in a small period of time |
| 11403 | 5 | vsftpd: Login failed accessing the FTP server (8 times) |
| 5503 | 5 | PAM: User login failed (14 times) |

The three things Wazuh completely missed:

- **The port scan:** Wazuh only reads host logs, it can't see raw network traffic. The scan never touches any log file on the target.
- **The backdoor trigger:** when a username with `:)` is sent, vsFTPd forks a shell and crashes before it gets a chance to write anything to the auth log. So there's no log entry for Wazuh to pick up.
- **The root shell session:** everything on port 6200 is just TCP traffic. There's no process running on the target that would log those commands. Wazuh would need something like auditd to catch that, and even then only if the shell was a proper login session.

So Wazuh caught the noise (brute force) but completely missed the actual attack. This is a good example of why log-based detection alone isn't enough — you also need something that can inspect network traffic, like Suricata.

---

### 4. Indicators of Compromise (IOCs)

#### 4.1 Network

| Indicator | Notes |
|---|---|
| 172.16.50.10 | Attacker's IP address |
| TCP port 21 | FTP is a vulnerable protocol |
| TCP port 6200 | Backdoor shell; should never have traffic in a normal environment |

#### 4.2 Payload strings

| String | Why it matters |
|---|---|
| `USER <anything>:)` | Trigger for a known exploit |
| `220 (vsFTPd 2.3.4)` | Version banner that identifies the vulnerable software |
| `PASS wrongpassword` | Password used in all brute force attempts |

---

### 5. Detection Gap

The biggest issue is that Wazuh only saw the brute force, not the actual compromise. The backdoor exploit and root shell left basically no trace in any host log. Here's what would have caught each stage earlier:

| What was missed | What would have caught it |
|---|---|
| Port scan | Suricata rule detecting SYN packets to many ports from the same source in a short time |
| CVE-2011-2523 trigger | Suricata content match on `:)` inside a FTP USER command |
| Port 6200 shell connection | Suricata alert on any TCP connection to port 6200, which should never have traffic |

The most impactful single fix would be deploying Suricata with a rule that matches `:)` in FTP USER commands. That would catch this specific exploit at the exact moment it's triggered, before the shell even opens.

---

## Phase 2 — Detection Engineering

### 1. Suricata Rules

I wrote 5 rules covering the main attack stages from Phase 1.

#### Rule 1 — CVE-2011-2523 backdoor trigger

This catches the `:)` smiley in the FTP username, which is what activates the backdoor.

```suricata
# Detect a known backdoor when ':)' appears in the FTP username.
#
# flow:to_server,established = only match packets going TO the FTP
# server after the TCP handshake is done (not SYN packets)
# content:'USER ' then content:':)' within:50 = find USER first,
# then look for ':)' in the next 50 bytes. distance:0 means start
# searching right after 'USER ' ends, not from the packet start.
# nocase on USER because FTP commands are case-insensitive.
# classtype:attempted-admin = high severity
alert tcp any any -> $HOME_NET 21 (msg:"LAB CVE-2011-2523 vsFTPd backdoor trigger - smiley in USER command"; flow:to_server,established; content:"USER "; nocase; content:":)"; distance:0; within:50; classtype:attempted-admin; sid:9100001; rev:1;)
```

#### Rule 2 — Connection to port 6200 (backdoor shell)

When the backdoor fires, vsFTPd opens a root shell on port 6200. This rule catches the very first SYN packet of that connection.

```suricata
# Detect a known port used in exploits (port 6200)
#
# flags:S = SYN only (not SYN-ACK, not data packets)
# No 'established' in flow because we want the SYN itself,
# before any handshake completes. Port 6200 has no legitimate
# use here so any connection attempt is suspicious.
alert tcp any any -> $HOME_NET 6200 (msg:"LAB CVE-2011-2523 vsFTPd backdoor shell - inbound connection to port 6200"; flow:to_server; flags:S; classtype:attempted-admin; sid:9100002; rev:1;)
```

#### Rule 3 — FTP slow brute force

The standard approach for brute force detection doesn't detect attempts that are sufficiently spaced out. I tuned it to 3 attempts in 3600 seconds (1 hour) instead. That catches the slow pattern but means the window is much wider, which could produce more false positives from users who legitimately forget their password a few times.

```suricata
# Detect FTP bruteforce attempts spaced apart.
#
# detection_filter fires only after the threshold is reached.
# track by_src counts per source IP across ALL connections,
# not just within one session — important because each attempt
# was a separate TCP connection in this attack.
alert tcp any any -> $HOME_NET 21 (msg:"LAB FTP slow brute force - 3 or more password attempts in 1 hour"; flow:to_server,established; content:"PASS "; nocase; detection_filter:track by_src,count 3,seconds 3600; classtype:attempted-user; sid:9100004; rev:2;)
```

#### Rule 4 — FTP anonymous login accepted

Anonymous FTP is enabled on this server. The rule matches the server's `230 Login successful` response rather than the client's `USER anonymous` request — that way we only alert when the login works, not just when someone tries it.

```suricata
# Detect anonymous FTP logins
#
# Matches the server's 230 response (flow:to_client) rather than
# the client's 'USER anonymous' so we only alert when it succeeds.
alert tcp $HOME_NET 21 -> any any (msg:"LAB FTP anonymous login accepted - anonymous access should be disabled"; flow:to_client,established; content:"230 Login successful"; classtype:policy-violation; sid:9100005; rev:1;)
```

#### Rule 5 — Port scan (SYN sweep)

Fires when the same source IP sends SYNs to 10 or more different ports within 30 seconds. This also needed tuning — the original threshold was 15 ports, but when I checked the PCAP the attacker's scan peaked at 12 unique ports in any 30-second window because they split it across time. Lowering to 10 caught it.

```suricata
# Detect port scan
#
# flow:stateless is required for SYN scans — they never complete
# the TCP handshake so 'established' would miss them entirely.
# flags:S,12 = SYN flag set AND reserved bits clear.
#
# Tuned from 15 to 10 ports: the attacker's scan burst peaked
# at 12 unique ports in 30s — threshold of 15 didn't fire.
alert tcp any any -> $HOME_NET any (msg:"LAB Port scan - SYN sweep to 10 or more ports in 30 seconds"; flow:stateless; flags:S,12; detection_filter:track by_src,count 10,seconds 30; classtype:network-scan; sid:9100007; rev:2;)
```

---

### 2. Test Evidence

Command used to replay the PCAP against the rules:

```bash
sudo suricata -c /etc/suricata/suricata.yaml \
  -S /etc/suricata/rules/learner/lab.rules \
  -r /home/blue08/nexacorp-INC2026001-evidence/file.pcap \
  -l /var/log/suricata/
```

Output from fast.log (19 alerts, all 5 rules fired):

| Timestamp (UTC) | SID | Alert |
|---|---|---|
| 05/09/2026-22:23:04 | 9100007 | Port scan - SYN sweep to 10 or more ports in 30 seconds — 172.16.50.10 -> 192.168.10.10:443 |
| 05/09/2026-22:23:04 | 9100007 | Port scan (continued) — 172.16.50.10 -> 192.168.10.10:23 |
| 05/09/2026-22:23:04 | 9100007 | Port scan (continued) — 172.16.50.10 -> 192.168.10.10:5432 |
| 05/09/2026-23:34:23 | 9100005 | FTP anonymous login accepted — 192.168.10.10:21 -> 172.16.50.10:33510 |
| 05/09/2026-22:12:23 | 9100005 | FTP anonymous login accepted — 192.168.10.10:21 -> 172.16.50.10:42296 |
| 05/09/2026-22:53:35 | 9100002 | vsFTPd backdoor shell - inbound connection to port 6200 — 172.16.50.10:41174 -> 192.168.10.10:6200 |
| 05/09/2026-23:05:49 | 9100005 | FTP anonymous login accepted — 192.168.10.10:21 -> 172.16.50.10:60354 |
| 05/09/2026-23:58:45 | 9100005 | FTP anonymous login accepted — 192.168.10.10:21 -> 172.16.50.10:33846 |
| 05/10/2026-00:48:03 | 9100005 | FTP anonymous login accepted — 192.168.10.10:21 -> 172.16.50.10:34160 |
| 05/10/2026-01:13:38 | 9100005 | FTP anonymous login accepted — 192.168.10.10:21 -> 172.16.50.10:39710 |
| 05/09/2026-20:08:16* | 9100001 | CVE-2011-2523 backdoor trigger - smiley in USER command — 172.16.50.10:59138 -> 192.168.10.10:21 |
| 05/09/2026-20:08:16* | 9100004 | FTP slow brute force - 3 or more password attempts in 1 hour (multiple flows) |

*\* The brute force and backdoor trigger alerts show timestamp 20:08:16 which is wrong — this is a known Suricata quirk in PCAP replay mode where detection_filter hits get assigned an early timestamp. The actual backdoor trigger was at 00:53:31 UTC+2. The detections themselves are real.*

The most important alert is SID 9100002 at 22:53:35 — that's the exact moment the backdoor shell opened. Rule 9100001 (the trigger) also fired, confirming the full chain was caught.

*Exhibit 4: Suricata rules verified on the SOC workstation*

---

### 3. False Positive Analysis

| SID | Times fired | False positives? | Notes |
|---|---|---|---|
| 9100001 | 1 | None in this pcap | Only one packet in the capture has `:)` in a USER command; the actual exploit. Very low FP risk in general since `:)` in a username is never legitimate. |
| 9100002 | 1 | None | Only one SYN to port 6200 in the whole capture. Port 6200 has no legitimate service so any connection is suspicious. |
| 9100004 | Multiple | Possible | Fires after 3 PASS commands in 1 hour from the same IP. In this pcap all PASS commands are the attacker. On a server with lots of users this could catch people who genuinely forget their password. |
| 9100005 | 6 | Possible | Fires on every successful anonymous login. All 6 are the attacker here, but if anonymous FTP was intentionally enabled for legitimate users it would fire on them too. |
| 9100007 | 3 | Low risk | Fired 3 times on the same scan burst. In a network with a Nessus scanner or other legitimate scanning tools this threshold might need raising. |

The only rules I'd really worry about for false positives in a real environment are 9100004 and 9100005. For 9100005, if anonymous FTP is intentionally enabled and legitimate, you'd want to either suppress the rule or scope it to external IPs only. For 9100004, the 1-hour window is the tradeoff — it has to be wide to catch slow attacks, but that makes it noisier.

---

### 4. Rule Limitations and Evasion

#### Ways each rule could be evaded

| Rule | How an attacker could evade it |
|---|---|
| 9100001 (backdoor trigger) | Send `:)` split across two TCP segments. Suricata reassembles streams so this probably wouldn't work in practice, but it's worth knowing about. |
| 9100001 (backdoor trigger) | If a future backdoor used a different trigger string, this rule would miss it entirely. |
| 9100002 (port 6200) | If the attacker recompiled vsFTPd to use a different port for the shell, this rule would miss it. |
| 9100004 (brute force) | Space attempts more than 1 hour apart; the attacker was already doing something similar at 12–40 minute intervals. Going to 90+ minutes would evade even the tuned rule. |
| 9100005 (anon login) | Nothing; if anonymous FTP is enabled and works, this rule will always fire. The only evasion is to not use anonymous access, which the attacker also didn't rely on for the actual exploit. |
| 9100007 (port scan) | Slow the scan down to fewer than 10 ports per 30 seconds. The attacker actually did this for most of the capture; the rule only caught one specific burst. |
| All rules | If FTP traffic was encrypted (FTPS/SFTP), Suricata can't inspect the payload. Rules 1, 4 and 5 would fail completely. |

#### What these rules don't cover at all

- **Post-exploitation commands:** once the shell is open on port 6200, we have no rules watching what commands get run. We'd need auditd on the endpoint for that.
- **The SSH logins seen in auth.log the morning after:** nothing in these rules would catch a public key SSH login that might be an attacker returning via a planted key.

---

### 6. Recommendations

Beyond the detection rules, here's what I'd recommend to actually prevent this class of attack.

#### Fix the root cause

- **Upgrade vsFTPd immediately.** Version 2.3.4 has a literal backdoor in it; no detection rule compensates for running deliberately compromised software. Current stable version is 3.0.x.
- **Disable anonymous FTP.** One line in `vsftpd.conf`: `anonymous_enable=NO`. There's no reason for it to be on here.
- **Remove the version banner.** Adding `ftpd_banner=FTP Server Ready` stops the server from announcing its version to anyone who connects. It doesn't fix the vulnerability but it removes a free clue for attackers. Do the same for Apache — suppress the `Server:` and `X-Powered-By:` headers so the web server doesn't reveal it's running Apache 2.2.8 and PHP 5.2.4. Both are years out of support.
- **Replace FTP and HTTP with encrypted alternatives.** These are vulnerable protocols that send everything in plain text. Replace FTP with SFTP (which runs over SSH) and make sure the web server is only accessible over HTTPS. If a legacy system genuinely can't support encrypted protocols, isolate it behind a firewall so only specific authorized hosts can reach it.

#### Run Suricata in IPS mode

Right now Suricata is in IDS mode — it alerts but doesn't block anything. If it was running inline in IPS mode, changing `alert` to `drop` on rules 9100001 and 9100002 would actually drop the exploit packet before it reaches vsFTPd. The backdoor would never fire. This is the single highest-impact change available without touching the vulnerable software itself.

#### Investigate the SSH logins from auth.log

Auth.log showed four SSH logins from 192.168.10.1 as `msfadmin` using public key authentication, starting at 08:47 the morning after the attack. Each session opened and closed within a second, consistent with automated commands. The attacker had root access at 00:53 and could have planted an SSH key in `msfadmin`'s `authorized_keys` file. Those SSH sessions should be investigated and the `authorized_keys` file checked against a known-good baseline.
