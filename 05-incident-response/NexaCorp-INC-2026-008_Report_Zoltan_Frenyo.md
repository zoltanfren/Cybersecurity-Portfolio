# NexaCorp Industries — Incident Report

**INC-2026-008 — Active Directory Enumeration and Kerberoasting**

| Field | Detail |
|---|---|
| Prepared by | Zoltan Frenyo, SOC Analyst — BeCode Corp |
| Reviewed by | Sarah Chen, Senior SOC Analyst |
| Client | NexaCorp Industries |
| Target system | NexaCorp Active Directory (nexacorp.lab) |
| Date of incident | 3 July 2026 |
| Submission date | 10 July 2026 |
| Classification | Confidential — NexaCorp management |

---

## Executive Summary

On the evening of Friday 3 July 2026, an attacker logged into NexaCorp's Windows domain using a real employee account and used it to request a crackable password for one of NexaCorp's service accounts. No system was broken into and no software vulnerability was exploited. The attacker logged in normally and then abused a standard feature of the way Windows handles authentication.

The account used to log in was `t.remy`, a regular domain account, and the login came from a single workstation, `bru-ws-01`. A few minutes after logging in, the attacker ran a tool that maps out the whole domain, then requested a Kerberos service ticket for the `svc_report` service account. They requested that ticket using an older, weaker form of encryption on purpose, because a ticket encrypted that way can be cracked offline to recover the account's password. The attacker does not need to stay connected to NexaCorp's network to do this — they can crack it on their own machine, at their own pace.

This means the `svc_report` password should now be treated as exposed. The most urgent action is to reset it before the attacker finishes cracking it.

NexaCorp's monitoring system (Wazuh) did not raise an alert on this attack. It did alert on a separate failed-login attempt from another machine earlier the same evening, but that was a different event and was not successful. The reason the real attack was missed is explained in the Detection Gap section, along with a rule that would catch it in future.

This is likely the same attacker involved in the earlier incidents this year. In June, the attacker exported NexaCorp's employee directory (INC-2026-007). That list of names and email addresses is probably how they worked out a valid username to log in with.

---

## Timeline

All times are in UTC.

| Time | What happened |
|---|---|
| 21:47:13 | `t.remy` logs in to the domain from workstation `bru-ws-01` |
| 21:49:30 | The attacker runs SharpHound, a tool that maps the Active Directory |
| 21:49:32 – 21:50:25 | The domain controller records 40 directory lookups in under a minute |
| 21:58:03 | The attacker requests a weak-encryption service ticket for `svc_report` |
| 21:58:07 | A second ticket for the same account is requested |

The whole sequence, from logging in to requesting the ticket, took about eleven minutes.

---

## The Targeted Account and How We Know

The attacker targeted the service account **`svc_report`**, which has the service identity (SPN) **`HTTP/bru-app-01.nexacorp.lab`**.

NexaCorp's account register lists five service accounts that each have an SPN registered, which means any of them *could* be targeted this way. Having an SPN on its own is not evidence of an attack. What proves `svc_report` was the one actually attacked is the service ticket request in the domain controller's logs:

- The request is recorded as a Windows Event ID 4769 (a service ticket request).
- It was made from the attacker's workstation, `bru-ws-01`, at 21:58:03.
- The ticket encryption type is `0x17`, which is the weak RC4 cipher.

Normal service tickets on a modern domain use AES encryption (shown as `0x11` or `0x12`). A request for the older RC4 cipher is the sign of a Kerberoasting attempt, because the attacker's tool forces the weaker cipher on purpose so the ticket can be cracked. Only one account — `svc_report` — had a weak-cipher ticket requested for it from the attacker's machine during the attack window. The other four SPN accounts were not targeted.

---

## Impact

The attacker now holds a service ticket for `svc_report` that they can crack offline to recover the account's password. If that password is short or based on a dictionary word, it could be recovered quickly.

If the attacker recovers the `svc_report` password, they gain a second valid credential inside NexaCorp — this time for a service account rather than a regular user. Depending on what `svc_report` is allowed to do, this could give the attacker access to the reporting application on `bru-app-01` and potentially further access from there. In short, the attacker started with a low-value login and is using it to try to obtain a more valuable one.

---

## Detection Gap

NexaCorp's Wazuh did not alert on the Kerberoasting attack. This is not because Wazuh failed — it is because service ticket requests are one of the most common events in any Windows domain. Every time an employee opens a shared folder or connects to an internal application, a service ticket request is generated. There are thousands per day. A rule that alerted on all of them would be useless.

The thing that made this request suspicious was the encryption type. The attacker's request used the weak RC4 cipher (`0x17`) instead of the normal AES. Wazuh was not checking that field, so the request looked like all the others and passed unnoticed.

Wazuh *did* alert, correctly, on a separate event earlier that evening: a burst of failed logins from a machine called KALI-ATTACK. That was a password-guessing attempt that never succeeded and was a separate, noisier event. The quiet attack that actually worked is the one that slipped through.

The fix is a rule that fires only when a service ticket request uses the weak RC4 encryption. This would have caught the attack and produced a single alert, while staying silent on all the normal AES traffic. The rule is included in the appendix.

---

## Remediation Recommendations

### Immediate

**Reset the `svc_report` password now.** The attacker already has the ticket and is likely trying to crack it. Resetting the password to a long, random value makes the stolen ticket useless. Use at least 25 characters so it cannot be cracked in a reasonable time.

**Check the `t.remy` account.** Work out how the attacker got this login, reset its password, and check whether the account was used for anything else. If the password was easy to guess from the employee's name, other accounts may be at similar risk.

### Medium-term

**Turn off RC4 encryption in the domain.** The root weakness is that the domain controller still accepts requests for the old RC4 cipher. If the domain is set to only allow AES, this type of attack stops working, because the domain controller will refuse to hand out a weak ticket in the first place. Before doing this, NexaCorp's IT team should check that no older applications still depend on RC4, so nothing breaks.

**Review the other service accounts.** The four other SPN accounts (`svc_sql`, `svc_web`, `svc_mail`, `svc_backup_ad`) are exposed to the same attack. Any of them with a weak password should be given a long, random one.

### Strategic / Detection

**Add the Wazuh rule for weak-cipher service tickets** (appendix). This catches any future Kerberoasting attempt regardless of which account is targeted, and does not fire on normal traffic. This is the Phase 2 deliverable for this incident.

---

## Appendix

### A — MITRE ATT&CK Mapping

This incident is one main technique preceded by a reconnaissance step.

| Stage | Technique | ID |
|---|---|---|
| Reconnaissance | Account Discovery: Domain Account | T1087.002 |
| Main attack | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 |

### B — Wazuh Detection Rule (Phase 2)

The rule fires on a service ticket request (Event ID 4769) that uses the weak RC4 cipher (`0x17`). Normal AES tickets (`0x11`, `0x12`) do not match, so it does not produce false positives on ordinary domain activity.

```xml
<group name="windows,active_directory,kerberos,">

  <rule id="100800" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <description>Possible Kerberoasting: service ticket requested with weak RC4 encryption</description>
    <mitre><id>T1558.003</id></mitre>
    <group>kerberoasting,</group>
  </rule>

</group>
```

The `rule.id` assigned on submission was [fill in after PASS].

### C — Key Evidence

| Item | Value |
|---|---|
| Foothold account | t.remy |
| Source workstation | bru-ws-01 (192.168.10.31) |
| Targeted service account | svc_report |
| Targeted SPN | HTTP/bru-app-01.nexacorp.lab |
| Malicious event | Event ID 4769, encryption type 0x17 |
| Attack time | 3 July 2026, 21:58:03 UTC |

---

*Prepared by Zoltan Frenyo, SOC Analyst, BeCode Corp — Reviewed by Sarah Chen, Senior SOC Analyst — 10 July 2026*
