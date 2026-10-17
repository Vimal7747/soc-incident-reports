# SOC Incident Reports

Customer-style incident reports from SOC alert investigations I've worked end to end: triage, investigation, containment, scoping and write-up.

All cases come from **simulated environments** (e.g. LetsDefend). No real organisations or customer data are involved. Indicators are defanged (`hxxps`, `[.]`).

## Reports

| # | Case | Type | Verdict | Highlights |
|---|---|---|---|---|
| 01 | [ClickFix phishing → Lumma Stealer (SOC338)](reports/01-clickfix-lumma-stealer-soc338.md) | Phishing / Infostealer | True Positive | Deobfuscated ClickFix PowerShell, mshta LOLBin abuse, EDR-to-firewall correlation via PID, UTC timeline normalisation, Sigma detection idea |

## Report structure

Each report follows the same format:

1. Executive summary (written for a non-technical reader)
2. Impact and scope
3. Timeline (UTC)
4. Investigation and evidence
5. Indicators of compromise
6. MITRE ATT&CK mapping
7. Response actions
8. Recommendations, including detection improvements
9. Lessons learned

## About

**Vimalkanth Muthaliyappan Veerakumar**, MSc Cybersecurity, CEH. SOC / detection engineering.
[LinkedIn](https://www.linkedin.com/in/vimalkanth-veerakumar) · [GitHub](https://github.com/Vimal7747)
