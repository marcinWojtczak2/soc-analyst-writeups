# KetoXplode diet gummies scam

| Field | Value |
|-------|-------|
| **Category** | Phishing Analysis |
| **Date** | 2026-04-08 |

---

## Executive Summary

**Verdict:** Phishing

---

## Analysis

### Step 1: Initial Triage

Received `sample-1056.eml`. Opened in Thunderbird and Sublime Text for header analysis.

![Screenshot](./Screenshot.png)

### Step 2: Header Analysis

```
From: KetoXplode Gummies Diet🚨✅<otto-newsletter@newsletter[.]otto[.]de>
Message-Id: <oTRXKBw.27188.548+=phishing@pot@winner-win[.]art>
Sender: hello<otto-newsletter@newsletter[.]otto[.]de>
Return-Path: return@winner-win[.]art
X-Sender-IP: 80[.]96[.]157[.]86
```

Email pretends to be from otto.de but Message-ID indicates that email came from winner-win.art


### Step 3: Authentication Results

```
spf=softfail    
dkim=none   
dmarc=fail  
```


### Step 4: Reputation

**VirusTotal:** 5/94 security vendors flagged winner-win.art domain as malicious

**whois.domaintools:** Indicates that the resolved host of sender IP is gateway24.websitewelcome.com, which is a host used by HostGator company email servers.

**SPF Check:** domain has no spf record 
```bash
dig txt winner-win.art +short 
```

### Step 5: URL/Attachment Analysis

hxxp[://]bsq2[.]firiri[.]shop/WlkxdHZ5Z281S1JQeVNtQk1NUE80SC9DTVBVWmpweGl4MTRHL1Z4YWxidW5uQWVLVE93U1U3WU5YVlkzYmtxUGFLQkFpM3dCMDBFNE1VdDBjaWJTRWc9PQ__
hxxp[://]bsq2[.]firiri[.]shop/R1BrZVdvOW1XSDB5em9keWtlU2lIY1NyWk1hQkZoczdLTzRpWmJxNW5nZm1Nb2oxcENZR2VwSjN3cTdXZjZlRDRxdGhHb0Z6eG5PbjJxak1iVmROU0E9PQ__
hxxp[://]bsq2[.]firiri[.]shop/K1hJcFVmVWVOMlEwa0VXa244REFkUk55MFQxQW9NZFJjWHdlOHFvaW9oRnFEOUJoMlZOSmVxeEkrcVh5eXViQjJRWTNza2Z2TnRjZUoyNmRhbFRYNlE9PQ__

The phishing URL bsq2.firiri.shop is flagged by 9/94 security vendors on VirusTotal as malicious. The domain no longer resolves (DNS failure), indicating it has been taken down or expired - typical lifecycle for throwaway phishing infrastructure

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| Email | `return@winner-win.art` | Actual sender |
| Domain | `winner-win[.]art` | Sender domain |
| URL | `hxxp[://]bsq2[.]firiri[.]shop/` | Malicious redirect link |
| IP | `80[.]96[.]157[.]86` | Sender IP (HostGator) |
| SCL | X-MS-Exchange-Organization-SCL: 7 | Spam Confidence level |
| BCL | X-Microsoft-Antispam: BCL:8; | Bulk Complaint Level |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| **Resource Development** | Acquire Infrastructure: Domains | T1583.001 | Registered throwaway domains (winner-win.art, firiri.shop) |
| **Resource Development** | Acquire Infrastructure: Web Services | T1583.006 | Used t.co (Twitter/X) URLshortener to obscure final destination |
| **Initial Access** | Phishing: Spearphishing Link | T1566.002 | Email contains malicious URL 
| **Execution** | User Execution: Malicious Link | T1204.001 | Victim must click to trigger attack 
| **Defense Evasion** | Impersonation | T1656 | Spoofed otto.de sender to appear legitimate |
| **Collection** | Automated Collection | T1119 | 1x1 tracking pixel to confirm email opens |

---

## Tools Used

- Thunderbird - Email viewing
- Sublime Text - Raw header analysis
- VirusTotal - IP/URL reputation check
- URLScan.io - URL investigation and redirect tracing
- whois.domaintools - IP ownership lookup
- dig - SPF record verification
- whois -h whois.ripe.net 

---

 ## Lessons Learned

- Email authentication failures (SPF softfail, DKIM none, DMARC fail) are strong indicators of spoofing
- Legitimate URL shorteners (t.co) can be abused to hide malicious destinations
- Always check Return-Path and Message-ID headers - they reveal the true sender
- High SCL (7) and BCL (8) scores indicate Microsoft already flagged this as spam
- Tracking pixels (1x1 hidden images) are used to confirm email opens


## References
- [T1566.002 - Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [T1204.001 - User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
- [T1656 - Impersonation](https://attack.mitre.org/techniques/T1656/)
- [T1583.001 - Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/)
- [T1583.006 - Acquire Infrastructure: Web Services](https://attack.mitre.org/techniques/T1583/006/)


