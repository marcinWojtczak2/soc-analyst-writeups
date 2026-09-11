# 2026-04-06 — SmartApeSG → ClickFix Lure → C2 Beacon

---

## Overview

| Field | Value |
|-------|-------|
| Platform | Real Investigation |
| Category | Network Analysis |
| Tools Used | Wireshark, CyberChef, VirusTotal |
| Date | 2026-04-06 |
| Victim IP | 10.4.6.101 |
| C2 Server | 89.110.110.119 |

---

## Background Notes

### SmartApeSG
- SmartApeSG is a threat actor originally nicknamed in June 2024, starting as a type of "SocGholish" campaign.
- Initially delivered malware through fake browser update pages.
- In late March / early April 2025, SmartApeSG switched from fake browser updates to ClickFix lures.
- References:
  - https://www.proofpoint.com/us/blog/threat-insight/part-1-socgholish-very-real-threat-very-fake-update
  - https://www.threatdown.com/blog/smartapesg-06-11-2024/

### ClickFix
- ClickFix is a social engineering technique that gained popularity in 2024.
- Uses clipboard hijacking to deliver malicious commands to victims.
- Instructs victims to paste malicious content into a Run or Terminal window.
- The malicious command is typically PowerShell to infect Windows computers with malware.

### Suspicious curl User-Agent
- `curl/8.18.0` appearing in HTTP traffic from a Windows machine is a red flag.
- Legitimate user browsers do not use curl as their User-Agent.
- This indicates a script or malware initiated the HTTP request, not a human browsing.

---

## Scenario

PCAP analysis of SmartApeSG traffic from April 6, 2026. Machine 10.4.6.101 established suspicious connections to external IPs. The investigation focused on identifying the attack vector, C2 infrastructure, and the malware behavior. Key indicators: HTTP traffic using a curl User-Agent and port 443 traffic with no TLS handshake.

---

## Analysis

### 1. Initial Triage

**PCAP Statistics:**

```
File:         2026-04-06-SmartApeSG-traffic.pcap
Packets:      56,939
Duration:     1:02:52
First packet: 15:16:43
Last packet:  16:19:36
```

**Protocol Hierarchy:**
- TCP — 56,894 packets (dominant)
- TLS — 5,776 packets
- HTTP — 4 packets (very low, suspicious — unencrypted traffic in 2026)

**Conversations** (Statistics → Conversations → IPv4, sort by Bytes):

```
10.4.6.101  →  172.96.137.160   — HTTP port 80 (zexxario.com)    ← SUSPICIOUS
10.4.6.101  →  89.110.110.119   — TCP port 443, no TLS           ← SUSPICIOUS
10.4.6.101  →  209.182.225.141  — TLS port 443 (bruvqqex.top)    ← SUSPICIOUS
```

---

### 2. Key Findings

#### Finding 1 — curl Request to Malicious IP (zexxario.com)

**Filter used:** `http`

**Evidence:**
- Frame: 3716
- Timestamp: 19:17:59
- Source: 10.4.6.101 → Destination: 172.96.137.160:80
- Request: `GET /health/check HTTP/1.1`
- Domain: zexxario.com
- User-Agent: `curl/8.18.0`
- Port: 80 (unencrypted HTTP)
- VirusTotal: 8/94 vendors flagged 172.96.137.160 as malicious

The `curl/8.18.0` User-Agent indicates this request was made by a script or malware, not a browser. The `-L` flag was likely used since the redirect was followed automatically.

---

#### Finding 2 — 301 Redirect to HTTPS

**Filter used:** `http`

**Evidence:**
- Frame: 3718
- Timestamp: 19:17:59
- Source: 172.96.137.160 → Destination: 10.4.6.101
- Response: `HTTP/1.1 301 Moved Permanently`
- Location: `https://zexxario.com/health/check`

The server redirected the victim to HTTPS. The redirect was followed, confirming the curl `-L` flag was used in the malicious script.

---

#### Finding 3 — TLS Connection to Malicious Domain (bruvqqex.top)

**Filter used:** `tls.handshake.type == 1`

**Evidence:**
- Frame: 2137
- Timestamp: 19:16:46
- Source: 10.4.6.101 → Destination: 209.182.225.141:443
- Server Name Indication (SNI): `bruvqqex.top`
- VirusTotal: 18/94 vendors flagged bruvqqex.top as malicious

**Note:** Frame 2137 (bruvqqex.top) came **before** Frame 3716 (zexxario.com) — meaning bruvqqex.top was the first malicious contact, likely the initial infection or dropper stage.

---

#### Finding 4 — Fake HTTPS C2 Traffic (port 443 without TLS)

**Filter used:** `ip.addr == 89.110.110.119 && tls.handshake`

**Evidence:**
- Source: 10.4.6.101 → Destination: 89.110.110.119:443
- Timestamp: 19:19:15
- Port: 443
- Protocol: TCP — **no TLS handshake present**

This proves the traffic on port 443 is **not real HTTPS**. The malware uses port 443 intentionally to bypass firewalls that allow outbound HTTPS, while the actual traffic is unencrypted. This is a common evasion technique.

---

### 3. Timeline

| Time (UTC) | Frame | Event |
|-----------|-------|-------|
| 15:16:43 | 1 | First packet — machine starts generating traffic |
| 19:16:46 | 2137 | TLS connection to bruvqqex.top (209.182.225.141:443) |
| 19:17:59 | 3716 | curl GET /health/check → zexxario.com (172.96.137.160:80) |
| 19:17:59 | 3718 | 301 redirect response from zexxario.com |
| 19:19:15 | 55524 | Suspicious TCP traffic to 89.110.110.119:443 (no TLS) |

**Key observation:** bruvqqex.top (frame 2137) appeared **before** zexxario.com (frame 3716) — this suggests bruvqqex.top was the first stage of infection.

---

## Extracted Artifacts

**Files Extracted** (File → Export Objects → HTTP):

```
check:   HTML document, ASCII text, with CRLF line terminators

SHA256 check:
7cb59ce037656d9a4e8ee9194bc31dfc540cbc8fd5b19c64439a89631cde3715

49.crl:  data (Certificate Revocation List)

SHA256 49.crl:
5de7602462599b455b6ef6e363500cb0986fcb9efac76ed101fa0c0acfba4331
```

---

## Indicators of Compromise (IOCs)

### Network IOCs

```
# Malicious IPs
172.96.137.160   — zexxario.com (HTTP port 80, curl download)
209.182.225.141  — bruvqqex.top (TLS port 443, first contact)
89.110.110.119   — C2 server (TCP port 443, no TLS — fake HTTPS)

# Malicious Domains
bruvqqex.top     — 18/94 vendors on VirusTotal
zexxario.com     — 8/94 vendors on VirusTotal

# Malicious URLs
hxxp://172.96.137.160/health/check
hxxps://zexxario.com/health/check

# Suspicious User-Agents
curl/8.18.0
```

### File IOCs

```
# SHA256 Hashes
7cb59ce037656d9a4e8ee9194bc31dfc540cbc8fd5b19c64439a89631cde3715  check
5de7602462599b455b6ef6e363500cb0986fcb9efac76ed101fa0c0acfba4331  49.crl
```

---

## MITRE ATT&CK

| ID | Technique |
|----|-----------|
| T1036 | Masquerading (port 443 without TLS to bypass firewall) |
| T1071.001 | Web Protocols (HTTP/S C2 communication) |
| T1105 | Ingress Tool Transfer (downloading check file via curl) |
| T1027 | Obfuscated Files or Information (fake HTTPS traffic) |

---

**Tags:** #network-analysis #pcap #smartapesg #clickfix #c2 #wireshark #virustotal #ioc
