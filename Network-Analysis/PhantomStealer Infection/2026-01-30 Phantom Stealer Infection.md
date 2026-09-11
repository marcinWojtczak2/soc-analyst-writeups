---

---
---

## Overview

| Field           | Value                         |
| --------------- | ----------------------------- |
| Platform        | Traffic Analysis Exercise     |
| Category        | Network Analysis              |
| Tools Used      | Wireshark, tcpdump, CyberChef |
| Date            | 2026-01-30                    |
| Victim IP       | 10.1.30.101                   |
| Victim Hostname | DESKTOP-WIN11PC<br>           |
| Victim MAC      | 20:e5:2a:b6:93:f1             |



---

## Background Notes


---

## Scenario 

---

## Analysis

### 1. Initial Triage

**PCAP Statistic:**

```
File: 2026-01-30-PhantomStealer-infection.pcap
Duration: 50 seconds (2026-01-30 20:21:06 - 2026-01-30 20:21:56)
First packet: 2026-01-30 20:21:06
Last packet: 2026-01-30 20:21:56
Packets: 8689
```


**Protocol Hierarchy:**
 - TCP (dominant - 99.9%)
 - TLS  (port 443 - 2.6%)

**Conversation**

```
10.1.30.101 -> 104.16.185.241 -> HTTP port 80 (icanhazip.com)
10.1.30.101 -> 185.38.151.11 -> TLS port 587 (exczx.com) <- SUSPICIOUS
10.1.30.101 -> 104.16.78.6 -> TLS port 443 (res.cloudinary.com)
10.1.30.101 -> 185.27.134.154 -> HTTP port 80 (scxzswx.lovestoblog.com) <- SUSPICIOUS
```

### 2. Key Findings 
#### Finding 1 - GET request to Malicious IP

**Filter used:** ip.addr ==  185.27.134.154  && http

**Evidence**:
 - Frame: 6, 7783
 - Timestamp: 20:21:06; 20:21:26
 - Source 10.1.30.101 -> Destination 185.27.134.154 
 - Request: GET /arquivo_20260129190545.txt HTTP/1.1; GET/arquivo_20260129190534.txt HTTP/1.1
 - Host: scxzswx.lovestoblog.com
 - Port: 80 (unencrypted HTTP)
 - User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)
 - VirusTotal:
    - arquivo_20260129190545.txt - 18/60 security vendors flagged this file as malicious
	-  arquivo_20260129190534.txt - 23/60 security vendors flagged this file as malicious
	-  scxzswx.lovestoblog.com - 11/91 security vendors flagged this domain as malicious

#### Finding 2 - TLS connection to 

**Filter used:** tls.handshake.type == 1

**Evidence:**
 - Frame: 8624
 - Timestamp: 20:21:55
 - Source 10.1.30.101 -> Destination 185.38.151.11
 - Server Name Indication (SIN): exczx.com
 - VirusTotal: 
	- 17/91 security vendors flagged this domain as malicious
	- 9/91 security vendors flagged this IP address as malicious

---

To consider:
 - scxzswx.lovestoblog.com - 11/91 security vendors flagged this domain as malicious but its ip  185.27.134.24 not 
 - how to decode body in arquivo_20260129190534.txt
 - what does thsi js script in  arquivo_20260129190545.txt do :
 - 10.1.30.101 -> 104.16.78.6 -> TLS port 443 (res.cloudinary.com) - looks fine?
 - how to find username 