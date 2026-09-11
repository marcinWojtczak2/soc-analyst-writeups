___
## Overview ##

| Field           | Value                                                              |
| --------------- | ------------------------------------------------------------------ |
| Platform        | Traffic Analysis Exercise                                          |
| Category        | Network Analysis                                                   |
| Tools Used      | Wireshark, tcpdump, CyberChef                                      |
| Date            | 2026-01-20                                                         |
| Victim IP       | 10.1.14.128                                                        |
| Victim Hostname | no host discovery traffic (DHCP/NBNS/LLMNR) present in capture<br> |
| Victim MAC      | 00:24:d6:70:ec:15                                                  |


---

## Analysis ##

### 1. Initial Triage

**PCAP Statistics:**

```
File: 2026-01-20-Xworm-infection-traffic.pcap
Packets: 2516
First packet: 2026-01-20 03:53:07
Last packet: 2026-01-20 04:09:58
Elapsed: 00:16:51
```

**Protocol Hierarchy:**
- TCP - 2511 packets (dominant)
- TLS - 300 packets 
- X11 - 78 packets 

**Conversation:**
- 10.1.14.128 -> 158.94.209.180
- 10.1.14.128 -> 104.18.50.34
- 10.1.14.128 -> 104.16.78.6

---
### 2. Key Findings

### Finding 1 - Malicious IP Address 158.94.209.180

**IP Analysis:**
- Virus Total: 13/92 security vendors flagged this IP address as malicious
- Cisco Talos: Sender IP Reputation: Poor
- whois.domaintools: ASN: AS202412 OMEGATECH-AS Omegatech LTD, SC, IP Location: Netherlands

### Finding 2 - Misidentified X11 Traffic

**Filter used:** `x11`

Wireshark showed 78 packets as **X11** traffic, all going to the same malicious IP as Finding 1 (158.94.209.180), over TCP port 6000. Wireshark only assigned this label because the connection used port 6000, which is the standard port for X11 — but the packet content does not actually match the X11 protocol structure. A genuine X11 connection must start with the byte 0x42 ('B') or 0x6C ('l'). The first byte of this traffic is 0x20 (a space character), which does not match either value.

**Conclusion:** This traffic is not genuine X11. It is most likely additional Xworm command-and-control (C2) communication with 158.94.209.180, disguised or coincidentally running on port 6000.

### Finding 3 - Cloudflare-Hosted Connections

**Filter used:** `tls.handshake.extencion_server_name`

SNI - Its TLS protocol extension which allow to handling many webside on one Ip adress.
In our case we receive two results: `res.cloudinary.com` and  `pub-3bc1de741f8149f49bdbafa703067f24.r2.dev`