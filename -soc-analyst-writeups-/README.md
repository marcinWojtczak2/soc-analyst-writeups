# SOC Analyst Writeups

Defensive security analysis reports documenting my blue team practice and methodology.

---

## Phishing Analysis

| Sample | Type | Verdict | MITRE Techniques |
|--------|------|---------|------------------|
| [sample-8](./sample-8/) | FTX Cryptocurrency Scam | Phishing | T1566.002, T1204.001 |
| [sample-16](./sample-16/) | Fake Order Confirmation | Phishing | T1566.002, T1204.001 |

## Skills Demonstrated

- Email header analysis (SPF, DKIM, DMARC verification)
- Malicious URL/attachment identification
- MITRE ATT&CK framework mapping
- Indicator of Compromise (IOC) extraction
- Threat intelligence documentation

## Tools

- Thunderbird, Sublime Text - Email analysis
- VirusTotal, URLScan.io - Reputation checks
- dig, whois - DNS/domain investigation
- olevba, pdfid.py - Attachment analysis



---

## Network Analysis

| Case | Type | Verdict | MITRE Techniques |
|------|------|---------|-------------------|
| [ClickFix C2 Beacon](./Network-Analysis/ClickFix-C2-Beacon/) | TeamViewer-based C2 Beacon | Malicious | T1219, T1071.001 |
| [Seven Days of Scans and Probes](./Network-Analysis/Seven-days-of-scans/) | Multi-CVE Web Server Scanning Campaign | Malicious — Attempted, Unsuccessful | T1190, T1595.003 |
| [SmartApeSG](./Network-Analysis/SmartApeSG/) | SmartApeSG → ClickFix → Fake-HTTPS C2 | Malicious | T1071.001, T1036 |

## Skills Demonstrated

- PCAP traffic analysis and protocol hierarchy triage (Wireshark)
- Threat intelligence correlation across multiple sources (VirusTotal, Cisco Talos, whois/DomainTools)
- C2 traffic identification, including protocol-mismatch detection (fake HTTPS on port 443)
- SNI-based domain identification for traffic hidden behind shared infrastructure (Cloudflare)
- CVE-based exploit attempt analysis (CVE-2024-4577, CVE-2021-41773)
- Payload deobfuscation and decoding (CyberChef, base64)
- Attack timeline reconstruction from multi-stage traffic
- MITRE ATT&CK technique mapping
- Custom detection rule writing (Snort)
- Distinguishing successful vs. failed exploitation attempts (triage judgment)

## Tools

- Wireshark, tcpdump — packet capture and traffic analysis
- CyberChef — payload decoding/deobfuscation
- VirusTotal, Cisco Talos — IP/domain/file reputation checks
- whois / DomainTools — domain registration and infrastructure lookup
- Snort — custom detection rule writing

---

## SIEM / Detection Engineering

| Case | Technique Detected | Log Source | MITRE Techniques |
|------|--------------------|------------|-------------------|
| [AD Compromise — DCSync & LSASS Investigation](./SIEM-Detection/AD-Compromise-DCSync-Investigation.md) | DCSync attack + LSASS credential dumping via process injection | Splunk (Sysmon, Windows Security Log, linux:syslog) | T1003.006, T1055, T1021.002 |

---

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [phishing_pot samples](https://github.com/rf-peixoto/phishing_pot)
- [malware-traffic-analysis.net](https://malware-traffic-analysis.net) 
 
---

*Part of my journey toward CPTS certification and SOC Analyst role.*
