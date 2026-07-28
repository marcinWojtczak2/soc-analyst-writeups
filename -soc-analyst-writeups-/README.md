# SOC Analyst Writeups

Defensive security analysis reports documenting my blue team practice and methodology.

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

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [phishing_pot samples](https://github.com/rf-peixoto/phishing_pot)

---

*Part of my journey toward CPTS certification and SOC Analyst role.*
