# FTX Cryptocurrency Scam - Phishing Analysis

| Field | Value |
|-------|-------|
| **Platform** | phishing_pot (GitHub) |
| **Category** | Phishing Analysis |
| **Difficulty** | Easy |
| **Date** | 2024-03-31 |

---

## Executive Summary

**Verdict:** Phishing - Cryptocurrency Scam

Phishing email impersonating **FTX** (bankrupt cryptocurrency exchange) claiming withdrawals are now authorized. Targets victims who lost money in the FTX collapse. Sent via legitimate Amazon SES infrastructure.

---

## Analysis

### Step 1: Initial Triage

Received `sample-8.eml`. Opened in Thunderbird and Sublime Text for header analysis.

**First impressions:**
- Subject mentions "Withdraw Process" - financial lure
- Claims to be from "FTXinsurance" - impersonating bankrupt exchange
- Targets crypto investors who lost money

### Step 2: Header Analysis

**Key Headers Found:**

| Header | Value | Analysis |
|--------|-------|----------|
| **From** | `FTXinsurance <noreplye[@]promotix[.]com>` | Impersonates FTX |
| **Subject** | `Announcement : Withdraw Process is Authorized Now !` | Financial lure |
| **Return-Path** | `...[@]amazonses[.]com` | Sent via Amazon SES |
| **X-Sender-IP** | `54[.]240[.]9[.]14` | Amazon SES server |
| **Date** | Thu, 7 Sep 2023 15:17:24 +0000 | |

### Step 3: Authentication Check

```
spf=pass (sender IP is 54.240.9.14) smtp.mailfrom=amazonses.com
dkim=pass header.d=promotix.com
dmarc=pass action=none header.from=promotix.com
```

**SPF Verification:**
```bash
$ dig TXT amazonses.com +short | grep spf
"v=spf1 ip4:54.240.0.0/18 ... -all"

Sender IP 54.240.9.14 is within 54.240.0.0/18 ✓
```

**All authentication passes!** But this proves it came from Amazon SES, not that it's legitimate.

### Step 4: Red Flags

| Red Flag | Evidence |
|----------|----------|
| FTX impersonation | FTX is bankrupt - no legitimate "insurance" withdrawals |
| Domain mismatch | `promotix.com` is NOT an FTX domain |
| Generic "noreply" sender | `noreplye@promotix.com` - typo in "noreply" |
| Urgency/excitement | "Authorized Now !" - pressure tactic |
| Targets victims | FTX investors lost billions - easy targets |

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| Email | `noreplye[@]promotix[.]com` | Sender address |
| Domain | `promotix[.]com` | Sender domain |
| IP | `54[.]240[.]9[.]14` | Amazon SES server |
| Display Name | `FTXinsurance` | Impersonated brand |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Execution | User Execution: Malicious Link | T1204.001 |

---

## Tools Used

- Thunderbird - Email viewing
- Sublime Text - Raw header analysis
- `dig` - SPF record lookup
- Manual header analysis

---

## Lessons Learned

1. **SPF/DKIM/DMARC pass ≠ legitimate** - Attackers use real services (Amazon SES) to send phishing
2. **Context matters** - FTX is bankrupt, so any "withdrawal" email is a scam
3. **Target awareness** - Attackers exploit current events (FTX collapse) to target victims
4. **Check the actual domain** - `promotix.com` has nothing to do with FTX

---

## References

- [MITRE ATT&CK - Phishing](https://attack.mitre.org/techniques/T1566/)
- [FTX Bankruptcy Info](https://en.wikipedia.org/wiki/Bankruptcy_of_FTX)
