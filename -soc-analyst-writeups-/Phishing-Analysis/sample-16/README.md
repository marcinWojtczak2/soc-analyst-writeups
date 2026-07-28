# Fake Order Confirmation - Phishing Analysis

| Field | Value |
|-------|-------|
| **Platform** | phishing_pot (GitHub) |
| **Category** | Phishing Analysis |
| **Difficulty** | Easy |
| **Date** | 2026-03-31 |

---

## Executive Summary

**Verdict:** Phishing

Phishing email impersonating an order confirmation. Uses an image-based email body with hidden clickable areas to bypass text-based spam filters. Links redirect through LinkedIn URL shortener (`lnkd.in`) to hide the actual malicious destination.

---

## Analysis

### Step 1: Initial Triage

Received `sample-16.eml`. Opened in Thunderbird and Sublime Text for header analysis.

**First impressions:**
- Subject "OrderConfirmation:93345881" - no spaces, looks auto-generated
- Sender is a suspicious Gmail address with random string
- Display name "2U" attempts to appear legitimate

### Step 2: Header Analysis

| Header | Value | Analysis |
|--------|-------|----------|
| **From** | `2U <makarifulislamkariful24599+NMwGO8qDiD8HKv6RyvtRa6ND11[@]gmail[.]com>` | Suspicious Gmail with random string |
| **Subject** | `OrderConfirmation:93345881` | Fake order number, no spaces |
| **Return-Path** | `makarifulislamkariful24599[@]gmail[.]com` | Same suspicious user |
| **X-Sender-IP** | `209[.]85[.]166[.]43` | Google mail server |
| **Date** | Tue, 6 Sep 2022 21:56:52 +0000 | |

### Step 3: Authentication Results

```
spf=pass (sender IP is 209.85.166.43) smtp.mailfrom=gmail.com
dkim=pass header.d=gmail.com
dmarc=pass action=none header.from=gmail.com
```

**All authentication passes** - but this only proves it was sent from a real Gmail account, not that it's legitimate.

### Step 4: URL/Attachment Analysis

**Email Structure:** Image-based with clickable map areas

```html
<img src="https://content.app-us1.com/...">
<map name="...">
    <area href="https://lnkd.in/eQNhqYKW#?act=cl&pid=...">
</map>
```

**URLs Found:**

| URL | Purpose | Suspicious? |
|-----|---------|-------------|
| `hxxps[://]lnkd[.]in/eQNhqYKW` | LinkedIn shortener - hides real destination | **Yes** |
| `hxxps[://]content[.]app-us1[.]com/...` | ActiveCampaign - hosts the image | Abused |
| `hxxps[://]mcusercontent[.]com/...` | Mailchimp CDN - background image | Abused |
| `hxxps[://]fonts[.]googleapis[.]com/...` | Google Fonts | Legitimate |

### Step 5: Red Flags

| Red Flag | Evidence |
|----------|----------|
| Suspicious sender | Random string in Gmail: `makarifulislamkariful24599+NMwGO8qDiD8HKv6RyvtRa6ND11` |
| Image-based body | Entire email is an image to bypass text filters |
| Hidden clickable areas | `<area>` tags hide links within the image |
| URL shortener | `lnkd.in` hides the actual malicious destination |
| No order details | Real order confirmations include item details, prices |
| Generic subject | No company name, just "OrderConfirmation" |

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| Email | `makarifulislamkariful24599[@]gmail[.]com` | Sender address |
| URL | `hxxps[://]lnkd[.]in/eQNhqYKW` | Malicious redirect link |
| URL | `hxxps[://]content[.]app-us1[.]com/z4Mxq/2022/09/06/...` | Hosted phishing image |
| IP | `209[.]85[.]166[.]43` | Sender IP (Google) |
| Display Name | `2U` | Impersonated brand |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Execution | User Execution: Malicious Link | T1204.001 |

---

## Tools Used

- Thunderbird - Email viewing
- Sublime Text - Raw header/HTML analysis
- Manual HTML analysis - Identified image map structure

---

## Lessons Learned

1. **Image-based emails bypass text filters** - Attackers embed everything in images to avoid keyword detection
2. **URL shorteners hide malicious destinations** - `lnkd.in` (LinkedIn) is trusted but can redirect anywhere
3. **SPF/DKIM/DMARC pass means nothing** - Attackers use legitimate services (Gmail) to send phishing
4. **Check the HTML source** - Clickable areas in images are invisible without inspecting the code
5. **Real order confirmations have details** - No items, prices, or shipping info = fake

---

## References

- [MITRE ATT&CK - Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK - User Execution](https://attack.mitre.org/techniques/T1204/)
- [Image-based Phishing Techniques](https://www.proofpoint.com/us/threat-reference/phishing)
