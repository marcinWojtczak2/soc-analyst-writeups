# Car Insurance Phishing 

| Field    | Value             |
| -------- | ----------------- |
| Category | Phishing Analysis |
| Date     | 30.07.2026        |

---

# Executive Summary

**Verdict:** Phishing

Email impersonating seguro-autoo.com car insurance. Attacker spoofed seguro-autoo.com, which is a car insurance domain, but the email subject concerns health insurance. Decoded URL contains a tracking code with an ID and the recipient's email address.

---

# Analysis 

### Step 1: Initial Triage

Received sample-681. Opened in Thunderbird and Sublime Text for header analysis.

![[Screenshot_2026-07-30_08_10_12.png]]

### Step 2: Header Analysis

```
Received: from srv01(mailfrom:daiane@e.seguro-autoo.com fp:SMTPD_-VHcBUOx-v5)
          by smtpdm.aliyun.com(127.0.0.1);
          Sat, 20 May 2023 18:15:35 +0800
From: "Daiane Santos - Corretora" <daiane@e.seguro-autoo.com>
To: phishing@pot
Subject: =?ISO-8859-1?Q?Rodrigo=2C_seu_plano_de_sa=FAde_foi_?= =?ISO-8859-1?Q?reajustado_=3F?=
Date: Sat, 20 May 2023 07:15:32 -0300
Reply-To: daiane@seguro-autoo.com
Message-ID:
 <79f98a45-df69-4dba-a7f6-4efdad5a9cb1@VI1EUR06FT042.eop-eur06.prod.protection.outlook.com>
Return-Path: daiane@e.seguro-autoo.com
X-Sender-IP: 140.205.208.121
```

Email pretends to be from e.seguro-autoo.com domain, but subject line reads "Rodrigo, seu plano de saúde foi reajustado ?" - which translates to "Rodrigo, has your health insurance plan been adjusted?" This means the email actually concerns health insurance, despite the domain name literally translating to "car insurance" ("seguro auto"). Additionally, the subject is written in Portuguese, not Chinese, despite the sending server being hosted in China via Alibaba Cloud.

Cisco Talos and Mxtoolbox confirm that the email server originates from an Alibaba server based in China.

### Step 3: Authentication Results

```
spf=pass    <- IP  140.205.208.121 is allowed to send email in the name of seguro-autoo.com domain
dkim=none   <- No digital signature
dmarc=pass  <- Domain alignment pass
```

**Conclusion:** Although the authentication process passed successfully, this only confirms that the domain is correctly configured to send on its own behalf - it does not confirm legitimacy. Additionally, the subject header indicates something different than the sender domain name would suggest (health insurance vs. car insurance).

### Step 4: Reputation

VirusTotal, Cisco Talos, and WHOIS/DomainTools show no flags on 140.205.208.121 — confirmed as an Alibaba Cloud (China) IP. Clean IP reputation doesn't confirm legitimacy. The same applies to domains seguro-autoo.com / e.seguro-autoo.com

### Step 5: URL Attachment analysis

```url
https://zd-d.seguro-autoo.com/lnk.php?id=312C37322C726F647269676F2D662D7040686F746D61696C2E636F6D2C33383339
```

```url
https://zd-d.seguro-autoo.com/rem.php?id=312C37322C726F647269676F2D662D7040686F746D61696C2E636F6D2C33383339
```

After decoding the id parameter from both URL's in CyberChef (From Hex), both resolve the same strings: **1,72,rodrigo-f-p@hotmail.com** - confirming that link contains a recipient-specific tracking code with the target's email embedded. lnk.php and rem.php sharing the same ID suggests separate tracking purpose.

Attempt to resolve hxxps[://]zd-d[.]seguro-autoo[.]com via urlscan.io - DNS resolution failed, indicating the phishing infrastructure is no longer active. Consistent with disposable/short-lived infrastructure commonly used to bypass sustained detection.

### Step 6: Findings

- **1,72,rodrigo-f-p@hotmail.com**  - tracking code and target email embedded in the url
- email subject suggested the email concerns health insurance instead of car insurance
- mismatch between **From: daiane@e.seguro-autoo.com**  and  **Reply-To: daiane@seguro-autoo.com**
- **zd-d.seguro-autoo.com** no longer resolves — campaign ended or domain burned/abandoned.

---

# Indicator of compromise (IOCs)

| Type                | Value                                     | Description                     |
| ------------------- | ----------------------------------------- | ------------------------------- |
| Sender IP           | 140.205.208.121                           | Actual sender                   |
| Sender domain       | e.seguro-autoo.com                        | Sender domain                   |
| Reply-To domain     | seguro-autoo.com                          | Reply-To domain                 |
| URL                 | zd-d[.]seguro-autoo[.]com/lnk[.]php?id=.. | Click-tracking redirect link    |
| URL                 | zd-d[.]seguro-autoo[.]com/rem[.]php?id=.. | Secondary tracking endpoint     |
| Recipient(targeted) | rodrigo-f-p@hotmail[.]com                 | Email embedded in malicious URL |

---

# MITRE ATT&CK Mapping


| Tactics  | Techniques         | ID        | Evidence                                                     |
| -------- | ------------------ | --------- | ------------------------------------------------------------ |
| Phishing | Spearphishing Link | T1566.002 | Email contains malicious URL with embedded ID and email address |

