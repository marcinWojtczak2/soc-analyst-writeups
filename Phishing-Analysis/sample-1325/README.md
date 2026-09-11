
| Field    | Value             |
| -------- | ----------------- |
| Category | Phishing Analysis |
| Date     | 06.08.2026        |

---

# Executive Summary

**Verdict:** Malicious — spoofed sender email impersonating stayfriends.de (failed SPF/DKIM/DMARC) used as bait to redirect victims to an unrelated gambling site via easilett.com.

---

# Analysis

### Step 1: Initial Triage

Received sample-1325. Opened in Thunderbird and Sublime Text for header analysis

![[Screenshot_2026-08-06_08_06_38.png]]

### Step 2: Header Analysis

```
Received: from krawlspace.online (100.42.79.2) by
 BN8NAM04FT045.mail.protection.outlook.com (10.13.160.73) with Microsoft SMTP Server id 15.20.6792.24 via Frontend Transport; Sat, 16 Sep 2023 16:10:05 +0000
From: Enence, jehd <service@stayfriends.de>
Subject: Bereisen Sie die Welt mit Zuversicht
Cc: phishing@pot
Content-Type: text/html; charset="UTF-8"
Date: Sat, 16 Sep 2023 17:50:56 +0200
To: phishing@pot
X-IncomingHeaderCount: 8
Message-ID:
 <d164fcf5-14f2-436a-be65-25f846fecc9d@BN8NAM04FT045.eop-NAM04.prod.protection.outlook.com>
Return-Path: return@krawlspace.online
X-Sender-IP: 100.42.79.2
```

Email content concerns a Japanese bidirectional translator in real time but the email sender domain: **stayfriends.de** indicates a German social networking site. Cisco Talos and whois.domaintools confirm that the **stayfriends.de** is hosted on a German server.
However sender server introduced in received header as **krawlspace.online** but **X-Sender-IP: 100.42.79.2** belongs to fullybox.shop which originates from an Amazon server based in the USA as confirmed by Cisco Talos and whois.domaintools.

```
dig -x 100.42.79.2 +short
fullybox.shop.
```

### Step 3: Authentication Results

```
spf=none       ->    IP 100.42.79.2 is not authorized to send email on behalf of krawlspace.online
dkim=none      ->    no digital signature
dmarc=none     ->    no domain alignment 
```

**Conclusion:** The lack of an SPF record for krawlspace.online is consistent with the use of disposable, one-time phishing infrastructure — attackers typically don't configure authentication mechanisms for such domains. DMARC also failed alignment for the header-from domain stayfriends.de, since no valid SPF/DKIM was connected to this domain.

### Step 4: Url /Attachment Analysis

```url
href="http://easilett.com/cl/49_md/2010/4/24/4/383653
href="http://easilett.com/oop/49_md/2010/4/24/4/383653
```

Urlscan.io analysis shows that domain **easilett.com** is connected to 10 IPs across 5 countries. The main IP is **168.76.87.16**, geolocated in South Africa and registered to ASLINE-AS-AP - ASLINE LIMITED, HK. Notably, urlscan.io shows that the landing page's title corresponds to a Chinese illegal sports-betting platform — **'必一BY唯一官方网站-必一by官网登录入口'** **(Bi Yi)** — rather than anything related to stayfriends.de. This suggests the sender is not really trying to steal stayfriends.de login data. Instead, stayfriends.de is just used as bait to get the email opened, while the real link makes money by sending clicks to an unrelated gambling site.

### Step 5: Findings

- The From header indicates a German social networking site (stayfriends.de), but the email content advertises a Japanese instant translator device — a mismatch consistent with sender spoofing.
- Embedded URLs highly probably redirect to a gambling site (based on current urlscan.io data — the domain's content may have changed since the email was originally sent).

---

# Indicator of compromise (IOCs)

| Type                | Value                                                | Description                                                                         |
| ------------------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Sender IP           | 100.42.79.2                                          | Actual sending IP                                                                   |
| Impersonated Domain | stayfriends.de                                       | Spoofed domain shown in From header                                                 |
| Return-Path Domain  | krawlspace.online                                    | Envelope/MAIL FROM domain declared by the sending server                            |
| URL                 | hxxp[://]easilett[.]com/cl/49_md/2010/4/24/4/383653  | Redirect link                                                                       |
| URL                 | hxxp[://]easilett[.]com/oop/49_md/2010/4/24/4/383653 | Redirect link                                                                       |
| Redirect Landing IP | 168.76.87.16                                         | IP hosting the gambling redirect landing page                                       |
| Link Domain         | easilett.com                                         | Redirect domain, resolves to 10 IPs across 5 countries                              |
| PTR Hostname        | fullybox.shop                                        | Reverse-DNS hostname for the sending IP, differs from the claimed krawlspace.online |

---

# MITRE ATT&CK Mapping

| Tactics        | Techniques                   | ID        | Evidence                                                   |
| -------------- | ---------------------------- | --------- | ---------------------------------------------------------- |
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Email contains redirect link that leads to a gambling site |

