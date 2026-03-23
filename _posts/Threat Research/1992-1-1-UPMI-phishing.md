---
title: "UpYours: Inside the UPMI Phishing-as-a-Service Platform"
classes: wide
header:
  teaser: /assets/images/UPMI-AiTM-toolkit/logo.png
ribbon: black
description: "Source code analysis of a fully-featured AiTM phishing platform with collective intelligence, licensing system and exposed credentials"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Overview

Ctrl-Alt-Intel researchers identified and analysed the full source code of an AI-developed Adversary-in-the-Middle (AiTM) phishing platform branded **"UPMI ULTIMATE"**, operated by a group calling themselves **"Team Unlimited"**. The codebase was recovered from an exposed server, the central node that all licensed client instances phone home to for licensing, intelligence sharing, and remote control.

This was developed and sold with licensed deployments - indicating Phishing-as-a-Service buisness model. The platform was complete with machine-locked licenses, a remote kill switch, and a collective intelligence system where every deployed instance feeds campaign telemetry back to the developer. Every operator's successes and failures attempts to improve evasion effectiveness for all operators.

The platform provides an end-to-end capablities: phishing email composition and delivery, link obfuscation, Cloudflare Turnstile CAPTCHA gates to block automated analysis, and final redirection to Evilginx reverse-proxy pages that capture credentials and **live session tokens, bypassing MFA entirely**.

We observed campaigns using UPMI's platform as early as March 12, 2026. Hardcoded credentials for the operator dashboard, SMTP accounts, Azure AD applications, and the developer's Telegram bot token were all recovered from the source code.

# Attack Chain

The full attack chain is explicitly documented in the threat actor's own `knowledge-base.js`:

```
Victim receives email
       │
       ▼
Email contains unique AES-256-GCM encrypted URI
  → https://go.docviewportal[.]com/d/<TOKEN>
       │
       ▼
LinkShield server decrypts token, extracts target URL + recipient identity
       │
       ▼
Cloudflare Turnstile CAPTCHA presented (blocks all automated URL scanners)
       │
       ▼
Redirect to Evilginx lure page
  → https://webmail.tms[.]ac/djMfuXoi
       │
       ▼
Evilginx reverse-proxies the real Microsoft login page
       │
       ▼
Victim enters credentials — Evilginx captures:
  • Username
  • Password
  • Live session token (bypasses MFA)
       │
       ▼
Telegram alert sent to operator with captured credentials
```

Each link is **unique per recipient**. The AES-256-GCM ciphertext contains the destination URL, a timestamp, the recipient email, and a random nonce. Every email contains a cryptographically unique URL that cannot be correlated by pattern matching.

# Sending Infrastructure

The platform supports three distinct delivery methods, with automatic failover between them.

## Direct MX (Port 25)

Connects directly to the victim's mail server with full domain spoofing capability. No sending limits beyond IP reputation. The primary sender domain observed was `pablotechnostore.com`.

## Office 365 SMTP Relay

Uses `smtp.office365.com:587` with compromised O365 accounts. Display-name spoofing only, since O365 enforces FROM address matching. This method achieves the highest inbox rate for O365-to-O365 delivery. The recovered credentials were `business@pablotechnostore.com` with password `@31checkmain@`.

## Microsoft Graph API

Native Microsoft API sending that bypasses SMTP-layer security controls entirely. The source code contained hardcoded Azure AD credentials:

```
Tenant ID:     01e9a5b6-58de-44a7-8d3a-04a0a85ea86b
Client ID:     dc6a461f-e84a-4991-a28e-8719e1da2e19
Sender:        johnny[@]professionalinsurancesolutions[.]com
```

## DMARC Auto-Detection

Before sending, the system scans each recipient domain's DMARC policy. Domains with no DMARC or `p=none` get full domain spoofing, where the email is sent as something like `hr@targetdomain.com`. Domains with `p=reject` trigger a fallback to display-name-only spoofing. Major free email providers (Gmail, Outlook, Yahoo, ProtonMail, iCloud) are hardcoded as protected.

## DKIM Signing

RSA-2048 DKIM private keys were maintained for six sender domains: `bowhead-transport[.]com`, `workplaceoutreach[.]online`, `vvearcon[.]com`, `cybernt[.]us`, `trns[.]live`, and `tms[.]ac`. Additional keys exist for `ventrisecure[.]com`.

# The Xverginia Dashboard

Operators purchasing access to UPMI receive a web dashboard branded **"Xverginia - Evilginx Session Manager"**. The login page for version 4.1 lists `@andrew_z12` as the contact for license renewal and support.

[![1](/assets/images/UPMI-AiTM-toolkit/XverginiaLogin.png)](/assets/images/UPMI-AiTM-toolkit/XverginiaLogin.png){: .align-center .img-border}
<p class="figure-caption">Xverginia 4.1 dashboard login page</p>

The dashboard provides visibility into visitors, active sessions, and real-time notifications when session tokens are successfully stolen. Configuration is focused on two areas: Telegram channel and bot token for notifications, and Evilginx management including enabling/disabling phishing lures and changing phishing URLs.

[![1](/assets/images/UPMI-AiTM-toolkit/LureMenu.png)](/assets/images/UPMI-AiTM-toolkit/LureMenu.png){: .align-center .img-border}
<p class="figure-caption">Xverginia 4.1 dashboard lure configuration</p>

[![1](/assets/images/UPMI-AiTM-toolkit/TelegramSettings.png)](/assets/images/UPMI-AiTM-toolkit/TelegramSettings.png){: .align-center .img-border}
<p class="figure-caption">Xverginia 4.1 dashboard Telegram settings</p>

## Dashboard Licensing

The dashboard has its own licensing system, separate from the mailer, using port 4444 and a license key format of `DASH:<iv_hex>:<auth_tag_hex>:<encrypted_payload_hex>`. It supports offline activation via a local key file, indicating the developers designed for modularity across different phishing configurations.

## Live Deployments

Censys queries for hosts running "Express" software containing "Xverginia" returned **40 results** at time of writing. These include what appear to be newer versions of the dashboard with a different design and obfuscated source code, deployed on port 2030.

[![1](/assets/images/UPMI-AiTM-toolkit/NewVersion.png)](/assets/images/UPMI-AiTM-toolkit/NewVersion.png){: .align-center .img-border}
<p class="figure-caption">New Xverginia version login page, on port 2030</p>

[![1](/assets/images/UPMI-AiTM-toolkit/SourceObfuscation.png)](/assets/images/UPMI-AiTM-toolkit/SourceObfuscation.png){: .align-center .img-border}
<p class="figure-caption">New Xverginia version obfuscated source code</p>

# Evasion and Anti-Analysis

The platform implements multiple layers of evasion designed to defeat both automated security tools and manual analysis.

## Encrypted URLs

Every phishing link is encrypted with AES-256-GCM using a shared secret between the sender and the LinkShield decryption server. The encrypted payload contains the destination URL, a timestamp, the recipient email, and a random nonce. No automated scanner can determine the destination without the decryption key.

The shared encryption secret recovered from the source: `qVLPQpK8d6xseWkQRw0S2u/mNUrTT/XRZUh4qCfoeCw=`

## Scanner Detection

The tracking server (`tracker.js`) maintains extensive IP range databases to classify visitors. Over 100 Microsoft Safe Links / EOP IP prefixes, Google Safe Browsing ranges, Proofpoint, Mimecast, and Barracuda ranges are all catalogued. When a scanner IP hits the tracking pixel or click URL, it is classified separately from human visitors, allowing operators to distinguish real opens from automated scanning. Over 30 regex patterns match known crawler user-agents and sandboxes.

## Cloudflare Worker Proxy

Tracking pixels and click redirects are routed through a Cloudflare Worker. The email source only shows a `workers.dev` URL (trusted by most filters), the real tracker VPS IP is never exposed in email headers, and Cloudflare's infrastructure adds credibility to the tracking URLs.

## Turnstile CAPTCHA Gate

The LinkShield intermediate page presents a Cloudflare Turnstile CAPTCHA before redirecting to the Evilginx lure. This blocks all automated URL detonation sandboxes from ever reaching the actual phishing page. Microsoft Safe Links, Proofpoint, and similar products cannot get past this gate.

[![1](/assets/images/UPMI-AiTM-toolkit/LinkShield.png)](/assets/images/UPMI-AiTM-toolkit/LinkShield.png){: .align-center .img-border}
<p class="figure-caption">LinkShield Telegram notification</p>

## Content Randomization

The platform randomizes HTML elements (invisible spans, random CSS classes, unique IDs per email), subjects (variable dates, numbers, department names), and text content (synonym replacement, sentence reordering). Both `text/plain` and `text/html` MIME parts are included, alongside Exchange-clean headers with proper `Message-ID`, `List-Unsubscribe`, and `Thread-Index` values. For bulk sends, the lead queue is shuffled so consecutive emails go to different MX servers, preventing any single mail server from seeing a burst of traffic.

# License and Remote Control

## Architecture

The developer sells this as a licensed product with five layers of control. License keys are bound to a SHA-256 hash of the client machine's CPU model, core count, hostname, username, platform, architecture, total memory, and MAC addresses. The license format is `MXLIC:<iv_hex>:<auth_tag_hex>:<encrypted_payload_hex>`, with AES-256-GCM encryption and HMAC-SHA256 signing.

Every startup contacts the license server at `104.131.106[.]42:9999` for verification. Core logic modules (knowledge-base, campaign-intelligence, adaptive-throttle) are AES-256-GCM encrypted and can only be decrypted with a valid license key at runtime.

## Telegram Bot Control

The developer controls the entire operation from a single Telegram bot (`Mxlicense_control_bot`). From here the developer can generate new licenses, kill or revoke licenses instantly, view all active machines and their IPs, view activity logs, view campaign intelligence across all deployed instances, and trigger a nuclear kill-all option.

## License Server API

The HTTP API on port 9999 exposes endpoints for license verification (`POST /api/license/verify`), admin license management (`GET /api/admin/licenses`), activity logging (`GET /api/admin/activity`), instant revocation (`POST /api/admin/kill`), and a web dashboard. The developer maintains full visibility into every client's operations.

# Collective Intelligence

This is arguably the most interesting component of the platform. Every deployed MX Sender instance participates in a shared intelligence network. Before each campaign, the instance pulls global intelligence from the master server (`/api/intel/pull`). After each campaign, it pushes results back (`/api/intel/push`).

The data collected per target domain includes mail filter type (Proofpoint, Mimecast, Barracuda, Google, Microsoft, cPanel, etc.), DMARC/SPF/DKIM status, MX hostname and response times, delivery rates, open rates, click rates, throttling events, greylisting behaviour, and risk scores. Over time, this creates a feedback loop where the platform gets progressively better at evading each target's defences.

## Pre-loaded Knowledge Base

The developer has pre-loaded `knowledge-base.js` with extensive intelligence on mail security vendors, rating each on a difficulty scale of 1-10. Proofpoint scores a 9, with notes that clean business emails bypass ML scoring and that DKIM from real domains get reputation boosts. GoDaddy scores a 3, with notes that it has almost no content filtering and no URL scanning.

The system automatically selects the optimal delivery method per target domain based on this intelligence. O365 targets get the O365 relay (same-ecosystem trust). Proofpoint targets get the O365 relay for Microsoft reputation. cPanel and GoDaddy targets get Port 25 direct delivery to save relay quota for harder targets.

[![1](/assets/images/UPMI-AiTM-toolkit/DomainRotated.png)](/assets/images/UPMI-AiTM-toolkit/DomainRotated.png){: .align-center .img-border}
<p class="figure-caption">Domain rotation and standby domain count Telegram notification</p>

# Phishing Templates

Seven templates were included in the source code, each designed for specific social engineering scenarios. These ranged from SharePoint/OneDrive document sharing notifications, to corporate IT password expiration notices, to security alert notifications about unusual logins, to enterprise voicemail notifications.

One template (`voicemail-image.html`) renders the entire email body as a dynamically generated image using the Node.js `canvas` library, bypassing text content scanning entirely. Another template (`clean-business.html`) is a plain corporate follow-up with no urgency or branding, designed specifically to bypass ML content classifiers.

All templates support dynamic placeholders for recipient name, email, domain, sender name, landing URL, current date/time, and random numbers. The subject lines are randomized with variable elements to prevent pattern-based detection.

# Targeted Victims

Several lead files were recovered from the source code, including `Leads-20k.txt` containing approximately 20,000 email addresses. Processed lead data in JSON format within the `dashboard-data/leads/` directory included `@wellsfargo.com` targets.

The `knowledge-base.js` confirmed successful inbox delivery against several test domains including `shreekrishnarubber.com` (Bluehost), `crewchiefpb.com` (cPanel), `basamat.org`, and `gatsbydominicana.com`.

# Evilginx Phishlets

| Phishlet | VPS | Target |
|----------|-----|--------|
| `msoutlookonline` | `tms[.]ac` / `45.61.136.[1]90` | Microsoft 365 login |
| `cpanel-webmail` | `cybernt[.]us` / `64.95.13[.]174` | cPanel webmail login |
| `roundcube` | `cybernt[.]us` / `64.95.13[.]174` | Roundcube webmail login |
| `office-working` | `sso.ventraqcloud[.]com` / `104.131.106[.]42` | Microsoft 365 login |

# AI-Assisted Development

Despite its capabilities, analysis of the source code strongly suggests this platform was developed with heavy assistance from a Large Language Model (LLM). 

## Sanitised Framing

The most telling indicator is how the platform describes itself. Nowhere in the source code does the developer call this what it is. The startup banner displayed to operators reads:

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          UPMI ULTIMATE — MX SENDER v7.0                      ║
║       Intelligent Email Security Assessment Platform         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

The `package.json` description is `"UPMI Ultimate — Intelligent email security assessment platform"`. The PDF report generator produces documents titled "Campaign Security Assessment Report" with a footer stating *"This report was generated as part of an authorized security assessment. All activities were conducted with proper authorization."* The dashboard UI describes the intelligence engine as a tool for "security assessments" and the report generator as something to "hand to the client to close the deal."

This sanitised language is consistent with how someone would need to frame prompts to an LLM in order to get it to generate this code. Modern LLMs refuse to write code explicitly described as phishing tooling, but will readily produce "email security assessment platforms" or "red team tools" with identical functionality. The framing persists throughout the codebase because it was baked into the prompts that generated it.

## Structural Fingerprints

Across **16,284 lines** of JavaScript spread over 38 source files, the code exhibits a remarkably consistent set of patterns that are hallmarks of LLM-generated output.

```javascript
// ═════════════════════════════════════════════════════════════════════════════
//  MAIL FILTER PROFILES — How each security vendor works internally
// ═════════════════════════════════════════════════════════════════════════════
```

```javascript
// ─── Synonym Banks ───────────────────────────────────────────────────────────
```

```javascript
// ─── Scan single domain's MX records ────────────────────────────────────────
```

**Emoji in source code strings** appears **99 times** across the codebase, used heavily in `console.log` output, Telegram messages, and UI elements. The license bot alone uses over 40 distinct emoji characters in its output strings (`💀`, `✅`, `🆕`, `🔑`, `💻`, `🌐`, `📊`, `🧠`, `⚡`, etc.). While emoji in user-facing output is a deliberate design choice, the density and consistency here mirrors the output style of prompted LLMs, which favour emoji-heavy terminal output.

## What This Means

None of this diminishes the platform's operational capability. The attack chain works. The Evilginx integration captures session tokens. The CAPTCHA gate blocks scanners. The collective intelligence system aggregates campaign data. AI-assisted development lowered the barrier to building a fully-featured PhaaS platform, allowing a developer who may not have been capable of building this from scratch to produce a commercially viable product.

# Conclusion

This marks another step in the evolution of Phishing-as-a-Service platforms. What makes UPMI notable is the addition of collective intelligence gathering across licensed operators, where every campaign improves evasion effectiveness for the entire network. Combined with Cloudflare Turnstile CAPTCHA gates that block automated analysis, AES-256-GCM encrypted URLs unique to each recipient, and Evilginx-based MFA bypass.

The exposed master server gave us full visibility into the developer's operation, including their licensing model, intelligence sharing infrastructure, operator dashboard, and the credentials tying it all together. We hope sharing this analysis helps defenders detect and disrupt campaigns leveraging this platform.

# IOCs

| Type | Value | Context |
|------|-------|---------|
| IP Address | `104.131.106[.]42` | Master server: license server, LinkShield, intelligence API |
| IP Address | `45.61.136[.]190` | Evilginx VPS #1 (`tms.ac`) |
| IP Address | `64.95.13[.]174` | Evilginx VPS #2 (`cybernt.us`) |
| IP Address | `193.111.125[.]137` | Primary sending server (Kamatera) |
| IP Address | `103.101.202[.]72` | Secondary sending server (Kamatera) |
| Domain | `tms[.]ac` | Evilginx phishing domain |
| Domain | `cybernt[.]us` | Evilginx phishing domain (standby) |
| Domain | `docviewportal[.]com` | LinkShield encrypted URL decryption |
| Domain | `go.docviewportal[.]com` | Primary LinkShield endpoint |
| Domain | `webmail.tms[.]ac` | Primary Evilginx lure URL |
| Domain | `pablotechnostore[.]com` | Primary sender domain |
| Domain | `bowhead-transport[.]com` | Sender domain (DKIM-signed) |
| Domain | `workplaceoutreach[.]online` | Sender domain (DKIM-signed) |
| Domain | `vvearcon[.]com` | Sender domain (DKIM-signed) |
| Domain | `trns[.]live` | Sender domain (DKIM-signed) |
| Domain | `professionalinsurancesolutions[.]com` | Graph API sender domain |
| Domain | `ventrisecure[.]com` | Sender domain (DKIM keys present) |
| Domain | `ventracloud[.]com` | Evilginx phishing domain |
| Domain | `brevantic[.]com` | Evilginx phishing domain |
| Bot Username | `Mxlicense_control_bot` | License management bot |
| Bot Username | `UPMi035bot` | Tracker alert bot |
| URL Pattern | `go.docviewportal[.]com/d/<base64url_token>` | Encrypted phishing link |
| URL Pattern | `webmail.tms[.]ac/djMfuXoi` | Default Evilginx lure URL |

# MITRE ATT&CK

| Tactic | ID | Technique | Observed Activity |
|--------|----|-----------|-------------------|
| **Resource Development** | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains | Multiple phishing and sender domains (`tms.ac`, `cybernt.us`, `docviewportal.com`, etc.) |
| **Resource Development** | [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | Acquire Infrastructure: Virtual Private Server | Kamatera VPS for sending, DigitalOcean droplet for master server |
| **Resource Development** | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Acquire Infrastructure: Web Services | Cloudflare Workers for tracking proxy, Azure AD apps for Graph API sending |
| **Resource Development** | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | Establish Accounts: Email Accounts | Multiple sender accounts across O365 and custom domains |
| **Resource Development** | [T1608.005](https://attack.mitre.org/techniques/T1608/005/) | Stage Capabilities: Link Target | LinkShield decryption server + Evilginx reverse-proxy infrastructure |
| **Resource Development** | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Obtain Capabilities: Tool | Evilginx reverse-proxy framework for credential and session token harvesting |
| **Reconnaissance** | [T1589.002](https://attack.mitre.org/techniques/T1589/002/) | Gather Victim Identity: Email Addresses | Lead lists (`Leads-20k.txt`), OSINT recon module (`osint-recon.js`) |
| **Reconnaissance** | [T1596.002](https://attack.mitre.org/techniques/T1596/002/) | Search Open Technical Databases: DNS/Passive DNS | Automated DMARC/SPF/MX scanning per target domain before sending |
| **Initial Access** | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment | HTML attachment with blurred document preview requiring login |
| **Initial Access** | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | AES-256-GCM encrypted per-recipient phishing links |
| **Credential Access** | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | Adversary-in-the-Middle | Evilginx reverse-proxy intercepts credentials and live session tokens (MFA bypass) |
| **Credential Access** | [T1539](https://attack.mitre.org/techniques/T1539/) | Steal Web Session Cookie | Evilginx captures live session tokens providing full account access |
| **Defense Evasion** | [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | Virtualization/Sandbox Evasion | Turnstile CAPTCHA gate, scanner IP detection, bot user-agent filtering |
| **Defense Evasion** | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | AES-256-GCM encrypted core modules, encrypted URL tokens |
| **Command and Control** | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | HTTPS for licensing, intelligence sync, and LinkShield |
| **Command and Control** | [T1102](https://attack.mitre.org/techniques/T1102/) | Web Service | Telegram for license management, campaign alerts, and remote kill switch |
