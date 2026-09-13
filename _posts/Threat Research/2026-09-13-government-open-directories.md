---
title: "Three Open Directories Expose Government Targeting and Compromise"
description: "Three exposed operator workspaces reveal government targeting, confirmed intrusions, stolen data and exploit attempts across Russia, Kyrgyzstan and Syria."
content_type: research
canonical_url: https://aabbcvc.github.io/research/government-open-directories/
categories:
  - Threat Research
tags:
  - Russia
  - C2
  - Exploitation
  - DFIR
  - Webshell
  - Credential Theft
  - Exfiltration
  - Vulnerability Research
header:
  teaser: /assets/images/covers/government-open-directories.png
  og_image: https://aabbcvc.github.io/assets/images/covers/government-open-directories.png
toc: true
---

## Overview

Exposed attacker infrastructure can reveal more than a list of malicious tools. It can preserve the targets an operator selected, the commands they tried, the access they obtained, and the information they collected. Sometimes it also preserves enough failures to show where an intrusion stopped.

Three open directories identified by Hunt.io offer that view into activity involving Russia’s Ministry of Emergency Situations, Kyrgyzstan’s Ministry of Foreign Affairs and national security service, and a historical C2 inventory associated with Syrian Customs. The collections contain very different evidence: administrative API responses and stolen business data, implant and command-output records, and a shell history dominated by exploitation attempts.

The distinction matters. A government hostname in a target list establishes interest. Returned command output supports execution. A database dump establishes collection. Those are different outcomes, and the directories should not be treated as three equally successful government breaches.

Hunt.io’s AttackCapture records establish the following first-observation dates:

| Exposed directory | First observed by Hunt.io | Principal government-related evidence |
|---|---|---|
| `45.151.139[.]249:8765` | 30 August 2026 | MChS Atlas access and modification; broader Russian targeting |
| `207.148.64[.]94:8083` | 30 August 2026 | Kyrgyz MFA execution records; separate Syrian Customs-associated C2 inventory |
| `89.124.123[.]216:8080` | 16 June 2026 | Repeated attempts against Kyrgyz national security webmail and Russian targets |

These dates describe when Hunt.io first observed the exposed directories, not when the attacks began. The local collections include material from different times, and file-copy dates are not reliable infection timestamps. No evidence establishes a common operator across all three workspaces.

One further limitation is material: the MFA collection contains testing, replay and investigation markers. Its captured technical behavior can be described, but its provenance does not support presenting every action as an independently verified hostile operation. The Syrian records also require separate treatment within that collection.

## 1. MChS Atlas and Russian Commercial Networks — `45.151.139[.]249:8765`

The first directory combined focused government targeting with a much broader search for exposed services. Its local analysis covered 1,195 original files, including scripts, reconnaissance output, API responses, binaries, SQL dumps and audio. The target census contained more than 5.2 million unique IP addresses. That scale describes the discovery corpus; it is not a count of victims or proof that every address received an exploit.

Within that corpus, Russia’s Ministry of Emergency Situations—MChS, also known as EMERCOM—received deliberate attention. The operator shortlisted 18 ministry-related domains and 18 public IP addresses. Targets included Atlas mapping services, authentication portals, emergency-dispatch systems, file-sharing services and administrative interfaces.

The strongest government compromise evidence concerned **Atlas**, where an operator-controlled account obtained administrative information and changed application state despite having no administrator role.

### A non-admin account with administrative visibility

The retained Atlas profile described a “Test Operator” account. Selected fields show the important distinction:

```json
{
  "isAdmin": false,
  "isSuperUser": false
}
```

The same profile had no assigned roles or additional permissions. Nevertheless, the account received data from 15 of 29 probed administrative endpoints. Returned information covered roles, permissions, object forms, categories, import definitions, metrics, regions, external connections and Web Map Service configuration.

The clearest inconsistency appeared between related routes. Direct role and permission requests returned `403` responses, while corresponding `/search` routes returned role records and permission definitions. This supports broken authorization at the application-function level: restrictions were enforced on some paths but did not consistently protect equivalent information elsewhere.

The scripts also supplied `X-Closed-Network: true` in some requests. That shows an attempt to invoke behavior intended for an internal context. The available evidence does not establish that this header caused the authorization failure.

The operator progressed from reading data to changing state. At **19:19:41 +03 on 27 August 2026**, Atlas recorded a newly created external connection named `SSRF Test`. An existing Greenplum connection showed an update 51 seconds later and appeared as `Greenplum_revealed`. The timing and naming support an association with the operator, although the original modifying request and previous values are missing.

A separate sequence of WMS snapshots showed six layers, then seven including a published `Test WMS` layer, then six again. The temporary layer pointed to an out-of-band callback service. A retained response obtained through the Atlas tile proxy confirmed a server-side fetch to that service.

This was meaningful application compromise: unauthorized administrative access, configuration changes and a demonstrated server-side request. It did not establish an operating-system shell, successful administrator promotion, or access to internal services or cloud metadata through that request mechanism.

### What was collected from the government platform?

The retained Atlas material was rich in configuration and structure. It included a category hierarchy covering emergency-response resources, flood and wildfire risks, hazardous facilities, dispatch services and other civil-protection functions. The analysis counted 455 retained category nodes, 396 marked `authorizedOnly: true`.

The operator also obtained nine Kafka import definitions. These exposed topic and schema names, field mappings, integration endpoints and operational counters. Two definitions contained reusable authentication-token values in their headers. Those secrets are excluded here.

The distinction between structure and underlying records is essential. Counters in the import definitions totalled approximately 3.74 million; they do not demonstrate theft of 3.74 million records. Similarly, the category tree described map layers without proving that their full contents or geometry were downloaded.

The collection held approximately 2.39 MB of Atlas JSON and 46 downloaded PNG attachments totalling 41.3 MB. The images were largely regional coats of arms, hazard symbols and map icons. Several API results were paginated or partial. The supported finding is administrative and operational-configuration disclosure, including integration secrets, rather than a complete emergency-management database dump.

Other ministry targets produced weaker results. File-sharing requests remained unauthenticated or returned `401`; emergency-dispatch attempts were rate-limited or rejected; account-elevation attempts did not produce a retained administrator session. Atlas should therefore be identified as the demonstrated application compromise, without extending that conclusion to all shortlisted MChS systems.

### The commercial branch reached deeper into a network

The same workspace contained stronger evidence of operating-system execution and business-data theft at **Union Travel**. A Zabbix service at `85.95.166[.]40:8080` accepted default credentials. The operator used its script-management functionality to execute commands.

Two calls in the retained automation show the mechanism; variable values are omitted:

```python
api("script.update", {"scriptid": sid, "command": cmd}, token)
api("script.execute", {"scriptid": sid, "hostid": hostid}, token, timeout=25)
```

Correlated transfer and tunnel logs then show `chisel` downloaded at 21:45:37 on 29 August, a reverse SOCKS tunnel established three seconds later, and `fscan` downloaded at 21:47:11. These times are recorded in logs without a verified timezone. The tunnel log includes:

```text
2026/08/29 21:45:40 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Chisel provided a route into the private network; fscan performed internal discovery. The resulting scan of `192.168.115.0/24` identified `office.union-travel.ru` and a mixture of workstations, servers, cameras, printers, telephony devices and other services.

Four SQL dumps in the workspace contained **406,654 inserted rows**, totalling **133.6 MB**. They covered customers, tourists, ticketing, employee or application accounts, and call-detail records. Rows are not unique people. Seven MP3 artifacts, representing six distinct file hashes, were consistent with call recordings.

The business-specific contents, internal hostname and tunnel chronology strongly support collection from this environment. The exact database-export command is absent, so the final extraction step cannot be reconstructed directly.

### Public tools, weak credentials and opportunistic expansion

This operation relied heavily on accessible management functions and public tools. Chisel supplied tunnelling, fscan supplied internal discovery, and custom scripts handled authentication, API access and collection. No distinct custom malware family, ransomware or wiper was identified.

Additional evidence included a Jenkins execution-and-tunnel chain, anonymous Confluence document collection, and Docker API access that exposed container configuration and secrets. Redis configuration writes staged cron-style callbacks on 15 hosts, but the retained callback log did not establish their execution. An etcd/Patroni configuration change similarly staged a malicious `archive_command` without showing that PostgreSQL executed it.

The toolkit referenced numerous CVEs, including **CVE-2024-4577** for PHP-CGI, **CVE-2024-3400** for PAN-OS, **CVE-2021-4034** for PwnKit and **CVE-2021-3156** for Baron Samedit. Their presence establishes exploit capability or intended use. The proven Atlas authorization failure and Zabbix default-credential chain cannot be assigned to those CVEs.

The distinction explains the operation’s success: the clearest gains came from inconsistent authorization, weak credentials and exposed administrative interfaces. A large exploit library was present, but it was not necessary to explain the most consequential observed outcomes.

Ukrainian-language comments and concentrated Russian targeting provide language and targeting context. They do not establish a specific group, nationality or state sponsor.

## 2. Kyrgyz MFA and the Syrian Customs Inventory — `207.148.64[.]94:8083`

The second directory exposed a C2-related working collection containing Linux payloads, command responses, transport diagnostics and a saved database. Hunt.io’s directory listing corroborates the presence of the distinctive operation and bridge directories, along with `db.original/`.

Two evidence sets need to remain separate. The first documents code execution on a host presented as the Kyrgyz Ministry of Foreign Affairs website. The second is a historical C2 inventory containing Syrian Customs-associated hostnames. Shared storage and compatible tooling do not establish that these were one continuous campaign.

### An image upload became a route to command execution

The recorded MFA workflow began with an **existing authenticated backend session**. It obtained a CSRF token, submitted a small GIF image containing PHP through an embassy-image upload field, located the resulting public `.php` file and requested it.

This type of file is often called a polyglot: it contains material interpretable in more than one format. Here, image content remained at the start of the response while PHP execution produced command output. A retained response contains:

```text
[43-byte GIF prefix omitted]
uid=33(www-data) gid=33(www-data) groups=33(www-data)

__ID_EXIT_CODE__=0
```

The first supplied successful proof is timestamped **28 August 2026 at 16:29:16 UTC**. Repeated captures identify the Linux host as `mfa`, with private address `10.51.6.93`, and execution under the web-service account `www-data`.

The demonstrated weakness was executable file upload through an authenticated application workflow. No defensible CVE assignment is available. The collection also does not establish how the initial backend session was acquired. An anonymous error response exposing internal application details is not evidence that authentication was bypassed.

The embassy upload directory identifies the application feature used. It does not mean that overseas embassies were independently compromised.

### VShell-compatible implants and a web-based transport

The operator initially tried a reverse-stage approach, but captures show errors and connectivity failures. The workflow then shifted to full Linux agents listening on the MFA host, first on port 8085 and then on 8086.

Two disk-backed payloads are tied to victim-side hashes, processes and socket evidence. The analysis identifies them with high confidence as **VShell or directly compatible builds**. The C2 log reports server/core version `4.9.3`; that version was not independently recovered from every binary.

The confirmed implant paths were:

```text
/tmp/.mfa-vshell-forward-8085
/tmp/.mfa-vshell-forward-8086
```

To carry traffic over the reachable website, the recorded operation used PHP endpoints under `/uploads/embassies/`, a Python helper and a Unix-domain socket. The reconstructed transport was:

```text
C2 service / SOCKS frontend
    → local TCP-to-HTTPS adapter
    → PHP endpoint on the MFA website
    → Unix socket and Python helper
    → local VShell-compatible agent
```

This is the collection’s most distinctive technical feature: adaptation to connectivity constraints by transporting implant traffic through the compromised application. Repeated revisions and reconnect attempts also show that the arrangement was unstable. Agent presence and working command exchanges are evidenced; reliable persistence across reboot is not.

A separate 9,800-byte C loader was present and served for download. Static analysis showed that it could retrieve a stage from `207.148.64[.]94:8084`, XOR-decode it with `0x99`, place it in a memory-backed file using `memfd_create`, and execute it with `fexecve` under the name `[kworker/0:2]`. Those are loader capabilities. Successful execution of that memory-loaded stage on the MFA host was not demonstrated.

### Secrets were collected; wider compromise remains unproven

From the web-service account, the recorded activity accessed application configuration, source excerpts, Git history and credentials. Material came from both the MFA application and a co-hosted UTN application. Exposed categories included database credentials, application and API secrets, cookie-validation keys, JWT-related material, and credentials for government integrations.

A local PostgreSQL session authenticated as `utn` and returned schema and role metadata. Table names included `person_info`, `organization`, `document`, `accident_record` and inspection-related records. This demonstrates database access and visibility into its structure. The collection does not contain extracted business rows from those tables.

A roughly 16 GB archive named `mfafront1.zip` appeared in a directory listing. Its presence does not establish that the operator created or downloaded it. It should not be counted as 16 GB of stolen MFA data.

The operator probed all 30 usable addresses in `10.51.6.64/27`, inspecting cloud-storage, notification, document-editing, licensing, vehicle-inspection and construction-expertise services. The visible activity included credential reuse, route discovery, exposed documentation and framework-specific tests.

Many follow-on attempts failed. A retained SSH verification summary reported 198 attempts and zero successes; a PostgreSQL reuse summary reported 40 attempts and zero successes. Other captures show authentication denials, source-access restrictions and timeouts. Local privilege checks did not demonstrate a root shell on MFA.

Laravel Ignition probing reached a debug/solution handler on an internal notification application, but did not demonstrate command execution. It should not be labelled successful **CVE-2021-3129** exploitation: the recorded framework/package context differed from the older affected stack, and no completed exploit chain was retained. An unsigned-JWT test that changed an error response from `403` to `500` likewise did not prove an authentication bypass.

The defensible outcome is substantial access to one recorded web host, deployment of two verified agent variants, collection of secrets and configuration, and extensive internal reconnaissance. Successful takeover of the additional Kyrgyz systems remains unproven.

### What the Syrian Customs records establish

The original C2 database contained **98 registrations representing 31 distinct hostname/IP pairs**. Five hostnames explicitly used `customs.gov.sy`, including `asyapp1`, `asyw-db1`, `asyw-db2`, `backup-01` and `oemcc`.

Adjacent entries described virtualization, storage, monitoring, collaboration, ERP and Windows systems. Reported account contexts included `root`, `oracle`, `vsphere-ui` and `NT AUTHORITY\SYSTEM`. If authentic, the inventory is consistent with broad infrastructure access in a Customs-associated environment.

These are self-reported agent identities, however, without the original exploitation chain, host-specific command history or independently verified compromise dates. Repeated registrations account for much of the database: two Windows identities alone contribute 60 rows. Ninety-eight registrations must not become 98 victims in the narrative.

The database also includes a probable test or analysis host, `PETER-PC`. Elsewhere, the collection contains `ctf` paths, a `test-virtual-machine`, probe labels and replay diagnostics. These markers leave the operational provenance unresolved. They do not erase the technical evidence, but they prevent a confident assertion that the entire collection represents one hostile actor compromising two governments.

No Syrian Customs business-data dump or verified theft volume is supplied. Reported C2 access is the strongest available evidence for that cluster.

## 3. Kyrgyz National Security Webmail and Russian Targets — `89.124.123[.]216:8080`

The third directory was first observed on **16 June 2026**, earlier than the two August exposures. Its 146-line shell history provides a view of interactive exploitation: cloning public repositories, installing dependencies, editing scripts, starting listeners and repeatedly changing payloads.

Its most persistent government target was `mail.gknb.gov[.]kg`, associated with Kyrgyzstan’s State Committee for National Security, or GKNB. The operator repeatedly attempted to exploit its Roundcube webmail service using account credentials supplied on the command line.

Unlike the preceding collections, this workspace lacks retained target responses, successful shell transcripts or collected victim data. It documents deliberate targeting and exploitation attempts, with no confirmed compromise.

### Repeated credential-supplied Roundcube attempts

The operator used public proof-of-concept implementations for **CVE-2025-49113**, a post-authentication remote-code-execution vulnerability involving PHP object deserialization. Roundcube addressed the issue in its June 2025 security releases, versions 1.6.11 and 1.5.10. That advisory establishes the vulnerability’s behavior, not whether the targeted installations were vulnerable. [Roundcube security announcement](https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10).

For GKNB, the history contains identity-discovery commands, netcat and shell callbacks, base64-wrapped variants and HTTP callbacks intended to carry encoded command output. A sanitized example preserves the attempted invocation while removing credentials and disabling the target URL:

```text
php CVE-2025-49113.php hxxps://mail.gknb.gov[.]kg/mail <ACCOUNT> <PASSWORD> "whoami"
```

The repeated changes show an operator trying to obtain or validate execution. They do not establish that a callback arrived. Even the validity of the supplied credentials remains unconfirmed because authentication results are absent.

Three other mail hosts appeared in credential-supplied Roundcube attempts: `mail.aca.cfuv[.]ru`, `mail.aviel[.]ru` and `mail.rcz-dnr[.]ru`. Commands aimed at the first included an attempt to read `/etc/shadow`; other attempts sought identity output or a reverse shell. The captured history reveals those objectives without proving the requested information was obtained.

### A wider collection of exploit tracks

The operator moved between webmail, edge appliances, databases and web applications. The workspace included the following tracks:

| Vulnerability or mechanism | Evidence in the directory | Supported outcome |
|---|---|---|
| Roundcube **CVE-2025-49113** | Credential-supplied commands against four mail hosts | Exploitation attempts; success unknown |
| PAN-OS **CVE-2024-3400** | Checker invocation and payload-generation tooling | The recorded checker syntax likely failed locally; no proven exploitation |
| PHP-CGI **CVE-2024-4577** | RCE-capable scripts invoked against URL variants on one host | Attempts; no retained results |
| ShareFile **CVE-2026-2699** | GET-based detection script used against six unique IPs | Detection requests; no captured exploitation chain |
| Ivanti Sentry tooling labelled **CVE-2026-10520** | Scanner and lists containing 598 endpoint strings across 542 hosts | List-only targeting; no recorded scanner invocation or results |
| Kerio Control / FreePBX | Malicious upgrade archive and authenticated-execution tooling | Payload preparation or attempted execution; no proven victim access |

The PAN-OS issue concerns command injection in affected GlobalProtect configurations; the PHP-CGI issue depends on particular Windows CGI and code-page conditions. Having the exploit does not establish those conditions on a target. [Palo Alto Networks advisory](https://security.paloaltonetworks.com/CVE-2024-3400), [PHP Group CVE description via NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-4577).

The ShareFile distinction is similarly important. The retained tool checked the response to `/ConfigService/Admin.aspx`. Its use did not demonstrate execution of the broader configuration-access and RCE chain described in the vendor advisory. [ShareFile security advisory](https://docs.sharefile.com/en-us/sharefile/storage-zones-controller/5-0/security-vulnerability-feb26).

The history also showed SQL-injection testing against a URL on Russia’s Federal Antimonopoly Service domain, `fas.gov[.]ru`, and execution of an incomplete-looking PHP/MySQL exploitation scaffold targeting `motcpiu[.]kg`. No successful result was retained for either.

Across the workspace, 559 unique target hosts were identified, but only 17 appeared in directly operated tracks. The large Ivanti lists account for most of the total. Treating every list entry as a scanned or compromised organization would substantially overstate the evidence.

### Staged payloads and intended data collection

The callback address `89.124.123[.]216` recurred across several exploit tracks, using ports 443, 8080 and 8081. That repetition links the attempts within this workspace to common staging and callback infrastructure.

A stock **p0wny PHP webshell** named `shell.php` was present. It supports command execution and file transfer, but no evidence demonstrates deployment to a victim. A small `upgrade.img` archive contained an `upgrade.sh` reverse-shell payload intended for Kerio’s custom-upgrade mechanism. The archive’s presence proves preparation, not delivery or execution.

No custom implant family or successful persistent C2 session was established. The operator relied on public exploits, ordinary shell utilities and short callback payloads.

The intended collection included password-file contents, command output and, in PAN-OS tooling, configuration data. Actual theft is unproven. The shell history also lacks reliable activity timestamps, so the June discovery date cannot be converted into exact dates for the GKNB attempts.

## What the Three Collections Show

These workspaces demonstrate how government targeting can coexist with opportunistic exploitation, but they show different depths of access and different levels of evidentiary certainty.

| Dimension | MChS / Russian commercial collection | MFA / Customs collection | GKNB / Russian-targeting collection |
|---|---|---|---|
| Target selection | Focused ministry shortlist within a mass-discovery corpus | MFA foothold followed by internal-service exploration; separate historical Customs inventory | Repeated webmail attempts alongside diverse appliance and application targets |
| Principal technique | Authorization failures, weak credentials and exposed management APIs | Authenticated executable upload, agents and HTTPS transport | Public CVEs, supplied credentials and iterative callback payloads |
| Strongest government result | Atlas administrative data access and application-state changes | Recorded MFA execution as `www-data`, implants and secret collection; provenance caveat | Targeting and attempts only |
| Wider success | Commercial execution, network pivots and retained SQL/audio | Internal reachability; additional Kyrgyz host compromise unproven | No confirmed compromise in the supplied evidence |
| Data evidence | Atlas configuration and integration secrets; commercial SQL, audio and other collected content | Application secrets, source/configuration and database metadata; no demonstrated business-record dump | Collection intent; no retained stolen data |
| Tooling | Chisel, fscan and custom automation | VShell-compatible agents, PHP/Python bridge, separate stage loader | Public PoCs, shell callbacks, staged p0wny webshell |

**Tradecraft differed most in how operators tried to extend access.** The first collection shows a practical route from exposed administration to reverse tunnelling and internal discovery. The second records adaptation around connectivity failures, using a compromised website to transport agent traffic. The third shows extensive manual experimentation, including syntax mistakes and repeated payload changes, without the outputs needed to establish success.

**Opportunism and focused targeting were compatible.** MChS received specific attention inside a much larger scan corpus. GKNB webmail received repeated attempts inside a workspace covering several unrelated technologies. A broad target list does not make a focused government target incidental; conversely, one government target does not make every opportunistic action part of a coordinated espionage mission.

**Success should be assessed at the resource actually accessed.** Atlas suffered demonstrated application-level access and modification without a proven server shell. The MFA captures show server execution and secrets collection, but no verified root access or wider Kyrgyz takeover. The GKNB evidence establishes intent and attempts. Historical Customs registrations suggest access, with substantially less corroboration than the MFA command captures.

The most consequential common feature was the exposure of the workspaces themselves. Target lists, credentials, payloads, command histories and collected information became available together. That gave investigators visibility into the operators’ decisions and, in the first collection, created further distribution of already collected data.

For defenders, the strongest lesson is to examine the chain of access rather than the length of an exploit list. Inconsistent API authorization, executable uploads, default credentials and reachable management services can turn a modest foothold into significant exposure. Public CVEs remain relevant, but these records show that successful access often depended on ordinary controls failing—and that many technically ambitious attempts still stopped short of a demonstrated compromise.

## IOCs

The table contains operator infrastructure and malware or host artifacts supported by the exposed workspaces. Victim-owned public systems are deliberately excluded.

| Indicator | Type | Context |
|---|---|---|
| `45.151.139[.]249:8765` | IP:port | Unauthenticated staging and data server for the MChS and Russian commercial campaign; first observed by Hunt.io on 30 August 2026. |
| `45.151.139[.]249:8888` | IP:port | Redis cron callback listener configured in the same operator workspace. |
| `207.148.64[.]94:8083` | IP:port | Exposed staging service containing the Kyrgyz MFA records and historical C2 database; first observed by Hunt.io on 30 August 2026. |
| `207.148.64[.]94:8084` | IP:port | Staging and C2 endpoint embedded in the analysed Linux stage loader. |
| `89.124.123[.]216:8080` | IP:port | Exposed operator workspace and recurring callback destination; first observed by Hunt.io on 16 June 2026. |
| `89.124.123[.]216:8081` | IP:port | Alternate reverse-shell listener and callback port used by payloads in the same workspace. |
| `f6ee6c03cead9ef26ad5e93f11437323c5e0acef0934468880ac740531234eaa` | SHA256 | VShell-compatible Linux payload variant present in the exposed MFA collection; exact execution location was not established. |
| `d79f80b7b2b437f8d8de2e6df54d637080230377c0a07dee384112fe5ef4a81f` | SHA256 | Linux TCP stage loader that retrieves and memory-executes an XOR-decoded payload from the configured staging endpoint; execution on MFA was not proven. |
| `576eed7cf2a6e8f900cc869b8b05620afb7609ed479412e32b139c8299847ada` | SHA256 | VShell-compatible Linux forward-agent variant present in the exposed MFA collection; no victim-side hash match was retained. |
| `6dceaa79c34ee2d6ea1734d77e1f1155292e9588f35427a6dcb18f7c0120187e` | SHA256 | VShell-compatible Linux forward agent whose hash was observed on the recorded MFA host with process evidence. |
| `d0ec32e389f3ea70d70cad67061ed6fa125641925821ec0546ebc463709d8f39` | SHA256 | VShell-compatible Linux forward agent whose hash was observed at `/tmp/.mfa-vshell-forward-8085` with process and listening-socket evidence. |
| `/tmp/.mfa-vshell-forward-8085` | File path | Confirmed implant path in the supplied Kyrgyz MFA execution records. |
| `/tmp/.mfa-vshell-forward-8086` | File path | Confirmed implant path for the second VShell-compatible MFA forward agent. |

## References

- [Hunt.io](https://hunt.io/)
- [Roundcube security updates 1.6.11 and 1.5.10](https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10)
- [Palo Alto Networks advisory for CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400)
- [NVD entry for CVE-2024-4577](https://nvd.nist.gov/vuln/detail/CVE-2024-4577)
- [ShareFile Storage Zones Controller security advisory](https://docs.sharefile.com/en-us/sharefile/storage-zones-controller/5-0/security-vulnerability-feb26)
- [Sysdig research on VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)
