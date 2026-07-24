---
title: "The Gentlemen Chronicles: Origins, OPSEC & OSINT"
classes: wide
header:
  teaser: /assets/images/gentlemen/1.png
ribbon: black
description: "Tracing The Gentlemen ransomware group's origins, infrastructure, OPSEC failures, organisational structure, and alleged leader."
categories:
  - Threat Research
tags:
  - Threat Research
  - Ransomware
  - OSINT
toc: true
---

# Executive Summary

The Gentlemen ransomware group has rapidly emerged as one of the most prolific Ransomware-as-a-Service operations of 2026. As of June, [ransomware.live](https://ransomware.live/group/thegentlemen) records nearly 500 claimed victims, placing the group second only to Qilin.

In this blog, we examine The Gentlemen's rise, operations, and weaknesses. We will focus on the group's origins, rapid growth, infrastructure, organisational structure, affiliates, and the OPSEC failures that exposed key parts of their ecosystem.

Those mistakes allowed us to track cybercriminal infrastructure linked to the group's alleged leader across a multi-year timespan. Separately, we analyse his movements across Russia and internationally, including travel to Dubai, China, Vietnam, and Thailand. This allowed us to identify additional photographs of the suspected ringleader and corroborate our findings against public reporting and leaked communications.

# Origins

The group gained public attention in September 2025 through an underground criminal forum advertisement posted by [zeta88](https://x.com/KrakenLabs_Team/status/1983458109323362432?s=20), which invited "teams and individual pentesters to collaborate." The advertisement offered affiliates a 90% share of ransom payments, control over negotiations, and a minimal infrastructure model that claimed to "guarantee affiliate security and reduce attack surface."

[![1](/assets/images/gentlemen/1.png){: .align-center .img-border}](/assets/images/gentlemen/1.png)
<p class="figure-caption">Affiliate Advertisement - The Gentlemen's RaaS</p>

September 2025 is not the beginning of the story. The Gentlemen group evolved from ArmCorp - a successful Qilin affiliate that left the RaaS over financial disputes. The ArmCorp group was run by `hastalamuerte`, believed to be the same individual behind the `zeta88` handle.

* **March to June 2025** - [PRODRAFT](https://catalyst.prodaft.com/public/report/inside-the-phantom-mantis-operation/overview) reports that ArmCorp's Rocket.Chat server had 34 registered users. Handles included `hastalamuerte`/`zeta88`, `DevMan`, `Protagor`, `Wick`, `Qbit`, `mAst3r`, `barinov`, and more.
  * `hastalamuerte`/`zeta88` was managing the server, creating new channels for victims and providing initial access to affiliates.
  * During this time, Devman was a known Qilin affiliate.
* **7 April 2025** - [@RakeshKrish12 tweeted](https://x.com/RakeshKrish12/status/1909169075365835014?s=20) the "Devman's Place" onion site. Devman shared writeups for Qilin intrusions and advertised 20 June as the release date of "his own RAAS platform!"

[![2](/assets/images/gentlemen/2.png){: .align-center .img-border}](/assets/images/gentlemen/2.png)
<p class="figure-caption">Devman's Place</p>

* **13 June 2025** - [Group-IB](https://www.group-ib.com/blog/hastalamuerte-gentlemen-raas-ttps/) reports the Rocket.Chat server was titled "ARMCORP."
* **1 July 2025** - [Devman tweets](https://x.com/Inifintyink/status/1940287983191761027) about a Qilin decryption vulnerability and shares communications surrounding their payout percentage.

[![3](/assets/images/gentlemen/3.png){: .align-center .img-border}](/assets/images/gentlemen/3.png)
<p class="figure-caption">Devman tweets about a Qilin decryption vulnerability</p>

* **11 July 2025** - [Group-IB](https://www.group-ib.com/blog/hastalamuerte-gentlemen-raas-ttps/) reports the Rocket.Chat server was renamed to "GENTLEMEN."
* **17 July 2025** - The first ransomware sample linked to The Gentlemen group was found on [VirusTotal](https://www.virustotal.com/gui/file/51b9f246d6da85631131fcd1fabf0a67937d4bdde33625a44f7ee6a3a7baebd2).
* **22 July 2025** - `hastalamuerte` raised an arbitration on the RAMP forum against Qilin, requesting $48k over mishandled ransomware proceeds.
  * [Group-IB](https://www.group-ib.com/blog/hastalamuerte-gentlemen-raas-ttps/) and [Analyst1](https://analyst1.com/threat-actors/the-gentlemen/) claim Devman was also involved in surrounding discussions at similar times.
* **9 September 2025** - The first public The Gentlemen DLS leak victim appeared.

Analysis of forum activity and social media posts suggests that both Devman and `hastalamuerte`'s ArmCorp, of which Devman was a member, had developed disagreements and hostility toward Qilin while operating as affiliates.

Following these disputes, members of ArmCorp appear to have split into two competing RaaS efforts. `hastalamuerte`, the original ArmCorp administrator, went on to create The Gentlemen, while Devman launched his own brand and appears to have taken at least one other ArmCorp member with him.

# Operational Security Failures

Operational Security (OPSEC) has been a persistent issue for The Gentlemen ransomware group and specifically its administrator `hastalamuerte`, causing significant damage to the reputation of the RaaS throughout 2026.

* Ctrl-Alt-Intel identified a Google Maps account active from 2017 to December 2025, which allowed us to trace the suspected leader's travel across Russia and internationally.
* Ctrl-Alt-Intel also identified cybercrime forum breach data exposing IP addresses linked to `hastalamuerte`. These were later corroborated through The Gentlemen leaks and connected to RMM abuse and C2 infrastructure over multiple years.
* On 19 March 2026, Group-IB published [Hasta la vista, Hastalamuerte: An Overview of The Gentlemen's TTPs](https://www.group-ib.com/blog/hastalamuerte-gentlemen-raas-ttps/).
* On 30 March 2026, a The Gentlemen affiliate exposed an [open directory](https://portal.hunt.io/attackcapture/filemanager?host=http%3A%2F%2F77.110.122.137%3A8888&isExcluded=false&tab=files) on the [Hunt.io](https://hunt.io/) platform.
* On 22 April 2026, a The Gentlemen affiliate exposed another [open directory](https://portal.hunt.io/attackcapture/filemanager?host=http%3A%2F%2F193.233.202.17%3A8080&isExcluded=false&tab=files) on the [Hunt.io](https://hunt.io/) platform.
* On 8 May 2026, the user `n345` leaked extensive communications from The Gentlemen Rocket.Chat spanning November 2025 to April 2026.
* On 10 June 2026, Brian Krebs published [Who Runs the Ransomware Group 'The Gentlemen?'](https://krebsonsecurity.com/2026/06/who-runs-the-ransomware-group-the-gentlemen/), exposing the suspected identity behind `hastalamuerte` as Alexander Andreevich Yapaev.

## Rocket.Chat Leaks

* From May 2025 to April 2026, [PRODRAFT](https://catalyst.prodaft.com/public/report/inside-the-phantom-mantis-operation/overview) identified 34 users within the Rocket.Chat group, including `DevMan` and `barinov`.
* From May 2026, [Ransom-ISAC](https://ransom-isac.com/blog/the-gentlemen-leak-analysis/) identified nine usernames from the exposed The Gentlemen Rocket.Chat communications - all of which were identified by PRODRAFT.
* From the December 2025 Devman Rocket.Chat leak, [Ctrl-Alt-Intel](https://ctrlaltintel.com/research/Devman-RaaS/) identified multiple usernames, including those from the original ArmCorp chat.

These leaks have been discussed in detail by multiple vendors and researchers, so we will not repeat those analyses. However, we will later corroborate our new findings with the prior communications during our OSINT investigation.

The reuse of monikers across multiple "private communications" servers is poor operational security practice. As shown below, if these servers are leaked, it is possible to see the evolution and separation of individuals or affiliates into separate groups from username handles alone.

[![4](/assets/images/gentlemen/4.png){: .align-center .img-border}](/assets/images/gentlemen/4.png)
<p class="figure-caption">ArmCorp username continuity into two later ransomware groups</p>

## A Very Unusual IP Address

Rocket.Chat leaks, as highlighted by [Ransom-ISAC](https://ransom-isac.com/blog/the-gentlemen-leak-analysis-part-2/) and [The Raven Files](https://theravenfile.com/author/theravenfile/), included recovered MegaCMD sessions attributed to the residential Russian IP address `92.39.211[.]142`, geolocated to Izhevsk, Russia. This location becomes important later in the investigation. The sessions were reportedly first observed on 2025-11-14 and last observed on 2025-12-19.

Ctrl-Alt-Intel used the `databoose.sql` BreachForums database leaked from ShinyHunters to identify that `hastalamuerte` was observed active on 2025-02-09 from this same Izhevsk residential IP address.

Leveraging the [Hunt.io](https://hunt.io/) platform and pivoting on this Izhevsk-geolocated IP address, we can see historic links to Havoc and XenoRAT infrastructure.

[![5](/assets/images/gentlemen/5.png){: .align-center .img-border}](/assets/images/gentlemen/5.png)
<p class="figure-caption">Hunt.io - 92.39.211.142 - Past ports</p>

[![6](/assets/images/gentlemen/6.png){: .align-center .img-border}](/assets/images/gentlemen/6.png)
<p class="figure-caption">Hunt.io - 92.39.211.142 - SSL history</p>

Furthermore, from 11 May 2025 to the beginning of January 2026, Hunt.io's SSL history telemetry suggested the domain `windows-mesh.duckdns[.]org` was being used. On 14 May 2025, a [MeshAgent sample](https://www.virustotal.com/gui/file/295b173db2473270726b7187892bfbb15b93351319e71575e0dd05bf86a4d0d2/details) was uploaded to VirusTotal that observed communications with the domain `windows-mesh.duckdns[.]org` (`92.39.211[.]142`).

[![7](/assets/images/gentlemen/7.png){: .align-center .img-border}](/assets/images/gentlemen/7.png)
<p class="figure-caption">AbuseIPDB - 92.39.211.142</p>

Notably, this IP address was linked to SSL/VPN brute-force activity spanning from late December 2024 to early 2025. Targeting corporate VPN devices is a common tactic for gaining initial access. The Gentlemen ransomware, like most prolific groups, has been known to do this.

Additionally, on 16 August 2023, three Word documents containing malicious macros were uploaded to VirusTotal in short succession. These were uploaded shortly after their creation date, suggesting the threat actor may have been testing payloads.

| File name | C2 URLs and artefacts |
|---|---|
| [RIGHTESTSIGNED.doc](https://www.virustotal.com/gui/file/1d4bd31d82588bf8ea6e5c8342cb6b73d1767d3c74bce480310c4f2342c5983f) | `hXXp://92.39.211[.]142:5555/ga.js` |
| [RIGHTEST.doc](https://www.virustotal.com/gui/file/dace6fa7e8f4eec95ced8f738675b801f6cf5a92a461912db6f5a3af223cb1b) | `hXXp://92.39.211[.]142:5555/ga.js`<br>`hXXp://92.39.211[.]142:5555/oHbC` |
| [RIGHTVT.doc](https://www.virustotal.com/gui/file/fa688fad8660a732cc40116f1b82d7ee27c909acb5273519ab0fb3424d23b394) | `hXXp://92.39.211[.]142:5555/ga.js`<br>`hXXp://92.39.211[.]142:5555/oHbC`<br>`hXXp://92.39.211[.]142:5555/submit.php?id=1366251514` |

The URIs `/ga.js` and `/submit.php?id=*` can be linked to a Cobalt Strike default beaconing profile, previously reported by [Unit42](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/). The same day these payloads were uploaded to VirusTotal, [Sekoia.io](https://sekoia.io/) provided corroborating evidence linking the IP address `92.39.211[.]142` to a Cobalt Strike C2 server.

[![8](/assets/images/gentlemen/8.png){: .align-center .img-border}](/assets/images/gentlemen/8.png)
<p class="figure-caption">Sekoia.io reporting links 92.39.211.142 to a Cobalt Strike C2 server</p>

| Timeline | Activity linked to Izhevsk residential IP `92.39.211[.]142` |
|---|---|
| May 2023 | Suspected AsyncRAT, port `6969` - [VirusTotal](https://www.virustotal.com/gui/file/d8b60130a130c3370b4117042430f1b688630d228ea5c3751fbceeae2f88771c) |
| August 2023 | Suspected AsyncRAT, port `6969` - [VirusTotal](https://www.virustotal.com/gui/file/a3fc3453664bdb9f33af5a7037aa5f4385d5778ff82bb0a59539bc51edd55ef0) |
| August 2023 | Maldoc to Cobalt Strike C2 - `/ga.js`, `/oHbC`, `/submit.php=...` - [VirusTotal](https://www.virustotal.com/gui/file/fa688fad8660a732cc40116f1b82d7ee27c909acb5273519ab0fb3424d23b394) |
| September 2023 | Havoc C2, port `443` - [ThreatFox](https://threatfox.abuse.ch/ioc/1162921/) |
| February 2024 | Havoc C2, port `4444` - [Hunt.io](https://portal.hunt.io/ip/92.39.211.142?tf=30) |
| December 2024 | SSL/VPN brute force - [AbuseIPDB](https://www.abuseipdb.com/check/92.39.211.142) |
| January 2025 | SSL/VPN brute force - [AbuseIPDB](https://www.abuseipdb.com/check/92.39.211.142) |
| February 2025 | `hastalamuerte` last seen accessing BreachForums |
| November 2025 | MeshAgent C2, port `6969` - [Hunt.io](https://portal.hunt.io/ip/92.39.211.142/ssl-history), [VirusTotal](https://www.virustotal.com/gui/file/295b173db2473270726b7187892bfbb15b93351319e71575e0dd05bf86a4d0d2) |
| November to December 2025 | MegaCMD session logs - The Gentlemen leaks |

The most significant finding here was `hastalamuerte` accessing BreachForums from this IP address. We also found it interesting that, across a two-year timespan, port `6969` was seen in use on multiple occasions.

This residential IP address raised many unanswered questions for Ctrl-Alt-Intel:

* Was this `hastalamuerte`'s personal home IP address, and did he also use it to host C2 infrastructure?
  * We later confirm `hastalamuerte`/`zeta88` is based in Izhevsk.
* Is this IP address associated with an office in Izhevsk where cybercrime activity was occurring?
  * Could this activity be tied to multiple individuals rather than just `hastalamuerte`/`zeta88`?

Regardless of these questions, the fact that this residential IP address was used for not just Command and Control infrastructure, but also accessing forums and MegaCMD, was a huge OPSEC failure.

# Organisational Structure

From the leaks, as discussed by many vendors already, we can ascertain the vague roles and responsibilities of many individuals. We will not go into detail, although we will focus on `zeta88`.

* `zeta88` - clear leader, administrator, and ringleader of the group. The same individual behind `hastalamuerte`.
  * Also observed performing hands-on intrusion activity and negotiation.
* `qbit` - focuses on access, infrastructure, exploitation, and tooling.
* `Protagor` - hands-on-keyboard operator.
* `Wick` - often mentioned in relation to lateral movement, evasion, and deployment.
* `mAst3r` - hands-on-keyboard operator working closely with Wick.
* `quant` - often seen providing initial access.
* `Kunder` - likely affiliate; mentions of G-BOT developer/operator. Appeared to run his own team.
* `JeLLy` - role not fully clear.
* `Bl0ck` - role not fully clear.

## Success Under Stress

Even after reputational damage ranging from extensive communication leaks to the public de-anonymisation of the group's alleged leader, `hastalamuerte`/`zeta88`, The Gentlemen has shown little indication of slowing down:

[![9](/assets/images/gentlemen/9.png){: .align-center .img-border}](/assets/images/gentlemen/9.png)
<p class="figure-caption">The Gentlemen victims per month - ransomware.live</p>

May 2026 had the largest recorded number of victims during the group's timeline, with an average of three victim organisations per day.

# Tracking The Gentlemen's Leader Across the Globe

Due to fantastic reporting and OSINT analysis by [Brian Krebs](https://krebsonsecurity.com/2026/06/who-runs-the-ransomware-group-the-gentlemen/), we were able to gain insight into the identity behind `hastalamuerte`/`zeta88` - Alexander Andreevich Yapaev, born on 19 July 1989 - who was identified via the email [`bu4vs@mail.ru`](mailto:bu4vs@mail.ru).

Ctrl-Alt-Intel found further corroborating evidence that `hastalamuerte`/`zeta88` was the identity behind Alexander Yapaev from a [SoundCloud account](https://soundcloud.com/alexandr-4apaev) with the username `h@st@l@mu3rt3`, linked to the name "Alexandr 4apaev":

[![10](/assets/images/gentlemen/10.png){: .align-center .img-border}](/assets/images/gentlemen/10.png)
<p class="figure-caption">SoundCloud account linked to Alexandr 4apaev</p>

The email identified by Krebs appeared to be inactive for a few years. However, using it, we can still find his photo linked to the LinkedIn account below:

[![11](/assets/images/gentlemen/11.jpg){: .align-center .img-border}](/assets/images/gentlemen/11.jpg)
<p class="figure-caption"><a href="https://www.linkedin.com/in/yapaev/">LinkedIn profile - Alexander Yapaev</a></p>

The email identified by Krebs was also registered on Shodan, a tool that can allow cybercriminals to identify devices on the internet.

Krebs also shared one of the mobile numbers used by Yapaev, `79127650004`. The Russian equivalent of DHL/FedEx, [CDEK](https://www.cdek.ru/ru/), suffered a data breach in 2022. In this breach, the above mobile number was linked to the email address [`stoneralexandr@gmail.com`](mailto:stoneralexandr@gmail.com), which, unlike [`bu4vs@mail.ru`](mailto:bu4vs@mail.ru), appeared to be active during the time of writing this article.

The [`stoneralexandr@gmail.com`](mailto:stoneralexandr@gmail.com) email address has been linked to the username `n0 0n3` across Google, Notion, and AliExpress.

Unlike many Russian males who are currently fighting a war, analysis of Google Maps reviews linked to the email address [`stoneralexandr@gmail.com`](mailto:stoneralexandr@gmail.com), used by Alexander Yapaev, suggested he had been spending time abroad. However, we also observed domestic travel and Russian residency during the full-scale invasion, which we will discuss later.

On 10 December 2025, Yapaev left a review at Guanyin of Nanshan in Hainan, China:

[![12](/assets/images/gentlemen/12.png){: .align-center .img-border}](/assets/images/gentlemen/12.png)
<p class="figure-caption">Google Review by Yapaev / stoneralexandr@gmail.com</p>

Analysis of the leaked Rocket.Chat communications can corroborate Yapaev's presence in China. On 2 February 2026, two months after his visit, `zeta88` (Yapaev) mentioned:

> I miss China - more precisely, Chinese food and the weather.

Given the group's recorded victims in China and the public exposure of Yapaev's alleged identity, any future travel to China may carry elevated legal risk.

Over two months later, `zeta88` asked `quant` whether he had been living it up for four months, questioning whether he had been enjoying Chinese opium. `quant` made a clear negative statement on opium drug abuse but confirmed he had been in Hainan, China.

| Date | User | English translation |
|---|---|---|
| 4/11/2026 | `zeta88` | You've been living it up / having fun for 4 months lol. |
| 4/11/2026 | `zeta88` | Chinese opium? |
| 4/17/2026 | `quant` | I've been in Hainan for a while. |
| 4/17/2026 | `quant` | Fuck no, I was in Hainan, bro - what "living it up"? |
| 4/17/2026 | `quant` | First the computer, then the hospital, Hainan, and now I'm here. |
| 4/17/2026 | `quant` | There are no targets. I dig through the logs every day. |
| 4/17/2026 | `quant` | Everything is zero / nothing useful. It's all crap. |
| 4/17/2026 | `quant` | Me and 902... I'm saying that with the logs, I can't even keep up myself. It's all bullshit, zero-value stuff. What opium? Stop it - I'm totally against that shit. |

It appears that at least two members of the group, `zeta88` (Yapaev) and `quant`, have travelled to Hainan, China within the last year.

Furthermore, we can see clear frustration from `quant` that, during March, they were struggling to get victims. `quant` said, "There are no targets" and "nothing useful. It's all crap."

These statements can be reflected in the ransomware.live statistics, with March showing significantly lower victim rates than the preceding and future months:

| Month (2026) | Number of victims |
|---|---:|
| February | 89 |
| **March** | **50** |
| April | 86 |
| May | 90 |
| June (up to 26th) | 75 |

On 16 August 2024, Alexander Yapaev appeared to travel to Dubai, UAE, leaving a positive review at the four-star [Park Regis Business Bay](https://www.parkregisbusinessbay.com/):

[![13](/assets/images/gentlemen/13.png){: .align-center .img-border}](/assets/images/gentlemen/13.png)
<p class="figure-caption">Google Review by Yapaev / stoneralexandr@gmail.com</p>

At the time of writing, The Gentlemen ransomware group has had five recorded UAE-based victims. As Yapaev is suspected to be the ringleader of the group, future travel to the UAE may carry significant legal risk.

As a final testament to incredibly poor Operational Security practices, it appeared that in April 2019 Yapaev, and at least one friend, travelled to Ko Samui and Ko Pha Ngan, leaving multiple reviews across both Thai islands:

[![14](/assets/images/gentlemen/14.png){: .align-center .img-border}](/assets/images/gentlemen/14.png)
<p class="figure-caption">Google Reviews by Yapaev / stoneralexandr@gmail.com</p>

During his time on the islands, Yapaev left multiple photos detailing his activities across tropical beaches and Buddhist temples. What we found most interesting was his face posted with a snake at a "Cobra Show" on Ko Samui island:

[![15](/assets/images/gentlemen/15.png){: .align-center .img-border}](/assets/images/gentlemen/15.png)
<p class="figure-caption">Google Review by Yapaev / stoneralexandr@gmail.com</p>

Included within this post was another individual holding the snake. This individual has not been included because we cannot assess their involvement.

Much like China and the UAE, at the time of writing, The Gentlemen ransomware group has 35 recorded Thai victims. As a result, we can assume it is in Yapaev's best interest not to return.

Additionally, this new email was linked to the X/Twitter account [@nO_0n3_C2](https://x.com/nO_0n3_C2). Hunt.io has already provided evidence of the handle `n0_0n3` being linked to Alexander Yapaev, also seen as the username for his Google Maps account. The X account has the profile picture below:

[![16](/assets/images/gentlemen/16.png){: .align-center .img-border}](/assets/images/gentlemen/16.png)
<p class="figure-caption">Figure 14 - Yapaev's X profile in HCMC, Vietnam</p>

This photo was taken from [Landmark 81](https://en.wikipedia.org/wiki/Landmark_81) in Ho Chi Minh City, the tallest building in Vietnam.

## Yapaev's Presence in Russia

From traffic fines, driver licence records, credit history records, T-Mobile records, and Rosreestr - Russia's federal service for state registration - it is clear Yapaev has been linked to an address on Karl Marx Street, Izhevsk, within the Udmurt Republic since at least 2012.

Other addresses within Izhevsk were also linked to Yapaev throughout 2021 to 2022 via Yandex Eats - a Russian equivalent to Uber Eats.

Regardless, it is clear the leader of The Gentlemen spent considerable time within Izhevsk. This was corroborated by the [Krebs report](https://krebsonsecurity.com/2026/06/who-runs-the-ransomware-group-the-gentlemen/), which suggested `zeta88` and `hastalamuerte` both registered on cybercrime forums from IP addresses that could be geolocated to Izhevsk.

From this report, it was noted that Intel 471 revealed that the BreachForums registration for `hastalamuerte` was in January 2025, indicating Yapaev's presence within Russia at the beginning of 2025.

With access to flight records linked to Yapaev's passport number, we can see Yapaev often travelled from Izhevsk to Moscow with similar return flights. Flights from Kazan and St. Petersburg were also seen on multiple occasions.

| Date | Flight number | Departure | Destination |
|---|---:|---|---|
| 2018-05-06 | 307 | Izhevsk (IJK) | Moscow (DME) |
| 2019-03-08 | 5538 | Kazan (KZN) | St. Petersburg (LED) |
| 2021-04-10 | N4129 | St. Petersburg (LED) | Simferopol (SIP) |
| 2021-04-30 | WZ769 | Simferopol (SIP) | Kazan (KZN) |
| 2023-02-27 | I8307 | Izhevsk (IJK) | Moscow (DME) |
| 2023-03-08 | 5538 | Kazan (KZN) | St. Petersburg (LED) |
| 2023-03-29 | I8308 | Moscow (DME) | Izhevsk (IJK) |

Throughout the OSINT investigation, we also identified many individuals we assess to be close to Yapaev. We have yet to confirm the roles of these individuals, so we will not include comprehensive analyses of their travel and online presence.

However, one of these individuals, Ostanin, stood out. Ostanin, also based in Izhevsk, was observed travelling on the same 2021 flights, N4129 and WZ769, as Yapaev. Additionally, Ostanin was listed as the policyholder on the car insurance for which Yapaev was listed as the driver from 2021-03-28 to 2022-03-27.

Yapaev was driving an INFINITI G37 with the number plate `E348AT18`. The last two numbers reference the registration location - in this case, 18, which is linked to the Udmurt Republic. The capital of the Udmurt Republic is Izhevsk.

There is an overwhelming amount of evidence suggesting Yapaev's presence in Izhevsk, in the Udmurt Republic of Russia.

# Conclusion

The Gentlemen's growth has been rapid, but not clean. The group appears to have emerged from the fallout around ArmCorp and Qilin, inheriting experienced operators, existing relationships, and a model designed to attract affiliates quickly.

Yet the same ecosystem has produced repeated OPSEC failures. Leaked chats, reused monikers, exposed infrastructure, forum breach data, and personal OSINT traces created a trail that could be followed across multiple years, platforms, and locations.

For defenders, the key lesson is that ransomware groups are rarely isolated brands. They are networks of people, aliases, infrastructure, habits, and mistakes. In The Gentlemen's case, those mistakes exposed enough connective tissue to link the group's origins, infrastructure, and alleged leadership with far more clarity than its operators likely intended.

# References

* [PRODRAFT - "Inside the Phantom Mantis Operation"](https://catalyst.prodaft.com/public/report/inside-the-phantom-mantis-operation/overview#paragraph-1000%7C0)
* [Brian Krebs - "Who Runs the Ransomware Group 'The Gentlemen?'"](https://krebsonsecurity.com/2026/06/who-runs-the-ransomware-group-the-gentlemen/)
* [@KrakenLabs_Team - "New RaaS recruiting: The Gentlemen's RaaS"](https://x.com/KrakenLabs_Team/status/1983458109323362432?s=20)
* [Group-IB - "An Overview of The Gentlemen's TTPs"](https://www.group-ib.com/blog/hastalamuerte-gentlemen-raas-ttps/)
* [Analyst1 - "The Gentlemen"](https://analyst1.com/threat-actors/the-gentlemen/)
* [Ransom-ISAC - "The Gentlemen Ransomware Group - Leak Analysis"](https://ransom-isac.com/blog/the-gentlemen-leak-analysis/)
* [Ransom-ISAC - "The Gentlemen Leak Analysis (Part 2) - JA456 Follow-on"](https://ransom-isac.com/blog/the-gentlemen-leak-analysis-part-2/)
* [The Raven Files - "GENTLEMEN RANSOMWARE LEAKS"](https://theravenfile.com/2026/05/23/gentlemen-ransomware-leaks/)
* [@RakeshKrish12 - "DEVMAN Ransomware announced"](https://x.com/RakeshKrish12/status/1909169075365835014?s=20)
* [Unit42 - "Cobalt Strike Malleable C2 Profile"](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/)
* [Ctrl-Alt-Intel - "How not to run a RaaS Operation"](https://ctrlaltintel.com/research/Devman-RaaS/)
