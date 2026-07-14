---
title: "Burnt by Burgers: Highlighting Void Blizzard's Russian State Links"
classes: wide
header:
  teaser: /assets/images/wp2/logo.jpg
ribbon: black
description: "OSINT analysis of Denis Obrezko & the Void Blizzard threat group"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Overview

On 30 October 2025, Russian citizen *Denis Obrezko* landed in Phuket, Thailand. Less than a week later, Thai authorities arrested him at the request of the FBI. *Obrezko* has since been extradited and indicted in the United States, where he is accused of participating in the Russian state-aligned threat group *Void Blizzard*, also known as *Laundry Bear*.

Following his arrest, Moscow reportedly placed *Obrezko* on an [international arrest warrant](https://www.gazeta.ru/social/news/2026/01/07/27571459.shtml). We assess this may have been intended to distance the Russian state from him by presenting *Obrezko* as a rogue criminal rather than a state-linked operative.

Using identifiers disclosed in FBI affidavits and indictments, Ctrl-Alt-Intel identified evidence connecting *Obrezko* to the *Information and Analytical Center of EMERCOM of Russia*, a state institution within Russia's *Ministry of Emergency Situations*. Our findings indicate that this connection was active during at least 2021.

## *Void Blizzard* Recap

Microsoft named [*Void Blizzard*](https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/) in May 2025, describing it as a Russia-affiliated threat actor conducting cyberespionage against NATO member states and Ukraine.

Working with the Netherlands' AIVD and MIVD intelligence agencies, Microsoft tracked the group from at least April 2024. In April 2025, it observed *Void Blizzard* using spear phishing to steal credentials. Although its techniques were not unique, Microsoft reported that they achieved widespread success.

Microsoft also identified targeting overlaps with other Russian state actors, including GRU-aligned groups, suggesting shared intelligence-collection priorities.

> Ctrl-Alt-Intel has previously exposed [Moscow linked actors](https://ctrlaltintel.com/research/FancyBear/) using phishing for espionage purposes

# Indictment & Affidavits 

In June 2026, US authorities released indictments and affidavits alleging that *Obrezko* had a history of involvement with Russian intelligence. According to the indictment, "between approximately 2012 and 2017, OBREZKO worked in an unknown capacity for [...] the Federal Security Service," or FSB.

[![1](/assets/images/vb/1.png){: .align-center .img-border}](/assets/images/vb/1.png)
<p class="figure-caption">FBI indictment</p>

The indictment further alleges that, from at least 2024, *Obrezko* worked as deputy director of the Russian technology company *Yutek-NN*, which US authorities link to *Void Blizzard*'s operations.

> Public records show that *Yutek-NN* holds an FSB-issued licence covering regulated surveillance-related technology. 

The FBI affidavit identifies *Obrezko* and lists infrastructure, IP addresses, domains, email addresses and a mobile number allegedly connected to him.

[![1](/assets/images/vb/2.png){: .align-center .img-border}](/assets/images/vb/2.png)
<p class="figure-caption">FBI affidavits</p>

## Indicators Linked to *Obrezko*

Throughout the affidavit, the FBI identified three email addresses and one mobile number linked to *Obrezko*:

* `wisperrrrr[@]gmail.com`
* `w1sper[@]mail.ru`
* `denis.obrezko[@]gmail.com`
* `+79263799902`

These identifiers allowed Ctrl-Alt-Intel to examine breached datasets for additional evidence concerning *Obrezko*'s professional history and connections to the Russian state.

# *Denis Obrezko*

Data from the 2012 VK breach contains an account associated with the email address `w1sper[@]mail.ru` and mobile number `+79263799902`:

* Full name: `Денис Wisperrrrr Обрезко` (*Denis Wisperrrrr Obrezko*)
* Username: `wisperrrrr`
* University: `МГТУ им. Баумана` (Bauman Moscow State Technical University)
* Faculty: `Информатики и систем управления` (Informatics and Control Systems)
* Speciality: `Информационная безопасность` (Information Security)

The account listed Information Security as *Obrezko*'s university speciality as early as 2012. 

## Ministry of Emergency Situations (EMERCOM)

Russia's Ministry of Emergency Situations, commonly known as [EMERCOM](https://en.wikipedia.org/wiki/Ministry_of_Emergency_Situations_(Russia)), was formally established in 1994. Its full translated name is the Ministry of Civil Defence, Emergencies and Disaster Relief of the Russian Federation:

[![1](/assets/images/vb/3.png){: .align-center .img-border}](/assets/images/vb/3.png)
<p class="figure-caption">EMERCOM emblem</p>

EMERCOM contains a sub-department, *ИАЦ МЧС РОССИИ*, the *"Information and Analytical Center"*, which is reportedly responsible for the internal IT & information-security of EMERCOM. For brevity, we refer to it as *IAC EMERCOM*.

In data attributed to a 2023 Alfa-Bank breach, we identified an additional telephone number associated with *Obrezko*:

[![1](/assets/images/vb/4.png){: .align-center .img-border}](/assets/images/vb/4.png)
<p class="figure-caption">AlfaBank 2023 data</p>

> Highlighted in Yellow are previously known pieces of data, linked already to *Obrezko*. The new number `+74994457578` allowed us to pivot through additional breached data

**OneClickMoney Breach** 

OneClickMoney is a Russian online lending service. Applicants may provide details about their salary, employer, workplace and work telephone number during financial checks. OneClickMoney was also subject to a breach which gave us additional data to query. 

Pivoting on the new mobile number, `+74994457578`, we identified three applicants who listed it as their work telephone number. We are not naming these individuals. All three supplied the same employer and workplace information:

* Work: `ФГБУ "ИАЦ МЧС РОССИИ"` - Federal State Budgetary Institution "Information and Analytical Center of the EMERCOM of Russia"
* PlaceOfWork: `г Москва, ул Давыдковская, д 7 стр 2`
* WorkPhone: `+74994457578`

Additionally, from a CDEK (Russian version of DHL) data breach, we could find corroborating evidence to suggest the mobile number `+74994457578` was linked to *IAC EMERCOM*. 

We assess with high-confidence is not a mobile number used by *Obrezko* but rather an office/work number linked to *IAC EMERCOM*

[![1](/assets/images/vb/5.png){: .align-center .img-border}](/assets/images/vb/5.png)
<p class="figure-caption">Correlation Diagram #1</p>

> Highlighted in purple are the identifiers revealed by the FBI, with the new mobile number highlighted in red

> *Obrezko*'s use of an *IAC EMERCOM*-associated number in the Alfa-Bank data supports an employment connection, but does not provide conclusive evidence by itself.

# Burnt by Burgers

To test this connection further, we examined leaked datasets attributed to the Russian food-delivery services *Yandex Food* and *Delivery Club*.

On the 1st March 2021 at 15:30 Moscow time, from an iOS device linked to the IP address `31.173.86[.]36`, the *Obrezko* email address `wisperrrrr@gmail.com` ordered from McDonald's:

* a Lipton Iced Tea
* 9 Chicken McNuggets 
* a McChicken Burger

This order was delivered to the below address: 

`Москва, Давыдковская улица, 7А` (7A Davydkovskaya Street, Moscow)

We can visit this exact address on Google Maps and verify it is the entrance of an EMERCOM VNIIGOChS building

[![1](/assets/images/vb/6.png){: .align-center .img-border}](/assets/images/vb/6.png)
<p class="figure-caption">McDonald's Delivery Location</p>

> Highlighted in red is the EMERCOM title & emblem we previously shared 

> This department building is associated with "All-Russian Research Institute for Civil Defense and Emergencies", rather than the headquarters

In the year of 2021, from *Obrezko* linked identifiers we can observe the below interesting deliveries to near identical addresses. 

| Date | Time | Day | Source | Address | Link to *Obrezko* |
|---|---:|---|---|---|---|
| 2021-03-01 | 15:30:26 | Monday | DeliveryClub | Москва, Давыдковская улица, 7А | `wisperrrrr@gmail.com`; `79263799902` |
| 2021-07-12 | 15:14:22 | Monday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-09-06 | 15:08:32 | Monday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-09-07 | 16:36:26 | Tuesday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-09-10 | 14:18:42 | Friday | YandexFood | Москва, Давыдковская улица, д. 7к1 | `79263799902` |
| 2021-09-17 | 17:02:28 | Friday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-09-20 | 14:42:27 | Monday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-09-23 | 15:08:09 | Thursday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-09-24 | 14:23:27 | Friday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-10-07 | 15:14:25 | Thursday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-10-12 | 14:51:04 | Tuesday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-10-29 | 15:15:03 | Friday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |
| 2021-12-16 | 15:49:57 | Thursday | YandexFood | Москва, Давыдковская улица, д. 7к10 | `79263799902` |

> In total, *Obrezko* made 13 deliveries to addresses right outside the EMERCOM government buildings 

> These orders were made during weekdays, from 14:15pm - 17:00pm, suggesting *Obrezko* often likes an afternoon snack at work. 

# *Yutek-NN*

The FBI indictment alleges that, from at least 2024, *Obrezko* worked as deputy director of the Russian technology company *Yutek-NN*. The FBI further alleges that *Yutek-NN* was responsible for the *Void Blizzard* intrusions:

[![1](/assets/images/vb/10.jpg){: .align-center .img-border}](/assets/images/vb/10.jpg)
<p class="figure-caption"><em>Yutek-NN</em> logo</p>

*ЮТЕК-НН*, or *Yutek-NN*, is a Russian technology company, founded in 2011, with the public facing website on [utech-nn.com](https://utech-nn.com):

[![1](/assets/images/vb/9.png){: .align-center .img-border}](/assets/images/vb/9.png)
<p class="figure-caption">utech-nn.com services</p>

Looking on the translated website, 3 broad categories of services are publicly advertised:

* IT product development
* Project management
* IT consulting

> There is no indication of cybersecurity, penetration testing, or services that relate to "espionage" on the public facing website, so what is really happening here?

## Licensed by the FSB 

Public records report that in April 2013, effective from December 2013, *Yutek-NN* was given a license, `ЛСЗ №0007002 1Т`. This was given by the Nizhny Novgorod department of the Federal Security Services (FSB), that allowed for the "covert acquisition of information":

[![1](/assets/images/vb/8.png){: .align-center .img-border}](/assets/images/vb/8.png)
<p class="figure-caption">FSB license</p>

Such a licence places *Yutek-NN* inside a regulated market for surveillance-adjacent equipment. It does not, by itself, prove that the company conducted espionage. This is alleged by the FBI, but has not been independently verified by Ctrl-Alt-Intel using open-source intelligence collection techniques. 

## Free Navalny!

This is not the first time *Yutek-NN* has been placed under the spotlight. In May 2021, [Meduza](https://amp.meduza.io/en/feature/2021/05/19/your-name-is-on-some-fsb-officer-s-list) and [Current Time](https://www.currenttime.tv/a/freenavalny-leak/31247843.html) mentioned the company while investigating the theft and exploitation of approximately 529,000 email addresses belonging to supporters of Alexey Navalny. The attackers enriched the data with personal and employment information before sending threats to victims and their employers.

Current Time reported that *Zasekin.ru* owner Dmitry Loboiko suspected the attack infrastructure could be connected to *Mikhail Dudin*, although it explicitly noted that he had **no direct evidence**. Meduza made a stronger allegation, citing unnamed sources who claimed Dudin was involved in attacks against both Navalny supporters and *Zasekin.ru*. Dudin did not respond to Meduza's questions.

Open-source records show [Dudin](https://zachestnyibiznes.ru/fl/631504004509) was *Yutek-NN*'s founder and owner from January 2011 until October 2018, while [Vadim Gaisin](https://zachestnyibiznes.ru/fl/637603072684) was its director from June 2018 until November 2020. They therefore overlapped at *Yutek-NN* for several months. Meduza described them as long-term business partners and reported that Gaisin became head of the presidential administration's *GlavNIVTs* research centre on 14th April 2021, one day before the threatening email campaign began.

> Neither investigation identified a *Yutek-NN* domain, IP address, employee or product as part of the operation. We assess *Yutek-NN* appeared as a circumstantial link through Dudin, Gaisin and its FSB-issued license - but the 2021 scrutiny shows the company was already under the spotlight years before the FBI linked it to *Void Blizzard*.

## *Yutek-NN* and *IAC EMERCOM* Personnel Links

Our OSINT findings independently connect *Obrezko* to *IAC EMERCOM*, a Russian government institution not mentioned in the FBI indictment or affidavit.

> The US filings allege that *Obrezko* previously worked for the FSB and later served as deputy director of *Yutek-NN*. They do not mention EMERCOM.

Public career data suggests that the relationship between *Yutek-NN* and *IAC EMERCOM* extends beyond *Obrezko*. At the time of review, the [Habr Career profile](https://career.habr.com/companies/utech-nn) for *Yutek-NN* showed one individual who joined *Yutek-NN* from *IAC EMERCOM* and two who later moved from *Yutek-NN* to *IAC EMERCOM*.

[![1](/assets/images/vb/10.png){: .align-center .img-border}](/assets/images/vb/10.png)
<p class="figure-caption">Personnel movements shown by Habr Career</p>

These records establish three publicly declared career transitions between the organisations. 

> Habr Career relies on information published by its users, so this should be treated as a visible minimum rather than a complete account of personnel movement. *Obrezko*, for example, is not included in the Habr data.

[![1](/assets/images/vb/11.png){: .align-center .img-border}](/assets/images/vb/11.png)
<p class="figure-caption">Correlation Graph</p>

# Conclusion

The US filings allege that *Obrezko* previously worked for the FSB, later became deputy director of *Yutek-NN*, and participated in *Void Blizzard* cyberespionage. Ctrl-Alt-Intel has not independently verified those operational allegations, but our OSINT provides additional context that is absent from the indictment and affidavit.

Identifiers attributed to *Obrezko* by the FBI appear alongside an *IAC EMERCOM*-associated work number and repeated weekday food deliveries to EMERCOM facilities during 2021. Taken together, these findings support our high-confidence assessment that *Obrezko* worked at, or regularly operated from, *IAC EMERCOM*.

Public records add further context around *Yutek-NN*: an FSB-issued licence for surveillance-adjacent equipment, and publicly declared personnel movements in both directions between *Yutek-NN* and *IAC EMERCOM*. None of these findings independently proves that *Yutek-NN* conducted cyberespionage. Collectively, however, they show that the company has deeper connections to Russian state and security institutions than its public-facing website suggests.

> A McChicken order does not prove cyberespionage. Combined with FBI filings, corporate records, professional histories and repeated activity at government facilities, however, it can expose relationships that official documents leave unstated.




















