---
title: "CTF in the Supply Chain: Backdooring Wordpress Plugins"
classes: wide
header:
  teaser: /assets/images/wordpress/logo.png
ribbon: black
description: "Analysis of a fully-featured AiTM phishing platform with a collective intelligence & licensing system"
categories:
  - Threat Research
tags:
  - Threat Research
toc: true
---

# Overview

Threat actors are increasingly using commercial AI tooling, specifically Anthropic's Claude, to perform successful attacks against production infrastructure belonging to **real victims**. 

At Ctrl-Alt-Intel, we've observed threat actors use Claude to successfully laterally move, escalate privileges and steal sensitive data from **multiple Mexican government departments**. Additionally, we've seen **creative and novel attack chains** to compromise American universities within the Middle East, following the conflict. 

However, in this blog we will be exposing a **French** threat actor who has used Claude, under the premise of a Capture The Flag (CTF) challenge, to perform a successful supply-chain attack. The flag in this case was infiltrating the CI/CD pipeline for the BuddyBoss Wordpress plugin/theme, embedding it with malicious code, and pushing this to production - successfully compromising **hundreds of victim websites**.

We will split this blog up into 4 core sections:

1. **Supply Chain Attack** - An analysis of the **French** threat actors prompts used to infiltrate the supply-chain
2. **Backdoored Plugins** - Studying the backdoors embedded within the Wordpress plugins
3. **Victimology** - 
4. **Seperate Targeting** - This threat actor also targeted Wordpress plugins without a backdoor, we'll analyse this too

# Claude's Supply Chain Attack

On 18th March 2026, [@ice_wzl_cyber](https://x.com/ice_wzl_cyber) 




