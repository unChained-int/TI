# MalwareBazaar – 17.10.2026 20:18 UTC

Dieser Run hat **41 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **42** |
| Kritisch (≥75) | **20** |
| Höchster Score | **84.4/100** – 8cb5c2385a45233d… |
| Häufigste Familie | **unbekannt** (20x) |
| Häufigster Typ | **elf** (25x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 15 Samples |
| Ø Dateigröße | 4.25 MB (σ=14.93) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 25 | 59.5%  ███████████ |
| `exe` | 13 | 31.0%  ██████ |
| `sh` | 2 | 4.8%   |
| `zip` | 1 | 2.4%   |
| `jar` | 1 | 2.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 20 | 47.6% |
| 2 | Mirai | 14 | 33.3% |
| 3 | Gafgyt | 2 | 4.8% |
| 4 | CoinMiner | 1 | 2.4% |
| 5 | FileRepMalware [Misc] | 1 | 2.4% |
| 6 | ValleyRAT | 1 | 2.4% |
| 7 | RustyStealer | 1 | 2.4% |
| 8 | FileRepMalware [Drp] | 1 | 2.4% |
| 9 | RemcosRAT | 1 | 2.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 16 | 38.1% | 95% |
| Linux-Malware | 9 | 21.4% | 45% |
| Andere / Unbekannt | 4 | 9.5% | 20% |
| Windows-Malware | 4 | 9.5% | 35% |
| Loader | 4 | 9.5% | 75% |
| RAT | 2 | 4.8% | 85% |
| Cryptominer | 1 | 2.4% | 75% |
| Infostealer | 1 | 2.4% | 75% |
| Trojaner | 1 | 2.4% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 20 | 47.6% |
| 🟠 HOCH | 5 | 11.9% |
| 🟡 MITTEL | 13 | 31.0% |
| 🟢 NIEDRIG | 4 | 9.5% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [8cb5c2385a4523…](https://bazaar.abuse.ch/sample/8cb5c2385a45233dcb8a92e2ecb6d03ee54f12e711ff4b045527d84445297ad2/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [39a670651da3cb…](https://bazaar.abuse.ch/sample/39a670651da3cb97eebbb3fc754c9efb1e2f6eaf83f1ce6fc792006a35499a4f/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [c49dfac7680e3b…](https://bazaar.abuse.ch/sample/c49dfac7680e3b0e79076030483f2b283ed6aa12c7c8c06bbf2856a616419fa3/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [8dcd02094df461…](https://bazaar.abuse.ch/sample/8dcd02094df461a66a0f15ef26b58bb5cad6a2e4dcf30783eb7e43a422f7c5bc/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [d037f5a5cb2292…](https://bazaar.abuse.ch/sample/d037f5a5cb2292237031ca99439f56184aff3439062d952b412c8ce5539ada06/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [46eae51c13ea3f…](https://bazaar.abuse.ch/sample/46eae51c13ea3f0b105e647282fff94dfe343ed281f1953248ae5a683db252ca/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [3b0fe8f97404ab…](https://bazaar.abuse.ch/sample/3b0fe8f97404abb1fb2c3c38ea6f97acd85614866cf13ff44f1d9810f11f9e77/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | 17.3% | 🟡 SCHWACH ERKANNT | ✗ |
| [e45d4154c9a1f5…](https://bazaar.abuse.ch/sample/e45d4154c9a1f5311ec5882464e7a8b8d0ab3cc2960d305a8a84db86ef68af85/) | Gafgyt | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |
| [b514ec72effd78…](https://bazaar.abuse.ch/sample/b514ec72effd78ad316e33948b9d19d160575b35f9ef2fd7a88b5b352986b111/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [7692dad7217418…](https://bazaar.abuse.ch/sample/7692dad72174183eaff8fc0773603b08bf9d73b5948b9f37a8d7434f0b829645/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |

### VT-Erkennung: Was bedeutet die Rate?

> ⚠️ **Niedrige Rate ≠ harmlos!** Eine Malware die nur 1/70 Engines erkennen = hochgradig evasiv.
> Sie ist GEFÄHRLICHER weil sie Antivirenprogramme umgeht.
> | Rate | Bedeutung | Farbe |
> |------|-----------|-------|
> | < 10% | ⚠️ KAUM ERKANNT – maximal evasiv | 🔴 ROT |
> | 10–40% | 🟡 SCHWACH ERKANNT | 🟠 ORANGE |
> | 40–70% | 🟠 MÄSSIG ERKANNT | 🟡 GELB |
> | ≥ 70% | ✅ GUT ERKANNT – breite Abdeckung | 🟢 GRÜN |

## AV-Zuverlässigkeit (Erkennungsrate pro Engine)

> Basiert auf allen bisher gesehenen VT-Ergebnissen.
> **Microsoft Defender** ist Pflicht-Check — wird immer explizit ausgewiesen.

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6024/7448 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6024/7448 |
| 3 | ESET-NOD32 | 77.4% | 5765/7448 |
| 4 | Kaspersky | 76.3% | 5685/7447 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5321/7445 |
| 8 | Rising | 68.7% | 5116/7448 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4939/7444 |
| 11 | Tencent | 65.3% | 4715/7222 |
| 12 | Avast | 65.1% | 4847/7444 |
| 13 | AVG | 65.1% | 4847/7443 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4559/7441 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 27 | 64.3% |
| 🪟 Windows | 13 | 31.0% |
| 📦 Archiv | 1 | 2.4% |
| ❓ Unbekannt | 1 | 2.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 38 | 90.5% |
| C2 / Nachladen | 3 | 7.1% |
| MaaS-Loader | 1 | 2.4% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 26 | 61.9% |
| 2 | 🇺🇸 US | 6 | 14.3% |
| 3 | 🇭🇺 HU | 6 | 14.3% |
| 4 | 🇳🇱 NL | 1 | 2.4% |
| 5 | 🇫🇷 FR | 1 | 2.4% |
| 6 | 🌐 PT | 1 | 2.4% |
| 7 | 🌐 Unbekannt | 1 | 2.4% |

## MITRE ATT&CK

> 15 von 42 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 14 |
| Lateral Movement | 14 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>8cb5c2385a45233dcb8a… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>39a670651da3cb97eebb… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c49dfac7680e3b0e7907… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>8dcd02094df461a66a0f… – Mirai | 🔴 KRITISCH 83.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>d037f5a5cb2292237031… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5e47989ec2b85caab993…](https://bazaar.abuse.ch/sample/5e47989ec2b85caab9939ca63da53a25ee6eb9785312703355ea35138aae7e0e/)

- **Familie:** FileRepMalware [Misc]
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `FileRepMalware [Misc]` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.E601CBB1` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (high confidence)` |
| Gridinsoft | `Trojan.Heur!.0301A0A3` |
| Malwarebytes | `Malware.Heuristic.2045` |
| McAfeeD | `ti!5E47989EC2B8` |
| Microsoft 🛡️ | `Program:Win32/Wacapew.C!ml` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.high.ml.score` |
| huorong | `Backdoor/Lotok.fo` |

### [3b0fe8f97404abb1fb2c…](https://bazaar.abuse.ch/sample/3b0fe8f97404abb1fb2c3c38ea6f97acd85614866cf13ff44f1d9810f11f9e77/)

- **Familie:** Mirai
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.ELF.Mirai.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| ClamAV | `Unix.Trojan.Mirai-10012200-0` |
| ESET-NOD32 | `Linux/DDoS.Agent.LJ trojan` |
| Fortinet | `ELF/Gafgyt.AEA!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Multiverze` |
| Kaspersky | `HEUR:Trojan.Linux.Mirai.gen` |
| Kingsoft | `Linux.Trojan.Mirai.gen` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Trojan.Mirai/Linux!8.13298 (CLOUD)` |
| Tencent | `Trojan.Linux.Mirai.Gfyra` |
| huorong | `Trojan/Linux.DDos.do` |

### [ecf9ee8895057f0934b2…](https://bazaar.abuse.ch/sample/ecf9ee8895057f0934b2f6c5fab74148932ecae0e46bcfc8618a112ca4fef82d/)

- **Familie:** FileRepMalware [Drp]
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `FileRepMalware [Drp]` |
| Avast | `FileRepMalware [Drp]` |
| Avira | `TR/W64.Agent` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Win64/Kryptik.GXY trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Agent` |
| GData | `Win32.Trojan.Agent.30Q8WI` |
| Kaspersky | `HEUR:Backdoor.Win32.Farfli.gen` |
| Kingsoft | `Win32.Hack.Farfli.gen` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| Rising | `Trojan.Kryptik!8.8 (CLOUD)` |
| Skyhigh | `Artemis` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Trojan.Win64.Kryptik.16003858` |
| TrellixENS | `Artemis!917D920F0343` |
| alibabacloud | `Trojan:Win/Kryptik.GDT` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (61/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Rat]` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
| Avast | `Win32:MalwareX-gen [Rat]` |
| Avira | `BDS/Backdoor.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Remcos.23` |
| Bkav | `W32.Malware.D80B3EFB` |
| CAT-QuickHeal | `Trojan.Remcos.S39598516` |
| CTX | `exe.trojan.remcos` |
| ClamAV | `Win.Trojan.Remcos-9841897-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.630` |
| ESET-NOD32 | `Win32/Rescoms.B trojan` |
| Elastic | `Windows.Trojan.Remcos` |
| Emsisoft | `Gen:Variant.Remcos.23 (B)` |
| F-Secure | `Backdoor.BDS/Backdoor.Gen` |
| Fortinet | `W32/Rescomms.B!tr` |
| GData | `Gen:Variant.Remcos.23` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Remcos.oa!s1` |
| Ikarus | `Backdoor.Remcos` |
| K7AntiVirus | `Backdoor ( 005ce3801 )` |
| K7GW | `Backdoor ( 005ce3801 )` |
| Kaspersky | `HEUR:Backdoor.Win32.Remcos.gen` |
| Kingsoft | `Win32.Hack.Remcos.gen` |
| Lionic | `Trojan.Win32.Rescoms.m!c` |
| Malwarebytes | `Backdoor.Remcos` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Backdoor.Remcos!1.BAC7 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.hh` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrellixENS | `RAT/Remcos!D532A55294F7` |
| TrendMicro | `Backdoor.Win32.REMCOS.USBLJB26` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (25×)
- **Mirai** (14×)
- **exe** (12×)
- **dropped-by-GCleaner** (3×)
- **sh** (2×)
- **C** (2×)
- **Gafgyt** (2×)
- **CoinMiner** (1×)
- **MIX2.file** (1×)
- **F** (1×)
- **MIX4.file** (1×)
- **RAT** (1×)
- **ValleyRAT** (1×)
- **RustyStealer** (1×)
- **zip** (1×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -7 (27→20)
- ↓ **Mirai** -27 (41→14)
- neu: **Gafgyt** (2)
- neu: **CoinMiner** (1)
- neu: **FileRepMalware [Misc]** (1)
- neu: **RustyStealer** (1)
- neu: **FileRepMalware [Drp]** (1)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -7 (27→20)
- ↓ **Mirai** -16 (30→14)
- neu: **Gafgyt** (2)
- neu: **FileRepMalware [Misc]** (1)
- neu: **RustyStealer** (1)
- neu: **FileRepMalware [Drp]** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.251 MB |
| σ Dateigröße | 14.929 MB |
| Ø Risiko-Score | 63.0/100 |
| Ø Klassifikations-Konfidenz | 67.4% |
| Samples mit VT | 4/42 |
| Samples mit MITRE | 15/42 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 19 |
| Unbekannte Familien | 4 (9.5%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 20:06 | [865e10835bd9…](https://bazaar.abuse.ch/sample/865e10835bd95c79fa64c91b420a29eb19ffc21ce761c7150666579829ea56d1/) | `exe` | CoinMiner | 67.8 | – | – | 🇺🇸US |
| 20:05 | [8cb5c2385a45…](https://bazaar.abuse.ch/sample/8cb5c2385a45233dcb8a92e2ecb6d03ee54f12e711ff4b045527d84445297ad2/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 19:57 | [39a670651da3…](https://bazaar.abuse.ch/sample/39a670651da3cb97eebbb3fc754c9efb1e2f6eaf83f1ce6fc792006a35499a4f/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 19:49 | [54cfa65b226d…](https://bazaar.abuse.ch/sample/54cfa65b226d657609b946b2542f2156ca0aae871d637df8d78a2c54b3bf5d78/) | `elf` | unbekannt | 42.9 | – | – | 🇩🇪DE |
| 19:44 | [842764224243…](https://bazaar.abuse.ch/sample/84276422424304e2cbb2b04f86911d85a77521f4b2d865d680dc6d6fdae38299/) | `elf` | unbekannt | 42.8 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 17.10.2026 20:18 UTC*