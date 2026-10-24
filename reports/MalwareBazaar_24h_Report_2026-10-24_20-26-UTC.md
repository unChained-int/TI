# MalwareBazaar – 24.10.2026 20:26 UTC

Dieser Run hat **34 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **35** |
| Kritisch (≥75) | **26** |
| Höchster Score | **96.8/100** – fe5ab151cc1bc84e… |
| Häufigste Familie | **Mirai** (20x) |
| Häufigster Typ | **elf** (20x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 2.14 MB (σ=5.18) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 20 | 57.1%  ███████████ |
| `exe` | 8 | 22.9%  ████ |
| `macho` | 4 | 11.4%  ██ |
| `zip` | 1 | 2.9%   |
| `ps1` | 1 | 2.9%   |
| `msi` | 1 | 2.9%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 20 | 57.1% |
| 2 | unbekannt | 11 | 31.4% |
| 3 | WannaCry | 1 | 2.9% |
| 4 | Amadey | 1 | 2.9% |
| 5 | Malware | 1 | 2.9% |
| 6 | PythonStealer | 1 | 2.9% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 20 | 57.1% | 95% |
| Andere / Unbekannt | 5 | 14.3% | 20% |
| Infostealer | 4 | 11.4% | 75% |
| Windows-Malware | 2 | 5.7% | 35% |
| Ransomware | 1 | 2.9% | 95% |
| Loader | 1 | 2.9% | 95% |
| Skript/Dropper | 1 | 2.9% | 35% |
| Trojaner | 1 | 2.9% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 26 | 74.3% |
| 🟠 HOCH | 1 | 2.9% |
| 🟡 MITTEL | 3 | 8.6% |
| 🟢 NIEDRIG | 5 | 14.3% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [fe5ab151cc1bc8…](https://bazaar.abuse.ch/sample/fe5ab151cc1bc84e985263a4af1bde172c17ea6c3733e48d8da6631ca5ff82f3/) | WannaCry | Ransomware | **96.8** | 🔴 KRITISCH | – | – | ? |
| [62e1c8b2f42729…](https://bazaar.abuse.ch/sample/62e1c8b2f427296a64de68031105058afa1dfa0ada054cd98026746e51ba87c1/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [95d3b53b17d267…](https://bazaar.abuse.ch/sample/95d3b53b17d267bdb6b547a0c5f167d4807ce31349eb06fa698a6b0c111f2af2/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [9d12a0b1dac546…](https://bazaar.abuse.ch/sample/9d12a0b1dac5467771edfeccb3c599b73412c0754051f5b0aabc8013e9346d50/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [20740f7da1421e…](https://bazaar.abuse.ch/sample/20740f7da1421e9fea1199c7a44689b53317da9f6c63fd6c96f0cf1c13567f78/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [2dc2cda5399b4d…](https://bazaar.abuse.ch/sample/2dc2cda5399b4d50d123592f8d4c890f84ce94b15b7f68d9084a362dbb9ede46/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [b99da9425f9a73…](https://bazaar.abuse.ch/sample/b99da9425f9a73c0c887485fb5692987ec123a239ae0f6ceb7d4b788b059f330/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [66d809ab377510…](https://bazaar.abuse.ch/sample/66d809ab37751057afa220c80f31325357c8078780d6e35580e2b6f3a7b59a94/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [a51f6d785ad9d1…](https://bazaar.abuse.ch/sample/a51f6d785ad9d1952603177b431918fab29e969e4946b8baf9d9cffb1f8c92d9/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [29d9f9085b69b3…](https://bazaar.abuse.ch/sample/29d9f9085b69b3d26f92fb76e1bb037a195250400ba0d38df2179185760ee783/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6164/7610 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6164/7610 |
| 3 | ESET-NOD32 | 77.2% | 5872/7610 |
| 4 | Kaspersky | 75.9% | 5774/7609 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5408/7607 |
| 8 | Rising | 68.3% | 5198/7610 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5035/7606 |
| 11 | Avast | 65.1% | 4949/7606 |
| 12 | AVG | 65.1% | 4949/7605 |
| 13 | Tencent | 64.8% | 4788/7384 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4655/7603 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 21 | 60.0% |
| 🪟 Windows | 10 | 28.6% |
| 🍎 macOS | 4 | 11.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 32 | 91.4% |
| Exploit / N-Day | 1 | 2.9% |
| MaaS-Loader | 1 | 2.9% |
| Trojanisierte Software | 1 | 2.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 12 | 34.3% |
| 2 | 🇺🇸 US | 11 | 31.4% |
| 3 | 🇪🇸 ES | 8 | 22.9% |
| 4 | 🇬🇧 GB | 1 | 2.9% |
| 5 | 🇳🇱 NL | 1 | 2.9% |
| 6 | 🇭🇺 HU | 1 | 2.9% |
| 7 | 🌐 Unbekannt | 1 | 2.9% |

## MITRE ATT&CK

> 21 von 35 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 20 |
| Lateral Movement | 20 |
| Execution | 1 |
| Persistence | 1 |

<details><summary>62e1c8b2f427296a64de… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>95d3b53b17d267bdb6b5… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>9d12a0b1dac5467771ed… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>20740f7da1421e9fea11… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9bd91039bad7799c22da…](https://bazaar.abuse.ch/sample/9bd91039bad7799c22da48a6ddfd7e83510c0c4adddbb8c4151f3eb9b2d52d23/)

- **Familie:** Mirai
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Cling.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Cling.1`

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Cling.1` |
| AVG | `ELF:Mirai-BYP [Trj]` |
| AhnLab-V3 | `Trojan/Linux.Mirai.SE302` |
| Arcabit | `Trojan.Linux.Cling.1` |
| Avast | `ELF:Mirai-BYP [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `EXP/ELF.Mirai.D` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Cling.1` |
| CTX | `elf.unknown.cling` |
| ClamAV | `Unix.Trojan.Gafgyt-6981160-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| Emsisoft | `Gen:Variant.Linux.Cling.1 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.D` |
| Fortinet | `ELF/Fodcha.080F!tr` |
| GData | `Gen:Variant.Linux.Cling.1` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gen` |
| Kingsoft | `Linux.Backdoor.elf.2023761` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| MicroWorld-eScan | `Gen:Variant.Linux.Cling.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BA!xp` |
| Rising | `Backdoor.Gafgyt/Linux!1.DE80 (CLASSIC)` |
| Sangfor | `Backdoor.Linux.Mirai.V60k` |
| Tencent | `Backdoor.Linux.Zhtrap.dhyra` |
| VIPRE | `Gen:Variant.Linux.Cling.1` |
| alibabacloud | `Backdoor:Linux/Mirai.ASJ` |
| huorong | `Trojan/Linux.Mirai.f` |

### [52196a9dcc2f5aa5578b…](https://bazaar.abuse.ch/sample/52196a9dcc2f5aa5578bebbbbf9acb8bea4bc35244fcba589ccc16f5db7332af/)

- **Familie:** Mirai
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| Kingsoft | `Linux.Trojan.Agent.xu` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.NPE` |
| Tencent | `Linux.Trojan.Agent.Swhl` |
| alibabacloud | `Trojan:Linux/Flooder.Akgpp` |
| huorong | `Trojan/Linux.Flooder.ac` |

### [1d68dac879f13efe3661…](https://bazaar.abuse.ch/sample/1d68dac879f13efe3661f4ec3afcd561962c6388f3bcd595a4579390eb3741d7/)

- **Familie:** Malware
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.432BF704
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801029` |
| Bkav | `W32.Malware.432BF704` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Kryptik.HTB trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.87 (RDML:9TUifLtdiV1WXnrKeTkKjg)` |
| Symantec | `ML.Attribute.HighConfidence` |
| TrellixENS | `Artemis!87B096A39343` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |
| Webroot | `Win.Trojan.Gen` |
| huorong | `Trojan/Injector.aj!crit` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Qwexlafiba!rfn`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.qwexlafiba` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7GW | `Hacktool ( a007e0071 )` |
| Kingsoft | `Win32.Troj.qwexlafiba.v` |
| Malwarebytes | `Trojan.Injector` |
| MaxSecure | `Trojan.Malware.727547498.susgen` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **elf** (20×)
- **Mirai** (12×)
- **adb** (8×)
- **aisuru** (8×)
- **ddos** (8×)
- **mirai** (8×)
- **exe** (7×)
- **AMOS** (4×)
- **ClickFix** (4×)
- **Foxveil** (4×)
- **Mach-O** (4×)
- **macho** (4×)
- **macOS** (4×)
- **DvnX** (4×)
- **stealer** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +2 (18→20)
- ↓ **unbekannt** -8 (19→11)
- neu: **WannaCry** (1)
- neu: **Amadey** (1)
- neu: **Malware** (1)
- weg: **SalatStealer** (war 3)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -27 (38→11)
- neu: **WannaCry** (1)
- neu: **Amadey** (1)
- neu: **Malware** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.143 MB |
| σ Dateigröße | 5.175 MB |
| Ø Risiko-Score | 71.3/100 |
| Ø Klassifikations-Konfidenz | 76.0% |
| Samples mit VT | 4/35 |
| Samples mit MITRE | 21/35 |
| Eindeutige Familien | 6 |
| Eindeutige Tags | 35 |
| Unbekannte Familien | 5 (14.3%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 20:22 | [eaddd0e6bf1c…](https://bazaar.abuse.ch/sample/eaddd0e6bf1c396859cee853792e6878977c8951829e1c43a66b204cc11a6a47/) | `macho` | unbekannt | 32.7 | – | – | 🇺🇸US |
| 19:49 | [62e1c8b2f427…](https://bazaar.abuse.ch/sample/62e1c8b2f427296a64de68031105058afa1dfa0ada054cd98026746e51ba87c1/) | `elf` | Mirai | 84.0 | – | – | 🌐ES |
| 19:49 | [95d3b53b17d2…](https://bazaar.abuse.ch/sample/95d3b53b17d267bdb6b547a0c5f167d4807ce31349eb06fa698a6b0c111f2af2/) | `elf` | Mirai | 84.0 | – | – | 🌐ES |
| 19:49 | [9d12a0b1dac5…](https://bazaar.abuse.ch/sample/9d12a0b1dac5467771edfeccb3c599b73412c0754051f5b0aabc8013e9346d50/) | `elf` | Mirai | 84.0 | – | – | 🌐ES |
| 19:49 | [9bd91039bad7…](https://bazaar.abuse.ch/sample/9bd91039bad7799c22da48a6ddfd7e83510c0c4adddbb8c4151f3eb9b2d52d23/) | `elf` | Mirai | 79.1 | 36.0% | 🟡 SCHWACH ERKANNT | 🌐ES |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 24.10.2026 20:26 UTC*