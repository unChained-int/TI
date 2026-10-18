# MalwareBazaar – 18.10.2026 13:50 UTC

Dieser Run hat **77 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **78** |
| Kritisch (≥75) | **42** |
| Höchster Score | **91.6/100** – c19e5b75db1c7728… |
| Häufigste Familie | **unbekannt** (29x) |
| Häufigster Typ | **elf** (33x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 31 Samples |
| Ø Dateigröße | 8.34 MB (σ=24.50) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 33 | 42.3%  ████████ |
| `exe` | 26 | 33.3%  ██████ |
| `jar` | 8 | 10.3%  ██ |
| `js` | 3 | 3.8%   |
| `macho` | 2 | 2.6%   |
| `zip` | 1 | 1.3%   |
| `ps1` | 1 | 1.3%   |
| `sh` | 1 | 1.3%   |
| `hta` | 1 | 1.3%   |
| `zsh` | 1 | 1.3%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 29 | 37.2% |
| 2 | Mirai | 23 | 29.5% |
| 3 | RemcosRAT | 4 | 5.1% |
| 4 | SilentNet | 3 | 3.8% |
| 5 | QuasarRAT | 2 | 2.6% |
| 6 | AMOS | 2 | 2.6% |
| 7 | Vidar | 2 | 2.6% |
| 8 | ValleyRAT | 2 | 2.6% |
| 9 | FileRepMalware [Misc] | 1 | 1.3% |
| 10 | Malware | 1 | 1.3% |
| 11 | SheetRAT | 1 | 1.3% |
| 12 | Gh0stRAT | 1 | 1.3% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 25 | 32.1% | 94% |
| Andere / Unbekannt | 11 | 14.1% | 20% |
| Windows-Malware | 9 | 11.5% | 35% |
| Linux-Malware | 8 | 10.3% | 45% |
| RAT | 7 | 9.0% | 92% |
| Infostealer | 6 | 7.7% | 88% |
| Loader | 5 | 6.4% | 75% |
| Trojaner | 4 | 5.1% | 72% |
| Skript/Dropper | 2 | 2.6% | 35% |
| Backdoor | 1 | 1.3% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 42 | 53.8% |
| 🟠 HOCH | 6 | 7.7% |
| 🟡 MITTEL | 19 | 24.4% |
| 🟢 NIEDRIG | 11 | 14.1% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c19e5b75db1c77…](https://bazaar.abuse.ch/sample/c19e5b75db1c77281ab32fa9927fea7eedf2f6c61575c70b10f883fea99be633/) | Gh0stRAT | Backdoor | **91.6** | 🔴 KRITISCH | – | – | ? |
| [aab8685f629963…](https://bazaar.abuse.ch/sample/aab8685f629963b95409754e00795c3d444c44e2fcf2f3fa8f7b0e4bd99a02dd/) | RemcosRAT | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [fe3dd2365097e3…](https://bazaar.abuse.ch/sample/fe3dd2365097e3f899d393f8a006ca7e8f57fdb027e746c027921b331a0f778e/) | QuasarRAT | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [e6d81f3e45c61a…](https://bazaar.abuse.ch/sample/e6d81f3e45c61a47516820227d22bafe0266fef8eeb3f629f6995c90c3506a92/) | RemcosRAT | RAT | **88.0** | 🔴 KRITISCH | – | – | ? |
| [2b66b4b8780569…](https://bazaar.abuse.ch/sample/2b66b4b8780569cd63159360fbc53761d6ba15c7635c977976d55c77d1d93079/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [47e9e1bf4296b6…](https://bazaar.abuse.ch/sample/47e9e1bf4296b651d4d5d3bd066a0e3ceb44c4f897aa1edac79197d1ec680e6c/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [8ad8e7b22405a2…](https://bazaar.abuse.ch/sample/8ad8e7b22405a2368fe8b4a71c85311ed6846a159c911d6d068bd06e6c29ec6d/) | Vidar | Infostealer | **87.9** | 🔴 KRITISCH | – | – | ? |
| [6e29d480cbb739…](https://bazaar.abuse.ch/sample/6e29d480cbb73974e1826d83cd52f8631cdd0357f952dc9b00540b2dedd6fc52/) | Vidar | Infostealer | **87.9** | 🔴 KRITISCH | – | – | ? |
| [8764195a7594be…](https://bazaar.abuse.ch/sample/8764195a7594befd2451882ee64557a0f03acaec9409644455741ea7990de93b/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [8a442fc7e166b0…](https://bazaar.abuse.ch/sample/8a442fc7e166b0af2eb74fad903cfb85151c5b8f86e994c037692a7b5b298049/) | QuasarRAT | RAT | **87.2** | 🔴 KRITISCH | 16.0% | 🟡 SCHWACH ERKANNT | ✗ |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6040/7468 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6040/7468 |
| 3 | ESET-NOD32 | 77.4% | 5780/7468 |
| 4 | Kaspersky | 76.3% | 5698/7467 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5334/7465 |
| 8 | Rising | 68.7% | 5128/7468 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4949/7464 |
| 11 | Tencent | 65.3% | 4726/7242 |
| 12 | Avast | 65.1% | 4862/7464 |
| 13 | AVG | 65.1% | 4862/7463 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4569/7461 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 36 | 46.2% |
| 🪟 Windows | 28 | 35.9% |
| ❓ Unbekannt | 11 | 14.1% |
| 🍎 macOS | 2 | 2.6% |
| 📦 Archiv | 1 | 1.3% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 68 | 87.2% |
| C2 / Nachladen | 6 | 7.7% |
| Drive-By / Exploit-Kit | 3 | 3.8% |
| Trojanisierte Software | 1 | 1.3% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 27 | 34.6% |
| 2 | 🇩🇪 DE | 15 | 19.2% |
| 3 | 🇸🇪 SE | 10 | 12.8% |
| 4 | 🌐 DK | 7 | 9.0% |
| 5 | 🇳🇱 NL | 6 | 7.7% |
| 6 | 🇨🇭 CH | 4 | 5.1% |
| 7 | 🇫🇷 FR | 4 | 5.1% |
| 8 | 🇧🇪 BE | 2 | 2.6% |
| 9 | 🇨🇦 CA | 1 | 1.3% |
| 10 | 🇹🇷 TR | 1 | 1.3% |
| 11 | 🌐 Unbekannt | 1 | 1.3% |

## MITRE ATT&CK

> 31 von 78 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 23 |
| Lateral Movement | 23 |
| Command and Control | 6 |
| Collection | 6 |
| Exfiltration | 4 |
| Credential Access | 2 |

<details><summary>aab8685f629963b95409… – RemcosRAT | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>fe3dd2365097e3f899d3… – QuasarRAT | 🔴 KRITISCH 88.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>e6d81f3e45c61a475168… – RemcosRAT | 🔴 KRITISCH 88.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [305d16e738d326cd9d39…](https://bazaar.abuse.ch/sample/305d16e738d326cd9d39908f58db28b05b14a378cb0225841df13fe4446f3870/)

- **Familie:** FileRepMalware [Misc]
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.F66CFEA4` |
| Elastic | `malicious (high confidence)` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |

### [12ab564a85f05ad1c074…](https://bazaar.abuse.ch/sample/12ab564a85f05ad1c0744932f2d5dc31db5204559dd24d8672bc551e10d6076f/)

- **Familie:** Malware
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.529ADA6
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| Bkav | `W32.Malware.529ADA6` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Kryptik_AGen.AWJ trojan` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `Trojan-PSW.Win32.Greedy.oef` |
| McAfeeD | `ti!12AB564A85F0` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.high.ml.score` |

### [8a442fc7e166b0af2eb7…](https://bazaar.abuse.ch/sample/8a442fc7e166b0af2eb74fad903cfb85151c5b8f86e994c037692a7b5b298049/)

- **Familie:** QuasarRAT
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.3F6F0E6E
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| Bkav | `W32.Malware.3F6F0E6E` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| Elastic | `malicious (moderate confidence)` |
| Google | `Detected` |
| Ikarus | `Backdoor.QuasarRat` |
| Kaspersky | `HEUR:Trojan.Win32.Agentb.gen` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| tehtris | `Generic.Malware` |

### [7d8524c0062b7bd69bd1…](https://bazaar.abuse.ch/sample/7d8524c0062b7bd69bd16095becfe50921a905f4b1663ced0d9d800258ff8171/)

- **Familie:** ELF:Mirai-AJJ [PUP]
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-AJJ [PUP]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-AJJ [PUP]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-AJJ [PUP]` |
| Avira | `EXP/ELF.Agent.J.8` |
| ClamAV | `Unix.Trojan.Mirai-8041698-0` |
| Cynet | `Malicious (score: 99)` |
| F-Secure | `Exploit.EXP/ELF.Agent.J.8` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.GL!MTB` |
| Varist | `E32/Mirai.JK.gen!Eldorado` |

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

- **elf** (29×)
- **exe** (25×)
- **Mirai** (22×)
- **cowrie** (12×)
- **honeypot** (12×)
- **jar** (8×)
- **java** (8×)
- **python** (8×)
- **silentnet** (8×)
- **signed** (4×)
- **js** (3×)
- **dropped-by-GCleaner** (3×)
- **RemcosRAT** (3×)
- **521048dd5a8917782e586ac60bc1eceb** (3×)
- **dropped-by-remus** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +1 (28→29)
- ↓ **Mirai** -2 (25→23)
- ↑ **RemcosRAT** +3 (1→4)
- neu: **SilentNet** (3)
- neu: **QuasarRAT** (2)
- ↑ **AMOS** +1 (1→2)
- neu: **Vidar** (2)
- ↑ **ValleyRAT** +1 (1→2)
- neu: **FileRepMalware [Misc]** (1)
- neu: **Malware** (1)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +1 (28→29)
- ↓ **Mirai** -4 (27→23)
- ↑ **RemcosRAT** +2 (2→4)
- ↑ **SilentNet** +2 (1→3)
- neu: **QuasarRAT** (2)
- ↑ **AMOS** +1 (1→2)
- ↑ **Vidar** +1 (1→2)
- ↑ **ValleyRAT** +1 (1→2)
- neu: **FileRepMalware [Misc]** (1)
- neu: **Malware** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 8.341 MB |
| σ Dateigröße | 24.502 MB |
| Ø Risiko-Score | 64.4/100 |
| Ø Klassifikations-Konfidenz | 67.2% |
| Samples mit VT | 5/78 |
| Samples mit MITRE | 31/78 |
| Eindeutige Familien | 19 |
| Eindeutige Tags | 59 |
| Unbekannte Familien | 11 (14.1%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 13:41 | [314266ef9045…](https://bazaar.abuse.ch/sample/314266ef90452c61d6d097e28bdbc7f04b33763225332fe3707b13db85f4ee9c/) | `jar` | unbekannt | 32.6 | – | – | 🇺🇸US |
| 13:40 | [5158a514f752…](https://bazaar.abuse.ch/sample/5158a514f752287e787e202617a9236ba34940d8bf171b9b16e55698eea3a9b6/) | `jar` | unbekannt | 32.6 | – | – | 🇺🇸US |
| 13:40 | [44880f1d6c80…](https://bazaar.abuse.ch/sample/44880f1d6c80addb41f6274175428acbc7a9b94623d5e271ce5bc4d15bc8c1b3/) | `jar` | unbekannt | 32.6 | – | – | 🇺🇸US |
| 13:37 | [96ea1f7fc68f…](https://bazaar.abuse.ch/sample/96ea1f7fc68fd3b352fe0a16976158c2df1c677ca4bf021f8210529b2175367f/) | `jar` | unbekannt | 32.6 | – | – | 🇺🇸US |
| 13:35 | [43c6fe8a0c26…](https://bazaar.abuse.ch/sample/43c6fe8a0c2667500ab9e186af69ba8520f962d5dc223c299a823ff878ac9e45/) | `jar` | unbekannt | 32.5 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 18.10.2026 13:50 UTC*