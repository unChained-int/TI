# MalwareBazaar – 18.10.2026 03:40 UTC

Dieser Run hat **47 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **48** |
| Kritisch (≥75) | **35** |
| Höchster Score | **88.4/100** – 6c118d4bd1a56f56… |
| Häufigste Familie | **Mirai** (20x) |
| Häufigster Typ | **elf** (29x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 0.90 MB (σ=1.13) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 29 | 60.4%  ████████████ |
| `macho` | 9 | 18.8%  ███ |
| `exe` | 9 | 18.8%  ███ |
| `msi` | 1 | 2.1%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 20 | 41.7% |
| 2 | unbekannt | 12 | 25.0% |
| 3 | AMOS | 7 | 14.6% |
| 4 | Gafgyt | 4 | 8.3% |
| 5 | Snowlight | 1 | 2.1% |
| 6 | RemusStealer | 1 | 2.1% |
| 7 | NanoCore | 1 | 2.1% |
| 8 | B!ml | 1 | 2.1% |
| 9 | RemcosRAT | 1 | 2.1% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 24 | 50.0% | 95% |
| Infostealer | 9 | 18.8% | 91% |
| Loader | 4 | 8.3% | 75% |
| Linux-Malware | 3 | 6.2% | 45% |
| Windows-Malware | 2 | 4.2% | 35% |
| Andere / Unbekannt | 2 | 4.2% | 20% |
| Trojaner | 2 | 4.2% | 65% |
| RAT | 2 | 4.2% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 35 | 72.9% |
| 🟠 HOCH | 6 | 12.5% |
| 🟡 MITTEL | 5 | 10.4% |
| 🟢 NIEDRIG | 2 | 4.2% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [6c118d4bd1a56f…](https://bazaar.abuse.ch/sample/6c118d4bd1a56f56756b78134474c2a5becd3f138803d3297155691a427f6524/) | AMOS | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [510c4b3b85201e…](https://bazaar.abuse.ch/sample/510c4b3b85201eada32ff69b46e605f384ba5ff4bbcfb5399e42b31a7de37f63/) | AMOS | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [813bb6f2bc3783…](https://bazaar.abuse.ch/sample/813bb6f2bc378364b4a0ed1405fe6ccd34a1510c4c94fe98f5908e6514999c1a/) | AMOS | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [aa2fe64a8b365f…](https://bazaar.abuse.ch/sample/aa2fe64a8b365f79ba99c5cae660602063d6b555b3dd2e40d05f5293ca2c2a96/) | AMOS | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [f2c7af231a3dc1…](https://bazaar.abuse.ch/sample/f2c7af231a3dc1a9291a2421d2b67e3c6ed829073fdcbd7aeec3c33a933d2f6e/) | AMOS | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [d64921058e0307…](https://bazaar.abuse.ch/sample/d64921058e03078b75565d5aeea126e75698f39be3c6387d17c5d9fa8536d0ac/) | AMOS | Infostealer | **88.1** | 🔴 KRITISCH | – | – | ? |
| [e6490a700b965a…](https://bazaar.abuse.ch/sample/e6490a700b965a6dcf264eb1e8291217d9e52f167470d70bc24806697fabeeaa/) | AMOS | Infostealer | **88.1** | 🔴 KRITISCH | – | – | ? |
| [c661e95485ff9d…](https://bazaar.abuse.ch/sample/c661e95485ff9dbb4e71521ea24733eaf17375c50cbd0313e2507ceb79d59ede/) | NanoCore | RAT | **87.7** | 🔴 KRITISCH | – | – | ? |
| [c24ae3aef86d4c…](https://bazaar.abuse.ch/sample/c24ae3aef86d4ce54942f811bbc9bc2620131f340a4de4bf3fd1eb00f57341c9/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [8929dfa4b0165f…](https://bazaar.abuse.ch/sample/8929dfa4b0165fe00f055f058fc0f92584181856ab0975cda5779164062ec76f/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6032/7458 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6032/7458 |
| 3 | ESET-NOD32 | 77.4% | 5774/7458 |
| 4 | Kaspersky | 76.3% | 5691/7457 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5327/7455 |
| 8 | Rising | 68.7% | 5123/7458 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4943/7454 |
| 11 | Tencent | 65.3% | 4721/7232 |
| 12 | Avast | 65.1% | 4855/7454 |
| 13 | AVG | 65.1% | 4855/7453 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4564/7451 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 29 | 60.4% |
| 🪟 Windows | 10 | 20.8% |
| 🍎 macOS | 9 | 18.8% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 36 | 75.0% |
| MaaS-Loader | 6 | 12.5% |
| C2 / Nachladen | 5 | 10.4% |
| Trojanisierte Software | 1 | 2.1% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 29 | 60.4% |
| 2 | 🇩🇪 DE | 15 | 31.2% |
| 3 | 🇳🇱 NL | 3 | 6.2% |
| 4 | 🌐 Unbekannt | 1 | 2.1% |

## MITRE ATT&CK

> 21 von 48 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 20 |
| Lateral Movement | 20 |
| Command and Control | 1 |
| Collection | 1 |


## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [c3f27fa88aada79400d7…](https://bazaar.abuse.ch/sample/c3f27fa88aada79400d7a0ad373347b9b4c0493f2734d68f950019a389cd5123/)

- **Familie:** Snowlight
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.SNOWLIGHT.SMREAC
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2235` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.drq` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.Q!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!6C5DC1B05918` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrendMicro | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| TrendMicro-HouseCall | `Trojan.Linux.SNOWLIGHT.SMREAC` |
| Varist | `E64/Agent.BD.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.bw` |

### [042052c796e569d093f5…](https://bazaar.abuse.ch/sample/042052c796e569d093f5d6ed758446d241f5b63bf13fc67ad01b45c1ec28e3e4/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-AAP [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-AAP [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen` |
| Avast | `ELF:Mirai-AAP [Trj]` |
| Avast-Mobile | `ELF:Mirai-AT [Trj]` |
| Avira | `EXP/ELF.Gafgyt.X` |
| ClamAV | `Unix.Dropper.Mirai-7135928-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9838` |
| ESET-NOD32 | `Linux/Mirai.B trojan` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Exploit.EXP/ELF.Gafgyt.X` |
| Fortinet | `Linux/Mirai.B!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ew` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.DD` |
| Rising | `Backdoor.Mirai/Linux!1.12D96 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Sophos | `Linux/DDoS-BI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Trojan.Linux.Mirai.bbh` |
| ZoneAlarm | `Linux/DDoS-BI` |
| huorong | `Trojan/Linux.Mirai.g` |

### [4ecd3a4ad58c94418c8d…](https://bazaar.abuse.ch/sample/4ecd3a4ad58c94418c8dcc5d154588374862d538590038202cf95e5163622242/)

- **Familie:** RemusStealer
- **Erkannt von:** 37 von 75 Engines (49.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Midie.190317
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Midie.190317`

**Erkennende Engines (37/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Midie.190317` |
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5954155` |
| Alibaba | `TrojanDownloader:Win64/Generic.9e00de81` |
| Arcabit | `Trojan.Midie.D2E76D` |
| Avast | `FileRepMalware [Misc]` |
| BitDefender 🛡️ | `Gen:Variant.Midie.190317` |
| Bkav | `W32.Malware.2DA224F0` |
| CTX | `exe.trojan.midie` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/Agent_AGen.QWL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Midie.190317 (B)` |
| GData | `Gen:Variant.Midie.190317` |
| Gridinsoft | `Trojan.Win64.Agent.sa` |
| Kaspersky | `HEUR:Trojan-Downloader.Win32.Agent.gen` |
| Kingsoft | `Win32.Trojan-Downloader.Agent.gen` |
| Lionic | `Trojan.Win32.RemusStealer.4!c` |
| Malwarebytes | `Generic.Malware/Suspicious` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `ti!4ECD3A4AD58C` |
| MicroWorld-eScan | `Gen:Variant.Midie.190317` |
| Microsoft 🛡️ | `Trojan:Win32/Ravartar!rfn` |
| Paloalto | `generic.ml` |
| Rising | `Downloader.Agent!8.B23 (CLOUD)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan-Downloader.Agent.Nqil` |
| TrellixENS | `Artemis!85FF31B155F6` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H09JH26` |
| VIPRE | `Gen:Variant.Midie.190317` |
| alibabacloud | `Trojan[downloader]:Win/Agent_AGen.QIA` |
| huorong | `TrojanDownloader/W64.Agent.dr` |

### [74b9ae53f86db1b4a34c…](https://bazaar.abuse.ch/sample/74b9ae53f86db1b4a34c6aafe515af71399a4d6a24e9c416bae28342365a3bc0/)

- **Familie:** B!ml
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

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
- **Mirai** (19×)
- **macho** (9×)
- **exe** (8×)
- **AMOS** (7×)
- **ClickFix** (7×)
- **Foxveil** (7×)
- **Mach-O** (7×)
- **macOS** (7×)
- **loader** (6×)
- **dropped-by-GCleaner** (5×)
- **Gafgyt** (4×)
- **A** (3×)
- **gafgyt** (2×)
- **vshell** (2×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -13 (33→20)
- ↓ **unbekannt** -18 (30→12)
- neu: **AMOS** (7)
- neu: **Gafgyt** (4)
- neu: **Snowlight** (1)
- neu: **RemusStealer** (1)
- neu: **NanoCore** (1)
- neu: **B!ml** (1)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -8 (28→20)
- ↓ **unbekannt** -15 (27→12)
- ↑ **AMOS** +6 (1→7)
- neu: **Gafgyt** (4)
- neu: **Snowlight** (1)
- neu: **NanoCore** (1)
- neu: **B!ml** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 0.897 MB |
| σ Dateigröße | 1.135 MB |
| Ø Risiko-Score | 75.2/100 |
| Ø Klassifikations-Konfidenz | 82.5% |
| Samples mit VT | 5/48 |
| Samples mit MITRE | 21/48 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 37 |
| Unbekannte Familien | 2 (4.2%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:25 | [f3668cb7b874…](https://bazaar.abuse.ch/sample/f3668cb7b8748db4142d660a75f15bfa51936fbe6717093a770c57f51d33eb79/) | `msi` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 03:24 | [c24ae3aef86d…](https://bazaar.abuse.ch/sample/c24ae3aef86d4ce54942f811bbc9bc2620131f340a4de4bf3fd1eb00f57341c9/) | `elf` | Mirai | 84.3 | – | – | 🇺🇸US |
| 03:24 | [9bc7fd6c0f39…](https://bazaar.abuse.ch/sample/9bc7fd6c0f392b367d76e1f617e60978760b54acc14e40a54ef0d39f7d067a61/) | `macho` | unbekannt | 32.5 | – | – | 🇺🇸US |
| 03:24 | [c3f27fa88aad…](https://bazaar.abuse.ch/sample/c3f27fa88aada79400d7a0ad373347b9b4c0493f2734d68f950019a389cd5123/) | `elf` | Snowlight | 75.4 | 38.7% | 🟡 SCHWACH ERKANNT | 🇺🇸US |
| 03:04 | [320a8ba6be9b…](https://bazaar.abuse.ch/sample/320a8ba6be9b398f8bbe4c89246c93378b2421e195470c7d1be609001833f75e/) | `exe` | unbekannt | 74.6 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 18.10.2026 03:40 UTC*