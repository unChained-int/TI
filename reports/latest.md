# MalwareBazaar – 17.10.2026 16:55 UTC

Dieser Run hat **70 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **71** |
| Kritisch (≥75) | **52** |
| Höchster Score | **84.5/100** – 5144bdcbafac26bd… |
| Häufigste Familie | **Mirai** (33x) |
| Häufigster Typ | **elf** (39x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 34 Samples |
| Ø Dateigröße | 10.48 MB (σ=26.84) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 39 | 54.9%  ██████████ |
| `exe` | 26 | 36.6%  ███████ |
| `sh` | 5 | 7.0%  █ |
| `dll` | 1 | 1.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 33 | 46.5% |
| 2 | unbekannt | 31 | 43.7% |
| 3 | ValleyRAT | 3 | 4.2% |
| 4 | SalatStealer | 2 | 2.8% |
| 5 | SH | 1 | 1.4% |
| 6 | RemcosRAT | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 33 | 46.5% | 95% |
| Infostealer | 11 | 15.5% | 75% |
| Linux-Malware | 7 | 9.9% | 45% |
| Loader | 6 | 8.5% | 75% |
| RAT | 5 | 7.0% | 79% |
| Windows-Malware | 4 | 5.6% | 35% |
| Trojaner | 2 | 2.8% | 75% |
| Cryptominer | 1 | 1.4% | 75% |
| Backdoor | 1 | 1.4% | 75% |
| Andere / Unbekannt | 1 | 1.4% | 20% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 52 | 73.2% |
| 🟠 HOCH | 7 | 9.9% |
| 🟡 MITTEL | 11 | 15.5% |
| 🟢 NIEDRIG | 1 | 1.4% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [5144bdcbafac26…](https://bazaar.abuse.ch/sample/5144bdcbafac26bd8f1474087f2133561c8a18edf1936a91f197957500c5f91b/) | unbekannt | Backdoor | **84.5** | 🔴 KRITISCH | – | – | ? |
| [b13befdd6f8a03…](https://bazaar.abuse.ch/sample/b13befdd6f8a0353d8681949d3a9ce91e319d007eb457e8cc9c9df013217d0d3/) | unbekannt | Trojaner | **83.3** | 🔴 KRITISCH | – | – | ? |
| [3da1a5a4d7509e…](https://bazaar.abuse.ch/sample/3da1a5a4d7509e76292249b79eb1bfd33919f6054676c789d7402547fee580b5/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [bc02fec47a19d1…](https://bazaar.abuse.ch/sample/bc02fec47a19d13db3cb5b36df9052084204696ecddd8cd1f2a8905dc65b22ad/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [16e7712356bf17…](https://bazaar.abuse.ch/sample/16e7712356bf17eefd909480902a4987195c1b085d00a3a2c47dc36aefb60056/) | unbekannt | Trojaner | **82.9** | 🔴 KRITISCH | – | – | ? |
| [207ba61ec7b63c…](https://bazaar.abuse.ch/sample/207ba61ec7b63cd3e5db41908de1ca3159238cdd74a965e6a81ce211cd586ebc/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [c3814a225595b5…](https://bazaar.abuse.ch/sample/c3814a225595b5abd6fcede0da5723fc66c2cfdb07115bf516de99582594d4af/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [f5b1cd0523a281…](https://bazaar.abuse.ch/sample/f5b1cd0523a28117759fa2eed0e8666843febb4dd77ba85de544dac96d9c60b4/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [8c170fff66f307…](https://bazaar.abuse.ch/sample/8c170fff66f3071c983776321e71ec585c1d2be8e78040d350a230e52b09b874/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [0b52360cb5e7bc…](https://bazaar.abuse.ch/sample/0b52360cb5e7bc0de3fabcf6552958514f92db05083e9101780b361190004d16/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6020/7444 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6020/7444 |
| 3 | ESET-NOD32 | 77.4% | 5762/7444 |
| 4 | Kaspersky | 76.3% | 5682/7443 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5319/7441 |
| 8 | Rising | 68.7% | 5113/7444 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4938/7440 |
| 11 | Tencent | 65.3% | 4712/7218 |
| 12 | Avast | 65.1% | 4844/7440 |
| 13 | AVG | 65.1% | 4844/7439 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4557/7437 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 44 | 62.0% |
| 🪟 Windows | 27 | 38.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 61 | 85.9% |
| C2 / Nachladen | 4 | 5.6% |
| MaaS-Loader | 3 | 4.2% |
| Drive-By / Exploit-Kit | 3 | 4.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 41 | 57.7% |
| 2 | 🇳🇱 NL | 14 | 19.7% |
| 3 | 🇺🇸 US | 13 | 18.3% |
| 4 | 🇷🇺 RU | 1 | 1.4% |
| 5 | 🇨🇭 CH | 1 | 1.4% |
| 6 | 🌐 Unbekannt | 1 | 1.4% |

## MITRE ATT&CK

> 34 von 71 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 33 |
| Lateral Movement | 33 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>3da1a5a4d7509e762922… – Mirai | 🔴 KRITISCH 83.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>bc02fec47a19d13db3cb… – Mirai | 🔴 KRITISCH 83.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [29b9e559fcfd59c54f49…](https://bazaar.abuse.ch/sample/29b9e559fcfd59c54f49b366b8ae6982bf8262a5ab3401e31da72f6a3e826808/)

- **Familie:** SH
- **Erkannt von:** 4 von 75 Engines (5.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/TrojanDownloader.SH.GZA trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.DownLoader.2650` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.GZA trojan` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| huorong | `TrojanDownloader/BAT.Maloader.ae` |

### [b7e1ce9255b89d08c5e9…](https://bazaar.abuse.ch/sample/b7e1ce9255b89d08c5e95749f72993b8b50cfff17ee17f843dee947e873c8212/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.jw` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.130E7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!4AE090A03355` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| TrellixENS | `LINUX/Mirai-FQU!4AE090A03355` |
| Varist | `E32/Mirai.EF.gen!Eldorado` |

### [ef056928746baa0b5ca7…](https://bazaar.abuse.ch/sample/ef056928746baa0b5ca79fc3fbfdd624d980daa59ac2f17dd4b6671f2efce169/)

- **Familie:** Mirai
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-BQZ [PUP]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-BQZ [PUP]` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Agent-BQZ [PUP]` |
| Avira | `PUA/LINUX.Agent.BQZ` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10456` |
| ESET-NOD32 | `Linux/Mirai.FLQ trojan` |
| F-Secure | `PotentialRisk.PUA/LINUX.Agent.BQZ` |
| Fortinet | `ELF/Condi.CDB!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jp` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.148C3 (CLASSIC)` |
| Tencent | `Backdoor.Linux.DDoS.pa` |
| Varist | `E32/Mirai.BMU` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.mq` |

### [8e9905a85377fa1e13c3…](https://bazaar.abuse.ch/sample/8e9905a85377fa1e13c347fc3cd7ca1bb2e390bd093fd2d5a9c9675057a8f396/)

- **Familie:** Mirai
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-AIN [PUP]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-AIN [PUP]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Agent-AIN [PUP]` |
| Avira | `PUA/LINUX.Agent.AIN` |
| ClamAV | `Unix.Dropper.Mirai-7540662-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9829` |
| ESET-NOD32 | `Linux/Agent_AGen.GK trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `PotentialRisk.PUA/LINUX.Agent.AIN` |
| Fortinet | `ELF64/Mirai.TSU!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Multiverze` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nn` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BF!MTB` |
| SentinelOne | `Static AI - Malicious ELF` |
| huorong | `Trojan/Linux.Mirai.l` |

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

- **elf** (39×)
- **Mirai** (32×)
- **exe** (25×)
- **signed** (6×)
- **infostealer** (6×)
- **sh** (5×)
- **ValleyRAT** (5×)
- **honeypot** (4×)
- **dropped-by-GCleaner** (4×)
- **RAT** (3×)
- **upx-dec** (3×)
- **upx** (3×)
- **downloader** (2×)
- **DvnX** (2×)
- **stealer** (2×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -3 (36→33)
- ↑ **unbekannt** +2 (29→31)
- neu: **ValleyRAT** (3)
- ↑ **SalatStealer** +1 (1→2)
- neu: **SH** (1)
- weg: **AMOS** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +3 (30→33)
- ↑ **unbekannt** +4 (27→31)
- ↑ **ValleyRAT** +2 (1→3)
- neu: **SalatStealer** (2)
- neu: **SH** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 10.478 MB |
| σ Dateigröße | 26.841 MB |
| Ø Risiko-Score | 73.4/100 |
| Ø Klassifikations-Konfidenz | 78.6% |
| Samples mit VT | 5/71 |
| Samples mit MITRE | 34/71 |
| Eindeutige Familien | 6 |
| Eindeutige Tags | 49 |
| Unbekannte Familien | 1 (1.4%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 16:52 | [82eba36c8ac1…](https://bazaar.abuse.ch/sample/82eba36c8ac1613f451333eae4bff558e53cf814938d4b181790644371400eec/) | `sh` | unbekannt | 68.0 | – | – | 🇩🇪DE |
| 16:51 | [29b9e559fcfd…](https://bazaar.abuse.ch/sample/29b9e559fcfd59c54f49b366b8ae6982bf8262a5ab3401e31da72f6a3e826808/) | `sh` | SH | 80.6 | 5.3% | ⚠️ KAUM ERKANNT | 🇺🇸US |
| 16:48 | [5144bdcbafac…](https://bazaar.abuse.ch/sample/5144bdcbafac26bd8f1474087f2133561c8a18edf1936a91f197957500c5f91b/) | `sh` | unbekannt | 84.5 | – | – | 🇩🇪DE |
| 16:29 | [b13befdd6f8a…](https://bazaar.abuse.ch/sample/b13befdd6f8a0353d8681949d3a9ce91e319d007eb457e8cc9c9df013217d0d3/) | `dll` | unbekannt | 83.3 | – | – | 🇩🇪DE |
| 16:22 | [dd9face98b78…](https://bazaar.abuse.ch/sample/dd9face98b785172b8d31121199e25ca2756041f5fd1f38189f016c81a84bff7/) | `exe` | unbekannt | 38.6 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 17.10.2026 16:55 UTC*