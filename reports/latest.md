# MalwareBazaar – 18.10.2026 08:41 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **55** |
| Höchster Score | **86.4/100** – f7ac12efd9c1f2b1… |
| Häufigste Familie | **Mirai** (53x) |
| Häufigster Typ | **elf** (72x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 54 Samples |
| Ø Dateigröße | 1.56 MB (σ=5.02) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 72 | 71.3%  ██████████████ |
| `exe` | 15 | 14.9%  ██ |
| `sh` | 9 | 8.9%  █ |
| `macho` | 3 | 3.0%   |
| `ps1` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 53 | 52.5% |
| 2 | unbekannt | 40 | 39.6% |
| 3 | RustyStealer | 2 | 2.0% |
| 4 | AgentTesla | 2 | 2.0% |
| 5 | ELF:Svirtu-AA [Trj] | 1 | 1.0% |
| 6 | RemusStealer | 1 | 1.0% |
| 7 | CoinMiner | 1 | 1.0% |
| 8 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 54 | 53.5% | 94% |
| Linux-Malware | 18 | 17.8% | 45% |
| Andere / Unbekannt | 12 | 11.9% | 20% |
| Windows-Malware | 9 | 8.9% | 35% |
| Infostealer | 3 | 3.0% | 75% |
| Loader | 2 | 2.0% | 75% |
| Skript/Dropper | 2 | 2.0% | 35% |
| RAT | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 55 | 54.5% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 29 | 28.7% |
| 🟢 NIEDRIG | 12 | 11.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f7ac12efd9c1f2…](https://bazaar.abuse.ch/sample/f7ac12efd9c1f2b158b62a2463c6543d8fd82c6d59509a3d9c270bf064e67cae/) | Mirai | Botnet/IoT | **86.4** | 🔴 KRITISCH | 1.3% | ⚠️ KAUM ERKANNT | ✗ |
| [1d4b063e69d7ce…](https://bazaar.abuse.ch/sample/1d4b063e69d7ce91b723a71ed7ebc48a69c28d6e7489b50ea29e85ec59bfe582/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [900d784d8900de…](https://bazaar.abuse.ch/sample/900d784d8900dec27946f6d2b4a4132a37bbc4118cf69838dbb827f6f38f1354/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [d3039b7f1733be…](https://bazaar.abuse.ch/sample/d3039b7f1733bea1e62fe5b2d43d3a0e944a94e63d4ab61ce86cf0b2fd7a633e/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [9791ed495a9b9e…](https://bazaar.abuse.ch/sample/9791ed495a9b9e1c585a7f05073bd61b979a55084477ca6519502f0a6e1a518d/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [94e304c362e2a1…](https://bazaar.abuse.ch/sample/94e304c362e2a109142406e26d410ee83dd21acf9a64e40c48d86fce475da856/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [dfc7acebd7d2bc…](https://bazaar.abuse.ch/sample/dfc7acebd7d2bcc2fc1b81e4ab9b4cb8f4d68c314ec53b774cb9228bfcc6459f/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [fdfdce44637fb1…](https://bazaar.abuse.ch/sample/fdfdce44637fb1bb6e773068b8228b4909b06829524d9f9b32c6fc1094ff1dbc/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [f57d5568bd35e9…](https://bazaar.abuse.ch/sample/f57d5568bd35e9865aa555bcedf544a62caa0a3a3fd4a978a696daf34aadf1ae/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [1cce1c2c539ed3…](https://bazaar.abuse.ch/sample/1cce1c2c539ed3520b9daad17822996e9c9199bed23b01a8319646ae0033895e/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6037/7463 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6037/7463 |
| 3 | ESET-NOD32 | 77.4% | 5778/7463 |
| 4 | Kaspersky | 76.3% | 5695/7462 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5331/7460 |
| 8 | Rising | 68.7% | 5127/7463 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4947/7459 |
| 11 | Tencent | 65.3% | 4725/7237 |
| 12 | AVG | 65.2% | 4859/7458 |
| 13 | Avast | 65.1% | 4859/7459 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4567/7456 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 83 | 82.2% |
| 🪟 Windows | 15 | 14.9% |
| 🍎 macOS | 3 | 3.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 98 | 97.0% |
| C2 / Nachladen | 3 | 3.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 61 | 60.4% |
| 2 | 🇺🇸 US | 22 | 21.8% |
| 3 | 🇳🇱 NL | 16 | 15.8% |
| 4 | 🇫🇷 FR | 1 | 1.0% |
| 5 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 54 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 53 |
| Lateral Movement | 53 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>f7ac12efd9c1f2b158b6… – Mirai | 🔴 KRITISCH 86.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>1d4b063e69d7ce91b723… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>900d784d8900dec27946… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>d3039b7f1733bea1e62f… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>9791ed495a9b9e1c585a… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [3a958414ffa0cdbc749d…](https://bazaar.abuse.ch/sample/3a958414ffa0cdbc749d58465c05f94057805ea7a6e0345d8329361ce202f051/)

- **Familie:** ELF:Svirtu-AA [Trj]
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Svirtu-AA [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Svirtu-AA [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Svirtu-AA [Trj]` |
| Avast-Mobile | `ELF:Svirtu-AA [Trj]` |
| Avira | `TR/LINUX.Svirtu.AA` |
| ClamAV | `Unix.Trojan.Mirai-8274771-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| F-Secure | `Trojan.TR/LINUX.Svirtu.AA` |
| Fortinet | `ELF/Mirai.BHD!tr` |
| Google | `Detected` |
| Ikarus | `Linux.Mirai` |
| Jiangmin | `Backdoor.Linux.iayg` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.h` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `GenericRXTW-FA!6B401357EFFA` |
| Symantec | `Linux.Mirai` |
| Tencent | `Trojan.Linux.Mirai.zf` |
| TrellixENS | `GenericRXTW-FA!6B401357EFFA` |
| Varist | `E32/Mirai.BMN` |
| alibabacloud | `Backdoor:Linux/Mirai.a7e99a80` |
| huorong | `Trojan/Linux.Mirai.q!crit` |

### [93d89d70e6882448f1a7…](https://bazaar.abuse.ch/sample/93d89d70e6882448f1a727922d0eabc413f235ff14dde23f7e1da9d769a987fb/)

- **Familie:** Mirai
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** ELF:Gafgyt-KS [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Gafgyt-KS [Trj]` |
| AhnLab-V3 | `Linux/Mirai13.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Gafgyt-KS [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-KS [Trj]` |
| Avira | `TR/LINUX.Gafgyt.KS` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.DKV trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Gafgyt.KS` |
| Fortinet | `ELF/Mirai.DKV!tr` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Linux/Mirai.EQQ` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.E!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Mirai-FROZ!BB3AED2D1F0F` |
| Sophos | `Linux/DDoS-FP` |
| Symantec | `Linux.Mirai!g2` |
| Tencent | `Trojan.Linux.Mirai.zf` |
| TrellixENS | `Linux/Mirai-FROZ!BB3AED2D1F0F` |
| TrendMicro | `Backdoor.Linux.BASHLITE.SMJC11` |
| TrendMicro-HouseCall | `Backdoor.Linux.BASHLITE.SMJC11` |
| Varist | `E32/Mirai.DJ.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-FP` |
| huorong | `Trojan/Linux.Mirai.w!crit` |

### [83da0e8a179cf390198e…](https://bazaar.abuse.ch/sample/83da0e8a179cf390198e2576f2c2a0046367e8f5b5bfa02835ba9cdaca50be97/)

- **Familie:** RustyStealer
- **Erkannt von:** 48 von 75 Engines (64.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Heur.Whisperer.1.0000000100
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.Whisperer.1.0000000100`

**Erkennende Engines (48/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Misc]` |
| AhnLab-V3 | `Malware/Win.MalwareX-gen.R773530` |
| Alibaba | `Trojan:Win64/Inject.3613b069` |
| Antiy-AVL | `Trojan/Win32.Inject` |
| Arcabit | `Trojan.Whisperer.1.0000000100` |
| Avast | `Win64:MalwareX-gen [Misc]` |
| Avira | `TR/W64.Agent` |
| BitDefender 🛡️ | `Gen:Heur.Whisperer.1.0000000100` |
| Bkav | `W32.Malware.DB282B95` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Siggen5.32603` |
| ESET-NOD32 | `Win64/Agent_AGen.NQF trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.Whisperer.1.0000000100 (B)` |
| F-Secure | `Trojan.TR/W64.Agent` |
| GData | `Gen:Heur.Whisperer.1.0000000100` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win64.Agent.oa!s1` |
| Ikarus | `Trojan.Win64.Agent` |
| K7AntiVirus | `Trojan ( 006df7a51 )` |
| K7GW | `Trojan ( 006df7a51 )` |
| Kaspersky | `Trojan.Win32.Inject.arbnl` |
| Kingsoft | `Win32.Trojan.Inject.arbnl` |
| Lionic | `Trojan.Win32.Foreign.natV` |
| Malwarebytes | `Malware.AI.3305860687` |
| MaxSecure | `Trojan.Malware.272843718.susgen` |
| McAfeeD | `ti!83DA0E8A179C` |
| MicroWorld-eScan | `Gen:Heur.Whisperer.1.0000000100` |
| Microsoft 🛡️ | `Trojan:Win64/Whisperer.MX!MTB` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Zusy!8.10EDD (TFE:5:r8diXv89R3B)` |
| Skyhigh | `Artemis` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.10c47bb6` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H01ID26` |
| VBA32 | `Adware.Puwaders` |
| VIPRE | `Gen:Heur.Whisperer.1.0000000100` |
| Varist | `W64/ABTrojan.NPDC-2857` |
| Webroot | `Win.Trojan.Gen` |
| Zillya | `Trojan.Inject.Win32.358445` |
| alibabacloud | `Trojan:Win/Agent_AGen.NR!` |
| huorong | `Trojan/W64.Agent.ii` |

### [f7ac12efd9c1f2b158b6…](https://bazaar.abuse.ch/sample/f7ac12efd9c1f2b158b62a2463c6543d8fd82c6d59509a3d9c270bf064e67cae/)

- **Familie:** Mirai
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** -11
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

- **elf** (72×)
- **Mirai** (52×)
- **upx-dec** (16×)
- **upx** (16×)
- **exe** (14×)
- **sh** (9×)
- **dropped-by-GCleaner** (3×)
- **macho** (3×)
- **MIX8.file** (2×)
- **RustyStealer** (2×)
- **Hajime** (2×)
- **AgentTesla** (2×)
- **alien** (2×)
- **powershell** (2×)
- **ps1** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +26 (27→53)
- ↑ **unbekannt** +13 (27→40)
- neu: **RustyStealer** (2)
- neu: **AgentTesla** (2)
- neu: **ELF:Svirtu-AA [Trj]** (1)
- neu: **CoinMiner** (1)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +26 (27→53)
- ↑ **unbekannt** +12 (28→40)
- neu: **RustyStealer** (2)
- neu: **AgentTesla** (2)
- neu: **ELF:Svirtu-AA [Trj]** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.559 MB |
| σ Dateigröße | 5.020 MB |
| Ø Risiko-Score | 63.9/100 |
| Ø Klassifikations-Konfidenz | 69.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 54/101 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 26 |
| Unbekannte Familien | 12 (11.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 08:38 | [1d4b063e69d7…](https://bazaar.abuse.ch/sample/1d4b063e69d7ce91b723a71ed7ebc48a69c28d6e7489b50ea29e85ec59bfe582/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 08:34 | [900d784d8900…](https://bazaar.abuse.ch/sample/900d784d8900dec27946f6d2b4a4132a37bbc4118cf69838dbb827f6f38f1354/) | `elf` | Mirai | 84.5 | – | – | 🇳🇱NL |
| 08:34 | [d3039b7f1733…](https://bazaar.abuse.ch/sample/d3039b7f1733bea1e62fe5b2d43d3a0e944a94e63d4ab61ce86cf0b2fd7a633e/) | `elf` | Mirai | 84.5 | – | – | 🇳🇱NL |
| 08:34 | [9791ed495a9b…](https://bazaar.abuse.ch/sample/9791ed495a9b9e1c585a7f05073bd61b979a55084477ca6519502f0a6e1a518d/) | `elf` | Mirai | 84.5 | – | – | 🇳🇱NL |
| 08:34 | [94e304c362e2…](https://bazaar.abuse.ch/sample/94e304c362e2a109142406e26d410ee83dd21acf9a64e40c48d86fce475da856/) | `elf` | Mirai | 84.5 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 18.10.2026 08:41 UTC*