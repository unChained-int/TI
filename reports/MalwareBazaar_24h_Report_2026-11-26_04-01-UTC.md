# MalwareBazaar – 26.11.2026 04:01 UTC

Dieser Run hat **61 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **62** |
| Kritisch (≥75) | **33** |
| Höchster Score | **94.8/100** – bfe9197db6e12f0d… |
| Häufigste Familie | **unbekannt** (28x) |
| Häufigster Typ | **elf** (27x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 10 Samples |
| Ø Dateigröße | 7.13 MB (σ=17.88) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 27 | 43.5%  ████████ |
| `exe` | 22 | 35.5%  ███████ |
| `macho` | 6 | 9.7%  █ |
| `html` | 2 | 3.2%   |
| `sh` | 2 | 3.2%   |
| `msi` | 1 | 1.6%   |
| `apk` | 1 | 1.6%   |
| `hta` | 1 | 1.6%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 28 | 45.2% |
| 2 | Prometei | 9 | 14.5% |
| 3 | GoDDoSAgent | 6 | 9.7% |
| 4 | WARDENStealer | 4 | 6.5% |
| 5 | ConnectWise | 4 | 6.5% |
| 6 | njrat | 2 | 3.2% |
| 7 | WannaCry | 2 | 3.2% |
| 8 | Mirai | 2 | 3.2% |
| 9 | Runner | 1 | 1.6% |
| 10 | B | 1 | 1.6% |
| 11 | LummaStealer | 1 | 1.6% |
| 12 | Stealc | 1 | 1.6% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 19 | 30.6% | 78% |
| Infostealer | 10 | 16.1% | 78% |
| Linux-Malware | 9 | 14.5% | 45% |
| Botnet/IoT | 9 | 14.5% | 78% |
| Windows-Malware | 7 | 11.3% | 35% |
| Andere / Unbekannt | 2 | 3.2% | 20% |
| Trojaner | 2 | 3.2% | 65% |
| Ransomware | 2 | 3.2% | 95% |
| Android-Malware | 1 | 1.6% | 45% |
| Skript/Dropper | 1 | 1.6% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 33 | 53.2% |
| 🟠 HOCH | 9 | 14.5% |
| 🟡 MITTEL | 18 | 29.0% |
| 🟢 NIEDRIG | 2 | 3.2% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [bfe9197db6e12f…](https://bazaar.abuse.ch/sample/bfe9197db6e12f0df5abc426e6abfbe675da160c99a63f394512b3083a5ed485/) | WannaCry | Ransomware | **94.8** | 🔴 KRITISCH | – | – | ? |
| [9323a17410c577…](https://bazaar.abuse.ch/sample/9323a17410c5772e23b0b4ad39d8ae25fb141073a37be5acba9677b93e89181a/) | WannaCry | Ransomware | **94.2** | 🔴 KRITISCH | – | – | ? |
| [16cbdd04e6ed54…](https://bazaar.abuse.ch/sample/16cbdd04e6ed5451992cec8d6f8024afdd68e1925e361a58bffe0d538848f990/) | LummaStealer | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [52ba8d460ac1c5…](https://bazaar.abuse.ch/sample/52ba8d460ac1c5a47de84c8f5649ba0b521ae5ec8d9ea1c6f019e5ead182f6b2/) | Stealc | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [ebcf67129f78ec…](https://bazaar.abuse.ch/sample/ebcf67129f78ec5d6bae22311bbebdaf83a82b70d3bf85d1788e8405d1074474/) | QuasarRAT | RAT | **86.7** | 🔴 KRITISCH | – | – | ? |
| [0bd65dad9971ad…](https://bazaar.abuse.ch/sample/0bd65dad9971ad44c6b10d3802aa02031193f16ccca9f4a2cb9e24d8f1c39fe3/) | njrat | RAT | **86.3** | 🔴 KRITISCH | – | – | ? |
| [4bcbd737e58353…](https://bazaar.abuse.ch/sample/4bcbd737e58353b12cbca81ddd814c0b8d9e7127a6b9a035e29e34a8e3137bb1/) | Runner | Trojaner | **83.3** | 🔴 KRITISCH | 1.4% | ⚠️ KAUM ERKANNT | ✗ |
| [70e2c20f766b62…](https://bazaar.abuse.ch/sample/70e2c20f766b62aa54accfbe378d0c9405b8c82aa5168bb7f2369f81d33f9ef7/) | unbekannt | Infostealer | **81.9** | 🔴 KRITISCH | – | – | ? |
| [b051b1400b4eed…](https://bazaar.abuse.ch/sample/b051b1400b4eed7c3d573f94fc33474b44f4119160995e7ac11d061604d99bf6/) | B | Infostealer | **81.5** | 🔴 KRITISCH | 1.4% | ⚠️ KAUM ERKANNT | ✗ |
| [71f8bbdcd9c67a…](https://bazaar.abuse.ch/sample/71f8bbdcd9c67ab1dc96c9c21a6d1e2729702e67580345e15a8009983b41eb50/) | Mirai | Botnet/IoT | **81.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6610/8143 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6610/8143 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6308/8143 |
| 6 | Kaspersky | 75.6% | 6153/8142 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5800/8139 |
| 9 | Rising | 68.6% | 5588/8143 |
| 10 | Varist | 66.1% | 5379/8138 |
| 11 | Tencent | 65.2% | 5165/7917 |
| 12 | Avast | 65.2% | 5305/8139 |
| 13 | AVG | 65.2% | 5305/8138 |
| 14 | McAfeeD | 61.4% | 4993/8135 |
| 15 | huorong | 61.0% | 4963/8135 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 35 | 56.5% |
| 🪟 Windows | 24 | 38.7% |
| ❓ Unbekannt | 2 | 3.2% |
| 🤖 Android | 1 | 1.6% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 58 | 93.5% |
| Exploit / N-Day | 2 | 3.2% |
| Trojanisierte Software | 1 | 1.6% |
| APK-Sideloading | 1 | 1.6% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 24 | 38.7% |
| 2 | 🇩🇪 DE | 17 | 27.4% |
| 3 | 🇫🇷 FR | 14 | 22.6% |
| 4 | 🇳🇱 NL | 3 | 4.8% |
| 5 | 🇸🇪 SE | 2 | 3.2% |
| 6 | 🇯🇵 JP | 1 | 1.6% |
| 7 | 🌐 Unbekannt | 1 | 1.6% |

## MITRE ATT&CK

> 10 von 62 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 5 |
| Credential Access | 4 |
| Exfiltration | 4 |
| Command and Control | 3 |
| Initial Access | 3 |
| Lateral Movement | 3 |

<details><summary>16cbdd04e6ed5451992c… – LummaStealer | 🔴 KRITISCH 88.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>52ba8d460ac1c5a47de8… – Stealc | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>ebcf67129f78ec5d6bae… – QuasarRAT | 🔴 KRITISCH 86.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [4bcbd737e58353b12cbc…](https://bazaar.abuse.ch/sample/4bcbd737e58353b12cbca81ddd814c0b8d9e7127a6b9a035e29e34a8e3137bb1/)

- **Familie:** Runner
- **Erkannt von:** 1 von 74 Engines (1.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan/BAT.Runner.dk
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/74):**

| Engine | Erkannter Name |
|--------|----------------|
| huorong | `Trojan/BAT.Runner.dk` |

### [b051b1400b4eed7c3d57…](https://bazaar.abuse.ch/sample/b051b1400b4eed7c3d573f94fc33474b44f4119160995e7ac11d061604d99bf6/)

- **Familie:** B
- **Erkannt von:** 1 von 74 Engines (1.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** PSH/Stealer.B
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Varist | `PSH/Stealer.B` |

### [204fc71b003e0c20d639…](https://bazaar.abuse.ch/sample/204fc71b003e0c20d639cd611432876daf70e5ebcaadefaa12d54660c4ff3ca6/)

- **Familie:** njrat
- **Erkannt von:** 59 von 74 Engines (79.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (59/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Spyware.GenericAD.Agent` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.BFFB9412` |
| CAT-QuickHeal | `Trojan.MsilFC.S26036257` |
| CTX | `exe.unknown.msil` |
| ClamAV | `Win.Packed.njRAT-7445143-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.BladabindiNET.10` |
| ESET-NOD32 | `MSIL/Bladabindi.AZ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Krypt.!cdmip!.2 (B)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/MALD2.F963!tr` |
| GData | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `MSIL.Trojan-Spy.KeyLogger.gen` |
| Lionic | `Trojan.Win32.Bladabindi.l!c` |
| Malwarebytes | `Trojan.MalPack` |
| MaxSecure | `Trojan.W32.M161126.NjRat.YR` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| NANO-Antivirus | `Trojan.Win32.KeyLogger.lhiedu` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Generic` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!2D5EBA72F838` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Backdoor.Ratenjay!gen3` |
| Tencent | `Trojan.Msil.Bladabindi.16009413` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!2D5EBA72F838` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101KN26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/Bladabindi.HK.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Bladabindi.21504.SD` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| Webroot | `W32.Malware.gen` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |

### [ad15afb60cc9d19ffe05…](https://bazaar.abuse.ch/sample/ad15afb60cc9d19ffe05d0995b52c478ae966a478ba2810efa30a71b6fd58eb1/)

- **Familie:** Prometei
- **Erkannt von:** 30 von 74 Engines (40.5%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39504221
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39504221`

**Erkennende Engines (30/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39504221` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC95D` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.39504221` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Mirai.39504221 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Mirai.39504221` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39504221` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39504221` |
| Varist | `E64/PrometeiS.C` |
| huorong | `Trojan/Prometei.c` |

### [c7937a0589cfc76c51ef…](https://bazaar.abuse.ch/sample/c7937a0589cfc76c51ef46b2f4e5b5d7e3da42bf01740baebe5e3d45c8cb0b88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 29 von 74 Engines (39.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Suschil!rfn`

**Erkennende Engines (29/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `RiskWare[RemoteAdmin]/MSIL.ConnectWise` |
| Bkav | `W32.Malware.CE6D6E6` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Win32.Trojan.Agent.TQDT4J` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| Lionic | `Trojan.Win32.ConnectWise.4!c` |
| Malwarebytes | `RiskWare.ConnectWise.Abused` |
| Microsoft 🛡️ | `Trojan:Win32/Suschil!rfn` |
| NANO-Antivirus | `Trojan.Win32.Drop.llafhv` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H06K926` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |


## Top Tags

- **elf** (26×)
- **RAT** (18×)
- **exe** (17×)
- **EasyShell** (16×)
- **Rust** (16×)
- **SnoopyTriage** (16×)
- **Prometei** (9×)
- **signed** (7×)
- **GoDDoSAgent** (6×)
- **macho** (6×)
- **WARDENStealer** (4×)
- **stealer** (3×)
- **Mirai** (3×)
- **ConnectWise** (3×)
- **vidar** (2×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -6 (34→28)
- ↑ **Prometei** +5 (4→9)
- neu: **GoDDoSAgent** (6)
- ↑ **ConnectWise** +2 (2→4)
- neu: **njrat** (2)
- neu: **WannaCry** (2)
- neu: **Runner** (1)
- neu: **B** (1)
- weg: **FunStealer** (war 28)
- weg: **EasyShell** (war 10)
- weg: **AsyncRAT** (war 4)
- weg: **Vidar** (war 2)
- weg: **RemcosRAT** (war 4)
- weg: **Formbook** (war 2)
- weg: **SilentNet** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -9 (37→28)
- ↑ **Prometei** +4 (5→9)
- neu: **GoDDoSAgent** (6)
- ↑ **ConnectWise** +3 (1→4)
- neu: **WannaCry** (2)
- ↓ **Mirai** -23 (25→2)
- neu: **Runner** (1)
- neu: **B** (1)
- weg: **RemcosRAT** (war 2)
- weg: **Snowlight** (war 3)
- weg: **EasyShell** (war 5)
- weg: **FunStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 7.128 MB |
| σ Dateigröße | 17.878 MB |
| Ø Risiko-Score | 65.4/100 |
| Ø Klassifikations-Konfidenz | 65.5% |
| Samples mit VT | 5/62 |
| Samples mit MITRE | 10/62 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 30 |
| Unbekannte Familien | 2 (3.2%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:40 | [70e2c20f766b…](https://bazaar.abuse.ch/sample/70e2c20f766b62aa54accfbe378d0c9405b8c82aa5168bb7f2369f81d33f9ef7/) | `exe` | unbekannt | 81.9 | – | – | 🇺🇸US |
| 02:40 | [d044cc11f5ec…](https://bazaar.abuse.ch/sample/d044cc11f5ec87fd134386cd7f8c769434ca7926a79883ef063ef22291bbd85c/) | `exe` | unbekannt | 81.0 | – | – | 🇫🇷FR |
| 02:05 | [6dc9369b976c…](https://bazaar.abuse.ch/sample/6dc9369b976cae0d9f8ffb157086188dd18b12b078f8a67d077897b30cd461a9/) | `html` | unbekannt | 31.1 | – | – | 🇺🇸US |
| 02:05 | [d3c3542aa380…](https://bazaar.abuse.ch/sample/d3c3542aa380a6a47c321cda47a6221d33c0a79863b549ae53d94f0268884880/) | `html` | unbekannt | 31.1 | – | – | 🇺🇸US |
| 02:05 | [4bcbd737e583…](https://bazaar.abuse.ch/sample/4bcbd737e58353b12cbca81ddd814c0b8d9e7127a6b9a035e29e34a8e3137bb1/) | `sh` | Runner | 83.3 | 1.4% | ⚠️ KAUM ERKANNT | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 26.11.2026 04:01 UTC*