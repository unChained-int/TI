# MalwareBazaar – 19.11.2026 12:37 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **72** |
| Höchster Score | **97.5/100** – 2d5fb9397c6b3ba4… |
| Häufigste Familie | **Mirai** (58x) |
| Häufigster Typ | **elf** (65x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 65 Samples |
| Ø Dateigröße | 3.09 MB (σ=13.09) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 65 | 64.4%  ████████████ |
| `exe` | 12 | 11.9%  ██ |
| `sh` | 6 | 5.9%  █ |
| `py` | 4 | 4.0%   |
| `dll` | 4 | 4.0%   |
| `zip` | 3 | 3.0%   |
| `php` | 2 | 2.0%   |
| `vhdx` | 1 | 1.0%   |
| `iso` | 1 | 1.0%   |
| `js` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 58 | 57.4% |
| 2 | unbekannt | 28 | 27.7% |
| 3 | Prometei | 6 | 5.9% |
| 4 | njrat | 5 | 5.0% |
| 5 | WannaCry | 1 | 1.0% |
| 6 | AsyncRAT | 1 | 1.0% |
| 7 | RemcosRAT | 1 | 1.0% |
| 8 | EpsilonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 59 | 58.4% | 94% |
| Andere / Unbekannt | 10 | 9.9% | 20% |
| Linux-Malware | 8 | 7.9% | 45% |
| RAT | 7 | 6.9% | 95% |
| Trojaner | 5 | 5.0% | 75% |
| Cryptominer | 4 | 4.0% | 75% |
| Windows-Malware | 3 | 3.0% | 35% |
| Ransomware | 1 | 1.0% | 95% |
| Loader | 1 | 1.0% | 75% |
| Backdoor | 1 | 1.0% | 75% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Infostealer | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 72 | 71.3% |
| 🟠 HOCH | 7 | 6.9% |
| 🟡 MITTEL | 12 | 11.9% |
| 🟢 NIEDRIG | 10 | 9.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [2d5fb9397c6b3b…](https://bazaar.abuse.ch/sample/2d5fb9397c6b3ba4ff4c083d5c756b53321ee5beb84b118ca919aa7088036812/) | WannaCry | Ransomware | **97.5** | 🔴 KRITISCH | – | – | ? |
| [df3469af6b6fd6…](https://bazaar.abuse.ch/sample/df3469af6b6fd6e425bec9e46d2835642be14ab5ecf1c56c6d5f5f4d760f1307/) | njrat | RAT | **89.2** | 🔴 KRITISCH | – | – | ? |
| [56e048a1f708bd…](https://bazaar.abuse.ch/sample/56e048a1f708bde497b3e01dcc218e8640b5903c8fc1989ee24dbe076c2070e3/) | njrat | RAT | **89.2** | 🔴 KRITISCH | – | – | ? |
| [7008be43b4d644…](https://bazaar.abuse.ch/sample/7008be43b4d644f1a54f63840ab39893ec454467fb9cc574cf93f0944928f56c/) | AsyncRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [c221e2da575ced…](https://bazaar.abuse.ch/sample/c221e2da575ced729ea0949a2d6817d3d22feea6eb802afb305866722813dcf1/) | njrat | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [5abb25a32ec97b…](https://bazaar.abuse.ch/sample/5abb25a32ec97bfcd604d9aac76884f2e4b5fe24981d0b4d9ee2132c39dab26e/) | RemcosRAT | RAT | **88.5** | 🔴 KRITISCH | – | – | ? |
| [153549acf79f3c…](https://bazaar.abuse.ch/sample/153549acf79f3cad8658b470e95df932d1bd7d5a5cd54251d99fec63955cf2ff/) | njrat | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [467ab622dd4abe…](https://bazaar.abuse.ch/sample/467ab622dd4abe7643168444dd5830c89b5391894763bfd42dde35f94e0c7844/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [35ab23f8b3d6e0…](https://bazaar.abuse.ch/sample/35ab23f8b3d6e095ba26a88956ec63f785dde7ae58417d47d735f630990e2e1d/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [c87ce92ddaf051…](https://bazaar.abuse.ch/sample/c87ce92ddaf0515bb01f40f838d8e3f20920a2f6d1f2063841f2533b2ec68401/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6537/8055 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6537/8055 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6233/8055 |
| 6 | Kaspersky | 75.6% | 6085/8054 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5739/8051 |
| 9 | Rising | 68.5% | 5520/8055 |
| 10 | Varist | 66.1% | 5320/8050 |
| 11 | Tencent | 65.2% | 5102/7829 |
| 12 | Avast | 65.2% | 5252/8051 |
| 13 | AVG | 65.2% | 5252/8050 |
| 14 | McAfeeD | 61.5% | 4952/8047 |
| 15 | huorong | 60.9% | 4904/8047 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 71 | 70.3% |
| 🪟 Windows | 16 | 15.8% |
| ❓ Unbekannt | 8 | 7.9% |
| 📦 Archiv | 4 | 4.0% |
| 🌐 Web | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 99 | 98.0% |
| Exploit / N-Day | 1 | 1.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 69 | 68.3% |
| 2 | 🇭🇺 HU | 8 | 7.9% |
| 3 | 🇺🇸 US | 5 | 5.0% |
| 4 | 🇳🇱 NL | 5 | 5.0% |
| 5 | 🇪🇸 ES | 5 | 5.0% |
| 6 | 🇫🇷 FR | 4 | 4.0% |
| 7 | 🇮🇳 IN | 2 | 2.0% |
| 8 | 🇸🇬 SG | 1 | 1.0% |
| 9 | 🌐 EG | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 65 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 58 |
| Lateral Movement | 58 |
| Command and Control | 7 |
| Collection | 6 |
| Execution | 1 |

<details><summary>df3469af6b6fd6e425be… – njrat | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>56e048a1f708bde497b3… – njrat | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>7008be43b4d644f1a54f… – AsyncRAT | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>c221e2da575ced729ea0… – njrat | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9d60609c956309cbbbfe…](https://bazaar.abuse.ch/sample/9d60609c956309cbbbfe791f654afe91476302871dbbdaa274cbfef42b8197b9/)

- **Familie:** Mirai
- **Erkannt von:** 23 von 74 Engines (31.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (23/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.11305` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [13a193a62d93811a87ad…](https://bazaar.abuse.ch/sample/13a193a62d93811a87ad4e521e0f1f7f875978e73f796319b5580ca2445e5769/)

- **Familie:** Prometei
- **Erkannt von:** 29 von 74 Engines (39.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (29/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39502263` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC1B7` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.39502263` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Mirai.39502263 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Mirai.39502263` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| Lionic | `Trojan.ELF.Prometei.4!c` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39502263` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39502263` |
| huorong | `Trojan/Prometei.c` |

### [23ae4c5d6d990929920e…](https://bazaar.abuse.ch/sample/23ae4c5d6d990929920e8c6187b56dc1561a95120ca61f572b1c96908f2ca5ce/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 74 Engines (33.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLQ [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.11305` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Kingsoft | `Linux.Backdoor.Gafgyt.go` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wgtra` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [8931f899bf04208d1853…](https://bazaar.abuse.ch/sample/8931f899bf04208d18536db7733ba87273907f74546d80ba3862f83f1f717b9d/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** njrat
- **Erkannt von:** 55 von 74 Engines (74.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (55/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Alibaba | `Backdoor:MSIL/Bladabindi.1adecf58` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.C33D8CB8` |
| CAT-QuickHeal | `Backdoor.Bladabindi` |
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
| GData | `MSIL.Backdoor.Bladabindi.HIT342` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Bladabindi.l!c` |
| Malwarebytes | `Trojan.MalPack` |
| MaxSecure | `Trojan.Malware.325019560.susgen` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!0C21066DB8E8` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Backdoor.Ratenjay!gen3` |
| Tencent | `Trojan.Msil.Bladabindi.16009413` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!0C21066DB8E8` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101KE26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/Bladabindi.HK.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |


## Top Tags

- **elf** (65×)
- **Mirai** (58×)
- **Torii** (56×)
- **exe** (11×)
- **Prometei** (6×)
- **sh** (5×)
- **banker** (5×)
- **BR** (5×)
- **Delphi** (5×)
- **FluxBanker** (5×)
- **FluxEngine** (5×)
- **njrat** (4×)
- **RAT** (4×)
- **boatnet** (4×)
- **ddos** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +22 (36→58)
- ↑ **unbekannt** +2 (26→28)
- ↑ **Prometei** +2 (4→6)
- ↑ **njrat** +4 (1→5)
- neu: **WannaCry** (1)
- ↓ **AsyncRAT** -2 (3→1)
- ↓ **RemcosRAT** -4 (5→1)
- neu: **EpsilonStealer** (1)
- weg: **AgentTesla** (war 4)
- weg: **Formbook** (war 2)
- weg: **MassLogger** (war 2)
- weg: **WARDENStealer** (war 4)
- weg: **Snowlight** (war 3)
- weg: **ConnectWise** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +21 (37→58)
- ↑ **unbekannt** +4 (24→28)
- ↑ **Prometei** +4 (2→6)
- ↑ **njrat** +4 (1→5)
- neu: **WannaCry** (1)
- ↓ **RemcosRAT** -2 (3→1)
- neu: **EpsilonStealer** (1)
- weg: **SalatStealer** (war 2)
- weg: **WARDENStealer** (war 6)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.088 MB |
| σ Dateigröße | 13.092 MB |
| Ø Risiko-Score | 72.5/100 |
| Ø Klassifikations-Konfidenz | 78.6% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 65/101 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 36 |
| Unbekannte Familien | 10 (9.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:18 | [de9463389f12…](https://bazaar.abuse.ch/sample/de9463389f124999353f4b1f14cbc9f41a22b1ee4395a771a14fe84268c02504/) | `elf` | unbekannt | 43.1 | – | – | 🇺🇸US |
| 12:15 | [2d5fb9397c6b…](https://bazaar.abuse.ch/sample/2d5fb9397c6b3ba4ff4c083d5c756b53321ee5beb84b118ca919aa7088036812/) | `exe` | WannaCry | 97.5 | – | – | 🇺🇸US |
| 12:11 | [dc5cbf67bd04…](https://bazaar.abuse.ch/sample/dc5cbf67bd0444799954b9d65d03883680378b13e3fdccb466bc24f90bddd709/) | `vhdx` | unbekannt | 32.4 | – | – | 🌐HU |
| 12:02 | [467ab622dd4a…](https://bazaar.abuse.ch/sample/467ab622dd4abe7643168444dd5830c89b5391894763bfd42dde35f94e0c7844/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 12:02 | [35ab23f8b3d6…](https://bazaar.abuse.ch/sample/35ab23f8b3d6e095ba26a88956ec63f785dde7ae58417d47d735f630990e2e1d/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 19.11.2026 12:37 UTC*