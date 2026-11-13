# MalwareBazaar – 13.11.2026 11:58 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **57** |
| Höchster Score | **95.6/100** – 533e67aa31d63a0b… |
| Häufigste Familie | **unbekannt** (35x) |
| Häufigster Typ | **elf** (34x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 39 Samples |
| Ø Dateigröße | 4.79 MB (σ=11.76) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 34 | 33.7%  ██████ |
| `exe` | 25 | 24.8%  ████ |
| `msi` | 11 | 10.9%  ██ |
| `vbs` | 10 | 9.9%  █ |
| `ps1` | 7 | 6.9%  █ |
| `zip` | 4 | 4.0%   |
| `sh` | 4 | 4.0%   |
| `js` | 2 | 2.0%   |
| `macho` | 1 | 1.0%   |
| `apk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 35 | 34.7% |
| 2 | Mirai | 27 | 26.7% |
| 3 | GuLoader | 8 | 7.9% |
| 4 | RevStealer | 7 | 6.9% |
| 5 | AgentTesla | 4 | 4.0% |
| 6 | WARDENStealer | 3 | 3.0% |
| 7 | Formbook | 3 | 3.0% |
| 8 | Havoc | 2 | 2.0% |
| 9 | SnappyClient | 2 | 2.0% |
| 10 | ConnectWise | 2 | 2.0% |
| 11 | IRAHook | 1 | 1.0% |
| 12 | WannaCry | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 27 | 26.7% | 95% |
| Windows-Malware | 21 | 20.8% | 35% |
| Infostealer | 16 | 15.8% | 79% |
| Loader | 9 | 8.9% | 93% |
| Linux-Malware | 7 | 6.9% | 45% |
| Skript/Dropper | 7 | 6.9% | 35% |
| Andere / Unbekannt | 6 | 5.9% | 20% |
| RAT | 5 | 5.0% | 79% |
| Android-Malware | 1 | 1.0% | 45% |
| Ransomware | 1 | 1.0% | 95% |
| Backdoor | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 57 | 56.4% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 36 | 35.6% |
| 🟢 NIEDRIG | 6 | 5.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [533e67aa31d63a…](https://bazaar.abuse.ch/sample/533e67aa31d63a0ba46ce26b18962508c13fc6a31a6e8a001ab059e5f2cf34b9/) | WannaCry | Ransomware | **95.6** | 🔴 KRITISCH | – | – | ? |
| [5814dbd3853615…](https://bazaar.abuse.ch/sample/5814dbd3853615c2434ec17c83ee53a4ad71691d0626c6b86d8f6f9e6fdb27e1/) | Gh0stRAT | Backdoor | **90.7** | 🔴 KRITISCH | – | – | ? |
| [48fd47c6778dfd…](https://bazaar.abuse.ch/sample/48fd47c6778dfd00330dd7993260528dfb17fd8bef2a58735ee4d5c1cdc4240e/) | Formbook | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [e28e8201263609…](https://bazaar.abuse.ch/sample/e28e82012636099db0c190d96663f29dab77d08ce5139d811bb65f0c102032be/) | Formbook | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [a012229ee04340…](https://bazaar.abuse.ch/sample/a012229ee0434052df93919a81c7d4b1a11851e4f7c8aded457604b1ab7db5c5/) | Formbook | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [00f0dcd03fefbc…](https://bazaar.abuse.ch/sample/00f0dcd03fefbcfe1544865b9b9ea8c199e42f752a5a37a40c296af5b922f6c8/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [ff0a67e00e9ed4…](https://bazaar.abuse.ch/sample/ff0a67e00e9ed435ae4d308dc882778806ef1eec9901a159f925703a2b384721/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [5f06679a948446…](https://bazaar.abuse.ch/sample/5f06679a94844656d74ccac5cb1137e5d121eca43a0f695c9055145e12e83f8b/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [0e767618d0a73d…](https://bazaar.abuse.ch/sample/0e767618d0a73d631d8d0fa2f627843ad4f243fea0301df8bd49d1a6057cdaf7/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [867ad6f6f10376…](https://bazaar.abuse.ch/sample/867ad6f6f103765c59cb85c180cfefc36d958fc11bf6ff3cbf49511913a180bc/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6465/7965 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6465/7965 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6159/7965 |
| 6 | Kaspersky | 75.5% | 6013/7964 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5672/7961 |
| 9 | Rising | 68.4% | 5450/7965 |
| 10 | Varist | 66.1% | 5260/7960 |
| 11 | Avast | 65.2% | 5189/7961 |
| 12 | AVG | 65.2% | 5189/7960 |
| 13 | Tencent | 65.0% | 5029/7739 |
| 14 | McAfeeD | 61.4% | 4889/7957 |
| 15 | huorong | 60.9% | 4845/7957 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 53 | 52.5% |
| 🐧 Linux | 39 | 38.6% |
| 📦 Archiv | 5 | 5.0% |
| ❓ Unbekannt | 2 | 2.0% |
| 🍎 macOS | 1 | 1.0% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 76 | 75.2% |
| Trojanisierte Software | 11 | 10.9% |
| Drive-By / Exploit-Kit | 10 | 9.9% |
| MaaS-Loader | 2 | 2.0% |
| APK-Sideloading | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 32 | 31.7% |
| 2 | 🇳🇱 NL | 17 | 16.8% |
| 3 | 🇸🇪 SE | 16 | 15.8% |
| 4 | 🇺🇸 US | 11 | 10.9% |
| 5 | 🇫🇷 FR | 11 | 10.9% |
| 6 | 🇨🇭 CH | 5 | 5.0% |
| 7 | 🇪🇸 ES | 5 | 5.0% |
| 8 | 🇭🇺 HU | 1 | 1.0% |
| 9 | 🇨🇿 CZ | 1 | 1.0% |
| 10 | 🇯🇵 JP | 1 | 1.0% |
| 11 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 39 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 27 |
| Lateral Movement | 27 |
| Defense Evasion | 8 |
| Execution | 8 |
| Collection | 4 |
| Credential Access | 3 |
| Command and Control | 1 |

<details><summary>48fd47c6778dfd00330d… – Formbook | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>e28e82012636099db0c1… – Formbook | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>a012229ee0434052df93… – Formbook | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b0ee9e2f31c63a5bb420…](https://bazaar.abuse.ch/sample/b0ee9e2f31c63a5bb42017b0babace7b82f2f34fee519c05d182a258e718ade4/)

- **Familie:** Mirai
- **Erkannt von:** 21 von 75 Engines (28.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Mirai.27
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Mirai.27`

**Erkennende Engines (21/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Mirai.27` |
| Antiy-AVL | `Trojan/Linux.Agent` |
| Arcabit | `Trojan.Linux.Mirai.27` |
| Avira | `TR/LINUX.Mirai.CRD` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Mirai.27` |
| CTX | `elf.unknown.mirai` |
| ClamAV | `Unix.Trojan.Mirai-9924065-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Fgt.6309` |
| ESET-NOD32 | `Linux/Mirai.FPV trojan` |
| Emsisoft | `Gen:Variant.Linux.Mirai.27 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CRD` |
| GData | `Gen:Variant.Linux.Mirai.27` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.bj` |
| MicroWorld-eScan | `Gen:Variant.Linux.Mirai.27` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BA!xp` |
| Rising | `Backdoor.Mirai/Linux!1.DEDC (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| VIPRE | `Gen:Variant.Linux.Mirai.27` |
| huorong | `Trojan/Linux.Mirai.l` |

### [1842f387b9ac9cba8c01…](https://bazaar.abuse.ch/sample/1842f387b9ac9cba8c01a8a7a1b73b6ae7032311c76a8da41596aae26d407037/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-BOK [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BOK [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.XE131` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-BOK [Trj]` |
| Avast-Mobile | `ELF:Mirai-CKT [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| ClamAV | `Unix.Trojan.Mirai-9441505-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.CIB trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `Linux/Mirai.CDB!tr` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| MaxSecure | `Backdoor.WIN32.130121.Linux.Mirai.cw.YR` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AU!MTB` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wan` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.dh` |

### [74b2e41106670c2d0394…](https://bazaar.abuse.ch/sample/74b2e41106670c2d0394f1dc4527abb7c6196f4d222f92464d6d99010fa7d02b/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39502263` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Mirai.D25AC1B7` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
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
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39502263` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39502263` |
| huorong | `Trojan/Prometei.c` |

### [608a2cd5f79bd2ab3acc…](https://bazaar.abuse.ch/sample/608a2cd5f79bd2ab3acc975e53c640ad849406f0d1a1f8e480531288e4d7ce33/)

- **Familie:** GuLoader
- **Erkannt von:** 8 von 75 Engines (10.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Script.GuLoader.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Script/Wacatac.B!ml`

**Erkennende Engines (8/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Ikarus | `Trojan.VBS.Agent` |
| Kingsoft | `Win32.Troj.Undef.a` |
| Lionic | `Trojan.Script.GuLoader.4!c` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Symantec | `Scr.Guloader!gen11` |
| Tencent | `Vbs.Trojan.Sagent.Mgil` |
| TrendMicro-HouseCall | `TROJ_GEN.F04IE00KD26` |
| huorong | `TrojanDropper/VBS.Agent.bf` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 62 von 75 Engines (82.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (62/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| AVG | `Win32:Evo-gen [Trj]` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avast | `Win32:Evo-gen [Trj]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
| CAT-QuickHeal | `Trojan.Injector` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Trojan.Nymeria-6895336-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.28` |
| ESET-NOD32 | `Win32/Injector.Autoit.DTL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.1TKG37Z` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `PUA:Win32/Caypnamer.A!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vtzo` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (33×)
- **Mirai** (26×)
- **exe** (24×)
- **Phantom53** (16×)
- **STRU** (16×)
- **Torii** (13×)
- **msi** (11×)
- **vbs** (10×)
- **Prometei** (8×)
- **GuLoader** (8×)
- **ps1** (7×)
- **zip** (5×)
- **TradingView** (5×)
- **youtube** (5×)
- **sh** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +10 (25→35)
- ↓ **Mirai** -21 (48→27)
- ↑ **GuLoader** +7 (1→8)
- ↑ **RevStealer** +6 (1→7)
- ↑ **AgentTesla** +3 (1→4)
- ↓ **WARDENStealer** -6 (9→3)
- ↑ **Formbook** +2 (1→3)
- neu: **Havoc** (2)
- neu: **SnappyClient** (2)
- weg: **SalatStealer** (war 3)
- weg: **CoinMiner** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +10 (25→35)
- ↓ **Mirai** -3 (30→27)
- ↑ **GuLoader** +7 (1→8)
- ↑ **RevStealer** +5 (2→7)
- ↑ **AgentTesla** +2 (2→4)
- ↓ **WARDENStealer** -1 (4→3)
- ↑ **Formbook** +2 (1→3)
- neu: **Havoc** (2)
- neu: **SnappyClient** (2)
- ↑ **ConnectWise** +1 (1→2)
- weg: **Snowlight** (war 3)
- weg: **SalatStealer** (war 6)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.793 MB |
| σ Dateigröße | 11.760 MB |
| Ø Risiko-Score | 63.7/100 |
| Ø Klassifikations-Konfidenz | 66.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 39/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 60 |
| Unbekannte Familien | 6 (5.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 11:52 | [4748571d98c6…](https://bazaar.abuse.ch/sample/4748571d98c6af34f4967a3886f73b4421239a1203f048140d3bfdaf8aa78937/) | `exe` | unbekannt | 39.0 | – | – | 🌐HU |
| 11:36 | [009099ba1036…](https://bazaar.abuse.ch/sample/009099ba10365b44bdb3ecc28dfcbed6a594ec0a0df86931620cdaac9843e611/) | `zip` | Havoc | 32.4 | – | – | 🇳🇱NL |
| 11:36 | [0dcfe51d2521…](https://bazaar.abuse.ch/sample/0dcfe51d2521e52a469f5cec6b42bc8e7e37b41df993cce7d739ff3fd248d8b1/) | `msi` | unbekannt | 38.8 | – | – | 🇳🇱NL |
| 11:36 | [9a2af4b6d978…](https://bazaar.abuse.ch/sample/9a2af4b6d9780e08c86ff35030ee1747ea11460cb1dffc868c48e7af6d626546/) | `msi` | unbekannt | 38.8 | – | – | 🇳🇱NL |
| 11:36 | [47e853092511…](https://bazaar.abuse.ch/sample/47e853092511d9663196e9b36d563a0c3e92ee734f88675c4f375ffcfa5f3db8/) | `msi` | unbekannt | 38.8 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 13.11.2026 11:58 UTC*