# MalwareBazaar – 09.11.2026 15:34 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **100** |
| Kritisch (≥75) | **51** |
| Höchster Score | **88.7/100** – 399a542f0c9ef085… |
| Häufigste Familie | **unbekannt** (29x) |
| Häufigster Typ | **js** (40x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 41 Samples |
| Ø Dateigröße | 3.03 MB (σ=5.18) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `js` | 40 | 40.0%  ████████ |
| `exe` | 18 | 18.0%  ███ |
| `vbs` | 18 | 18.0%  ███ |
| `ps1` | 5 | 5.0%  █ |
| `apk` | 4 | 4.0%   |
| `elf` | 4 | 4.0%   |
| `rar` | 3 | 3.0%   |
| `bat` | 2 | 2.0%   |
| `wsf` | 2 | 2.0%   |
| `sh` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 29 | 29.0% |
| 2 | RemcosRAT | 19 | 19.0% |
| 3 | AgentTesla | 17 | 17.0% |
| 4 | Formbook | 8 | 8.0% |
| 5 | Mirai | 6 | 6.0% |
| 6 | AsyncRAT | 3 | 3.0% |
| 7 | LxBaseRAT | 3 | 3.0% |
| 8 | njrat | 2 | 2.0% |
| 9 | GuLoader | 2 | 2.0% |
| 10 | MassLogger | 2 | 2.0% |
| 11 | XWorm | 2 | 2.0% |
| 12 | DonutLoader | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Skript/Dropper | 31 | 31.0% | 35% |
| RAT | 30 | 30.0% | 93% |
| Infostealer | 11 | 11.0% | 90% |
| Windows-Malware | 8 | 8.0% | 35% |
| Botnet/IoT | 6 | 6.0% | 95% |
| Loader | 5 | 5.0% | 89% |
| Andere / Unbekannt | 5 | 5.0% | 20% |
| Linux-Malware | 1 | 1.0% | 45% |
| Android-Malware | 1 | 1.0% | 45% |
| Cryptominer | 1 | 1.0% | 75% |
| Spyware | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 51 | 51.0% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 41 | 41.0% |
| 🟢 NIEDRIG | 5 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [399a542f0c9ef0…](https://bazaar.abuse.ch/sample/399a542f0c9ef085721361ba3cd4a49b01b3031fa77399adf7970055a62c5f39/) | RemcosRAT | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [c0c60b160af46d…](https://bazaar.abuse.ch/sample/c0c60b160af46d02e1e86e3ddc02e4b35bb3a827698eb23e62f98444af1734cc/) | RemcosRAT | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [f86620cdb7e1c2…](https://bazaar.abuse.ch/sample/f86620cdb7e1c2cd1969cf15bb6d1922ccd20d18a67b5a0d57469e1e0b976ad9/) | RemcosRAT | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [1f8f89c5cb4eb7…](https://bazaar.abuse.ch/sample/1f8f89c5cb4eb79e76d14910bb26abb22debd2e477cebd42f9351e8b2cab51ba/) | RemcosRAT | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [adeb9480ea58f6…](https://bazaar.abuse.ch/sample/adeb9480ea58f67a32f8833851cec18c6b14de83201070e3f0ea12b6c0e7e4a9/) | RemcosRAT | RAT | **88.0** | 🔴 KRITISCH | – | – | ? |
| [e37258a3586b45…](https://bazaar.abuse.ch/sample/e37258a3586b4571338cc84b84525c9a80d1ae0b1e9bbfed1182533975b37c17/) | RemcosRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [60ed02d8569d0c…](https://bazaar.abuse.ch/sample/60ed02d8569d0c17d6a7507a6525c7bc501edc04af5e0c886412b196fb9722b3/) | AsyncRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [2db602fad861e4…](https://bazaar.abuse.ch/sample/2db602fad861e4cc81edaeac2d88a0be4d2e088cc8038a5728b49ae80334c85a/) | AsyncRAT | RAT | **87.7** | 🔴 KRITISCH | – | – | ? |
| [b207bfdbcc74fe…](https://bazaar.abuse.ch/sample/b207bfdbcc74fe150c2d8ffd13ac6e3394d2d24aa5b743e4d312f033af10e35d/) | Formbook | Infostealer | **86.8** | 🔴 KRITISCH | – | – | ? |
| [f43d106ae3f661…](https://bazaar.abuse.ch/sample/f43d106ae3f661498c105b9f6a3e6ed9c1a11b7774bb6a96412e960331362c96/) | Formbook | Infostealer | **86.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6410/7906 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6410/7906 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6109/7906 |
| 6 | Kaspersky | 75.5% | 5967/7905 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5627/7902 |
| 9 | Rising | 68.4% | 5404/7906 |
| 10 | Varist | 66.1% | 5225/7901 |
| 11 | Avast | 65.2% | 5151/7902 |
| 12 | AVG | 65.2% | 5151/7901 |
| 13 | Tencent | 65.0% | 4989/7680 |
| 14 | McAfeeD | 61.4% | 4849/7898 |
| 15 | huorong | 60.9% | 4813/7898 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 44 | 44.0% |
| ❓ Unbekannt | 40 | 40.0% |
| 🤖 Android | 6 | 6.0% |
| 🐧 Linux | 6 | 6.0% |
| 📦 Archiv | 4 | 4.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 54 | 54.0% |
| Drive-By / Exploit-Kit | 42 | 42.0% |
| APK-Sideloading | 4 | 4.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇸🇪 SE | 54 | 54.0% |
| 2 | 🇩🇪 DE | 11 | 11.0% |
| 3 | 🇺🇸 US | 11 | 11.0% |
| 4 | 🇫🇷 FR | 9 | 9.0% |
| 5 | 🇮🇩 ID | 7 | 7.0% |
| 6 | 🇳🇱 NL | 4 | 4.0% |
| 7 | 🇹🇷 TR | 2 | 2.0% |
| 8 | 🇧🇷 BR | 1 | 1.0% |
| 9 | 🇯🇵 JP | 1 | 1.0% |

## MITRE ATT&CK

> 41 von 100 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 29 |
| Command and Control | 25 |
| Credential Access | 8 |
| Initial Access | 6 |
| Lateral Movement | 6 |
| Execution | 5 |
| Defense Evasion | 2 |
| Exfiltration | 1 |

<details><summary>399a542f0c9ef0857213… – RemcosRAT | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>c0c60b160af46d02e1e8… – RemcosRAT | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>f86620cdb7e1c2cd1969… – RemcosRAT | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>1f8f89c5cb4eb79e76d1… – RemcosRAT | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>adeb9480ea58f67a32f8… – RemcosRAT | 🔴 KRITISCH 88.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5011738286343d8671b7…](https://bazaar.abuse.ch/sample/5011738286343d8671b7910128727b0c61a8606332f13556d7def4f0f3cb6586/)

- **Familie:** Win64:MalwareX-gen [Drp]
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Drp]` |
| Alibaba | `Exploit:Win32/ChecksumController.38e18460` |
| Avast | `Win64:MalwareX-gen [Drp]` |
| Avira | `DR/W64.MalwareX` |
| Bkav | `W32.Malware.ED8F15E7` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Generik.FFKQGUI trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Dropper.DR/W64.MalwareX` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Win64.Trojan.Agent.MGZF9R` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| Kaspersky | `Exploit.Win32.ChecksumController.amk` |
| Kingsoft | `Win32.Exploit.ChecksumCont.amk` |
| McAfeeD | `ti!501173828634` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `suspicious.low.ml.score` |
| Varist | `W64/ABRisk.RJMP-3645` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 53 von 75 Engines (70.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (53/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| AVG | `Win32:Evo-gen [Trj]` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avast | `Win32:Evo-gen [Trj]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
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
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Trojan-AitInject.ak` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| Zillya | `Trojan.Injector.Win32.2062480` |
| ZoneAlarm | `Mal/AuItInj-A` |
| tehtris | `Generic.Malware` |

### [46ccaa5ac997b0421155…](https://bazaar.abuse.ch/sample/46ccaa5ac997b0421155051a6a73b9d0f484ab4b5fdbdc85a487a2d6df67656d/)

- **Familie:** Troj/PS-YA
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Troj/PS-YA
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Kaspersky | `UDS:Trojan.PowerShell.Alien.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Skyhigh | `BehavesLike.PS.Dropper.tg` |
| Sophos | `Troj/PS-YA` |
| ZoneAlarm | `Troj/PS-YA` |
| huorong | `TrojanDownloader/PS.Netloader.mj` |

### [a2cf0d13d2c68c9a1b0c…](https://bazaar.abuse.ch/sample/a2cf0d13d2c68c9a1b0c84123c2979c2c9362925c647d1b4e64fd33419858e85/)

- **Familie:** njrat
- **Erkannt von:** 54 von 75 Engines (72.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (54/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Alibaba | `Backdoor:MSIL/Bladabindi.86edc6d5` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.FF03C390` |
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
| Fortinet | `MSIL/Bladabindi.AZ!tr` |
| GData | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Bladabindi.4!c` |
| Malwarebytes | `Trojan.MalPack` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| NANO-Antivirus | `Trojan.Win32.KeyLogger.lhiedu` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!DF0E115D4140` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.14bb6577` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!DF0E115D4140` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101K626ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/ABApplication.DXXF-0386` |
| ViRobot | `Trojan.Win.Z.Bladabindi.24576.G` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |

### [1fdfba1127c33717cc26…](https://bazaar.abuse.ch/sample/1fdfba1127c33717cc26b749870bdace0567c15c14108bfd7080539199ff25cb/)

- **Familie:** RemcosRAT
- **Erkannt von:** 9 von 75 Engines (12.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** XSNet.Heur!gen12
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (9/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `PowerShell/CloudEye.QE trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `HEUR:Trojan.VBS.SAgent.gen` |
| McAfeeD | `ti!1FDFBA1127C3` |
| Microsoft 🛡️ | `Trojan:Win32/Malgent` |
| Symantec | `XSNet.Heur!gen12` |
| Tencent | `Vbs.Trojan.Sagent.Anhl` |
| Varist | `VBS/Agent.DDI!Eldorado` |


## Top Tags

- **js** (40×)
- **exe** (22×)
- **RemcosRAT** (18×)
- **vbs** (18×)
- **AgentTesla** (17×)
- **Formbook** (8×)
- **RAT** (7×)
- **Mirai** (6×)
- **ps1** (5×)
- **apk** (4×)
- **elf** (4×)
- **signed** (3×)
- **rar** (3×)
- **AsyncRAT** (3×)
- **cowrie** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +4 (25→29)
- neu: **RemcosRAT** (19)
- ↑ **AgentTesla** +16 (1→17)
- ↑ **Formbook** +7 (1→8)
- ↓ **Mirai** -28 (34→6)
- ↑ **AsyncRAT** +2 (1→3)
- neu: **LxBaseRAT** (3)
- neu: **njrat** (2)
- neu: **GuLoader** (2)
- neu: **MassLogger** (2)
- weg: **WARDENStealer** (war 4)
- weg: **SilentNet** (war 2)
- weg: **Snowlight** (war 10)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -4 (33→29)
- ↑ **RemcosRAT** +17 (2→19)
- ↑ **AgentTesla** +14 (3→17)
- ↑ **Formbook** +5 (3→8)
- ↓ **Mirai** -15 (21→6)
- ↑ **AsyncRAT** +2 (1→3)
- neu: **LxBaseRAT** (3)
- neu: **njrat** (2)
- neu: **GuLoader** (2)
- neu: **MassLogger** (2)
- weg: **WARDENStealer** (war 3)
- weg: **VShell** (war 2)
- weg: **Snowlight** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.029 MB |
| σ Dateigröße | 5.184 MB |
| Ø Risiko-Score | 61.6/100 |
| Ø Klassifikations-Konfidenz | 65.0% |
| Samples mit VT | 5/100 |
| Samples mit MITRE | 41/100 |
| Eindeutige Familien | 17 |
| Eindeutige Tags | 49 |
| Unbekannte Familien | 5 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 15:07 | [a1386137e6fb…](https://bazaar.abuse.ch/sample/a1386137e6fb4c86460e94e17ee0d201eb893739c4c454603030368130638880/) | `exe` | unbekannt | 38.7 | – | – | 🇫🇷FR |
| 15:07 | [0aaa2f815569…](https://bazaar.abuse.ch/sample/0aaa2f8155699d1f132dad8dc5b0e031e5326ba516f28a1c9eb4c0dbdb8fd6f9/) | `exe` | unbekannt | 38.7 | – | – | 🇫🇷FR |
| 15:02 | [501173828634…](https://bazaar.abuse.ch/sample/5011738286343d8671b7910128727b0c61a8606332f13556d7def4f0f3cb6586/) | `exe` | Win64:MalwareX-gen [Dr | 47.5 | 32.0% | 🟡 SCHWACH ERKANNT | 🇫🇷FR |
| 15:01 | [80a627d121d4…](https://bazaar.abuse.ch/sample/80a627d121d4ccb7efb357185ad21cefc987b8fea505ce7108688f09cd917b7e/) | `exe` | unbekannt | 38.6 | – | – | 🇫🇷FR |
| 15:00 | [28c3e715b66c…](https://bazaar.abuse.ch/sample/28c3e715b66c276443696e05cf6e5c89e585682d8605dd82b11a75a15d23d7b2/) | `exe` | unbekannt | 38.6 | – | – | 🇫🇷FR |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 09.11.2026 15:34 UTC*