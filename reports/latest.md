# MalwareBazaar – 20.11.2026 21:43 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **56** |
| Höchster Score | **95.8/100** – 467202adc7175932… |
| Häufigste Familie | **unbekannt** (43x) |
| Häufigster Typ | **exe** (39x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 13 Samples |
| Ø Dateigröße | 8.76 MB (σ=22.76) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 39 | 38.6%  ███████ |
| `elf` | 23 | 22.8%  ████ |
| `ps1` | 7 | 6.9%  █ |
| `js` | 5 | 5.0%   |
| `vbs` | 5 | 5.0%   |
| `apk` | 5 | 5.0%   |
| `vhdx` | 4 | 4.0%   |
| `sh` | 4 | 4.0%   |
| `bat` | 3 | 3.0%   |
| `dll` | 2 | 2.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 43 | 42.6% |
| 2 | WARDENStealer | 15 | 14.9% |
| 3 | Mirai | 10 | 9.9% |
| 4 | Prometei | 7 | 6.9% |
| 5 | ValleyRAT | 4 | 4.0% |
| 6 | SalatStealer | 4 | 4.0% |
| 7 | MopsStealer | 3 | 3.0% |
| 8 | DarkCoreRAT | 2 | 2.0% |
| 9 | AMOS | 2 | 2.0% |
| 10 | StreamRAT | 2 | 2.0% |
| 11 | njrat | 2 | 2.0% |
| 12 | RustyStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 31 | 30.7% | 76% |
| Skript/Dropper | 15 | 14.9% | 35% |
| RAT | 14 | 13.9% | 81% |
| Linux-Malware | 13 | 12.9% | 45% |
| Botnet/IoT | 10 | 9.9% | 95% |
| Andere / Unbekannt | 9 | 8.9% | 20% |
| Windows-Malware | 3 | 3.0% | 35% |
| Android-Malware | 2 | 2.0% | 45% |
| Ransomware | 1 | 1.0% | 95% |
| Backdoor | 1 | 1.0% | 95% |
| Trojaner | 1 | 1.0% | 75% |
| Loader | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 56 | 55.4% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 32 | 31.7% |
| 🟢 NIEDRIG | 9 | 8.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [467202adc71759…](https://bazaar.abuse.ch/sample/467202adc717593205cdaa0bb94130e1e7a36f9209738d1d933934aa8d7ac6c9/) | WannaCry | Ransomware | **95.8** | 🔴 KRITISCH | – | – | ? |
| [6594e6dce6e8a4…](https://bazaar.abuse.ch/sample/6594e6dce6e8a408d2dfbdf8d1bb67221a75780fd773287772e027b6ab01d207/) | Gh0stRAT | Backdoor | **90.2** | 🔴 KRITISCH | – | – | ? |
| [41e3b70a30071b…](https://bazaar.abuse.ch/sample/41e3b70a30071b6077d781889a8fbf77ac16786cb5d774a04a6a7b32c857e6c5/) | AMOS | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [067508744d6916…](https://bazaar.abuse.ch/sample/067508744d6916ba0234526eb1886a0e3b7b30d81c2cbfe801d4285bce2ec5ab/) | AMOS | Infostealer | **88.7** | 🔴 KRITISCH | – | – | ? |
| [a0a69d05198a0c…](https://bazaar.abuse.ch/sample/a0a69d05198a0c7e847c6a40aec114e139e3cc67d6ed6b036ba582b73abcfd83/) | AsyncRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [ff34caae4b6922…](https://bazaar.abuse.ch/sample/ff34caae4b69226b395084458f22e41eeebd3424e1211aedfe03e4ed6e6597b1/) | DCRat | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [4bf38a6a6ea3a8…](https://bazaar.abuse.ch/sample/4bf38a6a6ea3a87433801904f45f5f3dbca571bd2149c32c1a31072771688806/) | njrat | RAT | **86.4** | 🔴 KRITISCH | – | – | ? |
| [7734569bf71867…](https://bazaar.abuse.ch/sample/7734569bf71867af4e4318e95ad28374c00bd753d89f620caa159b2233749d61/) | RustyStealer | Infostealer | **84.9** | 🔴 KRITISCH | 6.8% | ⚠️ KAUM ERKANNT | ✗ |
| [0894eec4819f1a…](https://bazaar.abuse.ch/sample/0894eec4819f1ac49b99f594b38a6d8554c65ce5860aa30bb2ce9ba22aff8f62/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [c58cec9301826c…](https://bazaar.abuse.ch/sample/c58cec9301826c2757e01e9a8511eed6e8cca1a7e0c5a79fce888b15bba2a08c/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6551/8074 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6551/8074 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6249/8074 |
| 6 | Kaspersky | 75.6% | 6102/8073 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5756/8070 |
| 9 | Rising | 68.5% | 5534/8074 |
| 10 | Varist | 66.1% | 5336/8069 |
| 11 | Tencent | 65.2% | 5115/7848 |
| 12 | Avast | 65.2% | 5264/8070 |
| 13 | AVG | 65.2% | 5264/8069 |
| 14 | McAfeeD | 61.6% | 4965/8066 |
| 15 | huorong | 61.0% | 4917/8066 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 55 | 54.5% |
| 🐧 Linux | 29 | 28.7% |
| ❓ Unbekannt | 9 | 8.9% |
| 🤖 Android | 5 | 5.0% |
| 📦 Archiv | 2 | 2.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 85 | 84.2% |
| Drive-By / Exploit-Kit | 5 | 5.0% |
| APK-Sideloading | 5 | 5.0% |
| MaaS-Loader | 4 | 4.0% |
| Exploit / N-Day | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 25 | 24.8% |
| 2 | 🇺🇸 US | 20 | 19.8% |
| 3 | 🌐 CL | 14 | 13.9% |
| 4 | 🇭🇺 HU | 13 | 12.9% |
| 5 | 🇳🇱 NL | 7 | 6.9% |
| 6 | 🇫🇷 FR | 7 | 6.9% |
| 7 | 🇬🇧 GB | 6 | 5.9% |
| 8 | 🇨🇭 CH | 3 | 3.0% |
| 9 | 🇨🇦 CA | 2 | 2.0% |
| 10 | 🇺🇦 UA | 2 | 2.0% |
| 11 | 🇦🇹 AT | 1 | 1.0% |
| 12 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 13 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 10 |
| Lateral Movement | 10 |
| Command and Control | 3 |
| Collection | 2 |
| Execution | 1 |

<details><summary>a0a69d05198a0c7e847c… – AsyncRAT | 🔴 KRITISCH 87.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [37ebfe7d7e0460137b61…](https://bazaar.abuse.ch/sample/37ebfe7d7e0460137b61dad87045e0237b623eee12dc45d97fc79b6a4843deda/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 1 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ? (nicht in diesem VT-Scan)

### [7734569bf71867af4e43…](https://bazaar.abuse.ch/sample/7734569bf71867af4e4318e95ad28374c00bd753d89f620caa159b2233749d61/)

- **Familie:** RustyStealer
- **Erkannt von:** 5 von 74 Engines (6.8%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** W32.Malware.C47C95ED
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Bkav | `W32.Malware.C47C95ED` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Elastic | `malicious (high confidence)` |
| Gridinsoft | `Trojan.Heur!.00002033` |
| SentinelOne | `Static AI - Suspicious PE` |

### [dcbb0f20d29ecc90db8c…](https://bazaar.abuse.ch/sample/dcbb0f20d29ecc90db8c50ae5ee8d24a8faca5471725138786662aa9d2beecfd/)

- **Familie:** WARDENStealer
- **Erkannt von:** 24 von 74 Engines (32.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Pws]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Pws]` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R801029` |
| Avast | `MalwareX-gen [Pws]` |
| Bkav | `W32.Malware.5176E4AE` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/Injector.AOW!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Wacatac` |
| Kaspersky | `VHO:Trojan.Win32.Agent.gen` |
| Lionic | `Trojan.Win32.WARDENStealer.4!c` |
| Malwarebytes | `Trojan.Injector.RND.Generic` |
| McAfeeD | `Trojan:Win/RavenStealer.NE` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.86 (RDML:ltWDnnDb06uRNPZ2lyfZdA)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Shellcoderunner.16009525` |
| TrellixENS | `Artemis!0C5314D7D35A` |
| Varist | `W64/Agent.NRC.gen!Eldorado` |
| huorong | `Trojan/W64.Agent.dl!crit` |

### [a2ac9b950cdefd398bc8…](https://bazaar.abuse.ch/sample/a2ac9b950cdefd398bc8f8d00c5e5b113ccd1cb0bc0cac5060776d70142766d5/)

- **Familie:** SalatStealer
- **Erkannt von:** 46 von 74 Engines (62.2%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Stealer.1833
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.Stealer.1833`

**Erkennende Engines (46/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Stealer.1833` |
| AhnLab-V3 | `Trojan/Win.WallStealer.R803269` |
| Alibaba | `TrojanPSW:Win64/Coins.1d3ddde8` |
| Antiy-AVL | `Trojan[PSW]/Win64.Coins` |
| Arcabit | `Trojan.Stealer.D729` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.Stealer.1833` |
| Bkav | `W32.Malware.8253F21E` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Backdoor.LucidRook-10059729-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Agent.CJZ trojan` |
| Elastic | `Windows.Exploit.Generic` |
| Emsisoft | `Trojan.Stealer.1833 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/MALD2.22CF!tr` |
| GData | `Trojan.Stealer.1833` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win64.Agent.sa` |
| Ikarus | `Trojan.Win64.Agent` |
| K7AntiVirus | `Password-Stealer ( 005ce2d41 )` |
| K7GW | `Password-Stealer ( 005ce2d41 )` |
| Kaspersky | `HEUR:Trojan-PSW.Win64.Coins.pef` |
| Lionic | `Trojan.Win32.Stealer.12!c` |
| Malwarebytes | `Spyware.Stealer` |
| McAfeeD | `ti!A2AC9B950CDE` |
| MicroWorld-eScan | `Trojan.Stealer.1833` |
| Microsoft 🛡️ | `PWS:Win64/WallStealer.CI!MTB` |
| Paloalto | `generic.ml` |
| Rising | `Backdoor.Agent!8.C5D (TFE:5:uUuztGE45cU)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win64.Dropper.vh` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `backdoor.win64.agentcjz.16008246` |
| Trapmine | `suspicious.low.ml.score` |
| TrellixENS | `Artemis!C81A0642C075` |
| TrendMicro-HouseCall | `Trojan.Win64.WALLSTEALER.USBLKF26` |
| VIPRE | `Trojan.Stealer.1833` |
| Varist | `W64/Agent.NQZ.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Stealer.6495744.L` |
| alibabacloud | `Trojan[stealer]:Win/WallStealer.CL8PHU` |
| huorong | `TrojanSpy/Stealer.gg` |

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

- **exe** (37×)
- **elf** (23×)
- **WARDENStealer** (17×)
- **stealer** (10×)
- **Warden** (10×)
- **Mirai** (10×)
- **SilverFox** (7×)
- **ValleyRAT** (7×)
- **ps1** (7×)
- **Prometei** (7×)
- **upx-dec** (6×)
- **upx** (6×)
- **js** (5×)
- **vbs** (5×)
- **apk** (5×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +21 (22→43)
- ↑ **WARDENStealer** +9 (6→15)
- ↓ **Mirai** -36 (46→10)
- ↑ **Prometei** +2 (5→7)
- neu: **ValleyRAT** (4)
- ↓ **SalatStealer** -1 (5→4)
- neu: **MopsStealer** (3)
- neu: **DarkCoreRAT** (2)
- neu: **AMOS** (2)
- neu: **StreamRAT** (2)
- weg: **AgentTesla** (war 2)
- weg: **VShell** (war 2)
- weg: **RemcosRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +20 (23→43)
- ↑ **WARDENStealer** +10 (5→15)
- ↓ **Mirai** -30 (40→10)
- ↑ **Prometei** +4 (3→7)
- neu: **ValleyRAT** (4)
- ↑ **SalatStealer** +2 (2→4)
- neu: **MopsStealer** (3)
- neu: **DarkCoreRAT** (2)
- neu: **AMOS** (2)
- neu: **StreamRAT** (2)
- weg: **RemcosRAT** (war 3)
- weg: **AgentTesla** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 8.756 MB |
| σ Dateigröße | 22.764 MB |
| Ø Risiko-Score | 62.7/100 |
| Ø Klassifikations-Konfidenz | 62.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 13/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 83 |
| Unbekannte Familien | 9 (8.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:39 | [37ebfe7d7e04…](https://bazaar.abuse.ch/sample/37ebfe7d7e0460137b61dad87045e0237b623eee12dc45d97fc79b6a4843deda/) | `exe` | unbekannt | 55.9 | 0.0% | ⚠️ KAUM ERKANNT | 🇳🇱NL |
| 21:38 | [4bbc94a5ef57…](https://bazaar.abuse.ch/sample/4bbc94a5ef57d94237328c15c42d321a0e74ad46097c0c591f7c3364d4b70eca/) | `exe` | unbekannt | 82.2 | – | – | 🇺🇸US |
| 21:38 | [3d1f0e2c374d…](https://bazaar.abuse.ch/sample/3d1f0e2c374d056c9b10ed144b2b4a340ca6223e09648f2e07176cd8074eca58/) | `exe` | unbekannt | 82.2 | – | – | 🇺🇸US |
| 21:32 | [e16dd747d803…](https://bazaar.abuse.ch/sample/e16dd747d80343519a83d205191c9cb7d7169fb21453bb566981c91efd1d78ed/) | `js` | unbekannt | 38.9 | – | – | 🌐HU |
| 21:22 | [e367af8583ed…](https://bazaar.abuse.ch/sample/e367af8583edd14eb29e66d1ba2aa5f224b9538f21d2a5f38cc146b250816f21/) | `js` | unbekannt | 38.8 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 20.11.2026 21:43 UTC*