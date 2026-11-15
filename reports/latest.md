# MalwareBazaar – 15.11.2026 23:51 UTC

Dieser Run hat **44 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **45** |
| Kritisch (≥75) | **30** |
| Höchster Score | **87.9/100** – 00949b0da414ee5d… |
| Häufigste Familie | **Mirai** (13x) |
| Häufigster Typ | **elf** (18x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 17 Samples |
| Ø Dateigröße | 1.86 MB (σ=4.09) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 18 | 40.0%  ████████ |
| `exe` | 15 | 33.3%  ██████ |
| `sh` | 3 | 6.7%  █ |
| `apk` | 3 | 6.7%  █ |
| `ps1` | 2 | 4.4%   |
| `bat` | 2 | 4.4%   |
| `vbs` | 1 | 2.2%   |
| `jar` | 1 | 2.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 13 | 28.9% |
| 2 | unbekannt | 10 | 22.2% |
| 3 | WARDENStealer | 10 | 22.2% |
| 4 | Prometei | 3 | 6.7% |
| 5 | AsyncRAT | 2 | 4.4% |
| 6 | Gafgyt | 1 | 2.2% |
| 7 | GuLoader | 1 | 2.2% |
| 8 | AgentTesla | 1 | 2.2% |
| 9 | Arechclient2 | 1 | 2.2% |
| 10 | SilentNet | 1 | 2.2% |
| 11 | ShellcodeRunner | 1 | 2.2% |
| 12 | RemcosRAT | 1 | 2.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 14 | 31.1% | 95% |
| Infostealer | 12 | 26.7% | 75% |
| Linux-Malware | 5 | 11.1% | 45% |
| Andere / Unbekannt | 3 | 6.7% | 20% |
| Trojaner | 3 | 6.7% | 65% |
| RAT | 3 | 6.7% | 95% |
| Windows-Malware | 2 | 4.4% | 35% |
| Android-Malware | 2 | 4.4% | 45% |
| Loader | 1 | 2.2% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 30 | 66.7% |
| 🟠 HOCH | 3 | 6.7% |
| 🟡 MITTEL | 9 | 20.0% |
| 🟢 NIEDRIG | 3 | 6.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [00949b0da414ee…](https://bazaar.abuse.ch/sample/00949b0da414ee5d04c73db5970e825e3b53ac9edfc5f56a176409fb1141101d/) | AsyncRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [40f63e8404a80c…](https://bazaar.abuse.ch/sample/40f63e8404a80c35ca6cc110260c86fd0669947e81df59a7a70953cb53c7a26f/) | AsyncRAT | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [c3f64d23ea0371…](https://bazaar.abuse.ch/sample/c3f64d23ea037172fdb1269b1d2b89c52facde6140d7eb15f5e4ad8a962ab0ad/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [2ef0ef302b2331…](https://bazaar.abuse.ch/sample/2ef0ef302b23311fdb43a26c21a3bfc562e47bb999ca459d4b6c6fddb34e6fb8/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [57392f84cdbeb0…](https://bazaar.abuse.ch/sample/57392f84cdbeb0cb45687f77f8e292a7b9b92a4f9e64d8aa90582e54b0a3d15c/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [a07605f271a730…](https://bazaar.abuse.ch/sample/a07605f271a730f2a1a736b1e471b9a6e8efbdef3f119f50efa5d319d83edd95/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [c4fb91392c9add…](https://bazaar.abuse.ch/sample/c4fb91392c9addcf0336d6fe32b773f1c01fc18b2b69097c7f5e9509dee3e384/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [10eb259b4fdd9b…](https://bazaar.abuse.ch/sample/10eb259b4fdd9b455c48c2c67d8c07466f6b83e8bb7a8ce83c35d1d834497a45/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [b3d162cff7c391…](https://bazaar.abuse.ch/sample/b3d162cff7c3915acdf18fda0edccb9b8c04fc7ce8b6351aab515199e86edc50/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [6ba0ddb2dc99ab…](https://bazaar.abuse.ch/sample/6ba0ddb2dc99ab116cb84d7b2a52446f9c0b5f9a69ee8383ccb8899206b3b50d/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6501/8009 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6501/8009 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6193/8009 |
| 6 | Kaspersky | 75.5% | 6046/8008 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5704/8005 |
| 9 | Rising | 68.4% | 5482/8009 |
| 10 | Varist | 66.1% | 5287/8004 |
| 11 | Avast | 65.2% | 5216/8005 |
| 12 | AVG | 65.2% | 5216/8004 |
| 13 | Tencent | 65.1% | 5063/7783 |
| 14 | McAfeeD | 61.5% | 4918/8001 |
| 15 | huorong | 60.8% | 4867/8001 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 21 | 46.7% |
| 🪟 Windows | 20 | 44.4% |
| 🤖 Android | 3 | 6.7% |
| ❓ Unbekannt | 1 | 2.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 41 | 91.1% |
| APK-Sideloading | 3 | 6.7% |
| Drive-By / Exploit-Kit | 1 | 2.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇳🇱 NL | 20 | 44.4% |
| 2 | 🇺🇸 US | 9 | 20.0% |
| 3 | 🇩🇪 DE | 7 | 15.6% |
| 4 | 🇫🇷 FR | 4 | 8.9% |
| 5 | 🇨🇳 CN | 2 | 4.4% |
| 6 | 🇨🇭 CH | 1 | 2.2% |
| 7 | 🇵🇱 PL | 1 | 2.2% |
| 8 | 🌐 Unbekannt | 1 | 2.2% |

## MITRE ATT&CK

> 17 von 45 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 13 |
| Lateral Movement | 13 |
| Execution | 3 |
| Command and Control | 3 |
| Defense Evasion | 1 |
| Collection | 1 |

<details><summary>00949b0da414ee5d04c7… – AsyncRAT | 🔴 KRITISCH 87.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>40f63e8404a80c35ca6c… – AsyncRAT | 🔴 KRITISCH 87.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>c3f64d23ea037172fdb1… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>2ef0ef302b23311fdb43… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>57392f84cdbeb0cb4568… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [1b063de46a6665198358…](https://bazaar.abuse.ch/sample/1b063de46a6665198358d6844785f4bd13b0014715af7dccabdc8cdcc4fd5c68/)

- **Familie:** Prometei
- **Erkannt von:** 34 von 74 Engines (46.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Prometei.D
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Prometei.D`

**Erkennende Engines (34/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Prometei.D` |
| AVG | `ELF:Prometei-A [Trj]` |
| AhnLab-V3 | `Trojan/Linux.Prometei.SE260` |
| Antiy-AVL | `Trojan/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Prometei.D` |
| Avast | `ELF:Prometei-A [Trj]` |
| Avira | `EXP/ELF.Agent.L.22` |
| BitDefender 🛡️ | `Trojan.Linux.Prometei.D` |
| CTX | `elf.trojan.prometei` |
| ClamAV | `Unix.Trojan.Prometei-9992782-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Siggen.4460` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Emsisoft | `Trojan.Linux.Prometei.D (B)` |
| F-Secure | `Exploit.EXP/ELF.Agent.L.22` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Prometei.D` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Jiangmin | `Backdoor.Linux.hmdw` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| MicroWorld-eScan | `Trojan.Linux.Prometei.D` |
| Microsoft 🛡️ | `Trojan:Linux/Prometei!MTB` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Sophos | `Linux/Bdoor-BIT` |
| Tencent | `Backdoor.Linux.Prometei.ga` |
| VBA32 | `Trojan.Linux.Mirai` |
| VIPRE | `Trojan.Linux.Prometei.D` |
| Varist | `E64/PrometeiS.B` |
| Zillya | `Trojan.Prometei.Linux.26` |
| ZoneAlarm | `Linux/Bdoor-BIT` |
| alibabacloud | `Miner:Win/Prometei.35eca64e` |
| huorong | `Trojan/Prometei.f` |

### [0041f825e43586991734…](https://bazaar.abuse.ch/sample/0041f825e435869917347a9fd0fb65f11d557649537ee6b6ca31337d6404aa04/)

- **Familie:** AgentTesla
- **Erkannt von:** 6 von 74 Engines (8.1%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan.Script.AgentTesla.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Kaspersky | `HEUR:Trojan.PowerShell.Agent.gen` |
| Lionic | `Trojan.Script.AgentTesla.4!c` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Skyhigh | `BehavesLike.PS.Dropper.dg` |
| Symantec | `Scr.Malscript!gen48` |
| huorong | `TrojanDownloader/PS.Netloader.mj` |

### [4366f6b4036b6e4dbb83…](https://bazaar.abuse.ch/sample/4366f6b4036b6e4dbb8317c29b3cca895f8a1e36016f11539b63d7336b26da9f/)

- **Familie:** Mirai
- **Erkannt von:** 28 von 74 Engines (37.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39502263
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.39502263`

**Erkennende Engines (28/74):**

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
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39502263` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Mirai.39502263` |
| huorong | `Trojan/Prometei.c` |

### [89b862c5201d8849b6df…](https://bazaar.abuse.ch/sample/89b862c5201d8849b6df16beff7a402382dde4d966954166909521d89064d794/)

- **Familie:** ShellcodeRunner
- **Erkannt von:** 27 von 74 Engines (36.5%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.ShellcodeRunner.143
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.ShellcodeRunner.143`

**Erkennende Engines (27/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.ShellcodeRunner.143` |
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R797565` |
| Arcabit | `Trojan.ShellcodeRunner.143` |
| BitDefender 🛡️ | `Gen:Variant.ShellcodeRunner.143` |
| Bkav | `W32.Malware.483BBC36` |
| CTX | `dll.unknown.shellcoderunner` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/ShellcodeRunner.CQR trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.ShellcodeRunner.143 (B)` |
| Fortinet | `W64/MALD2.DEDF!tr` |
| GData | `Gen:Variant.ShellcodeRunner.143` |
| K7AntiVirus | `Trojan ( 006d9bf01 )` |
| K7GW | `Trojan ( 006d9bf01 )` |
| Kingsoft | `malware.kb.a.796` |
| McAfeeD | `ti!89B862C5201D` |
| MicroWorld-eScan | `Gen:Variant.ShellcodeRunner.143` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Malware.Undefined!8.C (TFE:6:C9WtrIs9t1G)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `ML/PE-A` |
| Tencent | `OB:Trojan.Win64.Shellcoderunner.16009525` |
| VIPRE | `Gen:Variant.ShellcodeRunner.143` |

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

- **Mirai** (13×)
- **exe** (12×)
- **Prometei** (9×)
- **stealer** (8×)
- **warden** (7×)
- **wardenstealer** (7×)
- **elf** (6×)
- **Torii** (6×)
- **Gafgyt** (5×)
- **WARDENStealer** (5×)
- **upx-dec** (4×)
- **upx** (4×)
- **signed** (3×)
- **divinex** (2×)
- **ps1** (2×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -47 (60→13)
- ↓ **unbekannt** -9 (19→10)
- ↑ **WARDENStealer** +6 (4→10)
- ↑ **Prometei** +2 (1→3)
- neu: **AsyncRAT** (2)
- neu: **Gafgyt** (1)
- neu: **GuLoader** (1)
- neu: **AgentTesla** (1)
- neu: **Arechclient2** (1)
- ↓ **SilentNet** -1 (2→1)
- weg: **RevStealer** (war 2)
- weg: **ConnectWise** (war 2)
- weg: **SalatStealer** (war 3)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -25 (38→13)
- ↓ **unbekannt** -16 (26→10)
- ↑ **WARDENStealer** +6 (4→10)
- neu: **Prometei** (3)
- neu: **AsyncRAT** (2)
- neu: **Gafgyt** (1)
- ↓ **AgentTesla** -1 (2→1)
- neu: **Arechclient2** (1)
- weg: **Snowlight** (war 2)
- weg: **SalatStealer** (war 6)
- weg: **RevStealer** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.857 MB |
| σ Dateigröße | 4.088 MB |
| Ø Risiko-Score | 69.9/100 |
| Ø Klassifikations-Konfidenz | 72.2% |
| Samples mit VT | 5/45 |
| Samples mit MITRE | 17/45 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 30 |
| Unbekannte Familien | 3 (6.7%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:47 | [c3f64d23ea03…](https://bazaar.abuse.ch/sample/c3f64d23ea037172fdb1269b1d2b89c52facde6140d7eb15f5e4ad8a962ab0ad/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 23:44 | [2ef0ef302b23…](https://bazaar.abuse.ch/sample/2ef0ef302b23311fdb43a26c21a3bfc562e47bb999ca459d4b6c6fddb34e6fb8/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 23:33 | [57392f84cdbe…](https://bazaar.abuse.ch/sample/57392f84cdbeb0cb45687f77f8e292a7b9b92a4f9e64d8aa90582e54b0a3d15c/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 23:24 | [b1c7903423b4…](https://bazaar.abuse.ch/sample/b1c7903423b432c0f02d062651e311da188d0343a3b24928020239769cd7b851/) | `elf` | unbekannt | 43.0 | – | – | 🇳🇱NL |
| 23:24 | [3c96e3462baf…](https://bazaar.abuse.ch/sample/3c96e3462baf4b78904f53b32654717c145058bca04c7de9813e3bd6101b2fb7/) | `sh` | unbekannt | 32.3 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 15.11.2026 23:51 UTC*