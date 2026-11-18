# MalwareBazaar – 18.11.2026 03:24 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **70** |
| Höchster Score | **96.0/100** – 1a93cd4b2c7d6b0e… |
| Häufigste Familie | **Mirai** (49x) |
| Häufigster Typ | **elf** (66x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 52 Samples |
| Ø Dateigröße | 2.23 MB (σ=5.48) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 66 | 65.3%  █████████████ |
| `exe` | 18 | 17.8%  ███ |
| `sh` | 6 | 5.9%  █ |
| `apk` | 5 | 5.0%   |
| `js` | 2 | 2.0%   |
| `ps1` | 2 | 2.0%   |
| `msi` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 49 | 48.5% |
| 2 | unbekannt | 21 | 20.8% |
| 3 | WARDENStealer | 11 | 10.9% |
| 4 | Prometei | 7 | 6.9% |
| 5 | CoinMiner | 3 | 3.0% |
| 6 | njrat | 2 | 2.0% |
| 7 | ACRStealer | 2 | 2.0% |
| 8 | RemcosRAT | 1 | 1.0% |
| 9 | B!ml | 1 | 1.0% |
| 10 | SpyNote | 1 | 1.0% |
| 11 | WannaCry | 1 | 1.0% |
| 12 | Gafgyt | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 50 | 49.5% | 95% |
| Linux-Malware | 14 | 13.9% | 45% |
| Infostealer | 14 | 13.9% | 75% |
| RAT | 4 | 4.0% | 90% |
| Android-Malware | 3 | 3.0% | 45% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Cryptominer | 3 | 3.0% | 75% |
| Loader | 3 | 3.0% | 75% |
| Windows-Malware | 2 | 2.0% | 35% |
| Skript/Dropper | 2 | 2.0% | 35% |
| Trojaner | 1 | 1.0% | 65% |
| Ransomware | 1 | 1.0% | 95% |
| Post-Exploitation | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 70 | 69.3% |
| 🟠 HOCH | 7 | 6.9% |
| 🟡 MITTEL | 21 | 20.8% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [1a93cd4b2c7d6b…](https://bazaar.abuse.ch/sample/1a93cd4b2c7d6b0ec051be2e54aaeaf91d3bbdd4d0d27ebd3b473475fa54f36e/) | WannaCry | Ransomware | **96.0** | 🔴 KRITISCH | – | – | ? |
| [3ebe852f79749c…](https://bazaar.abuse.ch/sample/3ebe852f79749cb9ad353556cd535e180bfd6175edc610d42b6353d3d983cef7/) | Sliver | Post-Exploitat | **91.4** | 🔴 KRITISCH | – | – | ? |
| [46560e81655b4f…](https://bazaar.abuse.ch/sample/46560e81655b4f0021d193d25208c17663521b9e58433526a0742b5dd7c4a1a9/) | RemcosRAT | RAT | **89.7** | 🔴 KRITISCH | – | – | ? |
| [007c2c34306aa2…](https://bazaar.abuse.ch/sample/007c2c34306aa2def929f721c4e47c11dba20e1fe6bdf7a4b035b5f7919e8071/) | njrat | RAT | **89.4** | 🔴 KRITISCH | – | – | ? |
| [7cfe97db459d72…](https://bazaar.abuse.ch/sample/7cfe97db459d72cad53391670693d46f0a361c6eac291019860708f119edc48f/) | Mirai | Botnet/IoT | **84.9** | 🔴 KRITISCH | 13.5% | 🟡 SCHWACH ERKANNT | ✗ |
| [1334fcf7fad5bd…](https://bazaar.abuse.ch/sample/1334fcf7fad5bd46482039ab5a15608d2078b5e5c5e255c2fe226c2a52068393/) | B!ml | Trojaner | **84.6** | 🔴 KRITISCH | 1.4% | ⚠️ KAUM ERKANNT | ✗ |
| [08f7cc7521f634…](https://bazaar.abuse.ch/sample/08f7cc7521f634b05eb7eab6201b87a8cbce7104dc58d616bd11529c65067e7d/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [83490814a5b8fb…](https://bazaar.abuse.ch/sample/83490814a5b8fb6022259464c77ccc4894181e744a94b25e16581cf4d28ed9ff/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [c5492b05fcb17d…](https://bazaar.abuse.ch/sample/c5492b05fcb17dd6b4079d38ccc1837ca524c8c9ecc4fdf6ccd62f8683cbd56a/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [51de6c6dce0b4c…](https://bazaar.abuse.ch/sample/51de6c6dce0b4c7e83ac0a9b708588fbca9fb121f190bd675b8cdd4bf2beb8ac/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6521/8037 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6521/8037 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6215/8037 |
| 6 | Kaspersky | 75.5% | 6070/8036 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5722/8033 |
| 9 | Rising | 68.5% | 5504/8037 |
| 10 | Varist | 66.0% | 5304/8032 |
| 11 | Avast | 65.2% | 5235/8033 |
| 12 | AVG | 65.2% | 5235/8032 |
| 13 | Tencent | 65.1% | 5085/7811 |
| 14 | McAfeeD | 61.5% | 4936/8029 |
| 15 | huorong | 60.9% | 4886/8029 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 72 | 71.3% |
| 🪟 Windows | 21 | 20.8% |
| 🤖 Android | 5 | 5.0% |
| ❓ Unbekannt | 2 | 2.0% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 89 | 88.1% |
| APK-Sideloading | 5 | 5.0% |
| MaaS-Loader | 3 | 3.0% |
| Drive-By / Exploit-Kit | 2 | 2.0% |
| Exploit / N-Day | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 39 | 38.6% |
| 2 | 🇺🇸 US | 29 | 28.7% |
| 3 | 🇫🇷 FR | 13 | 12.9% |
| 4 | 🇳🇱 NL | 11 | 10.9% |
| 5 | 🌐 CL | 3 | 3.0% |
| 6 | 🇸🇪 SE | 2 | 2.0% |
| 7 | 🇯🇵 JP | 1 | 1.0% |
| 8 | 🇨🇦 CA | 1 | 1.0% |
| 9 | 🇧🇪 BE | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 52 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 49 |
| Lateral Movement | 49 |
| Command and Control | 3 |
| Collection | 3 |

<details><summary>46560e81655b4f0021d1… – RemcosRAT | 🔴 KRITISCH 89.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>007c2c34306aa2def929… – njrat | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>7cfe97db459d72cad533… – Mirai | 🔴 KRITISCH 84.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [1334fcf7fad5bd464820…](https://bazaar.abuse.ch/sample/1334fcf7fad5bd46482039ab5a15608d2078b5e5c5e255c2fe226c2a52068393/)

- **Familie:** B!ml
- **Erkannt von:** 1 von 74 Engines (1.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.B!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [7cfe97db459d72cad533…](https://bazaar.abuse.ch/sample/7cfe97db459d72cad53391670693d46f0a361c6eac291019860708f119edc48f/)

- **Familie:** Mirai
- **Erkannt von:** 10 von 74 Engines (13.5%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux/Mirai.FNP trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan/Linux.Mirai` |
| DrWeb | `Linux.Mirai.11295` |
| ESET-NOD32 | `Linux/Mirai.FNP trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Ngioweb` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nx` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (TFE:14:Wd33jeUZH3M)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.tnog` |
| huorong | `Trojan/Linux.Mirai.np` |

### [396541b448bcac2b0077…](https://bazaar.abuse.ch/sample/396541b448bcac2b0077e5dce6668200c6871a9c7a90a7d043085bba48b0ceb5/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 74 Engines (33.8%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CYJ [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CYJ [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Avast | `ELF:Mirai-CYJ [Trj]` |
| Avira | `TR/LINUX.Mirai.CYJ` |
| ClamAV | `Unix.Trojan.Mirai-9858729-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.EQI trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CYJ` |
| Fortinet | `ELF/Mirai.CJS!tr` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| Kingsoft | `Linux.Backdoor.Mirai.b` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `ti!396541B448BC` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.HL!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.144FF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.waq` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Trojan/Linux.Mirai.l` |

### [af9aa6a428e423981b0e…](https://bazaar.abuse.ch/sample/af9aa6a428e423981b0ecef66a858c062ec400eb2c0ca957054fc377fb5a82f3/)

- **Familie:** WARDENStealer
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
| AVG | `MalwareX-gen [Pws]` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R797565` |
| Antiy-AVL | `Trojan/Win64.ShellcodeRunner` |
| Arcabit | `Trojan.ShellcodeRunner.143` |
| Avast | `MalwareX-gen [Pws]` |
| BitDefender 🛡️ | `Gen:Variant.ShellcodeRunner.143` |
| Bkav | `W32.Malware.10AFAE5D` |
| CTX | `dll.unknown.shellcoderunner` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/ShellcodeRunner.CQR trojan` |
| Emsisoft | `Gen:Variant.ShellcodeRunner.143 (B)` |
| GData | `Gen:Variant.ShellcodeRunner.143` |
| K7AntiVirus | `Trojan ( 006d9bf01 )` |
| K7GW | `Trojan ( 006d9bf01 )` |
| Kaspersky | `VHO:Trojan.Win32.Agent.gen` |
| MicroWorld-eScan | `Gen:Variant.ShellcodeRunner.143` |
| Rising | `Malware.Undefined!8.C (TFE:6:C9WtrIs9t1G)` |
| Sangfor | `Trojan.Win32.Save.a` |
| Tencent | `Trojan.Win64.Shellcoderunner.16009525` |
| TrellixENS | `Artemis!EA432B2AA4FA` |
| VIPRE | `Gen:Variant.ShellcodeRunner.143` |
| huorong | `Trojan/W64.ShellLoader.ea!crit` |

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

- **elf** (62×)
- **Mirai** (48×)
- **Torii** (27×)
- **exe** (17×)
- **WARDENStealer** (11×)
- **upx-dec** (11×)
- **upx** (11×)
- **stealer** (7×)
- **arm** (7×)
- **Prometei** (7×)
- **Warden** (6×)
- **apk** (4×)
- **wraith** (4×)
- **RAT** (3×)
- **CoinMiner** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +33 (16→49)
- ↑ **unbekannt** +7 (14→21)
- ↑ **WARDENStealer** +7 (4→11)
- ↑ **Prometei** +3 (4→7)
- neu: **CoinMiner** (3)
- neu: **ACRStealer** (2)
- ↓ **RemcosRAT** -10 (11→1)
- neu: **B!ml** (1)
- neu: **SpyNote** (1)
- weg: **AgentTesla** (war 6)
- weg: **Formbook** (war 4)
- weg: **MassLogger** (war 2)
- weg: **GuLoader** (war 2)
- weg: **AsyncRAT** (war 2)
- weg: **VIPKeylogger** (war 2)
- weg: **LxBaseRAT** (war 2)
- weg: **FantasyHub** (war 19)
- weg: **SilentNet** (war 2)
- weg: **SalatStealer** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +12 (37→49)
- ↓ **unbekannt** -2 (23→21)
- ↑ **WARDENStealer** +6 (5→11)
- ↑ **Prometei** +6 (1→7)
- ↑ **CoinMiner** +2 (1→3)
- ↑ **njrat** +1 (1→2)
- neu: **ACRStealer** (2)
- ↓ **RemcosRAT** -2 (3→1)
- neu: **B!ml** (1)
- neu: **SpyNote** (1)
- weg: **SalatStealer** (war 6)
- weg: **RevStealer** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **Formbook** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.231 MB |
| σ Dateigröße | 5.483 MB |
| Ø Risiko-Score | 71.3/100 |
| Ø Klassifikations-Konfidenz | 77.5% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 52/101 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 44 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:17 | [071f27d7d05b…](https://bazaar.abuse.ch/sample/071f27d7d05bb600b0de3e4ab4dfc0ce2fec874a6e868b8cb8b8acecec6893be/) | `exe` | unbekannt | 39.0 | – | – | 🌐SE |
| 03:17 | [46560e81655b…](https://bazaar.abuse.ch/sample/46560e81655b4f0021d193d25208c17663521b9e58433526a0742b5dd7c4a1a9/) | `js` | RemcosRAT | 89.7 | – | – | 🌐SE |
| 03:10 | [08f7cc7521f6…](https://bazaar.abuse.ch/sample/08f7cc7521f634b05eb7eab6201b87a8cbce7104dc58d616bd11529c65067e7d/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 03:10 | [7adad2b4e15c…](https://bazaar.abuse.ch/sample/7adad2b4e15c10a4364d2bcc35f2d6bddc00469e4b20884abf0055ec70135750/) | `elf` | unbekannt | 43.2 | – | – | 🇩🇪DE |
| 03:10 | [83490814a5b8…](https://bazaar.abuse.ch/sample/83490814a5b8fb6022259464c77ccc4894181e744a94b25e16581cf4d28ed9ff/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 18.11.2026 03:24 UTC*