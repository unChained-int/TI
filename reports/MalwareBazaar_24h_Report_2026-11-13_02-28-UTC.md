# MalwareBazaar – 13.11.2026 02:28 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **54** |
| Höchster Score | **95.7/100** – b07b17b3cf0ec6d9… |
| Häufigste Familie | **unbekannt** (29x) |
| Häufigster Typ | **exe** (66x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 21 Samples |
| Ø Dateigröße | 3.90 MB (σ=9.43) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 66 | 65.3%  █████████████ |
| `elf` | 15 | 14.9%  ██ |
| `msi` | 6 | 5.9%  █ |
| `ps1` | 4 | 4.0%   |
| `js` | 3 | 3.0%   |
| `apk` | 2 | 2.0%   |
| `vbs` | 2 | 2.0%   |
| `sh` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 29 | 28.7% |
| 2 | WARDENStealer | 22 | 21.8% |
| 3 | Mirai | 14 | 13.9% |
| 4 | ConnectWise | 6 | 5.9% |
| 5 | CoinMiner | 4 | 4.0% |
| 6 | RustyStealer | 4 | 4.0% |
| 7 | Vidar | 4 | 4.0% |
| 8 | Adware.OfferCore | 3 | 3.0% |
| 9 | RevStealer | 3 | 3.0% |
| 10 | GuLoader | 2 | 2.0% |
| 11 | SalatStealer | 2 | 2.0% |
| 12 | Meterpreter | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 36 | 35.6% | 77% |
| Windows-Malware | 30 | 29.7% | 35% |
| Botnet/IoT | 14 | 13.9% | 95% |
| Skript/Dropper | 7 | 6.9% | 35% |
| Loader | 3 | 3.0% | 88% |
| Cryptominer | 3 | 3.0% | 75% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Trojaner | 2 | 2.0% | 65% |
| Ransomware | 1 | 1.0% | 95% |
| Android-Malware | 1 | 1.0% | 45% |
| Linux-Malware | 1 | 1.0% | 45% |
| RAT | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 54 | 53.5% |
| 🟠 HOCH | 6 | 5.9% |
| 🟡 MITTEL | 39 | 38.6% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [b07b17b3cf0ec6…](https://bazaar.abuse.ch/sample/b07b17b3cf0ec6d943e7af638c6f973240b87b7a25168c84eef54bc4a7c95680/) | WannaCry | Ransomware | **95.7** | 🔴 KRITISCH | – | – | ? |
| [e94e3854db4dd3…](https://bazaar.abuse.ch/sample/e94e3854db4dd36cf8aa084136cdc99c2fb72591c8b4dd89aff786a6048b373d/) | Vidar | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [e222959aad15eb…](https://bazaar.abuse.ch/sample/e222959aad15eb605db1534921d11cd19e73e595c22c6080b99d2fdd4e605f45/) | Vidar | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [66cde465b99286…](https://bazaar.abuse.ch/sample/66cde465b99286ef211b185befd9cb14b975b2e9b6db49e39e4c469360042aa7/) | Vidar | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [b1ac2fb4d87234…](https://bazaar.abuse.ch/sample/b1ac2fb4d8723485c23a1d32846937592dd33956755d215b05fc37f4e3c656f1/) | Vidar | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [1eaba93e79031f…](https://bazaar.abuse.ch/sample/1eaba93e79031f4402debb37e18cac5959a579e20d281566ce4df124c608b2fc/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [13bbd78a44da51…](https://bazaar.abuse.ch/sample/13bbd78a44da51ed393884aa3cec179ea10f519a36e43e981523a3784d276725/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [7d8e2ed973ecce…](https://bazaar.abuse.ch/sample/7d8e2ed973eccedea4a76edcdca0860b37dda12e27404da0520da32f0b74d937/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [bd402aa2ee74ee…](https://bazaar.abuse.ch/sample/bd402aa2ee74ee9c8f13d0250f0816b662a438de1df56480983628b2397eabc9/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [98244dada836ad…](https://bazaar.abuse.ch/sample/98244dada836addb8910fdc27b155b97c4ba35c7d8e2098ed84f9df01ec0b7c6/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6460/7960 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6460/7960 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6155/7960 |
| 6 | Kaspersky | 75.5% | 6009/7959 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5669/7956 |
| 9 | Rising | 68.4% | 5446/7960 |
| 10 | Varist | 66.1% | 5258/7955 |
| 11 | Avast | 65.2% | 5186/7956 |
| 12 | AVG | 65.2% | 5186/7955 |
| 13 | Tencent | 65.0% | 5025/7734 |
| 14 | McAfeeD | 61.4% | 4886/7952 |
| 15 | huorong | 60.9% | 4841/7952 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 79 | 78.2% |
| 🐧 Linux | 16 | 15.8% |
| ❓ Unbekannt | 3 | 3.0% |
| 🤖 Android | 2 | 2.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 87 | 86.1% |
| Trojanisierte Software | 6 | 5.9% |
| Drive-By / Exploit-Kit | 5 | 5.0% |
| APK-Sideloading | 2 | 2.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 51 | 50.5% |
| 2 | 🇫🇷 FR | 36 | 35.6% |
| 3 | 🇳🇱 NL | 5 | 5.0% |
| 4 | 🇩🇪 DE | 5 | 5.0% |
| 5 | 🇨🇭 CH | 2 | 2.0% |
| 6 | 🇯🇵 JP | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 21 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 14 |
| Lateral Movement | 14 |
| Collection | 5 |
| Credential Access | 4 |
| Exfiltration | 4 |
| Defense Evasion | 2 |
| Execution | 2 |
| Command and Control | 1 |

<details><summary>e94e3854db4dd36cf8aa… – Vidar | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>e222959aad15eb605db1… – Vidar | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>66cde465b99286ef211b… – Vidar | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>b1ac2fb4d8723485c23a… – Vidar | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [f208e22323d690f516a9…](https://bazaar.abuse.ch/sample/f208e22323d690f516a92c8de55b319d1904f57bf06d58a6e2633e217a9995f0/)

- **Familie:** Mirai
- **Erkannt von:** 25 von 75 Engines (33.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQU!3CE5FD7D2F81
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (25/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-6981989-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.HK!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14339 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!3CE5FD7D2F81` |
| Tencent | `Backdoor.Linux.Mirai.zd` |
| TrellixENS | `LINUX/Mirai-FQU!3CE5FD7D2F81` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [20983573b840447e1aac…](https://bazaar.abuse.ch/sample/20983573b840447e1aacd6d3f6dd240732b15037d268d6456f0d3c4ec5051cb0/)

- **Familie:** CoinMiner
- **Erkannt von:** 52 von 75 Engines (69.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKDS.61586344
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKDS.61586344`

**Erkennende Engines (52/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKDS.61586344` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Rat]` |
| Alibaba | `TrojanDownloader:Win32/MalwareX.17be9632` |
| Antiy-AVL | `Trojan[Downloader]/Win32.Tiny` |
| Arcabit | `Trojan.GenericS.D3ABBBA8` |
| Avast | `Win64:MalwareX-gen [Rat]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKDS.61586344` |
| Bkav | `W32.Malware.C644A85D` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Siggen36.44671` |
| ESET-NOD32 | `Win64/Agent.LJN trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Trojan.GenericKDS.61586344 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/Agent.LJN!tr` |
| GData | `Trojan.GenericKDS.61586344` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Agent` |
| K7AntiVirus | `Trojan-Downloader ( 006e97151 )` |
| K7GW | `Trojan-Downloader ( 006e97151 )` |
| Kaspersky | `Trojan-Downloader.Win32.Tiny.tsw` |
| Kingsoft | `Win32.Trojan-Downloader.Tiny.ttv` |
| Lionic | `Trojan.Win32.GenericKDS.a!c` |
| Malwarebytes | `Generic.Malware/Suspicious` |
| McAfeeD | `ti!20983573B840` |
| MicroWorld-eScan | `Trojan.GenericKDS.61586344` |
| Microsoft 🛡️ | `Trojan:Win32/Leonem!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxGD.A` |
| Rising | `Downloader.Tiny!8.245 (CLOUD)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win64.Downloader.mc` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Malware.Win32.Gencirc.11e72f94` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Artemis!7FD491C23561` |
| TrendMicro | `TROJ_GEN.R023C0DJN26` |
| TrendMicro-HouseCall | `TROJ_GEN.R023C0DJN26` |
| VIPRE | `Trojan.GenericKDS.61586344` |
| Varist | `W64/ABTrojan.ZLHY-4580` |
| ViRobot | `Trojan.Win.Z.Agent.86016.HAJ` |
| Yandex | `Trojan.Agent!bhy4xy3CyiI` |
| Zillya | `Trojan.Tiny.Win32.93222` |
| alibabacloud | `Trojan[downloader]:Win/Leonem.Gen` |

### [d7fa54fc22418134af1b…](https://bazaar.abuse.ch/sample/d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066/)

- **Familie:** RevStealer
- **Erkannt von:** 22 von 75 Engines (29.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:Evo-gen [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win64:Evo-gen [Trj]` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| Bkav | `W32.Malware.D4BBA98B` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Packed.VMProtect.AM suspicious application` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Kaspersky | `HEUR:Trojan.Win32.Sdum.gen` |
| Malwarebytes | `Spyware.RevStealer` |
| McAfeeD | `ti!D7FA54FC2241` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Coins!8.133E9 (TFE:5:dSyxOJmmNXG)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| Zoner | `Probably Heur.ExeHeaderL` |

### [b99825060eafdd661039…](https://bazaar.abuse.ch/sample/b99825060eafdd661039eff03cbe4264662267265b01caecaf56e1991287d277/)

- **Familie:** RustyStealer
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.GenericKDZ.121705
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKDZ.121705`

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| Arcabit | `Trojan.Generic.D1DB69` |
| BitDefender 🛡️ | `Trojan.GenericKDZ.121705` |
| Bkav | `W32.Malware.93E0B67C` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Trojan.GenericKDZ.121705 (B)` |
| GData | `Trojan.GenericKDZ.121705` |
| Kaspersky | `VHO:Trojan.Win32.GenericML.xnet` |
| Kingsoft | `Win32.Troj.Undef.a` |
| Lionic | `Trojan.Win32.RustyStealer.4!c` |
| McAfeeD | `ti!B99825060EAF` |
| MicroWorld-eScan | `Trojan.GenericKDZ.121705` |
| Microsoft 🛡️ | `Program:Win32/Wacapew.C!ml` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| TrellixENS | `Artemis!065F122D5553` |
| VIPRE | `Trojan.GenericKDZ.121705` |
| Webroot | `W32.Malware.gen` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 63 von 75 Engines (84.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (63/75):**

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
| Sangfor | `Trojan.Win32.Autoit.Vmf1` |
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
| Zillya | `Trojan.Injector.Win32.2062480` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (65×)
- **WARDENStealer** (24×)
- **elf** (15×)
- **upx-dec** (15×)
- **upx** (15×)
- **stealer** (15×)
- **Warden** (15×)
- **signed** (14×)
- **Mirai** (13×)
- **Torii** (9×)
- **msi** (6×)
- **ConnectWise** (6×)
- **DIVINEX** (6×)
- **ps1** (4×)
- **Prometei** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +8 (21→29)
- ↑ **WARDENStealer** +20 (2→22)
- ↓ **Mirai** -36 (50→14)
- ↑ **ConnectWise** +5 (1→6)
- neu: **CoinMiner** (4)
- neu: **RustyStealer** (4)
- neu: **Vidar** (4)
- neu: **Adware.OfferCore** (3)
- ↑ **RevStealer** +1 (2→3)
- neu: **GuLoader** (2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +4 (25→29)
- ↑ **WARDENStealer** +19 (3→22)
- ↓ **Mirai** -16 (30→14)
- neu: **ConnectWise** (6)
- ↑ **CoinMiner** +3 (1→4)
- neu: **RustyStealer** (4)
- neu: **Vidar** (4)
- neu: **Adware.OfferCore** (3)
- ↑ **RevStealer** +1 (2→3)
- ↑ **GuLoader** +1 (1→2)
- weg: **Formbook** (war 2)
- weg: **Snowlight** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.904 MB |
| σ Dateigröße | 9.430 MB |
| Ø Risiko-Score | 62.8/100 |
| Ø Klassifikations-Konfidenz | 62.8% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 21/101 |
| Eindeutige Familien | 19 |
| Eindeutige Tags | 47 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 02:26 | [2fb07d961210…](https://bazaar.abuse.ch/sample/2fb07d96121058a0a1d7d28a950e95246ed82f9d19cd0b112ae43c401aace8b0/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 02:26 | [1eaba93e7903…](https://bazaar.abuse.ch/sample/1eaba93e79031f4402debb37e18cac5959a579e20d281566ce4df124c608b2fc/) | `elf` | Mirai | 84.5 | – | – | 🇺🇸US |
| 02:01 | [1677cd1d51ea…](https://bazaar.abuse.ch/sample/1677cd1d51eac543fe942e20a4a39eab1ac10b985dacad5f5246b6a3bea4b8e4/) | `ps1` | unbekannt | 38.7 | – | – | 🇺🇸US |
| 01:57 | [afcb18785813…](https://bazaar.abuse.ch/sample/afcb187858135123cc4bf27c0d1923ee08716c0a3f7ee3c3f94a9b6c75dc1dfa/) | `ps1` | unbekannt | 38.6 | – | – | 🇺🇸US |
| 01:53 | [d45361634083…](https://bazaar.abuse.ch/sample/d45361634083c162b50eca92a50e0410c538e31f51508b74f047415ab8ebb9e1/) | `exe` | unbekannt | 38.6 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 13.11.2026 02:28 UTC*