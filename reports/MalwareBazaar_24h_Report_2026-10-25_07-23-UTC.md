# MalwareBazaar – 25.10.2026 07:23 UTC

Dieser Run hat **73 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **74** |
| Kritisch (≥75) | **37** |
| Höchster Score | **96.8/100** – 9a64a2be5b27cefe… |
| Häufigste Familie | **unbekannt** (28x) |
| Häufigster Typ | **elf** (26x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 23 Samples |
| Ø Dateigröße | 2.41 MB (σ=3.69) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 26 | 35.1%  ███████ |
| `exe` | 21 | 28.4%  █████ |
| `macho` | 13 | 17.6%  ███ |
| `sh` | 6 | 8.1%  █ |
| `js` | 2 | 2.7%   |
| `php` | 2 | 2.7%   |
| `gz` | 1 | 1.4%   |
| `apk` | 1 | 1.4%   |
| `msi` | 1 | 1.4%   |
| `ps1` | 1 | 1.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 28 | 37.8% |
| 2 | Mirai | 19 | 25.7% |
| 3 | SalatStealer | 9 | 12.2% |
| 4 | CoinMiner | 6 | 8.1% |
| 5 | njrat | 2 | 2.7% |
| 6 | AMOS | 2 | 2.7% |
| 7 | RustyStealer | 2 | 2.7% |
| 8 | Prometei | 1 | 1.4% |
| 9 | WannaCry | 1 | 1.4% |
| 10 | Gafgyt | 1 | 1.4% |
| 11 | Vidar | 1 | 1.4% |
| 12 | ConnectWise | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 20 | 27.0% | 95% |
| Infostealer | 14 | 18.9% | 79% |
| Loader | 14 | 18.9% | 75% |
| Windows-Malware | 5 | 6.8% | 35% |
| Cryptominer | 5 | 6.8% | 75% |
| Andere / Unbekannt | 5 | 6.8% | 20% |
| Linux-Malware | 3 | 4.1% | 45% |
| Skript/Dropper | 3 | 4.1% | 35% |
| RAT | 2 | 2.7% | 95% |
| Ransomware | 1 | 1.4% | 95% |
| Backdoor | 1 | 1.4% | 75% |
| Trojaner | 1 | 1.4% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 37 | 50.0% |
| 🟠 HOCH | 21 | 28.4% |
| 🟡 MITTEL | 8 | 10.8% |
| 🟢 NIEDRIG | 8 | 10.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [9a64a2be5b27ce…](https://bazaar.abuse.ch/sample/9a64a2be5b27cefe726ccd7e6600ff18c3c220598d10bf27411323ffe0fb8c78/) | WannaCry | Ransomware | **96.8** | 🔴 KRITISCH | – | – | ? |
| [94996736d69177…](https://bazaar.abuse.ch/sample/94996736d6917702bae5aa7ce888ee896be94fa6e620c0b155e9f3c7bbe5a369/) | njrat | RAT | **89.3** | 🔴 KRITISCH | – | – | ? |
| [2de0e353270c3b…](https://bazaar.abuse.ch/sample/2de0e353270c3beddc1f38b860c09f86757d9c7006208bbf09a7cc22055442eb/) | AMOS | Infostealer | **86.5** | 🔴 KRITISCH | – | – | ? |
| [51754c16d7f706…](https://bazaar.abuse.ch/sample/51754c16d7f70607d607d7c1bc6e1ed40ac29538b585784f69ea00b9dabe805f/) | AMOS | Infostealer | **85.9** | 🔴 KRITISCH | – | – | ? |
| [8eec2049532e74…](https://bazaar.abuse.ch/sample/8eec2049532e744253e3a5a654d7ce173e874ab8e6e247d6db8e51c97437e25f/) | njrat | RAT | **85.0** | 🔴 KRITISCH | – | – | ? |
| [5031b6eb3b60a3…](https://bazaar.abuse.ch/sample/5031b6eb3b60a3bf9d72ab0c22378056ba9347dc68458d99d87cc2efb3fa6c01/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [0a33219aac70bd…](https://bazaar.abuse.ch/sample/0a33219aac70bd58053e542e99cfae1292d85fa349c883ce9f760bda531ae70d/) | Gafgyt | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |
| [ea4da928c3fcf3…](https://bazaar.abuse.ch/sample/ea4da928c3fcf30db2bf5fec2548b1e5cbd8c2bc626b9035bfce569c558b9f9d/) | SalatStealer | Infostealer | **81.9** | 🔴 KRITISCH | – | – | ? |
| [b161bd43b625ba…](https://bazaar.abuse.ch/sample/b161bd43b625bac3e6cd5d612c7de5f991c24b7c6776e37cca9f10fc1019fa83/) | SalatStealer | Infostealer | **81.9** | 🔴 KRITISCH | – | – | ? |
| [a016f6371a48ae…](https://bazaar.abuse.ch/sample/a016f6371a48aeceb793cc80e22bbcf2bb946525c6500b56530ee0cd7751ce58/) | Mirai | Botnet/IoT | **81.6** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6172/7620 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6172/7620 |
| 3 | ESET-NOD32 | 77.2% | 5880/7620 |
| 4 | Kaspersky | 75.9% | 5780/7619 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5413/7617 |
| 8 | Rising | 68.3% | 5202/7620 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5038/7616 |
| 11 | Avast | 65.1% | 4955/7616 |
| 12 | AVG | 65.1% | 4955/7615 |
| 13 | Tencent | 64.8% | 4792/7394 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4661/7613 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 33 | 44.6% |
| 🪟 Windows | 23 | 31.1% |
| 🍎 macOS | 13 | 17.6% |
| ❓ Unbekannt | 3 | 4.1% |
| 🤖 Android | 1 | 1.4% |
| 🌐 Web | 1 | 1.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 56 | 75.7% |
| MaaS-Loader | 14 | 18.9% |
| Drive-By / Exploit-Kit | 2 | 2.7% |
| Exploit / N-Day | 1 | 1.4% |
| Trojanisierte Software | 1 | 1.4% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 38 | 51.4% |
| 2 | 🌐 Unbekannt | 12 | 16.2% |
| 3 | 🇫🇷 FR | 8 | 10.8% |
| 4 | 🇩🇪 DE | 8 | 10.8% |
| 5 | 🇳🇱 NL | 5 | 6.8% |
| 6 | 🇬🇧 GB | 1 | 1.4% |
| 7 | 🇨🇭 CH | 1 | 1.4% |
| 8 | 🇪🇸 ES | 1 | 1.4% |

## MITRE ATT&CK

> 23 von 74 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 20 |
| Lateral Movement | 20 |
| Collection | 3 |
| Command and Control | 2 |
| Credential Access | 1 |
| Exfiltration | 1 |

<details><summary>94996736d6917702bae5… – njrat | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>8eec2049532e744253e3… – njrat | 🔴 KRITISCH 85.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [e9c9dca6c00141ee7e10…](https://bazaar.abuse.ch/sample/e9c9dca6c00141ee7e10a6ef2b9faf675bde8342c3187c51e5e6e0af37bbc7b6/)

- **Familie:** Mirai
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Application.Generic.37111556
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37111892`

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Application.Generic.37111556` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Application.Generic.D2364704` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Application.Generic.37111892` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Application.Generic.37111556 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Application.Generic.37111556` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Application.Generic.37111556` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Generic Reputation PUA (PUA)` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Application.Generic.37111315` |
| huorong | `Trojan/Prometei.c` |

### [757a32fe5659605c8a1c…](https://bazaar.abuse.ch/sample/757a32fe5659605c8a1c2843737a2e5efbf18a6724771175e7b184ae008d38ea/)

- **Familie:** CoinMiner
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Packed.Obfuscated.B suspicious application
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Script/Wacatac.B!ml`

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Packed]/Linux.Obfuscated` |
| ESET-NOD32 | `Linux/Packed.Obfuscated.B suspicious application` |
| Ikarus | `PUA.Linux.Obfuscated` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Trojan.CoinMiner/Linux!1.141AF (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |

### [f828c277b3316e0ee7a1…](https://bazaar.abuse.ch/sample/f828c277b3316e0ee7a13b35b00c26553785e7e260d2d9f386ad97b94e6dbfe2/)

- **Familie:** Vidar
- **Erkannt von:** 45 von 75 Engines (60.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Stealer.1490
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Stealer.1490`

**Erkennende Engines (45/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Stealer.1490` |
| AVG | `Win64:Evo-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.R773315` |
| Alibaba | `Backdoor:Win64/RemusStealer.2dd63060` |
| Antiy-AVL | `Trojan[Backdoor]/Win64.Gsb` |
| Arcabit | `Trojan.Stealer.D5D2` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| BitDefender 🛡️ | `Trojan.Stealer.1490` |
| Bkav | `W32.Malware.8B2B8B57` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/Kryptik.TS trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Stealer.1490 (B)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/MALD2.3301!tr` |
| GData | `Trojan.Stealer.1490` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Crypt` |
| K7AntiVirus | `Backdoor ( 006dd9cd1 )` |
| K7GW | `Backdoor ( 006dd9cd1 )` |
| Kaspersky | `HEUR:Trojan.Win32.Agent.pef` |
| Kingsoft | `Win64.Backdoor.Gsb.gen` |
| Lionic | `Trojan.Win32.Stealer.12!c` |
| Malwarebytes | `Spyware.Stealer` |
| MaxSecure | `Trojan.Malware.685085167.susgen` |
| McAfeeD | `Trojan:Win/Dllhijack.EAT` |
| MicroWorld-eScan | `Trojan.Stealer.1490` |
| Microsoft 🛡️ | `Trojan:Win64/RemusStealer.DGRS!MTB` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Trojan.ShellCodeRunner/x64!1.140E8 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Backdoor.Win64.Gsb.16004167` |
| TrellixENS | `Artemis!765F611D6825` |
| VBA32 | `Backdoor.Win64.Gsb` |
| VIPRE | `Trojan.Stealer.1490` |
| Varist | `W64/Agent.MMK.gen!Eldorado` |
| alibabacloud | `Backdoor:Multi/RemusStealer.DUYH3DGW` |
| huorong | `Trojan/W64.Agent.bs!crit` |

### [90950ae9570d317ba26d…](https://bazaar.abuse.ch/sample/90950ae9570d317ba26d8a72f45c3d64821d4d2c8a916e78e01c24b6b13368dd/)

- **Familie:** Mirai
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Application.Generic.37111556
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Application.Generic.37111892`

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Application.Generic.37111556` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Application.Generic.D2364704` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Application.Generic.37111892` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Application.Generic.37111556 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Application.Generic.37111556` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kingsoft | `Linux.Backdoor.Prometei.a` |
| Lionic | `Trojan.Linux.Prometei.m!c` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Application.Generic.37111556` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Sangfor | `Backdoor.Linux.Prometei.V6z6` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Generic Reputation PUA (PUA)` |
| Symantec | `Trojan.Promete!ATN` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| TrendMicro-HouseCall | `Backdoor.Linux.PROMETEI.USBLJP26` |
| VIPRE | `Application.Generic.37111315` |
| alibabacloud | `Backdoor:Linux/Prometei.CZ` |
| huorong | `Trojan/Prometei.c` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7AntiVirus | `Trojan ( 0001140e1 )` |
| K7GW | `Hacktool ( a007e0071 )` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **elf** (25×)
- **exe** (20×)
- **Mirai** (19×)
- **honeypot** (19×)
- **ClickFix** (14×)
- **loader** (13×)
- **Foxveil** (13×)
- **Mach-O** (13×)
- **macho** (13×)
- **macOS** (13×)
- **cowrie** (12×)
- **SalatStealer** (7×)
- **CoinMiner** (6×)
- **sh** (6×)
- **Prometei** (5×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +12 (16→28)
- ↑ **Mirai** +2 (17→19)
- ↑ **SalatStealer** +7 (2→9)
- neu: **CoinMiner** (6)
- neu: **njrat** (2)
- neu: **AMOS** (2)
- neu: **RustyStealer** (2)
- neu: **Prometei** (1)
- neu: **WannaCry** (1)
- neu: **Gafgyt** (1)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -9 (37→28)
- ↓ **Mirai** -1 (20→19)
- ↑ **SalatStealer** +8 (1→9)
- ↑ **CoinMiner** +3 (3→6)
- neu: **njrat** (2)
- ↑ **AMOS** +1 (1→2)
- neu: **RustyStealer** (2)
- neu: **Prometei** (1)
- neu: **WannaCry** (1)
- neu: **Gafgyt** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.410 MB |
| σ Dateigröße | 3.686 MB |
| Ø Risiko-Score | 68.0/100 |
| Ø Klassifikations-Konfidenz | 72.6% |
| Samples mit VT | 5/74 |
| Samples mit MITRE | 23/74 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 65 |
| Unbekannte Familien | 5 (6.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 07:15 | [ad0fdedffb06…](https://bazaar.abuse.ch/sample/ad0fdedffb064a1f092e849d7e50350e6423a3fdf43241da1a2e65c5de6dd831/) | `elf` | Prometei | 43.2 | – | – | 🇺🇸US |
| 07:14 | [305077552075…](https://bazaar.abuse.ch/sample/3050775520758beb259b83b77c6f217ecd1825159eaf02de85b60677a8b2b30e/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 06:59 | [ea4da928c3fc…](https://bazaar.abuse.ch/sample/ea4da928c3fcf30db2bf5fec2548b1e5cbd8c2bc626b9035bfce569c558b9f9d/) | `exe` | SalatStealer | 81.9 | – | – | 🇳🇱NL |
| 06:58 | [b161bd43b625…](https://bazaar.abuse.ch/sample/b161bd43b625bac3e6cd5d612c7de5f991c24b7c6776e37cca9f10fc1019fa83/) | `exe` | SalatStealer | 81.9 | – | – | 🇫🇷FR |
| 06:50 | [94996736d691…](https://bazaar.abuse.ch/sample/94996736d6917702bae5aa7ce888ee896be94fa6e620c0b155e9f3c7bbe5a369/) | `exe` | njrat | 89.3 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 25.10.2026 07:23 UTC*