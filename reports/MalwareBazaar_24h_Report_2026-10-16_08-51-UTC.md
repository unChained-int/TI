# MalwareBazaar – 16.10.2026 08:51 UTC

Dieser Run hat **68 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **69** |
| Kritisch (≥75) | **36** |
| Höchster Score | **89.5/100** – 88500498e6b984a5… |
| Häufigste Familie | **unbekannt** (37x) |
| Häufigster Typ | **exe** (29x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 24 Samples |
| Ø Dateigröße | 13.65 MB (σ=30.90) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 29 | 42.0%  ████████ |
| `zip` | 7 | 10.1%  ██ |
| `hta` | 5 | 7.2%  █ |
| `sh` | 4 | 5.8%  █ |
| `elf` | 4 | 5.8%  █ |
| `ps1` | 4 | 5.8%  █ |
| `js` | 4 | 5.8%  █ |
| `rar` | 3 | 4.3%   |
| `macho` | 2 | 2.9%   |
| `zsh` | 1 | 1.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 37 | 53.6% |
| 2 | Formbook | 7 | 10.1% |
| 3 | Mirai | 6 | 8.7% |
| 4 | RemcosRAT | 5 | 7.2% |
| 5 | Vidar | 3 | 4.3% |
| 6 | ConnectWise | 2 | 2.9% |
| 7 | AgentTesla | 2 | 2.9% |
| 8 | SalatStealer | 2 | 2.9% |
| 9 | VIPKeylogger | 1 | 1.4% |
| 10 | ValleyRAT | 1 | 1.4% |
| 11 | DarkTortilla | 1 | 1.4% |
| 12 | Adware.Generic | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 16 | 23.2% | 88% |
| Andere / Unbekannt | 12 | 17.4% | 20% |
| Loader | 8 | 11.6% | 75% |
| Trojaner | 8 | 11.6% | 75% |
| Skript/Dropper | 7 | 10.1% | 35% |
| Botnet/IoT | 6 | 8.7% | 95% |
| RAT | 6 | 8.7% | 92% |
| Windows-Malware | 5 | 7.2% | 35% |
| Spyware | 1 | 1.4% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 36 | 52.2% |
| 🟠 HOCH | 9 | 13.0% |
| 🟡 MITTEL | 12 | 17.4% |
| 🟢 NIEDRIG | 12 | 17.4% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [88500498e6b984…](https://bazaar.abuse.ch/sample/88500498e6b984a51dad47853bcc8c6b687a2e3cba93ae034a978c90cdb78460/) | RemcosRAT | RAT | **89.5** | 🔴 KRITISCH | – | – | ? |
| [36021508a7ced6…](https://bazaar.abuse.ch/sample/36021508a7ced6c92b564ca52f931ce0d59e08624d6e60527c29aed1242ff440/) | Formbook | Infostealer | **89.3** | 🔴 KRITISCH | – | – | ? |
| [4761fbdfdb609b…](https://bazaar.abuse.ch/sample/4761fbdfdb609ba22e96717a3e03d056c316b4ecf68db8d6ff238bcd002b7d65/) | Formbook | Infostealer | **89.3** | 🔴 KRITISCH | – | – | ? |
| [ee94674cff091e…](https://bazaar.abuse.ch/sample/ee94674cff091e8da2cc212d9dab58ca9080449bf6a8dc776245b00fcda275f9/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [9c3f872383f2e5…](https://bazaar.abuse.ch/sample/9c3f872383f2e55817f0e9e02e59408a7a60aa5632560d96d66e0541de33c020/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [2c9e4347b6bf87…](https://bazaar.abuse.ch/sample/2c9e4347b6bf877e92e9a2aafcb310b7a1de97ed9efb422c368fa7bda9114a77/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [8c481c82f3d052…](https://bazaar.abuse.ch/sample/8c481c82f3d052b0d18659721c25e5ee1240d833be3c474fb120cfce3162bef7/) | Formbook | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [95b5c650d9a1d3…](https://bazaar.abuse.ch/sample/95b5c650d9a1d3276cc3a3f7e3ee6f110fafef59015174e665349ba5c6a3368b/) | Vidar | Infostealer | **88.6** | 🔴 KRITISCH | – | – | ? |
| [d27e33a6766532…](https://bazaar.abuse.ch/sample/d27e33a6766532e8a826517790932a3c90e8c12fc6cbe96d19d398eb0e2f06f5/) | Vidar | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [41662daeb91040…](https://bazaar.abuse.ch/sample/41662daeb91040d14e6c727b7444652cc5f6473a1645b6e63f8d6c8df30ae4f9/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5995/7411 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5995/7411 |
| 3 | ESET-NOD32 | 77.5% | 5741/7411 |
| 4 | Kaspersky | 76.4% | 5659/7410 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5301/7408 |
| 8 | Rising | 68.8% | 5096/7411 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4924/7407 |
| 11 | Tencent | 65.3% | 4695/7185 |
| 12 | Avast | 65.1% | 4824/7407 |
| 13 | AVG | 65.1% | 4824/7406 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4542/7404 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 41 | 59.4% |
| 📦 Archiv | 11 | 15.9% |
| 🐧 Linux | 9 | 13.0% |
| ❓ Unbekannt | 6 | 8.7% |
| 🍎 macOS | 2 | 2.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 54 | 78.3% |
| C2 / Nachladen | 7 | 10.1% |
| Drive-By / Exploit-Kit | 5 | 7.2% |
| MaaS-Loader | 2 | 2.9% |
| Trojanisierte Software | 1 | 1.4% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 27 | 39.1% |
| 2 | 🇩🇪 DE | 18 | 26.1% |
| 3 | 🇫🇷 FR | 12 | 17.4% |
| 4 | 🇳🇱 NL | 3 | 4.3% |
| 5 | 🇨🇭 CH | 3 | 4.3% |
| 6 | 🇭🇺 HU | 2 | 2.9% |
| 7 | 🌐 DK | 2 | 2.9% |
| 8 | 🌐 TH | 1 | 1.4% |
| 9 | 🌐 Unbekannt | 1 | 1.4% |

## MITRE ATT&CK

> 24 von 69 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 17 |
| Credential Access | 12 |
| Initial Access | 6 |
| Lateral Movement | 6 |
| Command and Control | 5 |
| Exfiltration | 5 |
| Impact | 1 |

<details><summary>88500498e6b984a51dad… – RemcosRAT | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>36021508a7ced6c92b56… – Formbook | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>4761fbdfdb609ba22e96… – Formbook | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>ee94674cff091e8da2cc… – Formbook | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>9c3f872383f2e55817f0… – Formbook | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [a5470680dfab4b045f15…](https://bazaar.abuse.ch/sample/a5470680dfab4b045f15d8cd5ecb7505caa4afcbb34d8a377de263af7386226a/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2026-43284-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10760` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Fortinet | `ELF/Mirai.FIN!tr` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Exploit/Linux.CVE-2026-46300.a` |

### [43c447aac52cfc197b05…](https://bazaar.abuse.ch/sample/43c447aac52cfc197b05a183bd7e39b8e464c3de73f33b65464b46479ff273ce/)

- **Familie:** Formbook
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Other:Malware-gen [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Other:Malware-gen [Trj]` |
| Avast | `Other:Malware-gen [Trj]` |
| Avira | `TR/Malware` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `PowerShell.Loader.51` |
| ESET-NOD32 | `PowerShell/Kryptik.OU trojan` |
| Fortinet | `PowerShell/Agent.ATK!tr` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan.PowerShell.Alien.gen` |
| Kingsoft | `Win32.Troj.Undef.2061140` |
| Microsoft 🛡️ | `Trojan:PowerShell/FormBook.A!AMTB` |
| Rising | `Trojan.Kryptik/PS!8.13405 (TOPIS:E0:48mjwUxllvL)` |
| Tencent | `OB:Trojan.Powershell.Agent.405567s` |
| Varist | `PSH/Agent.ATK` |
| huorong | `Trojan/PS.Obfuscated.be` |

### [b265e2f0aa874af95a8c…](https://bazaar.abuse.ch/sample/b265e2f0aa874af95a8c0f2ca1bec999855756c743edf2c763938f6e87a9455f/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Generic.Trojan.Inject.8.77EA455F
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Trojan.Inject.8.77EA455F`

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Trojan.Inject.8.77EA455F` |
| AVG | `BV:Downloader-AEH [Drp]` |
| Arcabit | `Generic.Trojan.Inject.8.77EA455F` |
| Avast | `BV:Downloader-AEH [Drp]` |
| Avira | `DR/BAT.Downloader.AEH` |
| BitDefender 🛡️ | `Generic.Trojan.Inject.8.77EA455F` |
| CTX | `xml.trojan.inject` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.FJS trojan` |
| Emsisoft | `Generic.Trojan.Inject.8.77EA455F (B)` |
| F-Secure | `Dropper.DR/BAT.Downloader.AEH` |
| GData | `Generic.Trojan.Inject.8.77EA455F` |
| Google | `Detected` |
| Kingsoft | `Script.Troj.Shell.2058038` |
| MicroWorld-eScan | `Generic.Trojan.Inject.8.77EA455F` |
| Sangfor | `Trojan.Generic-Bash.Save.cbad8f80` |
| VIPRE | `Generic.Trojan.Inject.8.77EA455F` |
| Varist | `XML/Agent.IF` |
| huorong | `TrojanDownloader/Linux.Shell.cr` |

### [2de2cf002786d5e95d2a…](https://bazaar.abuse.ch/sample/2de2cf002786d5e95d2a413aa24e3a7220b62758006cb2ec7c70c3c5ac2d081b/)

- **Familie:** FileRepMalware [Misc]
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `FileRepMalware [Misc]` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.58BBEFC8` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Elastic | `malicious (high confidence)` |
| Kingsoft | `Win32.Troj.Undef.a` |
| Malwarebytes | `Malware.AI.2689162386` |
| McAfeeD | `ti!2DE2CF002786` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |

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

- **exe** (28×)
- **trojan** (8×)
- **dropped-by-GCleaner** (7×)
- **defendertamper** (7×)
- **dropper** (7×)
- **KillAV** (7×)
- **Formbook** (7×)
- **Mirai** (6×)
- **zip** (6×)
- **hta** (5×)
- **sh** (4×)
- **elf** (4×)
- **RemcosRAT** (4×)
- **stealer** (4×)
- **ps1** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +18 (19→37)
- ↑ **Formbook** +5 (2→7)
- ↓ **Mirai** -9 (15→6)
- ↑ **RemcosRAT** +3 (2→5)
- ↑ **Vidar** +2 (1→3)
- neu: **ConnectWise** (2)
- ↑ **AgentTesla** +1 (1→2)
- neu: **SalatStealer** (2)
- neu: **VIPKeylogger** (1)
- weg: **DDoSAgent** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +10 (27→37)
- ↑ **Formbook** +5 (2→7)
- ↓ **Mirai** -27 (33→6)
- ↑ **RemcosRAT** +3 (2→5)
- ↑ **Vidar** +2 (1→3)
- ↑ **ConnectWise** +1 (1→2)
- ↑ **AgentTesla** +1 (1→2)
- neu: **SalatStealer** (2)
- neu: **VIPKeylogger** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 13.651 MB |
| σ Dateigröße | 30.901 MB |
| Ø Risiko-Score | 64.9/100 |
| Ø Klassifikations-Konfidenz | 64.6% |
| Samples mit VT | 5/69 |
| Samples mit MITRE | 24/69 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 61 |
| Unbekannte Familien | 12 (17.4%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 08:48 | [4dfdbafe8982…](https://bazaar.abuse.ch/sample/4dfdbafe8982f92cea52cd4522277e88ff73b121bb7a2fc4e4e2f62937050970/) | `sh` | unbekannt | 32.7 | – | – | 🇩🇪DE |
| 08:43 | [6967bcb2f77e…](https://bazaar.abuse.ch/sample/6967bcb2f77e0819aa4d0d1cd8487fc38e080f63b749c4b4e16feeacb2f8ddbb/) | `zip` | unbekannt | 32.6 | – | – | 🇺🇸US |
| 08:34 | [4a6afb91e3ad…](https://bazaar.abuse.ch/sample/4a6afb91e3ad1e7c550ffee45a02428489b6b9f9ba0b398da753502749892f04/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 08:34 | [a5470680dfab…](https://bazaar.abuse.ch/sample/a5470680dfab4b045f15d8cd5ecb7505caa4afcbb34d8a377de263af7386226a/) | `elf` | Mirai | 82.1 | 25.3% | 🟡 SCHWACH ERKANNT | 🇩🇪DE |
| 08:33 | [c3b8375f0927…](https://bazaar.abuse.ch/sample/c3b8375f092798ac851bfacdb94310ccabfebcbe106f6e7324764a0e4fd4ea57/) | `macho` | unbekannt | 32.5 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 16.10.2026 08:51 UTC*