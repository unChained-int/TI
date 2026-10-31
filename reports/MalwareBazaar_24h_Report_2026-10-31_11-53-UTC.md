# MalwareBazaar – 31.10.2026 11:53 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **65** |
| Höchster Score | **97.3/100** – e993363a5da51bfe… |
| Häufigste Familie | **Mirai** (35x) |
| Häufigster Typ | **elf** (46x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 42 Samples |
| Ø Dateigröße | 2.10 MB (σ=6.08) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 46 | 45.5%  █████████ |
| `exe` | 24 | 23.8%  ████ |
| `sh` | 7 | 6.9%  █ |
| `macho` | 6 | 5.9%  █ |
| `ps1` | 6 | 5.9%  █ |
| `js` | 4 | 4.0%   |
| `jar` | 2 | 2.0%   |
| `apk` | 2 | 2.0%   |
| `msi` | 1 | 1.0%   |
| `xls` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 35 | 34.7% |
| 2 | unbekannt | 25 | 24.8% |
| 3 | RustyStealer | 11 | 10.9% |
| 4 | Prometei | 5 | 5.0% |
| 5 | Formbook | 5 | 5.0% |
| 6 | AMOS | 4 | 4.0% |
| 7 | SalatStealer | 3 | 3.0% |
| 8 | SilentNet | 2 | 2.0% |
| 9 | WannaCry | 1 | 1.0% |
| 10 | XWorm | 1 | 1.0% |
| 11 | FDF trojan | 1 | 1.0% |
| 12 | RatHat | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 36 | 35.6% | 94% |
| Infostealer | 27 | 26.7% | 81% |
| Linux-Malware | 10 | 9.9% | 45% |
| Andere / Unbekannt | 9 | 8.9% | 20% |
| Windows-Malware | 6 | 5.9% | 35% |
| Skript/Dropper | 3 | 3.0% | 35% |
| RAT | 3 | 3.0% | 88% |
| Maldoc | 2 | 2.0% | 35% |
| Loader | 2 | 2.0% | 75% |
| Ransomware | 1 | 1.0% | 95% |
| Cryptominer | 1 | 1.0% | 75% |
| Android-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 65 | 64.4% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 22 | 21.8% |
| 🟢 NIEDRIG | 9 | 8.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [e993363a5da51b…](https://bazaar.abuse.ch/sample/e993363a5da51bfe0bcc541f8ac83a13ba162cdd69724ee181446f2b7d42bc5e/) | WannaCry | Ransomware | **97.3** | 🔴 KRITISCH | – | – | ? |
| [e58caff40b3056…](https://bazaar.abuse.ch/sample/e58caff40b3056f15644c891ab78fa0f28dc9ebf1c321b1ccfd0718e82c0e71a/) | AMOS | Infostealer | **89.4** | 🔴 KRITISCH | – | – | ? |
| [8161009b41c1e2…](https://bazaar.abuse.ch/sample/8161009b41c1e2a45790429ca7907694fc33169c1710b26de542dad98e027add/) | XWorm | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [65d505c8ec91af…](https://bazaar.abuse.ch/sample/65d505c8ec91afd197545a3b11333c2893ba85d70df359a19d31322f8a89c287/) | Formbook | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [13d28c641475d9…](https://bazaar.abuse.ch/sample/13d28c641475d9cb3b8d0ecfc30626e1289a9bdfbb6aa31b4d119f11b02fb17e/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [0f4bdea083137d…](https://bazaar.abuse.ch/sample/0f4bdea083137db9fb14b677d019c8dc6c87f40ab76e46512afbe05bd6a4f76b/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [9b1933ff196a94…](https://bazaar.abuse.ch/sample/9b1933ff196a946f3b43fdf9a4bea548301b8490f4142c3c3064c0c1a44a7946/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [3a1e7d2aaeb545…](https://bazaar.abuse.ch/sample/3a1e7d2aaeb545d10018b4925a321de02d6ee47122de46c11c701b25a4f08d59/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [7c3b234169d90a…](https://bazaar.abuse.ch/sample/7c3b234169d90ac5d8b18e56e5c46012319124a225316a962506b236fc952075/) | AMOS | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |
| [4632c511b23947…](https://bazaar.abuse.ch/sample/4632c511b239471f0b4d4779195c7727bcbc1f97ed5e6826173eebd34d743037/) | AMOS | Infostealer | **87.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6280/7745 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6280/7745 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 5988/7745 |
| 6 | Kaspersky | 75.5% | 5848/7744 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5513/7741 |
| 9 | Rising | 68.3% | 5291/7745 |
| 10 | Varist | 66.2% | 5121/7740 |
| 11 | Avast | 65.2% | 5044/7741 |
| 12 | AVG | 65.2% | 5044/7740 |
| 13 | Tencent | 64.9% | 4883/7519 |
| 14 | McAfeeD | 61.3% | 4742/7737 |
| 15 | huorong | 60.8% | 4707/7737 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 55 | 54.5% |
| 🪟 Windows | 31 | 30.7% |
| 🍎 macOS | 6 | 5.9% |
| ❓ Unbekannt | 5 | 5.0% |
| 📄 Dokument | 2 | 2.0% |
| 🤖 Android | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 89 | 88.1% |
| Drive-By / Exploit-Kit | 4 | 4.0% |
| Phishing / E-Mail-Anhang | 2 | 2.0% |
| APK-Sideloading | 2 | 2.0% |
| MaaS-Loader | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 41 | 40.6% |
| 2 | 🇫🇷 FR | 15 | 14.9% |
| 3 | 🇳🇱 NL | 13 | 12.9% |
| 4 | 🇸🇪 SE | 11 | 10.9% |
| 5 | 🇩🇪 DE | 11 | 10.9% |
| 6 | 🇨🇭 CH | 6 | 5.9% |
| 7 | 🇮🇳 IN | 1 | 1.0% |
| 8 | 🇨🇦 CA | 1 | 1.0% |
| 9 | 🇯🇵 JP | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 42 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 35 |
| Lateral Movement | 35 |
| Credential Access | 6 |
| Collection | 6 |
| Exfiltration | 1 |
| Command and Control | 1 |

<details><summary>e58caff40b3056f15644… – AMOS | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>65d505c8ec91afd19754… – Formbook | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>13d28c641475d9cb3b8d… – Formbook | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [c7a02e58c72183a58b23…](https://bazaar.abuse.ch/sample/c7a02e58c72183a58b2322c6f97f472476bf41ef6154acb9a4e2d3992e7e717f/)

- **Familie:** Mirai
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2026-43284-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9871` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Exploit/Linux.CVE-2026-46300.a` |

### [8e073b59e35dc2a8a5ab…](https://bazaar.abuse.ch/sample/8e073b59e35dc2a8a5abe3d0862e4845be08f19a5f7ba5f2030443ca3658f198/)

- **Familie:** Mirai
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:CVE-2026-43284-A [Expl]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:CVE-2026-43284-A [Expl]` |
| Avast | `ELF:CVE-2026-43284-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-BOH [Trj]` |
| Avira | `EXP/LINUX.CVE-2026-.A` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9871` |
| ESET-NOD32 | `Linux/Exploit.CVE-2026-43284.B trojan` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai/Linux!1.DAAB (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Exploit/Linux.CVE-2026-46300.a` |

### [1fdae5afdca0a642242f…](https://bazaar.abuse.ch/sample/1fdae5afdca0a642242f0038b389a32b53d89569346eb0b7ec92c50e5a58a5c5/)

- **Familie:** FDF trojan
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Mirai.FDF trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Mirai.FDF trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Tencent | `Trojan.Linux.Mirai.ha` |

### [d7be406b98d6ce3b188f…](https://bazaar.abuse.ch/sample/d7be406b98d6ce3b188f3a3ee8227419ce4c39de0a6b489f060bc73a2016dfcc/)

- **Familie:** RustyStealer
- **Erkannt von:** 39 von 75 Engines (52.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81987490
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81987490`

**Erkennende Engines (39/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81987490` |
| APEX | `Malicious` |
| AhnLab-V3 | `HackTool/Win.PSWDump.R803040` |
| Alibaba | `HackTool:Win64/PSWDump_AGen.eb0c1056` |
| Antiy-AVL | `Trojan/Win32.Ravartar` |
| Arcabit | `Trojan.Generic.D4E307A2` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKD.81987490` |
| Bkav | `W32.Malware.1C5FEB5` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.Siggen36.47117` |
| ESET-NOD32 | `Win64/HackTool.PSWDump_AGen.CM trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.81987490 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| GData | `Win64.Trojan-Stealer.Rust.B` |
| Google | `Detected` |
| Gridinsoft | `Hack.Win64.Patcher.sa` |
| K7AntiVirus | `Password-Stealer ( 006e8deb1 )` |
| K7GW | `Password-Stealer ( 006e8deb1 )` |
| Lionic | `Hacktool.Win32.Stealer.3!c` |
| Malwarebytes | `Malware.AI.3240295592` |
| McAfeeD | `ti!D7BE406B98D6` |
| MicroWorld-eScan | `Trojan.GenericKD.81987490` |
| Microsoft 🛡️ | `Trojan:Win32/Ravartar!rfn` |
| Paloalto | `generic.ml` |
| Rising | `Spyware.Stealer!8.3090 (TFE:5:ioIFS3v37dT)` |
| Sangfor | `Hacktool.Win64.Agent.Vcnk` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `OB:Hacktool.Win64.Agent.16007786` |
| Varist | `W64/ABTrojan.ADTB-1390` |
| VirIT | `HackTool.Win64.Agent.IXS` |
| alibabacloud | `HackTool:Win/PSWDump_AGen.CZ` |
| huorong | `TrojanSpy/Stealer.aa` |

### [7e4c129f5bd09beffae1…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** SalatStealer
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (55/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.LummaStealer.103` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.Generic.R727379` |
| Antiy-AVL | `Trojan/Win32.SalatStealer` |
| Arcabit | `Trojan.LummaStealer.103` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.LummaStealer.103` |
| Bkav | `W32.Malware.62046A21` |
| CTX | `exe.trojan.lummastealer` |
| ClamAV | `Win.Malware.Salat-10058846-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent.VO trojan` |
| Elastic | `Multi.Generic.Threat` |
| Emsisoft | `Trojan.LummaStealer.103 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `W32/Agent.VO!tr` |
| GData | `Trojan.LummaStealer.103` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Agent.sa` |
| Ikarus | `Win32.Outbreak` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Kaspersky | `UDS:Trojan-PSW.Win64.Salat` |
| Kingsoft | `Win32.Troj.salatstealer.v` |
| Lionic | `Trojan.Win32.Agent.tt6y` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!9E7BE912AC3C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| Sangfor | `Infostealer.Win32.Salatstealer.Vsjg` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570877` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9E7BE912AC3C` |
| TrendMicro | `TrojanSpy.Win32.SALATSTEALER.YXGJZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **elf** (45×)
- **exe** (23×)
- **Mirai** (20×)
- **Torii** (18×)
- **mirai** (15×)
- **RustyStealer** (11×)
- **cowrie** (7×)
- **honeypot** (7×)
- **macho** (6×)
- **ps1** (6×)
- **Formbook** (5×)
- **ClickFix** (5×)
- **Foxveil** (5×)
- **Mach-O** (5×)
- **macOS** (5×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +15 (20→35)
- ↓ **unbekannt** -1 (26→25)
- ↑ **RustyStealer** +10 (1→11)
- neu: **Prometei** (5)
- ↑ **Formbook** +3 (2→5)
- neu: **AMOS** (4)
- ↓ **SalatStealer** -15 (18→3)
- neu: **SilentNet** (2)
- ↓ **WannaCry** -1 (2→1)
- ↓ **XWorm** -1 (2→1)
- weg: **NIKRAT** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +12 (23→35)
- ↑ **unbekannt** +2 (23→25)
- neu: **RustyStealer** (11)
- neu: **Prometei** (5)
- ↑ **Formbook** +3 (2→5)
- neu: **AMOS** (4)
- ↓ **SalatStealer** -13 (16→3)
- ↑ **SilentNet** +1 (1→2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.102 MB |
| σ Dateigröße | 6.078 MB |
| Ø Risiko-Score | 67.9/100 |
| Ø Klassifikations-Konfidenz | 71.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 42/101 |
| Eindeutige Familien | 19 |
| Eindeutige Tags | 72 |
| Unbekannte Familien | 9 (8.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 11:52 | [d2d641dfcfe6…](https://bazaar.abuse.ch/sample/d2d641dfcfe6893ec86978d7830bcf82f639006170c7247bca6258e21d52a091/) | `elf` | unbekannt | 43.4 | – | – | 🇺🇸US |
| 11:48 | [1c17f5aadfe1…](https://bazaar.abuse.ch/sample/1c17f5aadfe1bacde42360de099a0645a0a83669225296d9ba3d820567c040d5/) | `exe` | unbekannt | 82.2 | – | – | 🇳🇱NL |
| 11:40 | [b450c45831c1…](https://bazaar.abuse.ch/sample/b450c45831c106c26d340704801d3674fea392f8452203cee63f6a1985cf709e/) | `elf` | Prometei | 43.2 | – | – | 🇺🇸US |
| 11:40 | [981d0d0f5cae…](https://bazaar.abuse.ch/sample/981d0d0f5caeca27f9b03b0a32fe3ea68efac62e715776a73777ec8b20cdbb07/) | `exe` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 11:40 | [98007c5c1aec…](https://bazaar.abuse.ch/sample/98007c5c1aec882eff398b527fb9265d9e93e7216354e8b309db53998023db7e/) | `elf` | Mirai | 84.4 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 31.10.2026 11:53 UTC*