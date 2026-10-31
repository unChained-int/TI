# MalwareBazaar – 31.10.2026 17:00 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **71** |
| Höchster Score | **92.8/100** – c5418c52bdf33f70… |
| Häufigste Familie | **Mirai** (63x) |
| Häufigster Typ | **elf** (60x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 65 Samples |
| Ø Dateigröße | 2.08 MB (σ=4.70) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 60 | 59.4%  ███████████ |
| `jar` | 18 | 17.8%  ███ |
| `exe` | 10 | 9.9%  █ |
| `sh` | 7 | 6.9%  █ |
| `zip` | 2 | 2.0%   |
| `hta` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |
| `js` | 1 | 1.0%   |
| `rar` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 63 | 62.4% |
| 2 | unbekannt | 33 | 32.7% |
| 3 | Gh0stRAT | 1 | 1.0% |
| 4 | QuasarRAT | 1 | 1.0% |
| 5 | AokigaharaStealer | 1 | 1.0% |
| 6 | SilentNet | 1 | 1.0% |
| 7 | SalatStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 63 | 62.4% | 95% |
| Andere / Unbekannt | 22 | 21.8% | 20% |
| Infostealer | 7 | 6.9% | 74% |
| Linux-Malware | 4 | 4.0% | 45% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Backdoor | 1 | 1.0% | 95% |
| RAT | 1 | 1.0% | 95% |
| Loader | 1 | 1.0% | 75% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 71 | 70.3% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 5 | 5.0% |
| 🟢 NIEDRIG | 22 | 21.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c5418c52bdf33f…](https://bazaar.abuse.ch/sample/c5418c52bdf33f70aff9bcf014d3f10c4661a87ff2dbc8747feaa10415fc5e52/) | Gh0stRAT | Backdoor | **92.8** | 🔴 KRITISCH | – | – | ? |
| [9b151f4ffa4762…](https://bazaar.abuse.ch/sample/9b151f4ffa47622d8b0823c33dfb2471af4b619f1ef6296fbdb9089c076d5abf/) | QuasarRAT | RAT | **89.3** | 🔴 KRITISCH | – | – | ? |
| [82ea0074e950a5…](https://bazaar.abuse.ch/sample/82ea0074e950a589422046178545acaa950b5f0b61760630af27546741a02dfc/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [1b01265fc95eec…](https://bazaar.abuse.ch/sample/1b01265fc95eecf548211be11cb8708d63f774d92ca98be3d2edba6e6e1a7fc5/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [e6ffee9f550cf9…](https://bazaar.abuse.ch/sample/e6ffee9f550cf9d19dac0307e33361afdc86dba40049531f94a2228ded82aead/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [a4d39593428052…](https://bazaar.abuse.ch/sample/a4d3959342805223b2ebb945d27b5cb3fa9e6cbd3a191e6cac71cf6ba115b6ed/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [feb79fa2a9cb1f…](https://bazaar.abuse.ch/sample/feb79fa2a9cb1f4ae63cd40dcb9bf07af8c5d9c4b2846527ce2bad2c690b8ec1/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | 13.3% | 🟡 SCHWACH ERKANNT | ✗ |
| [41bfc8ee344029…](https://bazaar.abuse.ch/sample/41bfc8ee344029e37c3fa0930c96ce42509493a2dc8841d0c3cb34a0121641c4/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [f680f8115d7dd8…](https://bazaar.abuse.ch/sample/f680f8115d7dd82e7f4fa12e3d6c33858e19523f225e551854737188bd9f4420/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [fa4a4195abf22d…](https://bazaar.abuse.ch/sample/fa4a4195abf22d6b256dc05828e6c97bdd06c1840b47d7e9c2367071be14a5b1/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6284/7750 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6284/7750 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 5993/7750 |
| 6 | Kaspersky | 75.5% | 5853/7749 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5517/7746 |
| 9 | Rising | 68.3% | 5294/7750 |
| 10 | Varist | 66.2% | 5126/7745 |
| 11 | AVG | 65.2% | 5046/7745 |
| 12 | Avast | 65.1% | 5046/7746 |
| 13 | Tencent | 65.0% | 4888/7524 |
| 14 | McAfeeD | 61.3% | 4747/7742 |
| 15 | huorong | 60.9% | 4712/7742 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 67 | 66.3% |
| ❓ Unbekannt | 19 | 18.8% |
| 🪟 Windows | 11 | 10.9% |
| 📦 Archiv | 3 | 3.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 100 | 99.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 57 | 56.4% |
| 2 | 🇦🇹 AT | 16 | 15.8% |
| 3 | 🇳🇱 NL | 9 | 8.9% |
| 4 | 🇺🇸 US | 7 | 6.9% |
| 5 | 🇪🇸 ES | 6 | 5.9% |
| 6 | 🇫🇷 FR | 5 | 5.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 65 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 63 |
| Lateral Movement | 63 |
| Exfiltration | 2 |
| Command and Control | 1 |
| Credential Access | 1 |
| Collection | 1 |

<details><summary>9b151f4ffa47622d8b08… – QuasarRAT | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>82ea0074e950a5894220… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>1b01265fc95eecf54821… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>e6ffee9f550cf9d19dac… – Mirai | 🔴 KRITISCH 83.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9aa3787766dedfaa707e…](https://bazaar.abuse.ch/sample/9aa3787766dedfaa707e029d7426763de7acbbfee452d57dcce6a6ddbf65208d/)

- **Familie:** SilentNet
- **Erkannt von:** 49 von 75 Engines (65.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.Dacic.11262.5617CBBE
- **VT-Reputation:** -12
- **Microsoft Defender:** ✓ **JA** – `Generic.Dacic.11262.5617CBBE`

**Erkennende Engines (49/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Dacic.11262.5617CBBE` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Misc]` |
| AhnLab-V3 | `Malware/Win.Dacic.R765588` |
| Alibaba | `Trojan:Win64/Convagent.8304f2e2` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Arcabit | `Generic.Dacic.11262.5617CBBE` |
| Avast | `Win64:MalwareX-gen [Misc]` |
| Avira | `TR/W64.Agent` |
| BitDefender 🛡️ | `Generic.Dacic.11262.5617CBBE` |
| Bkav | `W32.Malware.5C0CE347` |
| CTX | `exe.unknown.dacic` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.DownLoader49.40340` |
| ESET-NOD32 | `Win64/FakeTool.C trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Generic.Dacic.11262.5617CBBE (B)` |
| F-Secure | `Trojan.TR/W64.Agent` |
| Fortinet | `W64/Agent.MCC!tr` |
| GData | `Generic.Dacic.11262.5617CBBE` |
| Gridinsoft | `Trojan.Win64.Agent.oa!s1` |
| Ikarus | `Trojan.Win64.Agent` |
| K7AntiVirus | `Riskware ( 00584baa1 )` |
| K7GW | `Riskware ( 00584baa1 )` |
| Kaspersky | `HEUR:Trojan.Win64.Convagent.gen` |
| Kingsoft | `Win64.Trojan.Convagent.gen` |
| Lionic | `Trojan.Win32.Dacic.4!c` |
| Malwarebytes | `Trojan.Loader` |
| McAfeeD | `Trojan:Win/Dacic.EBP` |
| MicroWorld-eScan | `Generic.Dacic.11262.5617CBBE` |
| Microsoft 🛡️ | `Trojan:Win64/Convagent.RVA!MTB` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Downloader.Agent/x64!1.1498F (CLASSIC)` |
| Sangfor | `Trojan.Win64.Convagent.Vr68` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.10c46679` |
| TrellixENS | `Artemis!5751FD485D69` |
| VIPRE | `Generic.Dacic.11262.5617CBBE` |
| Varist | `W64/ARisk.PQ` |
| ViRobot | `Trojan.Win.Z.Agent.1139712.AHR` |
| Webroot | `Win.Trojan.Gen` |
| Zillya | `Trojan.Agent.Win64.178605` |
| alibabacloud | `Trojan:Win/Convagent.RYZ2XJC` |
| huorong | `Backdoor/Agent.rv` |

### [21f464f4c72c3a424b62…](https://bazaar.abuse.ch/sample/21f464f4c72c3a424b62c71632360f209d4eb72be5bccc3d15918cf4146d81ad/)

- **Familie:** Mirai
- **Erkannt von:** 33 von 74 Engines (44.6%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40666856
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40666856`

**Erkennende Engines (33/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40666856` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE290` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Generic.D26C86E8` |
| Avast-Mobile | `ELF:Mirai-DAM [Trj]` |
| Avira | `TR/LINUX.Mirai.CFR` |
| BitDefender 🛡️ | `Trojan.Generic.40666856` |
| ClamAV | `Unix.Dropper.Mirai-7136288-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9810` |
| ESET-NOD32 | `Linux/Mirai.CGG trojan` |
| Emsisoft | `Trojan.Generic.40666856 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CFR` |
| Fortinet | `ELF/Mirai.CGG!tr` |
| GData | `Trojan.Generic.40666856` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| K7GW | `Trojan ( 0041109e1 )` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.hr` |
| Kingsoft | `Linux.CatDDos.elf.2023472` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| MicroWorld-eScan | `Trojan.Generic.40666856` |
| Microsoft 🛡️ | `Trojan:Win32/Leonem!rfn` |
| Rising | `Backdoor.Mirai/Linux!1.1271D (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Worm.Mirai!ATN` |
| Tencent | `Trojan.Linux.Mirai.zk` |
| VIPRE | `Trojan.Generic.40666856` |
| Varist | `E32/Mirai.DJ.gen!Camelot` |
| alibabacloud | `Trojan:Linux/Mirai.CHO` |
| huorong | `Backdoor/Linux.Mirai.gc` |

### [3841688a8c1044321b3c…](https://bazaar.abuse.ch/sample/3841688a8c1044321b3cf4c25331dcbce5d57817437c78b283d6828b6715976a/)

- **Familie:** Mirai
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unix.Trojan.Mirai-10012200-0
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| ClamAV | `Unix.Trojan.Mirai-10012200-0` |
| DrWeb | `Linux.Mirai.11295` |
| ESET-NOD32 | `Linux/Mirai.FNP trojan` |
| Fortinet | `ELF/Agent.BA!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Multiverze` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nx` |
| McAfeeD | `Trojan:Linux/Mirai.EQQ` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Tencent | `OB:Backdoor.Linux.Mirai.tnog` |
| Varist | `E32/Mirai.GE.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.np` |

### [feb79fa2a9cb1f4ae63c…](https://bazaar.abuse.ch/sample/feb79fa2a9cb1f4ae63cd40dcb9bf07af8c5d9c4b2846527ce2bad2c690b8ec1/)

- **Familie:** Mirai
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux/Mirai.FNP trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| DrWeb | `Linux.Mirai.11295` |
| ESET-NOD32 | `Linux/Mirai.FNP trojan` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nx` |
| McAfeeD | `Trojan:Linux/Mirai.ERC` |
| Tencent | `OB:Backdoor.Linux.Mirai.tnog` |
| Varist | `E32/Mirai.BK.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.np` |

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

- **elf** (60×)
- **Mirai** (59×)
- **Torii** (28×)
- **jar** (18×)
- **java** (16×)
- **python** (16×)
- **silentnet** (16×)
- **exe** (9×)
- **upx-dec** (8×)
- **sh** (7×)
- **upx** (6×)
- **signed** (3×)
- **stealer** (3×)
- **Warden** (3×)
- **WARDENStealer** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +39 (24→63)
- ↑ **unbekannt** +15 (18→33)
- neu: **Gh0stRAT** (1)
- neu: **QuasarRAT** (1)
- neu: **AokigaharaStealer** (1)
- neu: **SilentNet** (1)
- ↓ **SalatStealer** -13 (14→1)
- weg: **NIKRAT** (war 3)
- weg: **CoinMiner** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **Formbook** (war 3)
- weg: **Prometei** (war 2)
- weg: **XWorm** (war 2)
- weg: **WannaCry** (war 2)
- weg: **RustyStealer** (war 4)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +40 (23→63)
- ↑ **unbekannt** +11 (22→33)
- neu: **Gh0stRAT** (1)
- neu: **QuasarRAT** (1)
- neu: **AokigaharaStealer** (1)
- ↓ **SalatStealer** -15 (16→1)
- weg: **Formbook** (war 2)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.078 MB |
| σ Dateigröße | 4.703 MB |
| Ø Risiko-Score | 68.8/100 |
| Ø Klassifikations-Konfidenz | 74.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 65/101 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 45 |
| Unbekannte Familien | 22 (21.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 16:55 | [8cc8bf1f6441…](https://bazaar.abuse.ch/sample/8cc8bf1f64417890f7d4ebd7bce8ef55fbe724a70d8de9355bf027c92380c8eb/) | `hta` | unbekannt | 39.0 | – | – | 🇩🇪DE |
| 16:43 | [82ea0074e950…](https://bazaar.abuse.ch/sample/82ea0074e950a589422046178545acaa950b5f0b61760630af27546741a02dfc/) | `elf` | Mirai | 84.3 | – | – | 🇺🇸US |
| 16:40 | [c5418c52bdf3…](https://bazaar.abuse.ch/sample/c5418c52bdf33f70aff9bcf014d3f10c4661a87ff2dbc8747feaa10415fc5e52/) | `exe` | Gh0stRAT | 92.8 | – | – | 🇺🇸US |
| 16:35 | [1b01265fc95e…](https://bazaar.abuse.ch/sample/1b01265fc95eecf548211be11cb8708d63f774d92ca98be3d2edba6e6e1a7fc5/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 16:34 | [a2fa3be9c8bb…](https://bazaar.abuse.ch/sample/a2fa3be9c8bb41089d27885e686ea74f7250a54d8a3dd6613e0bbad94a92bd2e/) | `elf` | unbekannt | 43.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 31.10.2026 17:00 UTC*