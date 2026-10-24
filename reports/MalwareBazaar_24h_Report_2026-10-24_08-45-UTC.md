# MalwareBazaar – 24.10.2026 08:45 UTC

Dieser Run hat **37 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **38** |
| Kritisch (≥75) | **19** |
| Höchster Score | **90.6/100** – 25463b3ae1b55115… |
| Häufigste Familie | **unbekannt** (13x) |
| Häufigster Typ | **elf** (20x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 14 Samples |
| Ø Dateigröße | 5.48 MB (σ=10.06) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 20 | 52.6%  ██████████ |
| `exe` | 6 | 15.8%  ███ |
| `apk` | 3 | 7.9%  █ |
| `zip` | 3 | 7.9%  █ |
| `js` | 2 | 5.3%  █ |
| `vbs` | 1 | 2.6%   |
| `msi` | 1 | 2.6%   |
| `sh` | 1 | 2.6%   |
| `macho` | 1 | 2.6%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 13 | 34.2% |
| 2 | Mirai | 12 | 31.6% |
| 3 | CoinMiner | 2 | 5.3% |
| 4 | Grandoreiro | 2 | 5.3% |
| 5 | Vidar | 1 | 2.6% |
| 6 | IRATA | 1 | 2.6% |
| 7 | ValleyRAT | 1 | 2.6% |
| 8 | RemusStealer | 1 | 2.6% |
| 9 | ConnectWise | 1 | 2.6% |
| 10 | AsyncRAT | 1 | 2.6% |
| 11 | AMOS | 1 | 2.6% |
| 12 | Linux | 1 | 2.6% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 13 | 34.2% | 93% |
| Linux-Malware | 6 | 15.8% | 45% |
| Infostealer | 4 | 10.5% | 85% |
| Skript/Dropper | 3 | 7.9% | 35% |
| RAT | 3 | 7.9% | 82% |
| Windows-Malware | 3 | 7.9% | 35% |
| Android-Malware | 2 | 5.3% | 45% |
| Cryptominer | 2 | 5.3% | 75% |
| Andere / Unbekannt | 1 | 2.6% | 20% |
| Trojaner | 1 | 2.6% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 19 | 50.0% |
| 🟠 HOCH | 4 | 10.5% |
| 🟡 MITTEL | 13 | 34.2% |
| 🟢 NIEDRIG | 2 | 5.3% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [25463b3ae1b551…](https://bazaar.abuse.ch/sample/25463b3ae1b55115cb4da56fffa9f90857938523533f592d78ef5ebcd02560c3/) | Vidar | Infostealer | **90.6** | 🔴 KRITISCH | – | – | ? |
| [06a3833ccb61fe…](https://bazaar.abuse.ch/sample/06a3833ccb61fe1dea39f628f1425524fd865c05a850aaf12da84bca23713292/) | AMOS | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [ad6484135f0edf…](https://bazaar.abuse.ch/sample/ad6484135f0edf919f0e145d417b2a21f08b8ee3dd8dae2c6eb7259f36630b6c/) | AsyncRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [eeedb1bb012596…](https://bazaar.abuse.ch/sample/eeedb1bb01259665f76a6feff5196014c3678d90576a7a9141f038425fc90289/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [03c3e15399556a…](https://bazaar.abuse.ch/sample/03c3e15399556a5ac0a6d87bba2ac53e73b29e976ea3e818068392ade56284bc/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [b30e531a2a01c7…](https://bazaar.abuse.ch/sample/b30e531a2a01c77d2877c7634966254bf882e1c98e12d8c5e1fadc5e55677554/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [4cd746c8908fd0…](https://bazaar.abuse.ch/sample/4cd746c8908fd0e64bdc0cd788c64cfa61e6291e12af020a2eabf6f227fe74d9/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [075661075b4e05…](https://bazaar.abuse.ch/sample/075661075b4e05b4d770af74b7a21378c258e58c1925e08858c3fd4d9ee4de4b/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [b21ee4481a3b00…](https://bazaar.abuse.ch/sample/b21ee4481a3b008cd03b944fffd2d4353cf9465e2da710ce48b7ca8bae07471d/) | Mirai | Botnet/IoT | **81.8** | 🔴 KRITISCH | – | – | ? |
| [e23bf4e96123bc…](https://bazaar.abuse.ch/sample/e23bf4e96123bc438e63cf53a0e4e4a56bc90645c95d34f9b9f189df31d5db58/) | RemusStealer | Infostealer | **81.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6152/7597 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6152/7597 |
| 3 | ESET-NOD32 | 77.2% | 5865/7597 |
| 4 | Kaspersky | 75.9% | 5767/7596 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5404/7594 |
| 8 | Rising | 68.4% | 5194/7597 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5028/7593 |
| 11 | Avast | 65.1% | 4944/7593 |
| 12 | AVG | 65.1% | 4944/7592 |
| 13 | Tencent | 64.9% | 4783/7371 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4648/7590 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 21 | 55.3% |
| 🪟 Windows | 8 | 21.1% |
| 🤖 Android | 3 | 7.9% |
| 📦 Archiv | 3 | 7.9% |
| ❓ Unbekannt | 2 | 5.3% |
| 🍎 macOS | 1 | 2.6% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 32 | 84.2% |
| APK-Sideloading | 3 | 7.9% |
| Drive-By / Exploit-Kit | 2 | 5.3% |
| Trojanisierte Software | 1 | 2.6% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 18 | 47.4% |
| 2 | 🇺🇸 US | 8 | 21.1% |
| 3 | 🇨🇭 CH | 3 | 7.9% |
| 4 | 🇮🇳 IN | 3 | 7.9% |
| 5 | 🇳🇱 NL | 2 | 5.3% |
| 6 | 🇭🇺 HU | 1 | 2.6% |
| 7 | 🇷🇴 RO | 1 | 2.6% |
| 8 | 🌐 TH | 1 | 2.6% |
| 9 | 🌐 Unbekannt | 1 | 2.6% |

## MITRE ATT&CK

> 14 von 38 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 12 |
| Lateral Movement | 12 |
| Credential Access | 1 |
| Collection | 1 |
| Exfiltration | 1 |
| Command and Control | 1 |
| Execution | 1 |

<details><summary>25463b3ae1b55115cb4d… – Vidar | 🔴 KRITISCH 90.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>ad6484135f0edf919f0e… – AsyncRAT | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>eeedb1bb01259665f76a… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>03c3e15399556a5ac0a6… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [cf0d767d3898178b6a60…](https://bazaar.abuse.ch/sample/cf0d767d3898178b6a6026d9b258c26ead143aa5505350f0d729d986c86f4ccb/)

- **Familie:** Mirai
- **Erkannt von:** 34 von 75 Engines (45.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (34/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Mirai-COW [Trj]` |
| AhnLab-V3 | `Linux/Mirai13.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Mirai-COW [Trj]` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Mirai-9951087-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10541` |
| ESET-NOD32 | `Linux/Mirai.CXF trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.IA!tr.botnet` |
| GData | `Trojan.Linux.Mirai.1` |
| Google | `Detected` |
| Ikarus | `Trojan.Malware` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| McAfeeD | `Trojan:Script/Mirai.EBP` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.CC!xp` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-JBMX!30B21BBC8AE4` |
| Tencent | `Trojan.Linux.Mirai.zf` |
| TrellixENS | `LINUX/Mirai-JBMX!30B21BBC8AE4` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Mirai.DM.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.dh` |

### [1f4073e35d783d9c00eb…](https://bazaar.abuse.ch/sample/1f4073e35d783d9c00eb4a3c91aa327f976135d34d99c3af55325e2a94ecf34f/)

- **Familie:** Mirai
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Mirai-ALC [Trj]` |
| AhnLab-V3 | `Linux/Mirai17.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Mirai-ALC [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Mirai-9951087-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10541` |
| ESET-NOD32 | `Linux/Mirai.CXF trojan` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| GData | `Linux.Trojan.Mirai.G` |
| Google | `Detected` |
| Ikarus | `Linux.AVI.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| McAfeeD | `Trojan:Script/Mirai.EBP` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.DY!MTB` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (C64:YzY0Oklhyk3HVF6X)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Skyhigh | `LINUX/Mirai-JBMX!5FD45B7479A2` |
| Tencent | `Backdoor.Linux.Mirai.wav` |
| TrellixENS | `LINUX/Mirai-JBMX!5FD45B7479A2` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Mirai.BW.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.dh` |

### [044cebdeef95d9d4eb09…](https://bazaar.abuse.ch/sample/044cebdeef95d9d4eb098e63499c06663de5d3e791a6c1553170847f41f80321/)

- **Familie:** Linux
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** UDS:Backdoor.Linux.Mirai.gen
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Kaspersky | `UDS:Backdoor.Linux.Mirai.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |

### [ba44d153f9a5892c3899…](https://bazaar.abuse.ch/sample/ba44d153f9a5892c3899d36549a83c7d955579e265389c47ec7c840b73926787/)

- **Familie:** Mirai
- **Erkannt von:** 42 von 75 Engines (56.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Generic.40035649
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.40035649`

**Erkennende Engines (42/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.40035649` |
| AVG | `ELF:CVE-2017-17215-A [Expl]` |
| AhnLab-V3 | `Trojan/Linux.Mirai.SE306` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Generic.D262E541` |
| Avast | `ELF:CVE-2017-17215-A [Expl]` |
| Avast-Mobile | `ELF:Mirai-UM [Trj]` |
| Avira | `EXP/ELF.Gafgyt.Z.A` |
| BitDefender 🛡️ | `Trojan.Generic.40035649` |
| CTX | `elf.trojan.generic` |
| ClamAV | `Unix.Trojan.Mirai-7135937-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.BR trojan` |
| Elastic | `Linux.Exploit.CVE.2017.17215` |
| Emsisoft | `Trojan.Generic.40035649 (B)` |
| F-Secure | `Exploit.EXP/ELF.Gafgyt.Z.A` |
| Fortinet | `ELF/Mirai.AT!tr` |
| GData | `Trojan.Generic.40035649` |
| Google | `Detected` |
| Gridinsoft | `Susp.U.XOREncoded.sd!yf` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.dx` |
| Kingsoft | `Linux.Backdoor.Mirai.dx` |
| Lionic | `Trojan.Linux.Mirai.K!c` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `ti!BA44D153F9A5` |
| MicroWorld-eScan | `Trojan.Generic.40035649` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.BR!xp` |
| Rising | `Exploit.CVE-2017-17215!1.103D2 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Mirai-FQVY!3518EB01ECC6` |
| Sophos | `Linux/Mirai-O` |
| Symantec | `Linux.Gafgyt` |
| Tencent | `Backdoor.Linux.Mirai.waz` |
| TrellixENS | `Linux/Mirai-FQVY!3518EB01ECC6` |
| TrendMicro | `Trojan.Linux.MIRAI.SMMR1` |
| TrendMicro-HouseCall | `Trojan.Linux.MIRAI.SMMR1` |
| VIPRE | `Trojan.Generic.40035649` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| ZoneAlarm | `Linux/Mirai-O` |
| huorong | `Backdoor/Linux.Mirai.y` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Qwexlafiba!rfn`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.qwexlafiba` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7GW | `Hacktool ( a007e0071 )` |
| Kingsoft | `Win32.Troj.qwexlafiba.v` |
| Malwarebytes | `Trojan.Injector` |
| MaxSecure | `Trojan.Malware.727547498.susgen` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **elf** (20×)
- **Mirai** (12×)
- **exe** (5×)
- **signed** (3×)
- **Prometei** (3×)
- **apk** (3×)
- **SHAPARAK** (3×)
- **zip** (3×)
- **js** (2×)
- **CoinMiner** (2×)
- **upx-dec** (2×)
- **upx** (2×)
- **geo** (2×)
- **Grandoreiro** (2×)
- **MEX** (2×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -12 (25→13)
- ↓ **Mirai** -6 (18→12)
- neu: **CoinMiner** (2)
- neu: **Grandoreiro** (2)
- neu: **IRATA** (1)
- neu: **ValleyRAT** (1)
- neu: **RemusStealer** (1)
- neu: **ConnectWise** (1)
- neu: **AsyncRAT** (1)
- weg: **RemcosRAT** (war 2)
- weg: **Formbook** (war 2)
- weg: **SalatStealer** (war 3)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -26 (39→13)
- ↓ **Mirai** -9 (21→12)
- ↓ **CoinMiner** -1 (3→2)
- neu: **Grandoreiro** (2)
- neu: **Vidar** (1)
- neu: **IRATA** (1)
- neu: **ValleyRAT** (1)
- neu: **ConnectWise** (1)
- neu: **AsyncRAT** (1)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.477 MB |
| σ Dateigröße | 10.055 MB |
| Ø Risiko-Score | 63.6/100 |
| Ø Klassifikations-Konfidenz | 68.3% |
| Samples mit VT | 5/38 |
| Samples mit MITRE | 14/38 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 35 |
| Unbekannte Familien | 1 (2.6%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 08:33 | [25463b3ae1b5…](https://bazaar.abuse.ch/sample/25463b3ae1b55115cb4da56fffa9f90857938523533f592d78ef5ebcd02560c3/) | `exe` | Vidar | 90.6 | – | – | 🌐CH |
| 08:28 | [eeedb1bb0125…](https://bazaar.abuse.ch/sample/eeedb1bb01259665f76a6feff5196014c3678d90576a7a9141f038425fc90289/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 08:25 | [03c3e1539955…](https://bazaar.abuse.ch/sample/03c3e15399556a5ac0a6d87bba2ac53e73b29e976ea3e818068392ade56284bc/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 08:05 | [2934ae46e272…](https://bazaar.abuse.ch/sample/2934ae46e2726453e6a411e898e7d9a986ab3b8c4622e873e65a383d398f1e3f/) | `js` | unbekannt | 38.5 | – | – | 🇺🇸US |
| 08:03 | [425469176c41…](https://bazaar.abuse.ch/sample/425469176c41994bc33ce0582948798875f5c9682b7d0967c925a10f813e1a3d/) | `apk` | IRATA | 80.6 | – | – | 🇮🇳IN |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 24.10.2026 08:45 UTC*