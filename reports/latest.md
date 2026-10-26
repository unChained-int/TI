# MalwareBazaar – 26.10.2026 23:38 UTC

Dieser Run hat **71 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **72** |
| Kritisch (≥75) | **42** |
| Höchster Score | **88.8/100** – b3e93fda43d72109… |
| Häufigste Familie | **unbekannt** (33x) |
| Häufigster Typ | **elf** (43x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 32 Samples |
| Ø Dateigröße | 5.19 MB (σ=11.98) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 43 | 59.7%  ███████████ |
| `exe` | 13 | 18.1%  ███ |
| `apk` | 6 | 8.3%  █ |
| `zip` | 3 | 4.2%   |
| `sh` | 2 | 2.8%   |
| `gz` | 1 | 1.4%   |
| `msi` | 1 | 1.4%   |
| `vhdx` | 1 | 1.4%   |
| `js` | 1 | 1.4%   |
| `rar` | 1 | 1.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 33 | 45.8% |
| 2 | Mirai | 31 | 43.1% |
| 3 | RustyStealer | 2 | 2.8% |
| 4 | AveMariaRAT | 1 | 1.4% |
| 5 | Agent | 1 | 1.4% |
| 6 | AokigaharaStealer | 1 | 1.4% |
| 7 | QuantLoader | 1 | 1.4% |
| 8 | RedLineStealer | 1 | 1.4% |
| 9 | SalatStealer | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 33 | 45.8% | 94% |
| Linux-Malware | 10 | 13.9% | 45% |
| Infostealer | 9 | 12.5% | 76% |
| Loader | 9 | 12.5% | 75% |
| Andere / Unbekannt | 4 | 5.6% | 20% |
| Windows-Malware | 3 | 4.2% | 35% |
| RAT | 3 | 4.2% | 75% |
| Cryptominer | 1 | 1.4% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 42 | 58.3% |
| 🟠 HOCH | 13 | 18.1% |
| 🟡 MITTEL | 13 | 18.1% |
| 🟢 NIEDRIG | 4 | 5.6% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [b3e93fda43d721…](https://bazaar.abuse.ch/sample/b3e93fda43d72109f6d17cf6aa0fa6017db1f8ee9c237ec49083385bb0248bf5/) | RedLineStealer | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [8d6f4c7c0e52cb…](https://bazaar.abuse.ch/sample/8d6f4c7c0e52cb932f7802ca9417799843854b9ca1d380b24a9625fd7f3f7995/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [7242b14132c916…](https://bazaar.abuse.ch/sample/7242b14132c9169798dc74d7ecc44ab24940006ca631e45138d6d0b57f5187a3/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [367086805b221b…](https://bazaar.abuse.ch/sample/367086805b221bad037c6a781fdcc6c86498841f912157c5c8e391fa4dbb4031/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [05c458c702a87a…](https://bazaar.abuse.ch/sample/05c458c702a87a6c4e49077aa19fe9b6c408ff2dd11468c1dc02868e29789100/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [dd456414deb483…](https://bazaar.abuse.ch/sample/dd456414deb483efa5273e30b4137f8db33b22c193b661245de428f84aca7f41/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [524c7ea7afd578…](https://bazaar.abuse.ch/sample/524c7ea7afd5788e549f271a589c7ca000bbac0ca374fc9d1b809b477ae98e18/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [200827454b25a2…](https://bazaar.abuse.ch/sample/200827454b25a295ed2b4754bff86cc46bb2108a31947c30e64d1a7ea0fada00/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [c0b488bbda0c5a…](https://bazaar.abuse.ch/sample/c0b488bbda0c5a3e49449a98ac64bdf6b4757748f60f569cde4c10759a6f34b6/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [79da353594d81d…](https://bazaar.abuse.ch/sample/79da353594d81d29c74225f64df9807d37e0576ffe86b690901ad4ce4095b714/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6208/7658 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.1% | 6208/7658 |
| 3 | ESET-NOD32 | 77.2% | 5910/7658 |
| 4 | Kaspersky | 75.7% | 5796/7657 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5444/7655 |
| 8 | Rising | 68.3% | 5230/7658 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5065/7654 |
| 11 | Avast | 65.1% | 4983/7654 |
| 12 | AVG | 65.1% | 4983/7653 |
| 13 | Tencent | 64.9% | 4821/7432 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4685/7651 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 45 | 62.5% |
| 🪟 Windows | 14 | 19.4% |
| 🤖 Android | 6 | 8.3% |
| 📦 Archiv | 4 | 5.6% |
| ❓ Unbekannt | 3 | 4.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 63 | 87.5% |
| APK-Sideloading | 6 | 8.3% |
| MaaS-Loader | 1 | 1.4% |
| Trojanisierte Software | 1 | 1.4% |
| Drive-By / Exploit-Kit | 1 | 1.4% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 21 | 29.2% |
| 2 | 🇺🇸 US | 18 | 25.0% |
| 3 | 🇪🇸 ES | 16 | 22.2% |
| 4 | 🇭🇺 HU | 9 | 12.5% |
| 5 | 🇫🇷 FR | 4 | 5.6% |
| 6 | 🇨🇦 CA | 2 | 2.8% |
| 7 | 🇬🇧 GB | 1 | 1.4% |
| 8 | 🌐 Unbekannt | 1 | 1.4% |

## MITRE ATT&CK

> 32 von 72 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 31 |
| Lateral Movement | 31 |
| Credential Access | 1 |
| Collection | 1 |

<details><summary>b3e93fda43d72109f6d1… – RedLineStealer | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>8d6f4c7c0e52cb932f78… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>7242b14132c9169798dc… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>367086805b221bad037c… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>05c458c702a87a6c4e49… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9d5d1904302ed4eb81e1…](https://bazaar.abuse.ch/sample/9d5d1904302ed4eb81e113f453407217e3164067031b5113c7f955e42ca5ce8a/)

- **Familie:** Mirai
- **Erkannt von:** 32 von 75 Engines (42.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Cling.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Cling.1`

**Erkennende Engines (32/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Cling.1` |
| AVG | `ELF:Mirai-BYP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.Gafgyt.SE180` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Cling.1` |
| Avast | `ELF:Mirai-BYP [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.BYP` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Cling.1` |
| ClamAV | `Unix.Trojan.Mirai-7755770-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Fgt.6308` |
| ESET-NOD32 | `Linux/Mirai.AXA trojan` |
| Emsisoft | `Gen:Variant.Linux.Cling.1 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BYP` |
| Fortinet | `ELF/Mirai.9821!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gen` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| MicroWorld-eScan | `Gen:Variant.Linux.Cling.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.13A56 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!F46B3744058D` |
| Tencent | `Backdoor.Linux.Gafgyt.azb` |
| TrellixENS | `LINUX/Mirai-FQU!F46B3744058D` |
| VIPRE | `Gen:Variant.Linux.Cling.1` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [860d255074ca495bf5d5…](https://bazaar.abuse.ch/sample/860d255074ca495bf5d5fd4820d3a3f2fd47135bdafd1b5ed499f0096b04ebc8/)

- **Familie:** Agent
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Rootkit/Linux.Agent.h
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Avast-Mobile | `ELF:Miner-LO [PUP]` |
| DrWeb | `Tool.Linux.BtcMine.4901` |
| ESET-NOD32 | `Linux/CoinMiner.CP potentially unwanted application` |
| Google | `Detected` |
| Microsoft 🛡️ | `Trojan:Linux/CoinMiner.C12` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Hacktool.Linux.XMRigRk.Mnrra` |
| Varist | `E64/Coinminer.FW` |
| alibabacloud | `Miner:Multi/XmrigGo.SY` |
| huorong | `Rootkit/Linux.Agent.h` |

### [fdae1297014671ba62d8…](https://bazaar.abuse.ch/sample/fdae1297014671ba62d8ffe8c3ee13dc6a8234eb1c3a7d0f9ee0a7f19d190a06/)

- **Familie:** Mirai
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux.Generic.Threat
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Backdoor:Linux/Mirai.AW!xp`

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai.dx` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.AQY` |
| ClamAV | `Unix.Trojan.Mirai-7755770-0` |
| Cynet | `Malicious (score: 99)` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.AQY` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| huorong | `Trojan/Linux.Mirai.na` |

### [d43edaaf3f9d1d90668a…](https://bazaar.abuse.ch/sample/d43edaaf3f9d1d90668a3c870e9422dacbb76650bbb8e521bffdafb668a298a1/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux/Mirai.cx
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BYP [Trj]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-BYP [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.BYP` |
| ClamAV | `Unix.Trojan.Mirai-7755770-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Fgt.6308` |
| ESET-NOD32 | `Linux/Mirai.ATK trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BYP` |
| Fortinet | `ELF/Mirai.9821!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gen` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.HI!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.13A56 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Mirai.cx` |
| Tencent | `Trojan.Linux.Mirai.nk` |
| TrellixENS | `Linux/Mirai.cx` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [7e4c129f5bd09beffae1…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** SalatStealer
- **Erkannt von:** 44 von 75 Engines (58.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (44/75):**

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
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Malwarebytes | `Spyware.SalatStealer` |
| McAfeeD | `Real Protect-LS!9E7BE912AC3C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!9E7BE912AC3C` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9E7BE912AC3C` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **elf** (43×)
- **Mirai** (31×)
- **ddos** (14×)
- **jkl** (14×)
- **signed** (13×)
- **exe** (12×)
- **dropper** (8×)
- **apk** (6×)
- **Mparivahan** (6×)
- **DvnX** (4×)
- **stealer** (4×)
- **Warden** (4×)
- **WARDENStealer** (4×)
- **Yap** (4×)
- **YapStealer** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +18 (15→33)
- ↑ **Mirai** +17 (14→31)
- neu: **RustyStealer** (2)
- neu: **AveMariaRAT** (1)
- neu: **Agent** (1)
- neu: **AokigaharaStealer** (1)
- neu: **QuantLoader** (1)
- neu: **RedLineStealer** (1)
- ↓ **SalatStealer** -24 (25→1)
- weg: **RemcosRAT** (war 4)
- weg: **CoinMiner** (war 2)
- weg: **XWorm** (war 2)
- weg: **SilentNet** (war 6)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -1 (34→33)
- ↑ **Mirai** +12 (19→31)
- neu: **RustyStealer** (2)
- neu: **AveMariaRAT** (1)
- neu: **Agent** (1)
- neu: **AokigaharaStealer** (1)
- neu: **QuantLoader** (1)
- neu: **RedLineStealer** (1)
- ↓ **SalatStealer** -5 (6→1)
- weg: **CoinMiner** (war 3)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.192 MB |
| σ Dateigröße | 11.978 MB |
| Ø Risiko-Score | 70.2/100 |
| Ø Klassifikations-Konfidenz | 74.7% |
| Samples mit VT | 5/72 |
| Samples mit MITRE | 32/72 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 47 |
| Unbekannte Familien | 4 (5.6%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:22 | [69a0c89a1f4b…](https://bazaar.abuse.ch/sample/69a0c89a1f4b2805dfd85b003674186169afd29d9021245a44630ebfbf3708ca/) | `exe` | unbekannt | 82.0 | – | – | 🇺🇸US |
| 23:21 | [32227233bfaf…](https://bazaar.abuse.ch/sample/32227233bfaf1e4c4cd26ac665420bd16be281bd291be9c7b77274d70558631e/) | `exe` | unbekannt | 82.0 | – | – | 🇺🇸US |
| 23:21 | [d7f99e89d03a…](https://bazaar.abuse.ch/sample/d7f99e89d03a4c664ac78b468801d4b9323828bb92e9b8cbfe08a715038e9701/) | `exe` | unbekannt | 82.0 | – | – | 🇺🇸US |
| 23:21 | [d4bacbfd002a…](https://bazaar.abuse.ch/sample/d4bacbfd002a8f71fc4547e83fbf5af206fc8cb89ae49a660b176c982c3190b5/) | `exe` | unbekannt | 82.0 | – | – | 🇺🇸US |
| 23:17 | [090df03cf728…](https://bazaar.abuse.ch/sample/090df03cf728dacb6af8bb9cb4c7163afd32aadf83778cae71b96047e9c1aff8/) | `exe` | unbekannt | 38.8 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 26.10.2026 23:38 UTC*