# MalwareBazaar – 11.10.2026 04:46 UTC

Dieser Run hat **53 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ba0f697bbdbabdcb48c3…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **54** |
| Kritisch (≥75) | **43** |
| Höchster Score | **89.4/100** – 92a4bdc95e0d9920… |
| Häufigste Familie | **Mirai** (37x) |
| Häufigster Typ | **elf** (40x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 39 Samples |
| Ø Dateigröße | 1.04 MB (σ=1.77) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 40 | 74.1%  ██████████████ |
| `exe` | 8 | 14.8%  ██ |
| `dll` | 2 | 3.7%   |
| `macho` | 2 | 3.7%   |
| `sh` | 1 | 1.9%   |
| `msi` | 1 | 1.9%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 37 | 68.5% |
| 2 | unbekannt | 7 | 13.0% |
| 3 | VShell | 4 | 7.4% |
| 4 | AMOS | 2 | 3.7% |
| 5 | QuasarRAT | 1 | 1.9% |
| 6 | AsyncRAT | 1 | 1.9% |
| 7 | Prometei | 1 | 1.9% |
| 8 | ConnectWise | 1 | 1.9% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 37 | 68.5% | 95% |
| Windows-Malware | 6 | 11.1% | 35% |
| Infostealer | 4 | 7.4% | 85% |
| RAT | 2 | 3.7% | 95% |
| Linux-Malware | 2 | 3.7% | 45% |
| Trojaner | 2 | 3.7% | 65% |
| Andere / Unbekannt | 1 | 1.9% | 20% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 43 | 79.6% |
| 🟠 HOCH | 2 | 3.7% |
| 🟡 MITTEL | 8 | 14.8% |
| 🟢 NIEDRIG | 1 | 1.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [92a4bdc95e0d99…](https://bazaar.abuse.ch/sample/92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480/) | QuasarRAT | RAT | **89.4** | 🔴 KRITISCH | – | – | ? |
| [2a0bc1efd509f7…](https://bazaar.abuse.ch/sample/2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a/) | AsyncRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [e2605e9e08fa9f…](https://bazaar.abuse.ch/sample/e2605e9e08fa9f7b1cc23497fec745f290a97a212cc7056c87459544325ac048/) | AMOS | Infostealer | **87.7** | 🔴 KRITISCH | – | – | ? |
| [8d4fc1e1797743…](https://bazaar.abuse.ch/sample/8d4fc1e1797743dec4c00583dfe989820eb3c2785cf414feaaf440e54719bd6b/) | AMOS | Infostealer | **86.9** | 🔴 KRITISCH | – | – | ? |
| [5f924d5b8e190e…](https://bazaar.abuse.ch/sample/5f924d5b8e190ee9022fc821ee30bfbc0d91c7c8a96bac1a8d2cefc1c3878321/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [093e027a709e90…](https://bazaar.abuse.ch/sample/093e027a709e90916e7a15076711c5a07674b2a29f742632e4e2b3a85c2de581/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [47fa5cd944239c…](https://bazaar.abuse.ch/sample/47fa5cd944239c76582ab0956582fef2367a33392d02bbd10535edc012cd9c2e/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |
| [ddaadef14a9fd7…](https://bazaar.abuse.ch/sample/ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755/) | Mirai | Botnet/IoT | **82.2** | 🔴 KRITISCH | – | – | ? |
| [ba268ec991a555…](https://bazaar.abuse.ch/sample/ba268ec991a555c7e30325c4d88102c174d56657422b0ace511fa153658e803a/) | Mirai | Botnet/IoT | **82.2** | 🔴 KRITISCH | – | – | ? |
| [d0f2273f828b10…](https://bazaar.abuse.ch/sample/d0f2273f828b10391adcf877ff0775924e4b63435ec240b1047d89a1fa95a229/) | unbekannt | Infostealer | **82.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5913/7312 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5913/7312 |
| 3 | ESET-NOD32 | 77.4% | 5656/7312 |
| 4 | Kaspersky | 76.3% | 5577/7311 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5233/7309 |
| 8 | Rising | 68.7% | 5021/7312 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4858/7308 |
| 11 | Tencent | 65.2% | 4618/7086 |
| 12 | Avast | 65.0% | 4752/7308 |
| 13 | AVG | 65.0% | 4752/7307 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4483/7305 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 45 | 83.3% |
| 🪟 Windows | 7 | 13.0% |
| 🍎 macOS | 2 | 3.7% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 50 | 92.6% |
| MaaS-Loader | 3 | 5.6% |
| Trojanisierte Software | 1 | 1.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 35 | 64.8% |
| 2 | 🇺🇸 US | 13 | 24.1% |
| 3 | 🌐 Unbekannt | 2 | 3.7% |
| 4 | 🇸🇬 SG | 2 | 3.7% |
| 5 | 🇧🇷 BR | 1 | 1.9% |
| 6 | 🇳🇱 NL | 1 | 1.9% |

## MITRE ATT&CK

> 39 von 54 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 37 |
| Lateral Movement | 37 |
| Command and Control | 2 |
| Exfiltration | 1 |
| Execution | 1 |

<details><summary>92a4bdc95e0d99200c7e… – QuasarRAT | 🔴 KRITISCH 89.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>2a0bc1efd509f72273c3… – AsyncRAT | 🔴 KRITISCH 87.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>5f924d5b8e190ee9022f… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [102bfe850243f122aa9b…](https://bazaar.abuse.ch/sample/102bfe850243f122aa9bf9066c113d1832b7bec6547de230e5f084da5ef8121b/)

- **Familie:** Mirai
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Possible_MIRAI.SMLBRA52
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-DMS [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-DMS [Trj]` |
| Avira | `TR/LINUX.Mirai.DMS` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9829` |
| ESET-NOD32 | `Linux/DDoS.Agent.LJ trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DMS` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `OB:Trojan.Linux.Mirai.Gfyra` |
| TrendMicro | `Possible_MIRAI.SMLBRA52` |
| TrendMicro-HouseCall | `Possible_MIRAI.SMLBRA52` |
| huorong | `Trojan/Linux.Mirai.l!crit` |

### [09f9c15779c888660864…](https://bazaar.abuse.ch/sample/09f9c15779c888660864160eed3892e172c3df47a6a5110b0ae708a9af178ac0/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Possible_MIRAI.SMLBRA52
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-DMS [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-DMS [Trj]` |
| Avira | `TR/LINUX.Mirai.DMS` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9829` |
| ESET-NOD32 | `Linux/DDoS.Agent.LJ trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DMS` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `OB:Trojan.Linux.Mirai.Gfyra` |
| TrendMicro | `Possible_MIRAI.SMLBRA52` |
| TrendMicro-HouseCall | `Possible_MIRAI.SMLBRA52` |
| Varist | `E32/Mirai.DK.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.jg` |

### [d9c5e1e5042f02a7ae9b…](https://bazaar.abuse.ch/sample/d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb/)

- **Familie:** Prometei
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Prometei.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Prometei.5`

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Prometei.5` |
| AVG | `ELF:Prometei-E [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Prometei.5` |
| Avast | `ELF:Prometei-E [Trj]` |
| Avira | `TR/LINUX.Prometei.E` |
| BitDefender 🛡️ | `Trojan.Linux.Prometei.5` |
| CTX | `elf.trojan.prometei` |
| ClamAV | `Unix.Trojan.Prometei-10045451-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Emsisoft | `Trojan.Linux.Prometei.5 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.E` |
| Fortinet | `ELF/Prometei.12!tr` |
| GData | `Trojan.Linux.Prometei.5` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| MicroWorld-eScan | `Trojan.Linux.Prometei.5` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Prometei.5` |
| huorong | `Trojan/Prometei.c` |

### [8f700d2eeb4574e5aec6…](https://bazaar.abuse.ch/sample/8f700d2eeb4574e5aec68dcbf8c396df582723e1cd57ac16c8c32b1570b19da2/)

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
| Elastic | `Linux.Exploit.CVE.2018.10562` |
| F-Secure | `Exploit.EXP/LINUX.CVE-2026-.A` |
| Google | `Detected` |
| Ikarus | `Exploit.Linux.DirtyFrag` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.mu` |
| McAfeeD | `Trojan:Script/Dirtyfrag.EAD` |
| Microsoft 🛡️ | `Exploit:Linux/DirtyFrag.B` |
| Rising | `Backdoor.Mirai!1.146E0 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wz` |
| huorong | `Trojan/Linux.Mirai.f` |

### [ba0f697bbdbabdcb48c3…](https://bazaar.abuse.ch/sample/ba0f697bbdbabdcb48c377aec31dd6c9e09041e952f9903a23a06866cdcdbb88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81674645
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81674645`

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81674645` |
| Arcabit | `Trojan.Generic.D4DE4195` |
| BitDefender 🛡️ | `Trojan.GenericKD.81674645` |
| CTX | `msi.remote-access-trojan.connectwise` |
| DrWeb | `Program.RemoteAdmin.975` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.V potentially unsafe application` |
| Emsisoft | `Trojan.GenericKD.81674645 (B)` |
| Fortinet | `Riskware/RemoteAdmin_ConnectWiseControl` |
| GData | `Trojan.GenericKD.81674645` |
| Google | `Detected` |
| Ikarus | `PUA.ConnectWise` |
| Kaspersky | `not-a-virus:UDS:RemoteAdmin.MSIL.ConnectWise.gen` |
| Lionic | `Riskware.Win32.ConnectWise.1!c` |
| McAfeeD | `ti!BA0F697BBDBA` |
| MicroWorld-eScan | `Trojan.GenericKD.81674645` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| NANO-Antivirus | `Riskware.Win32.RemoteAdmin.ljylbz` |
| Rising | `Hacktool.ConnectWise!8.13A88 (CLOUD)` |
| Skyhigh | `ConnectWise` |
| Symantec | `PUA.Gen.2` |
| Tencent | `Msil.Trojan.Connectwise.Nsmw` |
| TrellixENS | `ConnectWise` |
| VBA32 | `Riskware.MSIL.ScreenConnect.Heur` |
| VIPRE | `Trojan.GenericKD.81674645` |
| Varist | `W32/ConnectWise.X.gen!Eldorado` |
| alibabacloud | `Backdoor[rat]:Win/RemoteAdmin.CafpcxiOBisDuBBYsU` |


## Top Tags

- **elf** (40×)
- **Mirai** (36×)
- **exe** (8×)
- **VShell** (4×)
- **dll** (3×)
- **stage** (2×)
- **x86-64** (2×)
- **AMOS** (2×)
- **ClickFix** (2×)
- **Foxveil** (2×)
- **loader** (2×)
- **Mach-O** (2×)
- **macho** (2×)
- **macOS** (2×)
- **ABE-bypass** (1×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -17 (54→37)
- ↓ **unbekannt** -22 (29→7)
- ↑ **VShell** +1 (3→4)
- neu: **AMOS** (2)
- neu: **QuasarRAT** (1)
- neu: **AsyncRAT** (1)
- neu: **Prometei** (1)
- ↓ **ConnectWise** -1 (2→1)
- weg: **SilentNet** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -25 (32→7)
- ↑ **VShell** +3 (1→4)
- neu: **AMOS** (2)
- neu: **QuasarRAT** (1)
- neu: **Prometei** (1)
- ↓ **ConnectWise** -1 (2→1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.039 MB |
| σ Dateigröße | 1.770 MB |
| Ø Risiko-Score | 74.0/100 |
| Ø Klassifikations-Konfidenz | 83.2% |
| Samples mit VT | 5/54 |
| Samples mit MITRE | 39/54 |
| Eindeutige Familien | 8 |
| Eindeutige Tags | 33 |
| Unbekannte Familien | 1 (1.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 04:40 | [d0f2273f828b…](https://bazaar.abuse.ch/sample/d0f2273f828b10391adcf877ff0775924e4b63435ec240b1047d89a1fa95a229/) | `exe` | unbekannt | 82.1 | – | – | 🇺🇸US |
| 04:21 | [5f924d5b8e19…](https://bazaar.abuse.ch/sample/5f924d5b8e190ee9022fc821ee30bfbc0d91c7c8a96bac1a8d2cefc1c3878321/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 04:21 | [92a4bdc95e0d…](https://bazaar.abuse.ch/sample/92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480/) | `exe` | QuasarRAT | 89.4 | – | – | 🇺🇸US |
| 04:17 | [093e027a709e…](https://bazaar.abuse.ch/sample/093e027a709e90916e7a15076711c5a07674b2a29f742632e4e2b3a85c2de581/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 04:11 | [85dfe92b4373…](https://bazaar.abuse.ch/sample/85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9/) | `exe` | unbekannt | 81.7 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 11.10.2026 04:46 UTC*