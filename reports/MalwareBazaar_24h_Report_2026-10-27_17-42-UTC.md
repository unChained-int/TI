# MalwareBazaar – 27.10.2026 17:42 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **76** |
| Höchster Score | **89.3/100** – 4cde1a56605bb940… |
| Häufigste Familie | **Mirai** (68x) |
| Häufigster Typ | **elf** (78x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 72 Samples |
| Ø Dateigröße | 0.64 MB (σ=1.50) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 78 | 77.2%  ███████████████ |
| `exe` | 8 | 7.9%  █ |
| `js` | 6 | 5.9%  █ |
| `sh` | 3 | 3.0%   |
| `jar` | 2 | 2.0%   |
| `ps1` | 1 | 1.0%   |
| `lnk` | 1 | 1.0%   |
| `hta` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 68 | 67.3% |
| 2 | unbekannt | 15 | 14.9% |
| 3 | SilentNet | 4 | 4.0% |
| 4 | CoinMiner | 3 | 3.0% |
| 5 | Formbook | 2 | 2.0% |
| 6 | njrat | 1 | 1.0% |
| 7 | Linux | 1 | 1.0% |
| 8 | AgentTesla | 1 | 1.0% |
| 9 | PureLogsStealer | 1 | 1.0% |
| 10 | XWorm | 1 | 1.0% |
| 11 | GuLoader | 1 | 1.0% |
| 12 | LxBaseRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 68 | 67.3% | 95% |
| Linux-Malware | 8 | 7.9% | 45% |
| Infostealer | 5 | 5.0% | 85% |
| Andere / Unbekannt | 4 | 4.0% | 20% |
| Loader | 4 | 4.0% | 78% |
| Windows-Malware | 4 | 4.0% | 35% |
| RAT | 3 | 3.0% | 88% |
| Cryptominer | 3 | 3.0% | 75% |
| Skript/Dropper | 2 | 2.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 76 | 75.2% |
| 🟠 HOCH | 7 | 6.9% |
| 🟡 MITTEL | 14 | 13.9% |
| 🟢 NIEDRIG | 4 | 4.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [4cde1a56605bb9…](https://bazaar.abuse.ch/sample/4cde1a56605bb940e269953430cad45fc0e5046ca48f39a4f03029fb7c8c0f58/) | Formbook | Infostealer | **89.3** | 🔴 KRITISCH | – | – | ? |
| [49acbf8b7dc914…](https://bazaar.abuse.ch/sample/49acbf8b7dc91464fb534b3dcf02f7c027115351edf9a985b182325f9ba45a73/) | njrat | RAT | **89.2** | 🔴 KRITISCH | – | – | ? |
| [2a6ebbac8400cd…](https://bazaar.abuse.ch/sample/2a6ebbac8400cd351b992216a02eea3927be2d5debdbb12f14cefd976475536f/) | Formbook | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [bd1c28603a4fae…](https://bazaar.abuse.ch/sample/bd1c28603a4fae25b60dc7263c88ffcc7fc14f1cf2cac5143d5bfa786b151433/) | AMOS | Infostealer | **88.8** | 🔴 KRITISCH | – | – | ? |
| [9df32476518c69…](https://bazaar.abuse.ch/sample/9df32476518c6949c433cf535d985a7d99b78b9f5f850feb2213909437c0d62b/) | XWorm | RAT | **88.3** | 🔴 KRITISCH | – | – | ? |
| [0005299abc319e…](https://bazaar.abuse.ch/sample/0005299abc319e5180c5fc9609775583ecc8ca56ddc02153ff14c05b68736a47/) | Mirai | Botnet/IoT | **85.5** | 🔴 KRITISCH | 5.3% | ⚠️ KAUM ERKANNT | ✗ |
| [e4c06ccb0fbba7…](https://bazaar.abuse.ch/sample/e4c06ccb0fbba7ac6282769c7cff777426006981d615c9b4f48df6b70570050e/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [3343bc0e390fd7…](https://bazaar.abuse.ch/sample/3343bc0e390fd74b53966ea235970de4fcb3bfc9166fdc9d1843fbddce5c359d/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [1b387e71de84b6…](https://bazaar.abuse.ch/sample/1b387e71de84b6e3645d14282f80732b97c61999bfc1cbbd78b146b9c40c80c2/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [7103dd5f95bdbb…](https://bazaar.abuse.ch/sample/7103dd5f95bdbb985cdf9692e97c5c0322860746ade53e3f847856e6c814e08f/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6218/7672 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6218/7672 |
| 3 | ESET-NOD32 | 77.2% | 5922/7672 |
| 4 | Kaspersky | 75.6% | 5798/7671 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5455/7669 |
| 8 | Rising | 68.3% | 5239/7672 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5075/7668 |
| 11 | Avast | 65.1% | 4992/7668 |
| 12 | AVG | 65.1% | 4992/7667 |
| 13 | Tencent | 64.9% | 4831/7446 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4692/7665 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 81 | 80.2% |
| 🪟 Windows | 11 | 10.9% |
| ❓ Unbekannt | 8 | 7.9% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 93 | 92.1% |
| Drive-By / Exploit-Kit | 6 | 5.9% |
| MaaS-Loader | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 39 | 38.6% |
| 2 | 🇪🇸 ES | 33 | 32.7% |
| 3 | 🇳🇱 NL | 8 | 7.9% |
| 4 | 🇸🇪 SE | 7 | 6.9% |
| 5 | 🇦🇹 AT | 5 | 5.0% |
| 6 | 🇺🇸 US | 3 | 3.0% |
| 7 | 🇫🇷 FR | 2 | 2.0% |
| 8 | 🇭🇺 HU | 2 | 2.0% |
| 9 | 🇬🇧 GB | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 72 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 68 |
| Lateral Movement | 68 |
| Collection | 3 |
| Credential Access | 2 |
| Command and Control | 1 |
| Defense Evasion | 1 |
| Execution | 1 |

<details><summary>4cde1a56605bb940e269… – Formbook | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>49acbf8b7dc91464fb53… – njrat | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>2a6ebbac8400cd351b99… – Formbook | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [deb0cdd422ff5a4736f3…](https://bazaar.abuse.ch/sample/deb0cdd422ff5a4736f32d0f1fe8cb7593bc63c26cdc0748801e7edc9e6dbe79/)

- **Familie:** Mirai
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-BYP [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BYP [Trj]` |
| Antiy-AVL | `Trojan/Linux.Mirai.a` |
| Avast | `ELF:Mirai-BYP [Trj]` |
| Avast-Mobile | `ELF:Mirai-AQY [Trj]` |
| Avira | `TR/LINUX.Mirai.BYP` |
| ClamAV | `Unix.Trojan.Mirai-7755770-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9821` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Trojan.TR/LINUX.Mirai.BYP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gen` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| Rising | `Backdoor.Mirai/Linux!1.13A56 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Trojan.Linux.Mirai.nk` |
| huorong | `Trojan/Linux.Mirai.na` |

### [61124c99ef9a8c11e210…](https://bazaar.abuse.ch/sample/61124c99ef9a8c11e210bf59439a31d985b9c964e4de2e4ce8f00ff71491ad65/)

- **Familie:** Linux
- **Erkannt von:** 36 von 75 Engines (48.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.Linux.Medusa.C.B4D3011C
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Generic.Linux.Medusa.C.B4D3011C`

**Erkennende Engines (36/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Linux.Medusa.C.B4D3011C` |
| AVG | `BV:Downloader-AAN [Drp]` |
| AhnLab-V3 | `Downloader/Shell.Generic.S1650` |
| Arcabit | `Generic.Linux.Medusa.C.B4D3011C` |
| Avast | `BV:Downloader-AAN [Drp]` |
| Avira | `HTML/ExpKit.Gen2` |
| BitDefender 🛡️ | `Generic.Linux.Medusa.C.B4D3011C` |
| CAT-QuickHeal | `Trojan.Shell.Downloader.39008` |
| CTX | `script.unknown.medusa` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2424` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.BFM trojan` |
| Emsisoft | `Generic.Linux.Medusa.C.B4D3011C (B)` |
| F-Secure | `Malware.HTML/ExpKit.Gen2` |
| Fortinet | `BASH/Dloader.P!tr` |
| GData | `Generic.Linux.Medusa.C.B4D3011C` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Sh` |
| K7GW | `Trojan ( 004102a21 )` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.p` |
| MicroWorld-eScan | `Generic.Linux.Medusa.C.B4D3011C` |
| Microsoft 🛡️ | `TrojanDownloader:Linux/ShWg.YB!MTB` |
| NANO-Antivirus | `Trojan.Script.Downloader.fjajjs` |
| Rising | `Downloader.Agent/BASH!1.DB4B (CLASSIC)` |
| Sangfor | `Virus.Generic-Script.Save.ba1` |
| Skyhigh | `Linux/Downloader.w` |
| Sophos | `Mal/ShellDl-A` |
| Symantec | `CL.Downloader!gen277` |
| Tencent | `Heur:Trojan.Linux.Downloader.e` |
| TrellixENS | `Linux/Downloader.w` |
| TrendMicro | `ELF_MIRAILOD.SM` |
| TrendMicro-HouseCall | `ELF_MIRAILOD.SM` |
| VIPRE | `Generic.Linux.Medusa.C.B4D3011C` |
| Varist | `SH/Mirai.A.gen!Camelot` |
| ZoneAlarm | `Mal/ShellDl-A` |
| huorong | `Trojan/BAT.Obfuscated.aar!crit` |

### [9fa061a2a90c76666b98…](https://bazaar.abuse.ch/sample/9fa061a2a90c76666b98a8b17c868ddcabc49f1a148127841d6b7b42ff3a8c2a/)

- **Familie:** CoinMiner
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux/CoinMiner.CP potentially unwanted application
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

### [0005299abc319e5180c5…](https://bazaar.abuse.ch/sample/0005299abc319e5180c5fc9609775583ecc8ca56ddc02153ff14c05b68736a47/)

- **Familie:** Mirai
- **Erkannt von:** 4 von 75 Engines (5.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/DDoS.Agent.LT trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `Linux.Mirai.9808` |
| ESET-NOD32 | `Linux/DDoS.Agent.LT trojan` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| huorong | `Trojan/Linux.DDos.ds` |

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

- **elf** (78×)
- **ddos** (33×)
- **jkl** (33×)
- **mirai** (33×)
- **Mirai** (28×)
- **exe** (7×)
- **upx-dec** (7×)
- **upx** (7×)
- **js** (6×)
- **python** (5×)
- **silentnet** (5×)
- **sh** (3×)
- **CoinMiner** (3×)
- **dropped-by-OffLoader** (2×)
- **jar** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +40 (28→68)
- ↓ **unbekannt** -13 (28→15)
- ↓ **SilentNet** -2 (6→4)
- neu: **CoinMiner** (3)
- neu: **Formbook** (2)
- neu: **njrat** (1)
- neu: **Linux** (1)
- neu: **AgentTesla** (1)
- neu: **PureLogsStealer** (1)
- weg: **ConnectWise** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +49 (19→68)
- ↓ **unbekannt** -17 (32→15)
- ↑ **SilentNet** +3 (1→4)
- ↑ **Formbook** +1 (1→2)
- neu: **njrat** (1)
- neu: **Linux** (1)
- neu: **AgentTesla** (1)
- neu: **PureLogsStealer** (1)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 0.640 MB |
| σ Dateigröße | 1.504 MB |
| Ø Risiko-Score | 74.2/100 |
| Ø Klassifikations-Konfidenz | 82.5% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 72/101 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 34 |
| Unbekannte Familien | 4 (4.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:21 | [18c502b5ed9d…](https://bazaar.abuse.ch/sample/18c502b5ed9dd34710989d51ff0e7efd289987662803ac9f0703466123e25561/) | `sh` | unbekannt | 32.4 | – | – | 🇩🇪DE |
| 17:18 | [e4c06ccb0fbb…](https://bazaar.abuse.ch/sample/e4c06ccb0fbba7ac6282769c7cff777426006981d615c9b4f48df6b70570050e/) | `elf` | Mirai | 84.2 | – | – | 🌐ES |
| 17:18 | [deb0cdd422ff…](https://bazaar.abuse.ch/sample/deb0cdd422ff5a4736f32d0f1fe8cb7593bc63c26cdc0748801e7edc9e6dbe79/) | `elf` | Mirai | 81.7 | 26.7% | 🟡 SCHWACH ERKANNT | 🌐ES |
| 17:18 | [3343bc0e390f…](https://bazaar.abuse.ch/sample/3343bc0e390fd74b53966ea235970de4fcb3bfc9166fdc9d1843fbddce5c359d/) | `elf` | Mirai | 84.2 | – | – | 🌐ES |
| 17:18 | [1b387e71de84…](https://bazaar.abuse.ch/sample/1b387e71de84b6e3645d14282f80732b97c61999bfc1cbbd78b146b9c40c80c2/) | `elf` | Mirai | 84.2 | – | – | 🌐ES |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 27.10.2026 17:42 UTC*