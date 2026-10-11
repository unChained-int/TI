# MalwareBazaar – 11.10.2026 18:42 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ba0f697bbdbabdcb48c3…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **51** |
| Höchster Score | **95.9/100** – e8cfa9a30a3a9126… |
| Häufigste Familie | **unbekannt** (40x) |
| Häufigster Typ | **elf** (49x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 37 Samples |
| Ø Dateigröße | 3.64 MB (σ=15.52) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 49 | 48.5%  █████████ |
| `exe` | 21 | 20.8%  ████ |
| `js` | 17 | 16.8%  ███ |
| `vbs` | 4 | 4.0%   |
| `msi` | 3 | 3.0%   |
| `vbe` | 2 | 2.0%   |
| `jar` | 2 | 2.0%   |
| `zsh` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 40 | 39.6% |
| 2 | Mirai | 22 | 21.8% |
| 3 | LxBaseRAT | 6 | 5.9% |
| 4 | CoinMiner | 3 | 3.0% |
| 5 | Formbook | 3 | 3.0% |
| 6 | XWorm | 3 | 3.0% |
| 7 | ConnectWise | 3 | 3.0% |
| 8 | GuLoader | 2 | 2.0% |
| 9 | SalatStealer | 2 | 2.0% |
| 10 | AgentTesla | 2 | 2.0% |
| 11 | AsyncRAT | 2 | 2.0% |
| 12 | RemcosRAT | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Linux-Malware | 25 | 24.8% | 45% |
| Botnet/IoT | 23 | 22.8% | 95% |
| RAT | 16 | 15.8% | 86% |
| Loader | 11 | 10.9% | 79% |
| Infostealer | 10 | 9.9% | 85% |
| Windows-Malware | 5 | 5.0% | 35% |
| Skript/Dropper | 5 | 5.0% | 35% |
| Cryptominer | 2 | 2.0% | 75% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Ransomware | 1 | 1.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 51 | 50.5% |
| 🟠 HOCH | 13 | 12.9% |
| 🟡 MITTEL | 35 | 34.7% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [e8cfa9a30a3a91…](https://bazaar.abuse.ch/sample/e8cfa9a30a3a91265ef0c1854ccf055befacdb8370aebc166f111cc4f40c01ff/) | WannaCry | Ransomware | **95.9** | 🔴 KRITISCH | – | – | ? |
| [2d54bf055e8791…](https://bazaar.abuse.ch/sample/2d54bf055e8791b01f58eadb2926dd4ddad3646d6ebdd92073b6b29c5c8ec2de/) | NanoCore | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [f9a4f06efdd969…](https://bazaar.abuse.ch/sample/f9a4f06efdd9694b895b3150d44ba0cbf6957a65a11dd9c6388314b399fde4af/) | XWorm | RAT | **88.4** | 🔴 KRITISCH | 5.3% | ⚠️ KAUM ERKANNT | ✗ |
| [08efd83b4e438b…](https://bazaar.abuse.ch/sample/08efd83b4e438b8e6c0911111d90bf30eb2164ffdb89c27d37e63ed80125179b/) | Vidar | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [aa3e272241995c…](https://bazaar.abuse.ch/sample/aa3e272241995ceb22e7b70239b1d010482af721ce7c6ac6bde70c5cfb3e156a/) | LummaStealer | Infostealer | **88.1** | 🔴 KRITISCH | – | – | ? |
| [b387422d5a21b9…](https://bazaar.abuse.ch/sample/b387422d5a21b9ee9dc1f992b110415ce3754ede1ccc4ae73ba4dc7e7ae533cd/) | Formbook | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [10f5d2271f4111…](https://bazaar.abuse.ch/sample/10f5d2271f411156d72f9f3a900716c6e555cb04d5fde57c9756c91d86410e84/) | Formbook | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [192822c60fb8e1…](https://bazaar.abuse.ch/sample/192822c60fb8e1c5decb4c4c99c2a26ae3d05b7e7887e5c720bdc4d25280e0cf/) | Formbook | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [82c614f3781d07…](https://bazaar.abuse.ch/sample/82c614f3781d0706d862e0f9f0a51db025fecbcaeb74107d060f6c4a0f6ad24c/) | QuasarRAT | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [1be153b2200554…](https://bazaar.abuse.ch/sample/1be153b2200554bd42cf7ac42337c4e88e5583e664ad2ec415af80219f133c0d/) | XWorm | RAT | **87.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5922/7322 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5922/7322 |
| 3 | ESET-NOD32 | 77.4% | 5665/7322 |
| 4 | Kaspersky | 76.3% | 5586/7321 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5241/7319 |
| 8 | Rising | 68.7% | 5029/7322 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4866/7318 |
| 11 | Tencent | 65.2% | 4626/7096 |
| 12 | Avast | 65.0% | 4759/7318 |
| 13 | AVG | 65.0% | 4759/7317 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.4% | 4489/7315 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 50 | 49.5% |
| 🪟 Windows | 29 | 28.7% |
| ❓ Unbekannt | 20 | 19.8% |
| 🍎 macOS | 1 | 1.0% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 68 | 67.3% |
| Drive-By / Exploit-Kit | 19 | 18.8% |
| MaaS-Loader | 6 | 5.9% |
| C2 / Nachladen | 3 | 3.0% |
| Trojanisierte Software | 3 | 3.0% |
| Exploit / N-Day | 1 | 1.0% |
| USB / Wechselmedium | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 43 | 42.6% |
| 2 | 🇸🇪 SE | 27 | 26.7% |
| 3 | 🇳🇱 NL | 18 | 17.8% |
| 4 | 🇺🇸 US | 9 | 8.9% |
| 5 | 🇦🇹 AT | 2 | 2.0% |
| 6 | 🇪🇸 ES | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 37 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 22 |
| Lateral Movement | 22 |
| Command and Control | 7 |
| Collection | 7 |
| Credential Access | 6 |
| Execution | 4 |
| Exfiltration | 3 |
| Defense Evasion | 2 |
| Impact | 2 |

<details><summary>08efd83b4e438b8e6c09… – Vidar | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>aa3e272241995ceb22e7… – LummaStealer | 🔴 KRITISCH 88.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [89e789b6ab36ca4d1f2b…](https://bazaar.abuse.ch/sample/89e789b6ab36ca4d1f2bd055e5675920abd0430ba5870830da035ab65e0dcf83/)

- **Familie:** Mirai
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Svirtu-AA [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Svirtu-AA [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Svirtu-AA [Trj]` |
| Avast-Mobile | `ELF:Svirtu-AA [Trj]` |
| Avira | `TR/LINUX.Svirtu.AA` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Rootkit.420` |
| ESET-NOD32 | `Linux/Mirai.FLQ trojan` |
| F-Secure | `Trojan.TR/LINUX.Svirtu.AA` |
| Fortinet | `ELF/MALD2.9BA9!tr` |
| Google | `Detected` |
| Ikarus | `LINUX.Siggen` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jp` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.DDoS.pa` |
| Varist | `E32/Mirai.BMN` |
| huorong | `Trojan/Linux.Mirai.mq` |

### [73c2ada67ca2fc3c0694…](https://bazaar.abuse.ch/sample/73c2ada67ca2fc3c0694f13c0d648c69cca08c99609f921472dc0b103aa09c2b/)

- **Familie:** Mirai
- **Erkannt von:** 41 von 75 Engines (54.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Formbook.1611
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Formbook.1611`

**Erkennende Engines (41/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Formbook.1611` |
| AVG | `ELF:Mirai-BDU [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen8` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Formbook.D64B` |
| Avast | `ELF:Mirai-BDU [Trj]` |
| Avast-Mobile | `ELF:Mirai-COW [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| BitDefender 🛡️ | `Trojan.Formbook.1611` |
| CTX | `elf.trojan.formbook` |
| ClamAV | `Unix.Dropper.Mirai-7135890-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.BC trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Formbook.1611 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `ELF/Mirai.AT!tr.botnet` |
| GData | `Trojan.Formbook.1611` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| MicroWorld-eScan | `Trojan.Formbook.1611` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.FO!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FRS!54A932B048C3` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Trojan.Linux.Mirai.zf` |
| TrellixENS | `LINUX/Mirai-FRS!54A932B048C3` |
| TrendMicro | `Backdoor.Linux.GAFGYT.SMMR3` |
| TrendMicro-HouseCall | `Backdoor.Linux.GAFGYT.SMMR3` |
| VBA32 | `Trojan.Linux.Floodr.L36.0160ad` |
| VIPRE | `Trojan.Formbook.1611` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.ji` |

### [7b8068f2d8d64dc4c0b9…](https://bazaar.abuse.ch/sample/7b8068f2d8d64dc4c0b958d4ad4cbc89f008d2c6d036f38a0a759e061384459e/)

- **Familie:** Mirai
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-ERA [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ERA [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Gafgyt` |
| Avast | `ELF:Agent-ERA [Trj]` |
| Avira | `TR/LINUX.Agent.ERA` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3022` |
| ESET-NOD32 | `Linux/Mirai.FFA trojan` |
| F-Secure | `Trojan.TR/LINUX.Agent.ERA` |
| Fortinet | `ELF/Agent.ERA!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nf` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Tencent | `Backdoor.Linux.Mirai.zytra` |
| Varist | `E32/Mirai.NV1.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.bj!crit` |

### [f9a4f06efdd9694b895b…](https://bazaar.abuse.ch/sample/f9a4f06efdd9694b895b3150d44ba0cbf6957a65a11dd9c6388314b399fde4af/)

- **Familie:** XWorm
- **Erkannt von:** 4 von 75 Engines (5.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** NetWorm ( 0053c52c1 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `VBS/TrojanDownloader.Agent.ADMR trojan` |
| K7AntiVirus | `NetWorm ( 0053c52c1 )` |
| K7GW | `NetWorm ( 0053c52c1 )` |
| Kaspersky | `HEUR:Trojan.Script.Agent.gen` |

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

- **elf** (49×)
- **exe** (21×)
- **Mirai** (19×)
- **js** (17×)
- **LxBaseRAT** (6×)
- **upx-dec** (5×)
- **upx** (5×)
- **RAT** (5×)
- **vbs** (4×)
- **dropper** (3×)
- **RemcosRAT** (3×)
- **CoinMiner** (3×)
- **salat** (3×)
- **Agent** (3×)
- **Formbook** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +20 (20→40)
- ↓ **Mirai** -29 (51→22)
- neu: **LxBaseRAT** (6)
- neu: **CoinMiner** (3)
- neu: **Formbook** (3)
- neu: **XWorm** (3)
- ↑ **ConnectWise** +2 (1→3)
- neu: **GuLoader** (2)
- neu: **SalatStealer** (2)
- neu: **AgentTesla** (2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +10 (30→40)
- ↓ **Mirai** -17 (39→22)
- neu: **LxBaseRAT** (6)
- neu: **CoinMiner** (3)
- ↑ **Formbook** +2 (1→3)
- ↑ **XWorm** +2 (1→3)
- ↑ **ConnectWise** +1 (2→3)
- neu: **GuLoader** (2)
- neu: **SalatStealer** (2)
- ↑ **AgentTesla** +1 (1→2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.641 MB |
| σ Dateigröße | 15.519 MB |
| Ø Risiko-Score | 66.3/100 |
| Ø Klassifikations-Konfidenz | 70.3% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 37/101 |
| Eindeutige Familien | 22 |
| Eindeutige Tags | 77 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 18:38 | [6de8efa3180e…](https://bazaar.abuse.ch/sample/6de8efa3180e82cb89d2dec05e9a53bc4c550ebccb409a47d0d96cd7031edb7e/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |
| 18:37 | [5655e53f6a28…](https://bazaar.abuse.ch/sample/5655e53f6a281d93905e93ed321bcebbb4cab8d69695ca1f142c31c26cd1ef6d/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 18:37 | [7efb76468a62…](https://bazaar.abuse.ch/sample/7efb76468a62a765fbd452a08c1fa475ea43149ed474b486b3d80312418ca16d/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 18:33 | [2acbf2703c28…](https://bazaar.abuse.ch/sample/2acbf2703c28ed594a9b34027bb28b10bfb4ac617ae6c32ab34513a4c3c2b716/) | `elf` | unbekannt | 43.2 | – | – | 🇩🇪DE |
| 18:33 | [f9359bfd7a69…](https://bazaar.abuse.ch/sample/f9359bfd7a69e44f85d5a0546c1f6475d5a944e66c46c0b55e7509501a148e4c/) | `elf` | unbekannt | 43.2 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 11.10.2026 18:42 UTC*