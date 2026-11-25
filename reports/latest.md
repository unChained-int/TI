# MalwareBazaar – 25.11.2026 02:00 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **58** |
| Höchster Score | **88.6/100** – 7b27d53d810025a2… |
| Häufigste Familie | **unbekannt** (36x) |
| Häufigster Typ | **elf** (65x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 30 Samples |
| Ø Dateigröße | 2.43 MB (σ=4.36) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 65 | 64.4%  ████████████ |
| `exe` | 22 | 21.8%  ████ |
| `macho` | 6 | 5.9%  █ |
| `msi` | 3 | 3.0%   |
| `sh` | 2 | 2.0%   |
| `vbs` | 2 | 2.0%   |
| `dll` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 36 | 35.6% |
| 2 | Mirai | 22 | 21.8% |
| 3 | Snowlight | 20 | 19.8% |
| 4 | Prometei | 7 | 6.9% |
| 5 | ConnectWise | 5 | 5.0% |
| 6 | GuLoader | 2 | 2.0% |
| 7 | BTN trojan | 1 | 1.0% |
| 8 | Tofsee | 1 | 1.0% |
| 9 | DCRat | 1 | 1.0% |
| 10 | AnyDesk | 1 | 1.0% |
| 11 | WARDENStealer | 1 | 1.0% |
| 12 | GCleaner | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 26 | 25.7% | 76% |
| Botnet/IoT | 25 | 24.8% | 93% |
| Linux-Malware | 25 | 24.8% | 45% |
| Windows-Malware | 12 | 11.9% | 35% |
| Infostealer | 7 | 6.9% | 78% |
| Loader | 4 | 4.0% | 85% |
| Trojaner | 2 | 2.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 58 | 57.4% |
| 🟠 HOCH | 6 | 5.9% |
| 🟡 MITTEL | 37 | 36.6% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [7b27d53d810025…](https://bazaar.abuse.ch/sample/7b27d53d810025a2120511a5e2fda33a7ea0f894899d018aba3407f73a3ea6f0/) | DCRat | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [8da8e118f9b760…](https://bazaar.abuse.ch/sample/8da8e118f9b760f33418dba61c2090d292f3d521a0c35e12ca5dec6e4f616339/) | Vidar | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [87af310107024a…](https://bazaar.abuse.ch/sample/87af310107024ad4d93e30276895614478afb6864943afe71fecbe9ad186db8c/) | njrat | RAT | **87.5** | 🔴 KRITISCH | – | – | ? |
| [b364931817bf01…](https://bazaar.abuse.ch/sample/b364931817bf01a007008ac74595028707a098a18961ae2a014020161e6e5dca/) | BTN trojan | RAT | **84.0** | 🔴 KRITISCH | 6.8% | ⚠️ KAUM ERKANNT | ✗ |
| [dee6b58c120562…](https://bazaar.abuse.ch/sample/dee6b58c120562685044d1108e963c39cfd9cecec71049299a0fe68d693674e8/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [92cfa7882645a3…](https://bazaar.abuse.ch/sample/92cfa7882645a36b371574142e321b0cb73000fb9de82afd529fe39ab81858dc/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [b569e7605005ca…](https://bazaar.abuse.ch/sample/b569e7605005ca5dc2dc04df9888fba9fdfdebbbba8c1155df144feea99a8af2/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [a66a06c091b519…](https://bazaar.abuse.ch/sample/a66a06c091b5192648537785579f2a086628c42b489d1e74837fdb548e74ad82/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [854ada6fe51d0b…](https://bazaar.abuse.ch/sample/854ada6fe51d0bf5b6cec49770335316e5b97873a19c6f761642243bbbe6149d/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [d4c7820789c63a…](https://bazaar.abuse.ch/sample/d4c7820789c63a75cf27fcd53a286ff6613d259946cf5d6825f90fdafbef03ec/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6599/8128 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6599/8128 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6295/8128 |
| 6 | Kaspersky | 75.6% | 6146/8127 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5790/8124 |
| 9 | Rising | 68.6% | 5576/8128 |
| 10 | Varist | 66.1% | 5368/8123 |
| 11 | Tencent | 65.2% | 5154/7902 |
| 12 | Avast | 65.2% | 5298/8124 |
| 13 | AVG | 65.2% | 5298/8123 |
| 14 | McAfeeD | 61.4% | 4988/8120 |
| 15 | huorong | 61.0% | 4956/8120 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 73 | 72.3% |
| 🪟 Windows | 27 | 26.7% |
| 📦 Archiv | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 89 | 88.1% |
| C2 / Nachladen | 6 | 5.9% |
| Trojanisierte Software | 3 | 3.0% |
| Drive-By / Exploit-Kit | 2 | 2.0% |
| MaaS-Loader | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 57 | 56.4% |
| 2 | 🇩🇪 DE | 18 | 17.8% |
| 3 | 🇫🇷 FR | 18 | 17.8% |
| 4 | 🇳🇱 NL | 3 | 3.0% |
| 5 | 🇨🇭 CH | 2 | 2.0% |
| 6 | 🇭🇺 HU | 1 | 1.0% |
| 7 | 🇸🇬 SG | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 30 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 25 |
| Lateral Movement | 25 |
| Collection | 3 |
| Defense Evasion | 2 |
| Execution | 2 |
| Credential Access | 2 |
| Exfiltration | 2 |
| Command and Control | 1 |

<details><summary>8da8e118f9b760f33418… – Vidar | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>87af310107024ad4d93e… – njrat | 🔴 KRITISCH 87.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>dee6b58c120562685044… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b364931817bf01a00700…](https://bazaar.abuse.ch/sample/b364931817bf01a007008ac74595028707a098a18961ae2a014020161e6e5dca/)

- **Familie:** BTN trojan
- **Erkannt von:** 5 von 74 Engines (6.8%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTN trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BTN trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Trojan.Agent/Linux!8.13268 (TFE:14:LukKB9f4rHJ)` |
| Tencent | `Malware.Linux.Generic.1c0ccd3e` |

### [7656180aa16e4b27c31e…](https://bazaar.abuse.ch/sample/7656180aa16e4b27c31e67f101ec9ee956295551b202f41007368d0f940ea280/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 73 Engines (35.6%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Downloader-BP [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/73):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| AhnLab-V3 | `Backdoor/Linux.VShell.XE272` |
| Antiy-AVL | `Trojan/Linux.SAgnt` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avira | `TR/LINUX.Downloade.BP` |
| ClamAV | `Unix.Downloader.Generic-10032902-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2270` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.emw` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.AT!MTB` |
| Rising | `Backdoor.VShell/Linux!1.1312B (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCQS!1250D7458154` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| VBA32 | `Trojan.Elf64.Agent` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Shell.ew` |

### [20b0dfbd5078bcec058e…](https://bazaar.abuse.ch/sample/20b0dfbd5078bcec058e44295d27b2e26b044bcd546e51802982e0d08fcfce19/)

- **Familie:** AnyDesk
- **Erkannt von:** 15 von 74 Engines (20.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepTool [RATool]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `FileRepTool [RATool]` |
| Avast | `FileRepTool [RATool]` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (high confidence)` |
| Lionic | `Trojan.Win32.Agent.tt9V` |
| MaxSecure | `Trojan.Malware.8328611.susgen` |
| Paloalto | `generic.ml` |
| Sangfor | `Suspicious.Win32.Save.ins` |
| TrellixENS | `Artemis!FA8012510E54` |
| TrendMicro-HouseCall | `Trojan.Win32.Gen.TL0101K526YH` |
| VBA32 | `Trojan.Agent` |

### [ee8c8607928d026a78ba…](https://bazaar.abuse.ch/sample/ee8c8607928d026a78ba163827e927666cf1cc1ce67ecc63194172592b016eab/)

- **Familie:** Yogi
- **Erkannt von:** 43 von 74 Engines (58.1%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.142606
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.142606`

**Erkennende Engines (43/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Cerbu.292667` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Pws]` |
| AhnLab-V3 | `Trojan/Win.Cerbu.C5980768` |
| Antiy-AVL | `Trojan/Win32.Convagent` |
| Arcabit | `Trojan.Yogi.D22D0E` |
| Avast | `Win64:MalwareX-gen [Pws]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.142606` |
| Bkav | `W32.Malware.7826DDEC` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Vidar.P trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.142606 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/Vidar.M!tr` |
| GData | `Gen:Variant.Yogi.142606` |
| K7AntiVirus | `Riskware ( 00584baa1 )` |
| K7GW | `Riskware ( 00584baa1 )` |
| Kaspersky | `UDS:Trojan.Win32.Agentb` |
| Kingsoft | `Win32.Trojan.Agentb.gen` |
| Lionic | `Trojan.Win32.Convagent.4!c` |
| Malwarebytes | `Malware.Heuristic.2062` |
| MaxSecure | `Trojan.W32.191126.Convagent.a.swat.YR` |
| McAfeeD | `ti!EE8C8607928D` |
| MicroWorld-eScan | `Gen:Variant.Yogi.142606` |
| Microsoft 🛡️ | `Trojan:Win32/Egairtigado!rfn` |
| Paloalto | `generic.ml` |
| Rising | `Spyware.Stealer!8.3090 (TFE:4:WQBWERM16OT)` |
| Sangfor | `Infostealer.Win64.Vidar.Vt7p` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan.W64.Fwnw` |
| TrellixENS | `Artemis!AFBE0756D71C` |
| VIPRE | `Gen:Variant.Yogi.142606` |
| VirIT | `Trojan.Win64.GenusT.GCLJ` |
| alibabacloud | `Trojan:Win/Vidar.P` |
| huorong | `HVM:TrojanSpy/W64.Stealer.a` |

### [c7937a0589cfc76c51ef…](https://bazaar.abuse.ch/sample/c7937a0589cfc76c51ef46b2f4e5b5d7e3da42bf01740baebe5e3d45c8cb0b88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 29 von 74 Engines (39.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Suschil!rfn`

**Erkennende Engines (29/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `RiskWare[RemoteAdmin]/MSIL.ConnectWise` |
| Bkav | `W32.Malware.CE6D6E6` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Win32.Trojan.Agent.TQDT4J` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| Lionic | `Trojan.Win32.ConnectWise.4!c` |
| Malwarebytes | `RiskWare.ConnectWise.Abused` |
| Microsoft 🛡️ | `Trojan:Win32/Suschil!rfn` |
| NANO-Antivirus | `Trojan.Win32.Drop.llafhv` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H06K926` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |


## Top Tags

- **elf** (65×)
- **Mirai** (25×)
- **RAT** (24×)
- **Rust** (24×)
- **EasyShell** (23×)
- **SnoopyTriage** (23×)
- **exe** (22×)
- **Snowlight** (20×)
- **Torii** (11×)
- **Prometei** (7×)
- **dropped-by-GCleaner** (7×)
- **macho** (6×)
- **stealer** (5×)
- **ConnectWise** (4×)
- **msi** (3×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -4 (40→36)
- ↑ **Mirai** +14 (8→22)
- ↑ **Snowlight** +10 (10→20)
- ↑ **Prometei** +6 (1→7)
- ↑ **ConnectWise** +1 (4→5)
- neu: **GuLoader** (2)
- neu: **BTN trojan** (1)
- neu: **Tofsee** (1)
- neu: **DCRat** (1)
- neu: **AnyDesk** (1)
- weg: **VShell** (war 2)
- weg: **EasyShell** (war 10)
- weg: **CatStorm** (war 6)
- weg: **RemcosRAT** (war 5)
- weg: **Formbook** (war 4)
- weg: **BotenaGo** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +1 (35→36)
- ↓ **Mirai** -8 (30→22)
- ↑ **Snowlight** +17 (3→20)
- ↑ **Prometei** +2 (5→7)
- ↑ **ConnectWise** +4 (1→5)
- neu: **GuLoader** (2)
- neu: **BTN trojan** (1)
- neu: **Tofsee** (1)
- neu: **DCRat** (1)
- neu: **AnyDesk** (1)
- weg: **RemcosRAT** (war 2)
- weg: **EasyShell** (war 4)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.428 MB |
| σ Dateigröße | 4.361 MB |
| Ø Risiko-Score | 65.9/100 |
| Ø Klassifikations-Konfidenz | 67.9% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 30/101 |
| Eindeutige Familien | 15 |
| Eindeutige Tags | 43 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 01:08 | [dee6b58c1205…](https://bazaar.abuse.ch/sample/dee6b58c120562685044d1108e963c39cfd9cecec71049299a0fe68d693674e8/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 01:06 | [11d9b9588c56…](https://bazaar.abuse.ch/sample/11d9b9588c5639aa98b84dffc0ae6ac6c332c79542456e30651cd335a84fd222/) | `elf` | unbekannt | 80.5 | – | – | 🇫🇷FR |
| 01:06 | [79dce3a8d5ad…](https://bazaar.abuse.ch/sample/79dce3a8d5ad620967936c7a262a314c98d84730765690009e1e71be40fe5602/) | `elf` | unbekannt | 80.5 | – | – | 🇫🇷FR |
| 01:06 | [bbf98cac2fb4…](https://bazaar.abuse.ch/sample/bbf98cac2fb4bc732c95441e7109c494bae517742c9ca50cffa90c5788338e0c/) | `elf` | unbekannt | 80.5 | – | – | 🇺🇸US |
| 01:05 | [149d38c3057c…](https://bazaar.abuse.ch/sample/149d38c3057c6365072a6ed7f1fd63706a927a8c8e38d0d9e2938c576df4950c/) | `macho` | unbekannt | 80.5 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 25.11.2026 02:00 UTC*