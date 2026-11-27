# MalwareBazaar – 27.11.2026 17:56 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **27** |
| Höchster Score | **91.6/100** – bf6d80bf56f0e3bd… |
| Häufigste Familie | **unbekannt** (66x) |
| Häufigster Typ | **exe** (41x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 16 Samples |
| Ø Dateigröße | 3.71 MB (σ=13.76) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 41 | 40.6%  ████████ |
| `elf` | 27 | 26.7%  █████ |
| `zip` | 16 | 15.8%  ███ |
| `sh` | 5 | 5.0%   |
| `ps1` | 4 | 4.0%   |
| `jar` | 2 | 2.0%   |
| `js` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |
| `gz` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 66 | 65.3% |
| 2 | Mirai | 14 | 13.9% |
| 3 | WARDENStealer | 4 | 4.0% |
| 4 | CatStorm | 3 | 3.0% |
| 5 | CoinMiner | 2 | 2.0% |
| 6 | Gafgyt | 2 | 2.0% |
| 7 | Hajime | 2 | 2.0% |
| 8 | MassLogger | 1 | 1.0% |
| 9 | DCRat | 1 | 1.0% |
| 10 | SnappyClient | 1 | 1.0% |
| 11 | malicious (high confidence) | 1 | 1.0% |
| 12 | Trojan.GenericKD.82325012 | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 53 | 52.5% | 81% |
| Andere / Unbekannt | 20 | 19.8% | 20% |
| Windows-Malware | 8 | 7.9% | 35% |
| Infostealer | 7 | 6.9% | 75% |
| Linux-Malware | 6 | 5.9% | 45% |
| Trojaner | 2 | 2.0% | 65% |
| RAT | 2 | 2.0% | 85% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Cryptominer | 1 | 1.0% | 75% |
| Post-Exploitation | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 27 | 26.7% |
| 🟠 HOCH | 39 | 38.6% |
| 🟡 MITTEL | 15 | 14.9% |
| 🟢 NIEDRIG | 20 | 19.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [bf6d80bf56f0e3…](https://bazaar.abuse.ch/sample/bf6d80bf56f0e3bd5ed906599593d7697e3e0f7b9e45eca455fb20e7367e5344/) | Sliver | Post-Exploitat | **91.6** | 🔴 KRITISCH | – | – | ? |
| [3599967a17e350…](https://bazaar.abuse.ch/sample/3599967a17e350b06bf8fd34b7640175d635b3c5388843e24d732384a9c95ed1/) | DCRat | RAT | **87.6** | 🔴 KRITISCH | – | – | ? |
| [774c4dd4024edc…](https://bazaar.abuse.ch/sample/774c4dd4024edc3eab82d44adff302704f00ccfe5c5f669315ee1ea5094930c0/) | WARDENStealer | Infostealer | **85.7** | 🔴 KRITISCH | 0.0% | ⚠️ KAUM ERKANNT | ✗ |
| [25973d53bb03bf…](https://bazaar.abuse.ch/sample/25973d53bb03bf5fc7ceb89db1bfc16befb00586e06c306b75326182ec683bb7/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [e6a16f714067a2…](https://bazaar.abuse.ch/sample/e6a16f714067a23b7034ca38dc402594263b0087a0364dd3a27503a0aadf2099/) | WARDENStealer | Infostealer | **81.0** | 🔴 KRITISCH | – | – | ? |
| [33a2e48cf2aff6…](https://bazaar.abuse.ch/sample/33a2e48cf2aff6ffdd7e9745de656f3df33c40e3504bde55662e290ad089286d/) | WARDENStealer | Infostealer | **81.0** | 🔴 KRITISCH | – | – | ? |
| [76d1d9e648b29f…](https://bazaar.abuse.ch/sample/76d1d9e648b29f29a4fdf9ed7d350b2b1ebecf12a9cb146da43dbf8a1315449f/) | WARDENStealer | Infostealer | **81.0** | 🔴 KRITISCH | – | – | ? |
| [fe3cd55775f46b…](https://bazaar.abuse.ch/sample/fe3cd55775f46bbbeb531a4d08b835f10c38651a566c3eafaec772e40ef12387/) | unbekannt | Infostealer | **80.9** | 🔴 KRITISCH | – | – | ? |
| [f7804335fefbbf…](https://bazaar.abuse.ch/sample/f7804335fefbbfc7e9e2e674d00bcc6b6a6e7807abf5954d6c24f7d74c6c51fc/) | Mirai | Botnet/IoT | **80.7** | 🔴 KRITISCH | – | – | ? |
| [e5e2a84c5acd6c…](https://bazaar.abuse.ch/sample/e5e2a84c5acd6cd1ec82feb6903fa05b0244779b1cc82f84e869010899795268/) | Mirai | Botnet/IoT | **80.7** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6626/8163 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6626/8163 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6325/8163 |
| 6 | Kaspersky | 75.5% | 6164/8162 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5815/8159 |
| 9 | Rising | 68.6% | 5603/8163 |
| 10 | Varist | 66.1% | 5393/8158 |
| 11 | Tencent | 65.3% | 5181/7937 |
| 12 | Avast | 65.1% | 5313/8159 |
| 13 | AVG | 65.1% | 5313/8158 |
| 14 | McAfeeD | 61.3% | 5001/8155 |
| 15 | huorong | 61.0% | 4977/8155 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 49 | 48.5% |
| 🐧 Linux | 32 | 31.7% |
| 📦 Archiv | 16 | 15.8% |
| ❓ Unbekannt | 4 | 4.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 98 | 97.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |
| MaaS-Loader | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 79 | 78.2% |
| 2 | 🇩🇪 DE | 8 | 7.9% |
| 3 | 🇫🇷 FR | 5 | 5.0% |
| 4 | 🇺🇦 UA | 3 | 3.0% |
| 5 | 🇭🇺 HU | 2 | 2.0% |
| 6 | 🇦🇺 AU | 2 | 2.0% |
| 7 | 🇨🇭 CH | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 16 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 15 |
| Lateral Movement | 15 |
| Credential Access | 1 |
| Collection | 1 |
| Exfiltration | 1 |

<details><summary>25973d53bb03bf5fc7ce… – Mirai | 🔴 KRITISCH 83.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [774c4dd4024edc3eab82…](https://bazaar.abuse.ch/sample/774c4dd4024edc3eab82d44adff302704f00ccfe5c5f669315ee1ea5094930c0/)

- **Familie:** WARDENStealer
- **Erkannt von:** 0 von 72 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [8fdc79897cd0f2f80349…](https://bazaar.abuse.ch/sample/8fdc79897cd0f2f80349ae7dd7c2315b16dbe6b95a7327eeadbec1af0b6df5ae/)

- **Familie:** CatStorm
- **Erkannt von:** 11 von 72 Engines (15.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-ETO [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/72):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ETO [Trj]` |
| Avast | `ELF:Agent-ETO [Trj]` |
| DrWeb | `Linux.DDoS.3446` |
| ESET-NOD32 | `Linux/CoinMiner.ASV trojan` |
| Fortinet | `ELF/Flooder.ADS!tr` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.yn` |
| Rising | `Backdoor.Mirai/Linux!1.DDEC (CLASSIC)` |
| SentinelOne | `Static AI - Suspicious ELF` |
| Tencent | `Trojan.Linux.Catstorm.qzvra` |
| VBA32 | `Trojan.Linux.Catstorm` |
| huorong | `Trojan/Linux.CoinMiner.eb` |

### [f76728bf4bfb8a30574a…](https://bazaar.abuse.ch/sample/f76728bf4bfb8a30574a8586429e4b7743a809859ff517b09815cbcba595078f/)

- **Familie:** malicious (high confidence)
- **Erkannt von:** 12 von 72 Engines (16.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** malicious (high confidence)
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan:NPM/Multiverze!rfn`

**Erkennende Engines (12/72):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `HEUR:Exploit.Win32.BypassUAC.b` |
| Kingsoft | `Win32.Exploit.BypassUAC.b` |
| Microsoft 🛡️ | `Trojan:NPM/Multiverze!rfn` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |

### [f1fc8e038756caf16068…](https://bazaar.abuse.ch/sample/f1fc8e038756caf16068bc14bd7663d7c997407785aa50834a8a28e03755bb6a/)

- **Familie:** Trojan.GenericKD.82325012
- **Erkannt von:** 48 von 72 Engines (66.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.82325012
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.82325012`

**Erkennende Engines (48/72):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.82325012` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Ransom]` |
| AhnLab-V3 | `Malware/Win.Generic.C5981835` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Agent` |
| Arcabit | `Trojan.Generic.D4E82E14` |
| Avast | `Win64:MalwareX-gen [Ransom]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKD.82325012` |
| Bkav | `W32.Malware.B556C1BD` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.DownLoader52.33128` |
| ESET-NOD32 | `Win64/TrojanDownloader.Agent_AGen.OD trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.82325012 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Trojan.GenericKD.82325012` |
| Google | `Detected` |
| Ikarus | `Trojan.SuspectCRC` |
| K7AntiVirus | `Trojan-Downloader ( 006ecbb01 )` |
| K7GW | `Trojan-Downloader ( 006ecbb01 )` |
| Kaspersky | `Trojan-Ransom.Win32.Foreign.opkj` |
| Lionic | `Trojan.Win32.Foreign.1f!c` |
| Malwarebytes | `Generic.Malware/Suspicious` |
| MaxSecure | `Trojan.Malware.8328611.susgen` |
| McAfeeD | `ti!F1FC8E038756` |
| MicroWorld-eScan | `Trojan.GenericKD.82325012` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxGD.A` |
| Rising | `Ransom.Foreign!8.292 (CLOUD)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.11e88005` |
| TrellixENS | `Artemis!265CEE3A6F5C` |
| TrendMicro | `Trojan.Win32.FOREIGN.USBLKP26` |
| TrendMicro-HouseCall | `Trojan.Win32.FOREIGN.USBLKP26` |
| VIPRE | `Trojan.GenericKD.82325012` |
| Varist | `W64/ABlRisk.NSET-2435` |
| alibabacloud | `Ransomware:Win/Agent_AGen.OF` |
| huorong | `HVM:TrojanDownloader/Onkods.a` |

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

- **DDoS** (51×)
- **SnoopyTriage** (51×)
- **Swag** (45×)
- **exe** (40×)
- **elf** (27×)
- **zip** (16×)
- **Mirai** (14×)
- **signed** (8×)
- **ntlt** (6×)
- **WARDENStealer** (4×)
- **ps1** (4×)
- **sh** (4×)
- **CatStorm** (3×)
- **stealer** (3×)
- **Gafgyt** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +34 (32→66)
- ↓ **WARDENStealer** -1 (5→4)
- ↓ **CatStorm** -5 (8→3)
- neu: **Gafgyt** (2)
- neu: **Hajime** (2)
- neu: **MassLogger** (1)
- neu: **DCRat** (1)
- neu: **SnappyClient** (1)
- weg: **ValleyRAT** (war 2)
- weg: **njrat** (war 3)
- weg: **GuLoader** (war 2)
- weg: **Snowlight** (war 8)
- weg: **RemusStealer** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +27 (39→66)
- ↓ **Mirai** -5 (19→14)
- ↑ **CatStorm** +1 (2→3)
- ↑ **CoinMiner** +1 (1→2)
- neu: **Gafgyt** (2)
- neu: **Hajime** (2)
- neu: **MassLogger** (1)
- neu: **DCRat** (1)
- neu: **SnappyClient** (1)
- weg: **njrat** (war 2)
- weg: **Snowlight** (war 4)
- weg: **EasyShell** (war 5)
- weg: **FunStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.713 MB |
| σ Dateigröße | 13.757 MB |
| Ø Risiko-Score | 61.4/100 |
| Ø Klassifikations-Konfidenz | 62.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 16/101 |
| Eindeutige Familien | 15 |
| Eindeutige Tags | 60 |
| Unbekannte Familien | 20 (19.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:54 | [dab41506aace…](https://bazaar.abuse.ch/sample/dab41506aacea1fd7bf823a87c917adb3d264d79c7e3aaf4b07df74598782a70/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 17:54 | [dff1e748f1a0…](https://bazaar.abuse.ch/sample/dff1e748f1a0cc13cb218464141ecf5c599694b43499c0cc27f01c7ee579494e/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 17:50 | [c589fa59fe04…](https://bazaar.abuse.ch/sample/c589fa59fe04d98c9a9efd5a53b1a8c98c60a9e69044cc1f2594b13716d12b6f/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 17:32 | [3807f4cf9dd4…](https://bazaar.abuse.ch/sample/3807f4cf9dd4d1093493d9475b3848bf6a9ee88f716fc1ddc0d8c9855055a1c3/) | `jar` | unbekannt | 32.4 | – | – | 🇺🇦UA |
| 17:31 | [81953cb82563…](https://bazaar.abuse.ch/sample/81953cb825635ec015a8c2fd20f5800f2a0e7c8d841735a1c1eddd3e940b1497/) | `jar` | unbekannt | 32.4 | – | – | 🇺🇦UA |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 27.11.2026 17:56 UTC*