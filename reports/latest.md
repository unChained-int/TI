# MalwareBazaar – 10.11.2026 22:58 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **50** |
| Höchster Score | **91.6/100** – 683a049283aa3d9d… |
| Häufigste Familie | **unbekannt** (32x) |
| Häufigster Typ | **elf** (32x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 32 Samples |
| Ø Dateigröße | 15.26 MB (σ=33.65) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 32 | 31.7%  ██████ |
| `exe` | 21 | 20.8%  ████ |
| `jar` | 18 | 17.8%  ███ |
| `js` | 13 | 12.9%  ██ |
| `vbs` | 6 | 5.9%  █ |
| `zip` | 2 | 2.0%   |
| `hta` | 2 | 2.0%   |
| `xls` | 2 | 2.0%   |
| `iso` | 1 | 1.0%   |
| `zsh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 32 | 31.7% |
| 2 | Mirai | 15 | 14.9% |
| 3 | SilentNet | 15 | 14.9% |
| 4 | RemcosRAT | 8 | 7.9% |
| 5 | GuLoader | 5 | 5.0% |
| 6 | SparkRAT | 4 | 4.0% |
| 7 | AgentTesla | 3 | 3.0% |
| 8 | Bombay | 3 | 3.0% |
| 9 | SalatStealer | 2 | 2.0% |
| 10 | Formbook | 2 | 2.0% |
| 11 | AsyncRAT | 2 | 2.0% |
| 12 | Malware | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Andere / Unbekannt | 22 | 21.8% | 20% |
| RAT | 16 | 15.8% | 89% |
| Botnet/IoT | 15 | 14.9% | 95% |
| Linux-Malware | 11 | 10.9% | 45% |
| Loader | 10 | 9.9% | 84% |
| Infostealer | 9 | 8.9% | 82% |
| Windows-Malware | 7 | 6.9% | 35% |
| Skript/Dropper | 5 | 5.0% | 35% |
| Trojaner | 2 | 2.0% | 70% |
| Backdoor | 1 | 1.0% | 75% |
| Post-Exploitation | 1 | 1.0% | 95% |
| Spyware | 1 | 1.0% | 75% |
| Cryptominer | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 50 | 49.5% |
| 🟠 HOCH | 6 | 5.9% |
| 🟡 MITTEL | 21 | 20.8% |
| 🟢 NIEDRIG | 24 | 23.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [683a049283aa3d…](https://bazaar.abuse.ch/sample/683a049283aa3d9d5b3a91c221a930edebd9c64eb712834af47c714c1cd5ba3e/) | SliverFox | Post-Exploitat | **91.6** | 🔴 KRITISCH | – | – | ? |
| [bbf91890ecbe5c…](https://bazaar.abuse.ch/sample/bbf91890ecbe5c0f87c616b3ea5682e0406c0587815649d0e26f1dcf159318ec/) | SnakeKeylogger | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [a1de6e22ccc652…](https://bazaar.abuse.ch/sample/a1de6e22ccc652607072b6d920eaa0a963c9e3558684b9ebdd6da257016d0bd4/) | Formbook | Infostealer | **86.6** | 🔴 KRITISCH | – | – | ? |
| [93b0ebb11b992e…](https://bazaar.abuse.ch/sample/93b0ebb11b992e401256e7514535d1565c7f113fc4a3159d37f2750b043cd576/) | Formbook | Infostealer | **86.6** | 🔴 KRITISCH | – | – | ? |
| [aa74860b29b3f1…](https://bazaar.abuse.ch/sample/aa74860b29b3f1dd8510f063e2efa9103d58cde19f6488f051c8413dfb09304c/) | RemcosRAT | RAT | **85.9** | 🔴 KRITISCH | – | – | ? |
| [0a772027c61cef…](https://bazaar.abuse.ch/sample/0a772027c61cef6a5402577307e898ceba7405911bf1a2fe57707be9bb30230e/) | RemcosRAT | RAT | **85.8** | 🔴 KRITISCH | – | – | ? |
| [3a71b1093e3769…](https://bazaar.abuse.ch/sample/3a71b1093e376997406e974deda12cfec19e4e77dfbd6a54c08be56d1a729d6c/) | RemcosRAT | RAT | **85.7** | 🔴 KRITISCH | – | – | ? |
| [a87fe399bea788…](https://bazaar.abuse.ch/sample/a87fe399bea78832466c6b5f6917e86779e5057d4dea018156d421fa47a0c576/) | RemcosRAT | RAT | **85.7** | 🔴 KRITISCH | – | – | ? |
| [54a3b5653c49ff…](https://bazaar.abuse.ch/sample/54a3b5653c49ffdb23173634e6314d81670362c9bbc14d427b05d1ac95314480/) | AsyncRAT | RAT | **85.7** | 🔴 KRITISCH | – | – | ? |
| [93af115a6656de…](https://bazaar.abuse.ch/sample/93af115a6656de050035d039bbc8fc260324cc134ab296226e9c6c65cb17d227/) | AsyncRAT | RAT | **85.7** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6429/7926 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6429/7926 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6128/7926 |
| 6 | Kaspersky | 75.5% | 5984/7925 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5645/7922 |
| 9 | Rising | 68.4% | 5422/7926 |
| 10 | Varist | 66.1% | 5239/7921 |
| 11 | Avast | 65.2% | 5164/7922 |
| 12 | AVG | 65.2% | 5164/7921 |
| 13 | Tencent | 65.0% | 5004/7700 |
| 14 | McAfeeD | 61.4% | 4862/7918 |
| 15 | huorong | 60.9% | 4825/7918 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 34 | 33.7% |
| ❓ Unbekannt | 31 | 30.7% |
| 🪟 Windows | 30 | 29.7% |
| 📦 Archiv | 2 | 2.0% |
| 🍎 macOS | 2 | 2.0% |
| 📄 Dokument | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 77 | 76.2% |
| Drive-By / Exploit-Kit | 18 | 17.8% |
| MaaS-Loader | 3 | 3.0% |
| Phishing / E-Mail-Anhang | 2 | 2.0% |
| USB / Wechselmedium | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 20 | 19.8% |
| 2 | 🇸🇪 SE | 18 | 17.8% |
| 3 | 🇦🇹 AT | 15 | 14.9% |
| 4 | 🇭🇺 HU | 11 | 10.9% |
| 5 | 🇺🇸 US | 11 | 10.9% |
| 6 | 🇨🇭 CH | 8 | 7.9% |
| 7 | 🇧🇷 BR | 6 | 5.9% |
| 8 | 🇳🇱 NL | 6 | 5.9% |
| 9 | 🇫🇷 FR | 4 | 4.0% |
| 10 | 🌐 NO | 1 | 1.0% |
| 11 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 32 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 15 |
| Lateral Movement | 15 |
| Command and Control | 10 |
| Collection | 10 |
| Execution | 7 |
| Defense Evasion | 5 |
| Credential Access | 2 |

<details><summary>a1de6e22ccc652607072… – Formbook | 🔴 KRITISCH 86.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>93b0ebb11b992e401256… – Formbook | 🔴 KRITISCH 86.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>aa74860b29b3f1dd8510… – RemcosRAT | 🔴 KRITISCH 85.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [8c56e2e69fc805ce2a13…](https://bazaar.abuse.ch/sample/8c56e2e69fc805ce2a13c7a4708c934c6f697184e15489e6f56d0b51352c77a9/)

- **Familie:** Malware
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** W32.Malware.3067D903
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Alibaba | `Downloader:Python/Generic.1962dd65` |
| Avira | `TR/ATRAPS.Gen` |
| Bkav | `W32.Malware.3067D903` |
| F-Secure | `Trojan.TR/ATRAPS.Gen` |
| Rising | `Downloader.Agent/PYC!1.F092 (CLOUD)` |
| SentinelOne | `Static AI - Malicious PE` |
| huorong | `Trojan/Python.ShellLoader.am` |

### [ea91c6d5d8936011245d…](https://bazaar.abuse.ch/sample/ea91c6d5d8936011245d0b0c06a6eb4105b9baf6be12a3345f0cacd7cbb306a0/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Prometei.10
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Prometei.10`

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Application.Generic.37119494` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Application.Generic.D23E0C8A` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Prometei.10` |
| CTX | `elf.trojan.prometei` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Prometei.10 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Application.Generic.37620874` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Prometei.10` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Application.Generic.37620874` |
| huorong | `Trojan/Prometei.c` |

### [5186174157df45d0c3f9…](https://bazaar.abuse.ch/sample/5186174157df45d0c3f9f6e438abb60668d48e93065ab6cacc07815e6c90d505/)

- **Familie:** BQZ trojan
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BQZ trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan/Linux.Agent` |
| ESET-NOD32 | `Linux/Agent.BQZ trojan` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Flooder` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Trojan.Agent/Linux!8.13268 (TFE:19:fLxTGV11B6)` |
| Tencent | `Malware.Linux.Generic.1c0c9f7b` |

### [a6749998621253207e1c…](https://bazaar.abuse.ch/sample/a6749998621253207e1cd86fad291da21e8494aba46c9be76f0d24bf3afd24d0/)

- **Familie:** XWorm
- **Erkannt von:** 9 von 75 Engines (12.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Script.XWorm.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (9/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `VBS/TrojanDropper.Agent.QIC trojan` |
| Fortinet | `VBS/Agent.QIC!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `HEUR:Trojan.VBS.Alien.gen` |
| Lionic | `Trojan.Script.XWorm.4!c` |
| Microsoft 🛡️ | `Trojan:VBS/Sonbokli.A!cl` |
| Symantec | `Scr.Guloader!gen3` |
| Varist | `JS/Agent.FIJ!Eldorado` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 59 von 75 Engines (78.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (59/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| AVG | `Win32:Evo-gen [Trj]` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avast | `Win32:Evo-gen [Trj]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Trojan.Nymeria-6895336-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.28` |
| ESET-NOD32 | `Win32/Injector.Autoit.DTL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.1TKG37Z` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/Genetic.gen` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vjon` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| Zillya | `Trojan.Injector.Win32.2062480` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (32×)
- **exe** (20×)
- **jar** (18×)
- **Mirai** (14×)
- **java** (14×)
- **python** (14×)
- **silentnet** (14×)
- **js** (13×)
- **Prometei** (8×)
- **upx** (7×)
- **RemcosRAT** (7×)
- **RAT** (6×)
- **upx-dec** (6×)
- **vbs** (6×)
- **GuLoader** (5×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -6 (21→15)
- neu: **SilentNet** (15)
- ↑ **RemcosRAT** +7 (1→8)
- neu: **GuLoader** (5)
- neu: **SparkRAT** (4)
- ↑ **AgentTesla** +2 (1→3)
- neu: **Bombay** (3)
- ↓ **SalatStealer** -5 (7→2)
- neu: **Formbook** (2)
- weg: **WARDENStealer** (war 5)
- weg: **Snowlight** (war 5)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -1 (33→32)
- ↓ **Mirai** -7 (22→15)
- neu: **SilentNet** (15)
- ↑ **RemcosRAT** +6 (2→8)
- neu: **GuLoader** (5)
- neu: **SparkRAT** (4)
- neu: **Bombay** (3)
- weg: **WARDENStealer** (war 3)
- weg: **VShell** (war 2)
- weg: **Snowlight** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 15.258 MB |
| σ Dateigröße | 33.646 MB |
| Ø Risiko-Score | 59.8/100 |
| Ø Klassifikations-Konfidenz | 61.7% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 32/101 |
| Eindeutige Familien | 21 |
| Eindeutige Tags | 76 |
| Unbekannte Familien | 22 (21.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 22:45 | [eddbb7f87f6c…](https://bazaar.abuse.ch/sample/eddbb7f87f6c3fd788f5aa002bf8ff5bf75cbdef2cced815cd412807a655168d/) | `exe` | unbekannt | 38.9 | – | – | 🌐HU |
| 22:36 | [73b2767f8bc6…](https://bazaar.abuse.ch/sample/73b2767f8bc6a714e7882645a355d8f85dedebc55e0efc9b8b1187ab26449614/) | `iso` | unbekannt | 32.4 | – | – | 🌐HU |
| 22:21 | [5d9dc8c9a900…](https://bazaar.abuse.ch/sample/5d9dc8c9a900fb171c33d36e9edf6b384762a17a380bfab97001779d8b0957e4/) | `zip` | unbekannt | 81.7 | – | – | 🌐NO |
| 22:06 | [59a315d5f91e…](https://bazaar.abuse.ch/sample/59a315d5f91ed7108c8e323cf640eb2f556d353a2db52561b46af67b0c058b21/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 21:58 | [d88a42a33fab…](https://bazaar.abuse.ch/sample/d88a42a33fabc1b1d761ada585006ad0c79b6918748328e8774774b2db3a3a8f/) | `elf` | unbekannt | 42.4 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 10.11.2026 22:58 UTC*