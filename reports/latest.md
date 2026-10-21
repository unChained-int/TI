# MalwareBazaar – 21.10.2026 23:04 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **41** |
| Höchster Score | **97.1/100** – 0c04ce5cd7f7ebfd… |
| Häufigste Familie | **unbekannt** (56x) |
| Häufigster Typ | **exe** (52x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 48 Samples |
| Ø Dateigröße | 6.76 MB (σ=10.24) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 52 | 51.5%  ██████████ |
| `rar` | 13 | 12.9%  ██ |
| `elf` | 12 | 11.9%  ██ |
| `zip` | 7 | 6.9%  █ |
| `js` | 4 | 4.0%   |
| `vbe` | 4 | 4.0%   |
| `doc` | 2 | 2.0%   |
| `hta` | 1 | 1.0%   |
| `cmd` | 1 | 1.0%   |
| `gz` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 56 | 55.4% |
| 2 | Mirai | 12 | 11.9% |
| 3 | CoinMiner | 9 | 8.9% |
| 4 | RemcosRAT | 8 | 7.9% |
| 5 | Formbook | 4 | 4.0% |
| 6 | AgentTesla | 3 | 3.0% |
| 7 | XWorm | 2 | 2.0% |
| 8 | WannaCry | 1 | 1.0% |
| 9 | Trojan ( 006e7e6e1 ) | 1 | 1.0% |
| 10 | RemusStealer | 1 | 1.0% |
| 11 | PhantomStealer | 1 | 1.0% |
| 12 | DonutLoader | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Loader | 40 | 39.6% | 76% |
| Andere / Unbekannt | 15 | 14.9% | 20% |
| Botnet/IoT | 12 | 11.9% | 95% |
| Infostealer | 10 | 9.9% | 83% |
| RAT | 10 | 9.9% | 95% |
| Windows-Malware | 6 | 5.9% | 35% |
| Skript/Dropper | 3 | 3.0% | 35% |
| Maldoc | 2 | 2.0% | 35% |
| Ransomware | 1 | 1.0% | 95% |
| Linux-Malware | 1 | 1.0% | 45% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 41 | 40.6% |
| 🟠 HOCH | 33 | 32.7% |
| 🟡 MITTEL | 12 | 11.9% |
| 🟢 NIEDRIG | 15 | 14.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [0c04ce5cd7f7eb…](https://bazaar.abuse.ch/sample/0c04ce5cd7f7ebfd12f9639f2bcb7dcd93b18f3706e394e3228e0fdbae4ebcb5/) | WannaCry | Ransomware | **97.1** | 🔴 KRITISCH | – | – | ? |
| [7d2c079e4bd0fa…](https://bazaar.abuse.ch/sample/7d2c079e4bd0fa3242541e42537ed36dea0e12447801998f212bbeb9187cef31/) | Formbook | Infostealer | **89.3** | 🔴 KRITISCH | – | – | ? |
| [5013e5cee099c7…](https://bazaar.abuse.ch/sample/5013e5cee099c794820705a1770178abf011553dd9d8eccb9d9077cbc1ac7f53/) | Formbook | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [32ac8b7017cd68…](https://bazaar.abuse.ch/sample/32ac8b7017cd681c2098774873736c3b93c1710796e55f6a19934530fca00e94/) | Formbook | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [2f4af185b7d5a8…](https://bazaar.abuse.ch/sample/2f4af185b7d5a89b71e6cf448ab48b6ce31f7e510b45940b263b5bdeb6c270df/) | Formbook | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [353a826ad0dad4…](https://bazaar.abuse.ch/sample/353a826ad0dad4b8ffa4bc17f6fbf00afb2b2997705a5fdb98fa47bc5bf951bb/) | RemcosRAT | RAT | **88.3** | 🔴 KRITISCH | – | – | ? |
| [2ac6b7a9b35ffe…](https://bazaar.abuse.ch/sample/2ac6b7a9b35ffe396321aab670303fc121e596ae3b8699de6b4acf85c5241a59/) | RemcosRAT | RAT | **88.3** | 🔴 KRITISCH | – | – | ? |
| [c547d151f81042…](https://bazaar.abuse.ch/sample/c547d151f81042c51784fd0206dbc9a9b89888971a63efc33ca0f38bafa521ec/) | RemcosRAT | RAT | **88.3** | 🔴 KRITISCH | – | – | ? |
| [1d4120bc2f98ae…](https://bazaar.abuse.ch/sample/1d4120bc2f98aec0abc5290a98e8702dfc91ec63a82be8d1d0739cdbdb337c59/) | RemcosRAT | RAT | **88.3** | 🔴 KRITISCH | – | – | ? |
| [db2de92e24d78a…](https://bazaar.abuse.ch/sample/db2de92e24d78a4f348e18f7beb90c1bc03fe008ab221f296764061315431a78/) | RemcosRAT | RAT | **88.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6103/7537 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6103/7537 |
| 3 | ESET-NOD32 | 77.3% | 5827/7537 |
| 4 | Kaspersky | 76.1% | 5737/7536 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.4% | 5376/7534 |
| 8 | Rising | 68.6% | 5172/7537 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 4989/7533 |
| 11 | Avast | 65.2% | 4914/7533 |
| 12 | AVG | 65.2% | 4914/7532 |
| 13 | Tencent | 65.1% | 4761/7311 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4615/7530 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 55 | 54.5% |
| 📦 Archiv | 21 | 20.8% |
| 🐧 Linux | 13 | 12.9% |
| ❓ Unbekannt | 10 | 9.9% |
| 📄 Dokument | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 51 | 50.5% |
| C2 / Nachladen | 37 | 36.6% |
| Drive-By / Exploit-Kit | 4 | 4.0% |
| MaaS-Loader | 3 | 3.0% |
| Phishing / E-Mail-Anhang | 2 | 2.0% |
| USB / Wechselmedium | 2 | 2.0% |
| Exploit / N-Day | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 49 | 48.5% |
| 2 | 🇨🇭 CH | 35 | 34.7% |
| 3 | 🇳🇱 NL | 7 | 6.9% |
| 4 | 🇩🇪 DE | 4 | 4.0% |
| 5 | 🌐 PT | 2 | 2.0% |
| 6 | 🇭🇺 HU | 2 | 2.0% |
| 7 | 🇬🇧 GB | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 48 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 35 |
| Credential Access | 27 |
| Exfiltration | 23 |
| Initial Access | 12 |
| Lateral Movement | 12 |
| Command and Control | 8 |
| Execution | 1 |
| Persistence | 1 |

<details><summary>7d2c079e4bd0fa324254… – Formbook | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>5013e5cee099c7948207… – Formbook | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>32ac8b7017cd681c2098… – Formbook | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>2f4af185b7d5a89b71e6… – Formbook | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [d767091c53ec51809c59…](https://bazaar.abuse.ch/sample/d767091c53ec51809c5927ea6803f4b7b85416fd590e084bc47d3c6d2d6fa5dd/)

- **Familie:** Trojan ( 006e7e6e1 )
- **Erkannt von:** 16 von 75 Engines (21.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan ( 006e7e6e1 )
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (16/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `CoinMiner/Win.MalwareX-gen.R799089` |
| Bkav | `W32.Malware.6E077274` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.FUN trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/GenKryptik.FUN!tr` |
| Google | `Detected` |
| K7AntiVirus | `Trojan ( 006e7e6e1 )` |
| K7GW | `Trojan ( 006e7e6e1 )` |
| Kaspersky | `HEUR:Trojan.Win64.Agent.pef` |
| Malwarebytes | `Trojan.FakeGoogle` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Kryptik.16006158` |
| Varist | `W64/Agent.NJL.gen!Eldorado` |

### [1639f8acdbf6c6e8afa9…](https://bazaar.abuse.ch/sample/1639f8acdbf6c6e8afa94235b51e7e208396b0892ea7ee26dc81e0b7a784913a/)

- **Familie:** CoinMiner
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Cryp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:MalwareX-gen [Cryp]` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.FYX trojan` |
| Elastic | `malicious (high confidence)` |
| Microsoft 🛡️ | `Trojan:Win32/Bearfoos.B!ml` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `OB:Trojan.Win32.Kryptik.16007442` |
| Webroot | `W32.Malware.Gen` |

### [d8660f70e47de14bc9fd…](https://bazaar.abuse.ch/sample/d8660f70e47de14bc9fdc36a3efad6bf17af4f810dcf6e35c0bd60d26d09ceee/)

- **Familie:** CoinMiner
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Cryp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:MalwareX-gen [Cryp]` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.FYX trojan` |
| Elastic | `malicious (moderate confidence)` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.80 (RDML:cD4mVkwg9qxjOiC7cVhHvg)` |
| Tencent | `OB:Trojan.Win32.Kryptik.16007442` |
| Webroot | `W32.Malware.Gen` |

### [56f04834f677d24a2fd7…](https://bazaar.abuse.ch/sample/56f04834f677d24a2fd769f47df1b978a9c650dd1353c413cdc080e21e9f9838/)

- **Familie:** ConnectWise
- **Erkannt von:** 30 von 75 Engines (40.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (30/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Alibaba | `RiskWare:MSIL/ConnectWise.49136667` |
| Bkav | `W32.Malware.F7B21A1E` |
| CTX | `exe.trojan.connectwise` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.MulDrop31.17564` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| GData | `Win32.Backdoor.EvilConwi.L` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| Jiangmin | `Trojan.Agent.edgo` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kaspersky | `not-a-virus:RemoteAdmin.MSIL.ConnectWise.b` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `BehavesLike.Win32.ScreenConnect.tc` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrellixENS | `PUP-IPR` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Yandex | `Riskware.RemoteAdmin!O4vT/8AeK2A` |
| huorong | `HackTool/ConnectWiseControl.i` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Qwexlafiba!rfn`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.qwexlafiba` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Ikarus | `Trojan.Win32.BadJoke` |
| Lionic | `Trojan.Win32.PythonStealer.4!c` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **exe** (51×)
- **signed** (26×)
- **dropped-by-Vidar** (23×)
- **rar** (13×)
- **Mirai** (12×)
- **dropped-by-GCleaner** (11×)
- **CoinMiner** (9×)
- **RemcosRAT** (8×)
- **19ccb70dbc12ef919d5869277e598933** (7×)
- **elf** (7×)
- **zip** (7×)
- **b89d843f29af2eed09805e9767a1165f** (5×)
- **c1399bfb1be0a51415613edd6f0068c5** (5×)
- **d852ede598d72f2b3a4050576466ec62** (5×)
- **C** (4×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -4 (60→56)
- ↓ **Mirai** -10 (22→12)
- ↑ **CoinMiner** +4 (5→9)
- ↑ **RemcosRAT** +7 (1→8)
- neu: **Formbook** (4)
- neu: **AgentTesla** (3)
- neu: **XWorm** (2)
- neu: **WannaCry** (1)
- neu: **Trojan ( 006e7e6e1 )** (1)
- neu: **RemusStealer** (1)
- weg: **SalatStealer** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +22 (34→56)
- ↓ **Mirai** -10 (22→12)
- ↑ **CoinMiner** +8 (1→9)
- ↑ **RemcosRAT** +7 (1→8)
- ↑ **Formbook** +3 (1→4)
- neu: **AgentTesla** (3)
- neu: **XWorm** (2)
- neu: **WannaCry** (1)
- neu: **Trojan ( 006e7e6e1 )** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 6.760 MB |
| σ Dateigröße | 10.242 MB |
| Ø Risiko-Score | 67.1/100 |
| Ø Klassifikations-Konfidenz | 67.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 48/101 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 65 |
| Unbekannte Familien | 15 (14.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:02 | [da17b439954e…](https://bazaar.abuse.ch/sample/da17b439954e61c155645ee8c5c08c29e281d0dee9b123c220ff3bab06f450bb/) | `exe` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 23:00 | [410eea0c6cd8…](https://bazaar.abuse.ch/sample/410eea0c6cd8de3c68226c80f9130e4453bdda7857552a3c711b786228441650/) | `exe` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 22:58 | [4fb55bbb7855…](https://bazaar.abuse.ch/sample/4fb55bbb7855abfce34786e2fa4481a3576a338ca8c01dca1c6902fecd9cdbe9/) | `exe` | unbekannt | 75.0 | – | – | 🇺🇸US |
| 22:57 | [7a257f160dab…](https://bazaar.abuse.ch/sample/7a257f160dab76c6df1aec5b26691caa2fb59eddcadb8d6fce813c8a6394f4ce/) | `exe` | unbekannt | 75.0 | – | – | 🇺🇸US |
| 22:54 | [57d342c6f74f…](https://bazaar.abuse.ch/sample/57d342c6f74fdf5183085318134a6672171edd44a0b3b36c04c79a2fe0d48eaf/) | `exe` | CoinMiner | 75.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 21.10.2026 23:04 UTC*