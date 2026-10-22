# MalwareBazaar – 22.10.2026 19:50 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **47** |
| Höchster Score | **95.7/100** – 8df06bfda2a5604a… |
| Häufigste Familie | **unbekannt** (47x) |
| Häufigster Typ | **elf** (58x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 39 Samples |
| Ø Dateigröße | 4.76 MB (σ=8.58) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 58 | 57.4%  ███████████ |
| `exe` | 24 | 23.8%  ████ |
| `zip` | 7 | 6.9%  █ |
| `sh` | 3 | 3.0%   |
| `jar` | 2 | 2.0%   |
| `ps1` | 2 | 2.0%   |
| `rar` | 1 | 1.0%   |
| `doc` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |
| `iso` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 47 | 46.5% |
| 2 | Mirai | 37 | 36.6% |
| 3 | Kaiji | 8 | 7.9% |
| 4 | Gafgyt | 3 | 3.0% |
| 5 | RustyStealer | 1 | 1.0% |
| 6 | RemusStealer | 1 | 1.0% |
| 7 | LummaStealer | 1 | 1.0% |
| 8 | ConnectWise | 1 | 1.0% |
| 9 | WannaCry | 1 | 1.0% |
| 10 | PythonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 40 | 39.6% | 95% |
| Windows-Malware | 20 | 19.8% | 35% |
| Linux-Malware | 19 | 18.8% | 45% |
| Andere / Unbekannt | 12 | 11.9% | 20% |
| Infostealer | 5 | 5.0% | 79% |
| Trojaner | 3 | 3.0% | 68% |
| Maldoc | 1 | 1.0% | 35% |
| Ransomware | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 47 | 46.5% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 40 | 39.6% |
| 🟢 NIEDRIG | 12 | 11.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [8df06bfda2a560…](https://bazaar.abuse.ch/sample/8df06bfda2a5604a312655437d45aae27ad0449bf4c01051a494775e930d8cf1/) | WannaCry | Ransomware | **95.7** | 🔴 KRITISCH | – | – | ? |
| [57b4d9fb4667d0…](https://bazaar.abuse.ch/sample/57b4d9fb4667d070220d58aa9040c64db081eae24d15c522b3e033d6094286ab/) | LummaStealer | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [a1f549624f4f51…](https://bazaar.abuse.ch/sample/a1f549624f4f5122b012c6047f5bc1523310492f3d6b9bce874bfd020b7d451e/) | Mirai | Botnet/IoT | **85.8** | 🔴 KRITISCH | 6.7% | ⚠️ KAUM ERKANNT | ✗ |
| [7dcdc5bf598c24…](https://bazaar.abuse.ch/sample/7dcdc5bf598c24904876fcc997a7c7bc1d219835d9c41bb2f53c7a8166f83aa3/) | Mirai | Botnet/IoT | **85.4** | 🔴 KRITISCH | 8.0% | ⚠️ KAUM ERKANNT | ✗ |
| [f8c57087c6261c…](https://bazaar.abuse.ch/sample/f8c57087c6261c45fd44c002bed22dcd75e8361ae8cf2170f56de8b1fdc28368/) | Mirai | Botnet/IoT | **85.1** | 🔴 KRITISCH | 9.3% | ⚠️ KAUM ERKANNT | ✗ |
| [59e0d43b006681…](https://bazaar.abuse.ch/sample/59e0d43b0066819d98375c242a7a68f17d39923513edf584f5c0154e40b7a104/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [568fdfdd2e64f9…](https://bazaar.abuse.ch/sample/568fdfdd2e64f93a53a1ac9b844f140f212ead459a8e1dabb51bf0221c31c406/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [935976acd84052…](https://bazaar.abuse.ch/sample/935976acd84052347fb65815be3a32ded9b4665ac028ff1e63615812d0b1f242/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [61348827b821b2…](https://bazaar.abuse.ch/sample/61348827b821b2fb62f8d5abe2b6837d45b985b3b68f3caac97e689e03ed164e/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [3ea89597e07592…](https://bazaar.abuse.ch/sample/3ea89597e075923d11bb7d29eaf29aa78aa5189ed62f941458fb3b739e36cabb/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6120/7557 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6120/7557 |
| 3 | ESET-NOD32 | 77.3% | 5842/7557 |
| 4 | Kaspersky | 76.0% | 5745/7556 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.3% | 5385/7554 |
| 8 | Rising | 68.5% | 5174/7557 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5001/7553 |
| 11 | Avast | 65.3% | 4929/7553 |
| 12 | AVG | 65.3% | 4929/7552 |
| 13 | Tencent | 65.0% | 4768/7331 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4625/7550 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 61 | 60.4% |
| 🪟 Windows | 27 | 26.7% |
| 📦 Archiv | 9 | 8.9% |
| ❓ Unbekannt | 2 | 2.0% |
| 📄 Dokument | 1 | 1.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 97 | 96.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |
| MaaS-Loader | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇮🇳 IN | 37 | 36.6% |
| 2 | 🇺🇸 US | 27 | 26.7% |
| 3 | 🇬🇧 GB | 7 | 6.9% |
| 4 | 🇳🇱 NL | 7 | 6.9% |
| 5 | 🇩🇪 DE | 7 | 6.9% |
| 6 | 🌐 AE | 6 | 5.9% |
| 7 | 🇭🇺 HU | 5 | 5.0% |
| 8 | 🇫🇷 FR | 2 | 2.0% |
| 9 | 🇦🇹 AT | 1 | 1.0% |
| 10 | 🇨🇦 CA | 1 | 1.0% |
| 11 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 39 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 37 |
| Lateral Movement | 37 |
| Credential Access | 2 |
| Exfiltration | 2 |

<details><summary>57b4d9fb4667d070220d… – LummaStealer | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |

</details>
<details><summary>a1f549624f4f5122b012… – Mirai | 🔴 KRITISCH 85.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>7dcdc5bf598c24904876… – Mirai | 🔴 KRITISCH 85.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>f8c57087c6261c45fd44… – Mirai | 🔴 KRITISCH 85.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [a1f549624f4f5122b012…](https://bazaar.abuse.ch/sample/a1f549624f4f5122b012c6047f5bc1523310492f3d6b9bce874bfd020b7d451e/)

- **Familie:** Mirai
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| huorong | `Trojan/Linux.Mirai.jx` |

### [f8c57087c6261c45fd44…](https://bazaar.abuse.ch/sample/f8c57087c6261c45fd44c002bed22dcd75e8361ae8cf2170f56de8b1fdc28368/)

- **Familie:** Mirai
- **Erkannt von:** 7 von 75 Engines (9.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (7/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| DrWeb | `Linux.DDoS.3349` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| huorong | `Trojan/Linux.Mirai.jx` |

### [7dcdc5bf598c24904876…](https://bazaar.abuse.ch/sample/7dcdc5bf598c24904876fcc997a7c7bc1d219835d9c41bb2f53c7a8166f83aa3/)

- **Familie:** Mirai
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** ELF:Agent-ESV [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-ESV [Trj]` |
| Avast | `ELF:Agent-ESV [Trj]` |
| ESET-NOD32 | `Linux/Flooder.Agent.OL trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xu` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| huorong | `Trojan/Linux.Mirai.jx` |

### [d751e9f3b56f8780a9c9…](https://bazaar.abuse.ch/sample/d751e9f3b56f8780a9c9fe089103c5520b1d398ca5f958964be2693cde596437/)

- **Familie:** Kaiji
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Agent.GQRF
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Agent.GQRF`

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Agent.GQRF` |
| AVG | `BV:Downloader-AEH [Drp]` |
| Arcabit | `Trojan.Agent.GQRF` |
| Avast | `BV:Downloader-AEH [Drp]` |
| Avira | `HTML/ExpKit.Gen2` |
| BitDefender 🛡️ | `Trojan.Agent.GQRF` |
| CTX | `shell.trojan.gqrf` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2650` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.BNO trojan` |
| Emsisoft | `Trojan.Agent.GQRF (B)` |
| F-Secure | `Malware.HTML/ExpKit.Gen2` |
| GData | `Trojan.Agent.GQRF` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Sh` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.p` |
| Kingsoft | `Script.Troj.shell.2023140` |
| MicroWorld-eScan | `Trojan.Agent.GQRF` |
| Microsoft 🛡️ | `TrojanDownloader:SH/SAgent.A!MTB` |
| Sangfor | `Trojan.Generic-Script.Save.ba568` |
| Skyhigh | `LINUX/Downloader.ei` |
| Symantec | `CL.Downloader!gen277` |
| TrellixENS | `LINUX/Downloader.ei` |
| VIPRE | `Trojan.Agent.GQRF` |
| Varist | `SH/Mirai.D.gen!Camelot` |
| huorong | `TrojanDownloader/Linux.CoinMiner.a!crit` |

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

- **Mirai** (36×)
- **elf** (10×)
- **upx** (9×)
- **Kaiji** (8×)
- **172-82-64-48** (7×)
- **zip** (7×)
- **opendir** (6×)
- **exe** (4×)
- **stealer** (3×)
- **jar** (2×)
- **ps1** (2×)
- **upx-dec** (2×)
- **Gafgyt** (2×)
- **funrat** (1×)
- **java** (1×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -10 (57→47)
- ↑ **Mirai** +28 (9→37)
- neu: **Kaiji** (8)
- neu: **Gafgyt** (3)
- neu: **RemusStealer** (1)
- neu: **LummaStealer** (1)
- neu: **ConnectWise** (1)
- neu: **WannaCry** (1)
- weg: **CoinMiner** (war 18)
- weg: **RemcosRAT** (war 4)
- weg: **Formbook** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +8 (39→47)
- ↑ **Mirai** +16 (21→37)
- neu: **Kaiji** (8)
- neu: **Gafgyt** (3)
- neu: **RustyStealer** (1)
- neu: **LummaStealer** (1)
- neu: **ConnectWise** (1)
- neu: **WannaCry** (1)
- neu: **PythonStealer** (1)
- weg: **RemcosRAT** (war 2)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.761 MB |
| σ Dateigröße | 8.580 MB |
| Ø Risiko-Score | 59.6/100 |
| Ø Klassifikations-Konfidenz | 62.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 39/101 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 41 |
| Unbekannte Familien | 12 (11.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 19:24 | [babb1fadc0ae…](https://bazaar.abuse.ch/sample/babb1fadc0ae3e1fd31ff0074be320caaba1e0c950df22b792004e8f469c0aa7/) | `jar` | unbekannt | 81.8 | – | – | 🌐AT |
| 19:23 | [b199422fe5f1…](https://bazaar.abuse.ch/sample/b199422fe5f11a4c532f05fbca85446edd426c70fb4f330bb7f78e566f5bd66a/) | `rar` | unbekannt | 32.3 | – | – | 🌐HU |
| 19:20 | [e6eca876f1e4…](https://bazaar.abuse.ch/sample/e6eca876f1e4423eadde8298c879774118f094d0b714a9dd202883b50ddc02dc/) | `doc` | unbekannt | 38.7 | – | – | 🌐HU |
| 19:12 | [09af553a032a…](https://bazaar.abuse.ch/sample/09af553a032ac6591b9f1271ade103549946640a82136dc2cee4b1da6a488552/) | `msi` | unbekannt | 38.5 | – | – | 🌐HU |
| 19:11 | [349ae6453976…](https://bazaar.abuse.ch/sample/349ae645397631e76e49a39a7e9486cfe7638566ef0f6bb9d3a8c2f942cf98a2/) | `zip` | unbekannt | 32.2 | – | – | 🇬🇧GB |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 22.10.2026 19:50 UTC*