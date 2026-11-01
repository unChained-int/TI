# MalwareBazaar – 01.11.2026 16:39 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **4** |
| Höchster Score | **84.8/100** – 3dc3659a6ca0b5e6… |
| Häufigste Familie | **unbekannt** (76x) |
| Häufigster Typ | **jar** (95x) |
| Hauptplattform | **Unbekannt** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 2 Samples |
| Ø Dateigröße | 1.48 MB (σ=3.62) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `jar` | 95 | 94.1%  ██████████████████ |
| `elf` | 3 | 3.0%   |
| `exe` | 2 | 2.0%   |
| `hta` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 76 | 75.2% |
| 2 | SilentNet | 20 | 19.8% |
| 3 | Mirai | 2 | 2.0% |
| 4 | HTA | 1 | 1.0% |
| 5 | Yogi | 1 | 1.0% |
| 6 | SalatStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Andere / Unbekannt | 95 | 94.1% | 20% |
| Botnet/IoT | 2 | 2.0% | 95% |
| Infostealer | 2 | 2.0% | 70% |
| Trojaner | 1 | 1.0% | 65% |
| Linux-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 4 | 4.0% |
| 🟠 HOCH | 1 | 1.0% |
| 🟡 MITTEL | 1 | 1.0% |
| 🟢 NIEDRIG | 95 | 94.1% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [3dc3659a6ca0b5…](https://bazaar.abuse.ch/sample/3dc3659a6ca0b5e60292778a27e905856debd2c9285f436f9356b0c055a88905/) | Mirai | Botnet/IoT | **84.8** | 🔴 KRITISCH | 14.7% | 🟡 SCHWACH ERKANNT | ✗ |
| [edebd3333e3f9c…](https://bazaar.abuse.ch/sample/edebd3333e3f9c035498a31301f88f64ffa417afce000eef158aa5044b5cfef5/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [5e237d144d7320…](https://bazaar.abuse.ch/sample/5e237d144d7320af81892286629e43b33775f79a78715ab09255fa855fa57fa7/) | HTA | Trojaner | **83.1** | 🔴 KRITISCH | 8.0% | ⚠️ KAUM ERKANNT | ✗ |
| [75a8d662531bbc…](https://bazaar.abuse.ch/sample/75a8d662531bbca14df10b8b36fb9a53fbff83d2b5b6710c161d5a1622bfff64/) | Yogi | Infostealer | **79.3** | 🔴 KRITISCH | 30.7% | 🟡 SCHWACH ERKANNT | ✓ |
| [7e4c129f5bd09b…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ | SalatStealer | Infostealer | **56.0** | 🟠 HOCH | 73.3% | ✅ GUT ERKANNT | ✓ |
| [d7f48cb76bd64f…](https://bazaar.abuse.ch/sample/d7f48cb76bd64f2868f61d660077c2353611b75dc708332e8c4c5be0c166ffbb/) | unbekannt | Linux-Malware | **43.1** | 🟡 MITTEL | – | – | ? |
| [f8e948c1ec83db…](https://bazaar.abuse.ch/sample/f8e948c1ec83db360da3cef76ccef41d56e82308040017bedc3deb3f5232e039/) | SilentNet | Andere / Unbek | **32.6** | 🟢 NIEDRIG | – | – | ? |
| [1f4ff8e96cd3b9…](https://bazaar.abuse.ch/sample/1f4ff8e96cd3b9b5619c74a5d921692f7447016da4080a0ecfee138f8974d175/) | SilentNet | Andere / Unbek | **32.6** | 🟢 NIEDRIG | – | – | ? |
| [407705985c70f0…](https://bazaar.abuse.ch/sample/407705985c70f0438a3a4fc69c2a822c7d3cca16a8479b68c1ee59ad938989a0/) | SilentNet | Andere / Unbek | **32.6** | 🟢 NIEDRIG | – | – | ? |
| [83153251da37eb…](https://bazaar.abuse.ch/sample/83153251da37eb17aa79701f03aab0356c1d8077a419a6fc7744e76e9754b604/) | SilentNet | Andere / Unbek | **32.6** | 🟢 NIEDRIG | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6298/7769 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6298/7769 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6005/7769 |
| 6 | Kaspersky | 75.5% | 5867/7768 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5529/7765 |
| 9 | Rising | 68.3% | 5306/7769 |
| 10 | Varist | 66.2% | 5137/7764 |
| 11 | Avast | 65.2% | 5059/7765 |
| 12 | AVG | 65.2% | 5059/7764 |
| 13 | Tencent | 64.9% | 4897/7543 |
| 14 | McAfeeD | 61.3% | 4760/7761 |
| 15 | huorong | 60.9% | 4724/7761 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| ❓ Unbekannt | 95 | 94.1% |
| 🪟 Windows | 3 | 3.0% |
| 🐧 Linux | 3 | 3.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 101 | 100.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 99 | 98.0% |
| 2 | 🇺🇸 US | 1 | 1.0% |
| 3 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 2 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 2 |
| Lateral Movement | 2 |

<details><summary>3dc3659a6ca0b5e60292… – Mirai | 🔴 KRITISCH 84.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>edebd3333e3f9c035498… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5e237d144d7320af8189…](https://bazaar.abuse.ch/sample/5e237d144d7320af81892286629e43b33775f79a78715ab09255fa855fa57fa7/)

- **Familie:** HTA
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan.HTA.Agent.IXP
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `JS.Phishing.1011` |
| ESET-NOD32 | `JS/TrojanDownloader.Agent.AFCN trojan` |
| Kingsoft | `Script.Troj.hta.2060232` |
| Microsoft 🛡️ | `Trojan:JS/Obfuse.SJ!MTB` |
| VirIT | `Trojan.HTA.Agent.IXP` |
| huorong | `Trojan/JS.Obfuscated.il!crit` |

### [3dc3659a6ca0b5e60292…](https://bazaar.abuse.ch/sample/3dc3659a6ca0b5e60292778a27e905856debd2c9285f436f9356b0c055a88905/)

- **Familie:** Mirai
- **Erkannt von:** 11 von 75 Engines (14.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-DKC [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (11/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-DKC [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-DKC [Trj]` |
| Avira | `TR/LINUX.Mirai.DKC` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.FDF trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.DKC` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.gen` |
| Tencent | `Trojan.Linux.Mirai.ha` |

### [75a8d662531bbca14df1…](https://bazaar.abuse.ch/sample/75a8d662531bbca14df10b8b36fb9a53fbff83d2b5b6710c161d5a1622bfff64/)

- **Familie:** Yogi
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.85599
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.85599`

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.85599` |
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R797565` |
| Arcabit | `Trojan.Yogi.D14E5F` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.85599` |
| Bkav | `W32.Malware.5FD397C7` |
| CTX | `dll.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/ShellcodeRunner.CQR trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.85599 (B)` |
| GData | `Gen:Variant.Yogi.85599` |
| K7AntiVirus | `Trojan ( 006d9bf01 )` |
| K7GW | `Trojan ( 006d9bf01 )` |
| Kaspersky | `VHO:Trojan.Win32.Convagent.gen` |
| MicroWorld-eScan | `Gen:Variant.Yogi.85599` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Malware.Undefined!8.C (TFE:6:C9WtrIs9t1G)` |
| VIPRE | `Gen:Variant.Yogi.85599` |
| huorong | `Trojan/W64.ShellLoader.ea!crit` |

### [7e4c129f5bd09beffae1…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** SalatStealer
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (55/75):**

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
| CTX | `exe.trojan.lummastealer` |
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
| Gridinsoft | `Trojan.Win32.Agent.sa` |
| Ikarus | `Win32.Outbreak` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Kaspersky | `UDS:Trojan-PSW.Win64.Salat` |
| Kingsoft | `Win32.Troj.salatstealer.v` |
| Lionic | `Trojan.Win32.Agent.tt6y` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!9E7BE912AC3C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| Sangfor | `Infostealer.Win32.Salatstealer.Vsjg` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570877` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9E7BE912AC3C` |
| TrendMicro | `TrojanSpy.Win32.SALATSTEALER.YXGJZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **jar** (95×)
- **SilentNet** (20×)
- **elf** (3×)
- **Mirai** (2×)
- **hta** (1×)
- **Torii** (1×)
- **DIVINEX** (1×)
- **exe** (1×)
- **stealer** (1×)
- **Warden** (1×)
- **WARDENStealer** (1×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +46 (30→76)
- neu: **SilentNet** (20)
- ↓ **Mirai** -20 (22→2)
- neu: **HTA** (1)
- neu: **Yogi** (1)
- ↓ **SalatStealer** -2 (3→1)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +51 (25→76)
- ↑ **SilentNet** +19 (1→20)
- ↓ **Mirai** -23 (25→2)
- neu: **HTA** (1)
- neu: **Yogi** (1)
- ↓ **SalatStealer** -15 (16→1)
- weg: **RemcosRAT** (war 2)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.484 MB |
| σ Dateigröße | 3.621 MB |
| Ø Risiko-Score | 34.9/100 |
| Ø Klassifikations-Konfidenz | 23.2% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 2/101 |
| Eindeutige Familien | 6 |
| Eindeutige Tags | 11 |
| Unbekannte Familien | 95 (94.1%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 16:28 | [f8e948c1ec83…](https://bazaar.abuse.ch/sample/f8e948c1ec83db360da3cef76ccef41d56e82308040017bedc3deb3f5232e039/) | `jar` | SilentNet | 32.6 | – | – | 🇩🇪DE |
| 16:28 | [1f4ff8e96cd3…](https://bazaar.abuse.ch/sample/1f4ff8e96cd3b9b5619c74a5d921692f7447016da4080a0ecfee138f8974d175/) | `jar` | SilentNet | 32.6 | – | – | 🇩🇪DE |
| 16:28 | [407705985c70…](https://bazaar.abuse.ch/sample/407705985c70f0438a3a4fc69c2a822c7d3cca16a8479b68c1ee59ad938989a0/) | `jar` | SilentNet | 32.6 | – | – | 🇩🇪DE |
| 16:28 | [83153251da37…](https://bazaar.abuse.ch/sample/83153251da37eb17aa79701f03aab0356c1d8077a419a6fc7744e76e9754b604/) | `jar` | SilentNet | 32.6 | – | – | 🇩🇪DE |
| 16:28 | [9219c6e6cd69…](https://bazaar.abuse.ch/sample/9219c6e6cd6980fcdbebc251a1522416fd199b1885643ca6363aae5293012306/) | `jar` | unbekannt | 32.6 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 01.11.2026 16:39 UTC*