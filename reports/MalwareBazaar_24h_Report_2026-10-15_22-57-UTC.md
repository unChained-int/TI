# MalwareBazaar – 15.10.2026 22:57 UTC

Dieser Run hat **26 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **27** |
| Kritisch (≥75) | **10** |
| Höchster Score | **82.6/100** – 6fbae9084529a4a8… |
| Häufigste Familie | **unbekannt** (21x) |
| Häufigster Typ | **exe** (19x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 1 Samples |
| Ø Dateigröße | 4.41 MB (σ=10.77) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 19 | 70.4%  ██████████████ |
| `hta` | 3 | 11.1%  ██ |
| `elf` | 1 | 3.7%   |
| `sh` | 1 | 3.7%   |
| `jar` | 1 | 3.7%   |
| `ps1` | 1 | 3.7%   |
| `dmg` | 1 | 3.7%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 21 | 77.8% |
| 2 | Win64:MalwareX-gen [Drp] | 1 | 3.7% |
| 3 | FleetDeck | 1 | 3.7% |
| 4 | MalwareX-gen [Drp] | 1 | 3.7% |
| 5 | Script | 1 | 3.7% |
| 6 | Agent | 1 | 3.7% |
| 7 | RemcosRAT | 1 | 3.7% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 6 | 22.2% | 35% |
| Infostealer | 6 | 22.2% | 75% |
| Loader | 4 | 14.8% | 75% |
| Andere / Unbekannt | 3 | 11.1% | 20% |
| Trojaner | 3 | 11.1% | 65% |
| Skript/Dropper | 2 | 7.4% | 35% |
| RAT | 2 | 7.4% | 85% |
| Linux-Malware | 1 | 3.7% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 10 | 37.0% |
| 🟠 HOCH | 5 | 18.5% |
| 🟡 MITTEL | 9 | 33.3% |
| 🟢 NIEDRIG | 3 | 11.1% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [6fbae9084529a4…](https://bazaar.abuse.ch/sample/6fbae9084529a4a8aa3c86138d5a60f8480134a7f6783ee3d2559749e957a8ed/) | Script | Trojaner | **82.6** | 🔴 KRITISCH | 1.3% | ⚠️ KAUM ERKANNT | ✗ |
| [e5b790c3a237ed…](https://bazaar.abuse.ch/sample/e5b790c3a237edc2c55f01a7c648d0eaf8e969a1a9223aff605a90a1d42900b7/) | unbekannt | Infostealer | **82.1** | 🔴 KRITISCH | – | – | ? |
| [404e448f179f66…](https://bazaar.abuse.ch/sample/404e448f179f662439bd08b2abbcddcaaf0034d11d786cc878cce6f9ef57b570/) | unbekannt | Infostealer | **82.1** | 🔴 KRITISCH | – | – | ? |
| [bb518757a09ffe…](https://bazaar.abuse.ch/sample/bb518757a09ffe9c92755bf86d86d589204ece9869918c7497c8739825bcc914/) | unbekannt | Infostealer | **82.1** | 🔴 KRITISCH | – | – | ? |
| [fb799fbe2729fa…](https://bazaar.abuse.ch/sample/fb799fbe2729fa88358d32375c15aa41b2de62e981655e60d4f53efb4e4fee73/) | unbekannt | Infostealer | **82.1** | 🔴 KRITISCH | – | – | ? |
| [cd0db049130475…](https://bazaar.abuse.ch/sample/cd0db04913047500d062f676d4099aced7ef039c7e12cebaddff6aac41def3ea/) | unbekannt | Infostealer | **82.0** | 🔴 KRITISCH | – | – | ? |
| [46659614c3bddf…](https://bazaar.abuse.ch/sample/46659614c3bddf6ff859af68fbd7d1faa53c3d6ba9e69d8f8820acb59b72f503/) | Agent | Trojaner | **81.4** | 🔴 KRITISCH | 5.3% | ⚠️ KAUM ERKANNT | ✗ |
| [26646cd038fad9…](https://bazaar.abuse.ch/sample/26646cd038fad9dbc2c2e5988043516b3f2fbc03e1f197a7cef8380e3499ba7d/) | MalwareX-gen [Drp] | Trojaner | **80.2** | 🔴 KRITISCH | 10.7% | 🟡 SCHWACH ERKANNT | ✗ |
| [2a6960cd53f862…](https://bazaar.abuse.ch/sample/2a6960cd53f862d3f2dace1e4758ff2f4981619428d7687e231d95b9426bbe79/) | unbekannt | Infostealer | **80.0** | 🔴 KRITISCH | – | – | ? |
| [f25ba62c66bee6…](https://bazaar.abuse.ch/sample/f25ba62c66bee6e6bb582064ffd048043015f3718a59fa8c56546d7998c420c0/) | unbekannt | RAT | **79.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5986/7401 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5986/7401 |
| 3 | ESET-NOD32 | 77.4% | 5732/7401 |
| 4 | Kaspersky | 76.4% | 5651/7400 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5293/7398 |
| 8 | Rising | 68.8% | 5089/7401 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4916/7397 |
| 11 | Tencent | 65.3% | 4688/7175 |
| 12 | Avast | 65.1% | 4814/7397 |
| 13 | AVG | 65.1% | 4814/7396 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4534/7394 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 23 | 85.2% |
| 🐧 Linux | 2 | 7.4% |
| ❓ Unbekannt | 1 | 3.7% |
| 🍎 macOS | 1 | 3.7% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 23 | 85.2% |
| C2 / Nachladen | 4 | 14.8% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 15 | 55.6% |
| 2 | 🇭🇺 HU | 6 | 22.2% |
| 3 | 🇩🇪 DE | 3 | 11.1% |
| 4 | 🇳🇱 NL | 2 | 7.4% |
| 5 | 🌐 Unbekannt | 1 | 3.7% |

## MITRE ATT&CK

> 1 von 27 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Command and Control | 1 |
| Collection | 1 |


## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [3508e6cb5ce9a6f5e78e…](https://bazaar.abuse.ch/sample/3508e6cb5ce9a6f5e78e5a636ee358fe47b6496f9af948fcce0cd7bf296d9690/)

- **Familie:** Win64:MalwareX-gen [Drp]
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Drp]` |
| AhnLab-V3 | `Trojan/Win.Generic.R758764` |
| Alibaba | `TrojanDropper:Win32/MalwareX.a6d5b090` |
| Avast | `Win64:MalwareX-gen [Drp]` |
| Avira | `DR/W64.MalwareX` |
| Bkav | `W32.Malware.2F4E5DDC` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/TrojanDropper.Agent.GZ trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Dropper.DR/W64.MalwareX` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `ti!3508E6CB5CE9` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Backdoor.CobaltStrike!8.197F7 (TFE:dGZlOiiTmPJvRLpkQw)` |
| Sangfor | `Dropper.Win64.Agent.V9vu` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Win32.Trojan.W64.Ddhl` |
| alibabacloud | `Trojan[dropper]:Multi/MalwareX.Gen` |
| huorong | `Backdoor/Lotok.y` |

### [26646cd038fad9dbc2c2…](https://bazaar.abuse.ch/sample/26646cd038fad9dbc2c2e5988043516b3f2fbc03e1f197a7cef8380e3499ba7d/)

- **Familie:** MalwareX-gen [Drp]
- **Erkannt von:** 8 von 75 Engines (10.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Drp]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `MalwareX-gen [Drp]` |
| Alibaba | `Trojan:Win32/Injuke.287ea19c` |
| Avast | `MalwareX-gen [Drp]` |
| Kaspersky | `Trojan.Win32.Injuke.qgku` |
| Kingsoft | `Win32.Troj.Unknown.a` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Injuke!8.10932 (CLOUD)` |
| Sophos | `Mal/Generic-S` |

### [6fbae9084529a4a8aa3c…](https://bazaar.abuse.ch/sample/6fbae9084529a4a8aa3c86138d5a60f8480134a7f6783ee3d2559749e957a8ed/)

- **Familie:** Script
- **Erkannt von:** 1 von 75 Engines (1.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** HEUR:Trojan.Script.Agent.gen
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (1/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Kaspersky | `HEUR:Trojan.Script.Agent.gen` |

### [46659614c3bddf6ff859…](https://bazaar.abuse.ch/sample/46659614c3bddf6ff859af68fbd7d1faa53c3d6ba9e69d8f8820acb59b72f503/)

- **Familie:** Agent
- **Erkannt von:** 4 von 75 Engines (5.3%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** JS/TrojanDownloader.Agent.AFCN trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/75):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `JS.Phishing.1011` |
| ESET-NOD32 | `JS/TrojanDownloader.Agent.AFCN trojan` |
| Kingsoft | `Script.Troj.hta.2060232` |
| huorong | `Trojan/JS.Obfuscated.il!crit` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (61/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Rat]` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
| Avast | `Win32:MalwareX-gen [Rat]` |
| Avira | `BDS/Backdoor.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Remcos.23` |
| Bkav | `W32.Malware.D80B3EFB` |
| CAT-QuickHeal | `Trojan.Remcos.S39598516` |
| CTX | `exe.trojan.remcos` |
| ClamAV | `Win.Trojan.Remcos-9841897-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.630` |
| ESET-NOD32 | `Win32/Rescoms.B trojan` |
| Elastic | `Windows.Trojan.Remcos` |
| Emsisoft | `Gen:Variant.Remcos.23 (B)` |
| F-Secure | `Backdoor.BDS/Backdoor.Gen` |
| Fortinet | `W32/Rescomms.B!tr` |
| GData | `Gen:Variant.Remcos.23` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Remcos.oa!s1` |
| Ikarus | `Backdoor.Remcos` |
| K7AntiVirus | `Backdoor ( 005ce3801 )` |
| K7GW | `Backdoor ( 005ce3801 )` |
| Kaspersky | `HEUR:Backdoor.Win32.Remcos.gen` |
| Kingsoft | `Win32.Hack.Remcos.gen` |
| Lionic | `Trojan.Win32.Rescoms.m!c` |
| Malwarebytes | `Backdoor.Remcos` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Backdoor.Remcos!1.BAC7 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.hh` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrellixENS | `RAT/Remcos!D532A55294F7` |
| TrendMicro | `Backdoor.Win32.REMCOS.USBLJB26` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **exe** (18×)
- **Stealer** (6×)
- **Warden** (5×)
- **WardenStealer** (5×)
- **signed** (5×)
- **dropped-by-GCleaner** (4×)
- **hta** (3×)
- **B** (2×)
- **MIX3.file** (2×)
- **FleetDeck** (1×)
- **jar** (1×)
- **java** (1×)
- **python** (1×)
- **silentnet** (1×)
- **F** (1×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +3 (18→21)
- neu: **Win64:MalwareX-gen [Drp]** (1)
- neu: **FleetDeck** (1)
- neu: **MalwareX-gen [Drp]** (1)
- neu: **Script** (1)
- neu: **Agent** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Mirai** (war 23)
- weg: **Formbook** (war 2)
- weg: **DDoSAgent** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -7 (28→21)
- neu: **Win64:MalwareX-gen [Drp]** (1)
- neu: **FleetDeck** (1)
- neu: **MalwareX-gen [Drp]** (1)
- neu: **Script** (1)
- neu: **Agent** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Mirai** (war 35)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.412 MB |
| σ Dateigröße | 10.770 MB |
| Ø Risiko-Score | 59.6/100 |
| Ø Klassifikations-Konfidenz | 55.6% |
| Samples mit VT | 5/27 |
| Samples mit MITRE | 1/27 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 22 |
| Unbekannte Familien | 3 (11.1%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 22:54 | [ff681630d707…](https://bazaar.abuse.ch/sample/ff681630d707f5903ea3d75c36f2bb87b2156636907268caa2e512032f5e6bf0/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 22:51 | [1350c4c4371a…](https://bazaar.abuse.ch/sample/1350c4c4371a1526d54ada91f98e089ffc12ef59df098c97b73e0480efba7daf/) | `exe` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 22:46 | [e5b790c3a237…](https://bazaar.abuse.ch/sample/e5b790c3a237edc2c55f01a7c648d0eaf8e969a1a9223aff605a90a1d42900b7/) | `exe` | unbekannt | 82.1 | – | – | 🇺🇸US |
| 22:46 | [404e448f179f…](https://bazaar.abuse.ch/sample/404e448f179f662439bd08b2abbcddcaaf0034d11d786cc878cce6f9ef57b570/) | `exe` | unbekannt | 82.1 | – | – | 🇺🇸US |
| 22:46 | [bb518757a09f…](https://bazaar.abuse.ch/sample/bb518757a09ffe9c92755bf86d86d589204ece9869918c7497c8739825bcc914/) | `exe` | unbekannt | 82.1 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 15.10.2026 22:57 UTC*