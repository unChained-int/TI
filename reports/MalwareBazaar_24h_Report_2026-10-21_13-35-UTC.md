# MalwareBazaar – 21.10.2026 13:35 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **54** |
| Höchster Score | **84.4/100** – 085147fb40495ff1… |
| Häufigste Familie | **unbekannt** (98x) |
| Häufigster Typ | **zip** (89x) |
| Hauptplattform | **Archiv** |
| VT-angereichert | 3 Samples |
| MITRE gemappt | 6 Samples |
| Ø Dateigröße | 1.66 MB (σ=4.84) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `zip` | 89 | 88.1%  █████████████████ |
| `exe` | 9 | 8.9%  █ |
| `elf` | 2 | 2.0%   |
| `macho` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 98 | 97.0% |
| 2 | MalwareX-gen [Misc] | 1 | 1.0% |
| 3 | Mirai | 1 | 1.0% |
| 4 | PythonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Loader | 96 | 95.0% | 75% |
| Linux-Malware | 1 | 1.0% | 45% |
| Andere / Unbekannt | 1 | 1.0% | 20% |
| Cryptominer | 1 | 1.0% | 75% |
| Botnet/IoT | 1 | 1.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 54 | 53.5% |
| 🟠 HOCH | 45 | 44.6% |
| 🟡 MITTEL | 1 | 1.0% |
| 🟢 NIEDRIG | 1 | 1.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [085147fb40495f…](https://bazaar.abuse.ch/sample/085147fb40495ff1320a31165c7d0f3232ca577c0cd9e7ab359ef17e9252de26/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [b5421b200e08af…](https://bazaar.abuse.ch/sample/b5421b200e08af755cbc8f3580cea341285d35d4ca4e54c7edbf0d30d4fb608e/) | unbekannt | Loader | **81.8** | 🔴 KRITISCH | 0.0% | ⚠️ KAUM ERKANNT | ? |
| [f1a4496a1313d7…](https://bazaar.abuse.ch/sample/f1a4496a1313d71c240127097a9957b7ee287a17d043fe86a5509aac5e293636/) | unbekannt | Loader | **75.1** | 🔴 KRITISCH | – | – | ? |
| [5cd56cee732cd7…](https://bazaar.abuse.ch/sample/5cd56cee732cd7e1a94b19be3017fb4b42c1b19c402bd724880de886cb0d6202/) | unbekannt | Loader | **75.1** | 🔴 KRITISCH | – | – | ? |
| [f3149931d9f63c…](https://bazaar.abuse.ch/sample/f3149931d9f63cf3fec09569646045f589e522fb376a8521d67cab2a1b3a107e/) | unbekannt | Loader | **75.1** | 🔴 KRITISCH | – | – | ? |
| [d4d28ceee9251b…](https://bazaar.abuse.ch/sample/d4d28ceee9251b104c7560edb547956425633dc2f3b23874eb3b252a569d5a70/) | unbekannt | Loader | **75.1** | 🔴 KRITISCH | – | – | ? |
| [7f396a0b5adcc2…](https://bazaar.abuse.ch/sample/7f396a0b5adcc2a29f9208b30b8232a79f8acbad8383e694daba6e7746da3394/) | unbekannt | Loader | **75.1** | 🔴 KRITISCH | – | – | ? |
| [af287301e0f101…](https://bazaar.abuse.ch/sample/af287301e0f10162dd3a9e40ac11232499918c7a1f9a411546788088806c208c/) | unbekannt | Loader | **75.1** | 🔴 KRITISCH | – | – | ? |
| [fc0da89a7672c7…](https://bazaar.abuse.ch/sample/fc0da89a7672c7dd269d6ff98de7500c3049bfdb3566e4ca905cb563a6e9268b/) | unbekannt | Loader | **75.1** | 🔴 KRITISCH | – | – | ? |
| [feeeb4f429a786…](https://bazaar.abuse.ch/sample/feeeb4f429a786df06e6ec11f8fd159f87b3c02fd9b83d7ef0561e4614feb60f/) | unbekannt | Loader | **75.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6095/7529 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6095/7529 |
| 3 | ESET-NOD32 | 77.3% | 5821/7529 |
| 4 | Kaspersky | 76.2% | 5733/7528 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.4% | 5372/7526 |
| 8 | Rising | 68.6% | 5168/7529 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 4984/7525 |
| 11 | Avast | 65.2% | 4908/7525 |
| 12 | AVG | 65.2% | 4908/7524 |
| 13 | Tencent | 65.1% | 4755/7303 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4612/7522 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 📦 Archiv | 89 | 88.1% |
| 🪟 Windows | 9 | 8.9% |
| 🐧 Linux | 2 | 2.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| MaaS-Loader | 89 | 88.1% |
| C2 / Nachladen | 6 | 5.9% |
| Unbekannt / nicht bestimmbar | 6 | 5.9% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 96 | 95.0% |
| 2 | 🇩🇪 DE | 2 | 2.0% |
| 3 | 🇷🇺 RU | 1 | 1.0% |
| 4 | 🇨🇭 CH | 1 | 1.0% |
| 5 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 6 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Credential Access | 5 |
| Collection | 5 |
| Exfiltration | 5 |
| Initial Access | 1 |
| Lateral Movement | 1 |

<details><summary>085147fb40495ff1320a… – Mirai | 🔴 KRITISCH 84.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>b5421b200e08af755cbc… – unbekannt | 🔴 KRITISCH 81.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [24e0a8e56a0de9e58910…](https://bazaar.abuse.ch/sample/24e0a8e56a0de9e589107f58535b4c4207ca7fdcba9b96b9c07763f359566cb4/)

- **Familie:** MalwareX-gen [Misc]
- **Erkannt von:** 34 von 75 Engines (45.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** MalwareX-gen [Misc]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (34/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Misc]` |
| Antiy-AVL | `Trojan/Win32.Chapak` |
| Avast | `MalwareX-gen [Misc]` |
| Avira | `TR/Crypt.ZPACK.Gen` |
| Bkav | `W32.Malware.DE546E26` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Vidar.10` |
| ESET-NOD32 | `Win32/PSW.Agent.OGR trojan` |
| Elastic | `Windows.Trojan.Vidar` |
| F-Secure | `Trojan.TR/Crypt.ZPACK.Gen` |
| Kaspersky | `VHO:Trojan.Win32.Sdum.gen` |
| Kingsoft | `Win32.Trojan.Sdum.gen` |
| Malwarebytes | `Generic.Malware/Suspicious` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!DA0E713A493B` |
| Microsoft 🛡️ | `Trojan:Win32/Vidar.GJN!MTB` |
| Panda | `Trj/GdSda.A` |
| Rising | `Stealer.Vidar!1.11730 (CLASSIC)` |
| Sangfor | `Suspicious.Win32.Save.pkr` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Dropper.ch` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan-Banker.Win32.Bandra.16000514` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `GenericRXQK-HV!DA0E713A493B` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAJ` |
| VirIT | `Trojan.Win32.GenusT.FMTY` |
| alibabacloud | `Trojan:Win/Vidar.GGS2XJC` |
| huorong | `TrojanSpy/Stealer.ou` |

### [b5421b200e08af755cbc…](https://bazaar.abuse.ch/sample/b5421b200e08af755cbc8f3580cea341285d35d4ca4e54c7edbf0d30d4fb608e/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 1 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ? (nicht in diesem VT-Scan)

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

- **github** (89×)
- **lua** (89×)
- **SmartLoader** (89×)
- **zip** (89×)
- **exe** (8×)
- **dropped-by-Vidar** (5×)
- **19ccb70dbc12ef919d5869277e598933** (3×)
- **signed** (3×)
- **elf** (2×)
- **ClickFix** (2×)
- **55001da20373e92a4261b69e9f1087ac** (1×)
- **AMOS** (1×)
- **Foxveil** (1×)
- **Mach-O** (1×)
- **macho** (1×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +53 (45→98)
- neu: **MalwareX-gen [Misc]** (1)
- ↓ **Mirai** -17 (18→1)
- weg: **SilentNet** (war 2)
- weg: **Formbook** (war 2)
- weg: **RemcosRAT** (war 2)
- weg: **AMOS** (war 2)
- weg: **CoinMiner** (war 5)
- weg: **SalatStealer** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +66 (32→98)
- neu: **MalwareX-gen [Misc]** (1)
- ↓ **Mirai** -21 (22→1)
- neu: **PythonStealer** (1)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.664 MB |
| σ Dateigröße | 4.837 MB |
| Ø Risiko-Score | 74.2/100 |
| Ø Klassifikations-Konfidenz | 74.2% |
| Samples mit VT | 3/101 |
| Samples mit MITRE | 6/101 |
| Eindeutige Familien | 4 |
| Eindeutige Tags | 21 |
| Unbekannte Familien | 1 (1.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 13:33 | [f1a4496a1313…](https://bazaar.abuse.ch/sample/f1a4496a1313d71c240127097a9957b7ee287a17d043fe86a5509aac5e293636/) | `zip` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 13:33 | [5cd56cee732c…](https://bazaar.abuse.ch/sample/5cd56cee732cd7e1a94b19be3017fb4b42c1b19c402bd724880de886cb0d6202/) | `zip` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 13:33 | [f3149931d9f6…](https://bazaar.abuse.ch/sample/f3149931d9f63cf3fec09569646045f589e522fb376a8521d67cab2a1b3a107e/) | `zip` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 13:33 | [d4d28ceee925…](https://bazaar.abuse.ch/sample/d4d28ceee9251b104c7560edb547956425633dc2f3b23874eb3b252a569d5a70/) | `zip` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 13:33 | [7f396a0b5adc…](https://bazaar.abuse.ch/sample/7f396a0b5adcc2a29f9208b30b8232a79f8acbad8383e694daba6e7746da3394/) | `zip` | unbekannt | 75.1 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 21.10.2026 13:35 UTC*