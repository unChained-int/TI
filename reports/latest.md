# MalwareBazaar – 21.10.2026 07:16 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **39** |
| Höchster Score | **90.0/100** – 3d16916c040840b0… |
| Häufigste Familie | **unbekannt** (35x) |
| Häufigster Typ | **exe** (57x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 65 Samples |
| Ø Dateigröße | 13.02 MB (σ=15.69) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 57 | 56.4%  ███████████ |
| `elf` | 21 | 20.8%  ████ |
| `zip` | 12 | 11.9%  ██ |
| `hta` | 3 | 3.0%   |
| `js` | 3 | 3.0%   |
| `jar` | 1 | 1.0%   |
| `ps1` | 1 | 1.0%   |
| `bat` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 35 | 34.7% |
| 2 | Mirai | 21 | 20.8% |
| 3 | CoinMiner | 19 | 18.8% |
| 4 | N-able | 4 | 4.0% |
| 5 | ArkeiStealer | 3 | 3.0% |
| 6 | RustyStealer | 3 | 3.0% |
| 7 | SmartLoader | 3 | 3.0% |
| 8 | RemcosRAT | 2 | 2.0% |
| 9 | Amadey | 2 | 2.0% |
| 10 | Formbook | 1 | 1.0% |
| 11 | ParallaxRAT | 1 | 1.0% |
| 12 | Yogi | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Loader | 46 | 45.5% | 76% |
| Botnet/IoT | 21 | 20.8% | 95% |
| Infostealer | 10 | 9.9% | 81% |
| Windows-Malware | 10 | 9.9% | 35% |
| Andere / Unbekannt | 5 | 5.0% | 20% |
| Skript/Dropper | 4 | 4.0% | 35% |
| RAT | 4 | 4.0% | 90% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 39 | 38.6% |
| 🟠 HOCH | 43 | 42.6% |
| 🟡 MITTEL | 14 | 13.9% |
| 🟢 NIEDRIG | 5 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [3d16916c040840…](https://bazaar.abuse.ch/sample/3d16916c040840b0d9b97c800684a37f0f10fff736f58ca63b667f1618bcbb71/) | Formbook | Infostealer | **90.0** | 🔴 KRITISCH | – | – | ? |
| [68b736e2aa1c56…](https://bazaar.abuse.ch/sample/68b736e2aa1c565c1748fcb17a5e44bbf1727714047fbf50e8c9c9d6844fe6ea/) | AMOS | Infostealer | **89.5** | 🔴 KRITISCH | – | – | ? |
| [2acd328d5843e8…](https://bazaar.abuse.ch/sample/2acd328d5843e8a2c1d871d7b0977c24654ec2fd90ad2fd8ab8b12e3101bd1bd/) | Vidar | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [16b395cac15981…](https://bazaar.abuse.ch/sample/16b395cac159811c5c38425170a9f7cd9d6802b4baa08a2eb5c2f3ad395a8813/) | XWorm | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [54146bd37bcab5…](https://bazaar.abuse.ch/sample/54146bd37bcab50ed1b37c6a8827a8ebe71ea9ccb80d8d50540dd39f9285021a/) | RemcosRAT | RAT | **88.4** | 🔴 KRITISCH | 13.3% | 🟡 SCHWACH ERKANNT | ✓ |
| [0d705051661953…](https://bazaar.abuse.ch/sample/0d705051661953231ea734323cb0156041033746b77060d25f5fb1a01423273d/) | RemcosRAT | RAT | **88.1** | 🔴 KRITISCH | – | – | ? |
| [68ee44a6026131…](https://bazaar.abuse.ch/sample/68ee44a60261316f5349adb341e97471efa5e8d13d80229fd397f9a25f85f4f0/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [04fcd925d1987f…](https://bazaar.abuse.ch/sample/04fcd925d1987f3b4032bd676e58715c3b3af8b26d1e6ff68d1509f2c9dd1d7a/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [073acd8059a1c4…](https://bazaar.abuse.ch/sample/073acd8059a1c492fcfe4bee8b5a6134003d85a4f30f5718a9a9c21d842d16e3/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [a8d77d8b93bb8f…](https://bazaar.abuse.ch/sample/a8d77d8b93bb8f726f7f8eab585933a6192806a48c49f5f4d5f7242fdade6ccf/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6093/7527 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6093/7527 |
| 3 | ESET-NOD32 | 77.3% | 5820/7527 |
| 4 | Kaspersky | 76.2% | 5732/7526 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.4% | 5372/7524 |
| 8 | Rising | 68.6% | 5167/7527 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 4983/7523 |
| 11 | Avast | 65.2% | 4906/7523 |
| 12 | AVG | 65.2% | 4906/7522 |
| 13 | Tencent | 65.1% | 4754/7301 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4610/7520 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 57 | 56.4% |
| 🐧 Linux | 23 | 22.8% |
| 📦 Archiv | 16 | 15.8% |
| ❓ Unbekannt | 4 | 4.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 52 | 51.5% |
| C2 / Nachladen | 39 | 38.6% |
| MaaS-Loader | 7 | 6.9% |
| Drive-By / Exploit-Kit | 3 | 3.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 64 | 63.4% |
| 2 | 🇩🇪 DE | 17 | 16.8% |
| 3 | 🇳🇱 NL | 13 | 12.9% |
| 4 | 🇨🇭 CH | 5 | 5.0% |
| 5 | 🇭🇺 HU | 1 | 1.0% |
| 6 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 65 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 42 |
| Credential Access | 40 |
| Exfiltration | 39 |
| Initial Access | 21 |
| Lateral Movement | 21 |
| Command and Control | 2 |
| Execution | 2 |
| Persistence | 2 |

<details><summary>3d16916c040840b0d9b9… – Formbook | 🔴 KRITISCH 90.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>2acd328d5843e8a2c1d8… – Vidar | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>54146bd37bcab50ed1b3… – RemcosRAT | 🔴 KRITISCH 88.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [4c214f78ae730325c198…](https://bazaar.abuse.ch/sample/4c214f78ae730325c1988f05d3595e6e811e4dfae02bd7ae813148dcaa2fbb7f/)

- **Familie:** Yogi
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.94454
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.94454`

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.94454` |
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `CoinMiner/Win.CoinMiner.R801890` |
| Arcabit | `Trojan.Yogi.D170F6` |
| Avast | `FileRepMalware [Misc]` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.94454` |
| Bkav | `W32.Malware.BB4A852D` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik.HVJK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.94454 (B)` |
| McAfeeD | `ti!4C214F78AE73` |
| MicroWorld-eScan | `Gen:Variant.Yogi.94454` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| VIPRE | `Gen:Variant.Yogi.94454` |
| Webroot | `W32.Malware.Gen` |

### [54146bd37bcab50ed1b3…](https://bazaar.abuse.ch/sample/54146bd37bcab50ed1b37c6a8827a8ebe71ea9ccb80d8d50540dd39f9285021a/)

- **Familie:** RemcosRAT
- **Erkannt von:** 10 von 75 Engines (13.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Generic.BAT.Loader.2.C6527282
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.BAT.Loader.2.C6527282`

**Erkennende Engines (10/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.BAT.Loader.2.C6527282` |
| Arcabit | `Generic.BAT.Loader.2.C6527282` |
| BitDefender 🛡️ | `Generic.BAT.Loader.2.C6527282` |
| CTX | `txt.unknown.loader` |
| Emsisoft | `Generic.BAT.Loader.2.C6527282 (B)` |
| Fortinet | `BAT/CloudEye.MF!tr` |
| GData | `Generic.BAT.Loader.2.C6527282` |
| Kaspersky | `HEUR:Trojan.BAT.Agent.gen` |
| MicroWorld-eScan | `Generic.BAT.Loader.2.C6527282` |
| VIPRE | `Generic.BAT.Loader.2.C6527282` |

### [de338092770481364cde…](https://bazaar.abuse.ch/sample/de338092770481364cde26e993ae496aac07d12e6de4c9914a109b3e100f5fe2/)

- **Familie:** CoinMiner
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Cryp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:MalwareX-gen [Cryp]` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.FYX trojan` |
| Elastic | `malicious (high confidence)` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.88 (RDML:o5yCwQ9z+w+K0GNoqxSPUQ)` |
| Sangfor | `Trojan.Win32.Kryptik.Vxbl` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `OB:Trojan.Win32.Kryptik.16007442` |
| Webroot | `W32.Malware.Gen` |
| alibabacloud | `Trojan:Win/GenKryptik_AGen.FNF` |

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

- **exe** (56×)
- **signed** (40×)
- **dropped-by-Vidar** (38×)
- **elf** (21×)
- **CoinMiner** (19×)
- **Mirai** (17×)
- **github** (15×)
- **c1399bfb1be0a51415613edd6f0068c5** (12×)
- **zip** (12×)
- **19ccb70dbc12ef919d5869277e598933** (11×)
- **upx-dec** (9×)
- **upx** (9×)
- **d852ede598d72f2b3a4050576466ec62** (9×)
- **b89d843f29af2eed09805e9767a1165f** (5×)
- **lua** (5×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -11 (46→35)
- ↓ **Mirai** -1 (22→21)
- neu: **CoinMiner** (19)
- neu: **N-able** (4)
- neu: **ArkeiStealer** (3)
- neu: **RustyStealer** (3)
- neu: **SmartLoader** (3)
- ↑ **RemcosRAT** +1 (1→2)
- neu: **Amadey** (2)
- ↓ **Formbook** -1 (2→1)
- weg: **SalatStealer** (war 5)
- weg: **SilentNet** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +3 (32→35)
- ↓ **Mirai** -1 (22→21)
- neu: **CoinMiner** (19)
- neu: **N-able** (4)
- neu: **ArkeiStealer** (3)
- neu: **RustyStealer** (3)
- neu: **SmartLoader** (3)
- neu: **Amadey** (2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 13.024 MB |
| σ Dateigröße | 15.693 MB |
| Ø Risiko-Score | 70.2/100 |
| Ø Klassifikations-Konfidenz | 72.4% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 65/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 52 |
| Unbekannte Familien | 5 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 07:05 | [68ee44a60261…](https://bazaar.abuse.ch/sample/68ee44a60261316f5349adb341e97471efa5e8d13d80229fd397f9a25f85f4f0/) | `elf` | Mirai | 84.4 | – | – | 🇳🇱NL |
| 07:04 | [04fcd925d198…](https://bazaar.abuse.ch/sample/04fcd925d1987f3b4032bd676e58715c3b3af8b26d1e6ff68d1509f2c9dd1d7a/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 07:00 | [6604c5fbdada…](https://bazaar.abuse.ch/sample/6604c5fbdada3b0e5f6d40cec570e16c2b848488d20f02691815e17a762b3b7e/) | `exe` | unbekannt | 74.9 | – | – | 🇺🇸US |
| 06:57 | [1c02b3618681…](https://bazaar.abuse.ch/sample/1c02b3618681ee83d82db4d222de434f35f730a55d64c2cfec1bf69f59f6f378/) | `exe` | CoinMiner | 74.8 | – | – | 🇺🇸US |
| 06:49 | [6347f53c7472…](https://bazaar.abuse.ch/sample/6347f53c747238cb4ce2bd43355991a6a3c7187f68546dc5d186ff34dd47cea5/) | `exe` | unbekannt | 74.7 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 21.10.2026 07:16 UTC*