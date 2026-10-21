# MalwareBazaar – 21.10.2026 00:26 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **49** |
| Höchster Score | **89.3/100** – c47f262b49eb2c25… |
| Häufigste Familie | **unbekannt** (65x) |
| Häufigster Typ | **exe** (68x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 52 Samples |
| Ø Dateigröße | 10.94 MB (σ=11.01) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 68 | 67.3%  █████████████ |
| `elf` | 21 | 20.8%  ████ |
| `macho` | 7 | 6.9%  █ |
| `vbs` | 4 | 4.0%   |
| `js` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 65 | 64.4% |
| 2 | Mirai | 14 | 13.9% |
| 3 | SalatStealer | 12 | 11.9% |
| 4 | RemusStealer | 2 | 2.0% |
| 5 | ValleyRAT | 1 | 1.0% |
| 6 | RemcosRAT | 1 | 1.0% |
| 7 | Yogi | 1 | 1.0% |
| 8 | Prometei | 1 | 1.0% |
| 9 | njrat | 1 | 1.0% |
| 10 | AMOS | 1 | 1.0% |
| 11 | Malware | 1 | 1.0% |
| 12 | PythonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Loader | 43 | 42.6% | 75% |
| Infostealer | 22 | 21.8% | 76% |
| Botnet/IoT | 14 | 13.9% | 95% |
| Windows-Malware | 7 | 6.9% | 35% |
| Worm | 6 | 5.9% | 75% |
| Skript/Dropper | 4 | 4.0% | 35% |
| RAT | 3 | 3.0% | 88% |
| Linux-Malware | 1 | 1.0% | 45% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 49 | 48.5% |
| 🟠 HOCH | 40 | 39.6% |
| 🟡 MITTEL | 12 | 11.9% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c47f262b49eb2c…](https://bazaar.abuse.ch/sample/c47f262b49eb2c25ef3824dd3dff2c851a8f870edc9074ada9ad8803bc127c06/) | RemcosRAT | RAT | **89.3** | 🔴 KRITISCH | – | – | ? |
| [13b4b87da60463…](https://bazaar.abuse.ch/sample/13b4b87da6046356804ccfa023d66b9809371027b00f62fb4e4812dca34a1571/) | AMOS | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [6bba006161f3d1…](https://bazaar.abuse.ch/sample/6bba006161f3d18b18495b329961b76ec1a6ad6e7595c6b74e86f961049d5370/) | njrat | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [7996a43a6a0e6a…](https://bazaar.abuse.ch/sample/7996a43a6a0e6a518eca52551099d8fd17dc9b3900a01151431508fff0c7d908/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [3a04e47eed6c3f…](https://bazaar.abuse.ch/sample/3a04e47eed6c3fb22b2ebbe5d6e0fec970596290c4b792868078cc980d662174/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [73a5dcaa227c8d…](https://bazaar.abuse.ch/sample/73a5dcaa227c8d3096e45140e3afbd318bdf34b155b88d394473ff1b95b5d750/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [cb97c61e970fff…](https://bazaar.abuse.ch/sample/cb97c61e970fffd3754185ad951b09bab2580cf2d3694df770418603c11a06b9/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [9b092bb1ca0d06…](https://bazaar.abuse.ch/sample/9b092bb1ca0d0694f66cf4dbe09fc2a1a26eb3a56a8b9e3a5e975d991cefc269/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [7586f02e355f0f…](https://bazaar.abuse.ch/sample/7586f02e355f0feb543da420bb96579df7577e1582129b9058b78e2e8ea18221/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [c90b77ad0ed791…](https://bazaar.abuse.ch/sample/c90b77ad0ed791cca61c29baa0434e07c28bfab66b4306101f19bd04b9dae5a0/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6090/7523 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6090/7523 |
| 3 | ESET-NOD32 | 77.3% | 5818/7523 |
| 4 | Kaspersky | 76.2% | 5731/7522 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.4% | 5372/7520 |
| 8 | Rising | 68.7% | 5166/7523 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4982/7519 |
| 11 | Avast | 65.2% | 4903/7519 |
| 12 | AVG | 65.2% | 4903/7518 |
| 13 | Tencent | 65.1% | 4753/7297 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4608/7516 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 72 | 71.3% |
| 🐧 Linux | 21 | 20.8% |
| 🍎 macOS | 7 | 6.9% |
| ❓ Unbekannt | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 50 | 49.5% |
| C2 / Nachladen | 38 | 37.6% |
| MaaS-Loader | 6 | 5.9% |
| USB / Wechselmedium | 6 | 5.9% |
| Drive-By / Exploit-Kit | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 63 | 62.4% |
| 2 | 🇩🇪 DE | 12 | 11.9% |
| 3 | 🇳🇱 NL | 11 | 10.9% |
| 4 | 🇨🇦 CA | 6 | 5.9% |
| 5 | 🇨🇭 CH | 4 | 4.0% |
| 6 | 🇧🇬 BG | 3 | 3.0% |
| 7 | 🇫🇷 FR | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 52 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 38 |
| Credential Access | 36 |
| Exfiltration | 36 |
| Initial Access | 14 |
| Lateral Movement | 14 |
| Command and Control | 2 |

<details><summary>c47f262b49eb2c25ef38… – RemcosRAT | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>6bba006161f3d18b1849… – njrat | 🔴 KRITISCH 88.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>7996a43a6a0e6a518eca… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>3a04e47eed6c3fb22b2e… – Mirai | 🔴 KRITISCH 83.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [f2aefa81a342a164c91b…](https://bazaar.abuse.ch/sample/f2aefa81a342a164c91b0f8f0fec351e3dc857d0abf5b5933736ea2a5a0b1850/)

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
| Bkav | `W32.Malware.D8FF077C` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik.HVJK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.94454 (B)` |
| McAfeeD | `ti!F2AEFA81A342` |
| MicroWorld-eScan | `Gen:Variant.Yogi.94454` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| VIPRE | `Gen:Variant.Yogi.94454` |
| Webroot | `W32.Malware.Gen` |

### [8c2b247214f3e95165c4…](https://bazaar.abuse.ch/sample/8c2b247214f3e95165c43757c603aacc6742f3f0d83f364934b05a89a0b9ba44/)

- **Familie:** Malware
- **Erkannt von:** 14 von 75 Engines (18.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.B14BD10F
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (14/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `Trojan/Win.MalwareX-gen.R800440` |
| Bkav | `W32.Malware.B14BD10F` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Injector.AOW trojan` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.Wacatac` |
| Malwarebytes | `Trojan.Injector` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Trojan.Kryptik@AI.87 (RDML:ohjoqHFou1fvOwOk9BpyyQ)` |
| Sangfor | `Trojan.Win32.Save.a` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/Agent.NJT.gen!Eldorado` |

### [d01ceaab8cf29d24ab4c…](https://bazaar.abuse.ch/sample/d01ceaab8cf29d24ab4c69bad06713e5890875812ca9e6eee1ab6a89d14969b5/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Backdoor.Linux.BASHLITE.SMJC11
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Gafgyt-KR [Trj]` |
| AhnLab-V3 | `Linux/Mirai01.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Gafgyt-KR [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-KS [Trj]` |
| Avira | `TR/LINUX.Gafgyt.KR` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.DKV trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `Trojan.TR/LINUX.Gafgyt.KR` |
| Fortinet | `ELF/UNSTABLE.AT!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Linux/Mirai.ERC` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AU!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.106E5 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.wan` |
| TrendMicro | `Backdoor.Linux.BASHLITE.SMJC11` |
| TrendMicro-HouseCall | `Backdoor.Linux.BASHLITE.SMJC11` |
| Varist | `E32/Mirai.DI.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.w!crit` |

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

- **exe** (67×)
- **signed** (37×)
- **dropped-by-Vidar** (36×)
- **elf** (21×)
- **19ccb70dbc12ef919d5869277e598933** (15×)
- **Mirai** (14×)
- **c1399bfb1be0a51415613edd6f0068c5** (12×)
- **SalatStealer** (12×)
- **upx-dec** (8×)
- **ClickFix** (7×)
- **Foxveil** (7×)
- **Mach-O** (7×)
- **macho** (7×)
- **macOS** (7×)
- **d852ede598d72f2b3a4050576466ec62** (7×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +17 (48→65)
- ↓ **Mirai** -8 (22→14)
- ↑ **SalatStealer** +10 (2→12)
- ↑ **RemusStealer** +1 (1→2)
- neu: **ValleyRAT** (1)
- neu: **Yogi** (1)
- neu: **Prometei** (1)
- neu: **njrat** (1)
- ↓ **AMOS** -1 (2→1)
- weg: **Formbook** (war 2)
- weg: **SilentNet** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +35 (30→65)
- ↓ **Mirai** -8 (22→14)
- ↑ **SalatStealer** +11 (1→12)
- ↑ **RemusStealer** +1 (1→2)
- ↓ **RemcosRAT** -1 (2→1)
- neu: **Yogi** (1)
- neu: **Prometei** (1)
- neu: **njrat** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 10.938 MB |
| σ Dateigröße | 11.007 MB |
| Ø Risiko-Score | 73.1/100 |
| Ø Klassifikations-Konfidenz | 73.6% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 52/101 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 52 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 00:25 | [09b5143a55ac…](https://bazaar.abuse.ch/sample/09b5143a55acbb87423681f6c70a1bbed0034289a7448becc5d3adab51fddb77/) | `macho` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 00:25 | [06e8c194b2df…](https://bazaar.abuse.ch/sample/06e8c194b2dfce2771dd27e0b8c029497ca6617e5719297cf39f08007e46ad45/) | `exe` | RemusStealer | 82.2 | – | – | 🇳🇱NL |
| 00:24 | [e62d2838d4b9…](https://bazaar.abuse.ch/sample/e62d2838d4b9ba224db88fa8e04d73064c4ef3a36b77592408e3872f2092b724/) | `exe` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 00:21 | [251711d57f85…](https://bazaar.abuse.ch/sample/251711d57f85b1f56d128ab44061a52d1b19c81265cac7404e7a1106ec6d8a93/) | `exe` | unbekannt | 75.0 | – | – | 🇺🇸US |
| 00:18 | [7e189c577e07…](https://bazaar.abuse.ch/sample/7e189c577e071818400830e2ae8ad41be5894064e33199e9c3d744c712f38542/) | `macho` | unbekannt | 75.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 21.10.2026 00:26 UTC*