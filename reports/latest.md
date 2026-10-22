# MalwareBazaar – 22.10.2026 09:15 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **25** |
| Höchster Score | **90.9/100** – 542b86f0589312bf… |
| Häufigste Familie | **unbekannt** (57x) |
| Häufigster Typ | **exe** (67x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 74 Samples |
| Ø Dateigröße | 12.79 MB (σ=11.61) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 67 | 66.3%  █████████████ |
| `elf` | 12 | 11.9%  ██ |
| `js` | 7 | 6.9%  █ |
| `ps1` | 3 | 3.0%   |
| `hta` | 3 | 3.0%   |
| `vbs` | 3 | 3.0%   |
| `sh` | 2 | 2.0%   |
| `macho` | 2 | 2.0%   |
| `xls` | 1 | 1.0%   |
| `py` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 57 | 56.4% |
| 2 | CoinMiner | 19 | 18.8% |
| 3 | Mirai | 9 | 8.9% |
| 4 | RemcosRAT | 5 | 5.0% |
| 5 | LxBaseRAT | 2 | 2.0% |
| 6 | Formbook | 1 | 1.0% |
| 7 | a310Logger | 1 | 1.0% |
| 8 | Gafgyt | 1 | 1.0% |
| 9 | AgentTesla | 1 | 1.0% |
| 10 | AsyncRAT | 1 | 1.0% |
| 11 | PureRAT | 1 | 1.0% |
| 12 | Trojan ( 006e7e6e1 ) | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Loader | 59 | 58.4% | 75% |
| Botnet/IoT | 10 | 9.9% | 95% |
| RAT | 9 | 8.9% | 88% |
| Skript/Dropper | 8 | 7.9% | 35% |
| Windows-Malware | 5 | 5.0% | 35% |
| Linux-Malware | 3 | 3.0% | 45% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Infostealer | 1 | 1.0% | 95% |
| Maldoc | 1 | 1.0% | 35% |
| Backdoor | 1 | 1.0% | 95% |
| Trojaner | 1 | 1.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 25 | 24.8% |
| 🟠 HOCH | 56 | 55.4% |
| 🟡 MITTEL | 17 | 16.8% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [542b86f0589312…](https://bazaar.abuse.ch/sample/542b86f0589312bf0e15096a5666b2e54630bcd458e2d02035b2fee39963a8fb/) | Gh0stRAT | Backdoor | **90.9** | 🔴 KRITISCH | – | – | ? |
| [aba911d9838ad6…](https://bazaar.abuse.ch/sample/aba911d9838ad6424ecad818874b2bc54636669f3964312293490c190e197f10/) | Formbook | Infostealer | **89.5** | 🔴 KRITISCH | – | – | ? |
| [e98d71d4476f4b…](https://bazaar.abuse.ch/sample/e98d71d4476f4b4b28602b5fde9dc5d493847d07571a97f42d157f5013a99204/) | RemcosRAT | RAT | **88.6** | 🔴 KRITISCH | – | – | ? |
| [f602bc26633792…](https://bazaar.abuse.ch/sample/f602bc26633792893cff08d8d3ff608b5c0b998d581ad54717fbec2e2339a415/) | RemcosRAT | RAT | **87.9** | 🔴 KRITISCH | – | – | ? |
| [b18543a2095963…](https://bazaar.abuse.ch/sample/b18543a2095963834c96803f37cc9ffbb6cd4d41e6cefefef1434ab7ac938ea6/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [f79faec32b002f…](https://bazaar.abuse.ch/sample/f79faec32b002f532c9cecf6f960bac480208c1e3386b18c734a31b64f089fad/) | AsyncRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [7bbd42de4d25ca…](https://bazaar.abuse.ch/sample/7bbd42de4d25caad10d0c58292e68474509d030dec0fef2200bda2d16049120f/) | RemcosRAT | RAT | **87.8** | 🔴 KRITISCH | – | – | ? |
| [0d13fb38d59c6a…](https://bazaar.abuse.ch/sample/0d13fb38d59c6aa5a1c8e7a8d9e6e22097b61c901a498beea0aa6d0e009e0459/) | RemcosRAT | RAT | **87.4** | 🔴 KRITISCH | – | – | ? |
| [8fc2f7cb7d3ad5…](https://bazaar.abuse.ch/sample/8fc2f7cb7d3ad512e1718c1e0d3a003e2bea5f7ab59e34dc7f03b250cd92246e/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [cb3165a030abd2…](https://bazaar.abuse.ch/sample/cb3165a030abd22158f80ce0e22186ae5f4522a5eb7d76c7431116178c917a2e/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6112/7547 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6112/7547 |
| 3 | ESET-NOD32 | 77.3% | 5835/7547 |
| 4 | Kaspersky | 76.1% | 5740/7546 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.3% | 5381/7544 |
| 8 | Rising | 68.5% | 5173/7547 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 4995/7543 |
| 11 | Avast | 65.2% | 4920/7543 |
| 12 | AVG | 65.2% | 4920/7542 |
| 13 | Tencent | 65.1% | 4766/7321 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4620/7540 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 76 | 75.2% |
| 🐧 Linux | 14 | 13.9% |
| ❓ Unbekannt | 8 | 7.9% |
| 🍎 macOS | 2 | 2.0% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| C2 / Nachladen | 58 | 57.4% |
| Unbekannt / nicht bestimmbar | 34 | 33.7% |
| Drive-By / Exploit-Kit | 7 | 6.9% |
| MaaS-Loader | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 69 | 68.3% |
| 2 | 🇩🇪 DE | 10 | 9.9% |
| 3 | 🇳🇱 NL | 8 | 7.9% |
| 4 | 🇸🇪 SE | 8 | 7.9% |
| 5 | 🇨🇦 CA | 4 | 4.0% |
| 6 | 🌐 EG | 1 | 1.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 74 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 64 |
| Credential Access | 59 |
| Exfiltration | 58 |
| Initial Access | 9 |
| Lateral Movement | 9 |
| Command and Control | 6 |
| Execution | 1 |

<details><summary>aba911d9838ad6424eca… – Formbook | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>e98d71d4476f4b4b2860… – RemcosRAT | 🔴 KRITISCH 88.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>f602bc26633792893cff… – RemcosRAT | 🔴 KRITISCH 87.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>b18543a2095963834c96… – RemcosRAT | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9bccc773079f8b44134e…](https://bazaar.abuse.ch/sample/9bccc773079f8b44134e0d90f7b8090f241515f71f6733bab9fd42cadc78c609/)

- **Familie:** CoinMiner
- **Erkannt von:** 8 von 75 Engines (10.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.CoinMiner.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/75):**

| Engine | Erkannter Name |
|--------|----------------|
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.FYX trojan` |
| Elastic | `malicious (moderate confidence)` |
| Lionic | `Trojan.Win32.CoinMiner.4!c` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `OB:Trojan.Win32.Kryptik.16007442` |
| Webroot | `W32.Malware.Gen` |

### [31eb9db333129f588baf…](https://bazaar.abuse.ch/sample/31eb9db333129f588baf5c1d5e7e7da119db0d1ff502da95408ef8d5a7e19f97/)

- **Familie:** Gafgyt
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Agent-AIN [PUP]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Agent-AIN [PUP]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Agent-AIN [PUP]` |
| Avira | `PUA/LINUX.Agent.AIN` |
| ClamAV | `Unix.Dropper.Mirai-7540662-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9829` |
| ESET-NOD32 | `Linux/Gafgyt.BTR trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `PotentialRisk.PUA/LINUX.Agent.AIN` |
| Fortinet | `ELF64/Mirai.TSU!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Gafgyt` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.fz` |
| Microsoft 🛡️ | `Backdoor:Linux/Gafgyt.BF!MTB` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| alibabacloud | `Backdoor:Linux/Gafgyt.BSY` |

### [b3eb2f5abb3c35894dee…](https://bazaar.abuse.ch/sample/b3eb2f5abb3c35894deedba32463a5bc04799a44b731da9b39373e78ae91004a/)

- **Familie:** Trojan ( 006e7e6e1 )
- **Erkannt von:** 19 von 75 Engines (25.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan ( 006e7e6e1 )
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (19/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AhnLab-V3 | `CoinMiner/Win.MalwareX-gen.R799089` |
| Bkav | `W32.Malware.183DE4BD` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.FUN trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/GenKryptik.FUN!tr` |
| Google | `Detected` |
| K7AntiVirus | `Trojan ( 006e7e6e1 )` |
| K7GW | `Trojan ( 006e7e6e1 )` |
| Kaspersky | `HEUR:Trojan.Win64.Agent.pef` |
| Malwarebytes | `Trojan.FakeGoogle` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Sophos | `ML/PE-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Kryptik.16006158` |
| Varist | `W64/AEi.59C958E0!Eldorado` |

### [177d490830425a468584…](https://bazaar.abuse.ch/sample/177d490830425a468584f8e513764238159e9935e6edf7b372dd42f5bd1dffd4/)

- **Familie:** CoinMiner
- **Erkannt von:** 9 von 75 Engines (12.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Cryp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (9/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:MalwareX-gen [Cryp]` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.FYX trojan` |
| Elastic | `malicious (high confidence)` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Tencent | `OB:Trojan.Win32.Kryptik.16007442` |
| Webroot | `W32.Malware.Gen` |

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

- **exe** (66×)
- **dropped-by-Vidar** (58×)
- **signed** (54×)
- **c1399bfb1be0a51415613edd6f0068c5** (20×)
- **CoinMiner** (19×)
- **19ccb70dbc12ef919d5869277e598933** (19×)
- **d852ede598d72f2b3a4050576466ec62** (16×)
- **Mirai** (9×)
- **js** (7×)
- **b89d843f29af2eed09805e9767a1165f** (5×)
- **RemcosRAT** (5×)
- **RAT** (5×)
- **55001da20373e92a4261b69e9f1087ac** (3×)
- **ps1** (3×)
- **hta** (3×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -5 (62→57)
- ↑ **CoinMiner** +11 (8→19)
- ↓ **Mirai** -10 (19→9)
- ↑ **RemcosRAT** +3 (2→5)
- neu: **LxBaseRAT** (2)
- neu: **a310Logger** (1)
- neu: **Gafgyt** (1)
- neu: **AsyncRAT** (1)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +21 (36→57)
- ↑ **CoinMiner** +17 (2→19)
- ↓ **Mirai** -13 (22→9)
- ↑ **RemcosRAT** +4 (1→5)
- neu: **LxBaseRAT** (2)
- neu: **a310Logger** (1)
- neu: **Gafgyt** (1)
- neu: **AgentTesla** (1)
- neu: **AsyncRAT** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 12.789 MB |
| σ Dateigröße | 11.606 MB |
| Ø Risiko-Score | 68.9/100 |
| Ø Klassifikations-Konfidenz | 70.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 74/101 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 39 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 09:12 | [6d5a7c36fb36…](https://bazaar.abuse.ch/sample/6d5a7c36fb36ff758cbbe27d4c509e5d17c23023945d74c91fcee33fb8f4c4e1/) | `exe` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 09:09 | [20127be7a27a…](https://bazaar.abuse.ch/sample/20127be7a27a8c2dd6fdebf7a69c59369961dbebd0fcb1d33f826d8d3efdce9c/) | `exe` | unbekannt | 75.0 | – | – | 🇺🇸US |
| 09:05 | [bfa94d333bf0…](https://bazaar.abuse.ch/sample/bfa94d333bf0b694d7ca7cee5dbe1d0bf4edc1d3b169876a3f58e7a1ed217cc8/) | `exe` | CoinMiner | 75.0 | – | – | 🇺🇸US |
| 09:05 | [21b26e4435c0…](https://bazaar.abuse.ch/sample/21b26e4435c0c6d8212ed91a5e70c13710d41faf912474d2d17ef21fa13ab361/) | `ps1` | unbekannt | 39.0 | – | – | 🇺🇸US |
| 09:00 | [d3428bbb655f…](https://bazaar.abuse.ch/sample/d3428bbb655fd4cd8ab327c2d9d57a40a407909aad0542c73c31f7e90ee98e67/) | `exe` | unbekannt | 74.9 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 22.10.2026 09:15 UTC*