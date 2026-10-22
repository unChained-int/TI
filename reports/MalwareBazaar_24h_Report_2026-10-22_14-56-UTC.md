# MalwareBazaar – 22.10.2026 14:56 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **24** |
| Höchster Score | **94.9/100** – a9309b8ca82e8d3a… |
| Häufigste Familie | **unbekannt** (65x) |
| Häufigster Typ | **exe** (77x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 68 Samples |
| Ø Dateigröße | 13.76 MB (σ=13.74) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 77 | 76.2%  ███████████████ |
| `js` | 7 | 6.9%  █ |
| `elf` | 4 | 4.0%   |
| `py` | 3 | 3.0%   |
| `zip` | 2 | 2.0%   |
| `iso` | 2 | 2.0%   |
| `bat` | 2 | 2.0%   |
| `xlsx` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 65 | 64.4% |
| 2 | CoinMiner | 21 | 20.8% |
| 3 | Mirai | 3 | 3.0% |
| 4 | Formbook | 2 | 2.0% |
| 5 | Yogi | 2 | 2.0% |
| 6 | RemcosRAT | 2 | 2.0% |
| 7 | AgentTesla | 1 | 1.0% |
| 8 | Trojan.GenericFCA.12645 | 1 | 1.0% |
| 9 | FleetDeck | 1 | 1.0% |
| 10 | Gh0stRAT | 1 | 1.0% |
| 11 | WannaCry | 1 | 1.0% |
| 12 | PythonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Loader | 62 | 61.4% | 75% |
| Infostealer | 11 | 10.9% | 79% |
| Skript/Dropper | 6 | 5.9% | 35% |
| Andere / Unbekannt | 5 | 5.0% | 20% |
| Trojaner | 5 | 5.0% | 73% |
| Botnet/IoT | 3 | 3.0% | 95% |
| Windows-Malware | 2 | 2.0% | 35% |
| Ransomware | 2 | 2.0% | 85% |
| RAT | 2 | 2.0% | 95% |
| Maldoc | 1 | 1.0% | 35% |
| Backdoor | 1 | 1.0% | 95% |
| Linux-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 24 | 23.8% |
| 🟠 HOCH | 62 | 61.4% |
| 🟡 MITTEL | 10 | 9.9% |
| 🟢 NIEDRIG | 5 | 5.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [a9309b8ca82e8d…](https://bazaar.abuse.ch/sample/a9309b8ca82e8d3a16085a53df0b270903c6bf02df720904cc88813b0489e759/) | WannaCry | Ransomware | **94.9** | 🔴 KRITISCH | – | – | ? |
| [c685032015152d…](https://bazaar.abuse.ch/sample/c685032015152dd6f91b5ec2036e2da240a190911b87b1f7fdeba1440070c37d/) | Gh0stRAT | Backdoor | **90.8** | 🔴 KRITISCH | – | – | ? |
| [bd6f0ba1f651ac…](https://bazaar.abuse.ch/sample/bd6f0ba1f651ac2cdcc7178077ac9c0a4716cc6148dc17af21c0f16386af8ffd/) | Formbook | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [f02bc1401bb7b8…](https://bazaar.abuse.ch/sample/f02bc1401bb7b817145796be2340fbdf8a091c293eefc79f1aa95c8d66678d01/) | unbekannt | Ransomware | **88.6** | 🔴 KRITISCH | – | – | ? |
| [3f4b6451af04b1…](https://bazaar.abuse.ch/sample/3f4b6451af04b1d6d2b34f017a9baa73671ab6f92aaa921ffaf1c799c6f3a794/) | Formbook | Infostealer | **87.7** | 🔴 KRITISCH | – | – | ? |
| [484a5754480023…](https://bazaar.abuse.ch/sample/484a57544800235ac6c0a0e53e38b8eaa2f12ba281316e3cf22b3f78c1592c28/) | RemcosRAT | RAT | **87.6** | 🔴 KRITISCH | – | – | ? |
| [d5409fcb66447d…](https://bazaar.abuse.ch/sample/d5409fcb66447dd85ce014abe6a7f168b9ab299c9c3c2082b515b98d90940bc5/) | RemcosRAT | RAT | **87.4** | 🔴 KRITISCH | – | – | ? |
| [4d9c1fc38da414…](https://bazaar.abuse.ch/sample/4d9c1fc38da4149360dd5e65eb3cc1072b9e8fbf5f7ff24ed9bf127c0d9f2840/) | unbekannt | Trojaner | **83.4** | 🔴 KRITISCH | – | – | ? |
| [ad69e1b5d2c5ae…](https://bazaar.abuse.ch/sample/ad69e1b5d2c5ae5cd1f697ea5b1dd70fb223018cc57693c6837569fc9c3803fc/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [b9f9860a395601…](https://bazaar.abuse.ch/sample/b9f9860a395601e358725b5e61bf772aa41a3d907392a547d2058586d7ce8352/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6116/7552 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6116/7552 |
| 3 | ESET-NOD32 | 77.3% | 5838/7552 |
| 4 | Kaspersky | 76.0% | 5741/7551 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.3% | 5384/7549 |
| 8 | Rising | 68.5% | 5174/7552 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 4999/7548 |
| 11 | Avast | 65.2% | 4924/7548 |
| 12 | AVG | 65.2% | 4924/7547 |
| 13 | Tencent | 65.1% | 4768/7326 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4624/7545 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 81 | 80.2% |
| ❓ Unbekannt | 9 | 8.9% |
| 🐧 Linux | 5 | 5.0% |
| 📦 Archiv | 4 | 4.0% |
| 📄 Dokument | 1 | 1.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| C2 / Nachladen | 62 | 61.4% |
| Unbekannt / nicht bestimmbar | 30 | 29.7% |
| Drive-By / Exploit-Kit | 7 | 6.9% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 77 | 76.2% |
| 2 | 🇫🇷 FR | 10 | 9.9% |
| 3 | 🇩🇪 DE | 7 | 6.9% |
| 4 | 🇭🇺 HU | 3 | 3.0% |
| 5 | 🌐 PH | 1 | 1.0% |
| 6 | 🇳🇱 NL | 1 | 1.0% |
| 7 | 🌐 EG | 1 | 1.0% |
| 8 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 68 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 65 |
| Credential Access | 63 |
| Exfiltration | 61 |
| Initial Access | 3 |
| Lateral Movement | 3 |
| Command and Control | 2 |

<details><summary>bd6f0ba1f651ac2cdcc7… – Formbook | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>3f4b6451af04b1d6d2b3… – Formbook | 🔴 KRITISCH 87.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9c7d1a813bd9898579a4…](https://bazaar.abuse.ch/sample/9c7d1a813bd9898579a4e50111bd421aebadeb722139062afc89c8bf0803e74f/)

- **Familie:** Trojan.GenericFCA.12645
- **Erkannt von:** 35 von 75 Engines (46.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericFCA.12645
- **VT-Reputation:** -54
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericFCA.12645`

**Erkennende Engines (35/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericFCA.12645` |
| AVG | `Other:Malware-gen [Trj]` |
| Arcabit | `Trojan.GenericFCA.D3165` |
| Avast | `Other:Malware-gen [Trj]` |
| Avira | `TR/Malware` |
| BitDefender 🛡️ | `Trojan.GenericFCA.12645` |
| CTX | `dll.trojan.dllhijack` |
| Cynet | `Malicious (score: 99)` |
| Emsisoft | `Trojan.GenericFCA.12645 (B)` |
| F-Secure | `Trojan.TR/Malware` |
| GData | `Trojan.GenericFCA.12645` |
| Google | `Detected` |
| K7AntiVirus | `Riskware ( 00584baa1 )` |
| K7GW | `Riskware ( 00584baa1 )` |
| Kaspersky | `Trojan.Win64.Agent.smhmmf` |
| Lionic | `Trojan.Win32.DLLHijack.4!c` |
| Malwarebytes | `Trojan.DLLHijack` |
| MaxSecure | `Trojan.Malware.101399416.susgen` |
| McAfeeD | `ti!9C7D1A813BD9` |
| MicroWorld-eScan | `Trojan.GenericFCA.12645` |
| Microsoft 🛡️ | `Trojan:Win64/DLLHijack!MTB` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.DllHijack!8.198D2 (CLOUD)` |
| Skyhigh | `BehavesLike.Win64.Trojan.th` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Win64.Trojan.Agent.Rnkl` |
| TrellixENS | `Artemis!059CCB75C8CC` |
| TrendMicro | `Trojan.Win64.DLLHIJACK.USBLII26` |
| TrendMicro-HouseCall | `Trojan.Win64.DLLHIJACK.USBLII26` |
| VIPRE | `Trojan.GenericFCA.12645` |
| Varist | `W64/ABTrojan.IMXO-0321` |
| ViRobot | `Trojan.Win.Z.Agent.5580800.D` |
| Zillya | `Trojan.Agent.Win64.193856` |
| alibabacloud | `Trojan:Win/DLLHijack.gyf` |

### [04fc1074b0959fd36d6e…](https://bazaar.abuse.ch/sample/04fc1074b0959fd36d6e3dd9beef5af9dcb83c35a2375b10c245fb84bb67471b/)

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
| AhnLab-V3 | `CoinMiner/Win.CoinMiner.R802423` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik_AGen.FYX trojan` |
| Elastic | `malicious (high confidence)` |
| Tencent | `OB:Trojan.Win32.Kryptik.16007442` |
| Webroot | `W32.Malware.Gen` |

### [32d7534009f98fd8b2f8…](https://bazaar.abuse.ch/sample/32d7534009f98fd8b2f82a234d115bf01fa6369a359ceabd9218c2432a8bc5d1/)

- **Familie:** Yogi
- **Erkannt von:** 21 von 75 Engines (28.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.94454
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.94454`

**Erkennende Engines (21/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.94454` |
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5960944` |
| Arcabit | `Trojan.Yogi.D170F6` |
| Avast | `FileRepMalware [Misc]` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.94454` |
| Bkav | `W32.Malware.2EBF8B28` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/GenKryptik.HVJK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.94454 (B)` |
| Google | `Detected` |
| Malwarebytes | `Trojan.CoinMiner` |
| McAfeeD | `ti!32D7534009F9` |
| MicroWorld-eScan | `Gen:Variant.Yogi.94454` |
| Microsoft 🛡️ | `Trojan:Win64/Barys.BN!MTB` |
| VIPRE | `Gen:Variant.Yogi.94454` |
| Varist | `W64/AEi.C04E9928!Eldorado` |
| Webroot | `W32.Malware.Gen` |

### [9ca6707e76d276cea8ea…](https://bazaar.abuse.ch/sample/9ca6707e76d276cea8ea240af0e366d9e8b87ff306f3155767d88e01d7c3faa5/)

- **Familie:** Yogi
- **Erkannt von:** 20 von 75 Engines (26.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.94454
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.94454`

**Erkennende Engines (20/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.94454` |
| AhnLab-V3 | `CoinMiner/Win.CoinMiner.R801890` |
| Arcabit | `Trojan.Yogi.D170F6` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.94454` |
| Bkav | `W32.Malware.67847724` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| ESET-NOD32 | `Win64/GenKryptik.HVJK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.94454 (B)` |
| Google | `Detected` |
| Malwarebytes | `Trojan.CoinMiner` |
| McAfeeD | `ti!9CA6707E76D2` |
| MicroWorld-eScan | `Gen:Variant.Yogi.94454` |
| Microsoft 🛡️ | `Trojan:Win64/Barys.BN!MTB` |
| Panda | `Trj/GdSda.A` |
| Sophos | `Mal/Generic-S` |
| VIPRE | `Gen:Variant.Yogi.94454` |
| Varist | `W64/AEi.C04E9928!Eldorado` |
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

- **exe** (78×)
- **signed** (60×)
- **dropped-by-Vidar** (57×)
- **CoinMiner** (21×)
- **55001da20373e92a4261b69e9f1087ac** (15×)
- **b89d843f29af2eed09805e9767a1165f** (12×)
- **d852ede598d72f2b3a4050576466ec62** (12×)
- **19ccb70dbc12ef919d5869277e598933** (12×)
- **js** (7×)
- **c1399bfb1be0a51415613edd6f0068c5** (6×)
- **stealer** (5×)
- **ClickFix** (5×)
- **dropped-by-GCleaner** (4×)
- **trojan** (4×)
- **vidar** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +13 (52→65)
- ↑ **CoinMiner** +8 (13→21)
- ↓ **Mirai** -18 (21→3)
- ↑ **Formbook** +1 (1→2)
- neu: **Yogi** (2)
- ↓ **RemcosRAT** -2 (4→2)
- neu: **Trojan.GenericFCA.12645** (1)
- neu: **FleetDeck** (1)
- neu: **Gh0stRAT** (1)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +27 (38→65)
- ↑ **CoinMiner** +19 (2→21)
- ↓ **Mirai** -19 (22→3)
- ↑ **Formbook** +1 (1→2)
- neu: **Yogi** (2)
- neu: **AgentTesla** (1)
- neu: **Trojan.GenericFCA.12645** (1)
- neu: **FleetDeck** (1)
- neu: **Gh0stRAT** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 13.759 MB |
| σ Dateigröße | 13.741 MB |
| Ø Risiko-Score | 69.9/100 |
| Ø Klassifikations-Konfidenz | 70.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 68/101 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 73 |
| Unbekannte Familien | 5 (5.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 14:48 | [07be91c98c5f…](https://bazaar.abuse.ch/sample/07be91c98c5feee161e87d01ff2c617b324baebb5a0b6eeb7c888900ad3588bb/) | `zip` | unbekannt | 32.6 | – | – | 🌐HU |
| 14:48 | [477d6810f64e…](https://bazaar.abuse.ch/sample/477d6810f64e552158e073e1af947991e490cd5f4b774205bbd3287bdd359d79/) | `exe` | AgentTesla | 39.0 | – | – | 🇺🇸US |
| 14:36 | [974b6cd3056f…](https://bazaar.abuse.ch/sample/974b6cd3056f895c70388e96f303acea3f572c0dd5e3dee3d99b1679bf4f867a/) | `exe` | unbekannt | 74.8 | – | – | 🇺🇸US |
| 14:36 | [9e678aa1f798…](https://bazaar.abuse.ch/sample/9e678aa1f798053aab18ccd6326a750a21c9cf5559e2fbbeb94164d529d64078/) | `exe` | unbekannt | 74.8 | – | – | 🇺🇸US |
| 14:36 | [4d9c1fc38da4…](https://bazaar.abuse.ch/sample/4d9c1fc38da4149360dd5e65eb3cc1072b9e8fbf5f7ff24ed9bf127c0d9f2840/) | `exe` | unbekannt | 83.4 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 22.10.2026 14:56 UTC*