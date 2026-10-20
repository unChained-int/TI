# MalwareBazaar – 20.10.2026 11:07 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **63** |
| Höchster Score | **96.2/100** – 087652837c60f07a… |
| Häufigste Familie | **unbekannt** (39x) |
| Häufigster Typ | **elf** (42x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 48 Samples |
| Ø Dateigröße | 4.41 MB (σ=12.08) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 42 | 41.6%  ████████ |
| `exe` | 40 | 39.6%  ███████ |
| `zip` | 5 | 5.0%   |
| `js` | 4 | 4.0%   |
| `msi` | 2 | 2.0%   |
| `macho` | 2 | 2.0%   |
| `php` | 1 | 1.0%   |
| `xlsx` | 1 | 1.0%   |
| `zsh` | 1 | 1.0%   |
| `wsf` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 39 | 38.6% |
| 2 | Mirai | 33 | 32.7% |
| 3 | SalatStealer | 8 | 7.9% |
| 4 | Formbook | 4 | 4.0% |
| 5 | GuLoader | 2 | 2.0% |
| 6 | AgentTesla | 2 | 2.0% |
| 7 | ValleyRAT | 2 | 2.0% |
| 8 | ConnectWise | 1 | 1.0% |
| 9 | IH trojan | 1 | 1.0% |
| 10 | Trojan.GenericKD.81719560 | 1 | 1.0% |
| 11 | WannaCry | 1 | 1.0% |
| 12 | RemusStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 33 | 32.7% | 95% |
| Infostealer | 20 | 19.8% | 80% |
| Windows-Malware | 11 | 10.9% | 35% |
| Loader | 11 | 10.9% | 79% |
| Andere / Unbekannt | 7 | 6.9% | 20% |
| Linux-Malware | 6 | 5.9% | 45% |
| RAT | 5 | 5.0% | 79% |
| Trojaner | 3 | 3.0% | 68% |
| Skript/Dropper | 2 | 2.0% | 35% |
| Ransomware | 2 | 2.0% | 85% |
| Maldoc | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 63 | 62.4% |
| 🟠 HOCH | 11 | 10.9% |
| 🟡 MITTEL | 20 | 19.8% |
| 🟢 NIEDRIG | 7 | 6.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [087652837c60f0…](https://bazaar.abuse.ch/sample/087652837c60f07a352de8b64b7df182799ca236b89b98dc3c5c418cbe9ae6b8/) | WannaCry | Ransomware | **96.2** | 🔴 KRITISCH | – | – | ? |
| [4c9e58b6f266ed…](https://bazaar.abuse.ch/sample/4c9e58b6f266edbb74b25b1dee4213d4ad6395e4d67901c0c98a9a68ce135b75/) | Formbook | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [e5126ba96da0de…](https://bazaar.abuse.ch/sample/e5126ba96da0decf071eaca32fc68fcf10048f70dd35398ad6e2a1fa773b26a2/) | Formbook | Infostealer | **87.9** | 🔴 KRITISCH | – | – | ? |
| [bc0bde5dd5ca31…](https://bazaar.abuse.ch/sample/bc0bde5dd5ca313436bc7119c5f603d9f4fb99dcbb09b2eaa5fd7ccda2c33794/) | AMOS | Infostealer | **87.1** | 🔴 KRITISCH | – | – | ? |
| [44a7cba81a611e…](https://bazaar.abuse.ch/sample/44a7cba81a611e798624ffab187b137725a5b7c0b80e53160f32839f01c7093f/) | Formbook | Infostealer | **86.8** | 🔴 KRITISCH | – | – | ? |
| [f8741d3a7a1956…](https://bazaar.abuse.ch/sample/f8741d3a7a19561b0c04436efab2f43a07a5f38a04ddcc9f45b6019ac627d6e0/) | Formbook | Infostealer | **86.6** | 🔴 KRITISCH | – | – | ? |
| [7fec3c5196460f…](https://bazaar.abuse.ch/sample/7fec3c5196460fbb3f9d484f4c15bc0c63ea627479abc9865cd74428b53521c3/) | unbekannt | Ransomware | **86.4** | 🔴 KRITISCH | – | – | ? |
| [1e98a36b2c4044…](https://bazaar.abuse.ch/sample/1e98a36b2c40441a1bf33060bad8b52bf74ee659472aa15d3463bd51b118725f/) | AsyncRAT | RAT | **86.2** | 🔴 KRITISCH | – | – | ? |
| [64afc9a1a577e6…](https://bazaar.abuse.ch/sample/64afc9a1a577e61ae81dc98fba75bd9fbe38c05a5ec4094998174071a168535a/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [1ab4122ab1b082…](https://bazaar.abuse.ch/sample/1ab4122ab1b082c4d5bc9e8f562cad456536a4e314aa208ced4a748db3349ed2/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6078/7510 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6078/7510 |
| 3 | ESET-NOD32 | 77.4% | 5809/7510 |
| 4 | Kaspersky | 76.3% | 5726/7509 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5366/7507 |
| 8 | Rising | 68.7% | 5159/7510 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4974/7506 |
| 11 | Tencent | 65.2% | 4748/7284 |
| 12 | Avast | 65.2% | 4894/7506 |
| 13 | AVG | 65.2% | 4894/7505 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4598/7503 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 43 | 42.6% |
| 🐧 Linux | 43 | 42.6% |
| ❓ Unbekannt | 6 | 5.9% |
| 📦 Archiv | 5 | 5.0% |
| 🍎 macOS | 2 | 2.0% |
| 🌐 Web | 1 | 1.0% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 80 | 79.2% |
| C2 / Nachladen | 8 | 7.9% |
| Drive-By / Exploit-Kit | 5 | 5.0% |
| MaaS-Loader | 4 | 4.0% |
| Trojanisierte Software | 2 | 2.0% |
| Exploit / N-Day | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 56 | 55.4% |
| 2 | 🇺🇸 US | 22 | 21.8% |
| 3 | 🇭🇺 HU | 7 | 6.9% |
| 4 | 🇫🇷 FR | 4 | 4.0% |
| 5 | 🇳🇱 NL | 3 | 3.0% |
| 6 | 🇨🇭 CH | 2 | 2.0% |
| 7 | 🇮🇩 ID | 2 | 2.0% |
| 8 | 🌐 LV | 1 | 1.0% |
| 9 | 🇸🇪 SE | 1 | 1.0% |
| 10 | 🇬🇧 GB | 1 | 1.0% |
| 11 | 🇨🇦 CA | 1 | 1.0% |
| 12 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 48 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 36 |
| Lateral Movement | 36 |
| Collection | 10 |
| Credential Access | 8 |
| Exfiltration | 5 |
| Execution | 3 |
| Defense Evasion | 2 |
| Command and Control | 2 |

<details><summary>4c9e58b6f266edbb74b2… – Formbook | 🔴 KRITISCH 88.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>e5126ba96da0decf071e… – Formbook | 🔴 KRITISCH 87.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>44a7cba81a611e798624… – Formbook | 🔴 KRITISCH 86.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [81bb92e262b064f336a8…](https://bazaar.abuse.ch/sample/81bb92e262b064f336a8f3443fccbeca4acd765e64052f7714add1059e7d822b/)

- **Familie:** IH trojan
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** JS/Agent.IH trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `JS/Agent.IH trojan` |
| alibabacloud | `Trojan[downloader]:Javascript/Generic.Gen` |

### [c1fef7708c4ee9e6e0b6…](https://bazaar.abuse.ch/sample/c1fef7708c4ee9e6e0b6ece3a301d8544c4c68799a1f90232b2db941bed2def7/)

- **Familie:** Trojan.GenericKD.81719560
- **Erkannt von:** 49 von 75 Engines (65.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.81719560
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.81719560`

**Erkennende Engines (49/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.81719560` |
| APEX | `Malicious` |
| AVG | `Win64:MalwareX-gen [Expl]` |
| AhnLab-V3 | `Exploit/Win.BypassUAC.R799961` |
| Alibaba | `Exploit:Win32/BypassUAC.b86140d8` |
| Antiy-AVL | `Trojan[Exploit]/Win32.BypassUAC` |
| Arcabit | `Trojan.Generic.D4DEF108` |
| Avast | `Win64:MalwareX-gen [Expl]` |
| Avira | `EXP/W64.MalwareX` |
| BitDefender 🛡️ | `Trojan.GenericKD.81719560` |
| Bkav | `W32.Malware.6E45675C` |
| CTX | `exe.trojan.bypassuac` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `MSIL/Agent.YSO trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.81719560 (B)` |
| F-Secure | `Exploit.EXP/W64.MalwareX` |
| Fortinet | `W64/Agent_AGen.QUB!tr` |
| GData | `Trojan.GenericKD.81719560` |
| Google | `Detected` |
| K7AntiVirus | `Exploit ( 005cee711 )` |
| K7GW | `Exploit ( 005cee711 )` |
| Kaspersky | `UDS:Exploit.Win32.BypassUAC.b` |
| Kingsoft | `Win32.Exploit.BypassUAC.b` |
| Lionic | `Trojan.Win32.BypassUAC.4!c` |
| Malwarebytes | `GameHack.Riskware.Agent.DDS` |
| MaxSecure | `Trojan.Malware.338148470.susgen` |
| McAfeeD | `ti!C1FEF7708C4E` |
| MicroWorld-eScan | `Trojan.GenericKD.81719560` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Exploit.BypassUAC!8.87F5 (CLOUD)` |
| Sangfor | `Exploit.Win32.Bypassuac.Vkfs` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Malware.Win32.Gencirc.10c4ce25` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!7CFBB36583BB` |
| TrendMicro | `Trojan.Win64.AGENTAGEN.USBLJ926` |
| TrendMicro-HouseCall | `Trojan.Win64.AGENTAGEN.USBLJ926` |
| VBA32 | `Exploit.BypassUAC` |
| VIPRE | `Trojan.GenericKD.81719560` |
| Varist | `W64/ABTrojan.ZBBT-2054` |
| Zillya | `Trojan.Agent.Win32.4679046` |
| alibabacloud | `Exploit:Win/Agent_AGen.QCH` |
| huorong | `TrojanSpy/Stealer.yz` |

### [15d10a6db45fd36d394e…](https://bazaar.abuse.ch/sample/15d10a6db45fd36d394efa01528a05706afb9021fcf7d5f97e1af205acd65199/)

- **Familie:** Mirai
- **Erkannt von:** 22 von 75 Engines (29.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Possible_SMTOOLXMR-ELF64
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (22/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CSV [Trj]` |
| Antiy-AVL | `Trojan/Linux.Agent` |
| Avast | `ELF:Mirai-CSV [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9829` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| GData | `Linux.Application.CoinMiner.AH` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.fz` |
| Kingsoft | `Linux.Backdoor.Gafgyt.fz` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `ti!15D10A6DB45F` |
| Microsoft 🛡️ | `Trojan:Linux/CoinMiner.C12` |
| Rising | `Backdoor.Gafgyt/Linux!8.132A2 (CLOUD)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Worm.Mirai!ATN` |
| Tencent | `Linux.Backdoor.Gafgyt.Ljgl` |
| TrendMicro | `Possible_SMTOOLXMR-ELF64` |
| TrendMicro-HouseCall | `Possible_SMTOOLXMR-ELF64` |
| alibabacloud | `DDoS:Linux/Gafgyt.fu` |
| huorong | `Trojan/Linux.Mirai.jc` |

### [fc36de78d6ab0afbf824…](https://bazaar.abuse.ch/sample/fc36de78d6ab0afbf8241584965917d350cadbdcf5bf40a402c9b107706cefa6/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Possible_MIRAI.SMLBRA52
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BQA [Bot]` |
| Avast | `ELF:Mirai-BQA [Bot]` |
| Avira | `EXP/ELF.Mirai.W` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9829` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| GData | `Linux.Application.CoinMiner.AH` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ld` |
| Kingsoft | `Linux.Backdoor.Mirai.ld` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `ti!FC36DE78D6AB` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.GS!MTB` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (CLOUD)` |
| Sangfor | `Backdoor.Linux.Mirai.Vrdm` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Linux.Mirai` |
| Tencent | `Linux.Backdoor.Mirai.Zfow` |
| TrendMicro | `Possible_MIRAI.SMLBRA52` |
| TrendMicro-HouseCall | `Possible_MIRAI.SMLBRA52` |
| alibabacloud | `DDoS:Linux/Mirai` |
| huorong | `Trojan/Linux.Mirai.jc` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Lionic | `Trojan.Win32.PythonStealer.4!c` |
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

- **elf** (42×)
- **exe** (39×)
- **Mirai** (35×)
- **stealer** (7×)
- **signed** (6×)
- **SalatStealer** (6×)
- **dropped-by-GCleaner** (5×)
- **js** (4×)
- **zip** (4×)
- **Formbook** (4×)
- **vidar** (3×)
- **A** (3×)
- **upx-dec** (3×)
- **upx** (3×)
- **cowrie** (3×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -19 (58→39)
- ↑ **Mirai** +11 (22→33)
- neu: **SalatStealer** (8)
- ↑ **Formbook** +3 (1→4)
- neu: **GuLoader** (2)
- neu: **AgentTesla** (2)
- ↑ **ValleyRAT** +1 (1→2)
- neu: **ConnectWise** (1)
- neu: **IH trojan** (1)
- neu: **Trojan.GenericKD.81719560** (1)
- weg: **BlakcSeeStealer** (war 2)
- weg: **Prometei** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +9 (30→39)
- ↑ **Mirai** +10 (23→33)
- ↑ **SalatStealer** +7 (1→8)
- ↑ **Formbook** +3 (1→4)
- neu: **GuLoader** (2)
- neu: **AgentTesla** (2)
- ↑ **ValleyRAT** +1 (1→2)
- neu: **ConnectWise** (1)
- neu: **IH trojan** (1)
- neu: **Trojan.GenericKD.81719560** (1)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.413 MB |
| σ Dateigröße | 12.082 MB |
| Ø Risiko-Score | 68.6/100 |
| Ø Klassifikations-Konfidenz | 72.0% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 48/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 80 |
| Unbekannte Familien | 7 (6.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 11:05 | [c9adf76bfa8e…](https://bazaar.abuse.ch/sample/c9adf76bfa8e460ae8c765c0f1c002a1829cec45a7860d8c45d922d434e99ccb/) | `exe` | unbekannt | 82.2 | – | – | 🇫🇷FR |
| 11:05 | [b9fad4ddf388…](https://bazaar.abuse.ch/sample/b9fad4ddf388478b8f1d9033bd00f9fb7eb4ac4e613d608b7fafdc7f0ee4a910/) | `exe` | unbekannt | 82.2 | – | – | 🇫🇷FR |
| 11:03 | [64afc9a1a577…](https://bazaar.abuse.ch/sample/64afc9a1a577e61ae81dc98fba75bd9fbe38c05a5ec4094998174071a168535a/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 10:52 | [98842ccb3594…](https://bazaar.abuse.ch/sample/98842ccb35943023e5eb21be1eaa80f2207df991173a9166df91a6ebe593e6ec/) | `exe` | unbekannt | 82.0 | – | – | 🇫🇷FR |
| 10:48 | [c814dce9dd7a…](https://bazaar.abuse.ch/sample/c814dce9dd7a293bbbef9925f8223896ee5b821c307cb302cea49b95584f49cd/) | `elf` | unbekannt | 43.1 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 20.10.2026 11:07 UTC*