# MalwareBazaar – 20.10.2026 04:01 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **29** |
| Höchster Score | **95.5/100** – 1de2505c805069ad… |
| Häufigste Familie | **unbekannt** (73x) |
| Häufigster Typ | **js** (47x) |
| Hauptplattform | **Unbekannt** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 19 Samples |
| Ø Dateigröße | 1.79 MB (σ=7.32) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `js` | 47 | 46.5%  █████████ |
| `elf` | 21 | 20.8%  ████ |
| `macho` | 13 | 12.9%  ██ |
| `exe` | 11 | 10.9%  ██ |
| `msi` | 4 | 4.0%   |
| `ps1` | 3 | 3.0%   |
| `vbs` | 1 | 1.0%   |
| `hta` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 73 | 72.3% |
| 2 | Mirai | 18 | 17.8% |
| 3 | Snowlight | 2 | 2.0% |
| 4 | AMOS | 2 | 2.0% |
| 5 | Yogi | 1 | 1.0% |
| 6 | SalatStealer | 1 | 1.0% |
| 7 | RemusStealer | 1 | 1.0% |
| 8 | AgentTesla | 1 | 1.0% |
| 9 | WannaCry | 1 | 1.0% |
| 10 | PythonStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Skript/Dropper | 45 | 44.6% | 35% |
| Botnet/IoT | 18 | 17.8% | 95% |
| Andere / Unbekannt | 10 | 9.9% | 20% |
| Windows-Malware | 6 | 5.9% | 35% |
| RAT | 6 | 5.9% | 75% |
| Loader | 4 | 4.0% | 75% |
| Infostealer | 4 | 4.0% | 85% |
| Linux-Malware | 3 | 3.0% | 45% |
| Trojaner | 2 | 2.0% | 65% |
| Cryptominer | 2 | 2.0% | 75% |
| Ransomware | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 29 | 28.7% |
| 🟠 HOCH | 8 | 7.9% |
| 🟡 MITTEL | 54 | 53.5% |
| 🟢 NIEDRIG | 10 | 9.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [1de2505c805069…](https://bazaar.abuse.ch/sample/1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d/) | WannaCry | Ransomware | **95.5** | 🔴 KRITISCH | – | – | ? |
| [863ea1012d1379…](https://bazaar.abuse.ch/sample/863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107/) | AMOS | Infostealer | **88.7** | 🔴 KRITISCH | – | – | ? |
| [392070b982e063…](https://bazaar.abuse.ch/sample/392070b982e06331e6daaa38cc8bd713b6f47b5f884d2973a908b6190cf44d90/) | AMOS | Infostealer | **88.4** | 🔴 KRITISCH | – | – | ? |
| [098b91fd1bcb00…](https://bazaar.abuse.ch/sample/098b91fd1bcb00ace97418c0e463316fa26d37c4b6cda4dbd0b52421659b0eaf/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [93af664ca7cdd9…](https://bazaar.abuse.ch/sample/93af664ca7cdd9682c89d3999802e0cdc763898a66cf5e013b58b5f4a8eccc4e/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [3a2e3adaa695e3…](https://bazaar.abuse.ch/sample/3a2e3adaa695e37aa5437af52f275fb30c45cf8ae865b88eae21218435cb6ea1/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [7b7b37e805c674…](https://bazaar.abuse.ch/sample/7b7b37e805c6749feb65d02f6be3724fef181e95faa993ddd77ccac8df366af6/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [4a203def15c9d4…](https://bazaar.abuse.ch/sample/4a203def15c9d4b30d4602ed9db960d0407a6ba04114a64091b9658c5cd011f2/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [fd6fb49be7e020…](https://bazaar.abuse.ch/sample/fd6fb49be7e0202cba66080524a06072328f285446a50cb679645f99a19d04bb/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [2efd63cc32630d…](https://bazaar.abuse.ch/sample/2efd63cc32630d6a630dac0ca70afd9ff65a87826153678b0c89841a88308fc5/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6074/7505 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6074/7505 |
| 3 | ESET-NOD32 | 77.4% | 5807/7505 |
| 4 | Kaspersky | 76.3% | 5723/7504 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5363/7502 |
| 8 | Rising | 68.7% | 5156/7505 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4972/7501 |
| 11 | Tencent | 65.2% | 4745/7279 |
| 12 | Avast | 65.2% | 4890/7501 |
| 13 | AVG | 65.2% | 4890/7500 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4594/7498 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| ❓ Unbekannt | 47 | 46.5% |
| 🐧 Linux | 22 | 21.8% |
| 🪟 Windows | 19 | 18.8% |
| 🍎 macOS | 13 | 12.9% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Drive-By / Exploit-Kit | 49 | 48.5% |
| Unbekannt / nicht bestimmbar | 40 | 39.6% |
| C2 / Nachladen | 5 | 5.0% |
| Trojanisierte Software | 4 | 4.0% |
| MaaS-Loader | 2 | 2.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 72 | 71.3% |
| 2 | 🇩🇪 DE | 13 | 12.9% |
| 3 | 🇷🇴 RO | 7 | 6.9% |
| 4 | 🇫🇷 FR | 3 | 3.0% |
| 5 | 🇨🇭 CH | 3 | 3.0% |
| 6 | 🌐 PT | 2 | 2.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 19 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 18 |
| Lateral Movement | 18 |
| Credential Access | 1 |
| Collection | 1 |
| Exfiltration | 1 |

<details><summary>098b91fd1bcb00ace974… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>93af664ca7cdd9682c89… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [1f7c7b85548cf8338f74…](https://bazaar.abuse.ch/sample/1f7c7b85548cf8338f74e6d73c8ac7cb707bc87b087ce86f93b5922c0739d39c/)

- **Familie:** Mirai
- **Erkannt von:** 14 von 75 Engines (18.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Cling.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Cling.1`

**Erkennende Engines (14/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Cling.1` |
| Arcabit | `Trojan.Linux.Cling.1` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Cling.1` |
| CTX | `elf.unknown.cling` |
| DrWeb | `Linux.Mirai.10456` |
| ESET-NOD32 | `Linux/Mirai.FKR trojan` |
| Emsisoft | `Gen:Variant.Linux.Cling.1 (B)` |
| GData | `Gen:Variant.Linux.Cling.1` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.xh` |
| MicroWorld-eScan | `Gen:Variant.Linux.Cling.1` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.MKA!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.148B0 (CLASSIC)` |
| VIPRE | `Gen:Variant.Linux.Cling.1` |
| huorong | `Trojan/Linux.Mirai.mi` |

### [889643499f34373689fc…](https://bazaar.abuse.ch/sample/889643499f34373689fc109d7e09f764848e71082ec8d7de499b27c2c3892f4a/)

- **Familie:** Mirai
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-BOK [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-BOK [Trj]` |
| AhnLab-V3 | `Linux/Mirai07.Exp` |
| Antiy-AVL | `Trojan/Linux.Ngioweb` |
| Avast | `ELF:Mirai-BOK [Trj]` |
| Avast-Mobile | `ELF:Mirai-AJO [Trj]` |
| Avira | `EXP/ELF.Mirai.Z.A` |
| ClamAV | `Unix.Trojan.Mirai-9441505-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.BPP trojan` |
| Elastic | `Linux.Trojan.Gafgyt` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Z.A` |
| Fortinet | `Linux/Mirai.BWR!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.E816 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-ICV!19B3AEB74779` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.le` |
| Varist | `E64/Mirai.A.gen!Camelot` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.ji` |

### [5414de616cb7cad3e865…](https://bazaar.abuse.ch/sample/5414de616cb7cad3e8652004e8aff3a067ed97a30a781c2fe73bb5f029efac30/)

- **Familie:** Yogi
- **Erkannt von:** 36 von 75 Engines (48.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.92992
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.92992`

**Erkennende Engines (36/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.92992` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.C5960369` |
| Arcabit | `Trojan.Yogi.D16B40` |
| Avast | `Win32:MalwareX-gen [Cryp]` |
| Avira | `TR/Dropper.MSIL.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.92992` |
| Bkav | `W32.Malware.433E1D65` |
| CTX | `exe.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `MSIL/Agent.YTK trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.92992 (B)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen` |
| GData | `Gen:Variant.Yogi.92992` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan.MSIL.Agent.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Malwarebytes | `Trojan.MalPack.Confuser` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!4E9B523F07C5` |
| MicroWorld-eScan | `Gen:Variant.Yogi.92992` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Msil.Trojan.Agent.Uwhl` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAJ` |
| VBA32 | `Trojan.MSIL.Buts.gen` |
| VIPRE | `Gen:Variant.Yogi.92992` |
| Varist | `W32/S-3049d5f7!Eldorado` |

### [f2d4c3ce8d9a11fc7d49…](https://bazaar.abuse.ch/sample/f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQU!852D4DAA4AD5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Trojan.Mirai` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.jw` |
| Kingsoft | `Linux.Backdoor.elf.2023947` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14331 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!852D4DAA4AD5` |
| TrellixENS | `LINUX/Mirai-FQU!852D4DAA4AD5` |
| Varist | `E32/Mirai.EN.gen!Camelot` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Avast | `FileRepMalware [Misc]` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| Lionic | `Trojan.Win32.PythonStealer.4!c` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| Varist | `W64/ABTrojan.ANKV-0822` |


## Top Tags

- **js** (43×)
- **elf** (21×)
- **Mirai** (16×)
- **macho** (13×)
- **exe** (10×)
- **etherhiding** (7×)
- **freight-lure** (7×)
- **snowlight** (6×)
- **nodejs** (6×)
- **rat** (6×)
- **vnc** (6×)
- **ClickFix** (5×)
- **vshell** (5×)
- **msi** (4×)
- **dropped-by-remus** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +27 (46→73)
- ↓ **Mirai** -2 (20→18)
- neu: **Snowlight** (2)
- neu: **Yogi** (1)
- neu: **SalatStealer** (1)
- neu: **AgentTesla** (1)
- weg: **ValleyRAT** (war 2)
- weg: **BlakcSeeStealer** (war 2)
- weg: **Prometei** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +44 (29→73)
- ↓ **Mirai** -6 (24→18)
- neu: **Snowlight** (2)
- ↑ **AMOS** +1 (1→2)
- neu: **Yogi** (1)
- neu: **AgentTesla** (1)
- neu: **WannaCry** (1)
- neu: **PythonStealer** (1)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.791 MB |
| σ Dateigröße | 7.315 MB |
| Ø Risiko-Score | 52.5/100 |
| Ø Klassifikations-Konfidenz | 52.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 19/101 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 44 |
| Unbekannte Familien | 10 (9.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:59 | [029478409d69…](https://bazaar.abuse.ch/sample/029478409d6992823305cc3d10a87752b9cc7ab0f6c45bb486e96c897801b9c2/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 03:56 | [098b91fd1bcb…](https://bazaar.abuse.ch/sample/098b91fd1bcb00ace97418c0e463316fa26d37c4b6cda4dbd0b52421659b0eaf/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 03:54 | [93af664ca7cd…](https://bazaar.abuse.ch/sample/93af664ca7cdd9682c89d3999802e0cdc763898a66cf5e013b58b5f4a8eccc4e/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 03:52 | [88183421d4b6…](https://bazaar.abuse.ch/sample/88183421d4b666703af8021ecc56438e2708afb961845887e92d63ad63161e25/) | `msi` | unbekannt | 39.0 | – | – | 🇫🇷FR |
| 03:51 | [1f7c7b85548c…](https://bazaar.abuse.ch/sample/1f7c7b85548cf8338f74e6d73c8ac7cb707bc87b087ce86f93b5922c0739d39c/) | `elf` | Mirai | 83.9 | 18.7% | 🟡 SCHWACH ERKANNT | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 20.10.2026 04:01 UTC*