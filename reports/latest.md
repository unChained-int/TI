# MalwareBazaar – 25.10.2026 23:57 UTC

Dieser Run hat **22 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **23** |
| Kritisch (≥75) | **11** |
| Höchster Score | **83.5/100** – 57ac696dc6b78a8c… |
| Häufigste Familie | **Mirai** (10x) |
| Häufigster Typ | **elf** (14x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 10 Samples |
| Ø Dateigröße | 3.33 MB (σ=6.23) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 14 | 60.9%  ████████████ |
| `exe` | 6 | 26.1%  █████ |
| `jar` | 1 | 4.3%   |
| `iso` | 1 | 4.3%   |
| `sh` | 1 | 4.3%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 10 | 43.5% |
| 2 | unbekannt | 9 | 39.1% |
| 3 | SalatStealer | 2 | 8.7% |
| 4 | RustyStealer | 1 | 4.3% |
| 5 | PythonStealer | 1 | 4.3% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 11 | 47.8% | 93% |
| Linux-Malware | 4 | 17.4% | 45% |
| Infostealer | 3 | 13.0% | 75% |
| Windows-Malware | 2 | 8.7% | 35% |
| Andere / Unbekannt | 2 | 8.7% | 20% |
| Trojaner | 1 | 4.3% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 11 | 47.8% |
| 🟠 HOCH | 4 | 17.4% |
| 🟡 MITTEL | 6 | 26.1% |
| 🟢 NIEDRIG | 2 | 8.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [57ac696dc6b78a…](https://bazaar.abuse.ch/sample/57ac696dc6b78a8c4d377bf765cfa2541297d5cb6f83ec0bdecd00a3f8ee4344/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [5e7de71f3f146c…](https://bazaar.abuse.ch/sample/5e7de71f3f146cf71ae116a06508ab2fd78871176d3b2e73cfeafaf2e4fcd83e/) | Mirai | Botnet/IoT | **83.0** | 🔴 KRITISCH | – | – | ? |
| [df564c4d4b8896…](https://bazaar.abuse.ch/sample/df564c4d4b889684db786b00395d04bf4418461d8ec1fb47e4b5f70400da058e/) | Mirai | Botnet/IoT | **82.7** | 🔴 KRITISCH | – | – | ? |
| [ad1c96c881748e…](https://bazaar.abuse.ch/sample/ad1c96c881748e684de8fe3a994400f3c5fe51320ff52d20bedb360411f1896e/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | 18.7% | 🟡 SCHWACH ERKANNT | ✗ |
| [632a5f0b20063a…](https://bazaar.abuse.ch/sample/632a5f0b20063ab99570d0b40d5ca9bf80424f3ab5787cbfe5e4a715a41162b0/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [d775b0ac605c34…](https://bazaar.abuse.ch/sample/d775b0ac605c34e8c083f8c69e1f14fa5d8b6238d6448c1929175af7a5137e5b/) | Mirai | Botnet/IoT | **82.6** | 🔴 KRITISCH | – | – | ? |
| [7feb4889e475fb…](https://bazaar.abuse.ch/sample/7feb4889e475fbc09206b6078f9d7d24d884d4787317fbe3c9fb619191bbcf95/) | Mirai | Botnet/IoT | **82.5** | 🔴 KRITISCH | – | – | ? |
| [d87a4f91a87164…](https://bazaar.abuse.ch/sample/d87a4f91a871643915d156fe396418afd6d682675d9c61db39b428cfcb4233a2/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |
| [4cf9a28c0bb006…](https://bazaar.abuse.ch/sample/4cf9a28c0bb006f9dfd582596a7a8313871d1cd6f96af03fb04c03e8da6bb6cc/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |
| [c156a2f26872b1…](https://bazaar.abuse.ch/sample/c156a2f26872b1f1591a26e5ab2fc83079c1a1d092a7415ca1e63fb627013e5e/) | Mirai | Botnet/IoT | **82.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6191/7639 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6191/7639 |
| 3 | ESET-NOD32 | 77.2% | 5894/7639 |
| 4 | Kaspersky | 75.8% | 5790/7638 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5430/7636 |
| 8 | Rising | 68.3% | 5215/7639 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5053/7635 |
| 11 | Avast | 65.1% | 4968/7635 |
| 12 | AVG | 65.1% | 4968/7634 |
| 13 | Tencent | 64.8% | 4803/7413 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4675/7632 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 15 | 65.2% |
| 🪟 Windows | 6 | 26.1% |
| ❓ Unbekannt | 1 | 4.3% |
| 📦 Archiv | 1 | 4.3% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 23 | 100.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 11 | 47.8% |
| 2 | 🇺🇸 US | 4 | 17.4% |
| 3 | 🇭🇺 HU | 2 | 8.7% |
| 4 | 🇳🇱 NL | 2 | 8.7% |
| 5 | 🇫🇷 FR | 2 | 8.7% |
| 6 | 🇨🇦 CA | 1 | 4.3% |
| 7 | 🌐 Unbekannt | 1 | 4.3% |

## MITRE ATT&CK

> 10 von 23 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 10 |
| Lateral Movement | 10 |

<details><summary>57ac696dc6b78a8c4d37… – Mirai | 🔴 KRITISCH 83.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>5e7de71f3f146cf71ae1… – Mirai | 🔴 KRITISCH 83.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>df564c4d4b889684db78… – Mirai | 🔴 KRITISCH 82.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>ad1c96c881748e684de8… – Mirai | 🔴 KRITISCH 82.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>632a5f0b20063ab99570… – Mirai | 🔴 KRITISCH 82.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [ad1c96c881748e684de8…](https://bazaar.abuse.ch/sample/ad1c96c881748e684de8fe3a994400f3c5fe51320ff52d20bedb360411f1896e/)

- **Familie:** Mirai
- **Erkannt von:** 14 von 75 Engines (18.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux/DDoS-CI
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (14/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| ClamAV | `Unix.Trojan.Mirai-9858729-0` |
| DrWeb | `Linux.Mirai.10589` |
| Fortinet | `ELF/Mirai.CJS!tr` |
| Google | `Detected` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.HL!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.144FF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Tencent | `Backdoor.Linux.Mirai.waq` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Trojan/Linux.Mirai.l` |

### [aea291ecbfc916acb6cd…](https://bazaar.abuse.ch/sample/aea291ecbfc916acb6cd8b1d1f9a3671c8782c5bc051098c7ab9d94c786d5dcc/)

- **Familie:** RustyStealer
- **Erkannt von:** 40 von 75 Engines (53.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Doina.128020
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Doina.128020`

**Erkennende Engines (40/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Doina.128020` |
| APEX | `Malicious` |
| AVG | `Win64:Agent-KZ [Hack]` |
| AhnLab-V3 | `HackTool/Win.PSWDump.R797834` |
| Antiy-AVL | `HackTool/Win64.PSWDump` |
| Arcabit | `Trojan.Doina.D1F414` |
| Avast | `Win64:Agent-KZ [Hack]` |
| Avira | `TR/W64.Agent.KZ` |
| BitDefender 🛡️ | `Gen:Variant.Doina.128020` |
| Bkav | `W32.Malware.5112C836` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `Win64/Spy.Agent.BIH trojan` |
| Elastic | `Windows.Trojan.Generic` |
| Emsisoft | `Gen:Variant.Doina.128020 (B)` |
| F-Secure | `Trojan.TR/W64.Agent.KZ` |
| GData | `Gen:Variant.Doina.128020` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win64.Agent.sa` |
| Kaspersky | `Trojan-PSW.Win64.BroPass.imj` |
| Lionic | `Trojan.Win32.PSWDump.i!c` |
| Malwarebytes | `Spyware.Stealer` |
| McAfeeD | `Trojan:Win/ChromStealer.AA` |
| MicroWorld-eScan | `Gen:Variant.Doina.128020` |
| Microsoft 🛡️ | `HackTool:Win64/PSWDump.MX!MTB` |
| Paloalto | `generic.ml` |
| Rising | `HackTool.ChromElevator!1.1437F (CLASSIC)` |
| Sangfor | `Hacktool.Win64.Agent.Vse8` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Generic Reputation PUA (PUA)` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16006402` |
| TrellixENS | `Artemis!DE615576A892` |
| TrendMicro | `Trojan.Win64.PSWDUMP.USBLJP26` |
| TrendMicro-HouseCall | `Trojan.Win64.PSWDUMP.USBLJP26` |
| VIPRE | `Gen:Variant.Doina.128020` |
| Varist | `W64/ABApplication.OZWF-5239` |
| alibabacloud | `Trojan[stealer]:Win/PSWDump.MD8PHU` |
| huorong | `HackTool/W64.PwStealer.b!crit` |

### [29e67b1723a5616c3f02…](https://bazaar.abuse.ch/sample/29e67b1723a5616c3f02ab2ef3bcf01cc538c80650cd0612a0bd1d0d54b047ef/)

- **Familie:** SalatStealer
- **Erkannt von:** 45 von 75 Engines (60.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (45/75):**

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
| Bkav | `W32.Malware.8CE2D3C3` |
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
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!85C77984FD74` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!85C77984FD74` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!85C77984FD74` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAJ` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7AntiVirus | `Trojan ( 0001140e1 )` |
| K7GW | `Hacktool ( a007e0071 )` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| Malwarebytes | `Trojan.Injector` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `Artemis!A955B9C64FAF` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **elf** (14×)
- **Mirai** (10×)
- **exe** (5×)
- **upx-dec** (2×)
- **upx** (2×)
- **SalatStealer** (2×)
- **jar** (1×)
- **weedhack** (1×)
- **RustyStealer** (1×)
- **iso** (1×)
- **bashlite** (1×)
- **ddos** (1×)
- **gafgyt** (1×)
- **pie** (1×)
- **enthec** (1×)

## Änderungen – 24h-Vergleich

- ↓ **Mirai** -11 (21→10)
- ↓ **unbekannt** -10 (19→9)
- ↓ **SalatStealer** -9 (11→2)
- weg: **CoinMiner** (war 2)
- weg: **AveMariaRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↓ **Mirai** -10 (20→10)
- ↓ **unbekannt** -28 (37→9)
- ↓ **SalatStealer** -1 (3→2)
- neu: **RustyStealer** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.326 MB |
| σ Dateigröße | 6.226 MB |
| Ø Risiko-Score | 65.0/100 |
| Ø Klassifikations-Konfidenz | 69.8% |
| Samples mit VT | 4/23 |
| Samples mit MITRE | 10/23 |
| Eindeutige Familien | 5 |
| Eindeutige Tags | 17 |
| Unbekannte Familien | 2 (8.7%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:55 | [b9f8c6e4559f…](https://bazaar.abuse.ch/sample/b9f8c6e4559fba27077c3bdf357828894fa1e5ea498bd49674213491b277d38c/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 23:13 | [8c6b7de99ba2…](https://bazaar.abuse.ch/sample/8c6b7de99ba2a633ca27c65757186074e9814bc3a1edcc7cf171cfea19d5ac7f/) | `jar` | unbekannt | 32.1 | – | – | 🇩🇪DE |
| 22:49 | [57ac696dc6b7…](https://bazaar.abuse.ch/sample/57ac696dc6b78a8c4d377bf765cfa2541297d5cb6f83ec0bdecd00a3f8ee4344/) | `elf` | Mirai | 83.5 | – | – | 🇩🇪DE |
| 22:19 | [ad1c96c88174…](https://bazaar.abuse.ch/sample/ad1c96c881748e684de8fe3a994400f3c5fe51320ff52d20bedb360411f1896e/) | `elf` | Mirai | 82.6 | 18.7% | 🟡 SCHWACH ERKANNT | 🇩🇪DE |
| 22:11 | [4e7a6ed5e263…](https://bazaar.abuse.ch/sample/4e7a6ed5e263edb8b6af9f44a93d617411c66507791ab23dbd25edc96d81d8e1/) | `elf` | unbekannt | 41.8 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 25.10.2026 23:57 UTC*