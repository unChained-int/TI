# MalwareBazaar – 28.10.2026 01:03 UTC

Dieser Run hat **97 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **98** |
| Kritisch (≥75) | **56** |
| Höchster Score | **92.0/100** – 850d135d3ff871f8… |
| Häufigste Familie | **unbekannt** (44x) |
| Häufigster Typ | **exe** (61x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 23 Samples |
| Ø Dateigröße | 4.76 MB (σ=8.47) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 61 | 62.2%  ████████████ |
| `elf` | 22 | 22.4%  ████ |
| `macho` | 9 | 9.2%  █ |
| `vbs` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |
| `js` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |
| `iso` | 1 | 1.0%   |
| `rar` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 44 | 44.9% |
| 2 | SalatStealer | 27 | 27.6% |
| 3 | Mirai | 16 | 16.3% |
| 4 | AsyncRAT | 5 | 5.1% |
| 5 | Adware.OfferCore | 1 | 1.0% |
| 6 | njrat | 1 | 1.0% |
| 7 | Formbook | 1 | 1.0% |
| 8 | CoinMiner | 1 | 1.0% |
| 9 | Gh0stRAT | 1 | 1.0% |
| 10 | Malware | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 32 | 32.7% | 75% |
| Windows-Malware | 20 | 20.4% | 35% |
| Botnet/IoT | 16 | 16.3% | 95% |
| Loader | 9 | 9.2% | 75% |
| RAT | 9 | 9.2% | 87% |
| Linux-Malware | 6 | 6.1% | 45% |
| Andere / Unbekannt | 4 | 4.1% | 20% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Backdoor | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 56 | 57.1% |
| 🟠 HOCH | 11 | 11.2% |
| 🟡 MITTEL | 27 | 27.6% |
| 🟢 NIEDRIG | 4 | 4.1% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [850d135d3ff871…](https://bazaar.abuse.ch/sample/850d135d3ff871f88c96e5a6b889b1f454944ffdd35b2fce5e3fa1d049d8bf70/) | Gh0stRAT | Backdoor | **92.0** | 🔴 KRITISCH | – | – | ? |
| [e5155b144ad536…](https://bazaar.abuse.ch/sample/e5155b144ad5363d43fc0d0866c6b959b5dc4aa452e9f879b15b4e45d61b3566/) | Formbook | Infostealer | **89.9** | 🔴 KRITISCH | – | – | ? |
| [9758f758b221d0…](https://bazaar.abuse.ch/sample/9758f758b221d0ab47e831ce9ec8dee2e8d9fbb58d3c91b0ce056fa1f6fa0cfd/) | AsyncRAT | RAT | **89.2** | 🔴 KRITISCH | – | – | ? |
| [830fdb947aa60a…](https://bazaar.abuse.ch/sample/830fdb947aa60a491d22c8f698e9531fdd651f76cecafd3350d408442db4c59e/) | AsyncRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [b4ad9b09c01195…](https://bazaar.abuse.ch/sample/b4ad9b09c0119579e88b7627b9c48625934b1bd0a90fade337cd0d2281825513/) | AsyncRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [53a8bd56d87f50…](https://bazaar.abuse.ch/sample/53a8bd56d87f50e7cef6a9ffa7edbe1e3ed611457b6c7fd577a6a0ffb0f1d2d5/) | AsyncRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [9b6ba2ef41d4ba…](https://bazaar.abuse.ch/sample/9b6ba2ef41d4ba43c707f274f4b5c9b41ed41db6a99959821b983838495093cf/) | AsyncRAT | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [b533ff5c68ce2e…](https://bazaar.abuse.ch/sample/b533ff5c68ce2e87db3f14d4665cdccfbcdf5a57d660374cb9ad04f99142029e/) | Mirai | Botnet/IoT | **84.4** | 🔴 KRITISCH | – | – | ? |
| [104488c5f0ec2e…](https://bazaar.abuse.ch/sample/104488c5f0ec2e42f6d87d5f294843b945db2f2cfef9738f2e2539b1fcf9938d/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [b21222b00a8480…](https://bazaar.abuse.ch/sample/b21222b00a8480013893e48595d6adb346daf84393363476be8fc8d26a56ef35/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6226/7682 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6226/7682 |
| 3 | ESET-NOD32 | 77.2% | 5931/7682 |
| 4 | Kaspersky | 75.6% | 5804/7681 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5463/7679 |
| 8 | Rising | 68.3% | 5246/7682 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5080/7678 |
| 11 | Avast | 65.1% | 4999/7678 |
| 12 | AVG | 65.1% | 4999/7677 |
| 13 | Tencent | 64.9% | 4838/7456 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4699/7675 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 63 | 64.3% |
| 🐧 Linux | 23 | 23.5% |
| 🍎 macOS | 9 | 9.2% |
| 📦 Archiv | 2 | 2.0% |
| ❓ Unbekannt | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 85 | 86.7% |
| MaaS-Loader | 10 | 10.2% |
| Drive-By / Exploit-Kit | 1 | 1.0% |
| C2 / Nachladen | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 48 | 49.0% |
| 2 | 🇫🇷 FR | 15 | 15.3% |
| 3 | 🇩🇪 DE | 13 | 13.3% |
| 4 | 🇳🇱 NL | 12 | 12.2% |
| 5 | 🇨🇭 CH | 6 | 6.1% |
| 6 | 🌐 Unbekannt | 2 | 2.0% |
| 7 | 🇭🇺 HU | 2 | 2.0% |

## MITRE ATT&CK

> 23 von 98 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 16 |
| Lateral Movement | 16 |
| Command and Control | 6 |
| Execution | 5 |
| Collection | 2 |
| Credential Access | 1 |

<details><summary>e5155b144ad5363d43fc… – Formbook | 🔴 KRITISCH 89.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>9758f758b221d0ab47e8… – AsyncRAT | 🔴 KRITISCH 89.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>830fdb947aa60a491d22… – AsyncRAT | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>b4ad9b09c0119579e88b… – AsyncRAT | 🔴 KRITISCH 89.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [6460e128d268b65aff9e…](https://bazaar.abuse.ch/sample/6460e128d268b65aff9e62b58fb8be11e54b1e79d36348d16cf60a821becb5ee/)

- **Familie:** SalatStealer
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (55/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.8401` |
| APEX | `Malicious` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R765081` |
| Alibaba | `TrojanBanker:Win32/SalatStealer.306ecd88` |
| Antiy-AVL | `Trojan[PSW]/Win32.Convagent` |
| Arcabit | `Trojan.Draftor.D20D1` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/Crypt.ULPM.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.8401` |
| Bkav | `W32.Malware.8A8C2314` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent_AGen.XS trojan` |
| Emsisoft | `Gen:Variant.Draftor.8401 (B)` |
| F-Secure | `Trojan.TR/Crypt.ULPM.Gen` |
| Fortinet | `W32/Agent.XS!tr` |
| GData | `Gen:Variant.Draftor.8401` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Agent.oa!s2` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Kaspersky | `UDS:DangerousObject.Multi.Generic` |
| Lionic | `Trojan.Win32.Salat.4!c` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!390C84649ED3` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Stealer.Salat!1.13A22 (CLOUD)` |
| Sangfor | `Infostealer.Win32.Agent.Vc7a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!D66D588A672E` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570858` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Artemis!390C84649ED3` |
| TrendMicro | `Trojan.Win32.WACATAC.USBLJQ26` |
| TrendMicro-HouseCall | `Trojan.Win32.WACATAC.USBLJQ26` |
| VBA32 | `TrojanPSW.Satal` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| Varist | `W32/ABTrojan.ZTGF-3976` |
| ViRobot | `Trojan.Win.Z.Draftor.3592938.A` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| ZoneAlarm | `Troj/Salat-B` |
| huorong | `Trojan/Agent.e!crit` |

### [e203242dfee424e4a3cf…](https://bazaar.abuse.ch/sample/e203242dfee424e4a3cf548a697a58440019c68501fae20de4fb2be771fa0930/)

- **Familie:** SalatStealer
- **Erkannt von:** 57 von 75 Engines (76.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (57/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.8401` |
| APEX | `Malicious` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R765081` |
| Alibaba | `TrojanBanker:Win32/SalatStealer.a4e9a9dc` |
| Antiy-AVL | `Trojan[PSW]/Win32.Convagent` |
| Arcabit | `Trojan.Draftor.D20D1` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/Crypt.ULPM.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.8401` |
| Bkav | `W32.Malware.66D00515` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.PWS.Salat.389` |
| ESET-NOD32 | `WinGo/Agent_AGen.XS trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Gen:Variant.Draftor.8401 (B)` |
| F-Secure | `Trojan.TR/Crypt.ULPM.Gen` |
| Fortinet | `W32/Agent.XS!tr` |
| GData | `Gen:Variant.Draftor.8401` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Win32.Agent.oa!s2` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Kaspersky | `UDS:DangerousObject.Multi.Generic` |
| Lionic | `Trojan.Win32.Salat.4!c` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!C7AAE4749F65` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Stealer.Salat!1.13A22 (CLOUD)` |
| Sangfor | `Infostealer.Win32.Agent.Vuuo` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!3ECE79FD7158` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570819` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Artemis!C7AAE4749F65` |
| TrendMicro | `Trojan.Win32.WACATAC.USBLJQ26` |
| TrendMicro-HouseCall | `Trojan.Win32.WACATAC.USBLJQ26` |
| VBA32 | `TrojanPSW.Satal` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| Varist | `W32/ABTrojan.TZLM-8794` |
| ViRobot | `Trojan.Win.Z.Draftor.3592899.A` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| ZoneAlarm | `Troj/Salat-B` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |

### [6eec26c15b5458108d3a…](https://bazaar.abuse.ch/sample/6eec26c15b5458108d3a7a52d905acd93ba716fd9b0555259946128a1bb4ccfa/)

- **Familie:** njrat
- **Erkannt von:** 40 von 75 Engines (53.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.XWorm.196
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.XWorm.196`

**Erkennende Engines (40/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.XWorm.196` |
| APEX | `Malicious` |
| AVG | `MSIL:GenMalicious-DRT [Trj]` |
| AhnLab-V3 | `Trojan/Win.Crypt.C5417594` |
| Arcabit | `Trojan.XWorm.196` |
| Avast | `MSIL:GenMalicious-DRT [Trj]` |
| Avira | `TR/GenMalicious.DRT` |
| BitDefender 🛡️ | `Gen:Variant.XWorm.196` |
| Bkav | `W32.Malware.E2BCE80E` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.XWormNET.5` |
| ESET-NOD32 | `MSIL/XWorm.N trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.XWorm.196 (B)` |
| F-Secure | `Trojan.TR/GenMalicious.DRT` |
| Fortinet | `MSIL/XWorm.ECL!tr` |
| GData | `MSIL.Backdoor.XWorm.C` |
| Google | `Detected` |
| Ikarus | `Trojan.MSIL.Bladabindi` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Backdoor.MSIL.XWorm.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Malwarebytes | `Backdoor.XWorm` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!ADAC898D5B44` |
| MicroWorld-eScan | `Gen:Variant.XWorm.196` |
| Microsoft 🛡️ | `Trojan:MSIL/Bladabindi.SHG!MTB` |
| Sangfor | `Virus.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `ML/PE-A` |
| Symantec | `MSIL.XWorm!gen2` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Malware-Cryptor.MSIL.AgentTesla.Heur` |
| VIPRE | `Gen:Variant.XWorm.196` |
| Varist | `W32/MSIL_Kryptik.MVD.gen!Eldorado` |
| huorong | `Backdoor/MSIL.Agent.aw` |

### [0df3202d6a61ec93a8a1…](https://bazaar.abuse.ch/sample/0df3202d6a61ec93a8a195f3cdf942a7e2727eb91c9eb71cfe06ddc85187a31c/)

- **Familie:** Malware
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** W32.Malware.B69F00E4
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| Bkav | `W32.Malware.B69F00E4` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Elastic | `malicious (moderate confidence)` |
| Paloalto | `generic.ml` |
| SentinelOne | `Static AI - Suspicious PE` |

### [7e4c129f5bd09beffae1…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** SalatStealer
- **Erkannt von:** 44 von 75 Engines (58.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (44/75):**

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
| McAfeeD | `Real Protect-LS!9E7BE912AC3C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!9E7BE912AC3C` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9E7BE912AC3C` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **exe** (60×)
- **elf** (22×)
- **SalatStealer** (18×)
- **Mirai** (16×)
- **upx-dec** (12×)
- **upx** (12×)
- **ClickFix** (9×)
- **Foxveil** (9×)
- **Mach-O** (9×)
- **macho** (9×)
- **macOS** (9×)
- **loader** (8×)
- **arm** (8×)
- **salatstealer** (8×)
- **AsyncRAT** (5×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +22 (22→44)
- ↑ **SalatStealer** +7 (20→27)
- ↓ **Mirai** -16 (32→16)
- neu: **AsyncRAT** (5)
- neu: **Adware.OfferCore** (1)
- neu: **njrat** (1)
- neu: **Formbook** (1)
- neu: **Gh0stRAT** (1)
- neu: **Malware** (1)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +14 (30→44)
- ↑ **SalatStealer** +19 (8→27)
- ↓ **Mirai** -5 (21→16)
- neu: **AsyncRAT** (5)
- neu: **Adware.OfferCore** (1)
- neu: **njrat** (1)
- ↓ **CoinMiner** -2 (3→1)
- neu: **Gh0stRAT** (1)
- neu: **Malware** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.760 MB |
| σ Dateigröße | 8.471 MB |
| Ø Risiko-Score | 67.4/100 |
| Ø Klassifikations-Konfidenz | 67.0% |
| Samples mit VT | 5/98 |
| Samples mit MITRE | 23/98 |
| Eindeutige Familien | 10 |
| Eindeutige Tags | 45 |
| Unbekannte Familien | 4 (4.1%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 00:59 | [b70b226fd14b…](https://bazaar.abuse.ch/sample/b70b226fd14b746fd779902a92f845b4b7132c8e6d3baffe1d745e6edbcbc703/) | `macho` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 00:58 | [6dc0c1ad1688…](https://bazaar.abuse.ch/sample/6dc0c1ad1688123833100989f478e19dd9f4ceaa9a42f6bb85063332da3a5aed/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 00:54 | [114b69aa53a4…](https://bazaar.abuse.ch/sample/114b69aa53a40d7702a11ff81e3fc1d7104a3132c3395f403e6033c68f181230/) | `macho` | unbekannt | 75.0 | – | – | 🇺🇸US |
| 00:52 | [b533ff5c68ce…](https://bazaar.abuse.ch/sample/b533ff5c68ce2e87db3f14d4665cdccfbcdf5a57d660374cb9ad04f99142029e/) | `elf` | Mirai | 84.4 | – | – | 🇩🇪DE |
| 00:50 | [d6ce062f26b7…](https://bazaar.abuse.ch/sample/d6ce062f26b771b19a085a727ca13d5c568037cee3039a1bbf8c261e8c44e363/) | `macho` | unbekannt | 74.9 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 28.10.2026 01:03 UTC*