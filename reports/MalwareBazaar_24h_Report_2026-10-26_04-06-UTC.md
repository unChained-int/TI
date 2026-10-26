# MalwareBazaar – 26.10.2026 04:06 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **100** |
| Kritisch (≥75) | **82** |
| Höchster Score | **89.5/100** – 04d9c053e5cff50a… |
| Häufigste Familie | **SalatStealer** (92x) |
| Häufigster Typ | **exe** (96x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 2 Samples |
| Ø Dateigröße | 7.70 MB (σ=4.72) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 96 | 96.0%  ███████████████████ |
| `elf` | 3 | 3.0%   |
| `js` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | SalatStealer | 92 | 92.0% |
| 2 | unbekannt | 5 | 5.0% |
| 3 | RemcosRAT | 1 | 1.0% |
| 4 | Mirai | 1 | 1.0% |
| 5 | LummaStealer | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 83 | 83.0% | 75% |
| Windows-Malware | 12 | 12.0% | 35% |
| Trojaner | 2 | 2.0% | 70% |
| RAT | 1 | 1.0% | 95% |
| Botnet/IoT | 1 | 1.0% | 95% |
| Linux-Malware | 1 | 1.0% | 45% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 82 | 82.0% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 13 | 13.0% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [04d9c053e5cff5…](https://bazaar.abuse.ch/sample/04d9c053e5cff50a9eb0e974dd7b2b6a7065099329ba5073c769b4fe17f654f4/) | RemcosRAT | RAT | **89.5** | 🔴 KRITISCH | – | – | ? |
| [18dc14d98be70b…](https://bazaar.abuse.ch/sample/18dc14d98be70b0b3733839cd8582e3ead95e6dbfda2d9e0e44cc771c85b7345/) | Mirai | Botnet/IoT | **83.9** | 🔴 KRITISCH | – | – | ? |
| [815e8321b51a41…](https://bazaar.abuse.ch/sample/815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d/) | unbekannt | Trojaner | **82.3** | 🔴 KRITISCH | – | – | ? |
| [deb10b2a3c921b…](https://bazaar.abuse.ch/sample/deb10b2a3c921bb2e0cd7a2180f96a6f0cdb1cb830e55b885b53df4d3118d8f2/) | SalatStealer | Infostealer | **81.7** | 🔴 KRITISCH | – | – | ? |
| [49818c65eaad6e…](https://bazaar.abuse.ch/sample/49818c65eaad6ee5093f2b3253b2511e0733ac9800ec0b7033210e2ac462037d/) | SalatStealer | Infostealer | **81.6** | 🔴 KRITISCH | – | – | ? |
| [d98684d84b676f…](https://bazaar.abuse.ch/sample/d98684d84b676fbd89c39f01152c14ed7171065e59d1a231a15a077715859842/) | SalatStealer | Infostealer | **81.6** | 🔴 KRITISCH | – | – | ? |
| [965746db162d04…](https://bazaar.abuse.ch/sample/965746db162d04837da30254e20451f985efb1aff56b724baaa770b7f3de76a5/) | SalatStealer | Infostealer | **81.6** | 🔴 KRITISCH | – | – | ? |
| [56047cbe27a63d…](https://bazaar.abuse.ch/sample/56047cbe27a63d0cea335992c8111c06a8b2d1124c02c7e984bc2d0996732f08/) | SalatStealer | Infostealer | **81.6** | 🔴 KRITISCH | – | – | ? |
| [1fc26715d960f2…](https://bazaar.abuse.ch/sample/1fc26715d960f204b10dcd967843728b552ae22a7647147deb8a6f3c86b899ba/) | SalatStealer | Infostealer | **81.6** | 🔴 KRITISCH | – | – | ? |
| [50b420204ab02f…](https://bazaar.abuse.ch/sample/50b420204ab02f3848f862e0d8dedc740711e9d79c35fd90188b98205ce7e384/) | SalatStealer | Infostealer | **81.6** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6196/7644 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.1% | 6196/7644 |
| 3 | ESET-NOD32 | 77.2% | 5899/7644 |
| 4 | Kaspersky | 75.8% | 5790/7643 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5435/7641 |
| 8 | Rising | 68.3% | 5220/7644 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5056/7640 |
| 11 | Avast | 65.1% | 4973/7640 |
| 12 | AVG | 65.1% | 4973/7639 |
| 13 | Tencent | 64.8% | 4808/7418 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4680/7637 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 96 | 96.0% |
| 🐧 Linux | 3 | 3.0% |
| ❓ Unbekannt | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 99 | 99.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇳🇱 NL | 49 | 49.0% |
| 2 | 🇫🇷 FR | 36 | 36.0% |
| 3 | 🇺🇸 US | 12 | 12.0% |
| 4 | 🇨🇭 CH | 2 | 2.0% |
| 5 | 🇩🇪 DE | 1 | 1.0% |

## MITRE ATT&CK

> 2 von 100 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Command and Control | 1 |
| Collection | 1 |
| Initial Access | 1 |
| Lateral Movement | 1 |

<details><summary>04d9c053e5cff50a9eb0… – RemcosRAT | 🔴 KRITISCH 89.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>18dc14d98be70b0b3733… – Mirai | 🔴 KRITISCH 83.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [ba8346394f23db90f338…](https://bazaar.abuse.ch/sample/ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0/)

- **Familie:** SalatStealer
- **Erkannt von:** 47 von 75 Engines (62.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (47/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.8401` |
| APEX | `Malicious` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R765081` |
| Antiy-AVL | `Trojan[PSW]/Win32.Convagent` |
| Arcabit | `Trojan.Draftor.D20D1` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/Crypt.ULPM.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.8401` |
| Bkav | `W32.Malware.D9408B54` |
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
| Kingsoft | `malware.kb.b.919` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!DEAC839BF75D` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!5F142E753D3B` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-JBNR!5F142E753D3B` |
| VBA32 | `TrojanPSW.Satal` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| ZoneAlarm | `Troj/Salat-B` |
| huorong | `Trojan/Agent.e!crit` |

### [4dd43a8aea19f785570a…](https://bazaar.abuse.ch/sample/4dd43a8aea19f785570aed976c78b9dadf3dc6df954a2278b7d55373de964518/)

- **Familie:** LummaStealer
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
| Bkav | `W32.Malware.D50D3B54` |
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
| McAfeeD | `Real Protect-LS!75D8F5385D73` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!75D8F5385D73` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!75D8F5385D73` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [f585889eea97199802c6…](https://bazaar.abuse.ch/sample/f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2/)

- **Familie:** SalatStealer
- **Erkannt von:** 44 von 75 Engines (58.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (44/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.8401` |
| APEX | `Malicious` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R765081` |
| Antiy-AVL | `Trojan[PSW]/Win32.Convagent` |
| Arcabit | `Trojan.Draftor.D20D1` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/Crypt.ULPM.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.8401` |
| Bkav | `W32.Malware.5D9A19E9` |
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
| Malwarebytes | `Trojan.MalPack.Generic` |
| McAfeeD | `Real Protect-LS!C98B9D0A502E` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!90E58BD0BA19` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-JBNR!90E58BD0BA19` |
| VBA32 | `TrojanPSW.Satal` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| ZoneAlarm | `Troj/Salat-B` |
| huorong | `Trojan/Agent.e!crit` |

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

### [9d6740d5b7abd4aff685…](https://bazaar.abuse.ch/sample/9d6740d5b7abd4aff685678510b547c131bda2c7a086ba955368a4cf4715baa6/)

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
| Bkav | `W32.Malware.145BD1CA` |
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
| McAfeeD | `Real Protect-LS!5964EBF09E79` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!5964EBF09E79` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!5964EBF09E79` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **exe** (96×)
- **SalatStealer** (70×)
- **upx-dec** (48×)
- **upx** (46×)
- **salatstealer** (12×)
- **elf** (3×)
- **js** (1×)
- **RAT** (1×)
- **RemcosRAT** (1×)
- **Mirai** (1×)
- **wraith** (1×)
- **honeypot** (1×)
- **trojan.multiverze** (1×)

## Änderungen – 24h-Vergleich

- ↑ **SalatStealer** +80 (12→92)
- ↓ **unbekannt** -14 (19→5)
- neu: **RemcosRAT** (1)
- ↓ **Mirai** -20 (21→1)
- neu: **LummaStealer** (1)
- weg: **CoinMiner** (war 2)
- weg: **AveMariaRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **SalatStealer** +89 (3→92)
- ↓ **unbekannt** -32 (37→5)
- ↓ **Mirai** -18 (19→1)
- neu: **LummaStealer** (1)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 7.700 MB |
| σ Dateigröße | 4.724 MB |
| Ø Risiko-Score | 75.3/100 |
| Ø Klassifikations-Konfidenz | 70.1% |
| Samples mit VT | 5/100 |
| Samples mit MITRE | 2/100 |
| Eindeutige Familien | 5 |
| Eindeutige Tags | 13 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:55 | [34e5887dd333…](https://bazaar.abuse.ch/sample/34e5887dd33383ebaefa05e6237615463987affd4af6846163fba94221b0b435/) | `exe` | unbekannt | 38.9 | – | – | 🌐CH |
| 03:45 | [04d9c053e5cf…](https://bazaar.abuse.ch/sample/04d9c053e5cff50a9eb0e974dd7b2b6a7065099329ba5073c769b4fe17f654f4/) | `js` | RemcosRAT | 89.5 | – | – | 🇳🇱NL |
| 03:32 | [f9829cddd02a…](https://bazaar.abuse.ch/sample/f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2/) | `exe` | unbekannt | 38.6 | – | – | 🇺🇸US |
| 03:28 | [deb10b2a3c92…](https://bazaar.abuse.ch/sample/deb10b2a3c921bb2e0cd7a2180f96a6f0cdb1cb830e55b885b53df4d3118d8f2/) | `exe` | SalatStealer | 81.7 | – | – | 🇳🇱NL |
| 03:27 | [49818c65eaad…](https://bazaar.abuse.ch/sample/49818c65eaad6ee5093f2b3253b2511e0733ac9800ec0b7033210e2ac462037d/) | `exe` | SalatStealer | 81.6 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 26.10.2026 04:06 UTC*