# MalwareBazaar – 24.10.2026 03:49 UTC

Dieser Run hat **46 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `4124a486bff5d1fa6058…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **47** |
| Kritisch (≥75) | **20** |
| Höchster Score | **84.2/100** – edcd4de69b7e4c14… |
| Häufigste Familie | **unbekannt** (24x) |
| Häufigster Typ | **exe** (17x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 11 Samples |
| Ø Dateigröße | 3.58 MB (σ=4.00) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 17 | 36.2%  ███████ |
| `elf` | 14 | 29.8%  █████ |
| `macho` | 13 | 27.7%  █████ |
| `sh` | 1 | 2.1%   |
| `msi` | 1 | 2.1%   |
| `ps1` | 1 | 2.1%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 24 | 51.1% |
| 2 | Mirai | 10 | 21.3% |
| 3 | SalatStealer | 7 | 14.9% |
| 4 | RustyStealer | 3 | 6.4% |
| 5 | Adware.OfferCore | 1 | 2.1% |
| 6 | ConnectWise | 1 | 2.1% |
| 7 | PythonStealer | 1 | 2.1% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 11 | 23.4% | 75% |
| Botnet/IoT | 11 | 23.4% | 93% |
| Loader | 11 | 23.4% | 75% |
| Windows-Malware | 6 | 12.8% | 35% |
| Linux-Malware | 4 | 8.5% | 45% |
| Andere / Unbekannt | 2 | 4.3% | 20% |
| Skript/Dropper | 1 | 2.1% | 35% |
| Trojaner | 1 | 2.1% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 20 | 42.6% |
| 🟠 HOCH | 15 | 31.9% |
| 🟡 MITTEL | 10 | 21.3% |
| 🟢 NIEDRIG | 2 | 4.3% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [edcd4de69b7e4c…](https://bazaar.abuse.ch/sample/edcd4de69b7e4c14a8948a7a8c600a7ce22731fbd5da9fbdae7c8f59d5f2fb90/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [da54c10718b464…](https://bazaar.abuse.ch/sample/da54c10718b4649eb6e9dd59abd3347a3f1c100d14a89d837e99214e4442e303/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [d1ab5c35e09e0d…](https://bazaar.abuse.ch/sample/d1ab5c35e09e0d0bcfeea6a9c612169551e593957599260bce88c879efbb05af/) | RustyStealer | Infostealer | **81.9** | 🔴 KRITISCH | – | – | ? |
| [bdff003f47f176…](https://bazaar.abuse.ch/sample/bdff003f47f176d4c685a032ffdb7db5e482c812bcd0c7e58acc76327f317a36/) | RustyStealer | Infostealer | **81.9** | 🔴 KRITISCH | – | – | ? |
| [d65fec3809cf43…](https://bazaar.abuse.ch/sample/d65fec3809cf4341aedceccdb8eb856b430f7afcb6df88420eb3101011aacbf0/) | RustyStealer | Infostealer | **81.9** | 🔴 KRITISCH | – | – | ? |
| [6f714f70d511ef…](https://bazaar.abuse.ch/sample/6f714f70d511efb4eb3a21e50b6acf8728de66f0794b17db48f750b0e9b1212a/) | Mirai | Botnet/IoT | **81.2** | 🔴 KRITISCH | – | – | ? |
| [619e999480704d…](https://bazaar.abuse.ch/sample/619e999480704dde6e59626511a48a37170a17f6e4fdc42b942b562d631458ba/) | Mirai | Botnet/IoT | **81.1** | 🔴 KRITISCH | – | – | ? |
| [226bd33caa93d3…](https://bazaar.abuse.ch/sample/226bd33caa93d3ed07e70f229d58188caa10caa369cf9d1fbcc3af2842b3c5b5/) | Mirai | Botnet/IoT | **81.1** | 🔴 KRITISCH | – | – | ? |
| [2973d2d69a0d9e…](https://bazaar.abuse.ch/sample/2973d2d69a0d9ef0f0da6b285b2bb8bb2d1f6037de85214d9f2510f3329704ef/) | Mirai | Botnet/IoT | **81.0** | 🔴 KRITISCH | – | – | ? |
| [97fdba0b9d0588…](https://bazaar.abuse.ch/sample/97fdba0b9d0588d25db1b9c252e5154177fa1471abe35e947858ca0d82afcde7/) | Mirai | Botnet/IoT | **80.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6147/7592 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6147/7592 |
| 3 | ESET-NOD32 | 77.2% | 5862/7592 |
| 4 | Kaspersky | 75.9% | 5763/7591 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5401/7589 |
| 8 | Rising | 68.4% | 5191/7592 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5024/7588 |
| 11 | Avast | 65.1% | 4941/7588 |
| 12 | AVG | 65.1% | 4941/7587 |
| 13 | Tencent | 64.9% | 4780/7366 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4644/7585 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 19 | 40.4% |
| 🐧 Linux | 15 | 31.9% |
| 🍎 macOS | 13 | 27.7% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 35 | 74.5% |
| MaaS-Loader | 11 | 23.4% |
| Trojanisierte Software | 1 | 2.1% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 28 | 59.6% |
| 2 | 🇳🇱 NL | 9 | 19.1% |
| 3 | 🇩🇪 DE | 9 | 19.1% |
| 4 | 🌐 Unbekannt | 1 | 2.1% |

## MITRE ATT&CK

> 11 von 47 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 11 |
| Lateral Movement | 11 |

<details><summary>edcd4de69b7e4c14a894… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>da54c10718b4649eb6e9… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [b1bf43f0327f500bc47e…](https://bazaar.abuse.ch/sample/b1bf43f0327f500bc47e62f42630137cd85f0af715efce69a5700cbda7d870e7/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [121f6d62851254b75be4…](https://bazaar.abuse.ch/sample/121f6d62851254b75be4384deefd56bae63f09888b38f0a693099ba23c81dafb/)

- **Familie:** SalatStealer
- **Erkannt von:** 47 von 75 Engines (62.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (47/75):**

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
| Bkav | `W32.Malware.98AF6CA2` |
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
| McAfeeD | `Real Protect-LS!E8043F0E1752` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!E8043F0E1752` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!E8043F0E1752` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAJ` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Zillya | `Trojan.Agent.Win32.4649254` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [79f3a3dd483248bcdd90…](https://bazaar.abuse.ch/sample/79f3a3dd483248bcdd90f6e87ed6c3b38f4332448816cbe955bdb1add4c57ba7/)

- **Familie:** SalatStealer
- **Erkannt von:** 46 von 75 Engines (61.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (46/75):**

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
| Bkav | `W32.Malware.F14025C3` |
| CTX | `exe.unknown.draftor` |
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
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Kingsoft | `malware.kb.b.944` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!50C15494EE15` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!DC3428E098DF` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-JBNR!DC3428E098DF` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| ZoneAlarm | `Troj/Salat-B` |
| huorong | `Trojan/Agent.e!crit` |

### [0f832acaae076974077a…](https://bazaar.abuse.ch/sample/0f832acaae076974077a8a2b072a74ea70c441105ed560b625ca593a37de3d05/)

- **Familie:** Mirai
- **Erkannt von:** 18 von 75 Engines (24.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Linux/DDoS-BI
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (18/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Miner]/JS.CoinMiner` |
| DrWeb | `Linux.Mirai.10456` |
| ESET-NOD32 | `Linux/CoinMiner.AVN trojan` |
| Google | `Detected` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nn` |
| Kingsoft | `Linux.Backdoor.Mirai.nn` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `ti!0F832ACAAE07` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.U!MTB` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (CLOUD)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-BI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Linux.Trojan.Coinminer.Edhl` |
| Varist | `E32/ABMiner.NLAA-3` |
| ZoneAlarm | `Linux/DDoS-BI` |
| alibabacloud | `Miner:Linux/CoinMiner.SBW` |
| huorong | `Trojan/Linux.Mirai.l` |

### [4124a486bff5d1fa6058…](https://bazaar.abuse.ch/sample/4124a486bff5d1fa60585d36982618c97956b0f9483ddd5b8e7d7d8a18dc359b/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** PythonStealer
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Win32.QWEXLAFIBA.USBLJJ26
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Qwexlafiba!rfn`

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AhnLab-V3 | `Trojan/Win.Generic.C5961086` |
| Antiy-AVL | `Trojan/Win32.Agent` |
| Bkav | `W32.Malware.7053573B` |
| CTX | `exe.trojan.qwexlafiba` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Ikarus | `Trojan.Win32.BadJoke` |
| K7GW | `Hacktool ( a007e0071 )` |
| Kingsoft | `Win32.Troj.qwexlafiba.v` |
| Malwarebytes | `Trojan.Injector` |
| MaxSecure | `Trojan.Malware.727547498.susgen` |
| McAfeeD | `ti!4124A486BFF5` |
| Microsoft 🛡️ | `Trojan:Win32/Qwexlafiba!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| TrendMicro-HouseCall | `Trojan.Win32.QWEXLAFIBA.USBLJJ26` |
| VBA32 | `TrojanPSW.FBStealer` |
| Varist | `W64/ABTrojan.ANKV-0822` |
| VirIT | `Trojan.Win64.Agent.IXM` |
| alibabacloud | `Trojan:Win/Qwexlafiba.Gen` |


## Top Tags

- **exe** (16×)
- **macho** (13×)
- **elf** (12×)
- **ClickFix** (12×)
- **Foxveil** (12×)
- **Mach-O** (12×)
- **macOS** (12×)
- **loader** (11×)
- **Mirai** (10×)
- **upx-dec** (6×)
- **upx** (6×)
- **salatstealer** (4×)
- **RustyStealer** (3×)
- **SalatStealer** (3×)
- **Prometei** (2×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -2 (26→24)
- ↓ **Mirai** -12 (22→10)
- ↑ **SalatStealer** +6 (1→7)
- neu: **RustyStealer** (3)
- neu: **ConnectWise** (1)
- weg: **RemcosRAT** (war 3)
- weg: **Formbook** (war 3)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -15 (39→24)
- ↓ **Mirai** -12 (22→10)
- ↑ **SalatStealer** +6 (1→7)
- neu: **RustyStealer** (3)
- neu: **Adware.OfferCore** (1)
- neu: **ConnectWise** (1)
- weg: **RemcosRAT** (war 2)
- weg: **CoinMiner** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.583 MB |
| σ Dateigröße | 3.998 MB |
| Ø Risiko-Score | 66.3/100 |
| Ø Klassifikations-Konfidenz | 68.2% |
| Samples mit VT | 5/47 |
| Samples mit MITRE | 11/47 |
| Eindeutige Familien | 7 |
| Eindeutige Tags | 32 |
| Unbekannte Familien | 2 (4.3%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:26 | [a56f66cc45cd…](https://bazaar.abuse.ch/sample/a56f66cc45cd083ffe7ed8f4acb19b3ced3c17c699c32c06ea8d53337fe8c0c2/) | `elf` | unbekannt | 43.0 | – | – | 🇳🇱NL |
| 03:26 | [d1ab5c35e09e…](https://bazaar.abuse.ch/sample/d1ab5c35e09e0d0bcfeea6a9c612169551e593957599260bce88c879efbb05af/) | `exe` | RustyStealer | 81.9 | – | – | 🇺🇸US |
| 03:25 | [bdff003f47f1…](https://bazaar.abuse.ch/sample/bdff003f47f176d4c685a032ffdb7db5e482c812bcd0c7e58acc76327f317a36/) | `exe` | RustyStealer | 81.9 | – | – | 🇺🇸US |
| 03:25 | [2be0cf0161e4…](https://bazaar.abuse.ch/sample/2be0cf0161e40183c978b28bf20159a51cb77bec532bf0dd49c01572f4c7302d/) | `elf` | unbekannt | 75.7 | – | – | 🇺🇸US |
| 03:25 | [d65fec3809cf…](https://bazaar.abuse.ch/sample/d65fec3809cf4341aedceccdb8eb856b430f7afcb6df88420eb3101011aacbf0/) | `exe` | RustyStealer | 81.9 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 24.10.2026 03:49 UTC*