# MalwareBazaar – 31.10.2026 04:41 UTC

Dieser Run hat **90 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **91** |
| Kritisch (≥75) | **65** |
| Höchster Score | **97.5/100** – 8afbfbca417179ab… |
| Häufigste Familie | **SalatStealer** (53x) |
| Häufigster Typ | **exe** (69x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 7 Samples |
| Ø Dateigröße | 6.67 MB (σ=6.46) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 69 | 75.8%  ███████████████ |
| `elf` | 9 | 9.9%  █ |
| `dll` | 6 | 6.6%  █ |
| `sh` | 3 | 3.3%   |
| `msi` | 2 | 2.2%   |
| `jar` | 1 | 1.1%   |
| `macho` | 1 | 1.1%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | SalatStealer | 53 | 58.2% |
| 2 | unbekannt | 13 | 14.3% |
| 3 | Mirai | 7 | 7.7% |
| 4 | WannaCry | 5 | 5.5% |
| 5 | RustyStealer | 3 | 3.3% |
| 6 | Adware.OfferCore | 2 | 2.2% |
| 7 | ConnectWise | 2 | 2.2% |
| 8 | AveMariaRAT | 1 | 1.1% |
| 9 | CoinMiner | 1 | 1.1% |
| 10 | FleetDeck | 1 | 1.1% |
| 11 | Conficker | 1 | 1.1% |
| 12 | Redosdru | 1 | 1.1% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 57 | 62.6% | 75% |
| Windows-Malware | 14 | 15.4% | 35% |
| Botnet/IoT | 7 | 7.7% | 95% |
| Ransomware | 5 | 5.5% | 95% |
| Andere / Unbekannt | 4 | 4.4% | 20% |
| Linux-Malware | 2 | 2.2% | 45% |
| RAT | 1 | 1.1% | 75% |
| Cryptominer | 1 | 1.1% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 65 | 71.4% |
| 🟠 HOCH | 6 | 6.6% |
| 🟡 MITTEL | 16 | 17.6% |
| 🟢 NIEDRIG | 4 | 4.4% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [8afbfbca417179…](https://bazaar.abuse.ch/sample/8afbfbca417179ab9c6e18cf3e138b5c0eed324ea2aee735ad37070de4cb8028/) | WannaCry | Ransomware | **97.5** | 🔴 KRITISCH | – | – | ? |
| [d687fd479c608b…](https://bazaar.abuse.ch/sample/d687fd479c608be08e730f290b9f8963f68b218b6cdd64920004cafb856c1fbc/) | WannaCry | Ransomware | **94.3** | 🔴 KRITISCH | – | – | ? |
| [e6a3ac4235b6ef…](https://bazaar.abuse.ch/sample/e6a3ac4235b6ef444de81213a9c13c6ab5f208f67a240afb5e9182ff538425a5/) | WannaCry | Ransomware | **94.3** | 🔴 KRITISCH | – | – | ? |
| [eae060ec7b72fa…](https://bazaar.abuse.ch/sample/eae060ec7b72faf302fc7a95504c2a12992521b413ea3d5a3fee1a7cedb699db/) | WannaCry | Ransomware | **94.3** | 🔴 KRITISCH | – | – | ? |
| [8e066a643d856c…](https://bazaar.abuse.ch/sample/8e066a643d856cbaf6c121f665bb9d71f41a741c33419a10ba9a0a1c98b1a0e7/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [7b424ec6ef2a5d…](https://bazaar.abuse.ch/sample/7b424ec6ef2a5d88fc44a24f009f6390cd68267794c41373d8e1a5ea969f70d1/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [2f49e9b935e1f1…](https://bazaar.abuse.ch/sample/2f49e9b935e1f1a79505356a97697a6822fd662beeff960bce6143552e8dd64f/) | Mirai | Botnet/IoT | **83.3** | 🔴 KRITISCH | – | – | ? |
| [82724333d8ef6f…](https://bazaar.abuse.ch/sample/82724333d8ef6f8f603a2f0fa6d1d557a53f3c296d2115974075144df575274d/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [649f6882830f7b…](https://bazaar.abuse.ch/sample/649f6882830f7b390a957194e31d54cc4fcbfb0eb204315afefb3819a1882348/) | unbekannt | Infostealer | **82.2** | 🔴 KRITISCH | – | – | ? |
| [8fd487b8661f92…](https://bazaar.abuse.ch/sample/8fd487b8661f92cbd8df23cea0a13f0b6810ba12a28a1eb89683ede77e73dd20/) | RustyStealer | Infostealer | **82.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6275/7740 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6275/7740 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 5983/7740 |
| 6 | Kaspersky | 75.5% | 5845/7739 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5508/7736 |
| 9 | Rising | 68.3% | 5288/7740 |
| 10 | Varist | 66.2% | 5119/7735 |
| 11 | Avast | 65.2% | 5041/7736 |
| 12 | AVG | 65.2% | 5041/7735 |
| 13 | Tencent | 64.9% | 4878/7514 |
| 14 | McAfeeD | 61.3% | 4738/7732 |
| 15 | huorong | 60.8% | 4703/7732 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 77 | 84.6% |
| 🐧 Linux | 12 | 13.2% |
| ❓ Unbekannt | 1 | 1.1% |
| 🍎 macOS | 1 | 1.1% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 84 | 92.3% |
| Exploit / N-Day | 5 | 5.5% |
| Trojanisierte Software | 2 | 2.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 43 | 47.3% |
| 2 | 🇳🇱 NL | 26 | 28.6% |
| 3 | 🇫🇷 FR | 13 | 14.3% |
| 4 | 🇩🇪 DE | 8 | 8.8% |
| 5 | 🌐 Unbekannt | 1 | 1.1% |

## MITRE ATT&CK

> 7 von 91 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 7 |
| Lateral Movement | 7 |

<details><summary>8e066a643d856cbaf6c1… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [57ce811875c338ba2f30…](https://bazaar.abuse.ch/sample/57ce811875c338ba2f30c83655390c5420c5c512d8ae4fc1e73ebbc116f856a8/)

- **Familie:** SalatStealer
- **Erkannt von:** 48 von 75 Engines (64.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (48/75):**

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
| Bkav | `W32.Malware.C5385EF1` |
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
| Gridinsoft | `Trojan.Win32.Agent.oa!s1` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!F492EF96D2EA` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!F492EF96D2EA` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570822` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!F492EF96D2EA` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [b3bcbc57e7d1b1305dd5…](https://bazaar.abuse.ch/sample/b3bcbc57e7d1b1305dd5fa1107de1612629457186b1939d9dd01097c699e36f2/)

- **Familie:** SalatStealer
- **Erkannt von:** 60 von 75 Engines (80.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (60/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Draftor.8401` |
| APEX | `Malicious` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.SalatStealer.R765081` |
| Alibaba | `TrojanBanker:Win32/SalatStealer.b09b40e9` |
| Antiy-AVL | `Trojan[PSW]/Win32.Convagent` |
| Arcabit | `Trojan.Draftor.D20D1` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/Crypt.ULPM.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Draftor.8401` |
| Bkav | `W32.Malware.87C1B5E8` |
| CAT-QuickHeal | `Trojanpws.Win64` |
| CTX | `exe.unknown.draftor` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
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
| Kaspersky | `UDS:Trojan-PSW.Win64.Salat` |
| Kingsoft | `Win64.Trojan-PSW.Salat.a` |
| Lionic | `Trojan.Win32.Salat.i!c` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| McAfeeD | `Real Protect-LS!37E3CFAF5E53` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Panda | `Trj/Genetic.gen` |
| Rising | `Stealer.Salat!1.13A22 (CLOUD)` |
| Sangfor | `Infostealer.Win32.Agent.V0xx` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!DEA2D5F9197F` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570810` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Artemis!37E3CFAF5E53` |
| TrendMicro | `Trojan.Win32.SALAT.USBLJT26` |
| TrendMicro-HouseCall | `Trojan.Win32.SALAT.USBLJT26` |
| VBA32 | `TrojanPSW.Satal` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| Varist | `W32/ABTrojan.UKKW-0195` |
| ViRobot | `Trojan.Win.Z.Draftor.3592890.B` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| ZoneAlarm | `Troj/Salat-B` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |

### [db6c50bff6d12df001ce…](https://bazaar.abuse.ch/sample/db6c50bff6d12df001cec8103c85f883b248b9aa3d64cab52705cb49a63288e8/)

- **Familie:** SalatStealer
- **Erkannt von:** 40 von 75 Engines (53.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (40/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.LummaStealer.103` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.Generic.R727379` |
| Arcabit | `Trojan.LummaStealer.103` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.LummaStealer.103` |
| Bkav | `W32.Malware.2FE627C8` |
| ClamAV | `Win.Malware.Salat-10058846-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cynet | `Malicious (score: 99)` |
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
| Kaspersky | `HEUR:Trojan-PSW.Win32.Convagent.gen` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `ti!DB6C50BFF6D1` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!D811A767B7E5` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!D811A767B7E5` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [86b193b0614e1399b84e…](https://bazaar.abuse.ch/sample/86b193b0614e1399b84e4ea81e35d07cd0a96e93be6a5c97354aafbab2c81d2e/)

- **Familie:** WannaCry
- **Erkannt von:** 63 von 76 Engines (82.9%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Agent.CZTF
- **VT-Reputation:** -59
- **Microsoft Defender:** ✓ **JA** – `Trojan.Agent.CZTF`

**Erkennende Engines (63/76):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Agent.CZTF` |
| APEX | `Malicious` |
| AVG | `Sf:WNCryLdr-A [Trj]` |
| Acronis | `suspicious` |
| Ad-Aware | `Trojan.Agent.CZTF` |
| AhnLab-V3 | `Trojan/Win32.WannaCryptor.R200894` |
| Alibaba | `Ransom:Win32/CVE-2017-0147.4f292267` |
| Antiy-AVL | `Trojan[Ransom]/Win32.Wanna` |
| Arcabit | `Trojan.Agent.CZTF` |
| Avast | `Sf:WNCryLdr-A [Trj]` |
| Avira | `TR/Ransom.Gen` |
| Baidu | `Win32.Worm.Rbot.a` |
| BitDefender 🛡️ | `Trojan.Agent.CZTF` |
| BitDefenderTheta 🛡️ | `Gen:NN.ZedlaF.34780.@x5@aC0WZ7ei` |
| Bkav | `W32.AIDetectVM.malware2` |
| CAT-QuickHeal | `Ransom.Zenshirsh.SL8` |
| ClamAV | `Win.Ransomware.WannaCry-6313787-0` |
| Comodo | `TrojWare.Win32.Ransom.WannaCry.AB@75ge5e` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| Cyren | `W32/WannaCrypt.A.gen!Eldorado` |
| DrWeb | `Trojan.Encoder.11432` |
| ESET-NOD32 | `Win32/Exploit.CVE-2017-0147.A` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Agent.CZTF (B)` |
| F-Secure | `Trojan.TR/Ransom.Gen` |
| FireEye | `Generic.mg.32a2b30d99ddef91` |
| Fortinet | `W32/Wanna.M!tr` |
| GData | `Win32.Trojan-Ransom.WannaCry.K` |
| Gridinsoft | `Ransom.Win32.WannaCrypt.ko!s1` |
| Ikarus | `Exploit.CVE-2017-0147` |
| Jiangmin | `Trojan.Wanna.k` |
| K7AntiVirus | `Trojan ( 00557fc41 )` |
| K7GW | `Trojan ( 00557fc41 )` |
| Kaspersky | `Trojan-Ransom.Win32.Wanna.m` |
| MAX | `malware (ai score=100)` |
| Malwarebytes | `Ransom.WannaCrypt` |
| MaxSecure | `Trojan-Ransom.Win32.Wanna.m` |
| McAfee | `GenericRXFL-OG!32A2B30D99DD` |
| McAfee-GW-Edition | `BehavesLike.Win32.Generic.tm` |
| MicroWorld-eScan | `Trojan.Agent.CZTF` |
| Microsoft 🛡️ | `Ransom:Win32/CVE-2017-0147.A` |
| NANO-Antivirus | `Trojan.Win32.Wanna.epxkni` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Qihoo-360 | `Win32/Worm.WannaCrypt.W` |
| Rising | `Exploit.EternalBlue!1.AAED (CLASSIC)` |
| Sangfor | `Malware` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Generic-R + Mal/Wanna-A` |
| Symantec | `Ransom.Wannacry` |
| TACHYON | `Ransom/W32.WannaCry.5267459` |
| Tencent | `Trojan-Ransom.Win32.Wanna.m` |
| TrendMicro | `Ransom_WCRY.SMALYM` |
| TrendMicro-HouseCall | `Ransom_WCRY.SMALYM` |
| VBA32 | `Hoax.Wanna` |
| VIPRE | `Trojan.Win32.Generic!BT` |
| ViRobot | `Trojan.Win32.WannaCry.5267459` |
| Yandex | `Trojan.GenAsa!+DXFZHdb97c` |
| Zillya | `Exploit.CVE.Win32.1765` |
| ZoneAlarm | `Trojan-Ransom.Win32.Wanna.m` |
| eGambit | `Trojan.Generic` |

### [7e4c129f5bd09beffae1…](https://bazaar.abuse.ch/sample/7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** SalatStealer
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (55/75):**

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
| Gridinsoft | `Trojan.Win32.Agent.sa` |
| Ikarus | `Win32.Outbreak` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Kaspersky | `UDS:Trojan-PSW.Win64.Salat` |
| Kingsoft | `Win32.Troj.salatstealer.v` |
| Lionic | `Trojan.Win32.Agent.tt6y` |
| Malwarebytes | `Spyware.SalatStealer` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Real Protect-LS!9E7BE912AC3C` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| Sangfor | `Infostealer.Win32.Salatstealer.Vsjg` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570877` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!9E7BE912AC3C` |
| TrendMicro | `TrojanSpy.Win32.SALATSTEALER.YXGJZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |


## Top Tags

- **exe** (69×)
- **SalatStealer** (30×)
- **upx-dec** (26×)
- **upx** (26×)
- **salatstealer** (22×)
- **elf** (9×)
- **dionaea** (7×)
- **dll** (6×)
- **Mirai** (6×)
- **signed** (6×)
- **honeypot** (6×)
- **pe** (6×)
- **x86** (6×)
- **Torii** (5×)
- **WannaCry** (5×)

## Änderungen – 24h-Vergleich

- ↑ **SalatStealer** +39 (14→53)
- ↓ **unbekannt** -18 (31→13)
- ↓ **Mirai** -15 (22→7)
- ↑ **WannaCry** +4 (1→5)
- neu: **RustyStealer** (3)
- neu: **Adware.OfferCore** (2)
- neu: **ConnectWise** (2)
- neu: **AveMariaRAT** (1)
- neu: **FleetDeck** (1)
- weg: **Formbook** (war 2)
- weg: **AgentTesla** (war 2)
- weg: **NIKRAT** (war 3)
- weg: **XWorm** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **SalatStealer** +38 (15→53)
- ↓ **unbekannt** -10 (23→13)
- ↓ **Mirai** -16 (23→7)
- neu: **WannaCry** (5)
- neu: **RustyStealer** (3)
- neu: **Adware.OfferCore** (2)
- ↑ **ConnectWise** +1 (1→2)
- neu: **AveMariaRAT** (1)
- neu: **FleetDeck** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 6.667 MB |
| σ Dateigröße | 6.457 MB |
| Ø Risiko-Score | 70.1/100 |
| Ø Klassifikations-Konfidenz | 68.3% |
| Samples mit VT | 5/91 |
| Samples mit MITRE | 7/91 |
| Eindeutige Familien | 13 |
| Eindeutige Tags | 40 |
| Unbekannte Familien | 4 (4.4%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 04:40 | [649f6882830f…](https://bazaar.abuse.ch/sample/649f6882830f7b390a957194e31d54cc4fcbfb0eb204315afefb3819a1882348/) | `jar` | unbekannt | 82.2 | – | – | 🇺🇸US |
| 04:25 | [5e6344e84734…](https://bazaar.abuse.ch/sample/5e6344e847341634933353ce78815fd570bf4f6a9f4f9fc5e12a02be98503bc9/) | `sh` | unbekannt | 32.5 | – | – | 🇺🇸US |
| 04:25 | [8e066a643d85…](https://bazaar.abuse.ch/sample/8e066a643d856cbaf6c121f665bb9d71f41a741c33419a10ba9a0a1c98b1a0e7/) | `elf` | Mirai | 84.3 | – | – | 🇺🇸US |
| 04:25 | [af5062786294…](https://bazaar.abuse.ch/sample/af5062786294b67d1befa07b6a43e4f22cec72a887fe2e94e937688e15c53cc3/) | `dll` | unbekannt | 38.9 | – | – | 🇺🇸US |
| 04:25 | [8fd487b8661f…](https://bazaar.abuse.ch/sample/8fd487b8661f92cbd8df23cea0a13f0b6810ba12a28a1eb89683ede77e73dd20/) | `exe` | RustyStealer | 82.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 31.10.2026 04:41 UTC*