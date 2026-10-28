# MalwareBazaar – 28.10.2026 16:29 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **73** |
| Höchster Score | **89.3/100** – 1891b91cbe076577… |
| Häufigste Familie | **Mirai** (47x) |
| Häufigster Typ | **elf** (56x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 57 Samples |
| Ø Dateigröße | 2.92 MB (σ=11.30) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 56 | 55.4%  ███████████ |
| `exe` | 18 | 17.8%  ███ |
| `js` | 11 | 10.9%  ██ |
| `vbs` | 7 | 6.9%  █ |
| `sh` | 2 | 2.0%   |
| `lnk` | 1 | 1.0%   |
| `xlsm` | 1 | 1.0%   |
| `zsh` | 1 | 1.0%   |
| `wsf` | 1 | 1.0%   |
| `jar` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 47 | 46.5% |
| 2 | unbekannt | 15 | 14.9% |
| 3 | SalatStealer | 7 | 6.9% |
| 4 | XWorm | 6 | 5.9% |
| 5 | RemcosRAT | 5 | 5.0% |
| 6 | AgentTesla | 3 | 3.0% |
| 7 | SilentNet | 2 | 2.0% |
| 8 | Formbook | 2 | 2.0% |
| 9 | ConnectWise | 2 | 2.0% |
| 10 | AsyncRAT | 1 | 1.0% |
| 11 | Grandoreiro | 1 | 1.0% |
| 12 | C!ml | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 47 | 46.5% | 95% |
| RAT | 13 | 12.9% | 93% |
| Infostealer | 11 | 10.9% | 80% |
| Linux-Malware | 8 | 7.9% | 45% |
| Windows-Malware | 7 | 6.9% | 35% |
| Skript/Dropper | 6 | 5.9% | 35% |
| Andere / Unbekannt | 2 | 2.0% | 20% |
| Trojaner | 2 | 2.0% | 65% |
| Loader | 2 | 2.0% | 85% |
| Maldoc | 1 | 1.0% | 35% |
| Cryptominer | 1 | 1.0% | 75% |
| Spyware | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 73 | 72.3% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 22 | 21.8% |
| 🟢 NIEDRIG | 2 | 2.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [1891b91cbe0765…](https://bazaar.abuse.ch/sample/1891b91cbe07657794700e6c8eab5ef7a4c64ed0fb8ab1e1f14fdef66c074386/) | AsyncRAT | RAT | **89.3** | 🔴 KRITISCH | – | – | ? |
| [ae02f57c450fea…](https://bazaar.abuse.ch/sample/ae02f57c450feae937209022b742fc1fb7af5896b42c4183beed4ed67388a13b/) | AMOS | Infostealer | **89.0** | 🔴 KRITISCH | – | – | ? |
| [a46511c3289605…](https://bazaar.abuse.ch/sample/a46511c328960566b95965a60da2f59c5bd95600b4c455df4ad6066fa8a8be0b/) | XWorm | RAT | **88.7** | 🔴 KRITISCH | – | – | ? |
| [382e2bd0a1b1bf…](https://bazaar.abuse.ch/sample/382e2bd0a1b1bf18cdf94438ec898450b05b12577e6f2f3579019518d0bb2f5a/) | Formbook | Infostealer | **88.5** | 🔴 KRITISCH | – | – | ? |
| [e4bcaa042fd2fd…](https://bazaar.abuse.ch/sample/e4bcaa042fd2fdee097a8bfef573e94ce955144c8a52970383f5381b4821efbe/) | XWorm | RAT | **88.4** | 🔴 KRITISCH | – | – | ? |
| [d511b6fe91ef43…](https://bazaar.abuse.ch/sample/d511b6fe91ef43489335dd7608784648506a2cfff5fb60558e378ada1888f3ef/) | XWorm | RAT | **88.4** | 🔴 KRITISCH | – | – | ? |
| [6a8a4476ef5819…](https://bazaar.abuse.ch/sample/6a8a4476ef5819e4ebc0dffc03661f91d180f5e2fd160bcb3c3a16d87925d78d/) | Formbook | Infostealer | **88.0** | 🔴 KRITISCH | – | – | ? |
| [8fa7d47c3cb435…](https://bazaar.abuse.ch/sample/8fa7d47c3cb435fe6edeac5bdb580ae1a075c4cb8f25f3ec6e8e8047e2fc6b8c/) | RemcosRAT | RAT | **87.1** | 🔴 KRITISCH | – | – | ? |
| [b342e35b3f01fd…](https://bazaar.abuse.ch/sample/b342e35b3f01fd4a78ce2a0d1c94ccd3b24d65487f7b2091d84c8aa310fa2e40/) | XWorm | RAT | **87.0** | 🔴 KRITISCH | – | – | ? |
| [c475d58e160351…](https://bazaar.abuse.ch/sample/c475d58e160351b496c666f70ea13d494db1ecd8d54a36a27368b049c669233e/) | XWorm | RAT | **87.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6233/7691 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6233/7691 |
| 3 | ESET-NOD32 | 77.2% | 5937/7691 |
| 4 | Kaspersky | 75.5% | 5809/7690 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.1% | 5470/7688 |
| 8 | Rising | 68.3% | 5253/7691 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5085/7687 |
| 11 | Avast | 65.1% | 5005/7687 |
| 12 | AVG | 65.1% | 5005/7686 |
| 13 | Tencent | 64.9% | 4843/7465 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4705/7684 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 59 | 58.4% |
| 🪟 Windows | 27 | 26.7% |
| ❓ Unbekannt | 14 | 13.9% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 79 | 78.2% |
| Drive-By / Exploit-Kit | 12 | 11.9% |
| USB / Wechselmedium | 6 | 5.9% |
| MaaS-Loader | 2 | 2.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 35 | 34.7% |
| 2 | 🇺🇸 US | 22 | 21.8% |
| 3 | 🇳🇱 NL | 15 | 14.9% |
| 4 | 🇸🇪 SE | 15 | 14.9% |
| 5 | 🇭🇺 HU | 3 | 3.0% |
| 6 | 🇨🇦 CA | 2 | 2.0% |
| 7 | 🇫🇷 FR | 2 | 2.0% |
| 8 | 🇧🇷 BR | 1 | 1.0% |
| 9 | 🇪🇸 ES | 1 | 1.0% |
| 10 | 🌐 AL | 1 | 1.0% |
| 11 | 🇮🇳 IN | 1 | 1.0% |
| 12 | 🇦🇹 AT | 1 | 1.0% |
| 13 | 🌐 PT | 1 | 1.0% |
| 14 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 57 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 47 |
| Lateral Movement | 47 |
| Collection | 8 |
| Command and Control | 7 |
| Execution | 2 |
| Credential Access | 2 |
| Defense Evasion | 1 |

<details><summary>1891b91cbe0765779470… – AsyncRAT | 🔴 KRITISCH 89.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>
<details><summary>382e2bd0a1b1bf18cdf9… – Formbook | 🔴 KRITISCH 88.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [d2c93c1ed22c92edb690…](https://bazaar.abuse.ch/sample/d2c93c1ed22c92edb690727e92fff3fc797b34ebfeabcc02cb9c9a974053121e/)

- **Familie:** C!ml
- **Erkannt von:** 3 von 75 Engines (4.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan:Script/Wacatac.C!ml
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (3/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Flooder` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |

### [9b023827a3ac225c5672…](https://bazaar.abuse.ch/sample/9b023827a3ac225c5672cce1871a2ac1ddd58cbd37dc9c3933d13f8f0a61356a/)

- **Familie:** Riskware ( 00584baa1 )
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Riskware ( 00584baa1 )
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| Antiy-AVL | `Trojan[Miner]/Win64.CoinMiner` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W32/PossibleThreat` |
| Google | `Detected` |
| K7AntiVirus | `Riskware ( 00584baa1 )` |
| K7GW | `Riskware ( 00584baa1 )` |
| Lionic | `Trojan.Win32.Gen.tqzj` |
| Malwarebytes | `Malware.AI.248324237` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `ti!9B023827A3AC` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Scrami!8.105F3 (CLOUD)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `BehavesLike.Win64.Infected.tz` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| TrellixENS | `Artemis!A37251326727` |
| Varist | `W64/Kryptik.FDL.gen!Eldorado` |
| alibabacloud | `Trojan:Win/Phonzy.B9nj` |
| tehtris | `Generic.Malware` |

### [72d7233bae65dece9961…](https://bazaar.abuse.ch/sample/72d7233bae65dece99617142036ac7830f89190cb53c4c779fed8c00e7a7b3c0/)

- **Familie:** RemcosRAT
- **Erkannt von:** 15 von 75 Engines (20.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Script:SNH-gen [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (15/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Script:SNH-gen [Trj]` |
| Avast | `Script:SNH-gen [Trj]` |
| Avira | `TR/SNH` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `PowerShell/CloudEye.OX trojan` |
| F-Secure | `Trojan.TR/SNH` |
| GData | `Script.Trojan.Agent.EEH4W8` |
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `HEUR:Trojan.VBS.SAgent.gen` |
| Lionic | `Trojan.Script.RemcosRAT.4!c` |
| McAfeeD | `Trojan:Script/Remcos.JT` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Trojan.SAgent/VBS!9.884C0 (XSE:WFNFX1ZCUzqun3bnJ7TzLw5iX251FT4i)` |
| Symantec | `Scr.Guloader!gen11` |

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

- **elf** (49×)
- **Mirai** (47×)
- **Torii** (32×)
- **exe** (17×)
- **cowrie** (11×)
- **honeypot** (11×)
- **js** (11×)
- **vbs** (7×)
- **XWorm** (6×)
- **RemcosRAT** (6×)
- **SalatStealer** (6×)
- **upx** (5×)
- **arm** (4×)
- **upx-dec** (4×)
- **AgentTesla** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +15 (32→47)
- ↓ **unbekannt** -9 (24→15)
- ↓ **SalatStealer** -9 (16→7)
- neu: **XWorm** (6)
- neu: **RemcosRAT** (5)
- neu: **AgentTesla** (3)
- ↑ **SilentNet** +1 (1→2)
- ↑ **Formbook** +1 (1→2)
- neu: **ConnectWise** (2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +25 (22→47)
- ↓ **unbekannt** -13 (28→15)
- ↓ **SalatStealer** -3 (10→7)
- ↑ **XWorm** +5 (1→6)
- ↑ **RemcosRAT** +4 (1→5)
- neu: **AgentTesla** (3)
- ↑ **SilentNet** +1 (1→2)
- ↑ **Formbook** +1 (1→2)
- ↑ **ConnectWise** +1 (1→2)
- neu: **AsyncRAT** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.924 MB |
| σ Dateigröße | 11.302 MB |
| Ø Risiko-Score | 71.6/100 |
| Ø Klassifikations-Konfidenz | 78.2% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 57/101 |
| Eindeutige Familien | 21 |
| Eindeutige Tags | 57 |
| Unbekannte Familien | 2 (2.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 16:15 | [aa22704f4a17…](https://bazaar.abuse.ch/sample/aa22704f4a172e7082064d48d51672d3c8a16cbc8cf952a424493d71c3b6e731/) | `exe` | unbekannt | 38.9 | – | – | 🇳🇱NL |
| 15:57 | [1891b91cbe07…](https://bazaar.abuse.ch/sample/1891b91cbe07657794700e6c8eab5ef7a4c64ed0fb8ab1e1f14fdef66c074386/) | `exe` | AsyncRAT | 89.3 | – | – | 🌐CA |
| 15:43 | [f37cb4c615c0…](https://bazaar.abuse.ch/sample/f37cb4c615c04fb93f744387827c47accc659cf06a6471af35135e2a55dfe71b/) | `elf` | Mirai | 83.9 | – | – | 🇩🇪DE |
| 15:41 | [78625ed6397b…](https://bazaar.abuse.ch/sample/78625ed6397b0cbfccde8e5701022ec6692880168b8dfb7a0fe388d3f13158f1/) | `exe` | AgentTesla | 38.4 | – | – | 🇩🇪DE |
| 15:35 | [76ea3c8e5233…](https://bazaar.abuse.ch/sample/76ea3c8e523393464c9adb7ddeea8baa1469433a31556a4fdca705ca6197d66f/) | `elf` | Mirai | 83.7 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 28.10.2026 16:29 UTC*