# MalwareBazaar – 25.11.2026 21:19 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `c7937a0589cfc76c51ef…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **78** |
| Höchster Score | **87.8/100** – b7cbf0a8cd4afc3d… |
| Häufigste Familie | **unbekannt** (38x) |
| Häufigster Typ | **elf** (41x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 20 Samples |
| Ø Dateigröße | 5.43 MB (σ=16.22) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 41 | 40.6%  ████████ |
| `exe` | 22 | 21.8%  ████ |
| `js` | 16 | 15.8%  ███ |
| `macho` | 10 | 9.9%  █ |
| `hta` | 4 | 4.0%   |
| `jar` | 3 | 3.0%   |
| `vbe` | 2 | 2.0%   |
| `ps1` | 2 | 2.0%   |
| `xls` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 38 | 37.6% |
| 2 | EasyShell | 14 | 13.9% |
| 3 | RemcosRAT | 8 | 7.9% |
| 4 | WARDENStealer | 7 | 6.9% |
| 5 | Prometei | 7 | 6.9% |
| 6 | Mirai | 4 | 4.0% |
| 7 | Formbook | 3 | 3.0% |
| 8 | AsyncRAT | 3 | 3.0% |
| 9 | SilentNet | 3 | 3.0% |
| 10 | ConnectWise | 2 | 2.0% |
| 11 | LxBaseRAT | 2 | 2.0% |
| 12 | XWorm | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 56 | 55.4% | 80% |
| Infostealer | 17 | 16.8% | 79% |
| Linux-Malware | 7 | 6.9% | 45% |
| Windows-Malware | 6 | 5.9% | 35% |
| Botnet/IoT | 4 | 4.0% | 95% |
| Skript/Dropper | 4 | 4.0% | 35% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Loader | 2 | 2.0% | 85% |
| Trojaner | 2 | 2.0% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 78 | 77.2% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 17 | 16.8% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [b7cbf0a8cd4afc…](https://bazaar.abuse.ch/sample/b7cbf0a8cd4afc3dd6b680bc686c4589a45b6bb09eefa1a6306f3db4666f6774/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [52196ca51b09b5…](https://bazaar.abuse.ch/sample/52196ca51b09b58586f1a9622a10aa0300ea8caa5bc76f807333089d92448c44/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [4223eab13cb284…](https://bazaar.abuse.ch/sample/4223eab13cb28482e4b1971989478384bea2a4ad23554cf97946b52da8986076/) | Formbook | Infostealer | **87.8** | 🔴 KRITISCH | – | – | ? |
| [0aa6ce489af254…](https://bazaar.abuse.ch/sample/0aa6ce489af25425df679df31af8c71a73ee193826266daa4ec68be704c0c094/) | RemcosRAT | RAT | **86.8** | 🔴 KRITISCH | – | – | ? |
| [b7bf2c19ab51c3…](https://bazaar.abuse.ch/sample/b7bf2c19ab51c3e58dd9b3ef6b6b8a4f6caf717da2e31058cd22a2cc244f2759/) | RemcosRAT | RAT | **86.8** | 🔴 KRITISCH | – | – | ? |
| [63a125deb59b55…](https://bazaar.abuse.ch/sample/63a125deb59b558080f341eb32dddd170be7a46fa1291605da46a82d8c873fef/) | RemcosRAT | RAT | **86.8** | 🔴 KRITISCH | – | – | ? |
| [e2503de67b0e0c…](https://bazaar.abuse.ch/sample/e2503de67b0e0c6dbf5faef23d3650c8edaa0619917c1e435832eae1a374f76f/) | XWorm | RAT | **86.8** | 🔴 KRITISCH | – | – | ? |
| [1e0aca7d6ffce5…](https://bazaar.abuse.ch/sample/1e0aca7d6ffce5747c8bf89c373e824888f763f50bf2e7c0649e03a5ed612017/) | AsyncRAT | RAT | **86.8** | 🔴 KRITISCH | – | – | ? |
| [2df781f31d86ca…](https://bazaar.abuse.ch/sample/2df781f31d86caef2a879fd906ad579a337a75e97f107e31ea8d6e752fd07715/) | AsyncRAT | RAT | **86.8** | 🔴 KRITISCH | – | – | ? |
| [d3a5fae7dfcbf1…](https://bazaar.abuse.ch/sample/d3a5fae7dfcbf14ed6d046140742ee014a26388f1f5bac511cd05b26bbe59b22/) | XWorm | RAT | **86.8** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6607/8138 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6607/8138 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.5% | 6305/8138 |
| 6 | Kaspersky | 75.6% | 6151/8137 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5797/8134 |
| 9 | Rising | 68.6% | 5585/8138 |
| 10 | Varist | 66.1% | 5375/8133 |
| 11 | Tencent | 65.2% | 5162/7912 |
| 12 | Avast | 65.2% | 5303/8134 |
| 13 | AVG | 65.2% | 5303/8133 |
| 14 | McAfeeD | 61.4% | 4991/8130 |
| 15 | huorong | 61.0% | 4959/8130 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 51 | 50.5% |
| 🪟 Windows | 28 | 27.7% |
| ❓ Unbekannt | 21 | 20.8% |
| 📄 Dokument | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 82 | 81.2% |
| Drive-By / Exploit-Kit | 16 | 15.8% |
| MaaS-Loader | 1 | 1.0% |
| C2 / Nachladen | 1 | 1.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 44 | 43.6% |
| 2 | 🇫🇷 FR | 32 | 31.7% |
| 3 | 🇩🇪 DE | 13 | 12.9% |
| 4 | 🌐 AL | 3 | 3.0% |
| 5 | 🇳🇱 NL | 2 | 2.0% |
| 6 | 🇸🇬 SG | 2 | 2.0% |
| 7 | 🇨🇭 CH | 2 | 2.0% |
| 8 | 🇸🇪 SE | 1 | 1.0% |
| 9 | 🇪🇸 ES | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 20 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 12 |
| Command and Control | 11 |
| Initial Access | 4 |
| Lateral Movement | 4 |
| Credential Access | 4 |
| Execution | 4 |
| Exfiltration | 1 |
| Defense Evasion | 1 |

<details><summary>b7cbf0a8cd4afc3dd6b6… – Formbook | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>52196ca51b09b58586f1… – Formbook | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>4223eab13cb28482e4b1… – Formbook | 🔴 KRITISCH 87.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>0aa6ce489af25425df67… – RemcosRAT | 🔴 KRITISCH 86.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>b7bf2c19ab51c3e58dd9… – RemcosRAT | 🔴 KRITISCH 86.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [96b8ce1d634936df3227…](https://bazaar.abuse.ch/sample/96b8ce1d634936df3227d399412d5c2cb8472a8bce6cc277c69ba5dbd4b21c0e/)

- **Familie:** SalatStealer
- **Erkannt von:** 44 von 74 Engines (59.5%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.82017341
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.82017341`

**Erkennende Engines (44/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.82017341` |
| AVG | `FileRepMalware [Misc]` |
| Alibaba | `TrojanPSW:Python/Coins.0571437d` |
| Arcabit | `Trojan.Generic.D4E37C3D` |
| Avast | `FileRepMalware [Misc]` |
| BitDefender 🛡️ | `Trojan.GenericKD.82017341` |
| Bkav | `W32.Malware.AD4F78BA` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Siggen36.62206` |
| ESET-NOD32 | `Python/TrojanDropper.Agent.TP trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Trojan.GenericKD.82017341 (B)` |
| Fortinet | `W32/Agent.TP!tr` |
| GData | `Trojan.GenericKD.82017341` |
| Google | `Detected` |
| Gridinsoft | `Trojan.Heur!.00012433` |
| Ikarus | `Trojan-Dropper.Python.Agent` |
| K7AntiVirus | `Trojan ( 006e1b941 )` |
| K7GW | `Trojan ( 006e1b941 )` |
| Kaspersky | `Trojan-PSW.Win64.Coins.kzs` |
| Lionic | `Trojan.Win32.Xkcp.tt7V` |
| Malwarebytes | `Malware.AI.4036224740` |
| MaxSecure | `Trojan.Malware.730231862.susgen` |
| McAfeeD | `ti!96B8CE1D6349` |
| MicroWorld-eScan | `Trojan.GenericKD.82017341` |
| Microsoft 🛡️ | `Trojan:Win32/Egairtigado!rfn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxGD.A` |
| Rising | `Trojan.Agent/PYC!1.14354 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| TACHYON | `Trojan-PWS/W64.Coins.14331752` |
| Tencent | `Malware.Win32.Gencirc.14baf618` |
| TrellixENS | `Artemis!2B4214613970` |
| TrendMicro | `Trojan.Win32.COINS.USBLK126` |
| TrendMicro-HouseCall | `Trojan.Win32.COINS.USBLK126` |
| VBA32 | `TrojanPSW.Win64.GenericStealer` |
| VIPRE | `Trojan.GenericKD.82017341` |
| Varist | `W64/ABTrojan.TDOF-2464` |
| alibabacloud | `Trojan[dropper]:Python/Agent.TX` |
| huorong | `Trojan/Python.Starter.c` |

### [7fd9e3b10b60c1362e23…](https://bazaar.abuse.ch/sample/7fd9e3b10b60c1362e23c2ee37986a880ae397b64705a2dbf2ae39c23d84020c/)

- **Familie:** EasyShell
- **Erkannt von:** 5 von 74 Engines (6.8%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTN trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BTN trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Trojan.Agent/Linux!8.13268 (TFE:14:3KiNDdNqclO)` |
| Tencent | `Malware.Linux.Generic.1c0cccc5` |

### [dc316b573b096ec3972c…](https://bazaar.abuse.ch/sample/dc316b573b096ec3972c6741079d886a47f22aa057b4fa457ceb3e4268efd5d4/)

- **Familie:** ConnectWise
- **Erkannt von:** 5 von 73 Engines (6.9%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** malicious (high confidence)
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/73):**

| Engine | Erkannter Name |
|--------|----------------|
| DrWeb | `BackDoor.RA.364` |
| ESET-NOD32 | `MSIL/TrojanDropper.Agent.GWJ trojan` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `not-a-virus:HEUR:RemoteAdmin.Win32.ConnectWise.gen` |
| VBA32 | `Riskware.MSIL.ScreenConnect.Heur` |

### [5fa5f227e5dc11e8adc6…](https://bazaar.abuse.ch/sample/5fa5f227e5dc11e8adc67f507851f1922606f7a2c07c8677b3e5308fa31f4803/)

- **Familie:** EasyShell
- **Erkannt von:** 5 von 74 Engines (6.8%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTN trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BTN trojan` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Trojan.Agent/Linux!8.13268 (TFE:14:3KiNDdNqclO)` |
| Tencent | `Malware.Linux.Generic.1c0cccc5` |

### [c7937a0589cfc76c51ef…](https://bazaar.abuse.ch/sample/c7937a0589cfc76c51ef46b2f4e5b5d7e3da42bf01740baebe5e3d45c8cb0b88/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** ConnectWise
- **Erkannt von:** 29 von 74 Engines (39.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Unwanted-Program ( 005c6d501 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan:Win32/Suschil!rfn`

**Erkennende Engines (29/74):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `RiskWare[RemoteAdmin]/MSIL.ConnectWise` |
| Bkav | `W32.Malware.CE6D6E6` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win32/RemoteAdmin.ConnectWiseControl.E potentially unsafe application` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W32/PossibleThreat` |
| GData | `Win32.Trojan.Agent.TQDT4J` |
| Google | `Detected` |
| Ikarus | `PUA.MSIL.ConnectWise` |
| K7AntiVirus | `Unwanted-Program ( 005c6d501 )` |
| K7GW | `Unwanted-Program ( 005c6d501 )` |
| Kingsoft | `Win32.HACKTOOL.RemoteAdmin.v` |
| Lionic | `Trojan.Win32.ConnectWise.4!c` |
| Malwarebytes | `RiskWare.ConnectWise.Abused` |
| Microsoft 🛡️ | `Trojan:Win32/Suschil!rfn` |
| NANO-Antivirus | `Trojan.Win32.Drop.llafhv` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Generic!8.C3 (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Agent.16004532` |
| TrendMicro-HouseCall | `TROJ_GEN.R002H06K926` |
| VBA32 | `BScope.Riskware.ConnectWise` |
| Varist | `W32/ConnectWise.B.gen!Eldorado` |
| VirIT | `Trojan.Win32.GenusC.IHR` |
| Zillya | `Tool.Convagent.Win32.869` |
| huorong | `HackTool/ConnectWiseControl.i` |


## Top Tags

- **RAT** (47×)
- **elf** (41×)
- **EasyShell** (40×)
- **Rust** (40×)
- **SnoopyTriage** (40×)
- **exe** (21×)
- **js** (16×)
- **macho** (10×)
- **WARDENStealer** (9×)
- **RemcosRAT** (8×)
- **stealer** (7×)
- **Prometei** (7×)
- **Warden** (6×)
- **upx-dec** (4×)
- **upx** (4×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +5 (33→38)
- ↑ **EasyShell** +11 (3→14)
- neu: **RemcosRAT** (8)
- neu: **WARDENStealer** (7)
- ↑ **Prometei** +3 (4→7)
- ↓ **Mirai** -7 (11→4)
- neu: **Formbook** (3)
- ↑ **AsyncRAT** +1 (2→3)
- neu: **SilentNet** (3)
- ↓ **ConnectWise** -1 (3→2)
- weg: **Snowlight** (war 10)
- weg: **Vidar** (war 2)
- weg: **FunStealer** (war 28)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +1 (37→38)
- ↑ **EasyShell** +10 (4→14)
- ↑ **RemcosRAT** +7 (1→8)
- ↑ **WARDENStealer** +3 (4→7)
- ↑ **Prometei** +2 (5→7)
- ↓ **Mirai** -24 (28→4)
- neu: **Formbook** (3)
- ↑ **AsyncRAT** +2 (1→3)
- neu: **SilentNet** (3)
- ↑ **ConnectWise** +1 (1→2)
- weg: **njrat** (war 2)
- weg: **Snowlight** (war 4)
- weg: **FunStealer** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.425 MB |
| σ Dateigröße | 16.218 MB |
| Ø Risiko-Score | 72.3/100 |
| Ø Klassifikations-Konfidenz | 71.3% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 20/101 |
| Eindeutige Familien | 18 |
| Eindeutige Tags | 50 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 21:15 | [29ad0e1d12e1…](https://bazaar.abuse.ch/sample/29ad0e1d12e1d27b89633e2688b9dc3706c852e3771e9178b6ca99aaaafb0048/) | `exe` | unbekannt | 39.1 | – | – | 🌐SE |
| 21:13 | [26bd8437fd0c…](https://bazaar.abuse.ch/sample/26bd8437fd0ce29d9abfb300c1dbacdef3ad831901899f3fc429b297b54bd119/) | `exe` | unbekannt | 39.0 | – | – | 🇳🇱NL |
| 21:12 | [0ac0877cc0d4…](https://bazaar.abuse.ch/sample/0ac0877cc0d4139f75f5e849b35bbffbab171c36def89bcce12f4e165c6265cf/) | `exe` | unbekannt | 82.1 | – | – | 🇺🇸US |
| 21:12 | [1ba93f8448f0…](https://bazaar.abuse.ch/sample/1ba93f8448f09a60e684ab9eacefc0aa46f7caee87bfd72fedd17f995d3fad32/) | `exe` | unbekannt | 82.1 | – | – | 🇺🇸US |
| 21:05 | [7156a42c9bb0…](https://bazaar.abuse.ch/sample/7156a42c9bb0bb941b5963bdb2160e9ed0f5d6b632632ed745f3840408e9792b/) | `elf` | unbekannt | 81.1 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 25.11.2026 21:19 UTC*