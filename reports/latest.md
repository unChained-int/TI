# MalwareBazaar – 02.11.2026 01:21 UTC

Dieser Run hat **38 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **39** |
| Kritisch (≥75) | **12** |
| Höchster Score | **87.0/100** – f3b9bca4c11c0156… |
| Häufigste Familie | **unbekannt** (25x) |
| Häufigster Typ | **exe** (14x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 5 Samples |
| Ø Dateigröße | 2.62 MB (σ=3.23) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 14 | 35.9%  ███████ |
| `macho` | 12 | 30.8%  ██████ |
| `elf` | 9 | 23.1%  ████ |
| `sh` | 3 | 7.7%  █ |
| `hta` | 1 | 2.6%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 25 | 64.1% |
| 2 | SalatStealer | 7 | 17.9% |
| 3 | Mirai | 4 | 10.3% |
| 4 | AveMariaRAT | 1 | 2.6% |
| 5 | Detected | 1 | 2.6% |
| 6 | Yogi | 1 | 2.6% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Loader | 12 | 30.8% | 75% |
| Infostealer | 10 | 25.6% | 74% |
| Botnet/IoT | 4 | 10.3% | 95% |
| Linux-Malware | 4 | 10.3% | 45% |
| Windows-Malware | 3 | 7.7% | 35% |
| Andere / Unbekannt | 3 | 7.7% | 20% |
| RAT | 1 | 2.6% | 75% |
| Skript/Dropper | 1 | 2.6% | 35% |
| Cryptominer | 1 | 2.6% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 12 | 30.8% |
| 🟠 HOCH | 16 | 41.0% |
| 🟡 MITTEL | 8 | 20.5% |
| 🟢 NIEDRIG | 3 | 7.7% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f3b9bca4c11c01…](https://bazaar.abuse.ch/sample/f3b9bca4c11c01561c52db79c81456a70d205a9e333bb27de4a35ad511f2c471/) | Mirai | Botnet/IoT | **87.0** | 🔴 KRITISCH | 2.7% | ⚠️ KAUM ERKANNT | ✗ |
| [68e2d57df80768…](https://bazaar.abuse.ch/sample/68e2d57df807683c12accac30940ead9be2b7589e33f8cf20abbdc324f09b112/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [254240df904dc2…](https://bazaar.abuse.ch/sample/254240df904dc29fe2e71e93a1d63c60bbe6dfd67bf3b3bc57f981e86a8dc211/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [e5488094c4e143…](https://bazaar.abuse.ch/sample/e5488094c4e1433ada92e3a89585b23082cdaabcf777064bc6cfd2e277cfc725/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [54e791eba46a66…](https://bazaar.abuse.ch/sample/54e791eba46a6655cdc58b8dc7813d27d5fcf94a1bc10468e0334f6cb7f3d32f/) | unbekannt | Infostealer | **81.5** | 🔴 KRITISCH | – | – | ? |
| [0540d635edb31e…](https://bazaar.abuse.ch/sample/0540d635edb31efd4ea4b026f1aa526ae991fc4cd214ba91930ce04a5be280f8/) | SalatStealer | Infostealer | **81.4** | 🔴 KRITISCH | – | – | ? |
| [4afc0af2fe1a66…](https://bazaar.abuse.ch/sample/4afc0af2fe1a66a740b72a9ab743df63e2b5c2746717c1e7b29828929bf83064/) | SalatStealer | Infostealer | **81.4** | 🔴 KRITISCH | – | – | ? |
| [a7076f32e0c79a…](https://bazaar.abuse.ch/sample/a7076f32e0c79a9574f70102a5baba65894fb9e01504b28cbf657ebeb6ebc081/) | SalatStealer | Infostealer | **81.4** | 🔴 KRITISCH | – | – | ? |
| [0be112428e866e…](https://bazaar.abuse.ch/sample/0be112428e866e9aec6b54629a4e07dc21773764f4dadf33bb81fae0077a4194/) | SalatStealer | Infostealer | **81.4** | 🔴 KRITISCH | – | – | ? |
| [cd1ce568547d88…](https://bazaar.abuse.ch/sample/cd1ce568547d88162740ae66190335a2ee53ae0bf69ac6a011ad58b8c703dfe3/) | SalatStealer | Infostealer | **81.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6305/7779 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6305/7779 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.2% | 6009/7779 |
| 6 | Kaspersky | 75.5% | 5871/7778 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5536/7775 |
| 9 | Rising | 68.3% | 5310/7779 |
| 10 | Varist | 66.1% | 5142/7774 |
| 11 | AVG | 65.2% | 5065/7774 |
| 12 | Avast | 65.1% | 5065/7775 |
| 13 | Tencent | 64.9% | 4901/7553 |
| 14 | McAfeeD | 61.3% | 4767/7771 |
| 15 | huorong | 60.9% | 4730/7771 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 15 | 38.5% |
| 🍎 macOS | 12 | 30.8% |
| 🐧 Linux | 12 | 30.8% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 27 | 69.2% |
| MaaS-Loader | 12 | 30.8% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 22 | 56.4% |
| 2 | 🇳🇱 NL | 12 | 30.8% |
| 3 | 🇫🇷 FR | 3 | 7.7% |
| 4 | 🇩🇪 DE | 1 | 2.6% |
| 5 | 🌐 Unbekannt | 1 | 2.6% |

## MITRE ATT&CK

> 5 von 39 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 4 |
| Lateral Movement | 4 |
| Credential Access | 1 |
| Collection | 1 |
| Exfiltration | 1 |

<details><summary>f3b9bca4c11c01561c52… – Mirai | 🔴 KRITISCH 87.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>68e2d57df807683c12ac… – Mirai | 🔴 KRITISCH 83.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>254240df904dc29fe2e7… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>e5488094c4e1433ada92… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>54e791eba46a6655cdc5… – unbekannt | 🔴 KRITISCH 81.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [15169c97b1503d59aa97…](https://bazaar.abuse.ch/sample/15169c97b1503d59aa974bad5583e2a0c1fe96a9f00987f9742f18eec7b7d2f0/)

- **Familie:** SalatStealer
- **Erkannt von:** 51 von 75 Engines (68.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (51/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.LummaStealer.103` |
| AVG | `Win32:SalatStealer-A [Pws]` |
| AhnLab-V3 | `Trojan/Win.Generic.R727379` |
| Alibaba | `TrojanPSW:Win32/SalatStealer.eb1c1e6d` |
| Arcabit | `Trojan.LummaStealer.103` |
| Avast | `Win32:SalatStealer-A [Pws]` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.LummaStealer.103` |
| Bkav | `W32.Malware.887D997E` |
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
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Spyware ( 006d58511 )` |
| K7GW | `Spyware ( 006d58511 )` |
| Kaspersky | `HEUR:Trojan-PSW.Win32.Convagent.gen` |
| Malwarebytes | `Spyware.SalatStealer` |
| McAfeeD | `Trojan:Win/SalatStealer.AA` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| Paloalto | `generic.ml` |
| Panda | `Trj/CI.A` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| Sangfor | `Infostealer.Win32.Salatstealer.Vryq` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!624133B8C129` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Banker/W32.Agent.12572672.B` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!624133B8C129` |
| TrendMicro | `TrojanSpy.Win32.SALATSTEALER.YXGJ3Z` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.JMY` |
| ZoneAlarm | `Troj/Salat-A` |
| alibabacloud | `Trojan:Multi/Rozena.SS` |
| huorong | `Trojan/Agent.e!crit` |

### [f3b9bca4c11c01561c52…](https://bazaar.abuse.ch/sample/f3b9bca4c11c01561c52db79c81456a70d205a9e333bb27de4a35ad511f2c471/)

- **Familie:** Mirai
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux.DownLoader.2445
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Antiy-AVL | `Trojan[Miner]/JS.CoinMiner.xmr` |
| DrWeb | `Linux.DownLoader.2445` |

### [26a9c39f6e19e24a3690…](https://bazaar.abuse.ch/sample/26a9c39f6e19e24a3690aa99d5be2515939d1f292976eb316b7690426f3b4faa/)

- **Familie:** Detected
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Detected
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Varist | `E64/Coinminer.FW` |

### [d729ca1e148048aa9d42…](https://bazaar.abuse.ch/sample/d729ca1e148048aa9d42574d0cbd3486407e2746eab45583167336105637bc53/)

- **Familie:** Yogi
- **Erkannt von:** 35 von 75 Engines (46.7%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.85599
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.85599`

**Erkennende Engines (35/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.85599` |
| AVG | `MalwareX-gen [Misc]` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R797565` |
| Alibaba | `Trojan:Win64/ShellcodeRunner.8a559d94` |
| Arcabit | `Trojan.Yogi.D14E5F` |
| Avast | `MalwareX-gen [Misc]` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.85599` |
| Bkav | `W32.Malware.CFA1F3E0` |
| CTX | `dll.unknown.yogi` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/ShellcodeRunner.CQR trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.85599 (B)` |
| GData | `Gen:Variant.Yogi.85599` |
| Ikarus | `Win32.Outbreak` |
| K7AntiVirus | `Trojan ( 006d9bf01 )` |
| K7GW | `Trojan ( 006d9bf01 )` |
| Kaspersky | `UDS:Trojan.Win32.Agent` |
| Lionic | `Trojan.Win32.ShellcodeRunner.4!c` |
| McAfeeD | `ti!D729CA1E1480` |
| MicroWorld-eScan | `Gen:Variant.Yogi.85599` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Malware.Undefined!8.C (TFE:6:C9WtrIs9t1G)` |
| Sangfor | `Trojan.Win32.Shellcoderunner.Vsqp` |
| Skyhigh | `BehavesLike.Win64.Infected.dm` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Win64.Trojan.Shellcoderunner.Ximw` |
| TrellixENS | `Artemis!8354F8785379` |
| TrendMicro-HouseCall | `TROJ_GEN.R014H09K126` |
| VIPRE | `Gen:Variant.Yogi.85599` |
| alibabacloud | `Trojan:Win/ShellcodeRunner.CRY` |
| huorong | `Trojan/W64.ShellLoader.ea!crit` |

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

- **exe** (13×)
- **ClickFix** (12×)
- **Foxveil** (12×)
- **loader** (12×)
- **Mach-O** (12×)
- **macho** (12×)
- **macOS** (12×)
- **upx-dec** (6×)
- **elf** (6×)
- **upx** (6×)
- **SalatStealer** (5×)
- **Torii** (2×)
- **Mirai** (2×)
- **stealer** (2×)
- **signed** (1×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -17 (42→25)
- ↑ **SalatStealer** +3 (4→7)
- ↓ **Mirai** -21 (25→4)
- neu: **AveMariaRAT** (1)
- neu: **Detected** (1)
- neu: **Yogi** (1)
- weg: **SilentNet** (war 7)
- weg: **LegionLoader** (war 6)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -2 (27→25)
- ↓ **SalatStealer** -9 (16→7)
- ↓ **Mirai** -21 (25→4)
- neu: **AveMariaRAT** (1)
- neu: **Detected** (1)
- neu: **Yogi** (1)
- weg: **RemcosRAT** (war 2)
- weg: **Formbook** (war 2)
- weg: **SilentNet** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.617 MB |
| σ Dateigröße | 3.228 MB |
| Ø Risiko-Score | 65.8/100 |
| Ø Klassifikations-Konfidenz | 65.1% |
| Samples mit VT | 5/39 |
| Samples mit MITRE | 5/39 |
| Eindeutige Familien | 6 |
| Eindeutige Tags | 30 |
| Unbekannte Familien | 3 (7.7%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 00:54 | [0550a6acf888…](https://bazaar.abuse.ch/sample/0550a6acf8888eb660a8e7304ac6a789c3f2dc0ea51b25bec438655d03bc9628/) | `exe` | unbekannt | 38.7 | – | – | 🇺🇸US |
| 00:35 | [64fb0d531b51…](https://bazaar.abuse.ch/sample/64fb0d531b51a70cd4a40d4b2ece6c98d7a3d453c5d5b148f4cae75208584677/) | `macho` | unbekannt | 74.4 | – | – | 🇺🇸US |
| 00:33 | [b01d5a9d05b7…](https://bazaar.abuse.ch/sample/b01d5a9d05b788cdbff787e3317e207caec6b6e08979a1efe0f7764cbfdd86dc/) | `macho` | unbekannt | 74.4 | – | – | 🇺🇸US |
| 00:32 | [5c18af8d98e6…](https://bazaar.abuse.ch/sample/5c18af8d98e6b13dbf5b8b408d817a302a5239311fff0da0319e11c9d5ce76cb/) | `macho` | unbekannt | 74.4 | – | – | 🇺🇸US |
| 00:32 | [54e791eba46a…](https://bazaar.abuse.ch/sample/54e791eba46a6655cdc58b8dc7813d27d5fcf94a1bc10468e0334f6cb7f3d32f/) | `exe` | unbekannt | 81.5 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 02.11.2026 01:21 UTC*