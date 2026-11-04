# MalwareBazaar – 04.11.2026 08:46 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **41** |
| Höchster Score | **90.5/100** – eb175a973d117fb3… |
| Häufigste Familie | **unbekannt** (47x) |
| Häufigster Typ | **exe** (41x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 31 Samples |
| Ø Dateigröße | 2.49 MB (σ=6.17) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 41 | 40.6%  ████████ |
| `elf` | 19 | 18.8%  ███ |
| `js` | 17 | 16.8%  ███ |
| `msi` | 15 | 14.9%  ██ |
| `vbs` | 2 | 2.0%   |
| `bat` | 2 | 2.0%   |
| `zsh` | 1 | 1.0%   |
| `ps1` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 47 | 46.5% |
| 2 | Mirai | 15 | 14.9% |
| 3 | Formbook | 7 | 6.9% |
| 4 | NanoCore | 3 | 3.0% |
| 5 | AsyncRAT | 3 | 3.0% |
| 6 | AgentTesla | 3 | 3.0% |
| 7 | RemcosRAT | 3 | 3.0% |
| 8 | VShell | 3 | 3.0% |
| 9 | SnakeKeylogger | 2 | 2.0% |
| 10 | ConnectWise | 2 | 2.0% |
| 11 | njrat | 2 | 2.0% |
| 12 | XorDDoS | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 31 | 30.7% | 35% |
| Skript/Dropper | 18 | 17.8% | 35% |
| Botnet/IoT | 17 | 16.8% | 93% |
| RAT | 14 | 13.9% | 94% |
| Infostealer | 12 | 11.9% | 93% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Trojaner | 2 | 2.0% | 65% |
| Linux-Malware | 2 | 2.0% | 45% |
| Loader | 1 | 1.0% | 75% |
| Worm | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 41 | 40.6% |
| 🟠 HOCH | 6 | 5.9% |
| 🟡 MITTEL | 51 | 50.5% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [eb175a973d117f…](https://bazaar.abuse.ch/sample/eb175a973d117fb34df1c23fa46587c01f68bb014ea192790021be47730661b8/) | Formbook | Infostealer | **90.5** | 🔴 KRITISCH | – | – | ? |
| [a9894038b6d13c…](https://bazaar.abuse.ch/sample/a9894038b6d13c7a1652cff094430c50b1ce80c605497d5df0243eebfcb5ae76/) | Formbook | Infostealer | **90.5** | 🔴 KRITISCH | – | – | ? |
| [58ef254e7db2f4…](https://bazaar.abuse.ch/sample/58ef254e7db2f4009a0941e98d6327d80f4c44bf7bcddb6af77a42702e477396/) | SnakeKeylogger | Infostealer | **90.5** | 🔴 KRITISCH | – | – | ? |
| [2e90337407e97c…](https://bazaar.abuse.ch/sample/2e90337407e97c12f994d4d2a981a29516633c657f962ff94ba2c1f1ca22f4e4/) | Formbook | Infostealer | **89.7** | 🔴 KRITISCH | – | – | ? |
| [352cfb22ba4830…](https://bazaar.abuse.ch/sample/352cfb22ba4830b5c184041bf4457a21580e44bdfa66f615e003799c3a76fc97/) | NanoCore | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [3e66e6cd018119…](https://bazaar.abuse.ch/sample/3e66e6cd018119de4c9d8e384b9c2d6cb33ec899da2a10cb3fe6cbe4d6f6a713/) | AsyncRAT | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [3d2aab719bcda9…](https://bazaar.abuse.ch/sample/3d2aab719bcda98fef5a741571552117ca2b7d705ccb090c0afde2353b462ce3/) | XWorm | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [7ebbf1ced6ef05…](https://bazaar.abuse.ch/sample/7ebbf1ced6ef059e21b2504595bcc0a4671e1c713c975e21ee1d7d21441d62d0/) | AsyncRAT | RAT | **89.6** | 🔴 KRITISCH | – | – | ? |
| [4f03a59c124b15…](https://bazaar.abuse.ch/sample/4f03a59c124b154a10126dd253ad037bff96159c0a2827836e8bc0eb04b329de/) | Formbook | Infostealer | **89.4** | 🔴 KRITISCH | – | – | ? |
| [5815bb9cc42b73…](https://bazaar.abuse.ch/sample/5815bb9cc42b73d9a164cc85bd5565ffaaf759f1ed5acb4c1f4b4c505627a590/) | HawkEye | Infostealer | **89.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6331/7813 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6331/7813 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6038/7813 |
| 6 | Kaspersky | 75.5% | 5898/7812 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5561/7809 |
| 9 | Rising | 68.3% | 5335/7813 |
| 10 | Varist | 66.2% | 5168/7808 |
| 11 | Avast | 65.1% | 5083/7809 |
| 12 | AVG | 65.1% | 5083/7808 |
| 13 | Tencent | 64.9% | 4924/7587 |
| 14 | McAfeeD | 61.4% | 4789/7805 |
| 15 | huorong | 60.9% | 4751/7805 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 59 | 58.4% |
| 🐧 Linux | 24 | 23.8% |
| ❓ Unbekannt | 17 | 16.8% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 67 | 66.3% |
| Drive-By / Exploit-Kit | 17 | 16.8% |
| Trojanisierte Software | 15 | 14.9% |
| USB / Wechselmedium | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇦🇹 AT | 40 | 39.6% |
| 2 | 🇩🇪 DE | 20 | 19.8% |
| 3 | 🇫🇷 FR | 15 | 14.9% |
| 4 | 🇳🇱 NL | 11 | 10.9% |
| 5 | 🇮🇳 IN | 6 | 5.9% |
| 6 | 🇺🇸 US | 4 | 4.0% |
| 7 | 🇨🇭 CH | 2 | 2.0% |
| 8 | 🇭🇺 HU | 1 | 1.0% |
| 9 | 🌐 SK | 1 | 1.0% |
| 10 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 31 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 15 |
| Lateral Movement | 15 |
| Collection | 12 |
| Credential Access | 8 |
| Command and Control | 8 |
| Execution | 3 |
| Exfiltration | 1 |

<details><summary>eb175a973d117fb34df1… – Formbook | 🔴 KRITISCH 90.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>a9894038b6d13c7a1652… – Formbook | 🔴 KRITISCH 90.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>2e90337407e97c12f994… – Formbook | 🔴 KRITISCH 89.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [c6f212ac367f384d1add…](https://bazaar.abuse.ch/sample/c6f212ac367f384d1add9866e47b6b21e49c722601f5af5afa350544b62065c5/)

- **Familie:** Lazy
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Lazy.741233
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Lazy.741233`

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.87208` |
| AVG | `Win64:MalwareX-gen [Cryp]` |
| AhnLab-V3 | `Trojan/Win.Generic.R799590` |
| Arcabit | `Trojan.Lazy.DB4F71 [many]` |
| Avast | `Win64:MalwareX-gen [Cryp]` |
| Avira | `TR/W64.MalwareX` |
| BitDefender 🛡️ | `Gen:Variant.Lazy.741233` |
| CTX | `msi.unknown.yogi` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.Packed2.52091` |
| ESET-NOD32 | `Win64/GenKryptik.HVHT trojan` |
| Emsisoft | `Gen:Variant.Lazy.741233 (B)` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| Fortinet | `W64/GenKryptik.HVHT!tr` |
| GData | `Gen:Variant.Lazy.741233` |
| Google | `Detected` |
| Ikarus | `Trojan.Win64.Krypt` |
| Kaspersky | `VHO:Trojan.Win64.Injects.gen` |
| Rising | `Stealer.BroPass!8.13424 (TFE:2:ddhKcc6ceIH)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious MSI` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win64.Kryptik.16006318` |
| VIPRE | `Gen:Variant.Lazy.741233` |
| Varist | `W64/Agent.NLJ.gen!Eldorado` |
| VirIT | `Trojan.MSI.Agent.KGO` |

### [d3f328a85e44723ac781…](https://bazaar.abuse.ch/sample/d3f328a85e44723ac7816383c7d0daa4aed1a1d120c16c487beb1cd43e91224a/)

- **Familie:** Formbook
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** MalwareX-gen [Drp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `MalwareX-gen [Drp]` |
| Avast | `MalwareX-gen [Drp]` |
| Avira | `DR/W32.MalwareX` |
| Bkav | `W32.Malware.A0D8C665` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| ESET-NOD32 | `MSIL/Kryptik.UYA trojan` |
| Elastic | `malicious (high confidence)` |
| F-Secure | `Dropper.DR/W32.MalwareX` |
| Fortinet | `MSIL/Formbook.GZHA!tr` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan-PSW.MSIL.Agensla.gen` |
| Malwarebytes | `Trojan.MalPack.PNG.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Trojan:Win/GenericPack.BMP` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Malware.Obfus/MSIL@AI.93 (RDM.MSIL2:FaUS6CXXdPwiDkSW2TUKuA)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Suspicious PE` |
| Symantec | `MSIL.Packed.19` |
| Trapmine | `malicious.moderate.ml.score` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| Varist | `W32/MSIL_Kryptik.IUH.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |

### [d0c49323ffadf825f022…](https://bazaar.abuse.ch/sample/d0c49323ffadf825f022fd40f36772c7665d0f548a341d43347318e183fd42d6/)

- **Familie:** NanoCore
- **Erkannt von:** 62 von 75 Engines (82.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.NanoCore.5`

**Erkennende Engines (62/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AVG | `MSIL:NanoCore-B [Trj]` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avast | `MSIL:NanoCore-B [Trj]` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| BitDefender 🛡️ | `Trojan.NanoCore.5` |
| Bkav | `W32.Malware.29DFC31E` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!517D2813B2A6` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Panda | `Bck/Agent.KNM` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-FICC!517D2813B2A6` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-FICC!517D2813B2A6` |
| TrendMicro | `BKDR_NOANCOOE.SM` |
| TrendMicro-HouseCall | `BKDR_NOANCOOE.SM` |
| VBA32 | `Trojan.MSIL.NanoCore.Heur` |
| VIPRE | `Trojan.NanoCore.5` |
| Varist | `W32/NanoCore.C.gen!Eldorado` |
| ViRobot | `Backdoor.Win32.NanoCore.Gen.A` |
| VirIT | `Trojan.Win32.DownLoader12.BSON` |
| Xcitium | `Backdoor.MSIL.Noancooe.JDE@5s4u9t` |
| ZoneAlarm | `Troj/NanoCor-BT` |
| Zoner | `Trojan.Win32.48280` |
| alibabacloud | `Backdoor:MSIL/Vindor.Gen` |
| huorong | `Backdoor/MSIL.NanoCore.b` |

### [30a43e3a64b90e8853da…](https://bazaar.abuse.ch/sample/30a43e3a64b90e8853daaa61ca5c2a0e6b5f3e7126e47b3ab6d826243e9ca14b/)

- **Familie:** Malware
- **Erkannt von:** 6 von 75 Engines (8.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** W32.Malware.7D8D3E4A
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (6/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Bkav | `W32.Malware.7D8D3E4A` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cylance | `Unsafe` |
| Elastic | `malicious (high confidence)` |
| Sangfor | `Trojan.Win32.Save.a` |
| Symantec | `ML.Attribute.HighConfidence` |

### [09f7d2a30633ca2ea229…](https://bazaar.abuse.ch/sample/09f7d2a30633ca2ea229ae07d447819d96c19f1466021fb9c46a1fd241cf4ecf/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** NanoCore
- **Erkannt von:** 65 von 75 Engines (86.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.NanoCore.5
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.NanoCore.5`

**Erkennende Engines (65/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.NanoCore.5` |
| APEX | `Malicious` |
| AVG | `MSIL:NanoCore-B [Trj]` |
| AhnLab-V3 | `Win-Trojan/Nanocore.Exp` |
| Alibaba | `Trojan:Win32/NanoCore.348` |
| Antiy-AVL | `Trojan/MSIL.NanoCore` |
| Arcabit | `Trojan.NanoCore.5` |
| Avast | `MSIL:NanoCore-B [Trj]` |
| Avira | `TR/Dropper.MSIL.Gen7` |
| BitDefender 🛡️ | `Trojan.NanoCore.5` |
| Bkav | `W32.Malware.C47B2881` |
| CAT-QuickHeal | `Trojan.Orbus.C3` |
| CTX | `exe.trojan.nanocore` |
| ClamAV | `Win.Trojan.NanoCore-9852758-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `Trojan.Nanocore.23` |
| ESET-NOD32 | `MSIL/NanoCore.E trojan` |
| Elastic | `Windows.Trojan.Nanocore` |
| Emsisoft | `Trojan.NanoCore (A)` |
| F-Secure | `Trojan.TR/Dropper.MSIL.Gen7` |
| Fortinet | `MSIL/NanoCore.K!tr` |
| GData | `MSIL.Backdoor.Nancat.A` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Noancooe.cc!ni` |
| Ikarus | `Backdoor.Rat.Nanocore` |
| Jiangmin | `Backdoor.Generic.zwu` |
| K7AntiVirus | `Trojan ( 005b2a921 )` |
| K7GW | `Trojan ( 0057b88c1 )` |
| Kaspersky | `Trojan.MSIL.Agent.fpar` |
| Kingsoft | `MSIL.Trojan.Agent.fpar` |
| Lionic | `Trojan.Win32.Generic.mjrP` |
| Malwarebytes | `Backdoor.NanoCore` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!FD328284A530` |
| MicroWorld-eScan | `Trojan.NanoCore.5` |
| Microsoft 🛡️ | `Backdoor:MSIL/Nanocore!atmn` |
| NANO-Antivirus | `Trojan.Win32.NanoBot.hmqoyu` |
| Paloalto | `generic.ml` |
| Panda | `Bck/Agent.KNM` |
| Rising | `Backdoor.NanoCore!1.B6F9 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Nanocore/Variant` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-FICC!FD328284A530` |
| Sophos | `Troj/NanoCor-BT` |
| Symantec | `Trojan.Nancrat` |
| TACHYON | `Backdoor/W32.DN-Nanocore.207872` |
| Tencent | `Trojan.Msil.Agent.fb` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Trojan-FICC!FD328284A530` |
| TrendMicro | `BKDR_NOANCOOE.SM` |
| TrendMicro-HouseCall | `BKDR_NOANCOOE.SM` |
| VBA32 | `Trojan.MSIL.NanoCore.Heur` |
| VIPRE | `Trojan.NanoCore.5` |
| Varist | `W32/NanoCore.C.gen!Eldorado` |
| ViRobot | `Backdoor.Win32.NanoCore.Gen.A` |
| VirIT | `Trojan.Win32.DownLoader12.BSON` |
| Xcitium | `Backdoor.MSIL.Noancooe.JDE@5s4u9t` |
| ZoneAlarm | `Troj/NanoCor-BT` |
| Zoner | `Trojan.Win32.48280` |
| alibabacloud | `Backdoor:MSIL/Vindor.Gen` |
| huorong | `Backdoor/MSIL.NanoCore.b` |
| tehtris | `Generic.Malware` |


## Top Tags

- **exe** (33×)
- **elf** (19×)
- **js** (17×)
- **Mirai** (15×)
- **msi** (14×)
- **Torii** (11×)
- **Formbook** (7×)
- **RAT** (5×)
- **upx-dec** (4×)
- **AsyncRAT** (3×)
- **AgentTesla** (3×)
- **RemcosRAT** (3×)
- **upx** (3×)
- **VShell** (3×)
- **NanoCore** (2×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +20 (27→47)
- ↓ **Mirai** -12 (27→15)
- ↑ **Formbook** +3 (4→7)
- ↑ **NanoCore** +1 (2→3)
- ↑ **AsyncRAT** +2 (1→3)
- ↑ **RemcosRAT** +1 (2→3)
- ↑ **VShell** +1 (2→3)
- neu: **SnakeKeylogger** (2)
- neu: **ConnectWise** (2)
- weg: **SalatStealer** (war 3)
- weg: **WARDENStealer** (war 3)
- weg: **Silentnet** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +19 (28→47)
- ↓ **Mirai** -8 (23→15)
- ↑ **Formbook** +4 (3→7)
- neu: **NanoCore** (3)
- neu: **AsyncRAT** (3)
- ↑ **AgentTesla** +1 (2→3)
- ↑ **RemcosRAT** +1 (2→3)
- ↑ **VShell** +2 (1→3)
- neu: **SnakeKeylogger** (2)
- ↑ **ConnectWise** +1 (1→2)
- weg: **SalatStealer** (war 9)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.490 MB |
| σ Dateigröße | 6.168 MB |
| Ø Risiko-Score | 59.0/100 |
| Ø Klassifikations-Konfidenz | 60.9% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 31/101 |
| Eindeutige Familien | 21 |
| Eindeutige Tags | 43 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 08:36 | [fedae371dc02…](https://bazaar.abuse.ch/sample/fedae371dc02132501676259ec8d4e45a7dfef71697bb0b49885d9e69924d4a7/) | `js` | unbekannt | 39.0 | – | – | 🇩🇪DE |
| 08:32 | [eb175a973d11…](https://bazaar.abuse.ch/sample/eb175a973d117fb34df1c23fa46587c01f68bb014ea192790021be47730661b8/) | `exe` | Formbook | 90.5 | – | – | 🌐AT |
| 08:32 | [352cfb22ba48…](https://bazaar.abuse.ch/sample/352cfb22ba4830b5c184041bf4457a21580e44bdfa66f615e003799c3a76fc97/) | `exe` | NanoCore | 89.6 | – | – | 🌐AT |
| 08:32 | [c0b6230be84e…](https://bazaar.abuse.ch/sample/c0b6230be84eb027eeebb51e7bb56537c0882a85cbdb069863b2e6372130d1c0/) | `js` | unbekannt | 38.9 | – | – | 🌐AT |
| 08:32 | [497f188df761…](https://bazaar.abuse.ch/sample/497f188df761d422f0f96d90022ca8faf07854d73c299e6ef6fcfffd432005d5/) | `js` | unbekannt | 38.9 | – | – | 🌐AT |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 04.11.2026 08:46 UTC*