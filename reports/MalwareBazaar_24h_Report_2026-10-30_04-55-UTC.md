# MalwareBazaar – 30.10.2026 04:55 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **59** |
| Höchster Score | **97.3/100** – f5524521df17eb50… |
| Häufigste Familie | **SalatStealer** (37x) |
| Häufigster Typ | **exe** (58x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 18 Samples |
| Ø Dateigröße | 5.12 MB (σ=11.91) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 58 | 57.4%  ███████████ |
| `elf` | 17 | 16.8%  ███ |
| `macho` | 15 | 14.9%  ██ |
| `vbs` | 4 | 4.0%   |
| `msi` | 2 | 2.0%   |
| `py` | 1 | 1.0%   |
| `cmd` | 1 | 1.0%   |
| `zsh` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |
| `js` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | SalatStealer | 37 | 36.6% |
| 2 | unbekannt | 36 | 35.6% |
| 3 | Mirai | 14 | 13.9% |
| 4 | GuLoader | 3 | 3.0% |
| 5 | WannaCry | 2 | 2.0% |
| 6 | OverlordRAT | 2 | 2.0% |
| 7 | ConnectWise | 2 | 2.0% |
| 8 | VShell | 2 | 2.0% |
| 9 | Formbook | 1 | 1.0% |
| 10 | WARDENStealer | 1 | 1.0% |
| 11 | Snowlight | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Infostealer | 39 | 38.6% | 75% |
| Windows-Malware | 15 | 14.9% | 35% |
| Botnet/IoT | 14 | 13.9% | 95% |
| Loader | 13 | 12.9% | 80% |
| Andere / Unbekannt | 9 | 8.9% | 20% |
| Linux-Malware | 5 | 5.0% | 45% |
| RAT | 3 | 3.0% | 75% |
| Ransomware | 2 | 2.0% | 95% |
| Skript/Dropper | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 59 | 58.4% |
| 🟠 HOCH | 12 | 11.9% |
| 🟡 MITTEL | 21 | 20.8% |
| 🟢 NIEDRIG | 9 | 8.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f5524521df17eb…](https://bazaar.abuse.ch/sample/f5524521df17eb50fc3dfc7d4d447519ebdf2a4597c82fb9f16d46f64bf47822/) | WannaCry | Ransomware | **97.3** | 🔴 KRITISCH | – | – | ? |
| [ac29dd46f9347e…](https://bazaar.abuse.ch/sample/ac29dd46f9347e2adfa84e1d3b22ab807f6e472946829f57423d7948bcc167d1/) | WannaCry | Ransomware | **96.4** | 🔴 KRITISCH | – | – | ? |
| [db5a90a147265b…](https://bazaar.abuse.ch/sample/db5a90a147265bf5f253ce1e8f7a40a8cf5197f5d90f0a6c4cbe4c2328f18f14/) | Formbook | Infostealer | **88.9** | 🔴 KRITISCH | – | – | ? |
| [7ecb1e48abd985…](https://bazaar.abuse.ch/sample/7ecb1e48abd985233e3b70fee0fc648e05ae5e1df2685c30903a30262de3dac8/) | GuLoader | Loader | **83.0** | 🔴 KRITISCH | 6.7% | ⚠️ KAUM ERKANNT | ✗ |
| [50467b69921dd3…](https://bazaar.abuse.ch/sample/50467b69921dd34c67ddcbbdb529f81159844c6e80effe4b4ccb06725b14f26e/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [278bd6ea4a998a…](https://bazaar.abuse.ch/sample/278bd6ea4a998a126fc59102a339d2f2ad879de6c99addcc532465a11cce67bf/) | Mirai | Botnet/IoT | **82.8** | 🔴 KRITISCH | – | – | ? |
| [ea04ba910ce5fd…](https://bazaar.abuse.ch/sample/ea04ba910ce5fd987031377d8e17faaae855f8c9743f550a045f800820ecace4/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [e0805ad4034a37…](https://bazaar.abuse.ch/sample/e0805ad4034a37cb6e0e69d3a3a562874da540456f92a9f112758cd4db597a48/) | Mirai | Botnet/IoT | **82.4** | 🔴 KRITISCH | – | – | ? |
| [6e20b1859bf307…](https://bazaar.abuse.ch/sample/6e20b1859bf3072a5e6fbdd81d3e03279becbf1dee8503207b4ea1d86e569d3a/) | Mirai | Botnet/IoT | **82.3** | 🔴 KRITISCH | – | – | ? |
| [7c00572008134d…](https://bazaar.abuse.ch/sample/7c00572008134d39687755c03cf38a6dc57ae970922ea4aab6b7ec8c15fac9df/) | Mirai | Botnet/IoT | **82.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6257/7720 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 81.0% | 6257/7720 |
| 3 | ESET-NOD32 | 77.3% | 5964/7720 |
| 4 | Kaspersky | 75.6% | 5832/7719 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.2% | 5494/7717 |
| 8 | Rising | 68.3% | 5274/7720 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5105/7716 |
| 11 | Avast | 65.2% | 5028/7716 |
| 12 | AVG | 65.2% | 5028/7715 |
| 13 | Tencent | 64.9% | 4865/7494 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4726/7713 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 60 | 59.4% |
| 🐧 Linux | 21 | 20.8% |
| 🍎 macOS | 15 | 14.9% |
| ❓ Unbekannt | 3 | 3.0% |
| 📡 IoT/OT | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 83 | 82.2% |
| MaaS-Loader | 10 | 9.9% |
| Drive-By / Exploit-Kit | 4 | 4.0% |
| Exploit / N-Day | 2 | 2.0% |
| Trojanisierte Software | 2 | 2.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 55 | 54.5% |
| 2 | 🇳🇱 NL | 22 | 21.8% |
| 3 | 🇩🇪 DE | 10 | 9.9% |
| 4 | 🇫🇷 FR | 9 | 8.9% |
| 5 | 🇨🇭 CH | 4 | 4.0% |
| 6 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 18 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 14 |
| Lateral Movement | 14 |
| Defense Evasion | 3 |
| Execution | 3 |
| Credential Access | 1 |
| Collection | 1 |

<details><summary>db5a90a147265bf5f253… – Formbook | 🔴 KRITISCH 88.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>7ecb1e48abd985233e3b… – GuLoader | 🔴 KRITISCH 83.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Defense Evasion | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information |
| Execution | [T1106](https://attack.mitre.org/techniques/T1106/) | Native API |

</details>
<details><summary>50467b69921dd34c67dd… – Mirai | 🔴 KRITISCH 82.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [9bd124b714e997c74446…](https://bazaar.abuse.ch/sample/9bd124b714e997c744465e74d644ac7df44fe2a348c6b06cfd903dbe06a5c735/)

- **Familie:** SalatStealer
- **Erkannt von:** 46 von 75 Engines (61.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.LummaStealer.103
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.LummaStealer.103`

**Erkennende Engines (46/75):**

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
| Bkav | `W32.Malware.BA376C02` |
| CTX | `exe.trojan.lummastealer` |
| ClamAV | `Win.Malware.Salat-10058846-0` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
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
| McAfeeD | `Real Protect-LS!0E55F8CB3C09` |
| MicroWorld-eScan | `Trojan.LummaStealer.103` |
| Microsoft 🛡️ | `Trojan:Win32/SalatStealer!pz` |
| NANO-Antivirus | `Trojan.Win32.Salat.lhyjkz` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `SalatStealer!0E55F8CB3C09` |
| Sophos | `Troj/Salat-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570944` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| TrellixENS | `SalatStealer!0E55F8CB3C09` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `TrojanPSW.Win32.GenericStealer` |
| VIPRE | `Trojan.LummaStealer.103` |
| Varist | `W32/Salat.A.gen!Eldorado` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| ZoneAlarm | `Troj/Salat-A` |
| huorong | `Trojan/Agent.e!crit` |

### [219fe381157b3a2c9149…](https://bazaar.abuse.ch/sample/219fe381157b3a2c9149a96dc7ebdf1ed088bb444a2244e9c5b3bebdf6308522/)

- **Familie:** SalatStealer
- **Erkannt von:** 52 von 75 Engines (69.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Draftor.8401
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Draftor.8401`

**Erkennende Engines (52/75):**

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
| Bkav | `W32.Malware.71A05452` |
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
| Gridinsoft | `Trojan.Win32.Agent.oa!s2` |
| Ikarus | `Trojan.Win32.SalatStealer` |
| K7AntiVirus | `Trojan ( 005ce1d91 )` |
| K7GW | `Trojan ( 005ce1d91 )` |
| Kaspersky | `UDS:Trojan-PSW.Win64.Salat` |
| Kingsoft | `malware.kb.b.939` |
| Lionic | `Trojan.Win64.Salat.i!c` |
| Malwarebytes | `Trojan.MalPack.Generic` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!CD2E369BE14B` |
| MicroWorld-eScan | `Gen:Variant.Draftor.8401` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Stealer.Salat!1.13A22 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `Trojan-JBNR!305A93FC83E7` |
| Sophos | `Troj/Salat-B` |
| Symantec | `ML.Attribute.HighConfidence` |
| TACHYON | `Trojan/W32.Agent.12570847` |
| Tencent | `Trojan.Win32.Stealer.16001830` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `Artemis!CD2E369BE14B` |
| VBA32 | `TrojanPSW.Satal` |
| VIPRE | `Gen:Variant.Draftor.8401` |
| VirIT | `Trojan.Win32.SalatStlr.IXO` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.ULPM!u7xCWl8ouvU` |
| Zillya | `Trojan.AgentAGen.Win32.203200` |
| ZoneAlarm | `Troj/Salat-B` |
| huorong | `Trojan/Agent.e!crit` |

### [027ee20166749752ec93…](https://bazaar.abuse.ch/sample/027ee20166749752ec93c0cd25d25744f6496e969d0f43c75373a6d2ffd0c84f/)

- **Familie:** Mirai
- **Erkannt von:** 21 von 75 Engines (28.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Prometei-D [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (21/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| huorong | `Trojan/Prometei.c` |

### [7ecb1e48abd985233e3b…](https://bazaar.abuse.ch/sample/7ecb1e48abd985233e3b70fee0fc648e05ae5e1df2685c30903a30262de3dac8/)

- **Familie:** GuLoader
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Scr.Guloader!gen11
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Ikarus | `Trojan.VBS.Agent` |
| Kaspersky | `UDS:Trojan.VBS.SAgent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
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

- **exe** (57×)
- **SalatStealer** (22×)
- **upx-dec** (22×)
- **upx** (22×)
- **elf** (17×)
- **macho** (15×)
- **salatstealer** (14×)
- **Mirai** (13×)
- **ClickFix** (11×)
- **Foxveil** (11×)
- **Mach-O** (11×)
- **macOS** (11×)
- **loader** (10×)
- **Torii** (5×)
- **vbs** (4×)

## Änderungen – 24h-Vergleich

- ↑ **SalatStealer** +19 (18→37)
- ↑ **unbekannt** +11 (25→36)
- ↑ **Mirai** +1 (13→14)
- neu: **GuLoader** (3)
- neu: **OverlordRAT** (2)
- neu: **ConnectWise** (2)
- neu: **VShell** (2)
- ↓ **Formbook** -6 (7→1)
- neu: **WARDENStealer** (1)
- weg: **RemcosRAT** (war 4)
- weg: **AgentTesla** (war 2)
- weg: **MassLogger** (war 2)
- weg: **CoinMiner** (war 2)
- weg: **KATARU** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **SalatStealer** +24 (13→37)
- ↑ **unbekannt** +14 (22→36)
- ↓ **Mirai** -9 (23→14)
- neu: **GuLoader** (3)
- neu: **WannaCry** (2)
- neu: **OverlordRAT** (2)
- ↑ **ConnectWise** +1 (1→2)
- neu: **VShell** (2)
- ↓ **Formbook** -1 (2→1)
- neu: **WARDENStealer** (1)
- weg: **RemcosRAT** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 5.120 MB |
| σ Dateigröße | 11.911 MB |
| Ø Risiko-Score | 66.8/100 |
| Ø Klassifikations-Konfidenz | 66.1% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 18/101 |
| Eindeutige Familien | 11 |
| Eindeutige Tags | 40 |
| Unbekannte Familien | 9 (8.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 04:53 | [03a680cd8b8c…](https://bazaar.abuse.ch/sample/03a680cd8b8c2323d4f78bf578220aec930188a98143b3878160f0d9b8335b40/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 04:50 | [25d276912d13…](https://bazaar.abuse.ch/sample/25d276912d13fe510558f6e4382bd4cfd4b94cdfa84f5080dfee082cdc5fdcc4/) | `elf` | unbekannt | 43.3 | – | – | 🇺🇸US |
| 04:50 | [fa0007391da2…](https://bazaar.abuse.ch/sample/fa0007391da2cbd9c0b15937f1ce0e389f4d2d7f392f50331a4e831d2516834c/) | `elf` | unbekannt | 43.3 | – | – | 🇺🇸US |
| 04:49 | [2a93e929b69c…](https://bazaar.abuse.ch/sample/2a93e929b69caa6dc56901cda012b0073d83a4682a025193a0fc7234fedff83f/) | `macho` | unbekannt | 75.0 | – | – | 🇺🇸US |
| 04:48 | [905e2e48e90e…](https://bazaar.abuse.ch/sample/905e2e48e90e0d4aa332e7c39e9d7a41407fdc5bc78bad14c46294ec5c08b784/) | `py` | unbekannt | 32.6 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 30.10.2026 04:55 UTC*