# MalwareBazaar – 22.11.2026 17:41 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **63** |
| Höchster Score | **95.8/100** – 555156d6b0a2fd0f… |
| Häufigste Familie | **unbekannt** (45x) |
| Häufigster Typ | **exe** (39x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 16 Samples |
| Ø Dateigröße | 2.66 MB (σ=3.67) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 39 | 38.6%  ███████ |
| `elf` | 34 | 33.7%  ██████ |
| `ps1` | 9 | 8.9%  █ |
| `js` | 7 | 6.9%  █ |
| `macho` | 6 | 5.9%  █ |
| `bat` | 5 | 5.0%   |
| `vbs` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 45 | 44.6% |
| 2 | WARDENStealer | 14 | 13.9% |
| 3 | EasyShell | 10 | 9.9% |
| 4 | njrat | 7 | 6.9% |
| 5 | Prometei | 4 | 4.0% |
| 6 | RemcosRAT | 3 | 3.0% |
| 7 | AgentTesla | 3 | 3.0% |
| 8 | SnappyClient | 2 | 2.0% |
| 9 | AsyncRAT | 2 | 2.0% |
| 10 | CoinMiner | 2 | 2.0% |
| 11 | Sliver | 2 | 2.0% |
| 12 | Vidar | 2 | 2.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 38 | 37.6% | 81% |
| Skript/Dropper | 17 | 16.8% | 35% |
| Infostealer | 17 | 16.8% | 79% |
| Windows-Malware | 11 | 10.9% | 35% |
| Linux-Malware | 6 | 5.9% | 45% |
| Trojaner | 3 | 3.0% | 75% |
| Cryptominer | 2 | 2.0% | 75% |
| Post-Exploitation | 2 | 2.0% | 95% |
| Worm | 2 | 2.0% | 75% |
| Backdoor | 1 | 1.0% | 75% |
| Loader | 1 | 1.0% | 65% |
| Ransomware | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 63 | 62.4% |
| 🟠 HOCH | 4 | 4.0% |
| 🟡 MITTEL | 34 | 33.7% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [555156d6b0a2fd…](https://bazaar.abuse.ch/sample/555156d6b0a2fd0fa738b6aa7d77ede2e5fffd67462cf18a1a19f9dd2f747053/) | WannaCry | Ransomware | **95.8** | 🔴 KRITISCH | – | – | ? |
| [1823ed5c5dbad9…](https://bazaar.abuse.ch/sample/1823ed5c5dbad9919ef63a8ec20415d4a5b52abcc901ee846a48097c028d47d2/) | Sliver | Post-Exploitat | **94.7** | 🔴 KRITISCH | – | – | ? |
| [08382f74d5dfc8…](https://bazaar.abuse.ch/sample/08382f74d5dfc8e6e88ab35fc7daabff5d211da55b4b6458db0cbfce9fce1f50/) | Sliver | Post-Exploitat | **94.6** | 🔴 KRITISCH | – | – | ? |
| [bd1d2bfd7f1b5c…](https://bazaar.abuse.ch/sample/bd1d2bfd7f1b5c349c54a3ee68533b825eb81ccd89eb612638dfe351aa2c512f/) | Formbook | Infostealer | **90.0** | 🔴 KRITISCH | – | – | ? |
| [a02acdfdaa5464…](https://bazaar.abuse.ch/sample/a02acdfdaa54647abc023b13ec5511e7c8b0fcbbee27fd7945f0c862a2253f8f/) | Vidar | Infostealer | **89.8** | 🔴 KRITISCH | – | – | ? |
| [31f1f359dc5691…](https://bazaar.abuse.ch/sample/31f1f359dc569109a133017e23692ef6d86278875a8185cc32eaf3282b07e041/) | Vidar | Infostealer | **89.8** | 🔴 KRITISCH | – | – | ? |
| [501b3c32737e0e…](https://bazaar.abuse.ch/sample/501b3c32737e0eaa39c32521c9d41e0b9a1316f0dc8d1952b1a7df940a29daa2/) | RemcosRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [261da7690849fb…](https://bazaar.abuse.ch/sample/261da7690849fb63a04941f539c3da496b9763ca113b7c6da2a1a9d5729232fe/) | RemcosRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [e0788e78b12850…](https://bazaar.abuse.ch/sample/e0788e78b1285063e5e4f77d6a1c6f81d7fda105a619ee1b736735249831bb61/) | RemcosRAT | RAT | **89.1** | 🔴 KRITISCH | – | – | ? |
| [58a728ff82d235…](https://bazaar.abuse.ch/sample/58a728ff82d235c7251659172c818c6248ec2bed3f833ee0ce0252a915ff92a4/) | njrat | RAT | **89.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6575/8102 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6575/8102 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6272/8102 |
| 6 | Kaspersky | 75.6% | 6125/8101 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5773/8098 |
| 9 | Rising | 68.6% | 5555/8102 |
| 10 | Varist | 66.1% | 5351/8097 |
| 11 | Tencent | 65.2% | 5132/7876 |
| 12 | Avast | 65.2% | 5281/8098 |
| 13 | AVG | 65.2% | 5281/8097 |
| 14 | McAfeeD | 61.5% | 4976/8094 |
| 15 | huorong | 61.0% | 4935/8094 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 54 | 53.5% |
| 🐧 Linux | 40 | 39.6% |
| ❓ Unbekannt | 6 | 5.9% |
| 🤖 Android | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 90 | 89.1% |
| Drive-By / Exploit-Kit | 7 | 6.9% |
| USB / Wechselmedium | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇫🇷 FR | 39 | 38.6% |
| 2 | 🇺🇸 US | 36 | 35.6% |
| 3 | 🌐 CL | 14 | 13.9% |
| 4 | 🇩🇪 DE | 5 | 5.0% |
| 5 | 🇳🇱 NL | 3 | 3.0% |
| 6 | 🇨🇦 CA | 3 | 3.0% |
| 7 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 16 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Collection | 13 |
| Command and Control | 12 |
| Credential Access | 3 |
| Execution | 2 |
| Exfiltration | 2 |
| Impact | 1 |

<details><summary>bd1d2bfd7f1b5c349c54… – Formbook | 🔴 KRITISCH 90.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |

</details>
<details><summary>a02acdfdaa54647abc02… – Vidar | 🔴 KRITISCH 89.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [4e2d3e88b8ba86caffc2…](https://bazaar.abuse.ch/sample/4e2d3e88b8ba86caffc23f49f68dced3360cb82d07a6c8e9ef5e9850f5b19f6c/)

- **Familie:** BTN trojan
- **Erkannt von:** 4 von 74 Engines (5.4%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Linux/Agent.BTN trojan
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (4/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `Linux/Agent.BTN trojan` |
| Kaspersky | `HEUR:Backdoor.Linux.Agent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.C!ml` |
| Rising | `Backdoor.Agent/Linux!8.133D0 (TFE:14:3Ol2Hl59JIN)` |

### [28a82071ff9eaf288b1a…](https://bazaar.abuse.ch/sample/28a82071ff9eaf288b1a1f927f83c82707d712592a9fedd89b030190617a38c8/)

- **Familie:** njrat
- **Erkannt von:** 31 von 74 Engines (41.9%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** FileRepMalware [Rat]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (31/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Rat]` |
| Alibaba | `Trojan:Win64/GenKryptik.2851cd8f` |
| Antiy-AVL | `Trojan/Win64.Agent` |
| Avast | `FileRepMalware [Rat]` |
| Bkav | `W32.Malware.E05F9032` |
| CrowdStrike | `win/malicious_confidence_90% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.AsyncRAT.115` |
| ESET-NOD32 | `Win32/GenKryptik.HXVN trojan` |
| Elastic | `malicious (high confidence)` |
| GData | `Win32.Trojan.Agent.1E3A2P` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan.Win64.Generic` |
| Kingsoft | `Win64.Trojan.Generic.a` |
| Lionic | `Trojan.Win32.Generic.4!c` |
| McAfeeD | `ti!28A82071FF9E` |
| Microsoft 🛡️ | `Trojan:MSIL/Bladabindi!rfn` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Generic!8.C3 (TFE:5:NEee5cTu0F)` |
| Sangfor | `Trojan.Win32.Kryptik.Vv9o` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `BehavesLike.Win32.Dropper.kc` |
| Sophos | `Mal/Generic-S` |
| Symantec | `ML.Attribute.HighConfidence` |
| TrellixENS | `Artemis!360CEA82AEDE` |
| TrendMicro | `Backdoor.Win32.NJRAT.YXGKRZ` |
| Varist | `W32/ABTrojan.ZDJX-4525` |
| alibabacloud | `Trojan:Win/Generic.Gen` |
| huorong | `HVM:Trojan/MalBehav.gen!T` |

### [b1610927a71d6df8e85c…](https://bazaar.abuse.ch/sample/b1610927a71d6df8e85c56adab1c7a12c3897f8ba684c59e2a20cdd70e85178c/)

- **Familie:** AgentTesla
- **Erkannt von:** 12 von 74 Engines (16.2%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Script:SNH-gen [Trj]
- **VT-Reputation:** -12
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Script:SNH-gen [Trj]` |
| Avast | `Script:SNH-gen [Trj]` |
| Avira | `TR/SNH` |
| Cynet | `Malicious (score: 99)` |
| F-Secure | `Trojan.TR/SNH` |
| Google | `Detected` |
| Kaspersky | `HEUR:Trojan.PowerShell.Agent.gen` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Skyhigh | `BehavesLike.PS.Dropper.dg` |
| Symantec | `Scr.Malscript!gen48` |
| Varist | `PSH/Agent.AUX` |
| huorong | `TrojanDownloader/PS.Netloader.mj` |

### [5378c22c9d36c7ca8e6b…](https://bazaar.abuse.ch/sample/5378c22c9d36c7ca8e6b30629323cae9a8989eeffcc658fb2ebafab6028c72da/)

- **Familie:** WARDENStealer
- **Erkannt von:** 22 von 74 Engines (29.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.85599
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.85599`

**Erkennende Engines (22/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.85599` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R797565` |
| Arcabit | `Trojan.Yogi.D14E5F` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.85599` |
| CTX | `dll.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/ShellcodeRunner.CQR trojan` |
| Elastic | `malicious (moderate confidence)` |
| Emsisoft | `Gen:Variant.Yogi.85599 (B)` |
| GData | `Gen:Variant.Yogi.85599` |
| K7AntiVirus | `Trojan ( 006e90e91 )` |
| K7GW | `Trojan ( 006e90e91 )` |
| Kaspersky | `HEUR:Trojan.Win32.Agent.pef` |
| MicroWorld-eScan | `Gen:Variant.Yogi.85599` |
| Rising | `Trojan.ShellcodeRunner!8.6166 (TFE:5:ClKAJveoG7N)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Skyhigh | `BehavesLike.Win64.Trojan.jc` |
| VIPRE | `Gen:Variant.Yogi.85599` |
| Varist | `W64/ShellcodeRunner.W.gen!Eldorado` |
| huorong | `Trojan/W64.ShellLoader.et!crit` |

### [8931f899bf04208d1853…](https://bazaar.abuse.ch/sample/8931f899bf04208d18536db7733ba87273907f74546d80ba3862f83f1f717b9d/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** njrat
- **Erkannt von:** 55 von 74 Engines (74.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Heur.MSIL.Krypt.!cdmip!.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Heur.MSIL.Krypt.!cdmip!.2`

**Erkennende Engines (55/74):**

| Engine | Erkannter Name |
|--------|----------------|
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Klg]` |
| AhnLab-V3 | `Malware/Gen.RL_Reputation.C4341029` |
| Alibaba | `Backdoor:MSIL/Bladabindi.1adecf58` |
| Antiy-AVL | `Trojan/MSIL.Bladabindi` |
| Arcabit | `Trojan.MSIL.Krypt.!cdmip!.2` |
| Avast | `Win32:MalwareX-gen [Klg]` |
| Avira | `TR/Dropper.Gen` |
| BitDefender 🛡️ | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Bkav | `W32.Malware.C33D8CB8` |
| CAT-QuickHeal | `Backdoor.Bladabindi` |
| CTX | `exe.unknown.msil` |
| ClamAV | `Win.Packed.njRAT-7445143-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.BladabindiNET.10` |
| ESET-NOD32 | `MSIL/Bladabindi.AZ trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Heur.MSIL.Krypt.!cdmip!.2 (B)` |
| F-Secure | `Trojan.TR/Dropper.Gen` |
| Fortinet | `MSIL/MALD2.F963!tr` |
| GData | `MSIL.Backdoor.Bladabindi.HIT342` |
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Bladabindi.sa` |
| Ikarus | `Gen.MSIL.Krypt` |
| K7AntiVirus | `Trojan ( 700000201 )` |
| K7GW | `Trojan ( 700000201 )` |
| Kaspersky | `HEUR:Trojan-Spy.MSIL.KeyLogger.gen` |
| Kingsoft | `malware.kb.c.1000` |
| Lionic | `Trojan.Win32.Bladabindi.l!c` |
| Malwarebytes | `Trojan.MalPack` |
| MaxSecure | `Trojan.Malware.325019560.susgen` |
| McAfeeD | `Trojan:Win/Bladabindi.EBA` |
| MicroWorld-eScan | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Microsoft 🛡️ | `Backdoor:MSIL/Bladabindi!atmn` |
| Paloalto | `generic.ml` |
| Panda | `Trj/GdSda.A` |
| Rising | `Backdoor.njRAT!1.9E49 (CLASSIC)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `GenericRXKJ-UU!0C21066DB8E8` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Backdoor.Ratenjay!gen3` |
| Tencent | `Trojan.Msil.Bladabindi.16009413` |
| Trapmine | `malicious.moderate.ml.score` |
| TrellixENS | `GenericRXKJ-UU!0C21066DB8E8` |
| TrendMicro | `Backdoor.MSIL.BLADABINDI.TL0101KE26ZZ` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAN` |
| VBA32 | `Trojan.MSIL.Bladabindi.Heur` |
| VIPRE | `Gen:Heur.MSIL.Krypt.!cdmip!.2` |
| Varist | `W32/Bladabindi.HK.gen!Eldorado` |
| VirIT | `Trojan.Win32.MSIL_Heur.A` |
| alibabacloud | `Trojan:MSIL/Bladabindi.HTZ2XJC` |
| huorong | `Trojan/MSIL.Agent.q` |


## Top Tags

- **exe** (38×)
- **elf** (34×)
- **RAT** (29×)
- **EasyShell** (24×)
- **Rust** (24×)
- **SnoopyTriage** (24×)
- **WARDENStealer** (14×)
- **upx** (13×)
- **stealer** (10×)
- **Warden** (10×)
- **diicot** (10×)
- **ps1** (9×)
- **upx-dec** (8×)
- **js** (7×)
- **macho** (6×)

## Änderungen – 24h-Vergleich

- ↑ **WARDENStealer** +13 (1→14)
- neu: **EasyShell** (10)
- ↑ **njrat** +5 (2→7)
- neu: **RemcosRAT** (3)
- neu: **AgentTesla** (3)
- neu: **SnappyClient** (2)
- neu: **AsyncRAT** (2)
- ↑ **CoinMiner** +1 (1→2)
- weg: **Mirai** (war 33)
- weg: **Snowlight** (war 9)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +16 (29→45)
- ↑ **WARDENStealer** +9 (5→14)
- neu: **EasyShell** (10)
- ↑ **njrat** +6 (1→7)
- ↓ **Prometei** -1 (5→4)
- ↑ **RemcosRAT** +1 (2→3)
- ↑ **AgentTesla** +1 (2→3)
- neu: **SnappyClient** (2)
- ↑ **AsyncRAT** +1 (1→2)
- ↑ **CoinMiner** +1 (1→2)
- weg: **Mirai** (war 32)
- weg: **Snowlight** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.661 MB |
| σ Dateigröße | 3.669 MB |
| Ø Risiko-Score | 67.8/100 |
| Ø Klassifikations-Konfidenz | 65.6% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 16/101 |
| Eindeutige Familien | 17 |
| Eindeutige Tags | 56 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:37 | [a9ee1b703cb5…](https://bazaar.abuse.ch/sample/a9ee1b703cb599756b2b03833ba3e2491a5165c400ca57cea6993799ce060474/) | `elf` | unbekannt | 43.3 | – | – | 🇩🇪DE |
| 17:36 | [bd8251c5e4ce…](https://bazaar.abuse.ch/sample/bd8251c5e4ceefd1fe29618cab7073834658e12ba755a66b779a6cd27deaec4d/) | `elf` | unbekannt | 81.2 | – | – | 🇺🇸US |
| 17:36 | [4e2d3e88b8ba…](https://bazaar.abuse.ch/sample/4e2d3e88b8ba86caffc23f49f68dced3360cb82d07a6c8e9ef5e9850f5b19f6c/) | `elf` | BTN trojan | 85.1 | 5.4% | ⚠️ KAUM ERKANNT | 🇺🇸US |
| 17:36 | [d7250e2bf510…](https://bazaar.abuse.ch/sample/d7250e2bf510da94d65996bc232fee8daf1d188b3cc26cb6eedea6a316807a5d/) | `elf` | Prometei | 43.3 | – | – | 🇩🇪DE |
| 17:36 | [345171f363e5…](https://bazaar.abuse.ch/sample/345171f363e5130c2e983d6bb95c3ba03da5e480110620029413a2da50ca0758/) | `elf` | unbekannt | 81.2 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 22.11.2026 17:41 UTC*