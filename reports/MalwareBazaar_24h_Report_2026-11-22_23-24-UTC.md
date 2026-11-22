# MalwareBazaar – 22.11.2026 23:24 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `8931f899bf04208d1853…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **87** |
| Höchster Score | **94.2/100** – 671422d250c90425… |
| Häufigste Familie | **unbekannt** (44x) |
| Häufigster Typ | **elf** (66x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 35 Samples |
| Ø Dateigröße | 8.03 MB (σ=26.92) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 66 | 65.3%  █████████████ |
| `exe` | 18 | 17.8%  ███ |
| `macho` | 13 | 12.9%  ██ |
| `sh` | 2 | 2.0%   |
| `xlsm` | 1 | 1.0%   |
| `dll` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 44 | 43.6% |
| 2 | Mirai | 29 | 28.7% |
| 3 | EasyShell | 8 | 7.9% |
| 4 | ValleyRAT | 5 | 5.0% |
| 5 | Prometei | 4 | 4.0% |
| 6 | njrat | 4 | 4.0% |
| 7 | WARDENStealer | 3 | 3.0% |
| 8 | Linux | 1 | 1.0% |
| 9 | Yogi | 1 | 1.0% |
| 10 | WannaCry | 1 | 1.0% |
| 11 | CoinMiner | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| RAT | 51 | 50.5% | 77% |
| Botnet/IoT | 30 | 29.7% | 94% |
| Infostealer | 7 | 6.9% | 75% |
| Linux-Malware | 5 | 5.0% | 45% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Windows-Malware | 2 | 2.0% | 35% |
| Maldoc | 1 | 1.0% | 35% |
| Ransomware | 1 | 1.0% | 95% |
| Cryptominer | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 87 | 86.1% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 8 | 7.9% |
| 🟢 NIEDRIG | 3 | 3.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [671422d250c904…](https://bazaar.abuse.ch/sample/671422d250c9042509ad3023d01485eb667a257b1d2de16c994c7665f75557f8/) | WannaCry | Ransomware | **94.2** | 🔴 KRITISCH | – | – | ? |
| [3baaeffebce11b…](https://bazaar.abuse.ch/sample/3baaeffebce11b9ab56ea93d8810c6e34fdfcf7ca59596619b7214b2b92d0bca/) | njrat | RAT | **88.2** | 🔴 KRITISCH | – | – | ? |
| [62a9a3fd464449…](https://bazaar.abuse.ch/sample/62a9a3fd4644498c68273a2e2cc5496981ad485c75b9da7a93a4a3146a77ff85/) | njrat | RAT | **87.1** | 🔴 KRITISCH | – | – | ? |
| [4faae0920063ed…](https://bazaar.abuse.ch/sample/4faae0920063ed8122c298506d7519f0d57f7f5f4b0005a61d0f8f78fdcbb10c/) | njrat | RAT | **87.0** | 🔴 KRITISCH | – | – | ? |
| [c71bb57d291a13…](https://bazaar.abuse.ch/sample/c71bb57d291a1382310630a3751c7a3d4debe4e11838b2c1a73d2ed03f574457/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [c8eb80953b00c3…](https://bazaar.abuse.ch/sample/c8eb80953b00c3ae023b8985e7356260e2b49b61c257fe118c7b17485c28ea3e/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [12da680ed0ef26…](https://bazaar.abuse.ch/sample/12da680ed0ef26f45d455d8814a1aa9a1f019b068d7dfbdd5077d21419b215bc/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [86da5dac68bd54…](https://bazaar.abuse.ch/sample/86da5dac68bd54a80d0a2e3160e667db4cdf4b2a49a17341e0e66ff4faeb949a/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [15fe85ed47fd22…](https://bazaar.abuse.ch/sample/15fe85ed47fd22621376cd73f1bff0ba0153aafec8bc98cbe777c9f58ed3d751/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [11880f8454b079…](https://bazaar.abuse.ch/sample/11880f8454b079ddd41a4e38725cc8268cf3109c682aa12c5d13f43b14b08637/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.2% Erkennungsrate (6579/8106 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.2% | 6579/8106 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.4% | 6276/8106 |
| 6 | Kaspersky | 75.6% | 6129/8105 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5776/8102 |
| 9 | Rising | 68.6% | 5559/8106 |
| 10 | Varist | 66.1% | 5355/8101 |
| 11 | Tencent | 65.2% | 5136/7880 |
| 12 | Avast | 65.2% | 5284/8102 |
| 13 | AVG | 65.2% | 5284/8101 |
| 14 | McAfeeD | 61.5% | 4979/8098 |
| 15 | huorong | 61.0% | 4939/8098 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 80 | 79.2% |
| 🪟 Windows | 19 | 18.8% |
| 📄 Dokument | 1 | 1.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 99 | 98.0% |
| Phishing / E-Mail-Anhang | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 50 | 49.5% |
| 2 | 🇩🇪 DE | 22 | 21.8% |
| 3 | 🇳🇱 NL | 16 | 15.8% |
| 4 | 🇫🇷 FR | 9 | 8.9% |
| 5 | 🇭🇺 HU | 3 | 3.0% |
| 6 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 35 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 29 |
| Lateral Movement | 29 |
| Collection | 6 |
| Command and Control | 4 |
| Credential Access | 2 |
| Exfiltration | 2 |

<details><summary>3baaeffebce11b9ab56e… – njrat | 🔴 KRITISCH 88.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>62a9a3fd4644498c6827… – njrat | 🔴 KRITISCH 87.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>4faae0920063ed8122c2… – njrat | 🔴 KRITISCH 87.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>c71bb57d291a13823106… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [574ff030b3c98ba192c0…](https://bazaar.abuse.ch/sample/574ff030b3c98ba192c0bb43af25ca4f59e1c830726bf07e27415776624407d5/)

- **Familie:** Linux
- **Erkannt von:** 41 von 74 Engines (55.4%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (41/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Gafgyt-KS [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen3` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Gafgyt-KS [Trj]` |
| Avira | `EXP/ELF.Mirai.Bootnet.oc` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Dropper.Mirai-7135890-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.AX trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.Bootnet.oc` |
| Fortinet | `ELF/UNSTABLE.AT!tr.botnet` |
| GData | `Linux.Trojan.Mirai.J` |
| Google | `Detected` |
| Ikarus | `Linux.Mirai` |
| Jiangmin | `Backdoor.Linux.itcr` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.ba` |
| MaxSecure | `Backdoor.WIN32.130121.Linux.Mirai.cw.YR` |
| McAfeeD | `Trojan:Script/Mirai.EHI` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Mirai.k` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Trojan.Linux.Mirai.zf` |
| TrellixENS | `Linux/Mirai.k` |
| TrendMicro | `Backdoor.Linux.MIRAI.SMLBO20` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.SMLBO20` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Mirai.CA.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `Backdoor:Linux/Mirai.18722c58` |
| huorong | `Backdoor/Linux.Mirai.u` |

### [4545ec869599f41ff2e4…](https://bazaar.abuse.ch/sample/4545ec869599f41ff2e4236b8d4fe1817d3ff13a1a72509068edf9137264e010/)

- **Familie:** Mirai
- **Erkannt von:** 21 von 74 Engines (28.4%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (21/74):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9853` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.oc` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14B8A (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.iosi` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.na` |

### [fda278f47386da43b5fa…](https://bazaar.abuse.ch/sample/fda278f47386da43b5fa7a6f0b87a3634fd4f39019ae7a4e62539b1aa003131f/)

- **Familie:** Yogi
- **Erkannt von:** 26 von 74 Engines (35.1%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.85599
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.85599`

**Erkennende Engines (26/74):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.85599` |
| APEX | `Malicious` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R797565` |
| Arcabit | `Trojan.Yogi.D14E5F` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.85599` |
| Bkav | `W32.Malware.D69C9014` |
| CTX | `dll.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_100% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/ShellcodeRunner.CQR trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.85599 (B)` |
| GData | `Gen:Variant.Yogi.85599` |
| Google | `Detected` |
| K7AntiVirus | `Trojan ( 006d9bf01 )` |
| K7GW | `Trojan ( 006d9bf01 )` |
| Kaspersky | `VHO:Trojan.Win32.Dllhijack.gen` |
| MicroWorld-eScan | `Gen:Variant.Yogi.85599` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.C!ml` |
| Rising | `Malware.Undefined!8.C (TFE:6:C9WtrIs9t1G)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Tencent | `Trojan.Win64.Shellcoderunner.16009525` |
| VIPRE | `Gen:Variant.Yogi.85599` |
| Varist | `W64/Agent.NQO.gen!Eldorado` |
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

- **elf** (58×)
- **RAT** (45×)
- **EasyShell** (42×)
- **Rust** (42×)
- **SnoopyTriage** (42×)
- **Mirai** (29×)
- **Torii** (18×)
- **exe** (17×)
- **macho** (13×)
- **upx-dec** (6×)
- **upx** (6×)
- **stealer** (6×)
- **WARDENStealer** (5×)
- **SilverFox** (5×)
- **ValleyRAT** (5×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -5 (49→44)
- ↑ **Mirai** +14 (15→29)
- ↑ **EasyShell** +5 (3→8)
- neu: **ValleyRAT** (5)
- ↑ **Prometei** +1 (3→4)
- ↑ **njrat** +1 (3→4)
- ↓ **WARDENStealer** -3 (6→3)
- neu: **Linux** (1)
- neu: **Yogi** (1)
- neu: **WannaCry** (1)
- weg: **Snowlight** (war 9)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +13 (31→44)
- neu: **EasyShell** (8)
- neu: **ValleyRAT** (5)
- ↓ **Prometei** -1 (5→4)
- ↑ **njrat** +2 (2→4)
- ↓ **WARDENStealer** -2 (5→3)
- neu: **Linux** (1)
- neu: **Yogi** (1)
- neu: **WannaCry** (1)
- weg: **AgentTesla** (war 2)
- weg: **RemcosRAT** (war 3)
- weg: **Snowlight** (war 2)
- weg: **FantasyHub** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 8.026 MB |
| σ Dateigröße | 26.918 MB |
| Ø Risiko-Score | 75.4/100 |
| Ø Klassifikations-Konfidenz | 77.3% |
| Samples mit VT | 4/101 |
| Samples mit MITRE | 35/101 |
| Eindeutige Familien | 11 |
| Eindeutige Tags | 36 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:21 | [574ff030b3c9…](https://bazaar.abuse.ch/sample/574ff030b3c98ba192c0bb43af25ca4f59e1c830726bf07e27415776624407d5/) | `elf` | Linux | 65.8 | 55.4% | 🟠 MÄSSIG ERKANNT | 🇳🇱NL |
| 23:20 | [c71bb57d291a…](https://bazaar.abuse.ch/sample/c71bb57d291a1382310630a3751c7a3d4debe4e11838b2c1a73d2ed03f574457/) | `elf` | Mirai | 84.5 | – | – | 🇳🇱NL |
| 23:20 | [c8eb80953b00…](https://bazaar.abuse.ch/sample/c8eb80953b00c3ae023b8985e7356260e2b49b61c257fe118c7b17485c28ea3e/) | `elf` | Mirai | 84.5 | – | – | 🇳🇱NL |
| 23:20 | [8efca1e70034…](https://bazaar.abuse.ch/sample/8efca1e700348dd5d84874c81435d7e2b1f7d62ec7872110921a5c7633838cd2/) | `elf` | unbekannt | 43.3 | – | – | 🇳🇱NL |
| 23:20 | [12da680ed0ef…](https://bazaar.abuse.ch/sample/12da680ed0ef26f45d455d8814a1aa9a1f019b068d7dfbdd5077d21419b215bc/) | `elf` | Mirai | 84.5 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 22.11.2026 23:24 UTC*