# MalwareBazaar – 18.10.2026 17:09 UTC

Dieser Run hat **44 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **45** |
| Kritisch (≥75) | **20** |
| Höchster Score | **89.2/100** – 85fce9826974549c… |
| Häufigste Familie | **unbekannt** (24x) |
| Häufigster Typ | **elf** (16x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 4 Samples |
| MITRE gemappt | 17 Samples |
| Ø Dateigröße | 1.88 MB (σ=4.11) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 16 | 35.6%  ███████ |
| `jar` | 11 | 24.4%  ████ |
| `exe` | 11 | 24.4%  ████ |
| `sh` | 5 | 11.1%  ██ |
| `macho` | 1 | 2.2%   |
| `zsh` | 1 | 2.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 24 | 53.3% |
| 2 | Mirai | 16 | 35.6% |
| 3 | AMOS | 2 | 4.4% |
| 4 | Yogi | 1 | 2.2% |
| 5 | FileRepMalware [Misc] | 1 | 2.2% |
| 6 | RemcosRAT | 1 | 2.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 16 | 35.6% | 95% |
| Andere / Unbekannt | 11 | 24.4% | 20% |
| Loader | 11 | 24.4% | 75% |
| Infostealer | 5 | 11.1% | 81% |
| Cryptominer | 1 | 2.2% | 75% |
| RAT | 1 | 2.2% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 20 | 44.4% |
| 🟠 HOCH | 14 | 31.1% |
| 🟡 MITTEL | 0 | 0.0% |
| 🟢 NIEDRIG | 11 | 24.4% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [85fce982697454…](https://bazaar.abuse.ch/sample/85fce9826974549c2dd4c92a3207cf2543e10676ad2dfad7c8ea429f616cdf21/) | AMOS | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [6e9fda95863ee9…](https://bazaar.abuse.ch/sample/6e9fda95863ee943003d1b2ce25f4877f03c08d0cbfdaad1946450b6f4006fc2/) | AMOS | Infostealer | **89.2** | 🔴 KRITISCH | – | – | ? |
| [d01d6a5ae13395…](https://bazaar.abuse.ch/sample/d01d6a5ae13395dbb373d81898a808df3c927f1356573b6a077cabd4fa8968f6/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [594da4cf0e1c77…](https://bazaar.abuse.ch/sample/594da4cf0e1c77ac193abbb3753392725c6cb7c767b8576553383277cfdfe575/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [f36c38c0bc237a…](https://bazaar.abuse.ch/sample/f36c38c0bc237aa2dfd272a61aaff579f9f1cbd405d7ac5846db6efc10e28583/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [861946c9eca3fb…](https://bazaar.abuse.ch/sample/861946c9eca3fb11440db3d51868c9a4af6c75c48bfd70a8a34a55fae63feed0/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [888d245e689dbc…](https://bazaar.abuse.ch/sample/888d245e689dbcb40a1b41187991ce0320a78014968230b9f14283cdea445aba/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [617aec4b793f43…](https://bazaar.abuse.ch/sample/617aec4b793f439c2dac557740d6e1e03e26c40da858d1e4ed3df818bfc37952/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [89b323a8bf22b5…](https://bazaar.abuse.ch/sample/89b323a8bf22b5dc51851a4d1c63f0d01225429341724136dd1e32a15ba302fd/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |
| [56c6fd0a590a5b…](https://bazaar.abuse.ch/sample/56c6fd0a590a5bc2686194e6f889646f06ff2f636434ebcc59e52c695a894d25/) | Mirai | Botnet/IoT | **82.9** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6043/7472 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6043/7472 |
| 3 | ESET-NOD32 | 77.4% | 5783/7472 |
| 4 | Kaspersky | 76.3% | 5702/7471 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.4% | 5336/7469 |
| 8 | Rising | 68.7% | 5132/7472 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.3% | 4951/7468 |
| 11 | Tencent | 65.2% | 4728/7246 |
| 12 | Avast | 65.2% | 4866/7468 |
| 13 | AVG | 65.2% | 4866/7467 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.2% | 4572/7465 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 22 | 48.9% |
| ❓ Unbekannt | 11 | 24.4% |
| 🪟 Windows | 11 | 24.4% |
| 🍎 macOS | 1 | 2.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 34 | 75.6% |
| C2 / Nachladen | 6 | 13.3% |
| MaaS-Loader | 5 | 11.1% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 21 | 46.7% |
| 2 | 🇩🇪 DE | 16 | 35.6% |
| 3 | 🇳🇱 NL | 5 | 11.1% |
| 4 | 🌐 PT | 2 | 4.4% |
| 5 | 🌐 Unbekannt | 1 | 2.2% |

## MITRE ATT&CK

> 17 von 45 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 16 |
| Lateral Movement | 16 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>d01d6a5ae13395dbb373… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>594da4cf0e1c77ac193a… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>f36c38c0bc237aa2dfd2… – Mirai | 🔴 KRITISCH 82.9/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [f38cbf013bc2dfc1e6c7…](https://bazaar.abuse.ch/sample/f38cbf013bc2dfc1e6c75dfb40690a9ed5fb15e8157549068d6cf70e09c01138/)

- **Familie:** Mirai
- **Erkannt von:** 43 von 75 Engines (57.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.380
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.380`

**Erkennende Engines (43/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.380` |
| AVG | `ELF:Gafgyt-KS [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.380` |
| Avast | `ELF:Gafgyt-KS [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-KS [Trj]` |
| Avira | `EXP/ELF.Gafgyt.D` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.380` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Dropper.Mirai-7136013-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Linux.Mirai.380 (B)` |
| F-Secure | `Exploit.EXP/ELF.Gafgyt.D` |
| Fortinet | `ELF/Condi.CDB!tr.botnet` |
| GData | `Trojan.Linux.Mirai.380` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Jiangmin | `Backdoor.Linux.idyn` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.380` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.128BE (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Linux/Mirai-FROZ!71282F83D7BE` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.ck` |
| TrellixENS | `Linux/Mirai-FROZ!71282F83D7BE` |
| TrendMicro | `Backdoor.Linux.MIRAI.SMLBO20` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.SMLBO20` |
| VBA32 | `Trojan.Linux.Mirai` |
| VIPRE | `Trojan.Linux.Mirai.380` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai.5b1cc3ca` |
| huorong | `Trojan/Linux.Mirai.q!crit` |

### [2bbbdde62f2b4ceb29e6…](https://bazaar.abuse.ch/sample/2bbbdde62f2b4ceb29e62fb20197bdd140f354ac51c346a8bf505cee059f6465/)

- **Familie:** Yogi
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.64168
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.64168`

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.64168` |
| APEX | `Malicious` |
| AVG | `Win64:Agent-KZ [Hack]` |
| Arcabit | `Trojan.Yogi.DFAA8` |
| Avast | `Win64:Agent-KZ [Hack]` |
| Avira | `TR/W64.Agent.KZ` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.64168` |
| Bkav | `W32.Malware.8A79611E` |
| CTX | `dll.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_90% (D)` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/HackTool.PSWDump.M trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.64168 (B)` |
| F-Secure | `Trojan.TR/W64.Agent.KZ` |
| GData | `Gen:Variant.Yogi.64168` |
| K7AntiVirus | `Password-Stealer ( 006d9d151 )` |
| K7GW | `Password-Stealer ( 006d9d151 )` |
| Kaspersky | `VHO:Trojan-PSW.Win64.BroPass.gen` |
| McAfeeD | `Trojan:Win/ChromStealer.AA` |
| MicroWorld-eScan | `Gen:Variant.Yogi.64168` |
| Rising | `HackTool.ChromElevator!1.1437F (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win64.Dropper.tc` |
| Symantec | `ML.Attribute.HighConfidence` |
| VIPRE | `Gen:Variant.Yogi.64168` |

### [0059a3866d1902467dd4…](https://bazaar.abuse.ch/sample/0059a3866d1902467dd4fe64108aefd5c7fd2856a794a251c2b28004a92257b9/)

- **Familie:** FileRepMalware [Misc]
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Misc]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Misc]` |
| Avast | `FileRepMalware [Misc]` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Elastic | `malicious (high confidence)` |
| Kaspersky | `UDS:Trojan.Win32.Shellcode` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Rising | `Backdoor.Agent!8.C5D (CLOUD)` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| VirIT | `Trojan.Win64.Gen_Heur.C` |
| Webroot | `W32.Malware.gen` |

### [ec00d75b13137b4a6ee5…](https://bazaar.abuse.ch/sample/ec00d75b13137b4a6ee59c42acb2a49bee8b72092de446f0faa0d3ac487af3a4/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 61 von 75 Engines (81.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Gen:Variant.Remcos.23
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Remcos.23`

**Erkennende Engines (61/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Remcos.23` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Rat]` |
| AhnLab-V3 | `Backdoor/Win.Remcos.R759692` |
| Alibaba | `Backdoor:Win32/Rescoms.0facbd80` |
| Antiy-AVL | `Trojan[Backdoor]/Win32.Remcos` |
| Arcabit | `Trojan.Remcos.23` |
| Avast | `Win32:MalwareX-gen [Rat]` |
| Avira | `BDS/Backdoor.Gen` |
| BitDefender 🛡️ | `Gen:Variant.Remcos.23` |
| Bkav | `W32.Malware.D80B3EFB` |
| CAT-QuickHeal | `Trojan.Remcos.S39598516` |
| CTX | `exe.trojan.remcos` |
| ClamAV | `Win.Trojan.Remcos-9841897-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.630` |
| ESET-NOD32 | `Win32/Rescoms.B trojan` |
| Elastic | `Windows.Trojan.Remcos` |
| Emsisoft | `Gen:Variant.Remcos.23 (B)` |
| F-Secure | `Backdoor.BDS/Backdoor.Gen` |
| Fortinet | `W32/Rescomms.B!tr` |
| GData | `Gen:Variant.Remcos.23` |
| Google | `Detected` |
| Gridinsoft | `Backdoor.Win32.Remcos.oa!s1` |
| Ikarus | `Backdoor.Remcos` |
| K7AntiVirus | `Backdoor ( 005ce3801 )` |
| K7GW | `Backdoor ( 005ce3801 )` |
| Kaspersky | `HEUR:Backdoor.Win32.Remcos.gen` |
| Kingsoft | `Win32.Hack.Remcos.gen` |
| Lionic | `Trojan.Win32.Rescoms.m!c` |
| Malwarebytes | `Backdoor.Remcos` |
| MaxSecure | `Trojan.Malware.300983.susgen` |
| McAfeeD | `Real Protect-LS!D532A55294F7` |
| MicroWorld-eScan | `Gen:Variant.Remcos.23` |
| Microsoft 🛡️ | `Trojan:Win32/Rescoms.ZBH!MTB` |
| NANO-Antivirus | `Trojan.Win32.Remcos.lhikll` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Backdoor.Remcos!1.BAC7 (CLASSIC)` |
| SUPERAntiSpyware | `Backdoor.Bot/Variant` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.hh` |
| Sophos | `Troj/Remcos-APM` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Trojan.Win32.Remcos.16001234` |
| TrellixENS | `RAT/Remcos!D532A55294F7` |
| TrendMicro | `Backdoor.Win32.REMCOS.USBLJB26` |
| TrendMicro-HouseCall | `Trojan.Win32.VSX.PE04CAF` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Gen:Variant.Remcos.23` |
| Varist | `W32/Agent.JUB.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.527872.B` |
| Webroot | `Win.Trojan.Remcos` |
| Yandex | `Trojan.Rescoms!YLGvWb0ztTM` |
| ZoneAlarm | `Troj/Remcos-APM` |
| alibabacloud | `Backdoor:Win/Remcos.D` |
| huorong | `Backdoor/Remcos.k` |


## Top Tags

- **elf** (16×)
- **Mirai** (16×)
- **jar** (11×)
- **java** (10×)
- **exe** (10×)
- **python** (8×)
- **silentnet** (8×)
- **upx-dec** (5×)
- **upx** (5×)
- **sh** (5×)
- **dropped-by-GCleaner** (4×)
- **downloader** (3×)
- **korexnode** (2×)
- **AMOS** (2×)
- **ClickFix** (2×)

## Änderungen – 24h-Vergleich

- ↓ **unbekannt** -4 (28→24)
- ↓ **Mirai** -7 (23→16)
- neu: **Yogi** (1)
- neu: **FileRepMalware [Misc]** (1)
- ↓ **RemcosRAT** -1 (2→1)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -4 (28→24)
- ↓ **Mirai** -11 (27→16)
- ↑ **AMOS** +1 (1→2)
- neu: **Yogi** (1)
- neu: **FileRepMalware [Misc]** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.879 MB |
| σ Dateigröße | 4.112 MB |
| Ø Risiko-Score | 66.9/100 |
| Ø Klassifikations-Konfidenz | 69.8% |
| Samples mit VT | 4/45 |
| Samples mit MITRE | 17/45 |
| Eindeutige Familien | 6 |
| Eindeutige Tags | 40 |
| Unbekannte Familien | 11 (24.4%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 17:05 | [d01d6a5ae133…](https://bazaar.abuse.ch/sample/d01d6a5ae13395dbb373d81898a808df3c927f1356573b6a077cabd4fa8968f6/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 16:46 | [594da4cf0e1c…](https://bazaar.abuse.ch/sample/594da4cf0e1c77ac193abbb3753392725c6cb7c767b8576553383277cfdfe575/) | `elf` | Mirai | 84.2 | – | – | 🇩🇪DE |
| 16:36 | [55e752670ec4…](https://bazaar.abuse.ch/sample/55e752670ec450ecb29c3c21f3f683e13ce7d51d0025fcff2c5f7d70ee045487/) | `jar` | unbekannt | 32.2 | – | – | 🇺🇸US |
| 16:36 | [1d78a96f98a7…](https://bazaar.abuse.ch/sample/1d78a96f98a707c3aaba5badf6caea0f0296fcb8de09134a41899800243a1651/) | `jar` | unbekannt | 32.2 | – | – | 🇺🇸US |
| 16:20 | [9af7b019d2ee…](https://bazaar.abuse.ch/sample/9af7b019d2eec68e5ac23de89013dcae5c850a60afcdb56fe6f7d782818f869e/) | `jar` | unbekannt | 32.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 18.10.2026 17:09 UTC*