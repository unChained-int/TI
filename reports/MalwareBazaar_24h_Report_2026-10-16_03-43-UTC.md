# MalwareBazaar – 16.10.2026 03:43 UTC

Dieser Run hat **68 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **69** |
| Kritisch (≥75) | **36** |
| Höchster Score | **95.8/100** – b2f356e15402e11f… |
| Häufigste Familie | **unbekannt** (28x) |
| Häufigster Typ | **exe** (30x) |
| Hauptplattform | **Windows** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 30 Samples |
| Ø Dateigröße | 2.41 MB (σ=4.04) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `exe` | 30 | 43.5%  ████████ |
| `elf` | 26 | 37.7%  ███████ |
| `hta` | 7 | 10.1%  ██ |
| `macho` | 3 | 4.3%   |
| `js` | 1 | 1.4%   |
| `vbs` | 1 | 1.4%   |
| `msi` | 1 | 1.4%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 28 | 40.6% |
| 2 | Mirai | 26 | 37.7% |
| 3 | AMOS | 3 | 4.3% |
| 4 | njrat | 2 | 2.9% |
| 5 | ConnectWise | 1 | 1.4% |
| 6 | CoinMiner | 1 | 1.4% |
| 7 | FileRepMalware [Trj] | 1 | 1.4% |
| 8 | WannaCry | 1 | 1.4% |
| 9 | RustyStealer | 1 | 1.4% |
| 10 | UmbralStealer | 1 | 1.4% |
| 11 | AsyncRAT | 1 | 1.4% |
| 12 | SalatStealer | 1 | 1.4% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 26 | 37.7% | 95% |
| Loader | 13 | 18.8% | 75% |
| Windows-Malware | 9 | 13.0% | 35% |
| Skript/Dropper | 9 | 13.0% | 35% |
| Infostealer | 7 | 10.1% | 84% |
| RAT | 4 | 5.8% | 95% |
| Ransomware | 1 | 1.4% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 36 | 52.2% |
| 🟠 HOCH | 15 | 21.7% |
| 🟡 MITTEL | 18 | 26.1% |
| 🟢 NIEDRIG | 0 | 0.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [b2f356e15402e1…](https://bazaar.abuse.ch/sample/b2f356e15402e11fb6292b91a97f7f9a8f15cb323c5d43423b01bee04eef2746/) | WannaCry | Ransomware | **95.8** | 🔴 KRITISCH | – | – | ? |
| [1e8ed19e771e7a…](https://bazaar.abuse.ch/sample/1e8ed19e771e7a9378daf3b3652802143345db8ea4196e560e54f28176ef958a/) | AMOS | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [3ae3d11cd46ace…](https://bazaar.abuse.ch/sample/3ae3d11cd46aceee81783fb1204c4ae43459e670a8071f76c8a9a5851287a965/) | AMOS | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [e42b8c35db5ab7…](https://bazaar.abuse.ch/sample/e42b8c35db5ab7169327b9185c3e05db4a156e8922b985da61bcbd6223df8aea/) | AMOS | Infostealer | **88.1** | 🔴 KRITISCH | – | – | ? |
| [98379ccde6fc05…](https://bazaar.abuse.ch/sample/98379ccde6fc0517a749bdfb4fa3a384ccc8dbb86f1f4c1ada23a3bf57760d87/) | AsyncRAT | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [51ef64b51fbc68…](https://bazaar.abuse.ch/sample/51ef64b51fbc68f3fdffa43e7c0d89fad5a522a53d5c3930d8145bc96cc62067/) | njrat | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [99abb19b58002a…](https://bazaar.abuse.ch/sample/99abb19b58002ac9bd71b4d097dbcd63d41cc7e7a21e1e5eadac4b4a75acb4fc/) | njrat | RAT | **87.3** | 🔴 KRITISCH | – | – | ? |
| [3240e7ab26be06…](https://bazaar.abuse.ch/sample/3240e7ab26be062b3eba73429916b77a9894fffd76af12ac699a4e15676fc384/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [19a3b7924c8f76…](https://bazaar.abuse.ch/sample/19a3b7924c8f764a4fe6fc2c9fff192f7571cd50023fe37f9cc2ab2f3a4fa091/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [d3ad28e1f88e8a…](https://bazaar.abuse.ch/sample/d3ad28e1f88e8a2d4ad820d5c6ff81605932160197b5831de9d32083a776a40b/) | Mirai | Botnet/IoT | **83.1** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (5991/7406 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 5991/7406 |
| 3 | ESET-NOD32 | 77.5% | 5737/7406 |
| 4 | Kaspersky | 76.4% | 5656/7405 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.6% | 5297/7403 |
| 8 | Rising | 68.8% | 5093/7406 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.5% | 4921/7402 |
| 11 | Tencent | 65.3% | 4692/7180 |
| 12 | Avast | 65.1% | 4819/7402 |
| 13 | AVG | 65.1% | 4819/7401 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4539/7399 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🪟 Windows | 39 | 56.5% |
| 🐧 Linux | 26 | 37.7% |
| 🍎 macOS | 3 | 4.3% |
| ❓ Unbekannt | 1 | 1.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 48 | 69.6% |
| MaaS-Loader | 8 | 11.6% |
| C2 / Nachladen | 7 | 10.1% |
| Trojanisierte Software | 4 | 5.8% |
| Exploit / N-Day | 1 | 1.4% |
| Drive-By / Exploit-Kit | 1 | 1.4% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 25 | 36.2% |
| 2 | 🇺🇸 US | 23 | 33.3% |
| 3 | 🇸🇪 SE | 9 | 13.0% |
| 4 | 🇳🇱 NL | 7 | 10.1% |
| 5 | 🇨🇭 CH | 2 | 2.9% |
| 6 | 🌐 Unbekannt | 2 | 2.9% |
| 7 | 🇫🇷 FR | 1 | 1.4% |

## MITRE ATT&CK

> 30 von 69 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 26 |
| Lateral Movement | 26 |
| Command and Control | 4 |
| Collection | 3 |
| Execution | 1 |

<details><summary>98379ccde6fc0517a749… – AsyncRAT | 🔴 KRITISCH 87.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [3fa014e6a9d11e439b01…](https://bazaar.abuse.ch/sample/3fa014e6a9d11e439b01e1c24263471209be3f5b91129564fe43bff0367191b1/)

- **Familie:** Mirai
- **Erkannt von:** 42 von 75 Engines (56.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Cling.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Cling.1`

**Erkennende Engines (42/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Cling.1` |
| AVG | `ELF:Mirai-ADI [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen15` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Cling.1` |
| Avast | `ELF:Mirai-ADI [Trj]` |
| Avast-Mobile | `ELF:Mirai-FY [Trj]` |
| Avira | `EXP/ELF.Mirai.M` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Cling.1` |
| CTX | `elf.unknown.cling` |
| ClamAV | `Unix.Trojan.Mirai-7100807-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Gen:Variant.Linux.Cling.1 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.M` |
| Fortinet | `ELF/Condi.CDB!tr.botnet` |
| GData | `Gen:Variant.Linux.Cling.1` |
| Google | `Detected` |
| Gridinsoft | `Susp.U.XOREncoded.sd!yf` |
| Ikarus | `Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.cw` |
| MaxSecure | `Trojan.Malware.121218.susgen` |
| McAfeeD | `Trojan:Linux/GenericY.BN` |
| MicroWorld-eScan | `Gen:Variant.Linux.Cling.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Lnx/Mirai-FEBO!1C2655582297` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.waw` |
| TrellixENS | `Lnx/Mirai-FEBO!1C2655582297` |
| TrendMicro | `Backdoor.Linux.MIRAI.SMLBO20` |
| TrendMicro-HouseCall | `Backdoor.Linux.MIRAI.SMLBO20` |
| VIPRE | `Gen:Variant.Linux.Cling.1` |
| Varist | `E32/Mirai.EH.gen!Camelot` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.dh` |

### [2b31b7bdafb0d4c08f51…](https://bazaar.abuse.ch/sample/2b31b7bdafb0d4c08f517882311ff53a597e1b9f09c0473402045dfe636cf5d3/)

- **Familie:** Mirai
- **Erkannt von:** 36 von 75 Engines (48.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Cling.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Cling.1`

**Erkennende Engines (36/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Cling.1` |
| AVG | `ELF:Mirai-CBI [Cryp]` |
| AhnLab-V3 | `Linux/Mirai.Gen15` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Cling.1` |
| Avast | `ELF:Mirai-CBI [Cryp]` |
| Avira | `TR/LINUX.Mirai.CBI` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Cling.1` |
| CTX | `elf.unknown.cling` |
| ClamAV | `Unix.Dropper.Mirai-7135858-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9816` |
| ESET-NOD32 | `Linux/Mirai.A trojan` |
| Emsisoft | `Gen:Variant.Linux.Cling.1 (B)` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CBI` |
| Fortinet | `ELF/Mirai.A!tr` |
| GData | `Gen:Variant.Linux.Cling.1` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Jiangmin | `Backdoor.Linux.bner` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.r` |
| Kingsoft | `Linux.Backdoor.Mirai.r` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `ti!2B31B7BDAFB0` |
| MicroWorld-eScan | `Gen:Variant.Linux.Cling.1` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Gafgyt/Linux!1.12AC3 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.wan` |
| VIPRE | `Gen:Variant.Linux.Cling.1` |
| Varist | `E32/Mirai.BMT` |
| ZoneAlarm | `Linux/DDoS-CI` |
| alibabacloud | `DDOS:Linux/Mirai` |
| huorong | `Backdoor/Linux.Mirai.dh` |

### [39437aaa739756c8fd63…](https://bazaar.abuse.ch/sample/39437aaa739756c8fd63d59e65c7ffa148906cd14fe6d685c2a0a64eec5cd19a/)

- **Familie:** FileRepMalware [Trj]
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Trj]` |
| Avast | `FileRepMalware [Trj]` |
| Bkav | `W32.Malware.3C9D0DE8` |
| CrowdStrike | `win/malicious_confidence_60% (W)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/GenKryptik.HVTH trojan` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/Vidar.YI!tr` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `UDS:Trojan.Win32.Agent` |
| Malwarebytes | `Malware.AI.2700873640` |
| McAfeeD | `ti!39437AAA7397` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Paloalto | `generic.ml` |
| Sangfor | `Trojan.Win32.Agent.Voji` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

### [7e1f8efda2aa1e7eb795…](https://bazaar.abuse.ch/sample/7e1f8efda2aa1e7eb79557ca2275a229a76b55fb98e191d310e5b8e4ad38b954/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Gafgyt-MV [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Gafgyt-MV [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Gafgyt-MV [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| ClamAV | `Unix.Trojan.Mirai-9858729-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.CJS trojan` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.A!tr` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Multiverze` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| Kingsoft | `Linux.Backdoor.Mirai.b` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/Mirai.EQY` |
| Microsoft 🛡️ | `Trojan:Linux/Mirai.HAV!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.144FF (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Tencent | `Backdoor.Linux.Mirai.bktra` |
| Varist | `E32/Mirai.DO.gen!Eldorado` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Trojan/Linux.Mirai.l` |

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

- **exe** (29×)
- **elf** (26×)
- **Mirai** (26×)
- **signed** (12×)
- **msstore** (8×)
- **WailsLoader** (8×)
- **hta** (7×)
- **telegram-version** (7×)
- **dropped-by-GCleaner** (6×)
- **upx-dec** (6×)
- **upx** (6×)
- **Unpacked** (5×)
- **revoked-cert** (4×)
- **AMOS** (3×)
- **ClickFix** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +11 (17→28)
- ↑ **Mirai** +12 (14→26)
- ↑ **AMOS** +2 (1→3)
- ↑ **njrat** +1 (1→2)
- neu: **ConnectWise** (1)
- neu: **CoinMiner** (1)
- neu: **FileRepMalware [Trj]** (1)
- neu: **WannaCry** (1)
- neu: **RustyStealer** (1)
- neu: **UmbralStealer** (1)
- weg: **Formbook** (war 2)
- weg: **DDoSAgent** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **unbekannt** +1 (27→28)
- ↓ **Mirai** -7 (33→26)
- ↑ **AMOS** +2 (1→3)
- neu: **njrat** (2)
- neu: **FileRepMalware [Trj]** (1)
- neu: **RustyStealer** (1)
- neu: **UmbralStealer** (1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.413 MB |
| σ Dateigröße | 4.043 MB |
| Ø Risiko-Score | 68.6/100 |
| Ø Klassifikations-Konfidenz | 74.4% |
| Samples mit VT | 5/69 |
| Samples mit MITRE | 30/69 |
| Eindeutige Familien | 14 |
| Eindeutige Tags | 59 |
| Unbekannte Familien | 0 (0.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:19 | [b1cc5ad78b72…](https://bazaar.abuse.ch/sample/b1cc5ad78b72d2f0a94d370e840e24ea38a31690ece3af851da345975da7ca5c/) | `exe` | unbekannt | 74.7 | – | – | 🇺🇸US |
| 02:57 | [51c23cd7ae3b…](https://bazaar.abuse.ch/sample/51c23cd7ae3be097ad412657d6e03b4794fbc19853da07f24609fb7148610a5f/) | `exe` | ConnectWise | 74.4 | – | – | 🇺🇸US |
| 02:29 | [8bdb3ce10dee…](https://bazaar.abuse.ch/sample/8bdb3ce10dee7a3249a186050d7f804bca19859f292ddad7ae8c5afbb649a07b/) | `exe` | unbekannt | 38.0 | – | – | 🇺🇸US |
| 02:28 | [0e6d59fcdf8f…](https://bazaar.abuse.ch/sample/0e6d59fcdf8f143e23b076cc8380d6d23324839ae4f91793133b600e7eb76eb9/) | `exe` | unbekannt | 38.0 | – | – | 🇺🇸US |
| 02:28 | [0b8b6f4f9050…](https://bazaar.abuse.ch/sample/0b8b6f4f90506e651044cd2e4d953c313b4eab187865c6b6b8d51b03e72c4339/) | `exe` | unbekannt | 38.0 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 16.10.2026 03:43 UTC*