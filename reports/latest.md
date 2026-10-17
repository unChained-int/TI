# MalwareBazaar – 17.10.2026 03:33 UTC

Dieser Run hat **79 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `ec00d75b13137b4a6ee5…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **80** |
| Kritisch (≥75) | **56** |
| Höchster Score | **89.1/100** – 5861d36ffa3c3dee… |
| Häufigste Familie | **Mirai** (40x) |
| Häufigster Typ | **elf** (52x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 46 Samples |
| Ø Dateigröße | 1.74 MB (σ=3.45) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 52 | 65.0%  █████████████ |
| `exe` | 19 | 23.8%  ████ |
| `macho` | 6 | 7.5%  █ |
| `sh` | 2 | 2.5%   |
| `msi` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 40 | 50.0% |
| 2 | unbekannt | 26 | 32.5% |
| 3 | AMOS | 6 | 7.5% |
| 4 | Vidar | 3 | 3.8% |
| 5 | NanoCore | 1 | 1.2% |
| 6 | ValleyRAT | 1 | 1.2% |
| 7 | GhostPulse | 1 | 1.2% |
| 8 | ConnectWise | 1 | 1.2% |
| 9 | RemcosRAT | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 40 | 50.0% | 95% |
| Infostealer | 13 | 16.2% | 89% |
| Linux-Malware | 12 | 15.0% | 45% |
| Loader | 7 | 8.8% | 78% |
| Windows-Malware | 3 | 3.8% | 35% |
| RAT | 3 | 3.8% | 88% |
| Andere / Unbekannt | 2 | 2.5% | 20% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 56 | 70.0% |
| 🟠 HOCH | 8 | 10.0% |
| 🟡 MITTEL | 14 | 17.5% |
| 🟢 NIEDRIG | 2 | 2.5% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [5861d36ffa3c3d…](https://bazaar.abuse.ch/sample/5861d36ffa3c3deea7ab3b6a1faf4ee0af5dde2ae9fe491bdbb6b34c4125b7bc/) | AMOS | Infostealer | **89.1** | 🔴 KRITISCH | – | – | ? |
| [3425587876d45c…](https://bazaar.abuse.ch/sample/3425587876d45c0a1eaea90741b0f1a8e490af891ce848bfc5b685683a6d2533/) | NanoCore | RAT | **88.9** | 🔴 KRITISCH | – | – | ? |
| [322a9bdadc796f…](https://bazaar.abuse.ch/sample/322a9bdadc796f2b2a7459b949ff367ed3258e9a8eefb1af161b557418ce845d/) | AMOS | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [5b3c6ec6e558bf…](https://bazaar.abuse.ch/sample/5b3c6ec6e558bf2e4dcff9b8f810fc5522cb9ab6271522c2ce8b0f140151ba8b/) | AMOS | Infostealer | **88.3** | 🔴 KRITISCH | – | – | ? |
| [51ad0fe8782d97…](https://bazaar.abuse.ch/sample/51ad0fe8782d9756f1fc647bfd19e649b1b3e55e8b641a295062c935c1939bd8/) | AMOS | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [ecf0f6b181632f…](https://bazaar.abuse.ch/sample/ecf0f6b181632fb335c800bcc77cccc5584bc15b5ac594dc68019f05081c3d5d/) | AMOS | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [3bf9ac9cb26ecf…](https://bazaar.abuse.ch/sample/3bf9ac9cb26ecffd2ab26bb14c81c110b53fe31c196cc774291ad4af804023c3/) | AMOS | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [fbeacf6c0412e4…](https://bazaar.abuse.ch/sample/fbeacf6c0412e4a610b4dcde1d6156c18dccf100003799ccc0703069e0419786/) | Vidar | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [975f5c0dd3dc7f…](https://bazaar.abuse.ch/sample/975f5c0dd3dc7fc5ad3c42c296fc44dca55dfc9480b9335752cc4e099d93bcf2/) | Vidar | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [ff8a872e26abc2…](https://bazaar.abuse.ch/sample/ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 80.9% Erkennungsrate (6009/7430 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.3% | 21/23 |
| 2 | Microsoft 🛡️ | 80.9% | 6009/7430 |
| 3 | ESET-NOD32 | 77.4% | 5751/7430 |
| 4 | Kaspersky | 76.3% | 5671/7429 |
| 5 | McAfee-GW-Edition | 75.0% | 3/4 |
| 6 | MAX | 75.0% | 6/8 |
| 7 | Google | 71.5% | 5312/7427 |
| 8 | Rising | 68.7% | 5106/7430 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.4% | 4933/7426 |
| 11 | Tencent | 65.3% | 4705/7204 |
| 12 | Avast | 65.1% | 4836/7426 |
| 13 | AVG | 65.1% | 4836/7425 |
| 14 | BitDefenderTheta 🛡️ | 62.5% | 5/8 |
| 15 | McAfeeD | 61.3% | 4552/7423 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 54 | 67.5% |
| 🪟 Windows | 20 | 25.0% |
| 🍎 macOS | 6 | 7.5% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 67 | 83.8% |
| C2 / Nachladen | 6 | 7.5% |
| MaaS-Loader | 5 | 6.2% |
| Drive-By / Exploit-Kit | 1 | 1.2% |
| Trojanisierte Software | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 33 | 41.2% |
| 2 | 🇩🇪 DE | 33 | 41.2% |
| 3 | 🇳🇱 NL | 6 | 7.5% |
| 4 | 🇨🇭 CH | 4 | 5.0% |
| 5 | 🇫🇷 FR | 2 | 2.5% |
| 6 | 🇬🇧 GB | 1 | 1.2% |
| 7 | 🌐 Unbekannt | 1 | 1.2% |

## MITRE ATT&CK

> 46 von 80 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 40 |
| Lateral Movement | 40 |
| Collection | 5 |
| Credential Access | 4 |
| Exfiltration | 4 |
| Execution | 1 |
| Persistence | 1 |
| Command and Control | 1 |


## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [e9af652d27614eb8a767…](https://bazaar.abuse.ch/sample/e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78/)

- **Familie:** Vidar
- **Erkannt von:** 46 von 75 Engines (61.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.80916859
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.80916859`

**Erkennende Engines (46/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.80916859` |
| AVG | `Win64:Evo-gen [Trj]` |
| AhnLab-V3 | `Trojan/Win.Generic.R773315` |
| Alibaba | `Trojan:Win64/GenKryptik.00adc44f` |
| Antiy-AVL | `Trojan/Win64.GenKryptik` |
| Arcabit | `Trojan.Generic.D4D2B17B` |
| Avast | `Win64:Evo-gen [Trj]` |
| Avira | `TR/W64.Evo` |
| BitDefender 🛡️ | `Trojan.GenericKD.80916859` |
| Bkav | `W32.Malware.441CCBEA` |
| CTX | `dll.trojan.kryptik` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `WinGo/Kryptik.VN trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.80916859 (B)` |
| F-Secure | `Trojan.TR/W64.Evo` |
| Fortinet | `W64/MALD2.3301!tr` |
| GData | `Trojan.GenericKD.80916859` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Crypt` |
| K7AntiVirus | `Trojan ( 006df3b41 )` |
| K7GW | `Trojan ( 006df3b41 )` |
| Kaspersky | `HEUR:Trojan.Win32.Agent.pef` |
| Kingsoft | `Win32.Trojan.Agent.pef` |
| Lionic | `Trojan.Win32.Agent.Y!c` |
| Malwarebytes | `Trojan.Loader` |
| McAfeeD | `Trojan:Win/Dllhijack.EAT` |
| MicroWorld-eScan | `Trojan.GenericKD.80916859` |
| Microsoft 🛡️ | `Trojan:Win64/GoCrypt.C!MTB` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.ShellCodeRunner/x64!1.147B3 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Troj/Krypt-AYR` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Backdoor.Win64.Gsb.16004167` |
| TrellixENS | `Artemis!835501773C0B` |
| TrendMicro | `TrojanSpy.Win64.VIDAR.YXGGWZ` |
| TrendMicro-HouseCall | `TrojanSpy.Win64.VIDAR.YXGGWZ` |
| VBA32 | `Trojan.Agent` |
| VIPRE | `Trojan.GenericKD.80916859` |
| Varist | `W64/Agent.MMK.gen!Eldorado` |
| ZoneAlarm | `Troj/Krypt-AYR` |
| alibabacloud | `Trojan:Win/Wacatac.B9nj` |
| huorong | `Trojan/W64.Agent.bs!crit` |

### [453505bf331a5646152b…](https://bazaar.abuse.ch/sample/453505bf331a5646152b88692dd2e3d9e40f61b2ac97945f78c76f05ad5a57a0/)

- **Familie:** Mirai
- **Erkannt von:** 27 von 75 Engines (36.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** GenericRXIA-RS!595BA47A3F6A
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (27/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-AM [Trj]` |
| AhnLab-V3 | `Linux/Miraidown.Gen` |
| Antiy-AVL | `Trojan[Downloader]/Linux.Mirai` |
| Avast | `ELF:Mirai-AM [Trj]` |
| Avast-Mobile | `ELF:MiraiDownloader-QG [Trj]` |
| Avira | `TR/LINUX.Mirai.AM` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9779` |
| ESET-NOD32 | `Linux/TrojanDownloader.Mirai.A trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.AM` |
| Fortinet | `ELF/Mirai.A!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Mirai` |
| Kaspersky | `HEUR:Trojan-Downloader.Linux.Mirai.d` |
| Kingsoft | `Linux.Trojan-Downloader.Mirai.d` |
| McAfeeD | `ti!453505BF331A` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.GN!MTB` |
| Rising | `Backdoor.Mirai/Linux!8.13285 (TFE:14:JgdOskqJ8dF)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| Skyhigh | `GenericRXIA-RS!595BA47A3F6A` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.MiraiDownload.ve` |
| TrellixENS | `GenericRXIA-RS!595BA47A3F6A` |
| TrendMicro | `Possible_MIRAIDLOD.SMLBAT5` |
| TrendMicro-HouseCall | `Possible_MIRAIDLOD.SMLBAT5` |
| VirIT | `Linux.DownLoader.OA` |
| huorong | `Trojan/Linux.Mirai.q` |

### [400a6316ccd012a0cb46…](https://bazaar.abuse.ch/sample/400a6316ccd012a0cb468f44790f73e326db4acca66645c0c8c4ed0f7fc53da1/)

- **Familie:** unbekannt
- **Erkannt von:** 0 von 75 Engines (0.0%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** –
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

### [a0db0b57eaa2b978651c…](https://bazaar.abuse.ch/sample/a0db0b57eaa2b978651c7c3f4c3c63b382fcc66a03f2a8031f423c21ba97f378/)

- **Familie:** Mirai
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-DNH [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-DNH [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-DNH [Trj]` |
| DrWeb | `Linux.Mirai.10456` |
| ESET-NOD32 | `Linux/Mirai.FLQ trojan` |
| Jiangmin | `Backdoor.Linux.bner` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.jp` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Rising | `Backdoor.Mirai/Linux!1.11723 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.DDoS.pa` |
| huorong | `Trojan/Linux.Mirai.mq` |

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

- **elf** (52×)
- **Mirai** (39×)
- **exe** (18×)
- **wraith** (6×)
- **AMOS** (6×)
- **ClickFix** (6×)
- **Foxveil** (6×)
- **Mach-O** (6×)
- **macho** (6×)
- **macOS** (6×)
- **dropped-by-GCleaner** (6×)
- **loader** (5×)
- **upx-dec** (4×)
- **upx** (4×)
- **DvnX** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +25 (15→40)
- ↓ **unbekannt** -5 (31→26)
- ↑ **AMOS** +5 (1→6)
- ↑ **Vidar** +2 (1→3)
- neu: **NanoCore** (1)
- neu: **ValleyRAT** (1)
- neu: **GhostPulse** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +10 (30→40)
- ↓ **unbekannt** -1 (27→26)
- ↑ **AMOS** +5 (1→6)
- ↑ **Vidar** +2 (1→3)
- neu: **NanoCore** (1)
- neu: **GhostPulse** (1)
- ↓ **RemcosRAT** -1 (2→1)
- weg: **Formbook** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.738 MB |
| σ Dateigröße | 3.447 MB |
| Ø Risiko-Score | 72.9/100 |
| Ø Klassifikations-Konfidenz | 80.6% |
| Samples mit VT | 5/80 |
| Samples mit MITRE | 46/80 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 49 |
| Unbekannte Familien | 2 (2.5%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 03:22 | [e9af652d2761…](https://bazaar.abuse.ch/sample/e9af652d27614eb8a76788f0537350c3ec8aa23da38e8a57599cab1791c74c78/) | `exe` | Vidar | 77.7 | 61.3% | 🟠 MÄSSIG ERKANNT | 🌐CH |
| 03:22 | [37ddd1a7b72f…](https://bazaar.abuse.ch/sample/37ddd1a7b72fdb4986d966157ac085035b32d8cc3f84edef61808dec7158e12f/) | `exe` | unbekannt | 39.0 | – | – | 🌐CH |
| 03:17 | [d7234d9249e7…](https://bazaar.abuse.ch/sample/d7234d9249e7cc454cc684c0e7b124a32f4df870e1cac86188d8eeaf36f6819c/) | `sh` | unbekannt | 32.5 | – | – | 🇬🇧GB |
| 03:16 | [ff8a872e26ab…](https://bazaar.abuse.ch/sample/ff8a872e26abc29f664ea497c0c589c04ffeca3b036785f141149ee78044f661/) | `elf` | Mirai | 84.3 | – | – | 🇺🇸US |
| 02:58 | [453505bf331a…](https://bazaar.abuse.ch/sample/453505bf331a5646152b88692dd2e3d9e40f61b2ac97945f78c76f05ad5a57a0/) | `elf` | Mirai | 79.2 | 36.0% | 🟡 SCHWACH ERKANNT | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 17.10.2026 03:33 UTC*