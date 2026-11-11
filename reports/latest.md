# MalwareBazaar – 11.11.2026 21:07 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **79** |
| Höchster Score | **93.6/100** – 2479ada8152ee916… |
| Häufigste Familie | **Mirai** (45x) |
| Häufigster Typ | **elf** (51x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 66 Samples |
| Ø Dateigröße | 2.29 MB (σ=10.26) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 51 | 50.5%  ██████████ |
| `vbs` | 15 | 14.9%  ██ |
| `exe` | 12 | 11.9%  ██ |
| `js` | 11 | 10.9%  ██ |
| `sh` | 2 | 2.0%   |
| `zsh` | 2 | 2.0%   |
| `vbe` | 2 | 2.0%   |
| `apk` | 1 | 1.0%   |
| `zip` | 1 | 1.0%   |
| `macho` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 45 | 44.6% |
| 2 | unbekannt | 18 | 17.8% |
| 3 | RemcosRAT | 8 | 7.9% |
| 4 | GuLoader | 7 | 6.9% |
| 5 | njrat | 3 | 3.0% |
| 6 | Formbook | 3 | 3.0% |
| 7 | WARDENStealer | 2 | 2.0% |
| 8 | WannaCry | 2 | 2.0% |
| 9 | LxBaseRAT | 2 | 2.0% |
| 10 | Riskware ( 0053b5231 ) | 1 | 1.0% |
| 11 | MacSync | 1 | 1.0% |
| 12 | Prometei | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 45 | 44.6% | 95% |
| RAT | 16 | 15.8% | 90% |
| Loader | 10 | 9.9% | 89% |
| Infostealer | 8 | 7.9% | 82% |
| Skript/Dropper | 6 | 5.9% | 35% |
| Linux-Malware | 6 | 5.9% | 45% |
| Andere / Unbekannt | 3 | 3.0% | 20% |
| Trojaner | 2 | 2.0% | 70% |
| Windows-Malware | 2 | 2.0% | 35% |
| Ransomware | 2 | 2.0% | 95% |
| Backdoor | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 79 | 78.2% |
| 🟠 HOCH | 5 | 5.0% |
| 🟡 MITTEL | 9 | 8.9% |
| 🟢 NIEDRIG | 8 | 7.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [2479ada8152ee9…](https://bazaar.abuse.ch/sample/2479ada8152ee9164a7876a38d2a447366f428adbdf67a7144239b2872700de3/) | WannaCry | Ransomware | **93.6** | 🔴 KRITISCH | – | – | ? |
| [b759a27d26fabd…](https://bazaar.abuse.ch/sample/b759a27d26fabd52a08a9228dc482a46e9ec941e7b65864133ed6a765cbed654/) | WannaCry | Ransomware | **93.0** | 🔴 KRITISCH | – | – | ? |
| [a12ce4ca958be0…](https://bazaar.abuse.ch/sample/a12ce4ca958be06d0b68fd27c35e02020d7a5f62bc5be64b2a047321e92642d7/) | Gh0stRAT | Backdoor | **88.8** | 🔴 KRITISCH | – | – | ? |
| [086fc2e5e657fb…](https://bazaar.abuse.ch/sample/086fc2e5e657fbceecd209613ea1ca5aff391ed7294233745c5ab8f321abd844/) | njrat | RAT | **86.3** | 🔴 KRITISCH | – | – | ? |
| [e473f95230b6fe…](https://bazaar.abuse.ch/sample/e473f95230b6fe524aad2d2eedd072ff94254e56633503bca44bf6c95e004535/) | njrat | RAT | **86.3** | 🔴 KRITISCH | – | – | ? |
| [e94f8a1cb3f640…](https://bazaar.abuse.ch/sample/e94f8a1cb3f640000abd68cc4ed3f27810c0c4615b9c2488a142ae17039b6de6/) | Formbook | Infostealer | **85.9** | 🔴 KRITISCH | – | – | ? |
| [691c6defbe65e4…](https://bazaar.abuse.ch/sample/691c6defbe65e45ab1f8511bb7b4b331d79ebe32d29e65e3e87e2cd4d51613d7/) | Formbook | Infostealer | **85.9** | 🔴 KRITISCH | – | – | ? |
| [cef2fa3659724d…](https://bazaar.abuse.ch/sample/cef2fa3659724d192b88cbc4ba700af8e768696aa5e15a47f2530cf621d2261c/) | Formbook | Infostealer | **85.8** | 🔴 KRITISCH | 10.7% | 🟡 SCHWACH ERKANNT | ✗ |
| [fda86131b8dc17…](https://bazaar.abuse.ch/sample/fda86131b8dc175bc0d3771cca427b5bb421a0ecf5e99a2cc4869ab35568d65a/) | njrat | RAT | **85.2** | 🔴 KRITISCH | – | – | ? |
| [605efa221edac8…](https://bazaar.abuse.ch/sample/605efa221edac80f0c08c5688591505f1250c458d5ede95306eec7f25010b43b/) | RemcosRAT | RAT | **85.0** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6443/7941 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6443/7941 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6138/7941 |
| 6 | Kaspersky | 75.5% | 5995/7940 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5656/7937 |
| 9 | Rising | 68.4% | 5430/7941 |
| 10 | Varist | 66.1% | 5246/7936 |
| 11 | Avast | 65.2% | 5172/7937 |
| 12 | AVG | 65.2% | 5172/7936 |
| 13 | Tencent | 65.0% | 5012/7715 |
| 14 | McAfeeD | 61.4% | 4870/7933 |
| 15 | huorong | 60.9% | 4833/7933 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 56 | 55.4% |
| 🪟 Windows | 29 | 28.7% |
| ❓ Unbekannt | 13 | 12.9% |
| 🤖 Android | 2 | 2.0% |
| 🍎 macOS | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 74 | 73.3% |
| Drive-By / Exploit-Kit | 19 | 18.8% |
| MaaS-Loader | 4 | 4.0% |
| Exploit / N-Day | 2 | 2.0% |
| APK-Sideloading | 1 | 1.0% |
| Trojanisierte Software | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 47 | 46.5% |
| 2 | 🇸🇪 SE | 27 | 26.7% |
| 3 | 🇺🇸 US | 10 | 9.9% |
| 4 | 🇫🇷 FR | 4 | 4.0% |
| 5 | 🇳🇱 NL | 4 | 4.0% |
| 6 | 🇭🇺 HU | 3 | 3.0% |
| 7 | 🇨🇿 CZ | 1 | 1.0% |
| 8 | 🌐 KE | 1 | 1.0% |
| 9 | 🇨🇭 CH | 1 | 1.0% |
| 10 | 🌐 NO | 1 | 1.0% |
| 11 | 🌐 PT | 1 | 1.0% |
| 12 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 66 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 45 |
| Lateral Movement | 45 |
| Collection | 14 |
| Command and Control | 11 |
| Defense Evasion | 7 |
| Execution | 7 |
| Credential Access | 3 |

<details><summary>086fc2e5e657fbceecd2… – njrat | 🔴 KRITISCH 86.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>e473f95230b6fe524aad… – njrat | 🔴 KRITISCH 86.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [6cfe4f5baf5f0c15da5a…](https://bazaar.abuse.ch/sample/6cfe4f5baf5f0c15da5a24b202d2812a4dbad14e08c0f62af714b2ce73d62d7b/)

- **Familie:** Riskware ( 0053b5231 )
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Riskware ( 0053b5231 )
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| K7AntiVirus | `Riskware ( 0053b5231 )` |
| K7GW | `Riskware ( 0053b5231 )` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Miner.j` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| huorong | `Trojan/Linux.CoinMiner.cn` |

### [ebf474302f8ab146d4e7…](https://bazaar.abuse.ch/sample/ebf474302f8ab146d4e7488f514fdf065eddac459f490deb5669f4ff81ec7d52/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Linux.Prometei.10
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Prometei.10`

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Prometei.10` |
| AVG | `ELF:Prometei-D [Trj]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Prometei` |
| Arcabit | `Trojan.Linux.Prometei.10` |
| Avast | `ELF:Prometei-D [Trj]` |
| Avast-Mobile | `ELF:Prometei-B [Trj]` |
| Avira | `TR/LINUX.Prometei.D` |
| BitDefender 🛡️ | `Trojan.Linux.Prometei.10` |
| CTX | `elf.trojan.prometei` |
| ClamAV | `Unix.Trojan.Prometei-10045459-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.BackDoor.Prometei.12` |
| ESET-NOD32 | `Linux/Prometei.B trojan` |
| Elastic | `Linux.Hacktool.Flooder` |
| Emsisoft | `Trojan.Linux.Prometei.10 (B)` |
| F-Secure | `Trojan.TR/LINUX.Prometei.D` |
| Fortinet | `Linux/Prometei.B!tr` |
| GData | `Trojan.Linux.Prometei.10` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Prometei` |
| Kaspersky | `HEUR:Backdoor.Linux.Prometei.a` |
| McAfeeD | `Trojan:Win/Prometei.P` |
| MicroWorld-eScan | `Trojan.Linux.Prometei.10` |
| Microsoft 🛡️ | `Trojan:Linux/Coinminer.B` |
| Rising | `Backdoor.Prometei/Linux!1.DBE7 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Prometei.c` |
| VIPRE | `Trojan.Linux.Prometei.10` |
| huorong | `Trojan/Prometei.c` |

### [ed2a430026b80a257042…](https://bazaar.abuse.ch/sample/ed2a430026b80a257042a724cfd2a49c2eef734c6aecc24d25c2e42be5900988/)

- **Familie:** LxBaseRAT
- **Erkannt von:** 28 von 75 Engines (37.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** VB:Trojan.AsyncRAT.471
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `VB:Trojan.AsyncRAT.471`

**Erkennende Engines (28/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `VB:Trojan.AsyncRAT.471` |
| AVG | `Script:SNH-gen [Trj]` |
| Arcabit | `VB:Trojan.AsyncRAT.471` |
| Avast | `Script:SNH-gen [Trj]` |
| Avira | `TR/SNH` |
| BitDefender 🛡️ | `VB:Trojan.AsyncRAT.471` |
| CTX | `script.trojan.asyncrat` |
| Cynet | `Malicious (score: 99)` |
| ESET-NOD32 | `VBS/TrojanDropper.Agent.QIN trojan` |
| Emsisoft | `VB:Trojan.AsyncRAT.471 (B)` |
| F-Secure | `Trojan.TR/SNH` |
| Fortinet | `JS/XWorm.AEQQ!tr` |
| GData | `VB:Trojan.AsyncRAT.471` |
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan.Script.Generic` |
| Kingsoft | `Script.Trojan.Generic.a` |
| Lionic | `Trojan.Script.AsyncRAT.4!c` |
| McAfeeD | `ti!ED2A430026B8` |
| MicroWorld-eScan | `VB:Trojan.AsyncRAT.471` |
| Microsoft 🛡️ | `Trojan:Win32/Vigorf.A` |
| Skyhigh | `BehavesLike.VBS.Dropper.cx` |
| Symantec | `CL.Downloader!gen11` |
| Tencent | `Script.Trojan.Generic.Ewnw` |
| VIPRE | `VB:Trojan.AsyncRAT.471` |
| Varist | `VBS/Agent.DDS!Eldorado` |
| Xcitium | `TrojWare.Win32.BadShell.XSP@7pmj0k` |
| huorong | `Trojan/VBS.Obfuscated.hi!crit` |

### [cef2fa3659724d192b88…](https://bazaar.abuse.ch/sample/cef2fa3659724d192b88cbc4ba700af8e768696aa5e15a47f2530cf621d2261c/)

- **Familie:** Formbook
- **Erkannt von:** 8 von 75 Engines (10.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Trojan.Script.Formbook.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (8/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Google | `Detected` |
| Ikarus | `Win32.Outbreak` |
| Kaspersky | `HEUR:Trojan.VBS.Agent.gen` |
| Kingsoft | `Win32.Troj.Undef.a` |
| Lionic | `Trojan.Script.Formbook.4!c` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| Skyhigh | `BehavesLike.VBS.Dropper.gj` |
| Varist | `ABmRisk.EXEL-` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 56 von 75 Engines (74.7%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (56/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avira | `TR/W32.Evo` |
| BitDefender 🛡️ | `Trojan.Generic.39196960` |
| Bkav | `W32.Malware.73B18694` |
| CAT-QuickHeal | `Trojan.Injector` |
| CTX | `exe.trojan.generic` |
| ClamAV | `Win.Trojan.Nymeria-6895336-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| DeepInstinct | `MALICIOUS` |
| DrWeb | `BackDoor.Remcos.28` |
| ESET-NOD32 | `Win32/Injector.Autoit.DTL trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.Generic.39196960 (B)` |
| F-Secure | `Trojan.TR/W32.Evo` |
| Fortinet | `AutoIt/Nymeria.1777!tr` |
| GData | `Win32.Trojan.PSE.1TKG37Z` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `PUA:Win32/Caypnamer.A!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vlth` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (51×)
- **Mirai** (45×)
- **Torii** (34×)
- **vbs** (15×)
- **Prometei** (11×)
- **js** (11×)
- **exe** (11×)
- **RAT** (7×)
- **RemcosRAT** (7×)
- **GuLoader** (7×)
- **cowrie** (3×)
- **honeypot** (3×)
- **dropped-by-OffLoader** (3×)
- **njrat** (3×)
- **Formbook** (3×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +19 (26→45)
- ↓ **unbekannt** -7 (25→18)
- ↑ **RemcosRAT** +4 (4→8)
- ↑ **GuLoader** +4 (3→7)
- neu: **njrat** (3)
- ↑ **Formbook** +1 (2→3)
- ↓ **WARDENStealer** -1 (3→2)
- neu: **WannaCry** (2)
- neu: **LxBaseRAT** (2)
- neu: **Riskware ( 0053b5231 )** (1)
- weg: **SilentNet** (war 5)
- weg: **SalatStealer** (war 17)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +23 (22→45)
- ↓ **unbekannt** -14 (32→18)
- ↑ **RemcosRAT** +5 (3→8)
- ↑ **GuLoader** +6 (1→7)
- neu: **njrat** (3)
- ↑ **Formbook** +1 (2→3)
- ↓ **WARDENStealer** -1 (3→2)
- neu: **WannaCry** (2)
- neu: **LxBaseRAT** (2)
- neu: **Riskware ( 0053b5231 )** (1)
- weg: **SalatStealer** (war 4)
- weg: **RevStealer** (war 2)
- weg: **Snowlight** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 2.294 MB |
| σ Dateigröße | 10.263 MB |
| Ø Risiko-Score | 73.8/100 |
| Ø Klassifikations-Konfidenz | 82.2% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 66/101 |
| Eindeutige Familien | 20 |
| Eindeutige Tags | 64 |
| Unbekannte Familien | 3 (3.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 20:49 | [07623b70e2cd…](https://bazaar.abuse.ch/sample/07623b70e2cd5ae5a12e22522057ec040703983667d4123cf3d54a6efcd8fd8b/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 20:48 | [f53519b515e9…](https://bazaar.abuse.ch/sample/f53519b515e950fc3854c6b21f288fcd5eb24f2ea4ae0acff10be56a2c94e370/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 20:48 | [f05dca7add2b…](https://bazaar.abuse.ch/sample/f05dca7add2b8456d0a2f3d09c817bf361a74e73f7af9874f099ef70a919c1df/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 20:48 | [998cc5e2ad1a…](https://bazaar.abuse.ch/sample/998cc5e2ad1abce47d364acc02b7c01943f8cb2447bcf2c7e35884797f57e7ea/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |
| 20:47 | [6abb545700d0…](https://bazaar.abuse.ch/sample/6abb545700d0bdf54a26f52586035a4e6b611527fd17c2fdcd37acf6550be0a0/) | `elf` | Mirai | 84.3 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 11.11.2026 21:07 UTC*