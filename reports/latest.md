# MalwareBazaar – 12.11.2026 21:21 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `065cfe7c9627cdef0dad…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **73** |
| Höchster Score | **95.3/100** – c95d33d89a1b1bf1… |
| Häufigste Familie | **Mirai** (57x) |
| Häufigster Typ | **elf** (73x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 58 Samples |
| Ø Dateigröße | 3.38 MB (σ=15.88) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 73 | 72.3%  ██████████████ |
| `exe` | 21 | 20.8%  ████ |
| `jar` | 3 | 3.0%   |
| `msi` | 1 | 1.0%   |
| `sh` | 1 | 1.0%   |
| `html` | 1 | 1.0%   |
| `lnk` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 57 | 56.4% |
| 2 | unbekannt | 25 | 24.8% |
| 3 | SalatStealer | 6 | 5.9% |
| 4 | WARDENStealer | 4 | 4.0% |
| 5 | SilentNet | 2 | 2.0% |
| 6 | Socks5Systemz | 1 | 1.0% |
| 7 | WannaCry | 1 | 1.0% |
| 8 | Panchan | 1 | 1.0% |
| 9 | kkRAT | 1 | 1.0% |
| 10 | XorDDoS | 1 | 1.0% |
| 11 | CoinMiner | 1 | 1.0% |
| 12 | RemcosRAT | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 58 | 57.4% | 95% |
| Linux-Malware | 15 | 14.9% | 45% |
| Infostealer | 12 | 11.9% | 75% |
| Windows-Malware | 6 | 5.9% | 35% |
| Andere / Unbekannt | 4 | 4.0% | 20% |
| RAT | 3 | 3.0% | 82% |
| Ransomware | 1 | 1.0% | 95% |
| Post-Exploitation | 1 | 1.0% | 75% |
| Cryptominer | 1 | 1.0% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 73 | 72.3% |
| 🟠 HOCH | 3 | 3.0% |
| 🟡 MITTEL | 21 | 20.8% |
| 🟢 NIEDRIG | 4 | 4.0% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [c95d33d89a1b1b…](https://bazaar.abuse.ch/sample/c95d33d89a1b1bf175a7a278cefd307ad396868b462d26ca25c3c75a282222c3/) | WannaCry | Ransomware | **95.3** | 🔴 KRITISCH | – | – | ? |
| [abc27cc99ef167…](https://bazaar.abuse.ch/sample/abc27cc99ef167b4d3aa3648d696bd7068e9ab9d147934cd422f9ad8b5d49169/) | unbekannt | Post-Exploitat | **83.9** | 🔴 KRITISCH | – | – | ? |
| [258cb7c5321edf…](https://bazaar.abuse.ch/sample/258cb7c5321edf640b597623f76204aa3cb60ee8945c89748fa01b0fec5d74c1/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [61e3d5824f6774…](https://bazaar.abuse.ch/sample/61e3d5824f6774751409577b1952efec8b8f658de291dd28b3b86b6a8169007d/) | Mirai | Botnet/IoT | **83.5** | 🔴 KRITISCH | – | – | ? |
| [1d80331fddf9f2…](https://bazaar.abuse.ch/sample/1d80331fddf9f2b14b636fc3f214cbac348892d8d033c23d9ae213e2b0777943/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [1d2c04c5757040…](https://bazaar.abuse.ch/sample/1d2c04c5757040ec0f68dccd59beadd5e93d8811087422b4fc22d69ebc821c34/) | Mirai | Botnet/IoT | **82.2** | 🔴 KRITISCH | – | – | ? |
| [49fcc0094822ca…](https://bazaar.abuse.ch/sample/49fcc0094822ca5c00b16c85fbf70893a570004417eb5d1aa3c7646637910376/) | Mirai | Botnet/IoT | **81.4** | 🔴 KRITISCH | – | – | ? |
| [dc695a594f5f60…](https://bazaar.abuse.ch/sample/dc695a594f5f60396bc7b2a37c2aafc1d22aa6091e10df9646f063af9a1997c8/) | Mirai | Botnet/IoT | **81.4** | 🔴 KRITISCH | – | – | ? |
| [83b3af9eb64a45…](https://bazaar.abuse.ch/sample/83b3af9eb64a45f01998dae4890cb33157d7b69b634c69795ad1d4767267a56f/) | Mirai | Botnet/IoT | **81.4** | 🔴 KRITISCH | – | – | ? |
| [bbb35ecff02229…](https://bazaar.abuse.ch/sample/bbb35ecff02229ebd29f293e52e5d1c337b05e201f27ab225ab5b621bb9ce916/) | Mirai | Botnet/IoT | **81.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6455/7955 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6455/7955 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6151/7955 |
| 6 | Kaspersky | 75.5% | 6004/7954 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.3% | 5666/7951 |
| 9 | Rising | 68.4% | 5442/7955 |
| 10 | Varist | 66.1% | 5255/7950 |
| 11 | Avast | 65.2% | 5182/7951 |
| 12 | AVG | 65.2% | 5182/7950 |
| 13 | Tencent | 65.0% | 5022/7729 |
| 14 | McAfeeD | 61.4% | 4882/7947 |
| 15 | huorong | 60.9% | 4840/7947 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 74 | 73.3% |
| 🪟 Windows | 23 | 22.8% |
| ❓ Unbekannt | 4 | 4.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 97 | 96.0% |
| MaaS-Loader | 2 | 2.0% |
| Trojanisierte Software | 1 | 1.0% |
| Exploit / N-Day | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 60 | 59.4% |
| 2 | 🇺🇸 US | 9 | 8.9% |
| 3 | 🇫🇷 FR | 8 | 7.9% |
| 4 | 🌐 SK | 6 | 5.9% |
| 5 | 🇳🇱 NL | 3 | 3.0% |
| 6 | 🌐 DK | 3 | 3.0% |
| 7 | 🇦🇹 AT | 2 | 2.0% |
| 8 | 🌐 Unbekannt | 2 | 2.0% |
| 9 | 🇭🇺 HU | 2 | 2.0% |
| 10 | 🌐 PT | 2 | 2.0% |
| 11 | 🇧🇷 BR | 1 | 1.0% |
| 12 | 🇷🇴 RO | 1 | 1.0% |
| 13 | 🌐 CL | 1 | 1.0% |
| 14 | 🇨🇭 CH | 1 | 1.0% |

## MITRE ATT&CK

> 58 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 57 |
| Lateral Movement | 57 |
| Command and Control | 1 |
| Collection | 1 |

<details><summary>258cb7c5321edf640b59… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>61e3d5824f6774751409… – Mirai | 🔴 KRITISCH 83.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>1d80331fddf9f2b14b63… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [7792f7d53bb9bd6514a3…](https://bazaar.abuse.ch/sample/7792f7d53bb9bd6514a3555dd7e12c1b1508066869078168b8b6e1ad577e4527/)

- **Familie:** Mirai
- **Erkannt von:** 36 von 75 Engines (48.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.39414013
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Backdoor:Linux/Mirai.AR!MTB`

**Erkennende Engines (36/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.39414013` |
| AhnLab-V3 | `Linux/Mirai13.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.D25968FD` |
| Avast-Mobile | `ELF:Mirai-ADH [Trj]` |
| Avira | `EXP/ELF.Gafgyt.Z.H` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Dropper.Mirai-7135925-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.ASX trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Trojan.Linux.Mirai.39414013 (B)` |
| F-Secure | `Exploit.EXP/ELF.Gafgyt.Z.H` |
| Fortinet | `ELF/Mirai.H!tr` |
| GData | `Trojan.Linux.Mirai.39414013` |
| Google | `Detected` |
| Gridinsoft | `Susp.U.XOREncoded.sd!yf` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Jiangmin | `Backdoor.Linux.gree` |
| MaxSecure | `Backdoor.WIN32.130121.Linux.Mirai.cw.YR` |
| McAfeeD | `Trojan:Linux/Mirai.EAF` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.39414013` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.130E7 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CIA` |
| Symantec | `Linux.Mirai` |
| Tencent | `Backdoor.Linux.Mirai.ck` |
| VBA32 | `Trojan.Linux.Mirai.L32.422bb4` |
| VIPRE | `Trojan.Linux.Mirai.39414013` |
| Varist | `E32/Mirai.BT.gen!Eldorado` |
| ZoneAlarm | `Linux/DDoS-CIA` |
| alibabacloud | `DDOS:Linux/Mirai.4e3740f5` |
| huorong | `Backdoor/Linux.Mirai.bn` |

### [3fc79e48b04e38627a6d…](https://bazaar.abuse.ch/sample/3fc79e48b04e38627a6dab47a4597e87a516d06ea7fd51dc7e8ed6a9fa94b501/)

- **Familie:** Socks5Systemz
- **Erkannt von:** 13 von 75 Engines (17.3%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Win64:MalwareX-gen [Trj]
- **VT-Reputation:** -12
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (13/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `Win64:MalwareX-gen [Trj]` |
| Avast | `Win64:MalwareX-gen [Trj]` |
| Avira | `TR/W64.MalwareX` |
| ESET-NOD32 | `Win64/Agent_AGen.SZW trojan` |
| F-Secure | `Trojan.TR/W64.MalwareX` |
| GData | `Generic.Trojan.Agent.0ED47T` |
| Kaspersky | `HEUR:Trojan.Win64.Silverfox.gen` |
| McAfeeD | `ti!3FC79E48B04E` |
| Rising | `Malware.SwollenFile!1.E38A (CLASSIC)` |
| Skyhigh | `Artemis!Trojan` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Win64.Trojan.Silverfox.Sgil` |

### [96e1ec8a521e259d0392…](https://bazaar.abuse.ch/sample/96e1ec8a521e259d0392e845560d65d997cdcfd4ac8071b9c4585e91d5f25a3b/)

- **Familie:** Mirai
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CLP [Bot]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLP [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan/Linux.Mirai` |
| Avast | `ELF:Mirai-CLP [Bot]` |
| Avast-Mobile | `ELF:Mirai-CLQ [Bot]` |
| Avira | `TR/LINUX.Mirai.CLP` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLP` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.MiraiTR` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.LR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.14339 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.zd` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [b0212bf00e1ba31c3625…](https://bazaar.abuse.ch/sample/b0212bf00e1ba31c36259842f877ce9948c85e6936a1a0f0e71508973e7345f5/)

- **Familie:** Mirai
- **Erkannt von:** 29 von 75 Engines (38.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** LINUX/Mirai-FQU!CBD3B2D6EEA7
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (29/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CLQ [Bot]` |
| AhnLab-V3 | `Worm/Linux.Mirai.SE286` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CLQ [Bot]` |
| Avast-Mobile | `ELF:Mirai-CVH [Trj]` |
| Avira | `TR/LINUX.Mirai.CLQ` |
| ClamAV | `Unix.Trojan.Mirai-10008934-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10201` |
| ESET-NOD32 | `Linux/Mirai.CJR trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CLQ` |
| Fortinet | `ELF/Mirai.CJR!tr` |
| GData | `Linux.Trojan.Gafgyt.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Gafgyt.go` |
| Lionic | `Trojan.ELF.Mirai.4!c` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AW!xp` |
| Rising | `Backdoor.Mirai/Linux!1.128BE (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `LINUX/Mirai-FQU!CBD3B2D6EEA7` |
| Sophos | `Mal/Generic-S` |
| Tencent | `Backdoor.Linux.Mirai.zptra` |
| TrellixENS | `LINUX/Mirai-FQU!CBD3B2D6EEA7` |
| Varist | `E32/Mirai.EN.gen!Camelot` |
| huorong | `Trojan/Linux.Mirai.au!crit` |

### [065cfe7c9627cdef0dad…](https://bazaar.abuse.ch/sample/065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432/) ⭐ **WOCHEN-SAMPLE**

- **Familie:** RemcosRAT
- **Erkannt von:** 63 von 75 Engines (84.0%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** Trojan.Generic.39196960
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Generic.39196960`

**Erkennende Engines (63/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Generic.39196960` |
| APEX | `Malicious` |
| AVG | `Win32:Evo-gen [Trj]` |
| Alibaba | `Trojan:Win32/Injector.55ac695f` |
| Antiy-AVL | `Trojan/Win32.Occamy` |
| Arcabit | `Trojan.Generic.D2561920` |
| Avast | `Win32:Evo-gen [Trj]` |
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
| Google | `Detected` |
| Gridinsoft | `Ransom.Win32.Occamy.oa!s1` |
| Ikarus | `Trojan.Win32.Injector` |
| Jiangmin | `Trojan.Script.ahzg` |
| K7AntiVirus | `Trojan ( 005d2d011 )` |
| K7GW | `Trojan ( 005d2d011 )` |
| Kaspersky | `Trojan.Win32.Autoit.adiam` |
| Kingsoft | `malware.kb.a.1000` |
| Lionic | `Trojan.Win32.Autoit.4!c` |
| Malwarebytes | `Malware.AI.1538686817` |
| MaxSecure | `Backdoor.W32.030226.Remcos.YR` |
| McAfeeD | `Real Protect-LS!01276B2AAD68` |
| MicroWorld-eScan | `Trojan.Generic.39196960` |
| Microsoft 🛡️ | `PUA:Win32/Caypnamer.A!ml` |
| NANO-Antivirus | `Trojan.Win32.Nanocore.kwqeao` |
| Paloalto | `generic.ml` |
| Panda | `Trj/PhxBzA.A` |
| Rising | `Trojan.Injector!8.C4 (TFE:3:AsQVnLG3KvV)` |
| SUPERAntiSpyware | `Backdoor.Remcos/Variant` |
| Sangfor | `Trojan.Win32.Autoit.Vmf1` |
| SentinelOne | `Static AI - Malicious PE` |
| Skyhigh | `BehavesLike.Win32.Infected.th` |
| Sophos | `Mal/AuItInj-A` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `Unk.Win32.Script.404969` |
| TrellixENS | `Artemis!01276B2AAD68` |
| TrendMicro | `TROJ_GEN.R002C0DK926` |
| TrendMicro-HouseCall | `TROJ_GEN.R002C0DK926` |
| VBA32 | `Backdoor.Remcos` |
| VIPRE | `Trojan.Generic.39196960` |
| Varist | `W32/AutoIt.AFI.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Remcos.1606744.CK` |
| VirIT | `Trojan.Win32.Genus.ZHC` |
| Webroot | `Win.Trojan.Gen` |
| Yandex | `Trojan.GenAsa!W69KvkB5Cf0` |
| Zillya | `Trojan.Injector.Win32.2062480` |
| ZoneAlarm | `Mal/AuItInj-A` |
| alibabacloud | `Trojan:Win/Injector.AwlbYj` |
| tehtris | `Generic.Malware` |


## Top Tags

- **elf** (62×)
- **Mirai** (57×)
- **Torii** (44×)
- **exe** (20×)
- **Prometei** (7×)
- **signed** (5×)
- **WARDENStealer** (4×)
- **SalatStealer** (3×)
- **upx-dec** (3×)
- **salatstealer** (3×)
- **upx** (3×)
- **jar** (3×)
- **CookUp** (3×)
- **TamperedChef** (3×)
- **java** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +11 (46→57)
- ↑ **unbekannt** +6 (19→25)
- ↓ **SalatStealer** -16 (22→6)
- ↑ **WARDENStealer** +2 (2→4)
- neu: **SilentNet** (2)
- neu: **Socks5Systemz** (1)
- neu: **WannaCry** (1)
- neu: **Panchan** (1)
- neu: **kkRAT** (1)
- neu: **XorDDoS** (1)
- weg: **RevStealer** (war 4)
- weg: **Formbook** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +31 (26→57)
- ↓ **unbekannt** -4 (29→25)
- ↑ **SalatStealer** +1 (5→6)
- ↑ **WARDENStealer** +1 (3→4)
- ↑ **SilentNet** +1 (1→2)
- neu: **Socks5Systemz** (1)
- neu: **WannaCry** (1)
- neu: **Panchan** (1)
- neu: **kkRAT** (1)
- neu: **XorDDoS** (1)
- weg: **AgentTesla** (war 2)
- weg: **Formbook** (war 2)
- weg: **RevStealer** (war 2)
- weg: **Snowlight** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.381 MB |
| σ Dateigröße | 15.881 MB |
| Ø Risiko-Score | 69.8/100 |
| Ø Klassifikations-Konfidenz | 77.7% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 58/101 |
| Eindeutige Familien | 12 |
| Eindeutige Tags | 46 |
| Unbekannte Familien | 4 (4.0%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 20:31 | [258cb7c5321e…](https://bazaar.abuse.ch/sample/258cb7c5321edf640b597623f76204aa3cb60ee8945c89748fa01b0fec5d74c1/) | `elf` | Mirai | 83.8 | – | – | 🇺🇸US |
| 20:10 | [61e3d5824f67…](https://bazaar.abuse.ch/sample/61e3d5824f6774751409577b1952efec8b8f658de291dd28b3b86b6a8169007d/) | `elf` | Mirai | 83.5 | – | – | 🇺🇸US |
| 20:05 | [1d80331fddf9…](https://bazaar.abuse.ch/sample/1d80331fddf9f2b14b636fc3f214cbac348892d8d033c23d9ae213e2b0777943/) | `elf` | Mirai | 83.4 | – | – | 🇩🇪DE |
| 20:04 | [7792f7d53bb9…](https://bazaar.abuse.ch/sample/7792f7d53bb9bd6514a3555dd7e12c1b1508066869078168b8b6e1ad577e4527/) | `elf` | Mirai | 75.5 | 48.0% | 🟠 MÄSSIG ERKANNT | 🇩🇪DE |
| 19:41 | [3fc79e48b04e…](https://bazaar.abuse.ch/sample/3fc79e48b04e38627a6dab47a4597e87a516d06ea7fd51dc7e8ed6a9fa94b501/) | `msi` | Socks5Systemz | 80.7 | 17.3% | 🟡 SCHWACH ERKANNT | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 12.11.2026 21:21 UTC*