# MalwareBazaar – 30.10.2026 23:31 UTC

Dieser Run hat **80 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `7e4c129f5bd09beffae1…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **81** |
| Kritisch (≥75) | **54** |
| Höchster Score | **95.2/100** – 6cb322f63f55448c… |
| Häufigste Familie | **Mirai** (26x) |
| Häufigster Typ | **elf** (28x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 38 Samples |
| Ø Dateigröße | 1.41 MB (σ=3.12) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 28 | 34.6%  ██████ |
| `js` | 25 | 30.9%  ██████ |
| `exe` | 8 | 9.9%  █ |
| `vbs` | 7 | 8.6%  █ |
| `sh` | 5 | 6.2%  █ |
| `zip` | 2 | 2.5%   |
| `msi` | 2 | 2.5%   |
| `ps1` | 2 | 2.5%   |
| `macho` | 1 | 1.2%   |
| `vbe` | 1 | 1.2%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 26 | 32.1% |
| 2 | unbekannt | 17 | 21.0% |
| 3 | XWorm | 9 | 11.1% |
| 4 | Formbook | 7 | 8.6% |
| 5 | AgentTesla | 5 | 6.2% |
| 6 | RemcosRAT | 4 | 4.9% |
| 7 | WARDENStealer | 2 | 2.5% |
| 8 | VIPKeylogger | 2 | 2.5% |
| 9 | AMOS | 1 | 1.2% |
| 10 | WannaCry | 1 | 1.2% |
| 11 | CoinMiner | 1 | 1.2% |
| 12 | Vidar | 1 | 1.2% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 26 | 32.1% | 95% |
| RAT | 14 | 17.3% | 94% |
| Infostealer | 12 | 14.8% | 89% |
| Skript/Dropper | 10 | 12.3% | 35% |
| Andere / Unbekannt | 5 | 6.2% | 20% |
| Linux-Malware | 4 | 4.9% | 45% |
| Windows-Malware | 4 | 4.9% | 35% |
| Loader | 2 | 2.5% | 75% |
| Spyware | 2 | 2.5% | 75% |
| Ransomware | 1 | 1.2% | 95% |
| Cryptominer | 1 | 1.2% | 75% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 54 | 66.7% |
| 🟠 HOCH | 4 | 4.9% |
| 🟡 MITTEL | 18 | 22.2% |
| 🟢 NIEDRIG | 5 | 6.2% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [6cb322f63f5544…](https://bazaar.abuse.ch/sample/6cb322f63f55448c6599ecd0d7f95f026a1fc18e2fa5dc1d2716e6667b3ea91e/) | WannaCry | Ransomware | **95.2** | 🔴 KRITISCH | – | – | ? |
| [1eb39dbd8ca631…](https://bazaar.abuse.ch/sample/1eb39dbd8ca631431e37f173fa80b00fbac4a6c3a26effe6dacbe5b3eb4d8ecd/) | AMOS | Infostealer | **88.2** | 🔴 KRITISCH | – | – | ? |
| [359a7c8a50391e…](https://bazaar.abuse.ch/sample/359a7c8a50391ee13a1651b67b118fe7ab6ef6ddeae39876a393857fbfdc692b/) | Vidar | Infostealer | **87.6** | 🔴 KRITISCH | – | – | ? |
| [51fed5ce0887d3…](https://bazaar.abuse.ch/sample/51fed5ce0887d308554bb2da743b2c132444d1d4e309d8ccb846bddbcbac57ca/) | XWorm | RAT | **87.5** | 🔴 KRITISCH | 6.7% | ⚠️ KAUM ERKANNT | ✗ |
| [96d5897e7fab0c…](https://bazaar.abuse.ch/sample/96d5897e7fab0c099a0ac6e394b62f556fbd04acf3732d975ec165f8ab6ad36a/) | XWorm | RAT | **87.5** | 🔴 KRITISCH | 6.7% | ⚠️ KAUM ERKANNT | ✗ |
| [c165bca8fd3b3d…](https://bazaar.abuse.ch/sample/c165bca8fd3b3d41a63231985fdd892bfa6eda535a2ff07765756cdbff028a3d/) | Formbook | Infostealer | **87.4** | 🔴 KRITISCH | – | – | ? |
| [47544e2f0226f3…](https://bazaar.abuse.ch/sample/47544e2f0226f3de16ceb103c3678890565d610b4c289b291b4bb87d333c05bf/) | Formbook | Infostealer | **87.4** | 🔴 KRITISCH | – | – | ? |
| [fed0fea58ad792…](https://bazaar.abuse.ch/sample/fed0fea58ad792381666d83b401407b82bd6de24327f853c0e5ea099104245fb/) | Formbook | Infostealer | **87.4** | 🔴 KRITISCH | – | – | ? |
| [d53a127a739fcd…](https://bazaar.abuse.ch/sample/d53a127a739fcde6f917e3de18be79b47e746bcd2e39ef6d65a52ccef64e0deb/) | Formbook | Infostealer | **87.4** | 🔴 KRITISCH | – | – | ? |
| [fb57d8fc1e6d40…](https://bazaar.abuse.ch/sample/fb57d8fc1e6d408eaf060a31af3e085f0448a2cee0183ea781dcd488034c404f/) | Formbook | Infostealer | **87.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6270/7735 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 91.7% | 22/24 |
| 2 | Microsoft 🛡️ | 81.1% | 6270/7735 |
| 3 | MAX | 77.8% | 7/9 |
| 4 | ESET-NOD32 | 77.3% | 5978/7735 |
| 5 | Kaspersky | 75.5% | 5841/7734 |
| 6 | McAfee-GW-Edition | 75.0% | 3/4 |
| 7 | Google | 71.2% | 5504/7732 |
| 8 | Rising | 68.3% | 5283/7735 |
| 9 | Ad-Aware | 66.7% | 2/3 |
| 10 | Varist | 66.2% | 5115/7731 |
| 11 | Avast | 65.1% | 5036/7731 |
| 12 | AVG | 65.1% | 5036/7730 |
| 13 | Tencent | 64.9% | 4873/7509 |
| 14 | McAfeeD | 61.3% | 4734/7728 |
| 15 | huorong | 60.8% | 4699/7728 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 33 | 40.7% |
| ❓ Unbekannt | 26 | 32.1% |
| 🪟 Windows | 19 | 23.5% |
| 📦 Archiv | 2 | 2.5% |
| 🍎 macOS | 1 | 1.2% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 46 | 56.8% |
| Drive-By / Exploit-Kit | 25 | 30.9% |
| USB / Wechselmedium | 5 | 6.2% |
| Trojanisierte Software | 2 | 2.5% |
| MaaS-Loader | 2 | 2.5% |
| Exploit / N-Day | 1 | 1.2% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇸🇪 SE | 31 | 38.3% |
| 2 | 🇬🇧 GB | 15 | 18.5% |
| 3 | 🇩🇪 DE | 12 | 14.8% |
| 4 | 🇺🇸 US | 7 | 8.6% |
| 5 | 🇫🇷 FR | 5 | 6.2% |
| 6 | 🇭🇺 HU | 4 | 4.9% |
| 7 | 🇵🇱 PL | 3 | 3.7% |
| 8 | 🇳🇱 NL | 2 | 2.5% |
| 9 | 🇨🇿 CZ | 1 | 1.2% |
| 10 | 🌐 Unbekannt | 1 | 1.2% |

## MITRE ATT&CK

> 38 von 81 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 26 |
| Lateral Movement | 26 |
| Collection | 12 |
| Credential Access | 8 |
| Command and Control | 4 |
| Exfiltration | 1 |

<details><summary>359a7c8a50391ee13a16… – Vidar | 🔴 KRITISCH 87.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Credential Access | [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores |
| Collection | [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [700633a5a00e941dc10e…](https://bazaar.abuse.ch/sample/700633a5a00e941dc10ed7e7c575f7ee945b1c1cacc23751d13630882f1a4bb5/)

- **Familie:** Mirai
- **Erkannt von:** 34 von 75 Engines (45.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Gen:Variant.Linux.Mirai.27
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Linux.Mirai.27`

**Erkennende Engines (34/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Linux.Mirai.27` |
| AVG | `ELF:Gafgyt-KS [Trj]` |
| AhnLab-V3 | `Linux/Mirai13.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.27` |
| Avast | `ELF:Gafgyt-KS [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-KS [Trj]` |
| Avira | `TR/LINUX.Gafgyt.KS` |
| BitDefender 🛡️ | `Gen:Variant.Linux.Mirai.27` |
| CTX | `elf.unknown.mirai` |
| ClamAV | `Unix.Trojan.Mirai-10060414-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10808` |
| ESET-NOD32 | `Linux/Mirai.EIY trojan` |
| Elastic | `Linux.Generic.Threat` |
| Emsisoft | `Gen:Variant.Linux.Mirai.27 (B)` |
| F-Secure | `Trojan.TR/LINUX.Gafgyt.KS` |
| Fortinet | `ELF/Mirai.ETS!tr` |
| GData | `Gen:Variant.Linux.Mirai.27` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nb` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| MicroWorld-eScan | `Gen:Variant.Linux.Mirai.27` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.AR!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.130E7 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.ck` |
| TrendMicro | `Backdoor.Linux.BASHLITE.SMJC11` |
| TrendMicro-HouseCall | `Backdoor.Linux.BASHLITE.SMJC11` |
| VIPRE | `Gen:Variant.Linux.Mirai.27` |
| Varist | `E32/Mirai.AT.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.e!crit` |

### [51fed5ce0887d308554b…](https://bazaar.abuse.ch/sample/51fed5ce0887d308554bb2da743b2c132444d1d4e309d8ccb846bddbcbac57ca/)

- **Familie:** XWorm
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** VBS/Obfuscated.EL trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `VBS/Obfuscated.EL trojan` |
| Google | `Detected` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Script.Agent.gmbvfx` |
| Varist | `JS/Agent.FHW!Eldorado` |

### [96d5897e7fab0c099a0a…](https://bazaar.abuse.ch/sample/96d5897e7fab0c099a0ac6e394b62f556fbd04acf3732d975ec165f8ab6ad36a/)

- **Familie:** XWorm
- **Erkannt von:** 5 von 75 Engines (6.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** VBS/Obfuscated.EL trojan
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (5/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ESET-NOD32 | `VBS/Obfuscated.EL trojan` |
| Google | `Detected` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Script.Agent.gmbvfx` |
| Varist | `JS/Agent.FHW!Eldorado` |

### [76e8bd9717fef3598fd0…](https://bazaar.abuse.ch/sample/76e8bd9717fef3598fd0942f4fda3c682837784ae0ba192989f4231778f127ff/)

- **Familie:** WARDENStealer
- **Erkannt von:** 23 von 75 Engines (30.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Gen:Variant.Yogi.85599
- **VT-Reputation:** 0
- **Microsoft Defender:** ✓ **JA** – `Gen:Variant.Yogi.85599`

**Erkennende Engines (23/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Gen:Variant.Yogi.85599` |
| AVG | `MalwareX-gen [Pws]` |
| AhnLab-V3 | `Infostealer/Win.Lzveil.R797565` |
| Arcabit | `Trojan.Yogi.D14E5F` |
| Avast | `MalwareX-gen [Pws]` |
| BitDefender 🛡️ | `Gen:Variant.Yogi.85599` |
| Bkav | `W32.Malware.41573F24` |
| CTX | `dll.unknown.yogi` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 100)` |
| ESET-NOD32 | `Win64/ShellcodeRunner.CQR trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Gen:Variant.Yogi.85599 (B)` |
| GData | `Gen:Variant.Yogi.85599` |
| K7AntiVirus | `Trojan ( 006d9bf01 )` |
| K7GW | `Trojan ( 006d9bf01 )` |
| Kaspersky | `VHO:Trojan.Win32.Convagent.gen` |
| MicroWorld-eScan | `Gen:Variant.Yogi.85599` |
| Microsoft 🛡️ | `Trojan:Win32/Wacatac.B!ml` |
| Rising | `Malware.Undefined!8.C (TFE:6:C9WtrIs9t1G)` |
| VIPRE | `Gen:Variant.Yogi.85599` |
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

- **elf** (28×)
- **Mirai** (25×)
- **js** (23×)
- **Torii** (18×)
- **77-239-124-141** (16×)
- **opendir** (16×)
- **XWorm** (9×)
- **geo** (9×)
- **vbs** (7×)
- **Formbook** (7×)
- **exe** (6×)
- **TUR** (6×)
- **sh** (5×)
- **AgentTesla** (5×)
- **RemcosRAT** (4×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +7 (19→26)
- ↓ **unbekannt** -14 (31→17)
- neu: **XWorm** (9)
- ↑ **Formbook** +6 (1→7)
- neu: **AgentTesla** (5)
- neu: **RemcosRAT** (4)
- neu: **WARDENStealer** (2)
- neu: **VIPKeylogger** (2)
- neu: **AMOS** (1)
- weg: **NIKRAT** (war 3)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +3 (23→26)
- ↓ **unbekannt** -6 (23→17)
- ↑ **XWorm** +8 (1→9)
- ↑ **Formbook** +6 (1→7)
- ↑ **AgentTesla** +4 (1→5)
- ↑ **RemcosRAT** +3 (1→4)
- neu: **WARDENStealer** (2)
- neu: **VIPKeylogger** (2)
- neu: **AMOS** (1)
- neu: **WannaCry** (1)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.407 MB |
| σ Dateigröße | 3.115 MB |
| Ø Risiko-Score | 69.8/100 |
| Ø Klassifikations-Konfidenz | 75.2% |
| Samples mit VT | 5/81 |
| Samples mit MITRE | 38/81 |
| Eindeutige Familien | 17 |
| Eindeutige Tags | 45 |
| Unbekannte Familien | 5 (6.2%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 23:09 | [e08fe0658554…](https://bazaar.abuse.ch/sample/e08fe065855467201171844391ef1705077116a459746c27e10bb925e3fa7eb3/) | `sh` | unbekannt | 32.4 | – | – | 🇩🇪DE |
| 23:03 | [2c5145b89eb9…](https://bazaar.abuse.ch/sample/2c5145b89eb9c9eb46ddfb348cae64131d07cfdaacbc8817136630b5d92ddc63/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 22:56 | [77bb27215ce8…](https://bazaar.abuse.ch/sample/77bb27215ce812b5f255bd7866ca08fc6fb98d4ccb6abf30da08e2f13ee3c81d/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 22:41 | [a3b0305f464f…](https://bazaar.abuse.ch/sample/a3b0305f464fb030d4f1594a79dcc1168524c0d9104d92cb93fcd6ea7d749a62/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 22:39 | [beb7e7589979…](https://bazaar.abuse.ch/sample/beb7e7589979a43a2f763081d8eba2b84419a68c0e5a42b4cf6dc4fafce56733/) | `elf` | unbekannt | 42.6 | – | – | 🌐HU |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 30.10.2026 23:31 UTC*