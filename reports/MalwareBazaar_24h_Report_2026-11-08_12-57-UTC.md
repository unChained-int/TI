# MalwareBazaar – 08.11.2026 12:57 UTC

Dieser Run hat **89 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **90** |
| Kritisch (≥75) | **35** |
| Höchster Score | **88.0/100** – f7e8e61cbce42655… |
| Häufigste Familie | **unbekannt** (32x) |
| Häufigster Typ | **elf** (38x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 23 Samples |
| Ø Dateigröße | 4.19 MB (σ=16.12) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 38 | 42.2%  ████████ |
| `exe` | 35 | 38.9%  ███████ |
| `msi` | 3 | 3.3%   |
| `cmd` | 2 | 2.2%   |
| `doc` | 2 | 2.2%   |
| `hta` | 2 | 2.2%   |
| `lnk` | 1 | 1.1%   |
| `bat` | 1 | 1.1%   |
| `xlsx` | 1 | 1.1%   |
| `xlsm` | 1 | 1.1%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | unbekannt | 32 | 35.6% |
| 2 | Mirai | 19 | 21.1% |
| 3 | EchoBot | 8 | 8.9% |
| 4 | VShell | 7 | 7.8% |
| 5 | ConnectWise | 3 | 3.3% |
| 6 | GolstaStealer | 3 | 3.3% |
| 7 | CoinMiner | 2 | 2.2% |
| 8 | SnappyClient | 2 | 2.2% |
| 9 | NanoCore | 2 | 2.2% |
| 10 | PureRAT | 2 | 2.2% |
| 11 | WARDENStealer | 2 | 2.2% |
| 12 | RevStealer | 1 | 1.1% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Windows-Malware | 20 | 22.2% | 35% |
| Botnet/IoT | 19 | 21.1% | 95% |
| Linux-Malware | 18 | 20.0% | 45% |
| Infostealer | 11 | 12.2% | 77% |
| RAT | 7 | 7.8% | 89% |
| Skript/Dropper | 5 | 5.6% | 35% |
| Maldoc | 4 | 4.4% | 35% |
| Andere / Unbekannt | 3 | 3.3% | 20% |
| Loader | 2 | 2.2% | 75% |
| Trojaner | 1 | 1.1% | 65% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 35 | 38.9% |
| 🟠 HOCH | 5 | 5.6% |
| 🟡 MITTEL | 43 | 47.8% |
| 🟢 NIEDRIG | 7 | 7.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [f7e8e61cbce426…](https://bazaar.abuse.ch/sample/f7e8e61cbce426555822b337eac7560747e35b16799a4bab39abad9025464351/) | NanoCore | RAT | **88.0** | 🔴 KRITISCH | – | – | ? |
| [a9c28a31c8ad6f…](https://bazaar.abuse.ch/sample/a9c28a31c8ad6fd5315688201f77de358ee52cfa1eb7fc338b243cee59430071/) | QuasarRAT | RAT | **87.6** | 🔴 KRITISCH | – | – | ? |
| [8f1920aa856881…](https://bazaar.abuse.ch/sample/8f1920aa856881c43a2c059b814d3f2173740b181ab678cdea3a1f79d19afa3d/) | njrat | RAT | **86.6** | 🔴 KRITISCH | – | – | ? |
| [ed91e797ca9c4e…](https://bazaar.abuse.ch/sample/ed91e797ca9c4e4eebab32a142579df03627aeec35539daf43bbc17f7943ae89/) | RemcosRAT | RAT | **86.3** | 🔴 KRITISCH | – | – | ? |
| [0bc78397fc9d85…](https://bazaar.abuse.ch/sample/0bc78397fc9d858fb970ff6a7201c1ba483751fd636e46dbbd004c7e31bb0256/) | Mirai | Botnet/IoT | **84.5** | 🔴 KRITISCH | – | – | ? |
| [82ffa1a5ac0b77…](https://bazaar.abuse.ch/sample/82ffa1a5ac0b773c8683339191c4295a4112bd30f7c3f14c10364f0f738c9845/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [e90c74c7af5408…](https://bazaar.abuse.ch/sample/e90c74c7af54082bb98e39a484d63ee7df255e63a8ef7b73f75069059f8672b7/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | 2.7% | ⚠️ KAUM ERKANNT | ✗ |
| [eaed95ba1dc702…](https://bazaar.abuse.ch/sample/eaed95ba1dc702a81fa2ad9de7e9381384909bae550145709e401bb3144b0ba3/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [a43d17cf772559…](https://bazaar.abuse.ch/sample/a43d17cf772559cd23df743e8d3b40eeffb80643d0a00c53775f0f2d2f6fc8a5/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [57bc798151675c…](https://bazaar.abuse.ch/sample/57bc798151675ce86c2d199615241054d250449767e25917126e478b06e4126d/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.1% Erkennungsrate (6392/7886 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.1% | 6392/7886 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6092/7886 |
| 6 | Kaspersky | 75.5% | 5950/7885 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5611/7882 |
| 9 | Rising | 68.3% | 5389/7886 |
| 10 | Varist | 66.1% | 5211/7881 |
| 11 | Avast | 65.1% | 5134/7882 |
| 12 | AVG | 65.1% | 5134/7881 |
| 13 | Tencent | 64.9% | 4975/7660 |
| 14 | McAfeeD | 61.4% | 4837/7878 |
| 15 | huorong | 60.9% | 4800/7878 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 45 | 50.0% |
| 🪟 Windows | 37 | 41.1% |
| ❓ Unbekannt | 4 | 4.4% |
| 📄 Dokument | 4 | 4.4% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 79 | 87.8% |
| Phishing / E-Mail-Anhang | 4 | 4.4% |
| MaaS-Loader | 3 | 3.3% |
| Trojanisierte Software | 3 | 3.3% |
| Drive-By / Exploit-Kit | 1 | 1.1% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇩🇪 DE | 36 | 40.0% |
| 2 | 🇸🇪 SE | 21 | 23.3% |
| 3 | 🇳🇱 NL | 12 | 13.3% |
| 4 | 🇺🇸 US | 8 | 8.9% |
| 5 | 🇫🇷 FR | 8 | 8.9% |
| 6 | 🌐 PT | 2 | 2.2% |
| 7 | 🇭🇺 HU | 1 | 1.1% |
| 8 | 🇨🇭 CH | 1 | 1.1% |
| 9 | 🌐 Unbekannt | 1 | 1.1% |

## MITRE ATT&CK

> 23 von 90 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 19 |
| Lateral Movement | 19 |
| Collection | 3 |
| Command and Control | 3 |
| Credential Access | 1 |
| Exfiltration | 1 |

<details><summary>a9c28a31c8ad6fd53156… – QuasarRAT | 🔴 KRITISCH 87.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

</details>
<details><summary>8f1920aa856881c43a2c… – njrat | 🔴 KRITISCH 86.6/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>ed91e797ca9c4e4eebab… – RemcosRAT | 🔴 KRITISCH 86.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>0bc78397fc9d858fb970… – Mirai | 🔴 KRITISCH 84.5/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [a0796de3b0f3b80b721a…](https://bazaar.abuse.ch/sample/a0796de3b0f3b80b721a15e1b4cb523d617e53541f8a2ef00e95864c4300f710/)

- **Familie:** GolstaStealer
- **Erkannt von:** 36 von 75 Engines (48.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericFCA.17184
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericFCA.17184`

**Erkennende Engines (36/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericFCA.17184` |
| AVG | `Win64:Malware-gen` |
| AhnLab-V3 | `Trojan/Win.Generic.C5912843` |
| Antiy-AVL | `Trojan[PSW]/Win32.Agent` |
| Arcabit | `Trojan.GenericFCA.D4320` |
| Avast | `Win64:Malware-gen` |
| Avira | `TR/W64.Malware` |
| BitDefender 🛡️ | `Trojan.GenericFCA.17184` |
| Bkav | `W32.Malware.9D5159CF` |
| CTX | `exe.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_70% (D)` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Trojan.Siggen36.51249` |
| ESET-NOD32 | `Win64/PSW.Agent.AMF trojan` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericFCA.17184 (B)` |
| F-Secure | `Trojan.TR/W64.Malware` |
| Fortinet | `W64/Agent.AMF!tr.pws` |
| GData | `Trojan.GenericFCA.17184` |
| Gridinsoft | `Trojan.Win64.Agent.oa!s1` |
| K7AntiVirus | `Password-Stealer ( 006e2ba21 )` |
| K7GW | `Password-Stealer ( 006e2ba21 )` |
| Kaspersky | `HEUR:Trojan-PSW.Win32.Agent.gen` |
| Kingsoft | `Win32.Trojan-PSW.Agent.gen` |
| Malwarebytes | `Spyware.Stealer` |
| MaxSecure | `Trojan.Malware.698869727.susgen` |
| McAfeeD | `ti!A0796DE3B0F3` |
| MicroWorld-eScan | `Trojan.GenericFCA.17184` |
| Microsoft 🛡️ | `Trojan:Win64/GolstaStealer.AG!MTB` |
| Rising | `Spyware.Stealer!8.3090 (TFE:28:TPyki26yyVB)` |
| Sangfor | `Trojan.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Symantec | `ML.Attribute.HighConfidence` |
| Tencent | `OB:Trojan-Spy.Win64.Agent.16007769` |
| VIPRE | `Trojan.GenericFCA.17184` |
| huorong | `TrojanSpy/Stealer.it` |

### [1d48be9c03830f5749c6…](https://bazaar.abuse.ch/sample/1d48be9c03830f5749c64e7c002a02a32392892f53fa3a53d4a8664415bf30c5/)

- **Familie:** RedLineStealer
- **Erkannt von:** 55 von 75 Engines (73.3%)
- **Erkennungsqualität:** ✅ GUT ERKANNT
- **Häufigster Name:** IL:Trojan.RedLine.2
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `PWS:MSIL/RedLine!atmn`

**Erkennende Engines (55/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `IL:Trojan.RedLine.2` |
| APEX | `Malicious` |
| AVG | `Win32:MalwareX-gen [Misc]` |
| AhnLab-V3 | `Infostealer/Win.RedLine.C4566112` |
| Alibaba | `TrojanPSW:MSIL/RedLine.6a1f7a1e` |
| Antiy-AVL | `Trojan[Spy]/MSIL.RedLine` |
| Arcabit | `IL:Trojan.RedLine.2` |
| Avast | `Win32:MalwareX-gen [Misc]` |
| Avira | `TR/W32.Agent` |
| Bkav | `W32.ProDuuctAD.Trojan` |
| CTX | `exe.trojan.redline` |
| ClamAV | `Win.Malware.Bulz-9880537-0` |
| CrowdStrike | `win/malicious_confidence_100% (W)` |
| Cylance | `Unsafe` |
| Elastic | `Windows.Trojan.Generic` |
| Emsisoft | `Trojan-Spy.Agent (A)` |
| F-Secure | `Trojan.TR/W32.Agent` |
| Fortinet | `MSIL/Agent.DFY!tr.spy` |
| GData | `MSIL.Trojan-Stealer.Redline.B` |
| Gridinsoft | `Trojan.Win32.AsyncRAT.dd!n` |
| Ikarus | `Trojan-Spy.MSIL.Redline` |
| Jiangmin | `Trojan.PSW.MSIL.cihh` |
| K7AntiVirus | `Spyware ( 0057a2d41 )` |
| K7GW | `Spyware ( 0057a2d41 )` |
| Lionic | `Trojan.Win32.RedLine.i!c` |
| Malwarebytes | `Spyware.Passwordstealer` |
| MaxSecure | `Trojan.W32.M180222.Agent.gen.YR` |
| McAfeeD | `Real Protect-LS!A5C45448100C` |
| MicroWorld-eScan | `IL:Trojan.RedLine.2` |
| Microsoft 🛡️ | `PWS:MSIL/RedLine!atmn` |
| NANO-Antivirus | `Trojan.Win32.Reline.kbmoyj` |
| Paloalto | `generic.ml` |
| Rising | `Backdoor.SectopRAT!1.DA27 (CLASSIC)` |
| SUPERAntiSpyware | `Trojan.Agent/Gen-Crypt` |
| Sangfor | `Suspicious.Win32.Save.a` |
| SentinelOne | `Static AI - Malicious PE` |
| Sophos | `Mal/Reline-B` |
| Symantec | `Trojan Horse` |
| TACHYON | `Trojan-PWS/W32.DN-Reline.97792.B` |
| Tencent | `Trojan-PSW.MSIL.Reline.ha` |
| Trapmine | `malicious.high.ml.score` |
| TrellixENS | `GenericRXPZ-SW!A5C45448100C` |
| TrendMicro | `TrojanSpy.MSIL.REDLINE.SMYXDILZ` |
| TrendMicro-HouseCall | `TrojanSpy.MSIL.REDLINE.SMYXDILZ` |
| VIPRE | `IL:Trojan.RedLine.2` |
| Varist | `W32/MSIL_Agent.BJO.gen!Eldorado` |
| ViRobot | `Trojan.Win.Z.Redline.97792.BJX` |
| VirIT | `Trojan.Win32.Genus.LJH` |
| Webroot | `W32.Trojan.Gen` |
| Zillya | `Trojan.Agent.Win32.2485680` |
| ZoneAlarm | `Mal/Reline-B` |
| Zoner | `Trojan.Win32.139086` |
| alibabacloud | `Spy:MSIL/Redline.GG!MTB` |
| huorong | `TrojanSpy/MSIL.Stealer.aok!crit` |
| tehtris | `Generic.Malware` |

### [e90c74c7af54082bb98e…](https://bazaar.abuse.ch/sample/e90c74c7af54082bb98e39a484d63ee7df255e63a8ef7b73f75069059f8672b7/)

- **Familie:** Mirai
- **Erkannt von:** 2 von 75 Engines (2.7%)
- **Erkennungsqualität:** ⚠️ KAUM ERKANNT
- **Häufigster Name:** Trojan.ELF.Mirai.4!c
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (2/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Lionic | `Trojan.ELF.Mirai.4!c` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |

### [e3e8605e78993ab6fc3c…](https://bazaar.abuse.ch/sample/e3e8605e78993ab6fc3cec5ec419ba0c00a0bd297e5eba92a2b335667e5bb54e/)

- **Familie:** EchoBot
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Hajime-Q [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Hajime-Q [Trj]` |
| Avast | `ELF:Hajime-Q [Trj]` |
| Avast-Mobile | `ELF:Hajime-Q [Trj]` |
| Avira | `TR/LINUX.Hajime.Q` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.9871` |
| F-Secure | `Trojan.TR/LINUX.Hajime.Q` |
| GData | `Linux.Trojan.Agent.OGZCWA` |
| Kaspersky | `HEUR:Exploit.Linux.CVE-2018-10561.a` |
| McAfeeD | `ti!E3E8605E7899` |
| Microsoft 🛡️ | `Trojan:NPM/Multiverze!rfn` |
| Rising | `Exploit.CVE-2018-10561!8.105DA (CLOUD)` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.NPE` |
| Tencent | `Linux.Exploit.Cve-2018-10561.Psmw` |
| alibabacloud | `Exploit:Linux/Wacatac.C9nj` |
| huorong | `Trojan/Linux.Mirai.f` |

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
| MaxSecure | `Trojan.WIN32.230620.MSIL.Agent.fpar.YR` |
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

- **elf** (37×)
- **exe** (34×)
- **Mirai** (19×)
- **EchoBot** (8×)
- **VShell** (7×)
- **Prometei** (5×)
- **cowrie** (3×)
- **honeypot** (3×)
- **Torii** (3×)
- **dropped-by-OffLoader** (3×)
- **ConnectWise** (3×)
- **msi** (3×)
- **RMM** (3×)
- **ScreenConnect** (3×)
- **RAT** (3×)

## Änderungen – 24h-Vergleich

- ↑ **unbekannt** +8 (24→32)
- ↓ **Mirai** -10 (29→19)
- neu: **EchoBot** (8)
- ↑ **VShell** +6 (1→7)
- neu: **ConnectWise** (3)
- neu: **GolstaStealer** (3)
- neu: **CoinMiner** (2)
- neu: **SnappyClient** (2)
- ↑ **NanoCore** +1 (1→2)
- neu: **PureRAT** (2)
- weg: **Snowlight** (war 5)

## Änderungen – 7d-Vergleich

- ↓ **unbekannt** -2 (34→32)
- ↓ **Mirai** -1 (20→19)
- neu: **EchoBot** (8)
- ↑ **VShell** +5 (2→7)
- ↑ **ConnectWise** +2 (1→3)
- neu: **GolstaStealer** (3)
- ↑ **CoinMiner** +1 (1→2)
- neu: **SnappyClient** (2)
- ↑ **NanoCore** +1 (1→2)
- neu: **PureRAT** (2)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 4.188 MB |
| σ Dateigröße | 16.119 MB |
| Ø Risiko-Score | 56.4/100 |
| Ø Klassifikations-Konfidenz | 59.7% |
| Samples mit VT | 5/90 |
| Samples mit MITRE | 23/90 |
| Eindeutige Familien | 19 |
| Eindeutige Tags | 52 |
| Unbekannte Familien | 3 (3.3%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 12:55 | [0bc78397fc9d…](https://bazaar.abuse.ch/sample/0bc78397fc9d858fb970ff6a7201c1ba483751fd636e46dbbd004c7e31bb0256/) | `elf` | Mirai | 84.5 | – | – | 🇩🇪DE |
| 12:40 | [d31f4f528dec…](https://bazaar.abuse.ch/sample/d31f4f528decaec1cbe93f711651e4b1be0e5d150544a25c2ed8d03ad81d7509/) | `elf` | unbekannt | 43.1 | – | – | 🇺🇸US |
| 12:40 | [82ffa1a5ac0b…](https://bazaar.abuse.ch/sample/82ffa1a5ac0b773c8683339191c4295a4112bd30f7c3f14c10364f0f738c9845/) | `elf` | Mirai | 84.3 | – | – | 🇺🇸US |
| 12:28 | [eaed95ba1dc7…](https://bazaar.abuse.ch/sample/eaed95ba1dc702a81fa2ad9de7e9381384909bae550145709e401bb3144b0ba3/) | `elf` | Mirai | 84.1 | – | – | 🇩🇪DE |
| 11:57 | [a43d17cf7725…](https://bazaar.abuse.ch/sample/a43d17cf772559cd23df743e8d3b40eeffb80643d0a00c53775f0f2d2f6fc8a5/) | `elf` | Mirai | 83.6 | – | – | 🇩🇪DE |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 08.11.2026 12:57 UTC*