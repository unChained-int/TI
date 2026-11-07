# MalwareBazaar – 07.11.2026 05:47 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **53** |
| Höchster Score | **88.8/100** – 8c7994818bf87741… |
| Häufigste Familie | **Mirai** (41x) |
| Häufigster Typ | **elf** (53x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 44 Samples |
| Ø Dateigröße | 1.42 MB (σ=3.93) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 53 | 52.5%  ██████████ |
| `exe` | 25 | 24.8%  ████ |
| `macho` | 20 | 19.8%  ███ |
| `sh` | 1 | 1.0%   |
| `msi` | 1 | 1.0%   |
| `js` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 41 | 40.6% |
| 2 | unbekannt | 31 | 30.7% |
| 3 | Snowlight | 7 | 6.9% |
| 4 | RevStealer | 4 | 4.0% |
| 5 | VShell | 4 | 4.0% |
| 6 | Prometei | 2 | 2.0% |
| 7 | ValleyRAT | 2 | 2.0% |
| 8 | SalatStealer | 2 | 2.0% |
| 9 | ConnectWise | 2 | 2.0% |
| 10 | Loki | 1 | 1.0% |
| 11 | njrat | 1 | 1.0% |
| 12 | FileRepMalware [Trj] | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 41 | 40.6% | 95% |
| Andere / Unbekannt | 20 | 19.8% | 20% |
| Windows-Malware | 13 | 12.9% | 35% |
| Linux-Malware | 12 | 11.9% | 45% |
| Infostealer | 9 | 8.9% | 75% |
| RAT | 4 | 4.0% | 85% |
| Loader | 1 | 1.0% | 65% |
| Skript/Dropper | 1 | 1.0% | 35% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 53 | 52.5% |
| 🟠 HOCH | 2 | 2.0% |
| 🟡 MITTEL | 26 | 25.7% |
| 🟢 NIEDRIG | 20 | 19.8% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [8c7994818bf877…](https://bazaar.abuse.ch/sample/8c7994818bf877418e701f3d8aa4e1cbb24d9031e8f36c577c3541193baf96df/) | njrat | RAT | **88.8** | 🔴 KRITISCH | – | – | ? |
| [d4ea0857eff726…](https://bazaar.abuse.ch/sample/d4ea0857eff726c6bdf502461ccfe6d90e8a4808df1b78d39f548057cdfb6883/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [a996b6b9d64d12…](https://bazaar.abuse.ch/sample/a996b6b9d64d12f50e1b490b9ad54ae9b06c147ef29fb73e028b315b2e0ff209/) | Mirai | Botnet/IoT | **84.0** | 🔴 KRITISCH | – | – | ? |
| [870e679d592adb…](https://bazaar.abuse.ch/sample/870e679d592adb9ca80ffc61582d6ced9e6ce522a5623e031b9d69f083239cf8/) | Mirai | Botnet/IoT | **83.8** | 🔴 KRITISCH | – | – | ? |
| [796d79206eb13e…](https://bazaar.abuse.ch/sample/796d79206eb13e8f7ea9e9b2d0b6e2054ae2f7792fa8571bd53671e398ae6531/) | Mirai | Botnet/IoT | **83.4** | 🔴 KRITISCH | – | – | ? |
| [67219af1d55f4d…](https://bazaar.abuse.ch/sample/67219af1d55f4d943632a26b7f072709f3334f58424808d1e217ddb06b3a35d1/) | Mirai | Botnet/IoT | **83.2** | 🔴 KRITISCH | – | – | ? |
| [aa423ec2fbdb18…](https://bazaar.abuse.ch/sample/aa423ec2fbdb1835e1ad69c81db4d6c1b710faa27c192ac77e55d4f74a47325d/) | Mirai | Botnet/IoT | **81.7** | 🔴 KRITISCH | 22.7% | 🟡 SCHWACH ERKANNT | ✗ |
| [5dead91acf4972…](https://bazaar.abuse.ch/sample/5dead91acf4972d1503e4abc8b223767d78373f15066aa79e252557dc8894786/) | Mirai | Botnet/IoT | **81.3** | 🔴 KRITISCH | – | – | ? |
| [f2aa4b6d217354…](https://bazaar.abuse.ch/sample/f2aa4b6d2173545191741e3726f09e86bfc36a2cfbb562a60da7e059fc0689f3/) | Mirai | Botnet/IoT | **81.3** | 🔴 KRITISCH | – | – | ? |
| [1df069b263d1f0…](https://bazaar.abuse.ch/sample/1df069b263d1f07cde52576d3a0c8935edca42d6d68ca2b32f849e1049204f92/) | Mirai | Botnet/IoT | **81.3** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6368/7862 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6368/7862 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6074/7862 |
| 6 | Kaspersky | 75.5% | 5932/7861 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5596/7858 |
| 9 | Rising | 68.3% | 5369/7862 |
| 10 | Varist | 66.2% | 5198/7857 |
| 11 | Avast | 65.1% | 5114/7858 |
| 12 | AVG | 65.1% | 5114/7857 |
| 13 | Tencent | 64.9% | 4955/7636 |
| 14 | McAfeeD | 61.4% | 4822/7854 |
| 15 | huorong | 60.9% | 4780/7854 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 58 | 57.4% |
| 🪟 Windows | 22 | 21.8% |
| 🍎 macOS | 20 | 19.8% |
| ❓ Unbekannt | 1 | 1.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 99 | 98.0% |
| Trojanisierte Software | 1 | 1.0% |
| Drive-By / Exploit-Kit | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 61 | 60.4% |
| 2 | 🇩🇪 DE | 29 | 28.7% |
| 3 | 🇳🇱 NL | 5 | 5.0% |
| 4 | 🇫🇷 FR | 5 | 5.0% |
| 5 | 🌐 Unbekannt | 1 | 1.0% |

## MITRE ATT&CK

> 44 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 41 |
| Lateral Movement | 41 |
| Collection | 3 |
| Credential Access | 2 |
| Exfiltration | 2 |
| Command and Control | 1 |

<details><summary>8c7994818bf877418e70… – njrat | 🔴 KRITISCH 88.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |
| Collection | [T1056](https://attack.mitre.org/techniques/T1056/) | Input Capture |

</details>
<details><summary>d4ea0857eff726c6bdf5… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>a996b6b9d64d12f50e1b… – Mirai | 🔴 KRITISCH 84.0/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>870e679d592adb9ca80f… – Mirai | 🔴 KRITISCH 83.8/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>796d79206eb13e8f7ea9… – Mirai | 🔴 KRITISCH 83.4/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [4392cb9d92a4912687f1…](https://bazaar.abuse.ch/sample/4392cb9d92a4912687f12a462b346e7f0b4316f1ce9f31be4d8b0cb383e07b16/)

- **Familie:** Mirai
- **Erkannt von:** 34 von 75 Engines (45.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Generic.Linux.Medusa.C.EFA39488
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Generic.Linux.Medusa.C.EFA39488`

**Erkennende Engines (34/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Generic.Linux.Medusa.C.EFA39488` |
| AVG | `BV:Downloader-AAN [Drp]` |
| AhnLab-V3 | `Downloader/Shell.Generic.S1672` |
| Arcabit | `Generic.Linux.Medusa.C.EFAD9A40` |
| Avast | `BV:Downloader-AAN [Drp]` |
| Avira | `HTML/ExpKit.Gen2` |
| BitDefender 🛡️ | `Generic.Linux.Medusa.C.EFA39488` |
| CTX | `script.unknown.medusa` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.37` |
| ESET-NOD32 | `Linux/TrojanDownloader.SH.EXW trojan` |
| Emsisoft | `Generic.Linux.Medusa.C.EFA39488 (B)` |
| F-Secure | `Malware.HTML/ExpKit.Gen2` |
| Fortinet | `BASH/Dloader.P!tr` |
| GData | `Generic.Linux.Medusa.C.EFA39488` |
| Google | `Detected` |
| K7GW | `Trojan ( 004102a21 )` |
| Kaspersky | `HEUR:Trojan-Downloader.Shell.Agent.p` |
| MaxSecure | `Downloader.W32.Shell.Agent.p` |
| MicroWorld-eScan | `Generic.Linux.Medusa.C.EFA39488` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| NANO-Antivirus | `Trojan.Script.Downloader.hjbjep` |
| Rising | `Downloader.Mirai/BASH!1.CECE (CLASSIC)` |
| Sangfor | `Virus.Generic-Script.Save.ba1` |
| Skyhigh | `Linux/Downloader.w` |
| Sophos | `Mal/ShellDl-A` |
| Symantec | `CL.Downloader!gen277` |
| TrellixENS | `Linux/Downloader.w` |
| TrendMicro | `Possible_BASHDLOD.SMLBAT3` |
| TrendMicro-HouseCall | `Possible_BASHDLOD.SMLBAT3` |
| VIPRE | `Generic.Linux.Medusa.C.EFA39488` |
| Varist | `SH/Mirai.C.gen!Camelot` |
| ZoneAlarm | `Mal/ShellDl-A` |
| huorong | `Trojan/BAT.Obfuscated.aar!crit` |

### [aa423ec2fbdb1835e1ad…](https://bazaar.abuse.ch/sample/aa423ec2fbdb1835e1ad69c81db4d6c1b710faa27c192ac77e55d4f74a47325d/)

- **Familie:** Mirai
- **Erkannt von:** 17 von 75 Engines (22.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Mirai-CBI [Cryp]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (17/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Mirai-CBI [Cryp]` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Mirai-CBI [Cryp]` |
| Avira | `TR/LINUX.Mirai.CBI` |
| ClamAV | `Unix.Trojan.Coinminer-7668629-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DDoS.3343` |
| ESET-NOD32 | `Linux/Flooder.Agent.NQ trojan` |
| F-Secure | `Trojan.TR/LINUX.Mirai.CBI` |
| Fortinet | `ELF64/Mirai.TSU!tr.botnet` |
| Google | `Detected` |
| Ikarus | `Trojan.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.nd` |
| Microsoft 🛡️ | `Trojan:Script/Wacatac.B!ml` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Mal/Generic-S` |
| huorong | `Trojan/Linux.DDos.du` |

### [6946548ce23106e70957…](https://bazaar.abuse.ch/sample/6946548ce23106e70957952fc2fa08c8459fb4b2ea3e6b513e8a7387cc115cf3/)

- **Familie:** FileRepMalware [Trj]
- **Erkannt von:** 12 von 75 Engines (16.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** FileRepMalware [Trj]
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (12/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `FileRepMalware [Trj]` |
| Avast | `FileRepMalware [Trj]` |
| Bkav | `W32.Malware.984F3EEA` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (high confidence)` |
| Google | `Detected` |
| Ikarus | `Trojan.WinGo.Crypt` |
| Kaspersky | `VHO:Trojan-PSW.Win32.Stealerc.gen` |
| McAfeeD | `ti!6946548CE231` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

### [5e6c245a96999367701d…](https://bazaar.abuse.ch/sample/5e6c245a96999367701dfa2288b391a6dad9ec2044744291b61af665ae6f30e4/)

- **Familie:** Snowlight
- **Erkannt von:** 26 von 75 Engines (34.7%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** Downloader-FCSM!ADD0F9597456
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (26/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Downloader-BP [Trj]` |
| Antiy-AVL | `Trojan/Linux.Multiverze` |
| Avast | `ELF:Downloader-BP [Trj]` |
| Avast-Mobile | `ELF:Downloader-BR [Drp]` |
| Avira | `TR/LINUX.Downloade.BP` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.DownLoader.2312` |
| ESET-NOD32 | `Linux/TrojanDownloader.Agent.IT trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Trojan.TR/LINUX.Downloade.BP` |
| Fortinet | `ELF/Agent.IT!tr.dldr` |
| Google | `Detected` |
| Ikarus | `Trojan-Downloader.Linux.Agent` |
| Jiangmin | `Trojan.Linux.dws` |
| Kaspersky | `HEUR:Trojan.Linux.Agent.pm` |
| Microsoft 🛡️ | `Trojan:Linux/SAgnt.AI!MTB` |
| Rising | `Backdoor.VShell/Linux!1.13129 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Skyhigh | `Downloader-FCSM!ADD0F9597456` |
| Sophos | `Linux/Dldr-WW` |
| Tencent | `Trojan.Linux.Downloader.cbh` |
| TrellixENS | `Downloader-FCSM!ADD0F9597456` |
| Varist | `E32/Agent.BE.gen!Eldorado` |
| ZoneAlarm | `Linux/Dldr-WW` |
| alibabacloud | `Backdoor:Linux/Vshell.client.A` |
| huorong | `TrojanDownloader/Linux.Agent.ab!crit` |

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

- **elf** (53×)
- **Mirai** (41×)
- **exe** (24×)
- **macho** (20×)
- **Snowlight** (8×)
- **signed** (4×)
- **RevStealer** (4×)
- **VShell** (4×)
- **RAT** (3×)
- **Prometei** (3×)
- **upx-dec** (3×)
- **upx** (3×)
- **Stealer** (2×)
- **Vidar** (2×)
- **VidarStealer** (2×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +26 (15→41)
- ↑ **unbekannt** +7 (24→31)
- neu: **Snowlight** (7)
- ↓ **RevStealer** -4 (8→4)
- neu: **Prometei** (2)
- neu: **ValleyRAT** (2)
- neu: **SalatStealer** (2)
- neu: **ConnectWise** (2)
- neu: **Loki** (1)
- weg: **FunStealer** (war 5)
- weg: **RemcosRAT** (war 3)
- weg: **XWorm** (war 2)
- weg: **Formbook** (war 3)
- weg: **AgentTesla** (war 2)
- weg: **Silentnet** (war 3)
- weg: **CoinMiner** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +23 (18→41)
- ↓ **unbekannt** -4 (35→31)
- neu: **Snowlight** (7)
- ↑ **RevStealer** +3 (1→4)
- ↑ **VShell** +2 (2→4)
- neu: **Prometei** (2)
- ↑ **ValleyRAT** +1 (1→2)
- ↓ **SalatStealer** -1 (3→2)
- ↑ **ConnectWise** +1 (1→2)
- neu: **Loki** (1)
- weg: **Formbook** (war 3)
- weg: **RemcosRAT** (war 2)
- weg: **AgentTesla** (war 3)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 1.422 MB |
| σ Dateigröße | 3.934 MB |
| Ø Risiko-Score | 59.5/100 |
| Ø Klassifikations-Konfidenz | 63.4% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 44/101 |
| Eindeutige Familien | 15 |
| Eindeutige Tags | 29 |
| Unbekannte Familien | 20 (19.8%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 05:09 | [d4ea0857eff7…](https://bazaar.abuse.ch/sample/d4ea0857eff726c6bdf502461ccfe6d90e8a4808df1b78d39f548057cdfb6883/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 05:08 | [a996b6b9d64d…](https://bazaar.abuse.ch/sample/a996b6b9d64d12f50e1b490b9ad54ae9b06c147ef29fb73e028b315b2e0ff209/) | `elf` | Mirai | 84.0 | – | – | 🇩🇪DE |
| 04:58 | [870e679d592a…](https://bazaar.abuse.ch/sample/870e679d592adb9ca80ffc61582d6ced9e6ce522a5623e031b9d69f083239cf8/) | `elf` | Mirai | 83.8 | – | – | 🇩🇪DE |
| 04:55 | [4ec220894d9c…](https://bazaar.abuse.ch/sample/4ec220894d9c50b012c95d8b3842dfab945ff161563979419ace88db4166dd72/) | `exe` | Loki | 38.3 | – | – | 🇳🇱NL |
| 04:45 | [8c7994818bf8…](https://bazaar.abuse.ch/sample/8c7994818bf877418e701f3d8aa4e1cbb24d9031e8f36c577c3541193baf96df/) | `exe` | njrat | 88.8 | – | – | 🇳🇱NL |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 07.11.2026 05:47 UTC*