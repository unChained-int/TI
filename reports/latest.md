# MalwareBazaar – 04.11.2026 00:28 UTC

Dieser Run hat **100 neue Samples** gefunden (von 100 geprüft).

> ⭐ **Wochen-Sample aktiv:** `09f7d2a30633ca2ea229…` wird diese Woche dauerhaft getrackt.

---

## Überblick

| | |
|---|---|
| Neue Samples | **101** |
| Kritisch (≥75) | **67** |
| Höchster Score | **84.3/100** – 75cd53e5ff76cffe… |
| Häufigste Familie | **Mirai** (49x) |
| Häufigster Typ | **elf** (50x) |
| Hauptplattform | **Linux** |
| VT-angereichert | 5 Samples |
| MITRE gemappt | 55 Samples |
| Ø Dateigröße | 3.67 MB (σ=13.43) |

## Dateitypen

| Typ | Anzahl | Anteil |
|-----|--------|--------|
| `elf` | 50 | 49.5%  █████████ |
| `exe` | 28 | 27.7%  █████ |
| `macho` | 10 | 9.9%  █ |
| `sh` | 5 | 5.0%   |
| `zip` | 3 | 3.0%   |
| `dll` | 1 | 1.0%   |
| `js` | 1 | 1.0%   |
| `iso` | 1 | 1.0%   |
| `dmg` | 1 | 1.0%   |
| `jar` | 1 | 1.0%   |

## Familien / Signaturen

| # | Familie | Anzahl | Anteil |
|---|---------|--------|--------|
| 1 | Mirai | 49 | 48.5% |
| 2 | unbekannt | 38 | 37.6% |
| 3 | WARDENStealer | 5 | 5.0% |
| 4 | VShell | 4 | 4.0% |
| 5 | AokigaharaStealer | 1 | 1.0% |
| 6 | Malware | 1 | 1.0% |
| 7 | RustyStealer | 1 | 1.0% |
| 8 | Trojan.GenericKD.82018980 | 1 | 1.0% |
| 9 | NanoCore | 1 | 1.0% |

## Klassifikation

> Erkennungslogik: (1) Signatur-Lookup → (2) Tag-Keywords → (3) VT-Daten → (4) Dateityp-Heuristik

| Kategorie | Anzahl | Anteil | Konfidenz |
|-----------|--------|--------|-----------|
| Botnet/IoT | 50 | 49.5% | 95% |
| Windows-Malware | 15 | 14.9% | 35% |
| Infostealer | 13 | 12.9% | 75% |
| Andere / Unbekannt | 10 | 9.9% | 20% |
| Loader | 9 | 8.9% | 75% |
| Linux-Malware | 1 | 1.0% | 45% |
| Skript/Dropper | 1 | 1.0% | 35% |
| Trojaner | 1 | 1.0% | 65% |
| RAT | 1 | 1.0% | 95% |

## Risiko-Score

> **VT-Erkennung: NIEDRIGE Rate = GEFÄHRLICH** (Malware ist evasiv, kaum erkannt)
> Formel (mit VT):  `R = (0.35·Severity + 0.30·Signalstärke + 0.25·Evasivität + 0.10·Aktualität) × 100`
> Evasivität = `1 - VT_Rate` → 1/70 erkannt → s_det = 0.986 (maximal evasiv = gefährlich)

| Level | Samples | Anteil |
|-------|---------|--------|
| 🔴 KRITISCH | 67 | 66.3% |
| 🟠 HOCH | 7 | 6.9% |
| 🟡 MITTEL | 17 | 16.8% |
| 🟢 NIEDRIG | 10 | 9.9% |

**Top 10 nach Score:**

| SHA256 | Familie | Kat. | Score | Level | VT-Rate | Erkennungsqualität | Defender |
|--------|---------|------|-------|-------|---------|-------------------|----------|
| [75cd53e5ff76cf…](https://bazaar.abuse.ch/sample/75cd53e5ff76cffea431a9f640c156c6d2c8617c692c5445ee6b7a8486069d0b/) | Mirai | Botnet/IoT | **84.3** | 🔴 KRITISCH | – | – | ? |
| [97288455d19b4d…](https://bazaar.abuse.ch/sample/97288455d19b4dbec1ad0d93f99d1f28e001dd59bee53f1a63caac3ba4d9c497/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [3d6baaac3ecece…](https://bazaar.abuse.ch/sample/3d6baaac3ececed3116587a71c1b2ecdc1860145199140ecdca7d1d325203626/) | Mirai | Botnet/IoT | **84.2** | 🔴 KRITISCH | – | – | ? |
| [59ae87b9ddbb7d…](https://bazaar.abuse.ch/sample/59ae87b9ddbb7d557e075d089f10b7710c8bd4cafc946b425d41e1171a27ae42/) | Mirai | Botnet/IoT | **84.1** | 🔴 KRITISCH | – | – | ? |
| [c8cbd752fa4fc8…](https://bazaar.abuse.ch/sample/c8cbd752fa4fc8fd2f3cb6643ceb78928ec6d9adcad2e0bd47ebfacdf560f004/) | Mirai | Botnet/IoT | **83.7** | 🔴 KRITISCH | – | – | ? |
| [96487d78061413…](https://bazaar.abuse.ch/sample/96487d7806141359c73bad67fad5727d7fc368f0c343249db12fe47fe3eea84f/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [294615cebd58fc…](https://bazaar.abuse.ch/sample/294615cebd58fc34069f757f178fb772d704bc2ab8f40d92bb3aa8f9e72d3cba/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [990302e1260956…](https://bazaar.abuse.ch/sample/990302e1260956d4b15a984b41c8d1ea6ff7884ab1096f6fc90e4bee0cdce8f8/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [9ea1c4a77662a6…](https://bazaar.abuse.ch/sample/9ea1c4a77662a6cf964fdff21e1d0cb872d42df5f031038055ce33603fd72e35/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |
| [f806f0404b5ff0…](https://bazaar.abuse.ch/sample/f806f0404b5ff05dce8b899dee1adab3293ff578d10acc09254194df2debd7be/) | Mirai | Botnet/IoT | **83.6** | 🔴 KRITISCH | – | – | ? |

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

**Microsoft Defender (Pflicht-Check):** 81.0% Erkennungsrate (6328/7808 Samples erkannt)

| # | Engine | Erkennungsrate | Erkannt / Gesehen |
|---|--------|----------------|-------------------|
| 1 | FireEye | 92.0% | 23/25 |
| 2 | Microsoft 🛡️ | 81.0% | 6328/7808 |
| 3 | McAfee-GW-Edition | 80.0% | 4/5 |
| 4 | MAX | 80.0% | 8/10 |
| 5 | ESET-NOD32 | 77.3% | 6034/7808 |
| 6 | Kaspersky | 75.5% | 5894/7807 |
| 7 | Ad-Aware | 75.0% | 3/4 |
| 8 | Google | 71.2% | 5557/7804 |
| 9 | Rising | 68.3% | 5331/7808 |
| 10 | Varist | 66.2% | 5164/7803 |
| 11 | Avast | 65.1% | 5079/7804 |
| 12 | AVG | 65.1% | 5079/7803 |
| 13 | Tencent | 64.9% | 4921/7582 |
| 14 | McAfeeD | 61.4% | 4786/7800 |
| 15 | huorong | 60.9% | 4749/7800 |

## Betroffene Plattformen

| Plattform | Samples | Anteil |
|-----------|---------|--------|
| 🐧 Linux | 59 | 58.4% |
| 🪟 Windows | 25 | 24.8% |
| 🍎 macOS | 11 | 10.9% |
| 📦 Archiv | 4 | 4.0% |
| ❓ Unbekannt | 2 | 2.0% |

## Infektionsvektoren

| Vektor | Samples | Anteil |
|--------|---------|--------|
| Unbekannt / nicht bestimmbar | 91 | 90.1% |
| MaaS-Loader | 9 | 8.9% |
| Drive-By / Exploit-Kit | 1 | 1.0% |

## Herkunftsländer

| # | Land | Samples | Anteil |
|---|------|---------|--------|
| 1 | 🇺🇸 US | 38 | 37.6% |
| 2 | 🇩🇪 DE | 33 | 32.7% |
| 3 | 🇳🇱 NL | 9 | 8.9% |
| 4 | 🇬🇧 GB | 8 | 7.9% |
| 5 | 🇭🇺 HU | 5 | 5.0% |
| 6 | 🇨🇭 CH | 3 | 3.0% |
| 7 | 🌐 Unbekannt | 2 | 2.0% |
| 8 | 🇫🇷 FR | 2 | 2.0% |
| 9 | 🌐 FI | 1 | 1.0% |

## MITRE ATT&CK

> 55 von 101 Samples konnten auf MITRE-Techniken gemappt werden.

| Taktik | Betroffene Samples |
|--------|-------------------|
| Initial Access | 49 |
| Lateral Movement | 49 |
| Credential Access | 6 |
| Collection | 6 |
| Exfiltration | 6 |

<details><summary>75cd53e5ff76cffea431… – Mirai | 🔴 KRITISCH 84.3/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>97288455d19b4dbec1ad… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>3d6baaac3ececed31165… – Mirai | 🔴 KRITISCH 84.2/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>59ae87b9ddbb7d557e07… – Mirai | 🔴 KRITISCH 84.1/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>
<details><summary>c8cbd752fa4fc8fd2f3c… – Mirai | 🔴 KRITISCH 83.7/100</summary>

| Taktik | Technik | Name |
|--------|---------|------|
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services |

</details>

## VirusTotal

> **Farblogik:** 🔴 ROT = kaum erkannt (evasiv/gefährlich), 🟢 GRÜN = breit erkannt
> **VT-Fokus:** Windows Office (doc/docx/xls/xlsx), ELF (Linux), Windows-PE (exe/dll)

### [5dcc40e317084d044855…](https://bazaar.abuse.ch/sample/5dcc40e317084d044855bf99e8b867aacb0dd0fed581147db9430fed31d841a0/)

- **Familie:** Mirai
- **Erkannt von:** 31 von 75 Engines (41.3%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.Linux.Mirai.1
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.Linux.Mirai.1`

**Erkennende Engines (31/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.Linux.Mirai.1` |
| AVG | `ELF:Mirai-CTB [Trj]` |
| AhnLab-V3 | `Linux/Mirai.Gen35` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Arcabit | `Trojan.Linux.Mirai.1` |
| Avast | `ELF:Mirai-CTB [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| BitDefender 🛡️ | `Trojan.Linux.Mirai.1` |
| CTX | `elf.trojan.mirai` |
| ClamAV | `Unix.Trojan.Mirai-9858729-0` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10589` |
| ESET-NOD32 | `Linux/Mirai.CJS trojan` |
| Emsisoft | `Trojan.Linux.Mirai.1 (B)` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Mirai.A!tr` |
| GData | `Trojan.Linux.Mirai.1` |
| Google | `Detected` |
| Ikarus | `Backdoor.Linux.Mirai` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| McAfeeD | `Trojan:Linux/Mirai.ERH` |
| MicroWorld-eScan | `Trojan.Linux.Mirai.1` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.FS!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.12BC2 (CLASSIC)` |
| SentinelOne | `Static AI - Malicious ELF` |
| Sophos | `Linux/DDoS-CI` |
| Tencent | `Backdoor.Linux.Mirai.waz` |
| VIPRE | `Trojan.Linux.Mirai.1` |
| Varist | `E32/Mirai.FG.gen!Eldorado` |
| ZoneAlarm | `Linux/DDoS-CI` |
| huorong | `Backdoor/Linux.Mirai.y` |

### [5782a83c9afa1995178a…](https://bazaar.abuse.ch/sample/5782a83c9afa1995178a80b34f5abf01a2b0feaa34bdc0f98f8319c920287af2/)

- **Familie:** Malware
- **Erkannt von:** 9 von 75 Engines (12.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** W32.Malware.8F7D136D
- **VT-Reputation:** 0
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (9/75):**

| Engine | Erkannter Name |
|--------|----------------|
| Bkav | `W32.Malware.8F7D136D` |
| CrowdStrike | `win/malicious_confidence_70% (W)` |
| DeepInstinct | `MALICIOUS` |
| Elastic | `malicious (high confidence)` |
| Fortinet | `W64/Vidar.AAR!tr` |
| Google | `Detected` |
| McAfeeD | `ti!5782A83C9AFA` |
| Symantec | `ML.Attribute.HighConfidence` |
| Varist | `W64/WinGo.J.gen!Eldorado` |

### [98431366b487498a271e…](https://bazaar.abuse.ch/sample/98431366b487498a271ee6f660d0f421e72207e25351edde968970ff42531db4/)

- **Familie:** Mirai
- **Erkannt von:** 24 von 75 Engines (32.0%)
- **Erkennungsqualität:** 🟡 SCHWACH ERKANNT
- **Häufigster Name:** ELF:Gafgyt-DO [Trj]
- **VT-Reputation:** -11
- **Microsoft Defender:** ✗ **NEIN** – nicht erkannt

**Erkennende Engines (24/75):**

| Engine | Erkannter Name |
|--------|----------------|
| AVG | `ELF:Gafgyt-DO [Trj]` |
| AhnLab-V3 | `Linux/Mirai13.Exp` |
| Antiy-AVL | `Trojan[Backdoor]/Linux.Mirai` |
| Avast | `ELF:Gafgyt-DO [Trj]` |
| Avast-Mobile | `ELF:Gafgyt-DO [Trj]` |
| Avira | `EXP/ELF.Mirai.W` |
| Cynet | `Malicious (score: 99)` |
| DrWeb | `Linux.Mirai.10456` |
| ESET-NOD32 | `Linux/Mirai_AGen.ADO trojan` |
| Elastic | `Linux.Generic.Threat` |
| F-Secure | `Exploit.EXP/ELF.Mirai.W` |
| Fortinet | `ELF/Gafgyt.WN!tr` |
| GData | `Linux.Trojan.Mirai.B` |
| Google | `Detected` |
| Ikarus | `Linux.Bot` |
| Kaspersky | `HEUR:Backdoor.Linux.Mirai.b` |
| McAfeeD | `Trojan:Linux/GenericY.HS` |
| Microsoft 🛡️ | `Backdoor:Linux/Mirai.FO!MTB` |
| Rising | `Backdoor.Mirai/Linux!1.11724 (CLASSIC)` |
| Sangfor | `Suspicious.Linux.Save.a` |
| SentinelOne | `Static AI - Malicious ELF` |
| Tencent | `Backdoor.Linux.Mirai.waw` |
| Varist | `E32/Mirai.DM.gen!Eldorado` |
| huorong | `Trojan/Linux.Mirai.q` |

### [90d2f7a70efb200aa680…](https://bazaar.abuse.ch/sample/90d2f7a70efb200aa6807b25a0117f39fcfe3ca276ea376cd245dd283ba7b2dc/)

- **Familie:** Trojan.GenericKD.82018980
- **Erkannt von:** 39 von 75 Engines (52.0%)
- **Erkennungsqualität:** 🟠 MÄSSIG ERKANNT
- **Häufigster Name:** Trojan.GenericKD.82018980
- **VT-Reputation:** -11
- **Microsoft Defender:** ✓ **JA** – `Trojan.GenericKD.82018980`

**Erkennende Engines (39/75):**

| Engine | Erkannter Name |
|--------|----------------|
| ALYac | `Trojan.GenericKD.82018980` |
| APEX | `Malicious` |
| Antiy-AVL | `Trojan/Win32.Yephiler` |
| Arcabit | `Trojan.Generic.D4E382A4` |
| Avira | `TR/W64.Agent` |
| BitDefender 🛡️ | `Trojan.GenericKD.82018980` |
| CTX | `dll.trojan.generic` |
| CrowdStrike | `win/malicious_confidence_60% (D)` |
| Cylance | `Unsafe` |
| Cynet | `Malicious (score: 99)` |
| DeepInstinct | `MALICIOUS` |
| ESET-NOD32 | `Win64/Packed.Themida.L suspicious application` |
| Elastic | `malicious (high confidence)` |
| Emsisoft | `Trojan.GenericKD.82018980 (B)` |
| F-Secure | `Trojan.TR/W64.Agent` |
| Fortinet | `Riskware/Application` |
| GData | `Trojan.GenericKD.82018980` |
| Google | `Detected` |
| Ikarus | `PUA.Themida` |
| Kaspersky | `Trojan.Win32.Yephiler.mwy` |
| Lionic | `Trojan.Win32.Themida.4!c` |
| Malwarebytes | `Malware.Heuristic.2123` |
| McAfeeD | `ti!90D2F7A70EFB` |
| MicroWorld-eScan | `Trojan.GenericKD.82018980` |
| Microsoft 🛡️ | `Trojan:Win32/Ravartar!rfn` |
| Paloalto | `generic.ml` |
| Rising | `Trojan.Yephiler!8.19199 (CLOUD)` |
| Sangfor | `Trojan.Win32.Agent.Vdvr` |
| SentinelOne | `Static AI - Suspicious PE` |
| Sophos | `Mal/Generic-S` |
| Symantec | `Trojan.Gen.MBT` |
| Tencent | `Malware.Win32.Gencirc.10c4d9fa` |
| Trapmine | `suspicious.low.ml.score` |
| TrellixENS | `Artemis!5FCC8EDCD013` |
| TrendMicro-HouseCall | `TrojanSpy.Win32.YEPHILER.USBLJU26` |
| VIPRE | `Trojan.GenericKD.82018980` |
| Varist | `W64/ABApplication.DFXV-1291` |
| alibabacloud | `VirTool:Win/Packed.Themida.L` |
| huorong | `Trojan/Generic!36BAAD96318FCB83` |

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
| MaxSecure | `Trojan.Malware.300983.susgen` |
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

- **elf** (50×)
- **Mirai** (49×)
- **exe** (28×)
- **Torii** (15×)
- **macho** (10×)
- **ClickFix** (9×)
- **Foxveil** (9×)
- **loader** (9×)
- **Mach-O** (9×)
- **macOS** (9×)
- **upx-dec** (9×)
- **upx** (9×)
- **honeypot** (8×)
- **signed** (7×)
- **Stealer** (7×)

## Änderungen – 24h-Vergleich

- ↑ **Mirai** +36 (13→49)
- ↑ **unbekannt** +9 (29→38)
- ↑ **WARDENStealer** +2 (3→5)
- ↑ **VShell** +3 (1→4)
- neu: **AokigaharaStealer** (1)
- neu: **Malware** (1)
- neu: **Trojan.GenericKD.82018980** (1)
- ↓ **NanoCore** -1 (2→1)
- weg: **SalatStealer** (war 5)
- weg: **ConnectWise** (war 2)
- weg: **Silentnet** (war 2)
- weg: **AgentTesla** (war 3)
- weg: **Formbook** (war 4)
- weg: **XWorm** (war 2)
- weg: **RemcosRAT** (war 2)
- weg: **ValleyRAT** (war 2)

## Änderungen – 7d-Vergleich

- ↑ **Mirai** +26 (23→49)
- ↑ **unbekannt** +10 (28→38)
- ↑ **WARDENStealer** +4 (1→5)
- ↑ **VShell** +3 (1→4)
- neu: **AokigaharaStealer** (1)
- neu: **Malware** (1)
- neu: **Trojan.GenericKD.82018980** (1)
- neu: **NanoCore** (1)
- weg: **SalatStealer** (war 11)
- weg: **Formbook** (war 3)
- weg: **RemcosRAT** (war 2)
- weg: **AgentTesla** (war 2)

## Statistik

| Kennzahl | Wert |
|----------|------|
| Ø Dateigröße | 3.669 MB |
| σ Dateigröße | 13.425 MB |
| Ø Risiko-Score | 68.5/100 |
| Ø Klassifikations-Konfidenz | 72.7% |
| Samples mit VT | 5/101 |
| Samples mit MITRE | 55/101 |
| Eindeutige Familien | 9 |
| Eindeutige Tags | 62 |
| Unbekannte Familien | 10 (9.9%) |

## Neueste Samples

| Zeit (UTC) | SHA256 | Typ | Familie | Score | VT-Rate | Erkennungsqualität | Land |
|-----------|--------|-----|---------|-------|---------|-------------------|------|
| 00:26 | [dd9f91758266…](https://bazaar.abuse.ch/sample/dd9f917582660b3d1623203343a57c8984e95b4503cf2fd9295fbda832d3bf6b/) | `macho` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 00:25 | [4ca5d43fce40…](https://bazaar.abuse.ch/sample/4ca5d43fce402f6f68b1b4e4836e3a62151eae6f88f0b6f72eaba9a109c15af5/) | `macho` | unbekannt | 32.7 | – | – | 🇺🇸US |
| 00:25 | [7c80253e43ad…](https://bazaar.abuse.ch/sample/7c80253e43ad1808c820e408205816d29fcfdf0af68f15c89e8ca2a9847ce73f/) | `dll` | unbekannt | 39.1 | – | – | 🇺🇸US |
| 00:25 | [513502450f83…](https://bazaar.abuse.ch/sample/513502450f83157b57507d55d80cb0333bdebc06c8530fe3fd78a1e85b750e57/) | `macho` | unbekannt | 75.1 | – | – | 🇺🇸US |
| 00:24 | [2b5c3476770e…](https://bazaar.abuse.ch/sample/2b5c3476770e5dfaba082a9f1dc28f496192d166e27fa23f0cbd9fed9c78f6cc/) | `exe` | unbekannt | 39.1 | – | – | 🇺🇸US |

---
*Daten: [MalwareBazaar](https://bazaar.abuse.ch) × [VirusTotal](https://virustotal.com) — 04.11.2026 00:28 UTC*